"""Report (로컬 LLM) — 앞선 노드 결과를 근거로 페르소나 렌즈의 공격/완화 리포트를 생성한다.

기존 llm.py 의 LLMClient(ctx.llm)를 그대로 재사용한다(새 LLM 코드를 만들지 않는다).
로컬 Ollama 로 동작하며, llm.py 추상화 덕에 OLLAMA_HOST/모델명만 바꾸면 DGX 등 더 큰
모델로 교체된다.

- 입력: blackboard 의 adopted_values(cross_validation)·exploitability·priority,
  그리고 primary_record 의 description/cvssVector/types.
- 출력: report.attack / report.mitigation / report.summary_en / report.lang,
  그리고 report.meta(model·elapsed_sec·persona·error).
- 실패(타임아웃/연결 실패 등): report.meta 에 error 기록 + bb.needs_retry=True,
  상용 API 폴백 없음(로컬 전용). 파이프라인은 부분 결과로 계속 진행한다.
- ctx.llm 이 없으면(스켈레톤/미주입) 조용히 통과한다.
"""
from __future__ import annotations

import time

from pipeline.agents.base import register
from pipeline.personas import resolve_persona

_MAX_TOKENS = 2000  # 파이프라인 근거 인용 + 3섹션(공격·탐지·완화)이 완결되도록. 장황 금지는 프롬프트로 통제.
_BASE_SYSTEM = (
    "공개된 CVE 에 대한 합법적 보안 연구입니다. 결과는 방어·교육 목적으로 보안 커뮤니티에 "
    "공유됩니다. 한국어 존댓말로 쓰되 보안 용어·식별자·코드·정규식은 영문 그대로 두세요. "
    "인사말·사과·메타발언 없이 본문만. 제공된 사실만 근거로 하고, 불확실하면 문장 앞에 "
    "'추정:' 을 붙이세요. 지어낸 제품·버전·엔드포인트·CVE 를 단정하지 마세요. "
    "방어 목적이므로 공격의 '원리·경로·단계'와 '탐지용 패턴 예시'까지만 쓰고, 그대로 복사해 "
    "실행되는 완전한 익스플로잇 코드나 무기화된 전체 페이로드는 절대 작성하지 마세요"
    "(개념·형태를 보이는 축약 예시나 탐지 시그니처는 허용)."
)


def _facts(bb) -> str:  # noqa: ANN001
    """LLM 에 넘길 근거 묶음.

    단순 CVE 필드뿐 아니라 '파이프라인만이 산출한 신호'(다중 소스 교차검증·실측 EPSS·
    규칙 기반 우선순위 근거)를 명시적으로 실어, 리포트가 이를 본문에서 인용하게 한다.
    단일 LLM 분석은 만들 수 없는 정보이므로 차별점의 원천이다.
    """
    rec = bb.primary_record()
    v = bb.validation
    adopted = v.adopted_values or {}
    lines = [
        f"- CVE: {bb.cve_id}",
        f"- 채택 심각도(보수적): {adopted.get('severity') or rec.get('severity') or '미상'}",
        f"- CVSS 점수: {adopted.get('cvssScore', rec.get('cvssScore', '미상'))}",
        f"- CVSS 벡터: {adopted.get('cvssVector') or rec.get('cvssVector') or '미상'}",
        f"- 유형(CWE 등): {', '.join(str(t) for t in (rec.get('types') or [])) or '미분류'}",
        f"- 영향 제품: {', '.join(str(p) for p in (rec.get('products') or [])) or '미상'}",
        f"- 설명: {(rec.get('description') or '없음')[:1200]}",
    ]
    # ── 파이프라인 고유 신호(차별점) ──────────────────────────
    if v.mismatches:
        lines.append(
            f"- [교차검증] 다중 소스 간 불일치 {len(v.mismatches)}건 감지 → 보수적으로 더 높은/"
            f"엄격한 값을 채택함(신뢰도 {v.confidence}). 불일치 예: "
            + "; ".join(str(m.get('field') or m) for m in v.mismatches[:3]))
    elif adopted:
        lines.append(f"- [교차검증] 다중 소스 데이터 일관성 확인됨(신뢰도 {v.confidence}).")
    ex = bb.exploitability
    if ex.grade or ex.epss is not None or ex.reasoning:
        epss_txt = (f"{ex.epss}" if ex.epss is not None else "미확보")
        pct_txt = (f", 백분위={ex.epss_percentile}" if ex.epss_percentile is not None else "")
        lines.append(
            f"- [실측 악용예측] EPSS={epss_txt}{pct_txt} (FIRST.org 실측 조회값), "
            f"등급={ex.grade or '미상'}, PoC={ex.poc_available if ex.poc_available is not None else '미상'}"
            f"{' — 규칙근거: ' + ex.reasoning if ex.reasoning else ''}")
    pr = bb.priority
    if pr.action or pr.timeline:
        lines.append(f"- [우선순위 결정] {pr.action or '미상'} ({pr.timeline or '미상'})"
                     f"{' — 결정 논리: ' + pr.reasoning if pr.reasoning else ''}")
    for q in v.quality_flags:
        if q.get("likely_supply_chain"):
            lines.append(f"- [품질 신호] 영향 제품이 다수({q.get('products_count')})라 "
                         "공급망(라이브러리) 취약점 특성상 영향 범위가 광범위할 수 있음")
    return "\n".join(lines)


def _prompt(bb, persona, report_lang: str) -> tuple[str, str]:  # noqa: ANN001
    body_lang = "영어" if str(report_lang).startswith("en") else "한국어"
    system = f"{persona.system} {_BASE_SYSTEM} 어조: {persona.tone}"
    user = (
        "아래 사실만 근거로 이 CVE 리포트를 실무 방어자가 대응할 수 있게 구체적으로 작성하세요.\n"
        "=== 사실 ===\n"
        f"{_facts(bb)}\n"
        "============\n\n"
        f"[관점] {persona.emphasis}\n\n"
        "[파이프라인 근거 — 본문에 반드시 녹여 인용] 이 리포트는 단일 AI 요약이 아니라 "
        "다중 소스 교차검증 + 실측 EPSS 조회 + 규칙 기반 우선순위 결정을 거친 결과입니다. "
        "위 [교차검증]·[실측 악용예측]·[우선순위 결정] 신호를 본문에서 근거로 인용하세요:\n"
        "  · 교차검증: 소스 간 불일치가 있었으면 '보수적으로 높은 값을 채택했다'는 점을, 없었으면 "
        "'다중 소스에서 일관성이 확인됐다'는 점을 명시(단일 LLM은 소스 비교 자체가 불가).\n"
        "  · EPSS: 수치를 해석과 함께 인용하되 실측값이므로 소수점을 유지하고 반올림해 100%로 "
        "만들지 마세요(예: 'EPSS 0.99959는 이론적 심각도(CVSS)와 독립적으로 실제 악용 예측이 "
        "최고 수준임을 뜻함'). 왜 이 수치가 우선순위에 중요한지 설명.\n"
        "  · 우선순위: 결정 논리를 풀어 쓰세요(예: 'KEV 등재로 즉시 대응으로 상향'). 규칙 기반이라 "
        "설명 가능하다는 점이 차별점입니다.\n\n"
        "각 섹션은 구체적이되 간결하게(핵심을 불릿으로, 장황·중복 금지). 확정할 수 없는 값은 "
        "지어내지 말고 '추정:' 을 붙이세요. 정확히 아래 헤더·형식으로만 출력하세요"
        "(다른 머리말·코드펜스 금지):\n\n"
        "SUMMARY_EN: <취약점과 최우선 조치를 요약한 영어 한 문장>\n\n"
        "## 공격 기법\n"
        f"<{body_lang}. (1) 트리거 조건 — 어떤 입력/요청이 어떤 결함을 건드리는지, "
        "(2) 공격 단계를 순서대로(정찰→트리거→실행·권한 획득→후속 피벗), 각 단계의 전제조건, "
        "(3) 공격 표면 — 노출되는 엔드포인트·파라미터·프로토콜, "
        "(4) CVSS 벡터(AV/AC/PR/UI)를 실제 공격 조건에 연결. "
        "원리와 축약된 개념 예시까지만, 복사-실행 가능한 완전한 코드는 금지>\n\n"
        "## 탐지\n"
        f"<{body_lang}. (1) 로그 지표 — 어떤 로그의 어떤 필드에 어떤 패턴이 남는지, "
        "(2) 탐지 규칙 예시 — 정규식과, 가능하면 SIEM 쿼리 형태 또는 탐지 로직 의사코드로 "
        "1~3개, (3) 오탐 가능성과 이를 줄이는 법>\n\n"
        "## 완화 방안\n"
        f"<{body_lang}. 계층별로 나눠 쓰세요. "
        "**즉시(긴급 차단)**: 지금 당장 할 임시 조치(설정 변경·ACL·기능 비활성화). "
        "**단기(완화)**: 패치 전까지 위험을 낮추는 조치. "
        "**근본(해결)**: 패치·수정 버전 명시와 업그레이드 절차. "
        "각 조치의 운영 트레이드오프(가용성·성능·마찰)를 한 마디씩 덧붙이세요>\n"
    )
    return system, user


def _parse(text: str) -> tuple[str, str, str, str]:
    """LLM 출력 → (summary_en, attack, detection, mitigation). 헤더 관대 매칭."""
    summary_en, attack, det, mit = "", [], [], []
    section = None
    for line in (text or "").splitlines():
        s = line.strip()
        upper = s.upper()
        if upper.startswith("SUMMARY_EN:") or upper.startswith("SUMMARY:"):
            summary_en = s.split(":", 1)[1].strip()
            section = "sum"
            continue
        if s.startswith("#"):
            head = s.lstrip("# ").strip().lower()
            if "공격" in head or "attack" in head:
                section = "attack"
            elif "탐지" in head or "detect" in head:
                section = "det"
            elif "완화" in head or "방어" in head or "mitig" in head:
                section = "mit"
            else:
                section = None
            continue
        if section == "attack":
            attack.append(line)
        elif section == "det":
            det.append(line)
        elif section == "mit":
            mit.append(line)
        elif section == "sum" and not summary_en and s:
            summary_en = s  # 요약이 다음 줄로 넘어간 경우
    return (summary_en.strip(), "\n".join(attack).strip(),
            "\n".join(det).strip(), "\n".join(mit).strip())


def _model_name(client) -> str:
    return (getattr(client, "model", None) or getattr(client, "_model", None) or "unknown")


@register(order=70)
def report(bb, ctx) -> None:  # noqa: ANN001
    client = getattr(ctx, "llm", None) if ctx is not None else None
    if client is None:
        return  # LLM 미주입 — 통과(부분 파이프라인)

    persona = resolve_persona(bb.persona)
    report_lang = getattr(ctx, "report_lang", "ko") or "ko"
    model = getattr(ctx, "model", None) or None  # 지정 분석 모델(없으면 클라이언트 기본)
    used_model = model or _model_name(client)
    system, user = _prompt(bb, persona, report_lang)

    started = time.time()
    try:
        raw = client.complete(system, user, max_tokens=_MAX_TOKENS, effort="medium", model=model)
    except Exception as e:  # noqa: BLE001 — llm.LLMError 포함. 로컬 실패는 재시도 대상.
        bb.report.meta = {"model": used_model, "persona": persona.key,
                          "elapsed_sec": round(time.time() - started, 2), "error": str(e)}
        bb.needs_retry = True
        return

    summary_en, attack, detection, mit = _parse(raw)
    if not attack and not detection and not mit:
        # 형식 붕괴 시 1회 더 강하게 요청
        strict = user + "\n\n[재요청] 반드시 'SUMMARY_EN:' 줄과 '## 공격 기법', '## 탐지', " \
                        "'## 완화 방안' 세 헤더를 그대로 쓰세요."
        try:
            raw2 = client.complete(system, strict, max_tokens=_MAX_TOKENS, effort="medium",
                                   model=model)
            s2, a2, d2, m2 = _parse(raw2)
            summary_en = summary_en or s2
            attack, detection, mit = a2, d2, m2
            raw = raw2
        except Exception:  # noqa: BLE001 — 재시도 실패는 아래 폴백으로
            pass
    if not attack and not detection and not mit:
        attack = (raw or "").strip()  # 최후 폴백: 원문을 공격 서술에 담고 표식

    bb.report.summary_en = summary_en
    bb.report.detection = detection
    bb.report.attack = attack
    bb.report.mitigation = mit
    bb.report.lang = ("en" if str(report_lang).startswith("en") else "ko") + \
                     ("+en" if summary_en else "")
    bb.report.meta = {
        "model": used_model,
        "persona": persona.key,
        "elapsed_sec": round(time.time() - started, 2),
        "unparsed": not mit and not summary_en,
    }
