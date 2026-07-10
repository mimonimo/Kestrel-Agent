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

_MAX_TOKENS = 2600  # 파이프라인 근거 인용 + 5섹션(공격·영향·체이닝·탐지·완화)이 완결되도록.
                    # "길이"가 아니라 "구조적 깊이" — 각 섹션 간결하게(장황·중복 금지는 프롬프트로 통제).
_PEER_SCAN = 50          # 같은 CVE 의 다른 페르소나 분석을 찾으려 훑을 최근 분석 수(서버 필터 미지원).
                         # 플랫폼 limit 상한이 50 이라 이를 초과하면 422 → 최댓값 50 으로 고정.
_PEER_MAX = 2            # 프롬프트에 넣을 참고 분석 최대 수(토큰 비대화 방지 — 소수만).
_PEER_EXCERPT_CHARS = 420  # 참고 1건당 인용 길이 상한(복붙 방지 겸 균형).
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


def _peer_key(entry: dict) -> str:
    """참고 분석 엔트리 → 페르소나 key(offensive|defensive|analyst).

    플랫폼 엔트리의 author.persona('[공격]' 등)와 title('[방어] 분석 — …')로 해석한다.
    resolve_persona 의 alias 부분일치를 그대로 재사용(공격/방어/분석 등)."""
    author = entry.get("author") or {}
    src = f"{author.get('persona', '')} {entry.get('title', '')}"
    return resolve_persona(src).key


def _peer_reference(bb, ctx, own_key: str) -> tuple[str, int]:  # noqa: ANN001
    """같은 CVE 의 '다른 페르소나' 기존 분석을 가드가 붙은 참고 블록으로 만든다.

    반환: (프롬프트에 끼울 참고 블록, 사용한 참고 수). 아래 경우 모두 ("", 0) 로
    그레이스풀하게 독립 분석이 되게 한다:
      - kestrel 미주입(스켈레톤/테스트) 또는 cve_id 없음,
      - 조회 실패(네트워크/API 오류 — 예외를 여기서 흡수해 봇이 멈추지 않게),
      - 같은 CVE 의 다른 페르소나 분석이 없음(초기엔 대부분 이 경우).
    맹신·획일화·비대화 방지 지침은 블록 안에 명시하고, 참고 수는 _PEER_MAX,
    인용 길이는 _PEER_EXCERPT_CHARS 로 제한한다.
    """
    kestrel = getattr(ctx, "kestrel", None) if ctx is not None else None
    cve_id = getattr(bb, "cve_id", None)
    if kestrel is None or not cve_id:
        return "", 0
    try:
        rows = kestrel.analyses_for_cve(cve_id, scan=_PEER_SCAN)
    except Exception:  # noqa: BLE001 — 참고 조회 실패는 독립 분석으로 흡수(그레이스풀)
        return "", 0

    # 자기 페르소나 제외 + 인용할 내용(excerpt) 있는 것만, 페르소나 다양성 우선으로 소수 선택.
    picked: list[dict] = []
    seen: set[str] = set()
    for a in rows or []:
        if not isinstance(a, dict):
            continue
        pk = _peer_key(a)
        if pk == own_key or pk in seen:
            continue
        if not (a.get("excerpt") or "").strip():
            continue
        seen.add(pk)
        picked.append(a)
        if len(picked) >= _PEER_MAX:
            break
    if not picked:
        return "", 0

    blocks = []
    for i, a in enumerate(picked, 1):
        pk = _peer_key(a)
        exc = " ".join((a.get("excerpt") or "").split())[:_PEER_EXCERPT_CHARS]
        tags = []
        if a.get("priorityAction"):
            tags.append(f"우선순위={a['priorityAction']}")
        if a.get("exploitabilityGrade"):
            tags.append(f"악용등급={a['exploitabilityGrade']}")
        if a.get("cveSeverity"):
            tags.append(f"심각도={a['cveSeverity']}")
        head = f"[참고 {i} · 페르소나={pk}" + (f" · {', '.join(tags)}" if tags else "") + "]"
        blocks.append(f"{head}\n{exc}")

    block = (
        "\n[참고 — 다른 에이전트의 분석 (검증 대상이지 사실 아님)]\n"
        "아래는 같은 CVE 를 먼저 분석한 '다른 페르소나' 에이전트의 기존 분석 요지입니다. "
        "이는 다른 에이전트의 의견일 뿐 사실이 아니며 틀릴 수 있습니다. 위 [사실]과 대조해 "
        "스스로 검증하세요 — 참고의 수치·기법이 [사실]과 어긋나면 참고를 버리고 [사실]을 "
        "따르며, 참고가 틀렸다고 판단되면 본문에서 바로잡으세요. 참고를 그대로 인용·요약·"
        "복붙하지 말고 당신 분석의 재료로만 쓰세요. 목적은 다른 관점을 '인지'하고 당신 "
        "페르소나 고유 관점을 심화·차별화하는 것입니다: 겹치는 서술은 반복하지 말고, 참고가 "
        "짚은 지점에 당신 관점의 대응(예: 방어자라면 그 공격 경로를 겨냥한 구체적 탐지·완화)을 "
        "더하세요.\n"
        + "\n".join(blocks)
        + "\n[참고 끝 — 위는 검증 전 참고이며 확정 서술의 근거로 삼지 마세요]\n"
    )
    return block, len(picked)


def _prompt(bb, persona, report_lang: str, peer_block: str = "") -> tuple[str, str]:  # noqa: ANN001
    body_lang = "영어" if str(report_lang).startswith("en") else "한국어"
    system = f"{persona.system} {_BASE_SYSTEM} 어조: {persona.tone}"
    user = (
        "아래 사실만 근거로 이 CVE 리포트를 실무 방어자가 대응할 수 있게 구체적으로 작성하세요.\n"
        "=== 사실 ===\n"
        f"{_facts(bb)}\n"
        "============\n\n"
        f"[관점] {persona.emphasis}\n\n"
        f"{peer_block}"
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
        "각 섹션은 구체적이되 간결하게(핵심을 불릿으로, 장황·중복 금지 — 길이가 아니라 깊이). "
        "확정할 수 없는 값은 지어내지 말고 '추정:' 을 붙이세요. 정확히 아래 헤더·형식으로만 "
        "출력하세요(다른 머리말·코드펜스 금지):\n\n"
        "SUMMARY_EN: <취약점과 최우선 조치를 요약한 영어 한 문장>\n\n"
        "## 공격 기법\n"
        f"<{body_lang}. (1) 트리거 조건 — 어떤 입력/요청이 어떤 결함을 건드리는지, "
        "(2) 공격 단계를 순서대로(정찰→초기접근→실행·권한 획득→지속→영향), 각 단계의 전제조건과 "
        "관측 가능한 지표, (3) 공격 표면 — 노출되는 엔드포인트·파라미터·프로토콜, "
        "(4) CVSS 벡터(AV/AC/PR/UI)를 실제 공격 조건에 연결. "
        "원리와 축약된 개념 예시까지만, 복사-실행 가능한 완전한 코드·무기화된 전체 페이로드는 금지>\n\n"
        "## 영향 분석\n"
        f"<{body_lang}. 악용에 성공했을 때의 결과만. (1) 기술적 위험 — 이 CVE 에 실제로 해당하는 "
        "것만(데이터 유출·시스템 장악·서비스 중단·횡적 이동 등), (2) 비즈니스 영향 — 서비스 "
        "가용성·규제/컴플라이언스·신뢰 관점. 영향 제품·노출 규모를 근거로 삼되 과장 금지, "
        "해당 없는 위험은 적지 마세요>\n\n"
        "## 관련 취약점·체이닝\n"
        f"<{body_lang}. 이 결함이 다른 결함과 어떻게 이어질 수 있는지를 '유형·패턴' 수준으로만 "
        "(예: 정보 노출 → 권한 상승 → RCE 로 이어지는 체인). "
        "★실제 CVE 번호는 확실하지 않으면 절대 쓰지 마세요(지어내면 안 됩니다). 확실한 근거가 "
        "없으면 취약점 '유형'(CWE 계열)과 일반적 체이닝 패턴만 서술하고 '추정:' 을 붙이세요>\n\n"
        "## 탐지\n"
        f"<{body_lang}. (1) 로그 지표 — 어떤 로그의 어떤 필드에 어떤 패턴이 남는지, "
        "(2) 탐지 규칙 1~3개 — 소스/필드/조건/임계값을 갖춘 SIEM 쿼리 형태 또는 탐지 로직 "
        "의사코드(정규식 포함), (3) 오탐 시나리오와 이를 줄이는 튜닝 방법>\n\n"
        "## 완화 방안\n"
        f"<{body_lang}. 계층별로 나눠 쓰세요. "
        "**즉시(긴급 차단)**: 지금 당장 할 임시 조치(설정 변경·ACL·기능 비활성화). "
        "**단기(완화)**: 패치 전까지 위험을 낮추는 조치. "
        "**근본(해결)**: 패치·수정 버전 명시와 업그레이드 절차. "
        "각 조치마다 구현 난이도·운영 영향(가용성·성능·마찰)·검증 방법을 한 마디씩 덧붙이세요>\n"
    )
    return system, user


def _section_of(head: str) -> str | None:
    """헤더 텍스트(소문자) → 섹션 키. 순서 중요(체이닝을 완화보다 먼저)."""
    if "공격" in head or "attack" in head:
        return "attack"
    if "영향" in head or "impact" in head:
        return "impact"
    if "체이닝" in head or "chain" in head or "연계" in head or "관련" in head:
        return "chaining"
    if "탐지" in head or "detect" in head:
        return "detection"
    if "완화" in head or "방어" in head or "mitig" in head:
        return "mitigation"
    return None


def _parse(text: str) -> dict[str, str]:
    """LLM 출력 → {summary_en, attack, impact, chaining, detection, mitigation}. 헤더 관대 매칭."""
    buckets: dict[str, list[str]] = {
        "attack": [], "impact": [], "chaining": [], "detection": [], "mitigation": []}
    summary_en = ""
    section = None
    for line in (text or "").splitlines():
        s = line.strip()
        upper = s.upper()
        if upper.startswith("SUMMARY_EN:") or upper.startswith("SUMMARY:"):
            summary_en = s.split(":", 1)[1].strip()
            section = "sum"
            continue
        if s.startswith("#"):
            section = _section_of(s.lstrip("# ").strip().lower())
            continue
        if section in buckets:
            buckets[section].append(line)
        elif section == "sum" and not summary_en and s:
            summary_en = s  # 요약이 다음 줄로 넘어간 경우
    out = {k: "\n".join(v).strip() for k, v in buckets.items()}
    out["summary_en"] = summary_en.strip()
    return out


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
    # 단계2: 같은 CVE 의 다른 페르소나 분석을 (있으면) 가드와 함께 참고로 주입.
    # 실패·없음이면 빈 문자열 → 기존과 동일한 독립 분석(그레이스풀).
    peer_block, peer_used = _peer_reference(bb, ctx, persona.key)
    system, user = _prompt(bb, persona, report_lang, peer_block)

    started = time.time()
    try:
        raw = client.complete(system, user, max_tokens=_MAX_TOKENS, effort="medium", model=model)
    except Exception as e:  # noqa: BLE001 — llm.LLMError 포함. 로컬 실패는 재시도 대상.
        bb.report.meta = {"model": used_model, "persona": persona.key,
                          "elapsed_sec": round(time.time() - started, 2),
                          "peer_ref_used": peer_used, "error": str(e)}
        bb.needs_retry = True
        return

    p = _parse(raw)
    core_empty = not (p["attack"] or p["detection"] or p["mitigation"])
    if core_empty:
        # 형식 붕괴 시 1회 더 강하게 요청(핵심 3섹션 헤더를 명시)
        strict = user + "\n\n[재요청] 반드시 'SUMMARY_EN:' 줄과 '## 공격 기법', '## 탐지', " \
                        "'## 완화 방안' 헤더를 그대로 쓰세요."
        try:
            raw2 = client.complete(system, strict, max_tokens=_MAX_TOKENS, effort="medium",
                                   model=model)
            p2 = _parse(raw2)
            p2["summary_en"] = p["summary_en"] or p2["summary_en"]
            p, raw = p2, raw2
            core_empty = not (p["attack"] or p["detection"] or p["mitigation"])
        except Exception:  # noqa: BLE001 — 재시도 실패는 아래 폴백으로
            pass
    if core_empty:
        p["attack"] = (raw or "").strip()  # 최후 폴백: 원문을 공격 서술에 담고 표식

    bb.report.summary_en = p["summary_en"]
    bb.report.attack = p["attack"]
    bb.report.impact = p["impact"]
    bb.report.chaining = p["chaining"]
    bb.report.detection = p["detection"]
    bb.report.mitigation = p["mitigation"]
    bb.report.lang = ("en" if str(report_lang).startswith("en") else "ko") + \
                     ("+en" if p["summary_en"] else "")
    bb.report.meta = {
        "model": used_model,
        "persona": persona.key,
        "elapsed_sec": round(time.time() - started, 2),
        "peer_ref_used": peer_used,
        "unparsed": not p["mitigation"] and not p["summary_en"],
    }
