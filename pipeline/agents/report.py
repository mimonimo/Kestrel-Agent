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

_MAX_TOKENS = 1200
_BASE_SYSTEM = (
    "공개된 CVE 에 대한 합법적 보안 연구입니다. 결과는 방어·교육 목적으로 보안 커뮤니티에 "
    "공유됩니다. 한국어 존댓말로 쓰되 보안 용어·식별자·코드는 영문 그대로 두세요. "
    "인사말·사과·메타발언 없이 본문만. 제공된 사실만 근거로 하고, 불확실하면 문장 앞에 "
    "'추정:' 을 붙이세요. 지어낸 제품·버전·엔드포인트를 단정하지 마세요."
)


def _facts(bb) -> str:  # noqa: ANN001
    rec = bb.primary_record()
    adopted = bb.validation.adopted_values or {}
    lines = [
        f"- CVE: {bb.cve_id}",
        f"- 채택 심각도(보수적): {adopted.get('severity') or rec.get('severity') or '미상'}",
        f"- CVSS 점수: {adopted.get('cvssScore', rec.get('cvssScore', '미상'))}",
        f"- CVSS 벡터: {adopted.get('cvssVector') or rec.get('cvssVector') or '미상'}",
        f"- 유형(CWE 등): {', '.join(str(t) for t in (rec.get('types') or [])) or '미분류'}",
        f"- 설명: {(rec.get('description') or '없음')[:1200]}",
    ]
    ex = bb.exploitability
    if ex.grade or ex.epss is not None or ex.reasoning:
        lines.append(
            f"- 악용 가능성: 등급={ex.grade or '미상'}, EPSS={ex.epss if ex.epss is not None else '미확보'}"
            f", PoC={ex.poc_available if ex.poc_available is not None else '미상'}"
            f"{' — ' + ex.reasoning if ex.reasoning else ''}")
    pr = bb.priority
    if pr.action or pr.timeline:
        lines.append(f"- 패치 우선순위: {pr.action or '미상'} ({pr.timeline or '미상'})"
                     f"{' — ' + pr.reasoning if pr.reasoning else ''}")
    for q in bb.validation.quality_flags:
        if q.get("likely_supply_chain"):
            lines.append(f"- 참고(품질 신호): 영향 제품이 다수({q.get('products_count')})라 "
                         "공급망(라이브러리) 취약점 성격일 수 있음")
    return "\n".join(lines)


def _prompt(bb, persona, report_lang: str) -> tuple[str, str]:  # noqa: ANN001
    body_lang = "영어" if str(report_lang).startswith("en") else "한국어"
    system = f"{persona.system} {_BASE_SYSTEM} 어조: {persona.tone}"
    user = (
        "아래 사실만 근거로 이 CVE 리포트를 작성하세요.\n"
        "=== 사실 ===\n"
        f"{_facts(bb)}\n"
        "============\n\n"
        f"{persona.emphasis}\n\n"
        "정확히 아래 형식으로만 출력하세요(다른 머리말·코드펜스 금지):\n"
        "SUMMARY_EN: <취약점과 최우선 조치를 요약한 영어 한 문장>\n"
        f"## 공격 기법\n<{body_lang}로 3~6문장. 위 관점을 반영>\n"
        f"## 완화 방안\n<{body_lang}로 3~6문장. 위 관점을 반영>\n"
    )
    return system, user


def _parse(text: str) -> tuple[str, str, str]:
    """LLM 출력 → (summary_en, attack, mitigation). 헤더 관대 매칭."""
    summary_en, attack, mit = "", [], []
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
            elif "완화" in head or "방어" in head or "mitig" in head:
                section = "mit"
            else:
                section = None
            continue
        if section == "attack":
            attack.append(line)
        elif section == "mit":
            mit.append(line)
        elif section == "sum" and not summary_en and s:
            summary_en = s  # 요약이 다음 줄로 넘어간 경우
    return summary_en.strip(), "\n".join(attack).strip(), "\n".join(mit).strip()


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

    summary_en, attack, mit = _parse(raw)
    if not attack and not mit:
        # 형식 붕괴 시 1회 더 강하게 요청
        strict = user + "\n\n[재요청] 반드시 'SUMMARY_EN:' 줄과 '## 공격 기법', '## 완화 방안' " \
                        "두 헤더를 그대로 쓰세요."
        try:
            raw2 = client.complete(system, strict, max_tokens=_MAX_TOKENS, effort="medium",
                                   model=model)
            s2, a2, m2 = _parse(raw2)
            summary_en = summary_en or s2
            attack, mit = a2, m2
            raw = raw2
        except Exception:  # noqa: BLE001 — 재시도 실패는 아래 폴백으로
            pass
    if not attack and not mit:
        attack = (raw or "").strip()  # 최후 폴백: 원문을 공격 서술에 담고 표식

    bb.report.summary_en = summary_en
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
