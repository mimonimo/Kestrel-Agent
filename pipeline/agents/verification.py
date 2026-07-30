"""Verification (규칙 우선, LLM 은 수리 전용) — Report 가 낸 **출력물 자체**를 검사한다.

cross_validation 이 '입력 데이터'의 자기모순을 본다면, 이 노드는 'LLM 이 쓴 리포트'를 본다.
설계 원칙 — GPU 를 아끼기 위해 판정은 전부 결정론(무료)으로 하고, LLM 은 **실패한 경우에만**
1회 타겟 수리에 쓴다. 통과하는 리포트는 추가 GPU 비용이 0 이다.

차단(수리 트리거) 대상 — 프롬프트가 명시적으로 금지/요구한 것 중 기계로 확실히 판정되는 것만:
  1. ungrounded_cve : [사실]에 없는 CVE 번호를 본문에서 단정 — 환각의 가장 검증 가능한 형태
  2. sections       : 5개 섹션 중 실질 내용이 없는 섹션 존재

기록만 하고 수리하지 않는 것(지표로만 사용 — 판정이 주관적이거나 페르소나마다 정당하게 다름):
  구체성(정규식·쿼리·명령어 수), 파이프라인 근거 인용 여부, peer 대비 신규성.
  → 이걸로 리포트를 되돌리면 페르소나 편향(공격=엔드포인트, 방어=탐지규칙)을 품질 저하로
    오판하게 된다. arm 간 상대 비교에만 쓴다.

ctx.verify_report=False 면 검사 없이 통과(ablation 대조군용).
"""
from __future__ import annotations

from pipeline import metrics
from pipeline.agents.base import register

_MAX_REPAIR_TOKENS = 1400   # 수리는 문제 섹션만 다시 받으므로 본 생성보다 작게
_REPAIR_TEMP_EFFORT = "low"  # 수리는 창의성이 아니라 준수 — 저온도


def _compute(bb, ctx=None) -> dict:  # noqa: ANN001
    """리포트 지표 산출. report/exploitability/validation 값을 근거로 넘긴다.

    peer_texts 는 분석 요지(excerpt) + 동료 댓글 전문을 함께 쓴다 — 신규성·흡수율이
    '동료가 실제로 말한 것' 전체를 기준으로 계산되도록.
    """
    return metrics.report_metrics(
        bb.report.sections(),
        facts=bb.report.facts,
        target_cve=bb.cve_id,
        epss=bb.exploitability.epss,
        priority_action=bb.priority.action,
        validation_confidence=bb.validation.confidence,
        peer_texts=bb.report.peer_texts(),
        prior_body=getattr(ctx, "prior_body", "") if ctx is not None else "",
    )


def _evaluate(m: dict) -> tuple[dict, list[str]]:
    """지표 → (규칙별 통과여부, 실패한 규칙명 목록). 수리 트리거 규칙만 판정한다."""
    checks = {
        "ungrounded_cve": m.get("ungrounded_cve_count", 0) == 0,
        "sections": not m.get("missing_sections"),
    }
    return checks, [name for name, ok in checks.items() if not ok]


def _repair_prompt(bb, m: dict, failures: list[str]) -> str:  # noqa: ANN001
    """실패 항목만 콕 집어 고치게 하는 재작성 지시."""
    parts = ["앞서 작성한 리포트에 아래 문제가 있어 다시 작성해야 합니다.\n"]
    if "ungrounded_cve" in failures:
        bad = ", ".join(m.get("ungrounded_cves", [])[:6])
        parts.append(
            f"[문제 1] 제공된 [사실]에 없는 CVE 번호를 본문에 썼습니다: {bad}\n"
            "이 번호들은 근거가 없으므로 **모두 삭제**하세요. 체이닝·관련 취약점을 설명할 때는 "
            "실제 CVE 번호 대신 취약점 '유형'(CWE 계열)과 일반적 패턴으로만 서술하고 "
            "'추정:' 을 붙이세요.\n")
    if "sections" in failures:
        miss = ", ".join(m.get("missing_sections", []))
        parts.append(
            f"[문제 2] 다음 섹션이 비었거나 내용이 부실합니다: {miss}\n"
            "누락 없이 5개 섹션(## 공격 기법 / ## 영향 분석 / ## 관련 취약점·체이닝 / "
            "## 탐지 / ## 완화 방안)을 모두 실질 내용으로 채우세요.\n")
    parts.append("\n형식은 처음 지시와 동일하게 'SUMMARY_EN:' 줄과 5개 '##' 헤더를 그대로 쓰세요. "
                 "그 외 내용은 유지하되 위 문제만 교정하세요.")
    return "".join(parts)


@register(order=80)
def verification(bb, ctx) -> None:  # noqa: ANN001
    # 리포트가 없으면(LLM 미주입·생성 실패) 검사할 대상이 없다 — 조용히 통과.
    if not (bb.report.attack or bb.report.mitigation or bb.report.detection):
        return
    if ctx is not None and not getattr(ctx, "verify_report", True):
        bb.verification.metrics = _compute(bb, ctx)  # 지표는 남기되 게이트는 미적용(ablation)
        return

    m = _compute(bb, ctx)
    checks, failures = _evaluate(m)

    client = getattr(ctx, "llm", None) if ctx is not None else None
    if failures and client is not None:
        # ── 수리 1회 — 실패했을 때만 GPU 를 쓴다 ──
        from pipeline.agents.report import _MAX_TOKENS, _prompt  # noqa: PLC0415 — 순환 import 회피
        from pipeline.personas import resolve_persona  # noqa: PLC0415
        from pipeline.agents.report import _parse  # noqa: PLC0415

        persona = resolve_persona(bb.persona)
        report_lang = getattr(ctx, "report_lang", "ko") or "ko"
        system, base_user = _prompt(bb, persona, report_lang, "")
        user = base_user + "\n\n" + _repair_prompt(bb, m, failures)
        try:
            raw = client.complete(system, user, max_tokens=max(_MAX_REPAIR_TOKENS, _MAX_TOKENS // 2),
                                  effort=_REPAIR_TEMP_EFFORT,
                                  model=(getattr(ctx, "model", None) or None))
            p = _parse(raw)
            # 수리 결과가 핵심 섹션을 갖췄을 때만 채택(더 나빠지는 것 방지 — 안전한 롤백).
            if p["attack"] or p["mitigation"] or p["detection"]:
                bb.report.attack = p["attack"] or bb.report.attack
                bb.report.impact = p["impact"] or bb.report.impact
                bb.report.chaining = p["chaining"] or bb.report.chaining
                bb.report.detection = p["detection"] or bb.report.detection
                bb.report.mitigation = p["mitigation"] or bb.report.mitigation
                bb.report.summary_en = bb.report.summary_en or p["summary_en"]
                bb.verification.repaired = True
                m = _compute(bb, ctx)               # 수리 후 지표로 갱신
                checks, failures = _evaluate(m)
        except Exception as e:  # noqa: BLE001 — 수리 실패는 원본 유지(게시는 계속)
            bb.verification.repair_error = str(e)

    bb.verification.metrics = m
    bb.verification.checks = checks
    bb.verification.failures = failures
    bb.verification.passed = not failures
    # 수리 후에도 환각 CVE 가 남으면 사람 검토 대상으로 표시(게시는 막지 않되 추적 가능하게).
    if not checks.get("ungrounded_cve", True):
        bb.needs_human_review = True
