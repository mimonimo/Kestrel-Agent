"""Prioritization (규칙 융합) — CVSS·EPSS·KEV·exploitability·in_scope 를 합쳐 조치를 정한다.

전부 규칙 기반(가중치·구간)이며 LLM 을 쓰지 않는다.
  action ∈ monitor(0) < scheduled(1) < immediate(2), + timeline + reasoning.

기본 융합(_fuse):
  * KEV 또는 EPSS≥0.5 또는 (easy & CVSS≥9) → immediate
  * CVSS≥7 또는 easy/moderate 또는 EPSS≥0.1 → scheduled
  * 그 외 → monitor

조정(하향/상향):
  * in_scope=False(우리 자산에 없음) → 하향 신호. persona(defensive) 하향과 곱으로 겹치지
    않게 **최대 1단계만** 내린다(자산 매칭 실패 하나로 두 번 깎지 않는다).
  * persona 렌즈(선택): offensive 는 악용 실현성(kev/easy)에 +1 상향, defensive 는 자산밖에
    -1 하향(위 최대 1단계 규칙에 포함).

KEV floor(안전 하한, 마지막에 clamp):
  KEV=관측된 실제 악용 = 세 신호 중 가장 강한 실측 신호. 예측(EPSS)·자산(in_scope) 신호가
  이를 뒤집지 못하게, 모든 하향을 계산한 뒤 마지막에 하한을 보장한다:
    * KEV=True → 최소 scheduled(monitor 로 내려가지 않음)
    * KEV=True & EPSS≥0.9 → 최소 immediate(실제 악용 중 + 악용 확률 최고치)
  하한이 실제로 등급을 끌어올린 경우 reasoning 에 'KEV floor applied: <원래> → <하한>' 명시.
"""
from __future__ import annotations

from pipeline.agents.base import register
from pipeline.personas import resolve_persona

_ACTIONS = ["monitor", "scheduled", "immediate"]  # 낮음 → 높음
_TIMELINE = {"immediate": "지금 즉시(24h 내)", "scheduled": "이번 주 내", "monitor": "모니터링"}


def _clamp(i: int) -> int:
    return min(2, max(0, i))


def _fuse(score: float, kev: bool, epss: float | None, grade: str | None) -> str:
    s = score or 0
    if kev or (epss is not None and epss >= 0.5) or (grade == "easy" and s >= 9):
        return "immediate"
    if s >= 7 or grade in ("easy", "moderate") or (epss is not None and epss >= 0.1):
        return "scheduled"
    return "monitor"


def _persona_delta(persona, grade: str | None, kev: bool, in_scope: bool | None) -> int:  # noqa: ANN001
    """offensive=+1(악용 실현성 가중), defensive=-1(자산밖 가중), analyst=0."""
    if persona.key == "offensive" and (kev or grade == "easy"):
        return +1
    if persona.key == "defensive" and in_scope is False:
        return -1
    return 0


def _kev_floor(kev: bool, epss: float | None) -> int:
    if not kev:
        return 0
    if epss is not None and epss >= 0.9:
        return _ACTIONS.index("immediate")
    return _ACTIONS.index("scheduled")


@register(order=60)
def prioritization(bb, ctx) -> None:  # noqa: ANN001
    enriched = bb.enriched or {}
    score = enriched.get("cvss_score")
    kev = bool(enriched.get("kev"))
    ex = bb.exploitability
    in_scope = bb.context.in_scope
    persona = resolve_persona(bb.persona)

    base = _ACTIONS.index(_fuse(score, kev, ex.epss, ex.grade))

    # 하향은 최대 1단계(자산밖 + defensive 가 곱으로 겹치지 않게), 상향은 offensive +1.
    delta = _persona_delta(persona, ex.grade, kev, in_scope)
    down = 1 if (in_scope is False or delta < 0) else 0
    up = 1 if delta > 0 else 0
    adjusted = _clamp(base - down + up)

    # KEV floor 를 마지막에 clamp 로 적용.
    floor = _kev_floor(kev, ex.epss)
    final = max(adjusted, floor)
    action = _ACTIONS[final]

    floor_note = ""
    if final > adjusted:
        floor_note = f" · KEV floor applied: {_ACTIONS[adjusted]} → {action}"

    bb.priority.action = action
    bb.priority.timeline = _TIMELINE[action]
    bb.priority.reasoning = (
        f"CVSS={score if score is not None else '미상'} · "
        f"{'KEV' if kev else 'non-KEV'} · "
        f"EPSS={ex.epss if ex.epss is not None else '미확보'} · "
        f"exploit={ex.grade or '미상'} · in_scope={in_scope}{floor_note}"
    )
