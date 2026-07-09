"""Prioritization (규칙 융합) — CVSS·EPSS·KEV·exploitability·in_scope 를 합쳐 조치를 정한다.

전부 규칙 기반(가중치·구간)이며 LLM 을 쓰지 않는다.
  action ∈ immediate | scheduled | monitor, + timeline + reasoning.
  * KEV 등재 또는 높은 EPSS(≥0.5) 또는 (easy 등급 & CVSS≥9) → immediate
  * CVSS≥7 또는 easy/moderate 등급 또는 EPSS≥0.1 → scheduled
  * 그 외 → monitor
  * Context in_scope=False(우리 자산에 없음) → 한 단계 하향
persona 렌즈(선택): offensive 는 악용 실현성을, defensive 는 자산 노출을 더 가중한다.
"""
from __future__ import annotations

from pipeline.agents.base import register
from pipeline.personas import resolve_persona

_ACTIONS = ["monitor", "scheduled", "immediate"]  # 낮음 → 높음
_TIMELINE = {"immediate": "지금 즉시(24h 내)", "scheduled": "이번 주 내", "monitor": "모니터링"}


def _shift(action: str, step: int) -> str:
    i = _ACTIONS.index(action) if action in _ACTIONS else 0
    return _ACTIONS[min(2, max(0, i + step))]


def _fuse(score: float, kev: bool, epss: float | None, grade: str | None) -> str:
    s = score or 0
    if kev or (epss is not None and epss >= 0.5) or (grade == "easy" and s >= 9):
        return "immediate"
    if s >= 7 or grade in ("easy", "moderate") or (epss is not None and epss >= 0.1):
        return "scheduled"
    return "monitor"


def _persona_adjust(action: str, persona, grade: str | None, kev: bool,
                    in_scope: bool | None) -> str:  # noqa: ANN001
    if persona.key == "offensive":
        # 악용 실현성 가중: 실제 악용/쉬운 익스플로잇이면 monitor 로 내려가지 않게
        if (kev or grade == "easy") and action == "monitor":
            return "scheduled"
    elif persona.key == "defensive":
        # 자산 노출 가중: 우리 자산에 없으면 한 단계 더 낮춤(패치 부담 절감)
        if in_scope is False and action != "monitor":
            return _shift(action, -1)
    return action


@register(order=60)
def prioritization(bb, ctx) -> None:  # noqa: ANN001
    enriched = bb.enriched or {}
    score = enriched.get("cvss_score")
    kev = bool(enriched.get("kev"))
    ex = bb.exploitability
    in_scope = bb.context.in_scope

    action = _fuse(score, kev, ex.epss, ex.grade)
    if in_scope is False:
        action = _shift(action, -1)          # 자산에 없으면 하향
    action = _persona_adjust(action, resolve_persona(bb.persona), ex.grade, kev, in_scope)

    bb.priority.action = action
    bb.priority.timeline = _TIMELINE[action]
    bb.priority.reasoning = (
        f"CVSS={score if score is not None else '미상'} · "
        f"{'KEV' if kev else 'non-KEV'} · "
        f"EPSS={ex.epss if ex.epss is not None else '미확보'} · "
        f"exploit={ex.grade or '미상'} · "
        f"in_scope={in_scope}"
    )
