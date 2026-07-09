"""Prioritization (규칙) — CVSS/EPSS/KEV/exploitability/자산을 융합해 패치 우선순위를
산출한다.

스텁: 다음 단계에서 bb.priority 를 채운다. 지금은 통과만 한다.
"""
from __future__ import annotations

from pipeline.agents.base import register


@register(order=60)
def prioritization(bb, ctx) -> None:  # noqa: ANN001 — 스텁
    pass
