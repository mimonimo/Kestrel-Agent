"""Context (규칙) — 로컬 config 의 사용자 자산 CPE 목록과 매칭해 실제 영향 자산·범위를
판정한다.

스텁: 다음 단계에서 bb.context 를 채운다. 지금은 통과만 한다.
"""
from __future__ import annotations

from pipeline.agents.base import register


@register(order=50)
def context(bb, ctx) -> None:  # noqa: ANN001 — 스텁
    pass
