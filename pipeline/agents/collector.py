"""Collector (규칙) — kestrel_client 의 get_cve/related 로 다중소스 원본을 수집한다.

스텁: 다음 단계에서 bb.source_records 를 채운다. 지금은 통과만 한다.
"""
from __future__ import annotations

from pipeline.agents.base import register


@register(order=10)
def collector(bb, ctx) -> None:  # noqa: ANN001 — 스텁
    pass
