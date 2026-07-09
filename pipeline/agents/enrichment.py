"""Enrichment (규칙) — CVSS 벡터/점수·CWE·CPE 를 정규화한다.

스텁: 다음 단계에서 bb.enriched 를 채운다. 지금은 통과만 한다.
"""
from __future__ import annotations

from pipeline.agents.base import register


@register(order=20)
def enrichment(bb, ctx) -> None:  # noqa: ANN001 — 스텁
    pass
