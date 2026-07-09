"""Cross-Validation (결정론 규칙, LLM 없음) — 소스 간 불일치 탐지 + 보수적 채택 +
규칙 기반 confidence 산출.

스텁: 다음 단계에서 bb.validation 을 채운다. 지금은 통과만 한다.
"""
from __future__ import annotations

from pipeline.agents.base import register


@register(order=30)
def cross_validation(bb, ctx) -> None:  # noqa: ANN001 — 스텁
    pass
