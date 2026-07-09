"""Report (로컬 LLM) — 앞선 노드들의 결과를 근거로 페르소나 렌즈의 자연어 공격/완화
리포트를 생성한다(기존 llm.py 백엔드 사용).

스텁: 다음 단계에서 bb.report 를 채운다. 지금은 통과만 한다.
"""
from __future__ import annotations

from pipeline.agents.base import register


@register(order=70)
def report(bb, ctx) -> None:  # noqa: ANN001 — 스텁
    pass
