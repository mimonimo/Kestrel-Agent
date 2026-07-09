"""에이전트 레지스트리 — 노드를 데코레이터로 등록하면 파이프라인에 자동 편입된다(pluggable).

각 에이전트는 `(Blackboard, PipelineContext|None) -> None` 시그니처의 콜러블이며,
자기 구획만 채우고 상태를 그대로 통과시킨다. 실행 순서는 order 값으로 정한다.
handoff 라우팅은 에이전트 이름으로 대상을 지정한다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

# 에이전트 콜러블: 상태를 제자리(in place)에서 갱신하고 None 을 반환.
AgentFn = Callable[..., None]


@dataclass(frozen=True)
class AgentSpec:
    name: str
    order: int
    fn: AgentFn


_REGISTRY: dict[str, AgentSpec] = {}


def register(name: str | None = None, *, order: int):
    """노드 등록 데코레이터. name 을 생략하면 함수 이름을 쓴다."""
    def deco(fn: AgentFn) -> AgentFn:
        n = name or fn.__name__
        _REGISTRY[n] = AgentSpec(n, order, fn)
        return fn
    return deco


def registered_agents() -> list[AgentSpec]:
    """등록된 에이전트를 order 오름차순으로 반환(파이프라인 실행 순서)."""
    return sorted(_REGISTRY.values(), key=lambda a: a.order)


def get_agent(name: str) -> AgentSpec | None:
    return _REGISTRY.get(name)
