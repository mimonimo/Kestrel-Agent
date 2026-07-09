"""Supervisor — 등록된 에이전트를 순차 실행하고 handoff 라우팅·재시도·감사를 관장한다.

동작 규격:
  - 순차 실행: registered_agents() 순서(order)대로 각 노드를 실행.
  - handoff 회귀: 노드가 bb.handoff 에 대상 이름을 남기면 그 노드로 되돌아간다.
    누적 회귀는 _MAX_HANDOFFS(=2)회까지 허용하고, 초과하면 회귀하지 않고
    needs_human_review=True 로 두고 계속 전진한다.
  - 노드 예외: 1회 재시도 후에도 실패하면 그 노드를 건너뛴다(파이프라인은 계속).
  - 감사: 모든 노드 실행 결과를 bb.audit_log 에 {agent, status} 로 기록한다.
"""
from __future__ import annotations

from pipeline import agents as _agents  # noqa: F401 — import 부작용으로 스텁 7개 등록
from pipeline.agents.base import AgentSpec, registered_agents
from pipeline.state import Blackboard, PipelineContext

_MAX_HANDOFFS = 2


class Supervisor:
    def __init__(self, agents: list[AgentSpec] | None = None):
        self._agents = agents if agents is not None else registered_agents()
        self._index = {a.name: i for i, a in enumerate(self._agents)}

    def run(self, bb: Blackboard, ctx: PipelineContext | None = None) -> Blackboard:
        i = 0
        n = len(self._agents)
        while i < n:
            spec = self._agents[i]
            status = self._run_one(spec, bb, ctx)
            bb.audit_log.append({"agent": spec.name, "status": status})

            target = bb.handoff
            bb.handoff = None
            if target is not None and target in self._index:
                if bb.handoff_count < _MAX_HANDOFFS:
                    bb.handoff_count += 1
                    bb.audit_log.append(
                        {"agent": spec.name, "status": f"handoff→{target}"})
                    i = self._index[target]
                    continue
                # 한도 초과 — 회귀하지 않고 사람 검토 플래그 후 전진
                bb.needs_human_review = True
                bb.audit_log.append(
                    {"agent": spec.name, "status": "handoff-limit"})
            i += 1
        return bb

    @staticmethod
    def _run_one(spec: AgentSpec, bb: Blackboard, ctx: PipelineContext | None) -> str:
        """노드 1회 실행 + 실패 시 1회 재시도. 성공 'ok', 최종 실패 'skipped'."""
        for attempt in range(2):
            try:
                spec.fn(bb, ctx)
                return "ok"
            except Exception:  # noqa: BLE001 — 어떤 노드 오류든 격리해 파이프라인 유지
                if attempt == 0:
                    continue
                return "skipped"
        return "skipped"


def run_pipeline(bb: Blackboard, ctx: PipelineContext | None = None) -> Blackboard:
    """기본(등록된 7개 노드) 파이프라인을 한 번 실행한다."""
    return Supervisor().run(bb, ctx)
