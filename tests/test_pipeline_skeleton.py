"""계층 2 파이프라인 뼈대 테스트 — 7개 스텁이 순서대로 돌고 audit_log 에 남는지,
supervisor 의 handoff 회귀·한도 라우팅이 규격대로 동작하는지 검증한다.
"""
import unittest

from pipeline.agents.base import AgentSpec
from pipeline.state import Blackboard
from pipeline.supervisor import Supervisor, run_pipeline

_EXPECTED_ORDER = [
    "collector", "enrichment", "cross_validation", "exploitability",
    "context", "prioritization", "report",
]


class TestPipelineSkeleton(unittest.TestCase):
    def test_seven_stubs_run_in_order(self):
        bb = Blackboard(cve_id="CVE-2021-44228", persona="공격Agent")
        run_pipeline(bb)
        names = [e["agent"] for e in bb.audit_log]
        self.assertEqual(names, _EXPECTED_ORDER)
        self.assertEqual(len(bb.audit_log), 7)
        self.assertFalse(bb.needs_human_review)
        self.assertIsNone(bb.handoff)

    def test_default_blackboard_shape(self):
        bb = Blackboard(cve_id="CVE-2026-0001")
        self.assertEqual(bb.source_records, [])
        self.assertEqual(bb.enriched, {})
        self.assertEqual(bb.handoff_count, 0)
        self.assertIsNone(bb.exploitability.grade)
        self.assertIsNone(bb.exploitability.epss)
        self.assertIsNone(bb.priority.action)
        self.assertEqual(bb.validation.confidence, 0.0)
        self.assertEqual(bb.report.attack, "")


class TestSupervisorRouting(unittest.TestCase):
    def test_handoff_regresses_then_hits_limit(self):
        calls: list[str] = []

        def a(bb, ctx):
            calls.append("a")

        def b(bb, ctx):
            calls.append("b")
            bb.handoff = "a"  # 매번 a 로 되돌려 달라고 요청

        specs = [AgentSpec("a", 10, a), AgentSpec("b", 20, b)]
        bb = Blackboard(cve_id="X")
        Supervisor(specs).run(bb)

        # b 가 a 로 두 번까지 회귀시킨 뒤 한도 초과 → 사람 검토 플래그, 전진 종료
        self.assertEqual(bb.handoff_count, 2)
        self.assertTrue(bb.needs_human_review)
        self.assertEqual(calls, ["a", "b", "a", "b", "a", "b"])

    def test_node_exception_retries_once_then_skips(self):
        attempts: list[str] = []

        def flaky(bb, ctx):
            attempts.append("x")
            raise RuntimeError("boom")

        specs = [AgentSpec("flaky", 10, flaky)]
        bb = Blackboard(cve_id="X")
        Supervisor(specs).run(bb)

        self.assertEqual(len(attempts), 2)  # 최초 1 + 재시도 1
        self.assertEqual(bb.audit_log[-1]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
