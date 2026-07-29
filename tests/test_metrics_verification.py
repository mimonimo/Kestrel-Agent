"""품질 지표(metrics)·검증 노드(verification)·런 이벤트(analytics) 테스트.

논문 수치의 원천이므로 '지표가 실제로 그 현상을 잡는지'를 직접 확인한다.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analytics  # noqa: E402
from pipeline import metrics  # noqa: E402
from pipeline.agents.verification import _compute, _evaluate, verification  # noqa: E402
from pipeline.state import Blackboard, PipelineContext  # noqa: E402

_FACTS = "- CVE: CVE-2025-38322\n- 설명: NULL pointer dereference in net subsystem."


def _bb(**over) -> Blackboard:
    bb = Blackboard(cve_id="CVE-2025-38322", persona="방어Agent")
    bb.source_records = [{"kind": "primary", "data": {
        "cveId": "CVE-2025-38322", "severity": "medium", "cvssScore": 5.5,
        "cvssVector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        "types": ["CWE-476"], "products": ["Linux Kernel"], "kevListed": False,
        "description": "NULL pointer dereference in the net subsystem." * 4}}]
    bb.exploitability.epss = 0.00042
    bb.exploitability.grade = "hard"
    bb.priority.action = "monitor"
    bb.validation.confidence = 1.0
    bb.report.facts = _FACTS
    bb.report.attack = over.get("attack", "트리거 조건과 공격 단계를 서술합니다. " * 6)
    bb.report.impact = over.get("impact", "가용성 저하가 발생합니다. " * 6)
    bb.report.chaining = over.get("chaining", "정보노출에서 권한상승으로 이어집니다. " * 6)
    bb.report.detection = over.get("detection", "/var/log/kern.log 에서 (?i)null 패턴. " * 6)
    bb.report.mitigation = over.get("mitigation", "sysctl 로 차단 후 6.6.1 로 업그레이드. " * 6)
    bb.report.meta = {"persona": "defensive", "model": "test", "elapsed_sec": 1.0}
    return bb


class TestMetrics(unittest.TestCase):
    def test_ungrounded_cve_detected(self):
        """사실 블록에 없는 CVE 번호를 잡아낸다(환각의 검증 가능한 형태)."""
        body = "이 결함은 CVE-2019-11477 과 CVE-2021-4034 로 이어집니다."
        self.assertEqual(metrics.ungrounded_cves(body, _FACTS, "CVE-2025-38322"),
                         ["CVE-2019-11477", "CVE-2021-4034"])

    def test_target_and_fact_cves_are_grounded(self):
        """대상 CVE 와 사실 블록에 있는 CVE 는 환각이 아니다."""
        body = "CVE-2025-38322 은 NULL 역참조입니다."
        self.assertEqual(metrics.ungrounded_cves(body, _FACTS, "CVE-2025-38322"), [])

    def test_section_completeness_flags_thin_sections(self):
        out = metrics.section_completeness(
            {"attack": "가" * 200, "impact": "짧음", "chaining": "", "detection": "나" * 200,
             "mitigation": "다" * 200})
        self.assertEqual(sorted(out["missing_sections"]), ["chaining", "impact"])
        self.assertAlmostEqual(out["complete_ratio"], 0.6)

    def test_specificity_counts_concrete_artifacts(self):
        rich = metrics.specificity("index=linux sourcetype=kern (?i)null.* /var/log/kern.log "
                                   "sudo sysctl -w 6.6.1")
        thin = metrics.specificity("주의가 필요합니다. 패치를 권장합니다.")
        self.assertGreater(rich["specificity_total"], thin["specificity_total"])
        self.assertGreater(rich["specificity_kinds"], thin["specificity_kinds"])

    def test_novelty_none_without_peers(self):
        """peer 가 없으면 '측정 불가'(None) — 겹침 0 과 구분돼야 집계가 왜곡되지 않는다."""
        self.assertIsNone(metrics.novelty("아무 내용", [])["novel_ratio"])

    def test_novelty_detects_copying(self):
        peer = "공격자는 NULL 역참조로 커널 패닉을 유발합니다."
        copied = metrics.novelty(peer, [peer])["novel_ratio"]
        fresh = metrics.novelty("전혀 다른 탐지 규칙과 SIEM 쿼리를 제시합니다.", [peer])["novel_ratio"]
        self.assertEqual(copied, 0.0)
        self.assertGreater(fresh, 0.9)

    def test_evidence_citation(self):
        out = metrics.evidence_citation(
            "EPSS 0.00042 는 낮습니다. 교차검증에서 다중 소스 일관성이 확인됐고 모니터링 대상입니다.",
            epss=0.00042, priority_action="monitor", validation_confidence=1.0)
        self.assertTrue(out["epss_cited"])
        self.assertTrue(out["priority_cited"])
        self.assertTrue(out["validation_cited"])


class TestVerification(unittest.TestCase):
    def test_clean_report_passes_without_llm(self):
        """통과하는 리포트는 LLM 을 전혀 부르지 않는다(GPU 비용 0)."""
        bb = _bb()
        calls = []

        class LLM:
            def complete(self, *a, **k):
                calls.append(1)
                return ""

        verification(bb, PipelineContext(llm=LLM()))
        self.assertTrue(bb.verification.passed)
        self.assertEqual(calls, [])
        self.assertFalse(bb.verification.repaired)

    def test_hallucinated_cve_triggers_repair(self):
        bb = _bb(chaining="CVE-2019-11477 로 이어집니다. " * 6)
        checks, failures = _evaluate(_compute(bb))
        self.assertFalse(checks["ungrounded_cve"])
        self.assertIn("ungrounded_cve", failures)

        clean = ("SUMMARY_EN: Null pointer dereference.\n"
                 "## 공격 기법\n" + "공격 서술. " * 20 + "\n"
                 "## 영향 분석\n" + "영향 서술. " * 20 + "\n"
                 "## 관련 취약점·체이닝\n" + "추정: 유형 수준의 체이닝만 서술. " * 10 + "\n"
                 "## 탐지\n" + "탐지 서술. " * 20 + "\n"
                 "## 완화 방안\n" + "완화 서술. " * 20 + "\n")

        class LLM:
            def complete(self, *a, **k):
                return clean

        verification(bb, PipelineContext(llm=LLM()))
        self.assertTrue(bb.verification.repaired)
        self.assertTrue(bb.verification.passed)       # 수리 후 환각 사라짐
        self.assertFalse(bb.needs_human_review)

    def test_repair_failure_keeps_original(self):
        """수리가 실패해도 원본을 버리지 않는다(더 나빠지지 않게)."""
        bb = _bb(chaining="CVE-2019-11477 로 이어집니다. " * 6)
        original = bb.report.chaining

        class LLM:
            def complete(self, *a, **k):
                raise RuntimeError("타임아웃")

        verification(bb, PipelineContext(llm=LLM()))
        self.assertEqual(bb.report.chaining, original)
        self.assertIn("타임아웃", bb.verification.repair_error)
        self.assertTrue(bb.needs_human_review)        # 환각이 남았으므로 사람 검토 대상

    def test_verify_disabled_still_records_metrics(self):
        """ablation(verify_report=False)에서도 지표는 남아야 비교가 가능하다."""
        bb = _bb(chaining="CVE-2019-11477 로 이어집니다. " * 6)
        verification(bb, PipelineContext(llm=None, verify_report=False))
        self.assertEqual(bb.verification.metrics["ungrounded_cve_count"], 1)
        self.assertEqual(bb.verification.failures, [])   # 게이트 미적용
        self.assertFalse(bb.needs_human_review)

    def test_no_report_is_noop(self):
        bb = Blackboard(cve_id="CVE-2025-1", persona="방어Agent")
        verification(bb, PipelineContext(llm=None))
        self.assertEqual(bb.verification.metrics, {})


class TestRunEvent(unittest.TestCase):
    class _Cfg:
        peer_reference = True
        verify_report = True
        community_cadence = "balanced"
        interval = 400
        analysis_only = False
        arm = "platform"

    def test_event_captures_peer_exposure(self):
        """플랫폼 이점의 독립변수(peer 노출량)가 반드시 보존된다."""
        bb = _bb()
        bb.report.peer_personas = ["offensive", "analyst"]
        bb.report.peer_excerpts = ["공격 관점 요지", "중립 요지"]
        verification(bb, PipelineContext(llm=None))
        ev = analytics.build_run_event(bb, agent_tag="방어Agent", cfg=self._Cfg(),
                                       pipeline_version="v1")
        self.assertEqual(ev["peer_ref_used"], 2)
        self.assertEqual(ev["peer_personas"], ["offensive", "analyst"])
        self.assertEqual(ev["arm"], "platform")
        self.assertTrue(ev["config"]["peer_reference"])
        self.assertIn("specificity_total", ev["metrics"])
        self.assertIsNotNone(ev["metrics"]["novel_ratio"])  # peer 있으므로 측정됨

    def test_append_writes_one_json_line(self):
        d = tempfile.mkdtemp()
        analytics.append({"a": 1}, d)
        analytics.append({"a": 2}, d)
        lines = analytics.events_path(d).read_text(encoding="utf-8").splitlines()
        self.assertEqual([json.loads(x)["a"] for x in lines], [1, 2])

    def test_append_never_raises(self):
        """계측 실패가 봇 운영을 멈추면 안 된다."""
        analytics.append({"bad": object()}, "/nonexistent/path/xyz")


if __name__ == "__main__":
    unittest.main()
