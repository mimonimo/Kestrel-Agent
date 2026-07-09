"""Collector 실구현 + Cross-Validation 결정론 규칙 검증."""
import json
import os
import tempfile
import unittest

from pipeline import cvss
from pipeline.agents.collector import collector
from pipeline.agents.cross_validation import cross_validation
from pipeline.state import Blackboard, PipelineContext
from pipeline.supervisor import Supervisor

# CVE-2021-44228(Log4Shell) 실제 값과 동형의 일관된 레코드
_LOG4SHELL = {
    "cveId": "CVE-2021-44228",
    "title": "Apache Log4j2 JNDI RCE",
    "severity": "critical",
    "cvssScore": 10.0,
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "kevListed": True,
    "description": "Apache Log4j2 JNDI features do not protect against attacker "
                   "controlled LDAP and other JNDI related endpoints (remote code execution).",
    "types": ["CWE-502", "CWE-917"],
    "products": ["Apache Log4j2"],
}


class FakeKestrel:
    def __init__(self, detail, related=None, related_error=False):
        self._detail = detail
        self._related = related or []
        self._related_error = related_error

    def get_cve(self, cve_id):
        return dict(self._detail)

    def related(self, cve_id):
        if self._related_error:
            raise RuntimeError("related down")
        return self._related


def _record(bb, data, kind="primary"):
    bb.source_records.append(
        {"source": "kestrel", "kind": kind, "cveId": data.get("cveId"), "data": data})


# ── CVSS 계산 ──────────────────────────────────────────────
class TestCvss(unittest.TestCase):
    def test_parse_and_base_log4shell(self):
        m = cvss.parse_vector(_LOG4SHELL["cvssVector"])
        self.assertEqual(m["S"], "C")
        self.assertEqual(cvss.base_score(m), 10.0)

    def test_base_medium_example(self):
        m = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N")
        self.assertEqual(cvss.base_score(m), 4.3)

    def test_invalid_vector(self):
        self.assertIsNone(cvss.parse_vector("not-a-vector"))
        self.assertIsNone(cvss.parse_vector("CVSS:2.0/AV:N"))
        self.assertIsNone(cvss.parse_vector("CVSS:3.1/AVN/AC:L"))

    def test_missing_metrics_no_score(self):
        self.assertIsNone(cvss.base_score({"AV": "N"}))

    def test_severity_band(self):
        self.assertEqual(cvss.severity_band(10.0), "critical")
        self.assertEqual(cvss.severity_band(8.9), "high")
        self.assertEqual(cvss.severity_band(4.0), "medium")
        self.assertEqual(cvss.severity_band(3.9), "low")
        self.assertEqual(cvss.severity_band(0.0), "none")
        self.assertIsNone(cvss.severity_band(None))


# ── Collector ──────────────────────────────────────────────
class TestCollector(unittest.TestCase):
    def test_fills_primary_and_related(self):
        rel = [{"cveId": "CVE-2021-45046"}, {"cveId": "CVE-2021-45105"}]
        ctx = PipelineContext(kestrel=FakeKestrel(_LOG4SHELL, related=rel))
        bb = Blackboard(cve_id="CVE-2021-44228")
        collector(bb, ctx)
        kinds = [r["kind"] for r in bb.source_records]
        self.assertEqual(kinds, ["primary", "related", "related"])
        self.assertEqual(bb.primary_record()["cveId"], "CVE-2021-44228")

    def test_related_failure_still_keeps_primary(self):
        ctx = PipelineContext(kestrel=FakeKestrel(_LOG4SHELL, related_error=True))
        bb = Blackboard(cve_id="CVE-2021-44228")
        collector(bb, ctx)
        self.assertEqual([r["kind"] for r in bb.source_records], ["primary"])

    def test_no_kestrel_passes_through(self):
        bb = Blackboard(cve_id="CVE-2021-44228")
        collector(bb, None)
        self.assertEqual(bb.source_records, [])


# ── Cross-Validation ───────────────────────────────────────
class TestCrossValidation(unittest.TestCase):
    def _ctx(self):
        d = tempfile.mkdtemp()
        return PipelineContext(data_dir=d), d

    def test_consistent_record_full_confidence(self):
        ctx, d = self._ctx()
        bb = Blackboard(cve_id="CVE-2021-44228")
        _record(bb, _LOG4SHELL)
        cross_validation(bb, ctx)
        self.assertEqual(bb.validation.confidence, 1.0)
        self.assertEqual(bb.validation.mismatches, [])
        self.assertIsNone(bb.handoff)
        self.assertEqual(bb.validation.adopted_values["severity"], "critical")

    def test_inconsistent_record_mismatch_and_handoff(self):
        ctx, d = self._ctx()
        bad = dict(_LOG4SHELL, severity="critical", cvssScore=3.0,
                   products=["Windows Kernel"],
                   description="Apache Log4j2 JNDI lookup remote code execution")
        bb = Blackboard(cve_id="CVE-2021-44228")
        _record(bb, bad)
        cross_validation(bb, ctx)
        # confidence 는 확정 3규칙만: severity-score·vector-score 실패, vector-format 통과 → 1/3
        self.assertEqual(bb.validation.confidence, 0.333)
        rules = {m["rule"] for m in bb.validation.mismatches}
        self.assertEqual(rules, {"severity_score_band", "vector_score_match"})
        # products 불일치는 mismatches 가 아니라 quality_flags 로만
        self.assertNotIn("products_description", rules)
        self.assertIn("products_description",
                      {q["rule"] for q in bb.validation.quality_flags})
        self.assertEqual(bb.handoff, "enrichment")
        self.assertEqual(bb.validation.adopted_values["severity"], "critical")

    def test_products_mismatch_is_quality_flag_not_confidence(self):
        """products↔description 불일치만 있으면 confidence 는 1.0(3규칙 통과), handoff 없음."""
        ctx, d = self._ctx()
        rec = dict(_LOG4SHELL, products=["Totally Unrelated Widget"])
        bb = Blackboard(cve_id="CVE-2021-44228")
        _record(bb, rec)
        cross_validation(bb, ctx)
        self.assertEqual(bb.validation.confidence, 1.0)
        self.assertIsNone(bb.handoff)
        self.assertFalse(bb.needs_human_review)
        self.assertEqual(bb.validation.mismatches, [])
        self.assertIn("products_description",
                      {q["rule"] for q in bb.validation.quality_flags})

    def test_supply_chain_context_in_quality_flag(self):
        """Log4Shell 실데이터형(다운스트림 벤더 다수 + 라이브러리성 CWE) → 공급망 신호 표시."""
        ctx, d = self._ctx()
        rec = dict(_LOG4SHELL,
                   products=["cisco fxos", "siemens 6bk1602_firmware", "vmware vcenter",
                             "ibm qradar", "cisco ucs"],
                   types=["CWE-917"])
        bb = Blackboard(cve_id="CVE-2021-44228")
        _record(bb, rec)
        cross_validation(bb, ctx)
        self.assertEqual(bb.validation.confidence, 1.0)  # 확정 3규칙엔 영향 없음
        self.assertIsNone(bb.handoff)
        flag = next(q for q in bb.validation.quality_flags
                    if q["rule"] == "products_description")
        self.assertEqual(flag["products_count"], 5)
        self.assertTrue(flag["library_like_cwe"])       # CWE-917
        self.assertTrue(flag["likely_supply_chain"])

    def test_no_data_is_noop(self):
        ctx, d = self._ctx()
        bb = Blackboard(cve_id="CVE-9999-0000")  # source_records 비어 있음
        cross_validation(bb, ctx)
        self.assertIsNone(bb.handoff)
        self.assertEqual(bb.validation.mismatches, [])
        self.assertFalse(os.path.exists(os.path.join(d, "validation_events.jsonl")))

    def test_event_logged_to_jsonl(self):
        ctx, d = self._ctx()
        bb = Blackboard(cve_id="CVE-2021-44228")
        _record(bb, _LOG4SHELL)
        cross_validation(bb, ctx)
        path = os.path.join(d, "validation_events.jsonl")
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), 1)
        ev = json.loads(lines[0])
        self.assertEqual(ev["cveId"], "CVE-2021-44228")
        self.assertEqual(ev["confidence"], 1.0)
        self.assertIn("ts", ev)
        # confidence 규칙(3개)과 quality_flags 가 분리 기록됨
        self.assertEqual([r["rule"] for r in ev["rules"]],
                         ["severity_score_band", "vector_format", "vector_score_match"])
        self.assertIn("quality_flags", ev)


# ── 엔드투엔드(supervisor 경유) ────────────────────────────
class TestEndToEnd(unittest.TestCase):
    def test_full_pipeline_consistent(self):
        d = tempfile.mkdtemp()
        ctx = PipelineContext(kestrel=FakeKestrel(_LOG4SHELL), data_dir=d,
                              epss_fetch=lambda cid: None)  # 네트워크 차단(hermetic)
        bb = Blackboard(cve_id="CVE-2021-44228", persona="공격Agent")
        Supervisor().run(bb, ctx)
        self.assertEqual(bb.validation.confidence, 1.0)
        self.assertFalse(bb.needs_human_review)
        # 7개 노드가 최소 한 번씩(회귀 없음) 실행
        self.assertEqual(
            [e["agent"] for e in bb.audit_log],
            ["collector", "enrichment", "cross_validation", "exploitability",
             "context", "prioritization", "report"])

    def test_full_pipeline_inconsistent_escalates(self):
        d = tempfile.mkdtemp()
        bad = dict(_LOG4SHELL, cvssScore=2.0)  # severity critical ↔ score low
        ctx = PipelineContext(kestrel=FakeKestrel(bad), data_dir=d,
                              epss_fetch=lambda cid: None)  # 네트워크 차단(hermetic)
        bb = Blackboard(cve_id="CVE-2021-44228")
        Supervisor().run(bb, ctx)
        # cross_validation 이 enrichment 로 반복 회귀 → 한도 초과 → 사람 검토
        self.assertTrue(bb.needs_human_review)
        self.assertEqual(bb.handoff_count, 2)


if __name__ == "__main__":
    unittest.main()
