"""Enrichment·Exploitability·Context·Prioritization + EPSS 소스 — hermetic 검증.

EPSS 실제 호출은 http 주입/ctx.epss_fetch 주입으로 대체(네트워크 없음).
8개 노드 전체 완주(audit 8x ok)와 각 노드가 blackboard 를 채우는지 확인한다.
"""
import os
import tempfile
import unittest

from pipeline import assets as assets_mod
from pipeline.agents.context import context
from pipeline.agents.enrichment import enrichment
from pipeline.agents.exploitability import exploitability
from pipeline.agents.prioritization import prioritization
from pipeline.sources import epss as epss_mod
from pipeline.state import Blackboard, PipelineContext
from pipeline.supervisor import Supervisor

_LOG4 = {
    "cveId": "CVE-2021-44228", "severity": "critical", "cvssScore": 10.0,
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "kevListed": True, "types": ["CWE-917"],
    "products": ["apache log4j2", "cisco fxos", "vmware vcenter"],
    "description": "Apache Log4j2 JNDI lookup remote code execution.",
}


def _bb_with_primary(data=None, persona="분석가Agent"):
    bb = Blackboard(cve_id="CVE-2021-44228", persona=persona)
    bb.source_records.append({"source": "k", "kind": "primary",
                              "cveId": "CVE-2021-44228", "data": dict(data or _LOG4)})
    return bb


class FakeLLM:
    def __init__(self, response="서술 텍스트입니다.", raise_exc=None):
        self.response, self.raise_exc, self.calls = response, raise_exc, []

    def complete(self, system, user, *, max_tokens=1400, effort="medium", model=None):
        self.calls.append({"system": system, "user": user})
        if self.raise_exc:
            raise self.raise_exc
        return self.response


# ── EPSS 소스 ──────────────────────────────────────────────
class TestEpss(unittest.TestCase):
    def test_parse_and_cache(self):
        d = tempfile.mkdtemp()
        hits = []

        def fake_http(cve, timeout):
            hits.append(cve)
            return {"data": [{"cve": cve, "epss": "0.97417", "percentile": "0.99956"}]}

        r1 = epss_mod.fetch_epss("CVE-2021-44228", cache_dir=d, http=fake_http)
        self.assertAlmostEqual(r1["epss"], 0.97417)
        r2 = epss_mod.fetch_epss("CVE-2021-44228", cache_dir=d, http=fake_http)
        self.assertEqual(r2["epss"], r1["epss"])
        self.assertEqual(len(hits), 1)  # 두 번째는 캐시 → http 미호출
        self.assertTrue(os.path.exists(os.path.join(d, "epss_cache.json")))

    def test_empty_data_returns_none(self):
        d = tempfile.mkdtemp()
        r = epss_mod.fetch_epss("CVE-0000-0000", cache_dir=d,
                                http=lambda c, t: {"data": []})
        self.assertIsNone(r)

    def test_network_error_returns_none(self):
        d = tempfile.mkdtemp()

        def boom(c, t):
            raise TimeoutError("down")
        self.assertIsNone(epss_mod.fetch_epss("CVE-1-1", cache_dir=d, http=boom))


# ── Enrichment ─────────────────────────────────────────────
class TestEnrichment(unittest.TestCase):
    def test_normalizes_vector_and_cwe(self):
        bb = _bb_with_primary()
        enrichment(bb, PipelineContext())
        en = bb.enriched
        self.assertEqual(en["cvss_metrics"]["AV"], "N")
        self.assertEqual(en["cvss_metrics"]["S"], "C")
        self.assertEqual(en["cwes"], ["CWE-917"])
        self.assertTrue(en["kev"])
        self.assertEqual(en["cvss_base_recomputed"], 10.0)

    def test_prefers_adopted_values(self):
        bb = _bb_with_primary()
        bb.validation.adopted_values = {"severity": "high", "cvssScore": 7.5}
        enrichment(bb, PipelineContext())
        self.assertEqual(bb.enriched["severity"], "high")
        self.assertEqual(bb.enriched["cvss_score"], 7.5)


# ── Exploitability ─────────────────────────────────────────
class TestExploitability(unittest.TestCase):
    def _ctx(self, epss=None, llm=None):
        return PipelineContext(epss_fetch=lambda cid: ({"epss": epss} if epss is not None else None),
                               llm=llm)

    def test_kev_forces_easy(self):
        bb = _bb_with_primary()
        enrichment(bb, PipelineContext())
        exploitability(bb, self._ctx(epss=0.97))
        self.assertEqual(bb.exploitability.grade, "easy")
        self.assertAlmostEqual(bb.exploitability.epss, 0.97)
        self.assertIsNone(bb.exploitability.poc_available)

    def test_epss_unavailable_noted(self):
        rec = dict(_LOG4, kevListed=False)
        bb = _bb_with_primary(rec)
        enrichment(bb, PipelineContext())
        exploitability(bb, self._ctx(epss=None))
        self.assertIn("EPSS unavailable", bb.exploitability.reasoning)

    def test_high_friction_vector_is_harder(self):
        rec = dict(_LOG4, kevListed=False,
                   cvssVector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H")
        bb = _bb_with_primary(rec)
        enrichment(bb, PipelineContext())
        exploitability(bb, self._ctx(epss=0.01))  # 낮은 EPSS → 더 어렵게
        self.assertEqual(bb.exploitability.grade, "hard")

    def test_llm_narrative_and_failure(self):
        bb = _bb_with_primary()
        enrichment(bb, PipelineContext())
        exploitability(bb, self._ctx(epss=0.9, llm=FakeLLM("공격 난이도 서술")))
        self.assertEqual(bb.exploitability.narrative, "공격 난이도 서술")
        # 실패해도 등급 유지, 서술만 빔, needs_retry 는 안 걸림
        bb2 = _bb_with_primary()
        enrichment(bb2, PipelineContext())
        exploitability(bb2, self._ctx(epss=0.9, llm=FakeLLM(raise_exc=TimeoutError())))
        self.assertEqual(bb2.exploitability.grade, "easy")
        self.assertEqual(bb2.exploitability.narrative, "")
        self.assertFalse(bb2.needs_retry)


# ── Context ────────────────────────────────────────────────
class TestContext(unittest.TestCase):
    def test_in_scope_true_when_asset_matches(self):
        bb = _bb_with_primary()
        enrichment(bb, PipelineContext())
        ctx = PipelineContext(assets=["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"])
        context(bb, ctx)
        self.assertTrue(bb.context.in_scope)
        self.assertEqual(len(bb.context.affected_assets), 1)

    def test_in_scope_false_when_no_match(self):
        bb = _bb_with_primary()
        enrichment(bb, PipelineContext())
        context(bb, PipelineContext(assets=["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"]))
        self.assertFalse(bb.context.in_scope)
        self.assertEqual(bb.context.affected_assets, [])

    def test_no_assets_is_none(self):
        bb = _bb_with_primary()
        enrichment(bb, PipelineContext())
        context(bb, PipelineContext(assets=[]))  # 빈 목록 + 기본 파일 없음
        self.assertIsNone(bb.context.in_scope)

    def test_load_assets_simple_yaml(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "assets.yaml")
        with open(p, "w", encoding="utf-8") as f:
            f.write("# 주석\nassets:\n  - cpe:2.3:a:apache:log4j:x\n  - \"Apache Log4j2\"\n")
        self.assertEqual(assets_mod.load_assets(p),
                         ["cpe:2.3:a:apache:log4j:x", "Apache Log4j2"])


# ── Prioritization ─────────────────────────────────────────
class TestPrioritization(unittest.TestCase):
    def _prep(self, persona="분석가Agent", epss=0.97, in_scope=None):
        bb = _bb_with_primary(persona=persona)
        enrichment(bb, PipelineContext())
        exploitability(bb, PipelineContext(epss_fetch=lambda cid: {"epss": epss}))
        bb.context.in_scope = in_scope
        return bb

    def test_kev_high_epss_immediate(self):
        bb = self._prep()
        prioritization(bb, PipelineContext())
        self.assertEqual(bb.priority.action, "immediate")
        self.assertIn("KEV", bb.priority.reasoning)

    def _prep_nonkev(self, persona="분석가Agent", epss=0.6, in_scope=None):
        rec = dict(_LOG4, kevListed=False, cvssScore=8.0)
        bb = _bb_with_primary(rec, persona=persona)
        enrichment(bb, PipelineContext())
        exploitability(bb, PipelineContext(epss_fetch=lambda cid: {"epss": epss}))
        bb.context.in_scope = in_scope
        return bb

    def test_out_of_scope_downgrades_non_kev(self):
        bb = self._prep_nonkev(in_scope=False)  # immediate(EPSS≥0.5) → 한 단계 하향
        prioritization(bb, PipelineContext())
        self.assertEqual(bb.priority.action, "scheduled")

    def test_double_downgrade_capped_at_one_step(self):
        # non-KEV, in_scope=False + defensive → 두 하향이 겹쳐도 최대 1단계(monitor 아님)
        bb = self._prep_nonkev(persona="방어Agent", in_scope=False)
        prioritization(bb, PipelineContext())
        self.assertEqual(bb.priority.action, "scheduled")

    def test_kev_floor_prevents_monitor(self):
        # 핵심 회귀 방지: KEV + in_scope=False + defensive 라도 monitor 로 안 내려감
        bb = self._prep(persona="방어Agent", epss=0.3, in_scope=False)  # EPSS<0.9
        prioritization(bb, PipelineContext())
        self.assertEqual(bb.priority.action, "scheduled")
        self.assertNotEqual(bb.priority.action, "monitor")

    def test_kev_high_epss_floor_to_immediate(self):
        bb = self._prep(persona="방어Agent", epss=0.99, in_scope=False)
        prioritization(bb, PipelineContext())
        self.assertEqual(bb.priority.action, "immediate")
        self.assertIn("KEV floor applied", bb.priority.reasoning)

    def test_non_kev_has_no_floor(self):
        # KEV=False 는 기존 하향 로직 그대로(floor 없음) — monitor 까지 내려갈 수 있음
        rec = dict(_LOG4, kevListed=False, cvssScore=5.0,
                   cvssVector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        bb = _bb_with_primary(rec, persona="방어Agent")
        enrichment(bb, PipelineContext())
        exploitability(bb, PipelineContext(epss_fetch=lambda cid: {"epss": 0.2}))
        bb.context.in_scope = False
        prioritization(bb, PipelineContext())
        self.assertEqual(bb.priority.action, "monitor")
        self.assertNotIn("KEV floor", bb.priority.reasoning)

    def test_persona_offensive_vs_defensive_diverge(self):
        # 저심각·비KEV·자산밖 경계 케이스에서 관점이 갈리게
        rec = dict(_LOG4, kevListed=False, cvssScore=5.0,
                   cvssVector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        def prep(persona):
            bb = _bb_with_primary(rec, persona=persona)
            enrichment(bb, PipelineContext())
            exploitability(bb, PipelineContext(epss_fetch=lambda cid: {"epss": 0.2}))
            bb.context.in_scope = False
            prioritization(bb, PipelineContext())
            return bb.priority.action
        # 둘 다 자산밖이라 base 는 monitor 로 내려가지만, offensive 는 easy 등급이라 scheduled 로
        # 되돌리고 defensive 는 monitor 유지 → 관점이 갈린다.
        self.assertEqual(prep("공격Agent"), "scheduled")
        self.assertEqual(prep("방어Agent"), "monitor")


# ── 8개 노드 전체 완주 ─────────────────────────────────────
class FakeKestrel:
    def get_cve(self, cid):
        return dict(_LOG4)

    def related(self, cid):
        return []


class TestFullPipeline(unittest.TestCase):
    def test_all_nodes_ok_and_filled(self):
        d = tempfile.mkdtemp()
        ctx = PipelineContext(
            kestrel=FakeKestrel(), llm=FakeLLM("서술"), data_dir=d,
            epss_fetch=lambda cid: {"epss": 0.97, "percentile": 0.99},
            assets=["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
        )
        bb = Blackboard(cve_id="CVE-2021-44228", persona="방어Agent")
        Supervisor().run(bb, ctx)

        names_status = [(e["agent"], e["status"]) for e in bb.audit_log]
        self.assertEqual(
            names_status,
            [("collector", "ok"), ("enrichment", "ok"), ("cross_validation", "ok"),
             ("exploitability", "ok"), ("context", "ok"), ("prioritization", "ok"),
             ("report", "ok"), ("verification", "ok")])
        self.assertFalse(bb.needs_human_review)
        # 각 노드가 실제로 값을 채웠는지
        self.assertTrue(bb.enriched["cvss_metrics"])
        self.assertEqual(bb.validation.confidence, 1.0)
        self.assertEqual(bb.exploitability.grade, "easy")
        self.assertAlmostEqual(bb.exploitability.epss, 0.97)
        self.assertTrue(bb.context.in_scope)
        self.assertEqual(bb.priority.action, "immediate")
        self.assertTrue(bb.report.attack)


if __name__ == "__main__":
    unittest.main()
