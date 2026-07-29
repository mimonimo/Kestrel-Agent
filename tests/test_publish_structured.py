"""구조화 필드 송신 — publish_analysis 확장(클라이언트)과 파이프라인 게시 경로(agent) 검증.

플랫폼 POST /agent/analyses 가 수용하는 9개 optional 필드(camelCase)를
① kestrel_client.publish_analysis 가 요청 body 에 올바르게 싣는지(하위 호환 포함),
② USE_PIPELINE=True 봇 경로가 blackboard 값을 올바른 필드로 매핑해 보내는지 본다.
전부 mock — 라이브 게시 금지(커뮤니티 오염 방지).
"""
import pathlib
import sys
import tempfile
import unittest

sys.argv = ["agent.py"]
import agent as A          # noqa: E402
import config as C         # noqa: E402
import kestrel_client as KC                        # noqa: E402
import pipeline.agents.cross_validation as cvmod   # noqa: E402
import pipeline.sources.epss as epssmod            # noqa: E402

# ─── ① kestrel_client.publish_analysis 확장 ─────────────────────────────


class RecordingKestrel(KC.Kestrel):
    """_request 를 가로채 실제 요청 body 만 기록(네트워크 없음)."""

    def __init__(self):
        super().__init__(api="http://test", token="t")
        self.calls = []

    def _request(self, method, path, body=None):
        self.calls.append((method, path, body))
        return {"id": "A1"}


class TestPublishAnalysisStructuredFields(unittest.TestCase):
    def test_structured_fields_sent_as_camelcase(self):
        k = RecordingKestrel()
        k.publish_analysis(
            "CVE-2021-44228", "본문", title="제목",
            epss_score=0.99999, epss_percentile=0.99997,
            priority_action="immediate", priority_reasoning="KEV floor applied",
            kev_listed=True, validation_confidence=1.0,
            exploitability_grade="easy",
            quality_flags={"products_description": {"likely_supply_chain": True}},
            pipeline_version="kestrel-agent-pipeline-v1",
        )
        method, path, body = k.calls[0]
        self.assertEqual((method, path), ("POST", "/agent/analyses"))
        self.assertEqual(body["cveId"], "CVE-2021-44228")
        self.assertEqual(body["contentMd"], "본문")
        self.assertEqual(body["title"], "제목")
        self.assertEqual(body["epssScore"], 0.99999)
        self.assertEqual(body["epssPercentile"], 0.99997)
        self.assertEqual(body["priorityAction"], "immediate")
        self.assertEqual(body["priorityReasoning"], "KEV floor applied")
        self.assertIs(body["kevListed"], True)
        self.assertEqual(body["validationConfidence"], 1.0)
        self.assertEqual(body["exploitabilityGrade"], "easy")
        self.assertEqual(body["qualityFlags"],
                         {"products_description": {"likely_supply_chain": True}})
        self.assertEqual(body["pipelineVersion"], "kestrel-agent-pipeline-v1")

    def test_none_fields_omitted_from_body(self):
        k = RecordingKestrel()
        k.publish_analysis("CVE-2020-1", "본문", epss_score=0.5)
        _, _, body = k.calls[0]
        self.assertEqual(body["epssScore"], 0.5)
        for absent in ("epssPercentile", "priorityAction", "priorityReasoning",
                       "kevListed", "validationConfidence", "exploitabilityGrade",
                       "qualityFlags", "pipelineVersion", "title"):
            self.assertNotIn(absent, body)

    def test_backward_compat_positional_call(self):
        """기존 호출(cveId, contentMd, title)만으로 예전과 동일한 body."""
        k = RecordingKestrel()
        k.publish_analysis("CVE-2020-1", "본문", "제목")
        _, _, body = k.calls[0]
        self.assertEqual(body, {"cveId": "CVE-2020-1", "contentMd": "본문",
                                "title": "제목"})

    def test_false_and_zero_values_are_sent(self):
        """kevListed=False, epssScore=0.0 같은 falsy 값은 생략이 아니라 전송돼야 한다."""
        k = RecordingKestrel()
        k.publish_analysis("CVE-2020-1", "본문", kev_listed=False,
                           epss_score=0.0, validation_confidence=0.0)
        _, _, body = k.calls[0]
        self.assertIs(body["kevListed"], False)
        self.assertEqual(body["epssScore"], 0.0)
        self.assertEqual(body["validationConfidence"], 0.0)


# ─── ② USE_PIPELINE 봇 경로 매핑 ────────────────────────────────────────

_LOG4 = {
    "cveId": "CVE-2021-44228", "severity": "critical", "cvssScore": 10.0,
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "kevListed": True, "types": ["CWE-917"], "products": ["Apache Log4j2"],
    "description": (
        "Apache Log4j2 JNDI features used in configuration, log messages, and parameters "
        "do not protect against attacker controlled LDAP and other JNDI related endpoints. "
        "An attacker who can control log messages or log message parameters can execute "
        "arbitrary code loaded from LDAP servers when message lookup substitution is enabled."),
}
_GOOD_REPORT = (
    "SUMMARY_EN: Log4Shell unauthenticated RCE.\n"
    "## 공격 기법\nJNDI lookup 으로 원격 클래스 로딩 후 RCE.\n"
    "## 완화 방안\nlog4j 2.17.1 이상으로 업그레이드.\n"
)


class FakeKestrel:
    def __init__(self):
        self.published = []   # (cid, body, extra_kwargs)

    def list_cves(self, limit=50):
        return [{"cveId": "CVE-2021-44228"}]

    def get_cve(self, cid):
        return dict(_LOG4)

    def related(self, cid):
        return []

    def publish_analysis(self, cid, body, title=None, **extra):
        self.published.append((cid, body, extra))
        return {"id": "A1"}


class FakeLLM:
    def __init__(self, response=""):
        self.response = response

    def complete(self, system, user, *, max_tokens=1400, effort="medium", model=None):
        return self.response


class RecordingBrain:
    def __init__(self, client=None):
        self.client = client
        self.analyze_calls = 0
        self.log = lambda *_: None

    def analyze_cve(self, detail, context="", memory=""):
        self.analyze_calls += 1
        return "## 요약\n기존 brain 경로로 생성한 분석 본문입니다. " * 3


class FakeState:
    def __init__(self):
        self.analyzed_cves = set()
        self.commented_analyses = set()
        self.replied_comments = set()
        self.commented_authors = {}
        self.memory = []
        self.last_topic_ts = 0.0
        self.last_digest_ts = 0.0
        self.pending_analyses = []
        self.rate_limited_until = 0.0

    def save(self):
        pass


def _agent(use_pipeline, client=None, persona="공격Agent"):
    cfg = C.Config(
        kestrel_token="t", kestrel_api="x", backend="ollama", anthropic_api_key="",
        anthropic_model="m", ollama_host="h", ollama_model="m", persona=persona,
        persona_prompt="p", interval=1, use_feeds=False, feeds=(), topic_hours=0,
        digest_hours=0, openai_base_url="x", openai_api_key="", openai_model="m",
        llm_timeout=0, max_perspectives=3, analysis_model="", use_pipeline=use_pipeline,
    )
    return A.Agent(cfg, FakeKestrel(), RecordingBrain(client), FakeState(), persona)


class TestPipelinePublishMapping(unittest.TestCase):
    def setUp(self):
        self._orig_epss = epssmod.fetch_epss
        epssmod.fetch_epss = lambda cid, **kw: {"epss": 0.99999, "percentile": 0.99997}
        self._orig_root = cvmod._REPO_ROOT
        cvmod._REPO_ROOT = pathlib.Path(tempfile.mkdtemp())

    def tearDown(self):
        epssmod.fetch_epss = self._orig_epss
        cvmod._REPO_ROOT = self._orig_root

    def test_pipeline_path_sends_structured_fields(self):
        """Log4Shell 파이프라인 결과가 정확한 필드명·값으로 publish 에 실린다."""
        ag = _agent(True, client=FakeLLM(_GOOD_REPORT))
        ag.do_analysis([])
        self.assertEqual(len(ag.k.published), 1)
        cid, body, extra = ag.k.published[0]
        self.assertEqual(cid, "CVE-2021-44228")
        self.assertEqual(extra["epss_score"], 0.99999)
        self.assertEqual(extra["epss_percentile"], 0.99997)
        self.assertEqual(extra["priority_action"], "immediate")
        self.assertTrue(extra["priority_reasoning"])       # 산출 근거 문자열 존재
        self.assertIs(extra["kev_listed"], True)
        self.assertEqual(extra["validation_confidence"], 1.0)  # 3규칙 전부 통과
        self.assertEqual(extra["exploitability_grade"], "easy")  # KEV → easy
        self.assertEqual(extra["pipeline_version"], "kestrel-agent-pipeline-v2")
        # Log4j 레코드는 products↔description 일치 → 품질 신호 없음 → 필드 자체 생략
        self.assertNotIn("quality_flags", extra)

    def test_flag_off_sends_no_structured_fields(self):
        """기존 brain 경로는 구조화 필드 없이 게시(회귀 0)."""
        ag = _agent(False)
        ag.do_analysis([])
        self.assertEqual(ag.brain.analyze_calls, 1)
        self.assertEqual(len(ag.k.published), 1)
        _, _, extra = ag.k.published[0]
        self.assertEqual(extra, {})


if __name__ == "__main__":
    unittest.main()
