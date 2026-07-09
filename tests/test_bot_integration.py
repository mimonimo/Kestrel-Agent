"""4b 봇 통합 — USE_PIPELINE 플래그로 분석 게시 경로를 분기하는지 hermetic 검증.

기존 파일(agent.py)을 처음 수정하는 단계이므로: 플래그 off 회귀(기존 동작 그대로),
플래그 on 파이프라인 경로(publish 도달·brain 미사용), 실패 시 사이클 스킵·상태 무오염을 본다.
kestrel/LLM 은 Fake, EPSS·이벤트기록은 monkeypatch 로 네트워크·레포 오염 없이.
"""
import pathlib
import sys
import tempfile
import unittest

sys.argv = ["agent.py"]
import agent as A          # noqa: E402
import config as C         # noqa: E402
import pipeline.agents.cross_validation as cvmod  # noqa: E402
import pipeline.sources.epss as epssmod           # noqa: E402

_LOG4 = {
    "cveId": "CVE-2021-44228", "severity": "critical", "cvssScore": 10.0,
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "kevListed": True, "types": ["CWE-917"], "products": ["Apache Log4j2"],
    "description": "Apache Log4j2 JNDI lookup remote code execution.",
}
_GOOD_REPORT = (
    "SUMMARY_EN: Log4Shell unauthenticated RCE.\n"
    "## 공격 기법\nJNDI lookup 으로 원격 클래스 로딩 후 RCE.\n"
    "## 완화 방안\nlog4j 2.17.1 이상으로 업그레이드.\n"
)


class FakeKestrel:
    def __init__(self):
        self.published = []

    def list_cves(self, limit=50):
        return [{"cveId": "CVE-2021-44228"}]

    def get_cve(self, cid):
        return dict(_LOG4)

    def related(self, cid):
        return []

    def publish_analysis(self, cid, body):
        self.published.append((cid, body))
        return {"id": "A1"}


class FakeLLM:
    def __init__(self, response="", raise_exc=None):
        self.response, self.raise_exc = response, raise_exc

    def complete(self, system, user, *, max_tokens=1400, effort="medium", model=None):
        if self.raise_exc:
            raise self.raise_exc
        return self.response


class RecordingBrain:
    """기존 경로 사용 여부를 감지 + 파이프라인용 client 를 제공."""
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

    def save(self):
        pass


def _cfg(use_pipeline, persona="공격Agent"):
    return C.Config(
        kestrel_token="t", kestrel_api="x", backend="ollama", anthropic_api_key="",
        anthropic_model="m", ollama_host="h", ollama_model="m", persona=persona,
        persona_prompt="p", interval=1, use_feeds=False, feeds=(), topic_hours=0,
        digest_hours=0, openai_base_url="x", openai_api_key="", openai_model="m",
        llm_timeout=0, max_perspectives=3, analysis_model="", use_pipeline=use_pipeline,
    )


def _agent(use_pipeline, client=None, persona="공격Agent"):
    cfg = _cfg(use_pipeline, persona)
    return A.Agent(cfg, FakeKestrel(), RecordingBrain(client), FakeState(), persona)


class TestBotIntegration(unittest.TestCase):
    def setUp(self):
        # 네트워크(EPSS)·레포 오염(validation_events.jsonl) 차단
        self._orig_epss = epssmod.fetch_epss
        epssmod.fetch_epss = lambda cid, **kw: {"epss": 0.97, "percentile": 0.99}
        self._orig_root = cvmod._REPO_ROOT
        cvmod._REPO_ROOT = pathlib.Path(tempfile.mkdtemp())

    def tearDown(self):
        epssmod.fetch_epss = self._orig_epss
        cvmod._REPO_ROOT = self._orig_root

    def test_flag_off_uses_brain_path(self):
        ag = _agent(False)
        ag.do_analysis([])
        self.assertEqual(ag.brain.analyze_calls, 1)      # 기존 경로 사용
        self.assertEqual(len(ag.k.published), 1)
        cid, body = ag.k.published[0]
        self.assertIn("기존 brain", body)
        self.assertIn(cid, ag.state.analyzed_cves)

    def test_flag_on_uses_pipeline_path(self):
        ag = _agent(True, client=FakeLLM(_GOOD_REPORT))
        ag.do_analysis([])
        self.assertEqual(ag.brain.analyze_calls, 0)      # 기존 경로 미사용
        self.assertEqual(len(ag.k.published), 1)
        cid, body = ag.k.published[0]
        self.assertIn("공격 기법", body)
        self.assertIn("JNDI", body)                      # 파이프라인 report 반영
        self.assertIn("우선순위", body)                   # 위험도/우선순위 섹션
        self.assertIn("immediate", body)                 # KEV+EPSS → immediate
        self.assertIn(cid, ag.state.analyzed_cves)

    def test_pipeline_failure_skips_cycle_without_state_pollution(self):
        ag = _agent(True, client=FakeLLM(raise_exc=TimeoutError("연결 실패")))
        ag.do_analysis([])
        self.assertEqual(len(ag.k.published), 0)                       # 게시 안 함
        self.assertNotIn("CVE-2021-44228", ag.state.analyzed_cves)    # 상태 무오염
        self.assertEqual(ag.brain.analyze_calls, 0)                   # 폴백도 안 함

    def test_bot_persona_maps_to_pipeline_persona(self):
        from pipeline.personas import resolve_persona
        self.assertEqual(resolve_persona("방어Agent").key, "defensive")
        self.assertEqual(resolve_persona("공격Agent").key, "offensive")
        self.assertEqual(resolve_persona("분석가Agent").key, "analyst")


if __name__ == "__main__":
    unittest.main()
