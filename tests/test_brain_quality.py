import unittest
import brain


class TestGuards(unittest.TestCase):
    def test_find_cves(self):
        self.assertEqual(
            brain._find_cves("cve-2026-0001 and CVE-2026-12345 dup CVE-2026-0001"),
            {"CVE-2026-0001", "CVE-2026-12345"})

    def test_has_sections_keyword(self):
        text = "## 📋 요약\nx\n## 🔍 공격 방법\ny\n### PoC 예시\nz\n## 탐지\n## 방어"
        self.assertTrue(brain._has_sections(text, ["요약", "공격", "예시|PoC", "탐지", "방어"]))

    def test_has_sections_missing(self):
        text = "## 요약\n본문만 있고 나머지 헤더 없음"
        self.assertFalse(brain._has_sections(text, ["요약", "공격", "탐지"]))

    def test_redact_drops_bad_bullet(self):
        text = "- CVE-2026-0001 좋음\n- CVE-9999-9999 가짜\n본문"
        out = brain._redact_cves(text, {"CVE-2026-0001"})
        self.assertIn("CVE-2026-0001", out)
        self.assertNotIn("CVE-9999-9999", out)

    def test_redact_inline_replaces(self):
        out = brain._redact_cves("참고 CVE-9999-9999 임", {"CVE-2026-0001"})
        self.assertNotIn("CVE-9999-9999", out)
        self.assertIn("(관련 CVE)", out)

    def test_unfence_strips_markdown_wrapper(self):
        out = brain.Brain._unfence("```markdown\n## 제목\n본문\n```")
        self.assertTrue(out.startswith("## 제목"))
        self.assertNotIn("```", out)

    def test_unfence_keeps_real_code_block(self):
        code = "```python\nprint(1)\n```"
        self.assertEqual(brain.Brain._unfence(code), code)


import config as _config


def _brain_cfg():
    return _config.Config(
        kestrel_token="t", kestrel_api="x", backend="openai",
        anthropic_api_key="", anthropic_model="m", ollama_host="h", ollama_model="m",
        persona="공격Agent", persona_prompt="pp", interval=1, use_feeds=False, feeds=(),
        topic_hours=0, digest_hours=0, openai_base_url="x", openai_api_key="k", openai_model="m",
        llm_timeout=0, max_perspectives=3,
    )


class _SeqClient:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = 0

    def complete(self, system, user, *, max_tokens, effort):
        self.calls += 1
        return self.outputs.pop(0)


class TestGenerate(unittest.TestCase):
    def test_retry_then_pass(self):
        client = _SeqClient(["짧음", "## 동향 요약\n충분히 긴 본문 " + "가" * 200 + "\n## 권고\n패치"])
        b = brain.Brain(_brain_cfg(), client)
        out = b.generate("s", "u", max_tokens=900, min_len=150,
                         required=["동향|요약", "권고"], label="t")
        self.assertIn("권고", out)
        self.assertEqual(client.calls, 2)

    def test_hallucinated_cve_redacted_on_fallback(self):
        bad = "## 동향 요약\n" + "내용 " * 80 + "\n- CVE-9999-9999 가짜\n## 권고\n패치"
        client = _SeqClient([bad, bad, bad, bad, bad])
        b = brain.Brain(_brain_cfg(), client)
        out = b.generate("s", "u", max_tokens=900, min_len=50,
                         required=["동향|요약", "권고"], allowed_cves={"CVE-2026-0001"}, label="t")
        self.assertNotIn("CVE-9999-9999", out)
        self.assertEqual(client.calls, brain._MAX_CALLS)

    def test_fatal_error_propagates(self):
        from llm import LLMError

        class FatalClient:
            def complete(self, *a, **k):
                raise LLMError("auth", fatal=True)

        b = brain.Brain(_brain_cfg(), FatalClient())
        with self.assertRaises(LLMError):
            b.generate("s", "u", max_tokens=10, min_len=1, label="t")

    def test_transient_exhaustion_returns_empty(self):
        from llm import LLMError

        class DownClient:
            def __init__(self): self.calls = 0
            def complete(self, *a, **k):
                self.calls += 1
                raise LLMError("timeout")

        c = DownClient()
        b = brain.Brain(_brain_cfg(), c)
        out = b.generate("s", "u", max_tokens=10, min_len=1, label="t")
        self.assertEqual(out, "")
        self.assertEqual(c.calls, brain._MAX_CALLS)


if __name__ == "__main__":
    unittest.main()
