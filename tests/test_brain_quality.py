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


if __name__ == "__main__":
    unittest.main()
