import os, unittest
import config


class TestConfig(unittest.TestCase):
    def _clean_env(self):
        for k in ("AGENT_BACKEND", "LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL",
                  "AGENT_LLM_TIMEOUT", "AGENT_MAX_PERSPECTIVES", "KESTREL_TOKEN"):
            os.environ.pop(k, None)

    def test_openai_defaults(self):
        self._clean_env()
        os.environ["AGENT_BACKEND"] = "openai"
        c = config.Config.from_env()
        self.assertEqual(c.backend, "openai")
        self.assertEqual(c.openai_base_url, "https://api.openai.com/v1")
        self.assertEqual(c.openai_model, "gpt-4o-mini")
        self.assertEqual(c.max_perspectives, 3)
        self.assertEqual(c.llm_timeout, 0)

    def test_openai_public_requires_key(self):
        self._clean_env()
        os.environ.update(AGENT_BACKEND="openai", KESTREL_TOKEN="t")
        c = config.Config.from_env()
        with self.assertRaises(SystemExit):
            c.validate()

    def test_openai_custom_baseurl_no_key_ok(self):
        self._clean_env()
        os.environ.update(AGENT_BACKEND="openai", KESTREL_TOKEN="t",
                          LLM_BASE_URL="http://localhost:8000/v1")
        c = config.Config.from_env()
        c.validate()  # no exception


if __name__ == "__main__":
    unittest.main()
