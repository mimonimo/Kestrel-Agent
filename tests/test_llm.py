import io, json, unittest, urllib.error
import llm
import config


def _cfg(**kw):
    base = dict(
        kestrel_token="t", kestrel_api="http://x", backend="openai",
        anthropic_api_key="", anthropic_model="m", ollama_host="http://h", ollama_model="m",
        persona="p", persona_prompt="pp", interval=1, use_feeds=False, feeds=(),
        topic_hours=0, digest_hours=0, openai_base_url="https://api.openai.com/v1",
        openai_api_key="k", openai_model="gpt-4o-mini", llm_timeout=0, max_perspectives=3,
    )
    base.update(kw)
    return config.Config(**base)


class FakeClient(llm.LLMClient):
    def __init__(self, seq):
        super().__init__(timeout=1)
        self.seq = list(seq)   # each item: str or Exception
        self.calls = 0

    def _call(self, system, user, max_tokens, effort):
        self.calls += 1
        item = self.seq.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class TestComplete(unittest.TestCase):
    def test_success_strips(self):
        c = FakeClient(["  hi  "])
        self.assertEqual(c.complete("s", "u"), "hi")

    def test_empty_raises_nonfatal(self):
        c = FakeClient(["   "])
        with self.assertRaises(llm.LLMError) as cm:
            c.complete("s", "u")
        self.assertFalse(cm.exception.fatal)

    def test_http_401_fatal(self):
        err = urllib.error.HTTPError("u", 401, "no", {}, io.BytesIO(b"denied"))
        c = FakeClient([err])
        with self.assertRaises(llm.LLMError) as cm:
            c.complete("s", "u")
        self.assertTrue(cm.exception.fatal)

    def test_http_500_nonfatal(self):
        err = urllib.error.HTTPError("u", 500, "boom", {}, io.BytesIO(b"x"))
        c = FakeClient([err])
        with self.assertRaises(llm.LLMError) as cm:
            c.complete("s", "u")
        self.assertFalse(cm.exception.fatal)


class TestOpenAIPayload(unittest.TestCase):
    def test_chat_completions_payload(self):
        captured = {}

        class FakeResp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            captured["auth"] = req.get_header("Authorization")
            return FakeResp(json.dumps(
                {"choices": [{"message": {"content": "분석 결과"}}]}).encode())

        client = llm.OpenAIClient(_cfg())
        llm.urllib.request.urlopen = fake_urlopen  # monkeypatch
        try:
            out = client._call("SYS", "USR", max_tokens=500, effort="high")
        finally:
            import importlib; importlib.reload(llm)  # restore
        self.assertEqual(out, "분석 결과")
        self.assertTrue(captured["url"].endswith("/chat/completions"))
        self.assertEqual(captured["body"]["model"], "gpt-4o-mini")
        self.assertEqual(captured["body"]["temperature"], 0.3)  # high->0.3
        self.assertEqual(captured["auth"], "Bearer k")
        self.assertEqual(captured["body"]["messages"][0]["role"], "system")


class TestMakeClient(unittest.TestCase):
    def test_routes_openai(self):
        self.assertIsInstance(llm.make_client(_cfg(backend="openai")), llm.OpenAIClient)

    def test_routes_ollama(self):
        self.assertIsInstance(llm.make_client(_cfg(backend="ollama")), llm.OllamaClient)


if __name__ == "__main__":
    unittest.main()
