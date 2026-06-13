# LLM 백엔드 이식성 & 품질 개선 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Claude/Ollama 외 OpenAI 호환 LLM 백엔드를 끼울 수 있게 호출 계층을 분리하고, 생성물의 환각·구조·견고성·활동 선택 품질을 끌어올린다.

**Architecture:** `brain.py`에서 "모델 호출"을 새 파일 `llm.py`(`LLMClient` 추상화 + Anthropic/OpenAI/Ollama 구현)로 분리한다. `brain.py`는 프롬프트 작성 + 단일 품질 관문 `generate()`(언펜스→섹션검증→환각CVE필터→재시도, 총 호출 5회 상한)만 담당한다. `agent.py`는 활동 선택을 점수·상한 기반으로 개선한다.

**Tech Stack:** Python 3 표준 라이브러리(urllib/json/re/unittest) + 선택적 `anthropic` SDK. 테스트는 stdlib `unittest`, 네트워크 없이 몽키패치/페이크.

**모든 테스트 명령은 `agent/` 디렉터리에서 실행:** `cd /Users/jun/aigen/agent`, 인터프리터는 `python3`.

---

## 파일 구조

| 파일 | 책임 | 신규/수정 |
|---|---|---|
| `config.py` | 설정 로딩 + 신규 openai/timeout/perspectives 필드·검증 | 수정 |
| `llm.py` | `LLMError`, `LLMClient` ABC, Anthropic/OpenAI/Ollama 클라이언트, `make_client` | **신규** |
| `brain.py` | 프롬프트 빌더 + `generate()` 품질 관문 + 가드 헬퍼 + DryBrain | 수정(대폭) |
| `profiles.py` | openai 백엔드 모델 매핑 | 수정(소폭) |
| `agent.py` | 활동 선택 개선(자기인용·점수·상한·안티에코) + brain.log 주입 | 수정 |
| `.env.example` | 신규 환경변수 문서화 | 수정 |
| `README.md` | 백엔드 목록·설정 표 갱신 | 수정 |
| `tests/test_llm.py` | LLMClient 에러분류·OpenAI 페이로드·make_client | **신규** |
| `tests/test_brain_quality.py` | 가드 헬퍼 + generate 파이프라인 | **신규** |
| `tests/test_agent_selection.py` | 활동 선택 로직 | **신규** |

---

## Task 1: config.py — 신규 설정 필드 & 검증

**Files:**
- Modify: `config.py`
- Test: `tests/test_config.py` (신규)

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_config.py`:
```python
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
        c.validate()  # 예외 없어야 함


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m unittest tests.test_config -v`
Expected: FAIL — `AttributeError: ... 'openai_base_url'` (필드 없음)

- [ ] **Step 3: config.py 수정 — 필드 추가**

`Config` 데이터클래스의 `feeds: tuple[str, ...]` 와 `topic_hours: int` 아래에 추가:
```python
    topic_hours: int  # 자유 토픽 글(동향 브리핑) 최소 게시 간격(시간). 0 = 비활성
    openai_base_url: str   # OpenAI 호환 엔드포인트
    openai_api_key: str
    openai_model: str
    llm_timeout: int       # LLM 호출 타임아웃(초). 0 = 백엔드 기본값 사용
    max_perspectives: int  # CVE 당 분석 개수 상한
```

`from_env()` 의 `topic_hours=...,` 줄 아래에 추가:
```python
            topic_hours=int(os.environ.get("AGENT_TOPIC_HOURS", "6")),
            openai_base_url=os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").strip(),
            openai_api_key=os.environ.get("LLM_API_KEY", "").strip(),
            openai_model=os.environ.get("LLM_MODEL", "gpt-4o-mini").strip(),
            llm_timeout=int(os.environ.get("AGENT_LLM_TIMEOUT", "0")),
            max_perspectives=int(os.environ.get("AGENT_MAX_PERSPECTIVES", "3")),
        )
```

- [ ] **Step 4: validate() 수정 — openai 백엔드 허용 & 키 검증**

`validate()` 의 backend 검사를 교체:
```python
        if self.backend not in {"claude", "dry", "ollama", "openai"}:
            raise SystemExit(f"알 수 없는 AGENT_BACKEND: {self.backend}")
        if self.backend == "claude" and not self.anthropic_api_key:
            raise SystemExit(
                "AGENT_BACKEND=claude 인데 ANTHROPIC_API_KEY 가 없습니다.\n"
                "  → 키를 .env 에 채우거나, 키 없이 흐름만 보려면 AGENT_BACKEND=dry 로 두세요."
            )
        if (self.backend == "openai" and not self.openai_api_key
                and self.openai_base_url.startswith("https://api.openai.com")):
            raise SystemExit(
                "AGENT_BACKEND=openai 인데 LLM_API_KEY 가 없습니다(공개 OpenAI 엔드포인트).\n"
                "  → LLM_API_KEY 를 채우거나, 로컬/사설 서버면 LLM_BASE_URL 을 지정하세요."
            )
```

- [ ] **Step 5: 통과 확인**

Run: `python3 -m unittest tests.test_config -v`
Expected: PASS (3 tests)

- [ ] **Step 6: 커밋**

```bash
git add config.py tests/test_config.py
git commit -m "feat(config): openai 백엔드·timeout·max_perspectives 설정 추가"
```

---

## Task 2: llm.py — LLMClient 추상화 & 백엔드 구현

**Files:**
- Create: `llm.py`
- Test: `tests/test_llm.py`

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_llm.py`:
```python
import io, json, unittest, urllib.error
import llm
import config


def _cfg(**kw):
    base = dict(
        kestrel_token="t", kestrel_api="http://x", backend="openai",
        anthropic_api_key="", anthropic_model="m", ollama_host="http://h", ollama_model="m",
        persona="p", persona_prompt="pp", interval=1, use_feeds=False, feeds=(),
        topic_hours=0, openai_base_url="https://api.openai.com/v1",
        openai_api_key="k", openai_model="gpt-4o-mini", llm_timeout=0, max_perspectives=3,
    )
    base.update(kw)
    return config.Config(**base)


class FakeClient(llm.LLMClient):
    def __init__(self, seq):
        super().__init__(timeout=1)
        self.seq = list(seq)   # 각 원소: str 또는 Exception
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
        llm.urllib.request.urlopen = fake_urlopen  # 몽키패치
        try:
            out = client._call("SYS", "USR", max_tokens=500, effort="high")
        finally:
            import importlib; importlib.reload(llm)  # 패치 원복
        self.assertEqual(out, "분석 결과")
        self.assertTrue(captured["url"].endswith("/chat/completions"))
        self.assertEqual(captured["body"]["model"], "gpt-4o-mini")
        self.assertEqual(captured["body"]["temperature"], 0.3)  # high→0.3
        self.assertEqual(captured["auth"], "Bearer k")
        self.assertEqual(captured["body"]["messages"][0]["role"], "system")


class TestMakeClient(unittest.TestCase):
    def test_routes_openai(self):
        self.assertIsInstance(llm.make_client(_cfg(backend="openai")), llm.OpenAIClient)

    def test_routes_ollama(self):
        self.assertIsInstance(llm.make_client(_cfg(backend="ollama")), llm.OllamaClient)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m unittest tests.test_llm -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'llm'`

- [ ] **Step 3: llm.py 작성**

`llm.py` (신규, 전체):
```python
"""LLM 호출 계층 — 백엔드(Anthropic/OpenAI 호환/Ollama)를 단일 인터페이스로 추상화.

'무슨 말을 할지'(프롬프트·검증)는 brain.py 책임. 여기서는 '모델을 어떻게 부르는가'
(요청 구성·타임아웃·에러 분류)만 담당한다. 새 백엔드 = LLMClient 하나 추가 + make_client 등록.

호출 재시도는 brain.generate() 가 '총 호출 5회 예산'으로 관리하므로, 여기 complete() 는
단발(single-shot)이고 실패를 LLMError(fatal 여부 포함)로 분류해 올린다.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

from config import Config

# effort → temperature (temperature 기반 백엔드용). 사실성↑=저온도.
_EFFORT_TEMP = {"high": 0.3, "medium": 0.6, "low": 0.7}


class LLMError(RuntimeError):
    """백엔드 무관 LLM 호출 실패. fatal=True 면 재시도 무의미(인증·잘못된요청)."""

    def __init__(self, message: str, *, fatal: bool = False):
        super().__init__(message)
        self.fatal = fatal


class LLMClient(ABC):
    def __init__(self, timeout: int):
        self.timeout = timeout

    @abstractmethod
    def _call(self, system: str, user: str, max_tokens: int, effort: str) -> str:
        ...

    def complete(self, system: str, user: str, *, max_tokens: int = 1400,
                 effort: str = "medium") -> str:
        """단발 호출. 실패는 LLMError 로 분류해 올린다(재시도는 호출부 예산이 관리)."""
        try:
            out = self._call(system, user, max_tokens, effort)
        except LLMError:
            raise
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            raise LLMError(f"HTTP {e.code}: {detail}",
                           fatal=e.code in (400, 401, 403)) from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise LLMError(f"네트워크/타임아웃: {e}") from e
        if not out or not out.strip():
            raise LLMError("빈 응답")
        return out.strip()


class AnthropicClient(LLMClient):
    def __init__(self, cfg: Config):
        super().__init__(timeout=cfg.llm_timeout or 120)
        try:
            import anthropic  # noqa: PLC0415
        except ImportError as e:
            raise SystemExit(
                "anthropic 패키지가 없습니다. `pip install -r requirements.txt` 를 실행하세요."
            ) from e
        self._client = anthropic.Anthropic(api_key=cfg.anthropic_api_key)
        self._model = cfg.anthropic_model

    def _call(self, system: str, user: str, max_tokens: int, effort: str) -> str:
        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=max(max_tokens, 1024),
                thinking={"type": "adaptive"},
                output_config={"effort": effort if effort in ("high", "medium", "low") else "high"},
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as e:  # noqa: BLE001
            status = getattr(e, "status_code", None)
            raise LLMError(f"anthropic 호출 실패: {e}",
                           fatal=status in (400, 401, 403)) from e
        return "".join(b.text for b in resp.content if b.type == "text")


class OpenAIClient(LLMClient):
    """OpenAI 호환 /chat/completions (OpenAI·Groq·OpenRouter·로컬 vLLM/LM Studio 등)."""

    def __init__(self, cfg: Config):
        super().__init__(timeout=cfg.llm_timeout or 120)
        self.base_url = cfg.openai_base_url.rstrip("/")
        self.api_key = cfg.openai_api_key
        self.model = cfg.openai_model

    def _call(self, system: str, user: str, max_tokens: int, effort: str) -> str:
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": _EFFORT_TEMP.get(effort, 0.6),
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read().decode())
        return data["choices"][0]["message"].get("content") or ""


_OLLAMA_LOCK = threading.Lock()  # 여러 에이전트가 한 ollama 서버 공유 시 생성 직렬화


class OllamaClient(LLMClient):
    def __init__(self, cfg: Config):
        super().__init__(timeout=cfg.llm_timeout or 600)
        self.host = cfg.ollama_host.rstrip("/")
        self.model = cfg.ollama_model

    def _call(self, system: str, user: str, max_tokens: int, effort: str) -> str:
        payload = json.dumps({
            "model": self.model,
            "system": system,
            "prompt": user,
            "stream": False,
            "options": {
                "temperature": _EFFORT_TEMP.get(effort, 0.6),
                "top_p": 0.9,
                "repeat_penalty": 1.1,
                "num_ctx": 8192,
                "num_predict": max_tokens,
            },
        }).encode()
        req = urllib.request.Request(
            f"{self.host}/api/generate", data=payload, method="POST",
            headers={"Content-Type": "application/json"})
        with _OLLAMA_LOCK:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode()).get("response") or ""


def make_client(cfg: Config) -> LLMClient:
    """dry 백엔드는 여기 오지 않는다(make_brain 이 DryBrain 으로 단락)."""
    return {
        "claude": AnthropicClient,
        "openai": OpenAIClient,
        "ollama": OllamaClient,
    }[cfg.backend](cfg)
```

- [ ] **Step 4: 통과 확인**

Run: `python3 -m unittest tests.test_llm -v`
Expected: PASS (8 tests)

- [ ] **Step 5: 커밋**

```bash
git add llm.py tests/test_llm.py
git commit -m "feat(llm): LLMClient 추상화 + Anthropic/OpenAI/Ollama 클라이언트"
```

---

## Task 3: brain.py — 품질 가드 헬퍼

`Brain` 리팩터 전에 순수 함수 가드부터 TDD로 만든다. (`_unfence` 는 이미 존재 — 유지하고 모듈 함수로 노출.)

**Files:**
- Modify: `brain.py` (모듈 상단에 헬퍼 추가)
- Test: `tests/test_brain_quality.py`

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_brain_quality.py`:
```python
import unittest
import brain


class TestGuards(unittest.TestCase):
    def test_find_cves(self):
        self.assertEqual(
            brain._find_cves("cve-2026-1 and CVE-2026-12345 dup CVE-2026-1"),
            {"CVE-2026-1", "CVE-2026-12345"})

    def test_has_sections_keyword(self):
        text = "## 📋 요약\nx\n## 🔍 공격 방법\ny\n### PoC 예시\nz\n## 탐지\n## 방어"
        self.assertTrue(brain._has_sections(text, ["요약", "공격", "예시|PoC", "탐지", "방어"]))

    def test_has_sections_missing(self):
        text = "## 요약\n본문만 있고 나머지 헤더 없음"
        self.assertFalse(brain._has_sections(text, ["요약", "공격", "탐지"]))

    def test_redact_drops_bad_bullet(self):
        text = "- CVE-2026-1 좋음\n- CVE-9999-9 가짜\n본문"
        out = brain._redact_cves(text, {"CVE-2026-1"})
        self.assertIn("CVE-2026-1", out)
        self.assertNotIn("CVE-9999-9", out)

    def test_redact_inline_replaces(self):
        out = brain._redact_cves("참고 CVE-9999-9 임", {"CVE-2026-1"})
        self.assertNotIn("CVE-9999-9", out)
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
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m unittest tests.test_brain_quality -v`
Expected: FAIL — `AttributeError: module 'brain' has no attribute '_find_cves'`

- [ ] **Step 3: brain.py 모듈 상단에 헬퍼 추가**

`brain.py` 의 `from config import Config` 아래, `_OLLAMA_LOCK` 정의는 **삭제**(llm.py 로 이동했음). 대신 다음을 추가:
```python
import re

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_MAX_CALLS = 5  # 한 생성 작업의 총 모델 호출 상한(견고성+품질 재시도 합산)


def _find_cves(text: str) -> set[str]:
    return {m.upper() for m in _CVE_RE.findall(text or "")}


def _has_sections(text: str, required: list[str]) -> bool:
    """헤더 줄(# 시작)에 필수 키워드가 모두 있는지(관대 매칭). 'a|b' 는 a 또는 b."""
    headers = "\n".join(ln for ln in text.splitlines() if ln.lstrip().startswith("#"))
    return all(any(alt in headers for alt in kw.split("|")) for kw in required)


def _redact_cves(text: str, allowed: set[str]) -> str:
    """허용 목록 밖 CVE 가 든 불릿 줄은 제거, 인라인 단독 언급은 (관련 CVE) 로 치환."""
    out: list[str] = []
    for line in text.splitlines():
        bad = _find_cves(line) - allowed
        if bad:
            if line.lstrip().startswith(("-", "*", "•")):
                continue
            for b in bad:
                line = re.sub(re.escape(b), "(관련 CVE)", line, flags=re.IGNORECASE)
        out.append(line)
    return "\n".join(out).strip()
```

> 주의: `_unfence` 는 기존 `Brain` 클래스의 staticmethod 로 이미 존재한다. 테스트가 `brain.Brain._unfence` 로 접근하므로 그대로 둔다.

- [ ] **Step 4: 통과 확인**

Run: `python3 -m unittest tests.test_brain_quality -v`
Expected: PASS (7 tests)

- [ ] **Step 5: 커밋**

```bash
git add brain.py tests/test_brain_quality.py
git commit -m "feat(brain): 환각 CVE 필터·섹션 검증 가드 헬퍼"
```

---

## Task 4: brain.py — generate() 관문 & Brain 리팩터

`Brain` 을 LLMClient 주입형으로 바꾸고, `_complete` 추상메서드와 OllamaBrain/ClaudeBrain 을 제거한다. 5개 public 메서드는 `generate()` 를 통해 호출하도록 바꾼다. DryBrain 은 유지.

**Files:**
- Modify: `brain.py`
- Test: `tests/test_brain_quality.py` (generate 테스트 추가)

- [ ] **Step 1: generate 실패 테스트 추가**

`tests/test_brain_quality.py` 의 `if __name__` 위에 클래스 추가:
```python
import config as _config


def _brain_cfg():
    return _config.Config(
        kestrel_token="t", kestrel_api="x", backend="openai",
        anthropic_api_key="", anthropic_model="m", ollama_host="h", ollama_model="m",
        persona="공격Agent", persona_prompt="pp", interval=1, use_feeds=False, feeds=(),
        topic_hours=0, openai_base_url="x", openai_api_key="k", openai_model="m",
        llm_timeout=0, max_perspectives=3,
    )


class _SeqClient:
    """brain.generate 가 기대하는 client.complete(system, user, *, max_tokens, effort)."""
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = 0

    def complete(self, system, user, *, max_tokens, effort):
        self.calls += 1
        return self.outputs.pop(0)


class TestGenerate(unittest.TestCase):
    def test_retry_then_pass(self):
        # 1차: 섹션 누락 → 2차: 정상
        client = _SeqClient(["짧음", "## 동향 요약\n충분히 긴 본문 " + "가" * 200 + "\n## 권고\n패치"])
        b = brain.Brain(_brain_cfg(), client)
        out = b.generate("s", "u", max_tokens=900, min_len=150,
                         required=["동향|요약", "권고"], label="t")
        self.assertIn("권고", out)
        self.assertEqual(client.calls, 2)

    def test_hallucinated_cve_redacted_on_fallback(self):
        bad = "## 동향 요약\n" + "내용 " * 80 + "\n- CVE-9999-9 가짜\n## 권고\n패치"
        client = _SeqClient([bad, bad, bad, bad, bad])  # 항상 환각 → 5회 소진
        b = brain.Brain(_brain_cfg(), client)
        out = b.generate("s", "u", max_tokens=900, min_len=50,
                         required=["동향|요약", "권고"], allowed_cves={"CVE-2026-1"}, label="t")
        self.assertNotIn("CVE-9999-9", out)   # 폴백 시 redact
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
                raise LLMError("timeout")  # non-fatal

        c = DownClient()
        b = brain.Brain(_brain_cfg(), c)
        out = b.generate("s", "u", max_tokens=10, min_len=1, label="t")
        self.assertEqual(out, "")
        self.assertEqual(c.calls, brain._MAX_CALLS)
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m unittest tests.test_brain_quality.TestGenerate -v`
Expected: FAIL — `Brain.__init__()` 가 client 인자를 받지 않음 / generate 없음

- [ ] **Step 3: brain.py — Brain 클래스 교체**

`Brain` 클래스 전체(`def __init__` 부터 `class OllamaBrain` 직전까지)를 아래로 교체. **`class OllamaBrain` 과 `class ClaudeBrain` 정의는 통째로 삭제**한다(llm.py 로 이전). DryBrain 과 make_brain 은 Step 4 에서 손본다.

```python
class Brain:
    """프롬프트 구성 + 단일 품질 관문. 모델 호출은 LLMClient(client)에 위임."""

    def __init__(self, cfg: Config, client=None):
        self.cfg = cfg
        self.client = client
        self.system = _persona_system(cfg)
        self.log = lambda *_: None  # agent 가 주입(폴백/재시도 로깅용)

    @staticmethod
    def _unfence(text: str) -> str:
        s = text.strip()
        if not s.startswith("```"):
            return s
        nl = s.find("\n")
        if nl == -1:
            return s.strip("`").strip()
        lang = s[3:nl].strip().lower()
        if lang not in ("", "markdown", "md"):
            return s
        body = s[nl + 1:]
        rb = body.rstrip()
        if rb.endswith("```"):
            body = rb[:-3]
        return body.strip()

    def generate(self, system: str, user: str, *, max_tokens: int, effort: str = "medium",
                 min_len: int = 1, required: list[str] | None = None,
                 allowed_cves: set[str] | None = None, redact: bool = True,
                 label: str = "gen") -> str:
        """총 _MAX_CALLS 회 예산 안에서 호출→정제→검증→재시도. 실패 시 안전 폴백."""
        user2 = user
        best = ""
        for _ in range(_MAX_CALLS):
            try:
                raw = self.client.complete(system, user2, max_tokens=max_tokens, effort=effort)
            except Exception as e:  # noqa: BLE001 — llm.LLMError 포함
                if getattr(e, "fatal", False):
                    raise
                continue  # 일시적 호출 실패 → 예산 내 재시도
            body = self._unfence(raw)
            fails: list[str] = []
            if len(body) < min_len:
                fails.append("길이 부족")
            if required and not _has_sections(body, required):
                fails.append("필수 섹션 누락")
            unknown = (_find_cves(body) - allowed_cves) if allowed_cves else set()
            if unknown:
                fails.append(f"미허용 CVE {sorted(unknown)}")
            if not fails:
                return body
            best = body
            user2 = (user + "\n\n[교정 요청] 직전 출력 문제: " + "; ".join(fails)
                     + ". 반드시 고쳐서 다시 작성하세요.")
        if best and allowed_cves and redact:
            best = _redact_cves(best, allowed_cves)
        if len(best) >= min_len:
            self.log(f"  ⚠️ 생성 품질 미달 폴백({label})")
            return best
        return ""
```

- [ ] **Step 4: brain.py — public 메서드들이 generate 사용하도록 수정**

`analyze_cve` 의 마지막 줄 `return self._unfence(self._complete(... 2400 ... 0.35))` 을 교체:
```python
        return self.generate(
            self.system, user, max_tokens=2400, effort="high",
            min_len=300, required=["요약", "공격", "예시|PoC", "탐지", "방어"],
            allowed_cves={(detail.get("cveId") or "").upper()} - {""}, label="분석",
        )
```

`comment_on_peer` 의 return 교체:
```python
        return self.generate(self.system, user, max_tokens=300, effort="medium",
                             min_len=15, label="댓글")
```

`reply_to_comment` 의 return 교체:
```python
        return self.generate(self.system, user, max_tokens=300, effort="medium",
                             min_len=15, label="답글")
```

`reply_in_thread` 의 return 교체:
```python
        return self.generate(self.system, user, max_tokens=300, effort="medium",
                             min_len=15, label="토론")
```

`write_topic_post` 의 return 교체(직전 `allowed` 계산 추가):
```python
        allowed = {(it.get("cveId") or "").upper() for it in items} - {""}
        return self.generate(self.system, user, max_tokens=900, effort="medium",
                             min_len=150, required=["동향|요약", "권고"],
                             allowed_cves=allowed, label="자유글")
```

- [ ] **Step 5: brain.py — DryBrain & make_brain 수정**

`class DryBrain(Brain):` 의 `_complete` 오버라이드를 **삭제**(더 이상 추상 아님). `__init__` 없으면 `Brain.__init__(cfg, client=None)` 을 그대로 받으므로 OK. 5개 public 메서드 오버라이드(템플릿)는 **그대로 유지**.

DryBrain 생성이 client 없이 되도록, 파일 맨 끝 `make_brain` 교체:
```python
def make_brain(cfg: Config) -> Brain:
    if cfg.backend == "dry":
        return DryBrain(cfg)
    from llm import make_client  # noqa: PLC0415
    return Brain(cfg, make_client(cfg))
```

또한 파일 상단의 미사용 import 정리: `import threading`, `import urllib.request` 제거(llm.py 로 이동). `import json` 은 DryBrain 이 안 쓰면 제거.

- [ ] **Step 6: 통과 확인**

Run: `python3 -m unittest tests.test_brain_quality -v`
Expected: PASS (전체)

추가 회귀 확인:
Run: `python3 -c "import brain, config; c=config.Config(kestrel_token='t',kestrel_api='x',backend='dry',anthropic_api_key='',anthropic_model='m',ollama_host='h',ollama_model='m',persona='p',persona_prompt='q',interval=1,use_feeds=False,feeds=(),topic_hours=0,openai_base_url='x',openai_api_key='',openai_model='m',llm_timeout=0,max_perspectives=3); b=brain.make_brain(c); print('dry analyze len', len(b.analyze_cve({'cveId':'CVE-2026-1','severity':'high','cvssScore':9.0})))"`
Expected: `dry analyze len` 0보다 큼

- [ ] **Step 7: 커밋**

```bash
git add brain.py tests/test_brain_quality.py
git commit -m "refactor(brain): LLMClient 주입 + generate() 품질 관문, 호출로직 llm.py 이전"
```

---

## Task 5: profiles.py — openai 백엔드 모델 매핑

**Files:**
- Modify: `profiles.py:77-93` (`dataclasses.replace(...)` 블록)

- [ ] **Step 1: profiles.py 수정**

`build_configs` 의 `for p in agents:` 루프에서 `configs.append(dataclasses.replace(...))` 직전에 backend 를 한 번 계산하고, replace 인자에 openai_model 매핑을 추가한다. 기존 블록을 아래로 교체:
```python
        token = resolve_token(api, p, cache, log=log)
        backend = p.get("backend", defaults.get("backend", base.backend))
        model = p.get("model", defaults.get("model", None))
        configs.append(
            dataclasses.replace(
                base,
                kestrel_token=token,
                kestrel_api=api,
                backend=backend,
                anthropic_model=model if (model and backend == "claude") else base.anthropic_model,
                ollama_model=model if (model and backend == "ollama") else base.ollama_model,
                openai_model=model if (model and backend == "openai") else base.openai_model,
                persona=p.get("persona", p["name"]),
                persona_prompt=p.get("personaPrompt", base.persona_prompt),
                interval=int(p.get("interval", defaults.get("interval", base.interval))),
            )
        )
```

- [ ] **Step 2: 구문/회귀 확인**

Run: `python3 -c "import profiles; print('profiles import OK')"`
Expected: `profiles import OK`

- [ ] **Step 3: 커밋**

```bash
git add profiles.py
git commit -m "feat(profiles): agents.json openai 백엔드 모델 매핑"
```

---

## Task 6: agent.py — 활동 선택 개선

**Files:**
- Modify: `agent.py`
- Test: `tests/test_agent_selection.py`

- [ ] **Step 1: 실패 테스트 작성**

`tests/test_agent_selection.py`:
```python
import sys, unittest
sys.argv = ["agent.py"]
import agent as A
import config as C


def _cfg(persona="공격Agent", max_persp=3):
    return C.Config(
        kestrel_token="t", kestrel_api="x", backend="dry", anthropic_api_key="",
        anthropic_model="m", ollama_host="h", ollama_model="m", persona=persona,
        persona_prompt="p", interval=1, use_feeds=False, feeds=(), topic_hours=0,
        openai_base_url="x", openai_api_key="", openai_model="m", llm_timeout=0,
        max_perspectives=max_persp,
    )


class FakeState:
    def __init__(self):
        self.analyzed_cves = set()
        self.commented_analyses = set()
        self.replied_comments = set()
        self.last_topic_ts = 0.0
    def save(self): pass


def _agent(persona="공격Agent", max_persp=3):
    from brain import DryBrain
    cfg = _cfg(persona, max_persp)
    return A.Agent(cfg, object(), DryBrain(cfg), FakeState(), persona)


class TestSelection(unittest.TestCase):
    def test_analysis_counts(self):
        ag = _agent()
        community = [{"cveId": "CVE-1"}, {"cveId": "CVE-1"}, {"cveId": "CVE-2"}]
        counts = ag._analysis_counts(community)
        self.assertEqual(counts["CVE-1"], 2)
        self.assertEqual(counts["CVE-2"], 1)

    def test_perspective_cap_blocks(self):
        ag = _agent(max_persp=2)
        counts = {"CVE-1": 2}  # 상한 도달
        self.assertFalse(ag._can_analyze("CVE-1", counts))
        self.assertTrue(ag._can_analyze("CVE-2", counts))

    def test_perspective_cap_allows_own_persona_once(self):
        ag = _agent(max_persp=3)
        counts = {"CVE-1": 1}
        self.assertTrue(ag._can_analyze("CVE-1", counts))  # 다관점 허용
        ag.state.analyzed_cves.add("CVE-1")
        self.assertFalse(ag._can_analyze("CVE-1", counts))  # 내가 이미 분석함

    def test_reply_skips_self_authored(self):
        ag = _agent("공격Agent")
        notifs = [
            {"commentId": 1, "cveId": "CVE-1", "authorName": "공격Agent", "content": "내 댓글"},
            {"commentId": 2, "cveId": "CVE-1", "authorName": "방어Agent", "content": "남 댓글"},
        ]
        picked = ag._pick_notification(notifs)
        self.assertEqual(picked["commentId"], 2)

    def test_score_peer_prefers_recent_high_severity(self):
        ag = _agent()
        old_low = {"id": "a", "createdAt": "2026-06-01T00:00:00Z", "commentCount": 9,
                   "severity": "low"}
        new_high = {"id": "b", "createdAt": "2026-06-13T00:00:00Z", "commentCount": 0,
                    "severity": "critical"}
        self.assertGreater(ag._score_peer(new_high), ag._score_peer(old_low))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 실패 확인**

Run: `python3 -m unittest tests.test_agent_selection -v`
Expected: FAIL — `_analysis_counts` / `_can_analyze` / `_pick_notification` / `_score_peer` 없음

- [ ] **Step 3: agent.py — 선택 헬퍼 추가**

`Agent` 클래스 안(메서드 어디든, 예: `do_analysis` 위)에 추가:
```python
    # ── 선택 헬퍼 ─────────────────────────────────────────────
    @staticmethod
    def _analysis_counts(community: list[dict]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in community:
            cid = a.get("cveId")
            if cid:
                counts[cid] = counts.get(cid, 0) + 1
        return counts

    def _can_analyze(self, cve_id: str, counts: dict[str, int]) -> bool:
        """내가 아직 안 했고, CVE 당 분석 상한 미만이면 분석 가능(같은 CVE 다관점 허용)."""
        if cve_id in self.state.analyzed_cves:
            return False
        return counts.get(cve_id, 0) < self.cfg.max_perspectives

    def _pick_notification(self, notifs: list[dict]) -> dict | None:
        """내가 쓴 코멘트(자기인용)·기답·빈내용 제외, 오래된 미답부터."""
        for n in notifs:
            cid = n.get("commentId")
            if str(cid) in self.state.replied_comments:
                continue
            if (n.get("authorPersona") == self.cfg.persona
                    or n.get("authorName") == self.cfg.persona):
                continue
            if len((n.get("content") or "").strip()) < 2:
                continue
            return n
        return None

    @staticmethod
    def _score_peer(a: dict) -> float:
        """동료 분석 선택 점수: 최신 + 댓글 적음 + 심각도."""
        sev = {"critical": 3, "high": 2, "medium": 1}.get(
            (a.get("severity") or "").lower(), 0)
        created = a.get("createdAt") or ""
        # ISO 문자열 사전식 비교로 최신성 근사(동일 포맷 가정)
        recency = created  # 문자열; 비교는 _pick_peer 에서 정렬키로 사용
        comments = a.get("commentCount") or 0
        # 수치 점수: 심각도*10 - 댓글수*0.5 (+ 최신성은 정렬 1순위로 별도 처리)
        return sev * 10 - comments * 0.5

    def _pick_peer(self, community: list[dict]) -> dict | None:
        import random  # noqa: PLC0415
        eligible = [
            a for a in community
            if a.get("authorPersona") != self.cfg.persona
            and str(a.get("id")) not in self.state.commented_analyses
        ]
        if not eligible:
            return None
        # 최신성(createdAt) 1순위, 점수 2순위, 동률 랜덤
        random.shuffle(eligible)
        eligible.sort(key=lambda a: (a.get("createdAt") or "", self._score_peer(a)),
                      reverse=True)
        return eligible[0]
```

- [ ] **Step 4: agent.py — do_replies / do_comment / do_analysis 가 헬퍼 사용하도록 수정**

`do_replies` 본문을 교체:
```python
    def do_replies(self) -> None:
        n = self._pick_notification(self.k.notifications(limit=10) or [])
        if n is None:
            return
        cmt_id = n.get("commentId")
        self.state.replied_comments.add(str(cmt_id))
        text = self.brain.reply_to_comment(n)
        if len(text.strip()) < 2:
            return
        self.k.post_comment(n["cveId"], text, parent_id=cmt_id)
        self.log(f"  ↩️  답글: {n['cveId']} (← {n.get('authorName')})")
```

`do_comment` 의 `peer = next(...)` 선택부를 교체:
```python
    def do_comment(self, community: list[dict]) -> None:
        peer = self._pick_peer(community)
        if peer is None:
            return
        text = self.brain.comment_on_peer(peer)
        if len(text.strip()) < 2:
            return
        self.k.post_comment(peer["cveId"], text)
        self.state.commented_analyses.add(str(peer.get("id")))
        self.log(f"  💬 댓글: {peer['cveId']} (← {peer.get('authorName')})")
```

`do_analysis` 의 폴백(list_cves) 선택부를 다관점 상한 기준으로 교체. 기존:
```python
            cands = self.k.list_cves(limit=10)
            community_cves = {a.get("cveId") for a in community}
            target = next(
                (c for c in cands if c["cveId"] not in self.state.analyzed_cves
                 and c["cveId"] not in community_cves),
                None,
            ) or next((c for c in cands if c["cveId"] not in self.state.analyzed_cves), None)
```
을 다음으로 교체:
```python
            cands = self.k.list_cves(limit=10)
            counts = self._analysis_counts(community)
            target = next((c for c in cands if self._can_analyze(c["cveId"], counts)), None)
```
그리고 `_pick_from_feeds` 안의 `for cid, art in articles.items():` 루프의 `if cid in self.state.analyzed_cves: continue` 를, 호출부에서 counts 를 넘겨 상한도 보게 바꾼다. `_pick_from_feeds` 시그니처에 `counts` 인자를 추가:
```python
    def _pick_from_feeds(self, counts: dict[str, int]) -> tuple[dict | None, str, str]:
        ...
        for cid, art in articles.items():
            if not self._can_analyze(cid, counts):
                continue
        ...
```
그리고 `do_analysis` 첫 줄을 교체:
```python
    def do_analysis(self, community: list[dict]) -> None:
        counts = self._analysis_counts(community)
        detail, context, src = self._pick_from_feeds(counts)
```

- [ ] **Step 5: agent.py — brain.log 주입**

`Agent.__init__` 끝에 추가(생성 폴백 로그가 에이전트 로그로 나오도록):
```python
        self.brain.log = self.log
```

- [ ] **Step 6: 통과 확인**

Run: `python3 -m unittest tests.test_agent_selection -v`
Expected: PASS (5 tests)

- [ ] **Step 7: 커밋**

```bash
git add agent.py tests/test_agent_selection.py
git commit -m "feat(agent): 자기인용 수정·점수 댓글·다관점 분석 상한"
```

---

## Task 7: 문서 — .env.example & README

**Files:**
- Modify: `.env.example`, `README.md`

- [ ] **Step 1: .env.example 갱신**

기존 `# (선택) 저렴한 Claude 를 쓰려면 ...` 백엔드 안내 근처(또는 `AGENT_BACKEND` 정의 아래)에 추가:
```
# ─── OpenAI 호환 백엔드 (AGENT_BACKEND=openai) ───────────────
# OpenAI·Groq·OpenRouter·Together·로컬 vLLM/LM Studio 등 호환 API.
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=
LLM_MODEL=gpt-4o-mini
# LLM 호출 타임아웃(초). 0 = 백엔드 기본(ollama 600 / API 120).
AGENT_LLM_TIMEOUT=0
# CVE 당 분석 글 개수 상한(같은 CVE 다관점 허용 + 쏠림 방지).
AGENT_MAX_PERSPECTIVES=3
```

- [ ] **Step 2: README.md 갱신**

`brain.py` 설명 행 또는 백엔드 설명 부분에 openai 백엔드를 추가하고, API 표(읽기/쓰기)는 변경 없음. `## 사용하는 Kestrel API` 위 적절한 위치에 한 줄:
```
- LLM 백엔드: `ollama`(로컬·무료) / `claude`(Anthropic) / `openai`(OpenAI 호환: base_url 지정) / `dry`(데모). `AGENT_BACKEND` 로 선택.
```

- [ ] **Step 3: 커밋**

```bash
git add .env.example README.md
git commit -m "docs: openai 백엔드·신규 설정 문서화"
```

---

## Task 8: 통합 스모크 & 전체 검증

**Files:** 없음(검증·커밋만)

- [ ] **Step 1: 전체 구문 컴파일**

Run: `python3 -c "import py_compile,glob; [py_compile.compile(f,doraise=True) for f in glob.glob('*.py')]; print('compile OK')"`
Expected: `compile OK`

- [ ] **Step 2: 전체 테스트 스위트**

Run: `python3 -m unittest discover -s tests -v`
Expected: 전체 PASS (config/llm/brain_quality/agent_selection)

- [ ] **Step 3: dry 백엔드 단일 사이클 오프라인 스모크**

`agents.example.json`(토큰 없음)으로 dry 백엔드 1사이클이 import·생성 경로를 타는지 확인(실제 게시 없음 — Kestrel 미인증이라 build 단계에서 멈추는 게 정상). 대신 Brain 경로만 직접:
Run:
```bash
python3 -c "
import config, brain
c=config.Config(kestrel_token='t',kestrel_api='x',backend='dry',anthropic_api_key='',anthropic_model='m',ollama_host='h',ollama_model='m',persona='방어Agent',persona_prompt='q',interval=1,use_feeds=False,feeds=(),topic_hours=0,openai_base_url='x',openai_api_key='',openai_model='m',llm_timeout=0,max_perspectives=3)
b=brain.make_brain(c)
print('analyze', len(b.analyze_cve({'cveId':'CVE-2026-1','severity':'high','cvssScore':9.0,'title':'t'}))>0)
print('comment', len(b.comment_on_peer({'cveId':'CVE-2026-1','authorName':'x','excerpt':'y'}))>0)
print('topic', len(b.write_topic_post([{'cveId':'CVE-2026-1','source':'s','title':'t'}]))>0)
"
```
Expected: `analyze True` / `comment True` / `topic True`

- [ ] **Step 4: 최종 커밋(이미 단계별 커밋됨 — 잔여분 정리)**

```bash
git add -A
git status --short
git commit -m "test: 통합 스모크 검증" --allow-empty
```

---

## Self-Review 결과

- **스펙 커버리지:** 목표1(이식성)=Task2·5·7, 목표2(환각)=Task3·4, 목표3(검증·재시도)=Task4, 목표4(활동선택)=Task6, 목표5(견고성)=Task2·4. 설정 일반화=Task1·7. 테스트=Task1·2·3·4·6·8. 누락 없음.
- **스펙과의 의도적 차이:** `analyze_cve` 의 `allowed_cves` 를 `{cve}∪related()` 가 아니라 `{cve}` 로 단순화(브레인이 Kestrel 의존을 안 갖고, 분석마다 `related()` 추가 호출을 피하기 위함 — redact 가 인라인 치환이라 과삭제 위험 낮음). 견고성 재시도를 LLMClient/generate 두 층으로 나누지 않고 **generate 의 5회 예산 단일 루프**로 통합(스펙의 "총 5회 상한" 목표를 더 단순·예측가능하게 달성). 두 변경 모두 "최적화" 요청에 부합.
- **타입 일관성:** `generate(...)` 시그니처/`_find_cves`·`_has_sections`·`_redact_cves`·`_can_analyze`·`_pick_notification`·`_pick_peer`·`_analysis_counts`·`make_client`·`LLMError(fatal=)` 명칭이 정의·사용처에서 일치.
- **플레이스홀더:** 없음(모든 코드 단계에 실제 코드 포함).
