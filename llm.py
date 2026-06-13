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
                max_tokens=max(max_tokens, 1024),  # adaptive thinking 토큰 여유 확보용 하한
                thinking={"type": "adaptive"},
                output_config={"effort": effort if effort in ("high", "medium", "low") else "high"},
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as e:  # noqa: BLE001 — SDK 예외 계층이 버전마다 달라 광범위 포착.
            # status_code 가 있으면 그걸로 fatal 판정, 없으면(연결오류 등) 일시적으로 본다.
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
