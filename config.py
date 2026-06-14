"""환경설정 로더 — `.env` 를 읽어 Config 로 묶는다(외부 의존성 없음)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_BASE = Path(__file__).resolve().parent


def load_dotenv(path: Path = _BASE / ".env") -> None:
    """아주 가벼운 .env 파서 — 이미 os.environ 에 있으면 덮어쓰지 않는다."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


@dataclass(frozen=True)
class Config:
    kestrel_token: str
    kestrel_api: str
    backend: str  # claude | dry | ollama
    anthropic_api_key: str
    anthropic_model: str
    ollama_host: str
    ollama_model: str
    persona: str
    persona_prompt: str
    interval: int
    use_feeds: bool
    feeds: tuple[str, ...]
    topic_hours: int  # 자유 토픽 글(동향 브리핑) 최소 게시 간격(시간). 0 = 비활성
    digest_hours: int  # 커뮤니티 종합 글 최소 게시 간격(시간). 0 = 비활성
    openai_base_url: str   # OpenAI 호환 엔드포인트
    openai_api_key: str
    openai_model: str
    llm_timeout: int       # LLM 호출 타임아웃(초). 0 = 백엔드 기본값 사용
    max_perspectives: int  # CVE 당 분석 개수 상한

    @classmethod
    def from_env(cls) -> "Config":
        load_dotenv()
        return cls(
            kestrel_token=os.environ.get("KESTREL_TOKEN", "").strip(),
            kestrel_api=os.environ.get("KESTREL_API", "https://www.kestrel.forum/api/v1").strip(),
            backend=os.environ.get("AGENT_BACKEND", "claude").strip().lower(),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", "").strip(),
            anthropic_model=os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-8").strip(),
            ollama_host=os.environ.get("OLLAMA_HOST", "http://localhost:11434").strip(),
            ollama_model=os.environ.get("OLLAMA_MODEL", "llama3.1").strip(),
            persona=os.environ.get("AGENT_PERSONA", "보안 분석가").strip(),
            persona_prompt=os.environ.get(
                "AGENT_PERSONA_PROMPT", "실용적이고 방어 중심으로 분석합니다."
            ).strip(),
            interval=int(os.environ.get("AGENT_INTERVAL", "180")),
            use_feeds=os.environ.get("AGENT_USE_FEEDS", "true").strip().lower()
            not in ("0", "false", "no", ""),
            feeds=tuple(
                f.strip() for f in os.environ.get("AGENT_FEEDS", "").split(",") if f.strip()
            ),
            topic_hours=int(os.environ.get("AGENT_TOPIC_HOURS", "6")),
            digest_hours=int(os.environ.get("AGENT_DIGEST_HOURS", "8")),
            openai_base_url=os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").strip(),
            openai_api_key=os.environ.get("LLM_API_KEY", "").strip(),
            openai_model=os.environ.get("LLM_MODEL", "gpt-4o-mini").strip(),
            llm_timeout=int(os.environ.get("AGENT_LLM_TIMEOUT", "0")),
            max_perspectives=int(os.environ.get("AGENT_MAX_PERSPECTIVES", "3")),
        )

    def validate(self) -> None:
        if not self.kestrel_token:
            raise SystemExit("KESTREL_TOKEN 이 비어 있습니다. agent/.env 를 확인하세요.")
        if self.backend not in {"claude", "dry", "ollama", "openai"}:
            raise SystemExit(f"알 수 없는 AGENT_BACKEND: {self.backend}")
        if self.backend == "claude" and not self.anthropic_api_key:
            raise SystemExit(
                "AGENT_BACKEND=claude 인데 ANTHROPIC_API_KEY 가 없습니다.\n"
                "  → 키를 .env 에 채우거나, 키 없이 흐름만 보려면 AGENT_BACKEND=dry 로 두세요."
            )
        # 공개 OpenAI 엔드포인트는 키가 필수. 커스텀 base_url(로컬 vLLM/LM Studio·프록시 등)은
        # 키 없이 쓰는 경우가 많아 강제하지 않는다(가짜 키 입력 회피).
        if (self.backend == "openai" and not self.openai_api_key
                and self.openai_base_url.startswith("https://api.openai.com")):
            raise SystemExit(
                "AGENT_BACKEND=openai 인데 LLM_API_KEY 가 없습니다(공개 OpenAI 엔드포인트).\n"
                "  → LLM_API_KEY 를 채우거나, 로컬/사설 서버면 LLM_BASE_URL 을 지정하세요."
            )
