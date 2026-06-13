"""멀티 에이전트 프로필 — 여러 페르소나를 한 번에 정의/실행하기 위한 설정.

프로필 파일(JSON) 예시는 agents.example.json 참고. 각 에이전트는 자기 토큰으로
식별되며, 토큰이 없으면 자동 등록(/agents/register)해 .agent_tokens.json 에 캐시한다.

토큰 우선순위: profile.token  >  환경변수(profile.tokenEnv)  >  캐시  >  자동 등록
"""
from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

from config import Config
from kestrel_client import register_agent

_BASE = Path(__file__).resolve().parent
_TOKEN_CACHE = _BASE / ".agent_tokens.json"


def _load_cache() -> dict[str, str]:
    if _TOKEN_CACHE.exists():
        try:
            return json.loads(_TOKEN_CACHE.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _save_cache(cache: dict[str, str]) -> None:
    _TOKEN_CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def resolve_token(api: str, p: dict, cache: dict[str, str], log=print) -> str:
    """프로필 하나의 토큰을 확정한다(필요 시 자동 등록 후 캐시)."""
    if p.get("token"):
        return str(p["token"]).strip()
    env_name = p.get("tokenEnv")
    if env_name and os.environ.get(env_name):
        return os.environ[env_name].strip()
    name = p["name"]
    if cache.get(name):
        return cache[name]
    # 자동 등록
    log(f"· '{name}' 토큰이 없어 자동 등록합니다…")
    out = register_agent(
        api,
        name=name,
        persona=p.get("persona", ""),
        avatar_emoji=p.get("emoji", "🤖"),
        persona_prompt=p.get("personaPrompt", ""),
        bio=p.get("bio", ""),
    )
    token = out["token"]
    cache[name] = token
    _save_cache(cache)
    log(f"  ✅ 등록됨 (id={out.get('id')}) — 토큰을 .agent_tokens.json 에 캐시")
    return token


def build_configs(path: Path, base: Config, log=print) -> list[Config]:
    """프로필 파일 → 에이전트별 Config 목록. base(.env) 값을 기본값으로 사용."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    defaults = data.get("defaults", {})
    agents = data.get("agents", [])
    if not agents:
        raise SystemExit(f"{path} 에 agents 배열이 비어 있습니다.")

    api = defaults.get("api", base.kestrel_api)
    cache = _load_cache()
    configs: list[Config] = []
    for p in agents:
        if "name" not in p:
            raise SystemExit("각 에이전트 프로필에는 'name' 이 필요합니다.")
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
    return configs
