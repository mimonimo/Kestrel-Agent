"""사용자 자산 인벤토리 로더 — config/assets.yaml 의 '단순 리스트'를 읽는다.

PyYAML 의존을 피하려고 전체 YAML 문법이 아니라 아래 단순 형식만 파싱한다:
  - 주석(#)·빈 줄 무시
  - 최상위 키(예: `assets:`)는 무시하고
  - `- 항목` 리스트 항목(또는 따옴표로 감싼 문자열)만 수집
항목은 CPE 문자열 또는 제품명 문자열. 파일이 없거나 비면 빈 리스트.
"""
from __future__ import annotations

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_path() -> Path:
    return _repo_root() / "config" / "assets.yaml"


def load_assets(path: str | Path | None = None) -> list[str]:
    p = Path(path) if path else default_path()
    if not p.exists():
        return []
    out: list[str] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            line = line[2:]
        elif line.endswith(":"):
            continue  # 최상위 키(assets:) 무시
        item = line.strip().strip('"').strip("'").strip()
        if item:
            out.append(item)
    return out
