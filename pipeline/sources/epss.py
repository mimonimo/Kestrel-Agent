"""FIRST.org EPSS 단건 조회 — 표준 라이브러리(urllib)만, 24h 파일 캐시, 실패 시 None.

get_cve 응답엔 EPSS 가 없으므로 여기서 보강한다(키 불필요):
  GET https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY
  → data[0].epss(확률 문자열)·percentile 추출. data 가 [] 이면 None.

EPSS 는 하루 1회만 갱신되므로 cveId 별 24h 파일 캐시로 중복 호출을 막는다.
네트워크 실패·타임아웃·빈 응답은 예외를 삼키고 None 을 반환한다(파이프라인은 계속).
테스트는 http 인자로 가짜 fetch 를 주입해 hermetic 하게 검증한다.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

_API = "https://api.first.org/data/v1/epss"
_TTL = 24 * 3600
_CACHE_FILE = "epss_cache.json"
_UA = "Mozilla/5.0 (KestrelAgent EPSS reader)"


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _cache_path(cache_dir: str | None) -> Path:
    return (Path(cache_dir) if cache_dir else _repo_root()) / _CACHE_FILE


def _load_cache(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _save_cache(path: Path, cache: dict) -> None:
    try:
        path.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


def _http(cve_id: str, timeout: int) -> dict:
    url = f"{_API}?cve={urllib.parse.quote(cve_id)}"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def fetch_epss(cve_id: str, *, timeout: int = 5, cache_dir: str | None = None,
               http=_http) -> dict | None:
    """{'epss': float, 'percentile': float} 또는 None. 24h 캐시(없음도 캐시)."""
    path = _cache_path(cache_dir)
    cache = _load_cache(path)
    hit = cache.get(cve_id)
    now = time.time()
    if hit and now - hit.get("ts", 0) < _TTL:
        return ({"epss": hit["epss"], "percentile": hit["percentile"]}
                if hit.get("epss") is not None else None)

    try:
        data = http(cve_id, timeout)
    except Exception:  # noqa: BLE001 — 네트워크/타임아웃/파싱 실패는 조용히 None
        return None

    rows = (data or {}).get("data") or []
    if not rows:
        cache[cve_id] = {"epss": None, "percentile": None, "ts": now}
        _save_cache(path, cache)
        return None
    try:
        epss = float(rows[0].get("epss"))
        percentile = float(rows[0].get("percentile"))
    except (TypeError, ValueError):
        return None
    cache[cve_id] = {"epss": epss, "percentile": percentile, "ts": now}
    _save_cache(path, cache)
    return {"epss": epss, "percentile": percentile}
