"""외부 보안 이슈 파서 — 공개 보안 RSS/Atom 피드를 읽어 *실제로 보도되는* CVE 를 찾는다.

kestrel Agent API 는 CVE 에 묶인 분석만 게시할 수 있으므로, 외부 뉴스에서 CVE ID 를
추출해 'kestrel 에 존재하는 CVE' 와 매칭한다. 그러면 에이전트는 우선순위 점수뿐 아니라
*세상에서 지금 화제인* 취약점을 외부 보도 맥락과 함께 분석할 수 있다.

표준 라이브러리만 사용(urllib + xml.etree). 네트워크·파싱 실패는 조용히 건너뛴다.
"""
from __future__ import annotations

import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlparse

# 보안 전문 매체 공개 피드(인증 불필요). 필요시 .env AGENT_FEEDS 로 교체.
DEFAULT_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://isc.sans.edu/rssfeed.xml",
    "https://www.zerodayinitiative.com/rss/published/",  # ZDI — CVE 밀도 매우 높음
    "https://www.tenable.com/blog/feed",                 # Tenable 리서치
]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_UA = "Mozilla/5.0 (KestrelAgent feed reader)"


@dataclass
class Article:
    cve_id: str
    title: str
    link: str
    source: str
    summary: str


def _text(el) -> str:
    return (el.text or "").strip() if el is not None else ""


def _strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", " ", s or "").replace("&nbsp;", " ").strip()


def _fetch(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def _parse_items(xml_text: str) -> list[tuple[str, str, str]]:
    """RSS <item> / Atom <entry> 공통 파싱 → [(title, link, summary)]."""
    out: list[tuple[str, str, str]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1].lower()

    for node in root.iter():
        if local(node.tag) not in ("item", "entry"):
            continue
        title = link = summary = ""
        for child in node:
            t = local(child.tag)
            if t == "title":
                title = _text(child)
            elif t == "link":
                # RSS: 텍스트, Atom: href 속성
                link = _text(child) or child.attrib.get("href", "")
            elif t in ("description", "summary", "content", "encoded"):
                summary = summary or _strip_html(_text(child))
        out.append((title, link, summary))
    return out


def collect_cve_articles(feeds: list[str], log=lambda *_: None) -> dict[str, Article]:
    """피드들을 읽어 CVE ID → 그 CVE 를 언급한 첫 기사 매핑을 만든다(최신 우선)."""
    found: dict[str, Article] = {}
    for url in feeds:
        source = urlparse(url).netloc
        try:
            items = _parse_items(_fetch(url))
        except Exception as e:  # noqa: BLE001
            log(f"· 피드 실패 {source}: {type(e).__name__}")
            continue
        for title, link, summary in items:
            for m in _CVE_RE.findall(f"{title} {summary}"):
                cid = m.upper()
                if cid not in found:  # 먼저 등장한(=대개 더 최신) 기사 우선
                    found[cid] = Article(
                        cve_id=cid, title=title.strip(), link=link.strip(),
                        source=source, summary=summary[:600],
                    )
        log(f"· 피드 {source}: 기사 {len(items)}건")
    return found


# 여러 에이전트가 매 사이클 같은 피드를 다시 받지 않도록 TTL 캐시(공유).
_CACHE: dict = {"key": None, "ts": 0.0, "data": {}}


def collect_cached(feeds: list[str], ttl: int = 600, log=lambda *_: None) -> dict[str, Article]:
    key = tuple(feeds)
    now = time.time()
    if _CACHE["key"] == key and now - _CACHE["ts"] < ttl:
        return _CACHE["data"]
    data = collect_cve_articles(feeds, log=log)
    _CACHE.update(key=key, ts=now, data=data)
    return data
