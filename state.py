"""런타임 상태 — 이미 분석/댓글/답글한 대상을 기억해 중복을 막는다(재시작에도 유지).

에이전트마다 별도 파일(state_<slug>.json)을 써서 여러 에이전트가 서로 섞이지 않게 한다.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_BASE = Path(__file__).resolve().parent


def _slug(name: str) -> str:
    s = re.sub(r"[^0-9A-Za-z가-힣_-]+", "-", name).strip("-").lower()
    return s or "default"


class State:
    def __init__(self, name: str = "default") -> None:
        self.path = _BASE / f"state_{_slug(name)}.json"
        self.analyzed_cves: set[str] = set()
        self.commented_analyses: set[str] = set()
        self.replied_comments: set[str] = set()
        # 작성자(페르소나)별 내가 단 댓글 누적 횟수 — 한 사람에게 쏠리지 않게 분산용.
        self.commented_authors: dict[str, int] = {}
        self.last_topic_ts: float = 0.0  # 마지막 자유 토픽 글 게시 시각(epoch)
        self.last_digest_ts: float = 0.0  # 마지막 커뮤니티 종합 글 게시 시각(epoch)
        self.memory: list[str] = []  # 과거 분석 요지 누적(중복 회피·연속성용)
        # 429(레이트리밋)로 게시 못 한 파이프라인 분석 — 결과를 버리지 않고 보관해 다음
        # 사이클에 재게시한다. 각 항목: {cveId, body, meta, sev}.
        self.pending_analyses: list[dict] = []
        self.rate_limited_until: float = 0.0  # 이 시각(epoch) 전에는 게시 재시도 보류
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            self.analyzed_cves = set(d.get("analyzed_cves", []))
            self.commented_analyses = set(d.get("commented_analyses", []))
            # 댓글 ID 는 문자열로 정규화해 둔다(알림 commentId=정수, 스레드 댓글 id=정수/UUID
            # 가 섞여도 같은 집합에서 중복 판정이 일관되게 동작하도록).
            self.replied_comments = {str(x) for x in d.get("replied_comments", [])}
            self.commented_authors = {str(k): int(v)
                                      for k, v in (d.get("commented_authors") or {}).items()}
            self.last_topic_ts = float(d.get("last_topic_ts", 0.0))
            self.last_digest_ts = float(d.get("last_digest_ts", 0.0))
            self.memory = list(d.get("memory", []))[-20:]
            self.pending_analyses = list(d.get("pending_analyses", []))
            self.rate_limited_until = float(d.get("rate_limited_until", 0.0))
        except Exception:  # noqa: BLE001
            pass  # 손상 시 빈 상태로 시작

    def save(self) -> None:
        self.path.write_text(
            json.dumps(
                {
                    "analyzed_cves": sorted(self.analyzed_cves),
                    "commented_analyses": sorted(self.commented_analyses),
                    "replied_comments": sorted(self.replied_comments),
                    "commented_authors": self.commented_authors,
                    "last_topic_ts": self.last_topic_ts,
                    "last_digest_ts": self.last_digest_ts,
                    "memory": self.memory[-20:],
                    "pending_analyses": self.pending_analyses,
                    "rate_limited_until": self.rate_limited_until,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
