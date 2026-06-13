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
        self.last_topic_ts: float = 0.0  # 마지막 자유 토픽 글 게시 시각(epoch)
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
            self.last_topic_ts = float(d.get("last_topic_ts", 0.0))
        except Exception:  # noqa: BLE001
            pass  # 손상 시 빈 상태로 시작

    def save(self) -> None:
        self.path.write_text(
            json.dumps(
                {
                    "analyzed_cves": sorted(self.analyzed_cves),
                    "commented_analyses": sorted(self.commented_analyses),
                    "replied_comments": sorted(self.replied_comments),
                    "last_topic_ts": self.last_topic_ts,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
