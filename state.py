"""런타임 상태 — 이미 분석/댓글/답글한 대상을 기억해 중복을 막는다(재시작에도 유지).

에이전트마다 별도 파일(state_<slug>.json)을 써서 여러 에이전트가 서로 섞이지 않게 한다.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

_BASE = Path(__file__).resolve().parent
_MAX_RECORDS = 60         # 개정 후보로 유지할 CVE 수(최신순) — state 파일 비대화 방지
_MAX_RECORD_BODY = 8000   # 기록할 본문 상한(자). 개정 프롬프트에 싣는 양보다 넉넉히


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
        # 내가 게시한 분석의 CVE별 기록 — 개정(revision) 대상 선정과 전후 비교의 근거.
        # cveId → {analysis_id, ts, peer_at_write, comment_at_write, revisions, body}
        # analyzed_cves(중복 방지용 집합)와 별개로 둔다: 저 집합은 '했다/안 했다'만 알고,
        # 개정하려면 '무엇을 썼는지·그때 동료 정보가 얼마였는지'가 필요하다.
        self.analysis_records: dict[str, dict] = {}
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
            self.analysis_records = {str(k): dict(v) for k, v
                                     in (d.get("analysis_records") or {}).items()
                                     if isinstance(v, dict)}
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
                    "analysis_records": self.analysis_records,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    # ── 개정 대상 기록 ────────────────────────────────────────
    def record_analysis(self, cve_id: str, *, analysis_id: str | None, body: str,
                        peer_at_write: int, comment_at_write: int,
                        revision_index: int = 0) -> None:
        """게시한 분석을 CVE 단위로 기록(같은 CVE 재게시는 덮어쓴다 = 항상 최신판이 개정 대상).

        본문을 통째로 들고 있는 이유: 개정판의 '흡수율'을 재려면 이전 판 원문이 필요하다.
        state 파일 비대화를 막기 위해 _MAX_RECORDS 개만 최신순으로 유지한다.
        """
        prev = self.analysis_records.get(cve_id) or {}
        self.analysis_records[cve_id] = {
            "analysis_id": analysis_id,
            "ts": time.time(),
            "peer_at_write": int(peer_at_write),
            "comment_at_write": int(comment_at_write),
            "revisions": int(revision_index or prev.get("revisions", 0)),
            "body": body[:_MAX_RECORD_BODY],
        }
        self._trim_records()

    def _trim_records(self) -> None:
        if len(self.analysis_records) <= _MAX_RECORDS:
            return
        ordered = sorted(self.analysis_records.items(),
                         key=lambda kv: kv[1].get("ts", 0.0), reverse=True)
        self.analysis_records = dict(ordered[:_MAX_RECORDS])
