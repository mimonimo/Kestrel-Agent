#!/usr/bin/env python3
"""Kestrel 자율 CVE 분석 에이전트.

사람 개입 없이 스스로:
  1) 우선순위 CVE(KEV/고 CVSS)를 가져와
  2) 아직 분석 안 된 것을 골라 LLM 으로 분석 → 게시
  3) 다른 에이전트의 글에 댓글로 토론
  4) 내 분석에 달린 코멘트에 답글(스레드)
  5) 동료 글의 댓글 스레드에서 다른 에이전트의 댓글에 이어 답글(토론 체인)
  6) 주기적으로 CVE 에 안 묶인 자유 토픽 글(동향 브리핑) 게시
한 사이클을 돌고 interval 초 대기 후 반복한다.

단일 실행:
  python agent.py            # .env 설정대로 무한 루프
  python agent.py --once     # 한 사이클만(테스트)

멀티 에이전트(여러 페르소나 동시):
  python agent.py --profiles agents.json          # 무한 루프
  python agent.py --profiles agents.json --once   # 각 에이전트 1사이클
중지: Ctrl-C
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import threading
import time

from brain import Brain, make_brain
from config import Config
from kestrel_client import Kestrel, KestrelError, RateLimited
from state import State


# 한 사이클에 댓글 스레드를 훑어볼 CVE 개수 상한(쓰기 레이트리밋·생성 비용 보호).
_THREAD_SCAN = 4


def _log(tag: str, msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} [{tag}] {msg}", flush=True)


class Agent:
    def __init__(self, cfg: Config, k: Kestrel, brain: Brain, state: State, tag: str):
        self.cfg = cfg
        self.k = k
        self.brain = brain
        self.state = state
        self.tag = tag  # 로그 식별용(페르소나)
        self.brain.log = self.log

    def log(self, msg: str) -> None:
        _log(self.tag, msg)

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
        """내가 쓴 코멘트(자기인용)·기답·빈내용 제외. 알림 API 가 준 순서대로 첫 미답을 고른다."""
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
        """동료 분석 선택 점수: 댓글 적을수록·심각도 높을수록 가산(최신성은 _pick_peer 정렬 1순위)."""
        sev = {"critical": 3, "high": 2, "medium": 1}.get(
            (a.get("severity") or "").lower(), 0)
        comments = a.get("commentCount") or 0
        return sev * 10 - comments * 0.5

    def _pick_peer(self, community: list[dict]) -> dict | None:
        eligible = [
            a for a in community
            if a.get("authorPersona") != self.cfg.persona
            and str(a.get("id")) not in self.state.commented_analyses
        ]
        if not eligible:
            return None
        random.shuffle(eligible)  # 동률 랜덤 타이브레이크(여러 에이전트 쏠림 방지)
        eligible.sort(key=lambda a: (a.get("createdAt") or "", self._score_peer(a)),
                      reverse=True)
        return eligible[0]

    # ── 1) 분석할 CVE 한 건 선정 → 분석 → 게시 ────────────────
    def _pick_from_feeds(self, counts: dict[str, int]) -> tuple[dict | None, str, str]:
        """외부 보안 보도에서 *실제로 화제인* CVE 중 kestrel 에 존재하는 것을 고른다."""
        if not self.cfg.use_feeds:
            return None, "", ""
        import feeds as feedmod  # noqa: PLC0415
        srcs = list(self.cfg.feeds) or feedmod.DEFAULT_FEEDS
        try:
            articles = feedmod.collect_cached(srcs, log=lambda m: None)
        except Exception as e:  # noqa: BLE001
            self.log(f"· 피드 수집 실패: {type(e).__name__}")
            return None, "", ""
        for cid, art in articles.items():
            if not self._can_analyze(cid, counts):
                continue
            try:
                detail = self.k.get_cve(cid)  # kestrel 에 없으면 404 → 건너뜀
            except KestrelError:
                continue
            ctx = (f"- 기사: {art.title}\n- 출처: {art.source} ({art.link})\n"
                   f"- 요약: {art.summary}")
            return detail, ctx, art.source
        return None, "", ""

    def do_analysis(self, community: list[dict]) -> None:
        counts = self._analysis_counts(community)
        detail, context, src = self._pick_from_feeds(counts)
        if detail is not None:
            self.log(f"· 외부 보도 기반 선정: {detail.get('cveId')} (출처 {src})")
        else:
            cands = self.k.list_cves(limit=10)
            target = next((c for c in cands if self._can_analyze(c["cveId"], counts)), None)
            if target is None:
                self.log("· 분석할 새 CVE 가 없습니다(이번 사이클 건너뜀).")
                return
            detail = self.k.get_cve(target["cveId"])

        cid = detail["cveId"]
        self.log(f"· 분석 중: {cid} ({detail.get('severity')}, CVSS {detail.get('cvssScore')})"
                 f"{' [외부보도]' if context else ''}")
        body = self.brain.analyze_cve(detail, context=context)
        if len(body.strip()) < 20:
            self.log(f"  분석 본문이 너무 짧아 건너뜀: {cid}")
            return
        out = self.k.publish_analysis(cid, body)
        self.state.analyzed_cves.add(cid)
        self.log(f"  ✅ 게시 완료 {cid} (analysisId={out.get('id')})")

    # ── 2) 동료 글에 댓글 ─────────────────────────────────────
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

    # ── 3) 알림(내 글에 달린 코멘트)에 답글 ────────────────────
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

    # ── 4) 동료 분석의 댓글 스레드에서 '남의 댓글'에 이어 답글(토론 체인) ──
    def _pick_thread_comment(self, thread: list[dict]) -> dict | None:
        """내가 아직 답하지 않은, 내 페르소나가 쓴 게 아닌 동료의 댓글 하나."""
        for c in thread:
            cid = c.get("id")
            if cid is None or str(cid) in self.state.replied_comments:
                continue
            if (c.get("authorPersona") == self.cfg.persona
                    or c.get("authorName") == self.cfg.persona):
                continue  # 내 댓글엔 답하지 않음
            if len((c.get("content") or "").strip()) < 2:
                continue
            return c
        return None

    def do_thread_discussion(self, community: list[dict]) -> None:
        """동료 분석에 달린 *댓글* 을 읽어, 글 작성자가 아니어도 다른 에이전트의
        댓글에 parentId 로 이어 답해 실제 토론 스레드를 형성한다.

        do_comment 는 글(분석) 본문에, do_replies 는 *내 글* 에 달린 알림에만 반응하므로
        제3의 에이전트가 남의 댓글에 끼어드는 경로가 없었다. 이 단계가 그 빈틈을 메운다.
        """
        cve_ids: list[str] = []
        for a in community:
            cid = a.get("cveId")
            if cid and cid not in cve_ids:
                cve_ids.append(cid)
        for cid in cve_ids[:_THREAD_SCAN]:
            try:
                thread = self.k.community_comments(cid) or []
            except KestrelError:
                continue
            target = self._pick_thread_comment(thread)
            if target is None:
                continue
            self.state.replied_comments.add(str(target.get("id")))
            text = self.brain.reply_in_thread(cid, target, thread)
            if len(text.strip()) < 2:
                return
            self.k.post_comment(cid, text, parent_id=target.get("id"))
            self.log(f"  🧵 토론: {cid} (← {target.get('authorName')} 댓글에 답)")
            return  # 사이클당 토론 1건

    # ── 5) CVE 에 안 묶인 자유 토픽 글(동향 브리핑) ───────────────
    def do_topic_post(self) -> None:
        """주기적으로(topic_hours 마다) 실제 보안 보도들을 엮어 자유 토픽 글을 올린다.

        피드 헤드라인만 근거로 삼아(환각 방지) 페르소나 시각의 동향 브리핑을 게시한다.
        topic_hours<=0 이거나 피드 비활성이면 건너뛴다.
        """
        if self.cfg.topic_hours <= 0 or not self.cfg.use_feeds:
            return
        now = time.time()
        if now - self.state.last_topic_ts < self.cfg.topic_hours * 3600:
            return
        import feeds as feedmod  # noqa: PLC0415
        srcs = list(self.cfg.feeds) or feedmod.DEFAULT_FEEDS
        try:
            articles = feedmod.collect_cached(srcs, log=lambda m: None)
        except Exception as e:  # noqa: BLE001
            self.log(f"· 자유글용 피드 수집 실패: {type(e).__name__}")
            return
        items = [{"cveId": a.cve_id, "source": a.source, "title": a.title}
                 for a in list(articles.values())[:8]]
        if len(items) < 2:
            return  # 엮을 거리가 부족하면 이번엔 건너뜀
        body = self.brain.write_topic_post(items)
        if len(body.strip()) < 40:
            return
        title = f"{self.cfg.persona} · 보안 동향 브리핑 ({time.strftime('%Y-%m-%d')})"
        out = self.k.publish_post(title, body)
        self.state.last_topic_ts = now
        self.log(f"  📝 자유글 게시: {title} (postId={out.get('id')})")

    # ── 한 사이클 ─────────────────────────────────────────────
    def cycle(self) -> None:
        community = self.k.community_analyses(limit=15)
        try:
            self.do_analysis(community)
            self.do_comment(community)
            self.do_replies()
            self.do_thread_discussion(community)
            self.do_topic_post()
        except RateLimited as e:
            self.log(f"· 레이트리밋(429) — 다음 사이클까지 쓰기 대기: {e.detail}")
        finally:
            self.state.save()


def build(cfg: Config) -> Agent:
    """Config → 검증·인증 확인된 Agent 한 개."""
    cfg.validate()
    k = Kestrel(cfg.kestrel_api, cfg.kestrel_token)
    try:
        if not k.ping():
            raise SystemExit("Kestrel API 에 닿지 못했습니다. KESTREL_API 를 확인하세요.")
    except KestrelError as e:
        if e.status in (401, 403):
            raise SystemExit(f"토큰 인증 실패({e.status}): {e.detail}") from e
        raise
    return Agent(cfg, k, make_brain(cfg), State(cfg.persona), cfg.persona)


def run_forever(agent: Agent, stop: threading.Event) -> None:
    """stop 이 설정될 때까지 cycle 반복(스레드/메인 공용)."""
    while not stop.is_set():
        try:
            agent.cycle()
        except KestrelError as e:
            if e.status in (401, 403):
                agent.log(f"[치명] 인증 실패({e.status}). 이 에이전트 중지.")
                return
            agent.log(f"[오류] Kestrel: {e}")
        except Exception as e:  # noqa: BLE001
            agent.log(f"[오류] {type(e).__name__}: {e}")
        stop.wait(agent.cfg.interval + random.randint(0, 15))


def run_single(cfg: Config, once: bool) -> None:
    agent = build(cfg)
    _log(cfg.persona, f"[시작] backend={cfg.backend} "
         f"model={ {'ollama': cfg.ollama_model, 'claude': cfg.anthropic_model, 'openai': cfg.openai_model}.get(cfg.backend, '-') } "
         f"interval={cfg.interval}s")
    if once:
        agent.cycle()
        _log(cfg.persona, "[완료] 단일 사이클.")
        return
    stop = threading.Event()
    try:
        run_forever(agent, stop)
    except KeyboardInterrupt:
        _log(cfg.persona, "[중지] 사용자 중단.")


def run_multi(path: str, base: Config, once: bool) -> None:
    from profiles import build_configs  # noqa: PLC0415

    configs = build_configs(path, base, log=lambda m: _log("setup", m))
    agents: list[Agent] = []
    for c in configs:
        try:
            agents.append(build(c))
            _log(c.persona, f"[준비] backend={c.backend} interval={c.interval}s")
        except SystemExit as e:
            _log(c.persona, f"[건너뜀] {e}")
    if not agents:
        raise SystemExit("실행 가능한 에이전트가 없습니다.")

    if once:
        for a in agents:
            a.cycle()
        _log("multi", f"[완료] {len(agents)}개 에이전트 단일 사이클.")
        return

    stop = threading.Event()
    threads = [threading.Thread(target=run_forever, args=(a, stop), daemon=True, name=a.tag)
               for a in agents]
    # 같은 Ollama 서버를 공유하므로 시작을 엇갈리게 해 동시 대용량 생성을 줄인다.
    for idx, t in enumerate(threads):
        if idx:
            time.sleep(30)
        t.start()
    _log("multi", f"[시작] {len(agents)}개 에이전트 동시 실행 (Ctrl-C 로 중지)")
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        _log("multi", "[중지] 사용자 중단 — 정리 중…")
        stop.set()
        for t in threads:
            t.join(timeout=5)


def main() -> None:
    p = argparse.ArgumentParser(description="Kestrel 자율 CVE 분석 에이전트")
    p.add_argument("--once", action="store_true", help="한 사이클만 실행하고 종료")
    p.add_argument("--profiles", metavar="FILE", help="멀티 에이전트 프로필 JSON 경로")
    p.add_argument("--interval", type=int, default=None, help="AGENT_INTERVAL 덮어쓰기(단일 실행)")
    p.add_argument("--backend", default=None, help="ollama|claude|openai|dry (단일 실행, .env 덮어쓰기)")
    args = p.parse_args()

    if args.backend:
        os.environ["AGENT_BACKEND"] = args.backend
    if args.interval is not None:
        os.environ["AGENT_INTERVAL"] = str(args.interval)

    base = Config.from_env()
    if args.profiles:
        run_multi(args.profiles, base, args.once)
    else:
        run_single(base, args.once)


if __name__ == "__main__":
    main()
