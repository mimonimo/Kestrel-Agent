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

# 파이프라인産 분석의 게시 메타에 실리는 버전 표식 — 플랫폼/논문에서 어느 파이프라인이
# 생성했는지 추적한다. 파이프라인 산출 스키마가 바뀌면 올린다.
PIPELINE_VERSION = "kestrel-agent-pipeline-v1"


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

    def _is_self(self, author_name: str | None = None, author_persona: str | None = None) -> bool:
        """이 글·댓글 작성자가 나인지. API 가 authorName 에 이모지 접두("🤖 방어Agent")를
        붙이므로 정확 일치가 아니라 페르소나 포함 여부로 판정한다(자기 글에 자답 방지)."""
        if author_persona and author_persona == self.cfg.persona:
            return True
        return bool(author_name) and self.cfg.persona in author_name

    def _pick_notification(self, notifs: list[dict]) -> dict | None:
        """내가 쓴 코멘트(자기인용)·기답·빈내용 제외. 알림 API 가 준 순서대로 첫 미답을 고른다."""
        for n in notifs:
            cid = n.get("commentId")
            if str(cid) in self.state.replied_comments:
                continue
            if self._is_self(n.get("authorName"), n.get("authorPersona")):
                continue
            if len((n.get("content") or "").strip()) < 2:
                continue
            return n
        return None

    @staticmethod
    def _peer_author(a: dict) -> str:
        """동률·분산 판정용 작성자 키(페르소나 우선, 없으면 이름)."""
        return (a.get("authorPersona") or a.get("authorName") or "").strip()

    def _score_peer(self, a: dict, recency_rank: int) -> float:
        """동료 분석 선택 점수. 어느 한 사람·한 글에 쏠리지 않도록 가중치를 합산한다.

        - 심각도 높을수록 가산(critical 9 ~ medium 3)
        - 최신일수록 가산하되 *상한이 있는* 완만한 가산(recency_rank 0=최신 → +5, 이후 1씩 감소)
        - 댓글이 이미 많은 글은 감산(이미 토론이 붙은 글 말고 빈 글로 유도)
        - 내가 이미 그 작성자에게 댓글을 많이 달았으면 크게 감산(작성자 다양성)
        기존엔 createdAt 가 1순위라 '가장 최근 글 한 건'에만 쏠렸다 — 그 편향을 없앤다.
        """
        sev = {"critical": 9, "high": 6, "medium": 3}.get(
            (a.get("severity") or "").lower(), 1)
        comments = a.get("commentCount") or 0
        seen = self.state.commented_authors.get(self._peer_author(a), 0)
        return sev + max(0, 5 - recency_rank) - comments * 1.0 - seen * 4.0

    def _pick_peer(self, community: list[dict]) -> dict | None:
        eligible = [
            a for a in community
            if not self._is_self(a.get("authorName"), a.get("authorPersona"))
            and str(a.get("id")) not in self.state.commented_analyses
        ]
        if not eligible:
            return None
        # 최신순 등수(0=가장 최신)를 점수 한 요소로만 쓴다(절대 1순위 아님).
        order = sorted(eligible, key=lambda a: a.get("createdAt") or "", reverse=True)
        recency = {id(a): i for i, a in enumerate(order)}
        random.shuffle(eligible)  # 동점 랜덤 타이브레이크(쏠림 추가 방지)
        eligible.sort(key=lambda a: self._score_peer(a, recency[id(a)]), reverse=True)
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
        # 브레드스 우선: 아무도 분석 안 한 CVE(count 0)를 먼저 고르고, 같은 count 끼리는
        # 피드 등장순(대개 최신)을 유지한다. 같은 CVE 가 계속 재선정되는 쏠림을 줄인다.
        cands = [(cid, art) for cid, art in articles.items() if self._can_analyze(cid, counts)]
        cands.sort(key=lambda x: counts.get(x[0], 0))
        for cid, art in cands:
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
            cands = self.k.list_cves(limit=50)  # 풀을 넓혀 다양한 CVE 가 선정되도록
            eligible = [c for c in cands if self._can_analyze(c["cveId"], counts)]
            eligible.sort(key=lambda c: counts.get(c["cveId"], 0))  # 새 CVE(0건) 우선
            target = eligible[0] if eligible else None
            if target is None:
                self.log("· 분석할 새 CVE 가 없습니다(이번 사이클 건너뜀).")
                return
            detail = self.k.get_cve(target["cveId"])

        cid = detail["cveId"]
        self.log(f"· 분석 중: {cid} ({detail.get('severity')}, CVSS {detail.get('cvssScore')})"
                 f"{' [외부보도]' if context else ''}")
        # 과거 내 분석을 단순 최신순이 아니라 *이 CVE 와 관련된 것* 을 앞세워 전달해,
        # 새 분석이 기존 판단을 이어받아 더 깊어지도록(누적·고도화) 유도한다.
        mem_ctx = self._build_memory_context(cid)
        body, meta = self._make_analysis_body(detail, context, mem_ctx)
        if len(body.strip()) < 20:
            self.log(f"  분석 본문이 너무 짧아 건너뜀: {cid}")
            return
        out = self.k.publish_analysis(cid, body, **meta)
        self.state.analyzed_cves.add(cid)
        # 메모리 기록 — 핵심 요지(요약·위험도 결론)를 풍부하게 남겨 다음 분석이 이어받게 한다.
        self.state.memory.append(f"{cid}({detail.get('severity')}): {self._key_points(body)}")
        self.state.memory = self.state.memory[-20:]
        self.state.save()  # 게시 직후 즉시 저장 — 갑작스런 종료에도 재분석 방지
        self.log(f"  ✅ 게시 완료 {cid} (analysisId={out.get('id')})")

    # ── 분석 본문 생성: 기본은 brain, USE_PIPELINE=True 면 계층 2 파이프라인(4b) ──
    def _make_analysis_body(self, detail: dict, context: str,
                            mem_ctx: str) -> tuple[str, dict]:
        """(분석 본문 contentMd, publish_analysis 용 구조화 메타 kwargs)를 만든다.

        USE_PIPELINE=False(기본)면 기존 brain 경로 그대로 — 본문만 있고 메타는 {}
        (구조화 데이터가 없으므로 아무 필드도 보내지 않는다, 회귀 0).
        True 면 계층 2 파이프라인을 돌려 report 를 contentMd 로 변환하고 blackboard 의
        구조화 값(EPSS·우선순위·검증 신뢰도 등)을 메타로 함께 낸다. 파이프라인이
        실패하면 ""(빈 문자열)을 돌려 호출부가 이번 사이클 게시를 건너뛰게 한다
        (자동 폴백 없음 — 상태를 오염시키지 않고 다음 사이클에 재시도)."""
        if not getattr(self.cfg, "use_pipeline", False):
            return self.brain.analyze_cve(detail, context=context, memory=mem_ctx), {}
        return self._analysis_via_pipeline(detail)

    def _analysis_via_pipeline(self, detail: dict) -> tuple[str, dict]:
        from pipeline.state import Blackboard, PipelineContext  # noqa: PLC0415
        from pipeline.supervisor import run_pipeline  # noqa: PLC0415

        cid = detail.get("cveId")
        bb = Blackboard(cve_id=cid, persona=self.cfg.persona)
        # 봇이 이미 쓰는 kestrel·llm 클라이언트를 재사용(새 클라이언트 만들지 않음).
        # LLM 노드는 AGENT_ANALYSIS_MODEL(있으면)을 쓰고, 없으면 클라이언트 기본 모델.
        ctx = PipelineContext(kestrel=self.k, llm=getattr(self.brain, "client", None),
                              model=(self.cfg.analysis_model or None))
        try:
            run_pipeline(bb, ctx)
        except Exception as e:  # noqa: BLE001 — 한 CVE 실패가 봇 루프를 멈추지 않게
            self.log(f"  · 파이프라인 실행 실패({type(e).__name__}) — 이번 사이클 스킵")
            return "", {}
        if bb.needs_retry or not (bb.report.attack or bb.report.mitigation):
            self.log(f"  · 파이프라인 결과 미완(needs_retry={bb.needs_retry}) — 이번 사이클 스킵")
            return "", {}
        return self._pipeline_report_to_md(bb), self._pipeline_publish_meta(bb)

    @staticmethod
    def _pipeline_publish_meta(bb) -> dict:
        """blackboard 구조화 값 → publish_analysis 의 구조화 메타 kwargs.

        None 은 애초에 빼서 요청 body 에 실리지 않게 한다(플랫폼이 null 처리).
        quality_flags 는 blackboard 의 list[dict] 를 rule명 키의 dict 로 변환
        (플랫폼 스키마 dict[str,Any] 수용, 신호별 맥락 보존).
        validation_confidence 는 검증 규칙이 실제로 돌았을 때만 보낸다 —
        검증할 데이터가 없어 조용히 통과한 경우 기본값 0.0 을 보내면 오독이므로 생략."""
        v, ex, pr = bb.validation, bb.exploitability, bb.priority
        kev = bb.primary_record().get("kevListed")
        validated = bool(v.adopted_values or v.mismatches or v.quality_flags)
        quality = {f.get("rule", f"flag_{i}"): f
                   for i, f in enumerate(v.quality_flags)} or None
        meta = {
            "epss_score": ex.epss,
            "epss_percentile": ex.epss_percentile,
            "priority_action": pr.action,
            "priority_reasoning": pr.reasoning or None,
            "kev_listed": bool(kev) if kev is not None else None,
            "validation_confidence": v.confidence if validated else None,
            "exploitability_grade": ex.grade,
            "quality_flags": quality,
            "pipeline_version": PIPELINE_VERSION,
        }
        return {k: val for k, val in meta.items() if val is not None}

    @staticmethod
    def _pipeline_report_to_md(bb) -> str:
        """파이프라인 blackboard → 기존 publish_analysis 용 마크다운(contentMd).

        요약·위험도/우선순위 헤더를 포함해 기존 _key_points(메모리 누적)와도 호환되게 한다.
        """
        r, ex, pr = bb.report, bb.exploitability, bb.priority
        adopted = bb.validation.adopted_values or {}
        enriched = bb.enriched or {}
        parts: list[str] = []
        if r.summary_en:
            parts.append(f"> {r.summary_en}\n")
        sev = adopted.get("severity") or enriched.get("severity") or "미상"
        parts.append("## 📋 요약")
        parts.append(
            f"- 심각도 {sev} · CVSS {adopted.get('cvssScore', '미상')} · "
            f"EPSS {ex.epss if ex.epss is not None else '미확보'} · "
            f"악용난이도 {ex.grade or '미상'}"
            f"{' · KEV' if enriched.get('kev') else ''}")
        parts.append("\n## 🔍 공격 기법")
        parts.append(r.attack or "추정: 제공된 정보로는 상세 공격 기법을 확정하기 어렵습니다.")
        if ex.narrative:
            parts.append(f"\n**악용 가능성**: {ex.narrative}")
        if r.detection:
            parts.append("\n## 🔎 탐지")
            parts.append(r.detection)
        parts.append("\n## 🛡️ 완화 방안")
        parts.append(r.mitigation or "벤더 패치 적용과 노출면 점검을 우선하세요.")
        parts.append("\n## ⚖️ 위험도 / 우선순위")
        parts.append(f"- 조치: {pr.action or '미상'} ({pr.timeline or '미상'})")
        if pr.reasoning:
            parts.append(f"- 근거: {pr.reasoning}")
        return "\n".join(parts).strip()

    # ── 분석 누적·고도화 헬퍼 ─────────────────────────────────
    @staticmethod
    def _key_points(body: str) -> str:
        """분석 본문에서 핵심 요지를 추출(요약/위험도 결론 우선, 최대 ~240자).

        다음 분석이 '제목 수준' 이 아니라 *직전 판단의 내용* 을 이어받아 발전시키도록,
        90자 단순 절단 대신 의미 있는 결론 줄을 모은다."""
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        keep: list[str] = []
        section = ""
        for ln in lines:
            if ln.lstrip().startswith("#"):
                section = ln.lstrip("# ").strip()
                continue
            # 요약·위험도/우선순위 섹션의 본문 줄을 우선 수집(결론·판단이 담긴 곳)
            if any(k in section for k in ("요약", "위험도", "우선순위")):
                keep.append(ln.lstrip("-*• ").strip())
            if sum(len(s) for s in keep) > 240:
                break
        if not keep:  # 섹션 매칭 실패 시 본문 앞부분으로 폴백
            keep = [ln.lstrip("-*• ").strip() for ln in lines if not ln.startswith("#")][:2]
        return " / ".join(keep)[:240]

    def _build_memory_context(self, cid: str) -> str:
        """이 CVE 와 관련된 과거 내 분석을 앞에, 최근 분석을 뒤에 둔 컨텍스트 문자열."""
        related_ids: set[str] = set()
        try:
            related_ids = {r.get("cveId") for r in (self.k.related(cid) or []) if r.get("cveId")}
        except KestrelError:
            pass
        related_mem = [m for m in self.state.memory
                       if any(rid and rid in m for rid in related_ids)]
        recent_mem = [m for m in self.state.memory if m not in related_mem][-6:]
        # 관련 분석은 최대 4건까지 앞세우고, 그 뒤로 최근 분석을 붙인다.
        return "\n".join(related_mem[-4:] + recent_mem)


    # ── 2) 동료 글에 댓글 ─────────────────────────────────────
    def do_comment(self, community: list[dict]) -> None:
        peer = self._pick_peer(community)
        if peer is None:
            return
        text = self.brain.comment_on_peer(peer)
        if len(text.strip()) < 2:
            return
        # 최상위 댓글 — analysisId 필수(이 분석 스레드에 붙도록)
        self.k.post_comment(peer["cveId"], text, analysis_id=peer.get("id"))
        self.state.commented_analyses.add(str(peer.get("id")))
        author = self._peer_author(peer)
        if author:
            self.state.commented_authors[author] = \
                self.state.commented_authors.get(author, 0) + 1
        self.state.save()
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
        # 답글 — 알림의 analysisId + parentId(=commentId) 로 같은 스레드에 붙임
        self.k.post_comment(n["cveId"], text, parent_id=cmt_id, analysis_id=n.get("analysisId"))
        self.state.save()
        self.log(f"  ↩️  답글: {n['cveId']} (← {n.get('authorName')})")

    # ── 4) 동료 분석의 댓글 스레드에서 '남의 댓글'에 이어 답글(토론 체인) ──
    def _pick_thread_comment(self, thread: list[dict]) -> dict | None:
        """내가 아직 답하지 않은, 내 페르소나가 쓴 게 아닌 동료의 댓글 하나."""
        for c in thread:
            cid = c.get("id")
            if cid is None or str(cid) in self.state.replied_comments:
                continue
            if self._is_self(c.get("authorName"), c.get("authorPersona")):
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
            # 대댓글 — parentId(부모 댓글)로 스레드에 붙음. analysisId 는 부모에서 상속(있으면 명시).
            self.k.post_comment(cid, text, parent_id=target.get("id"),
                                analysis_id=target.get("analysisId"))
            self.state.save()
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
        self.state.save()
        self.log(f"  📝 자유글 게시: {title} (postId={out.get('id')})")

    # ── 6) 커뮤니티 분석들을 엮은 '쟁점 종합' 자유글(주기적) ──────────
    def do_community_digest(self, community: list[dict]) -> None:
        """digest_hours 마다, 커뮤니티에 올라온 실제 분석들을 엮어 쟁점 종합 글을 게시한다."""
        if self.cfg.digest_hours <= 0:
            return
        now = time.time()
        if now - self.state.last_digest_ts < self.cfg.digest_hours * 3600:
            return
        # 내 글만 있으면 '종합'할 거리가 없다 — 동료 분석이 2건 이상일 때만.
        peers = [a for a in community
                 if not self._is_self(a.get("authorName"), a.get("authorPersona"))]
        if len(peers) < 2:
            return
        body = self.brain.write_community_digest(community[:10])
        if len(body.strip()) < 40:
            return
        title = f"{self.cfg.persona} · 커뮤니티 쟁점 종합 ({time.strftime('%Y-%m-%d')})"
        out = self.k.publish_post(title, body)
        self.state.last_digest_ts = now
        self.state.save()
        self.log(f"  🧵 종합글 게시: {title} (postId={out.get('id')})")

    # ── 한 사이클 ─────────────────────────────────────────────
    def cycle(self) -> None:
        community = self.k.community_analyses(limit=15)
        try:
            self.do_analysis(community)
            self.do_comment(community)
            self.do_replies()
            self.do_thread_discussion(community)
            self.do_topic_post()
            self.do_community_digest(community)
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
