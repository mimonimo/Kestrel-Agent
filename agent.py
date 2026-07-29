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

import analytics
from brain import Brain, make_brain
from config import Config
from kestrel_client import Kestrel, KestrelError, RateLimited
from state import State


# 한 사이클에 댓글 스레드를 훑어볼 CVE 개수 상한(쓰기 레이트리밋·생성 비용 보호).
_THREAD_SCAN = 4

# 429 로 밀린 분석을 보관하는 로컬 큐의 상한(무한 적체 방지).
_MAX_PENDING = 50

# 기동 시 Kestrel API 가 일시적으로 느리거나 5xx 를 내면 build() 의 ping 이 실패한다.
# ping 은 기동 1회뿐이라, 여기서 재시도하지 않으면 그 페르소나가 프로세스 수명 내내
# 통째로 드롭된다(상시 3페르소나 구성이 조용히 깨짐). 일시 오류에 한해 재시도한다.
_BUILD_RETRIES = 6       # 최초 1회 + 최대 5회 재시도
_BUILD_RETRY_WAIT = 30   # 재시도 간 대기(초)

# 파이프라인産 분석의 게시 메타에 실리는 버전 표식 — 플랫폼/논문에서 어느 파이프라인이
# 생성했는지 추적한다. 파이프라인 산출 스키마가 바뀌면 올린다.
# v2: 페르소나별 섹션 깊이 분화(focus) + 번호 스캐폴드 복창 방지. v1 과 생성물이
# 달라지므로 런 이벤트에서 반드시 구분돼야 한다(같은 arm 이라도 별개 조건).
PIPELINE_VERSION = "kestrel-agent-pipeline-v2"


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
        # 파이프라인이 만든 런 이벤트를 게시 결과가 정해질 때까지 잠시 보관한다.
        # (생성 시점엔 outcome 을 모르고, 게시 시점엔 blackboard 가 없으므로.)
        self._run_event: dict | None = None

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
    def _pick_following(self) -> tuple[dict | None, str, str]:
        """다른 에이전트가 이미 분석한 CVE 를 따라간다(대조군 짝비교용).

        왜 필요한가: 기본 선정은 '아무도 분석 안 한 CVE 우선'이라 에이전트들이 서로 다른
        CVE 로 흩어진다. 커뮤니티 활성화엔 좋지만, arm 간 비교는 **같은 CVE** 를 양쪽이
        분석해야 성립하므로 대조군이 자연 겹침을 기다리면 표본이 거의 안 쌓인다.

        관점이 많이 붙은 CVE 를 먼저 고른다(짝이 최대한 많이 생기도록).
        max_perspectives 상한은 적용하지 않는다 — 대조군은 커뮤니티에 관점을 '더하는' 게
        아니라 같은 대상에 대한 독립 표본을 만드는 것이라 상한의 취지에 해당하지 않는다.
        """
        try:
            rows = self.k.community_analyses(limit=50)
        except KestrelError:
            return None, "", ""
        tally: dict[str, int] = {}
        for a in rows or []:
            cid = a.get("cveId")
            if not cid or self._is_self(a.get("authorName"), a.get("authorPersona")):
                continue
            tally[cid] = tally.get(cid, 0) + 1
        cands = sorted((c for c in tally if c not in self.state.analyzed_cves),
                       key=lambda c: -tally[c])
        for cid in cands:
            try:
                detail = self.k.get_cve(cid)
            except KestrelError:
                continue  # kestrel 에 없으면 건너뜀
            return detail, "", f"추종(관점 {tally[cid]}개)"
        return None, "", ""

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
        if time.time() < self.state.rate_limited_until:
            self.log("· 레이트리밋 대기 중 — 새 분석 생성 생략(큐 재게시 우선).")
            return
        # 추종 모드(대조군): 다른 에이전트가 분석한 CVE 를 우선 따라가 arm 간 짝을 만든다.
        detail, context, src = (None, "", "")
        if getattr(self.cfg, "follow_community", False):
            detail, context, src = self._pick_following()
            if detail is not None:
                self.log(f"· 추종 선정: {detail.get('cveId')} ({src})")
        if detail is None:
            detail, context, src = self._pick_from_feeds(counts)
            if detail is not None:
                self.log(f"· 외부 보도 기반 선정: {detail.get('cveId')} (출처 {src})")
        if detail is None:
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
            self._finalize_run_event("skipped_short")
            return
        self._publish_analysis(cid, body, meta, detail.get("severity"))

    # ── 게시(429 안전장치: 결과 큐 보관 + Retry-After 존중 재시도) ──────
    def _publish_analysis(self, cid: str, body: str, meta: dict, sev: str | None) -> bool:
        """분석을 게시. 성공 시 상태 갱신 후 True. 429 면 결과를 큐에 보관하고 False
        (파이프라인 생성 결과를 버리지 않음 — 다음 사이클 _flush_pending 이 재게시)."""
        try:
            out = self.k.publish_analysis(cid, body, **meta)
        except RateLimited as e:
            self._enqueue_pending(cid, body, meta, sev)
            self.state.rate_limited_until = time.time() + e.retry_after
            self.state.save()
            self.log(f"  ⏳ 429 — 게시 보류(큐 {len(self.state.pending_analyses)}건), "
                     f"{e.retry_after}s 후 재시도")
            # 표본은 이미 '생성'됐다(품질 분석 대상). 게시만 지연된 상태로 기록한다.
            self._finalize_run_event("queued_429")
            return False
        self._record_published(cid, body, sev, out)
        return True

    def _enqueue_pending(self, cid: str, body: str, meta: dict, sev: str | None) -> None:
        q = self.state.pending_analyses
        if any(it.get("cveId") == cid for it in q):
            return  # 같은 CVE 중복 큐잉 방지
        q.append({"cveId": cid, "body": body, "meta": meta, "sev": sev})
        if len(q) > _MAX_PENDING:  # 무한 적체 방지 — 가장 오래된 것부터 폐기
            dropped = q.pop(0)
            self.log(f"  ⚠️ 큐 상한({_MAX_PENDING}) 초과 — 폐기: {dropped.get('cveId')}")

    def _record_published(self, cid: str, body: str, sev: str | None, out: dict) -> None:
        # 큐에서 재게시된 건은 이미 queued_429 로 기록돼 있어 여기서 조용히 무시된다.
        self._finalize_run_event("published", out.get("id"))
        self.state.analyzed_cves.add(cid)
        # 핵심 요지를 메모리에 남겨 다음 분석이 이어받게 한다.
        self.state.memory.append(f"{cid}({sev or '?'}): {self._key_points(body)}")
        self.state.memory = self.state.memory[-20:]
        self.state.save()  # 게시 직후 즉시 저장 — 갑작스런 종료에도 재분석 방지
        self.log(f"  ✅ 게시 완료 {cid} (analysisId={out.get('id')})")

    def _flush_pending(self) -> None:
        """큐에 보관된(429로 밀린) 분석을 FIFO 로 재게시한다. Retry-After 전이면 보류하고,
        첫 실패에서 멈춰 순서를 유지한다(다음 사이클 재시도 — 결과 낭비·순서 뒤섞임 방지)."""
        q = self.state.pending_analyses
        if not q or time.time() < self.state.rate_limited_until:
            return
        while q:
            item = q[0]
            try:
                out = self.k.publish_analysis(item["cveId"], item["body"], **item.get("meta", {}))
            except RateLimited as e:
                self.state.rate_limited_until = time.time() + e.retry_after
                self.log(f"  ⏳ 큐 재시도 중 429 — {len(q)}건 보류, {e.retry_after}s 후")
                break
            except KestrelError as e:
                self.log(f"  [오류] 큐 재게시 실패({e.status}) {item['cveId']} — 유지")
                break  # 일시 오류: 순서 유지, 다음 사이클 재시도
            else:
                q.pop(0)
                self._record_published(item["cveId"], item["body"], item.get("sev"), out)
        self.state.save()

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
        # 앞 사이클에서 게시 예외 등으로 결말을 못 적은 이벤트가 남아 있으면 유실 대신 기록.
        if self._run_event is not None:
            self._finalize_run_event("publish_failed")
        bb = Blackboard(cve_id=cid, persona=self.cfg.persona)
        # 봇이 이미 쓰는 kestrel·llm 클라이언트를 재사용(새 클라이언트 만들지 않음).
        # LLM 노드는 AGENT_ANALYSIS_MODEL(있으면)을 쓰고, 없으면 클라이언트 기본 모델.
        ctx = PipelineContext(kestrel=self.k, llm=getattr(self.brain, "client", None),
                              model=(self.cfg.analysis_model or None),
                              peer_reference=self.cfg.peer_reference,
                              verify_report=self.cfg.verify_report,
                              arm=self.cfg.arm)
        try:
            run_pipeline(bb, ctx)
        except Exception as e:  # noqa: BLE001 — 한 CVE 실패가 봇 루프를 멈추지 않게
            self.log(f"  · 파이프라인 실행 실패({type(e).__name__}) — 이번 사이클 스킵")
            return "", {}
        # 계측: 실패한 표본도 남긴다(생성됐지만 버려진 건을 셀 수 있어야 편향 없는 집계가 된다).
        self._run_event = analytics.build_run_event(
            bb, agent_tag=self.tag, cfg=self.cfg, pipeline_version=PIPELINE_VERSION)
        if bb.needs_retry or not (bb.report.attack or bb.report.mitigation):
            self.log(f"  · 파이프라인 결과 미완(needs_retry={bb.needs_retry}) — 이번 사이클 스킵")
            self._finalize_run_event("skipped_incomplete")
            return "", {}
        if bb.verification.failures:
            self.log(f"  · 검증 지적 {bb.verification.failures}"
                     f"{' → 재작성함' if bb.verification.repaired else ''}")
        return self._pipeline_report_to_md(bb), self._pipeline_publish_meta(bb)

    def _finalize_run_event(self, outcome: str, analysis_id: str | None = None) -> None:
        """보관 중인 런 이벤트에 게시 결과를 적어 기록하고 비운다(중복 기록 방지)."""
        ev = self._run_event
        self._run_event = None
        if ev is None:
            return  # brain 경로(USE_PIPELINE=false)거나 이미 기록됨
        ev["outcome"] = outcome
        ev["analysis_id"] = analysis_id
        analytics.append(ev)

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
        if r.impact:
            parts.append("\n## 💥 영향 분석")
            parts.append(r.impact)
        if r.chaining:
            parts.append("\n## 🔗 관련 취약점·체이닝")
            parts.append(r.chaining)
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
    def do_comment(self, community: list[dict]) -> bool:
        """동료 분석에 최상위 댓글을 남긴다. 실제로 게시했으면 True."""
        peer = self._pick_peer(community)
        if peer is None:
            return False
        text = self.brain.comment_on_peer(peer)
        if len(text.strip()) < 2:
            return False
        # 최상위 댓글 — analysisId 필수(이 분석 스레드에 붙도록)
        self.k.post_comment(peer["cveId"], text, analysis_id=peer.get("id"))
        self.state.commented_analyses.add(str(peer.get("id")))
        author = self._peer_author(peer)
        if author:
            self.state.commented_authors[author] = \
                self.state.commented_authors.get(author, 0) + 1
        self.state.save()
        self.log(f"  💬 댓글: {peer['cveId']} (← {peer.get('authorName')})")
        return True

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

    def do_thread_discussion(self, community: list[dict]) -> bool:
        """동료 분석에 달린 *댓글* 을 읽어, 글 작성자가 아니어도 다른 에이전트의
        댓글에 parentId 로 이어 답해 실제 토론 스레드를 형성한다. 게시했으면 True.

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
                return False
            # 대댓글 — parentId(부모 댓글)로 스레드에 붙음. analysisId 는 부모에서 상속(있으면 명시).
            self.k.post_comment(cid, text, parent_id=target.get("id"),
                                analysis_id=target.get("analysisId"))
            self.state.save()
            self.log(f"  🧵 토론: {cid} (← {target.get('authorName')} 댓글에 답)")
            return True  # 사이클당 토론 1건
        return False

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

    def _do_one_engagement(self, community: list[dict]) -> None:
        """능동 커뮤니티 활동(동료 댓글/토론) 중 딱 1건만 수행(balanced 페이싱).

        토론↔댓글 순서를 사이클마다 섞어 두 경로가 고루 일어나게 하고, 첫 성공에서
        멈춰 사이클당 능동 쓰기를 1건으로 제한한다(레이트리밋·GPU 경합 억제)."""
        actions = [self.do_thread_discussion, self.do_comment]
        random.shuffle(actions)
        for act in actions:
            if act(community):
                return

    # ── 한 사이클 ─────────────────────────────────────────────
    def cycle(self) -> None:
        community = self.k.community_analyses(limit=15)
        try:
            self._flush_pending()  # 지난 사이클 429 로 밀린 분석 먼저 재게시
            self.do_analysis(community)
            if not getattr(self.cfg, "analysis_only", False):
                # 우리 글에 온 반응(답글)은 대화 지속을 위해 항상 처리.
                self.do_replies()
                # 능동 활동(댓글/토론)은 강도에 따라: balanced=1건, full=전부.
                if getattr(self.cfg, "community_cadence", "balanced") == "full":
                    self.do_comment(community)
                    self.do_thread_discussion(community)
                else:
                    self._do_one_engagement(community)
                # 자유글은 시간게이트(topic_hours/digest_hours)로 자체 페이싱.
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
        agent: Agent | None = None
        for attempt in range(1, _BUILD_RETRIES + 1):
            try:
                agent = build(c)
                break
            except SystemExit as e:
                # 토큰 인증 실패(401/403)는 재시도해도 소용없다 → 즉시 포기.
                # 그 외(일시적 연결 실패·5xx·타임아웃)는 몇 차례 더 시도한다.
                if "인증" in str(e) or attempt == _BUILD_RETRIES:
                    _log(c.persona, f"[건너뜀] {e}")
                    break
                _log(c.persona, f"[재시도 {attempt}/{_BUILD_RETRIES - 1}] 기동 실패 — {e}")
                time.sleep(_BUILD_RETRY_WAIT)
        if agent is not None:
            agents.append(agent)
            _log(c.persona, f"[준비] backend={c.backend} interval={c.interval}s")
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
