"""런 이벤트 로깅 — 분석 1건 = 레코드 1줄(`run_events.jsonl`). 논문/포스터 정량화의 원천 데이터.

왜 별도 파일인가: `validation_events.jsonl` 은 cross_validation 노드만의 기록이라 리포트 품질·
협업 노출량·실험 arm 을 담을 수 없다. 여기서는 **분석 1건의 전 과정**을 한 줄로 남겨,
나중에 어떤 조건에서 만들어진 결과인지 완전히 재구성할 수 있게 한다.

설계 원칙
  - append-only JSONL(동시 3 스레드가 쓰므로 락으로 줄 단위 원자성 보장).
  - 기록 실패가 봇 운영을 멈추지 않는다(모든 예외 흡수).
  - **실험 arm 서명을 매 레코드에 박는다** — 설정을 바꿔가며 상시 운영해도 나중에
    "이 결과는 어떤 조건이었나"를 되짚을 수 있다. 이게 없으면 운영 중 튜닝이
    데이터를 통째로 오염시킨다.
  - 게시 성공 여부(outcome)까지 남겨 '생성됐지만 버려진' 표본도 분석에 포함한다.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

_BASE = Path(__file__).resolve().parent
_EVENTS_FILE = "run_events.jsonl"
_LOCK = threading.Lock()

SCHEMA_VERSION = 1


def events_path(data_dir: str | None = None) -> Path:
    """기록 위치. AGENT_EVENTS_DIR 로 덮어쓸 수 있다.

    테스트는 conftest 에서 이 환경변수를 임시 디렉터리로 돌려, 실제 수집 데이터에
    가짜 이벤트가 섞이지 않게 한다(논문 표본 오염 방지).
    """
    base = data_dir or os.environ.get("AGENT_EVENTS_DIR") or _BASE
    return Path(base) / _EVENTS_FILE


def build_run_event(bb, *, agent_tag: str, cfg, pipeline_version: str,
                    arm: str = "") -> dict:  # noqa: ANN001
    """Blackboard + 설정 → 런 이벤트 레코드(게시 결과는 아직 미정).

    bb 는 파이프라인 완주 후의 상태여야 한다(verification 까지 실행된 뒤).
    """
    rec = bb.primary_record()
    v, ex, pr = bb.validation, bb.exploitability, bb.priority
    ver = bb.verification
    rep = bb.report

    return {
        "schema": SCHEMA_VERSION,
        "ts": datetime.now(timezone.utc).isoformat(),
        # ── 실험 조건(arm 서명) ─────────────────────────────
        "arm": arm or getattr(cfg, "arm", "") or "default",
        "agent": agent_tag,
        "persona": (rep.meta or {}).get("persona"),
        "config": {
            "pipeline_version": pipeline_version,
            "model": (rep.meta or {}).get("model"),
            "peer_reference": bool(getattr(cfg, "peer_reference", True)),
            "verify_report": bool(getattr(cfg, "verify_report", True)),
            "cadence": getattr(cfg, "community_cadence", None),
            "interval": getattr(cfg, "interval", None),
            "analysis_only": bool(getattr(cfg, "analysis_only", False)),
        },
        # ── 협업 노출량(플랫폼 이점의 독립변수) ──────────────
        "peer_ref_used": len(rep.peer_personas),
        "peer_personas": list(rep.peer_personas),
        # 댓글은 플랫폼이 전문을 주는 유일한 협업 채널이라 excerpt 와 정보량이 다르다.
        # 별도 변수로 남겨 '무엇이 효과를 냈는지'를 사후에 분리할 수 있게 한다.
        "comment_ref_used": (rep.meta or {}).get("comment_ref_used", 0),
        # 총수(사용 수와 다름) — 개정 트리거가 '작성 시점 대비 증가'를 판정하는 기준선.
        "peer_total": (rep.meta or {}).get("peer_total", 0),
        "comment_total": (rep.meta or {}).get("comment_total", 0),
        "revision_index": (rep.meta or {}).get("revision_index", 0),
        # ── 대상 CVE 특성(난이도 통제 변수) ──────────────────
        "cve": bb.cve_id,
        "cve_severity": rec.get("severity"),
        "cvss_score": rec.get("cvssScore"),
        "kev_listed": rec.get("kevListed"),
        "cwes": [str(t) for t in (rec.get("types") or [])],
        "product_count": len(rec.get("products") or []),
        "description_chars": len(rec.get("description") or ""),
        # ── 파이프라인 산출(설명 가능 신호) ──────────────────
        "epss": ex.epss,
        "epss_percentile": ex.epss_percentile,
        "exploitability_grade": ex.grade,
        "priority_action": pr.action,
        "validation_confidence": v.confidence,
        "validation_mismatches": [m.get("rule") for m in (v.mismatches or [])],
        "quality_flags": [q.get("rule") for q in (v.quality_flags or [])],
        "needs_human_review": bool(bb.needs_human_review),
        "handoff_count": bb.handoff_count,
        "audit_log": [f"{a.get('agent')}:{a.get('status')}" for a in (bb.audit_log or [])],
        # ── 리포트 생성 ──────────────────────────────────────
        "elapsed_sec": (rep.meta or {}).get("elapsed_sec"),
        "report_error": (rep.meta or {}).get("error"),
        # ── 품질 지표(결정론) ────────────────────────────────
        "verification_passed": ver.passed,
        "verification_failures": list(ver.failures),
        "verification_repaired": bool(ver.repaired),
        "metrics": ver.metrics or {},
        # ── 리포트 본문(페르소나 차별성 분석용) ───────────────
        # 플랫폼 API 는 280자 excerpt 만 돌려주고 그 앞부분은 정형 헤더(요약·CVSS·EPSS)라
        # 사실상 전부 같아 보인다. 페르소나가 실제로 다른 내용을 쓰는지 검증하려면
        # 본문을 직접 갖고 있어야 한다. 1건당 ~2.5KB 이므로 하루 ~1MB 수준.
        "report_sections": {
            "summary_en": rep.summary_en,
            "attack": rep.attack,
            "impact": rep.impact,
            "chaining": rep.chaining,
            "detection": rep.detection,
            "mitigation": rep.mitigation,
        },
        # ── 게시 결과(호출부가 채움) ─────────────────────────
        "outcome": None,
        "analysis_id": None,
    }


def append(event: dict, data_dir: str | None = None) -> None:
    """레코드 1줄 append. 실패는 흡수(운영을 막지 않는다)."""
    try:
        line = json.dumps(event, ensure_ascii=False, default=str) + "\n"
        with _LOCK:
            with open(events_path(data_dir), "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:  # noqa: BLE001 — 계측 실패가 봇을 멈추게 두지 않는다
        pass
