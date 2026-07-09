"""Cross-Validation (결정론 규칙, LLM 없음) — 단일 병합 레코드의 내부 일관성을 검증한다.

kestrel 은 지금 소스별 원본을 따로 주지 않으므로, 이번 단계는 '진짜 소스 간 대조'가 아니라
'한 레코드 내부의 자기모순·데이터 품질' 검증으로 시작한다(향후 소스별 원본이 노출되면 확장).

규칙(모두 결정론적, 값이 없으면 n/a 로 배제):
  1. severity_score_band : severity 문자열과 cvssScore 구간의 정합성
  2. vector_format       : cvssVector 가 CVSS:3.x 형식으로 파싱되는지
  3. vector_score_match  : cvssVector 로 계산한 base score 와 cvssScore 의 차 ≤ 1.0
  4. products_description: products[] 가 description 의 영향 제품과 겹치는지(품질 플래그)

confidence = 통과 규칙 / 적용 가능 규칙 (LLM 신뢰도가 아니라 '규칙 통과 비율'이다).
불일치 시 adopted_values 는 보수적으로(더 높은 심각도) 채택한다.
confidence < _CONFIDENCE_MIN 이면 enrichment 로 handoff(재정규화 유도) — 반복 실패는
supervisor 가 handoff 한도 초과 시 needs_human_review 로 승격한다.
모든 판정은 validation_events.jsonl 에 append 되어 향후 '불일치 탐지율' 지표의 원천이 된다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pipeline import cvss
from pipeline.agents.base import register

_CONFIDENCE_MIN = 0.6
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_EVENTS_FILE = "validation_events.jsonl"

# 심각도 순위(보수적 채택·구간 비교용)
_SEV_ORDER = ["none", "low", "medium", "high", "critical"]
# products↔description 매칭에서 무시할 일반 토큰(제조사·접미어 등)
_GENERIC = {"the", "inc", "corp", "ltd", "co", "project", "software", "server",
            "apache", "microsoft", "oracle", "foundation", "systems", "technologies"}


@dataclass(frozen=True)
class _Rule:
    name: str
    status: str   # "pass" | "fail" | "n/a"
    detail: str = ""


def _rule_severity_score(rec: dict) -> _Rule:
    sev = (rec.get("severity") or "").strip().lower() or None
    score = rec.get("cvssScore")
    band = cvss.severity_band(score)
    if sev is None or band is None:
        return _Rule("severity_score_band", "n/a")
    if sev == band:
        return _Rule("severity_score_band", "pass")
    return _Rule("severity_score_band", "fail",
                 f"severity={sev} 이나 cvssScore={score} 는 {band} 구간")


def _rule_vector_format(rec: dict) -> _Rule:
    v = rec.get("cvssVector")
    if not v:
        return _Rule("vector_format", "n/a")
    if cvss.parse_vector(v) is None:
        return _Rule("vector_format", "fail", f"cvssVector 형식 파싱 불가: {v!r}")
    return _Rule("vector_format", "pass")


def _rule_vector_score(rec: dict) -> _Rule:
    v = rec.get("cvssVector")
    score = rec.get("cvssScore")
    metrics = cvss.parse_vector(v) if v else None
    if metrics is None or score is None:
        return _Rule("vector_score_match", "n/a")
    base = cvss.base_score(metrics)
    if base is None:
        return _Rule("vector_score_match", "n/a")
    if abs(base - score) > 1.0:
        return _Rule("vector_score_match", "fail",
                     f"벡터 base score {base} 와 cvssScore {score} 차이 {abs(base - score):.1f}")
    return _Rule("vector_score_match", "pass")


def _tokens(name: str) -> set[str]:
    raw = "".join(c if c.isalnum() else " " for c in name.lower()).split()
    return {t for t in raw if len(t) >= 3 and t not in _GENERIC}


def _rule_products_description(rec: dict) -> _Rule:
    products = rec.get("products") or []
    desc = (rec.get("description") or "").lower()
    if not desc or not products:
        return _Rule("products_description", "n/a")
    for prod in products:
        if any(tok in desc for tok in _tokens(prod)):
            return _Rule("products_description", "pass")
    return _Rule("products_description", "fail",
                 f"products {products} 가 설명 본문과 매칭되지 않음(품질 플래그)")


_RULES = (_rule_severity_score, _rule_vector_format,
          _rule_vector_score, _rule_products_description)


def _higher_severity(a: str | None, b: str | None) -> str | None:
    ranked = [s for s in (a, b) if s in _SEV_ORDER]
    if not ranked:
        return a or b
    return max(ranked, key=_SEV_ORDER.index)


def _adopt(rec: dict) -> dict:
    """신뢰 가능한 값 채택 — 불일치 시 보수적으로(더 높은 심각도) 잡는다."""
    stated = (rec.get("severity") or "").strip().lower() or None
    score = rec.get("cvssScore")
    band = cvss.severity_band(score)
    adopted: dict = {"severity": _higher_severity(stated, band)}
    if score is not None:
        adopted["cvssScore"] = score
    v = rec.get("cvssVector")
    if v and cvss.parse_vector(v) is not None:
        adopted["cvssVector"] = v
    return adopted


def _events_path(ctx) -> Path:
    base = Path(ctx.data_dir) if (ctx and getattr(ctx, "data_dir", None)) else _REPO_ROOT
    return base / _EVENTS_FILE


def _append_event(ctx, event: dict) -> None:
    try:
        with open(_events_path(ctx), "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 — 기록 실패가 파이프라인을 막지 않는다
        pass


@register(order=30)
def cross_validation(bb, ctx) -> None:  # noqa: ANN001
    rec = bb.primary_record()
    results = [rule(rec) for rule in _RULES]
    passed = [r for r in results if r.status == "pass"]
    failed = [r for r in results if r.status == "fail"]
    applicable = passed + failed

    if not applicable:
        # 검증할 데이터가 없음(수집 전/필드 부재) — 조용히 통과(handoff·기록 안 함).
        return

    confidence = round(len(passed) / len(applicable), 3)
    bb.validation.confidence = confidence
    bb.validation.mismatches = [{"rule": r.name, "detail": r.detail} for r in failed]
    bb.validation.adopted_values = _adopt(rec)

    decision = "ok"
    if confidence < _CONFIDENCE_MIN:
        # 보수적 라우팅: enrichment 로 회귀시켜 재정규화 유도. 반복 실패는 supervisor 가
        # handoff 한도 초과 시 needs_human_review 로 승격한다.
        bb.handoff = "enrichment"
        decision = f"handoff:enrichment (confidence {confidence} < {_CONFIDENCE_MIN})"

    _append_event(ctx, {
        "ts": datetime.now(timezone.utc).isoformat(),
        "cveId": bb.cve_id,
        "rules": [{"rule": r.name, "status": r.status} for r in results],
        "passed": [r.name for r in passed],
        "failed": [{"rule": r.name, "detail": r.detail} for r in failed],
        "confidence": confidence,
        "decision": decision,
    })
