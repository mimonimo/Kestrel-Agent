"""Cross-Validation (결정론 규칙, LLM 없음) — 단일 병합 레코드의 내부 일관성을 검증한다.

kestrel 은 지금 소스별 원본을 따로 주지 않으므로, 이번 단계는 '진짜 소스 간 대조'가 아니라
'한 레코드 내부의 자기모순·데이터 품질' 검증으로 시작한다(향후 소스별 원본이 노출되면 확장).

두 종류로 나눈다:
  ● confidence 규칙(결정론적으로 확실 — confidence·handoff 에 반영):
      1. severity_score_band : severity 문자열과 cvssScore 구간의 정합성
      2. vector_format       : cvssVector 가 CVSS:3.x 형식으로 파싱되는지
      3. vector_score_match  : cvssVector 로 계산한 base score 와 cvssScore 의 차 ≤ 1.0
  ● quality_flags(참고용 데이터 품질 신호 — confidence·handoff 에 **반영 안 함**):
      products_description : products[] 가 description 과 겹치는지.
      라이브러리/공급망 CVE(Log4Shell 등)는 description 이 라이브러리를, products 는
      다운스트림 벤더를 나열해 구조적 false positive 가 난다. 그래서 이걸로 confidence 를
      깎거나 human-review 로 보내지 않고, 개수·CWE 맥락과 함께 기록만 한다.

confidence = 통과 confidence 규칙 / 적용 가능 confidence 규칙(LLM 신뢰도 아님).
불일치 시 adopted_values 는 보수적으로(더 높은 심각도) 채택한다.
confidence < _CONFIDENCE_MIN 이면 enrichment 로 handoff(재정규화 유도) — 반복 실패는
supervisor 가 handoff 한도 초과 시 needs_human_review 로 승격한다.
모든 판정은 validation_events.jsonl 에 append(rules 와 quality_flags 를 분리 기록)된다.
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
_MANY_PRODUCTS = 3  # products 가 이보다 많으면 공급망 취약점(정상) 가능성 신호

# 심각도 순위(보수적 채택·구간 비교용)
_SEV_ORDER = ["none", "low", "medium", "high", "critical"]
# products↔description 매칭에서 무시할 일반 토큰(제조사·접미어 등)
_GENERIC = {"the", "inc", "corp", "ltd", "co", "project", "software", "server",
            "apache", "microsoft", "oracle", "foundation", "systems", "technologies"}
# 라이브러리/공급망성 취약점에서 흔한 CWE(품질 신호 해석용). 확정 판정엔 쓰지 않는다.
_LIBRARY_CWES = {"CWE-502", "CWE-917", "CWE-94", "CWE-829", "CWE-1104", "CWE-937", "CWE-1035"}


@dataclass(frozen=True)
class _Rule:
    name: str
    status: str   # "pass" | "fail" | "n/a"
    detail: str = ""


# ── confidence 규칙(확정) ──────────────────────────────────
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


_CONFIDENCE_RULES = (_rule_severity_score, _rule_vector_format, _rule_vector_score)


# ── 품질 신호(참고용) ──────────────────────────────────────
def _tokens(name: str) -> set[str]:
    raw = "".join(c if c.isalnum() else " " for c in name.lower()).split()
    return {t for t in raw if len(t) >= 3 and t not in _GENERIC}


def _products_description(rec: dict) -> _Rule:
    products = rec.get("products") or []
    desc = (rec.get("description") or "").lower()
    if not desc or not products:
        return _Rule("products_description", "n/a")
    for prod in products:
        if any(tok in desc for tok in _tokens(prod)):
            return _Rule("products_description", "pass")
    return _Rule("products_description", "fail",
                 "products 가 description 본문과 매칭되지 않음")


def _quality_flag(rec: dict, rule: _Rule) -> dict:
    """품질 신호에 해석용 맥락을 붙인다 — '진짜 이상' vs '공급망 정상 패턴' 구분용."""
    products = rec.get("products") or []
    cwes = [str(t).upper() for t in (rec.get("types") or [])
            if str(t).upper().startswith("CWE-")]
    library_like = any(c in _LIBRARY_CWES for c in cwes)
    many = len(products) > _MANY_PRODUCTS
    return {
        "rule": rule.name,
        "detail": rule.detail,
        "products_count": len(products),
        "cwes": cwes,
        "library_like_cwe": library_like,
        # products 가 많거나 라이브러리성 CWE 면 공급망 취약점의 정상 패턴일 소지가 큼
        "likely_supply_chain": many or library_like,
    }


# ── 채택·기록 ──────────────────────────────────────────────
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

    results = [rule(rec) for rule in _CONFIDENCE_RULES]
    passed = [r for r in results if r.status == "pass"]
    failed = [r for r in results if r.status == "fail"]
    applicable = passed + failed

    quality = _products_description(rec)
    quality_flags = [_quality_flag(rec, quality)] if quality.status == "fail" else []

    if not applicable and not quality_flags:
        # 검증할 데이터도 품질 신호도 없음 — 조용히 통과(handoff·기록 안 함).
        return

    # confidence 는 확정 규칙만으로. 적용 가능한 확정 규칙이 없으면 '하드 불일치 근거 없음'(1.0).
    confidence = round(len(passed) / len(applicable), 3) if applicable else 1.0
    bb.validation.confidence = confidence
    bb.validation.mismatches = [{"rule": r.name, "detail": r.detail} for r in failed]
    bb.validation.adopted_values = _adopt(rec)
    bb.validation.quality_flags = quality_flags

    decision = "ok"
    if applicable and confidence < _CONFIDENCE_MIN:
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
        "quality_flags": quality_flags,
    })
