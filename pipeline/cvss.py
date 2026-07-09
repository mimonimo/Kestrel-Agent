"""CVSS v3.x 벡터 파싱·base score 계산·심각도 구간 — 순수 함수(외부 의존성 없음).

Cross-Validation 이 '단일 레코드 내부 일관성'을 결정론적으로 검증할 때 쓴다.
base score 는 CVSS v3.1 공식(v3.0 도 계수 동일, 반올림만 미세차 → 우리 허용오차 1.0 에
영향 없음)을 따른다. 참고: FIRST CVSS v3.1 Specification §7.
"""
from __future__ import annotations

import math

# Base metric 계수 (CVSS v3.1)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}   # Scope 변경 시 PR 계수가 달라짐
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str | None) -> dict[str, str] | None:
    """"CVSS:3.1/AV:N/AC:L/..." → {'AV':'N', ...}. 형식이 아니면 None.

    CVSS:3.0 / CVSS:3.1 접두만 받는다. pair 하나라도 형식이 깨지면 None(형식 무효).
    """
    if not vector or not isinstance(vector, str):
        return None
    parts = vector.strip().split("/")
    if not parts[0].upper().startswith(("CVSS:3.0", "CVSS:3.1")):
        return None
    metrics: dict[str, str] = {}
    for p in parts[1:]:
        if ":" not in p:
            return None
        key, _, val = p.partition(":")
        key, val = key.strip().upper(), val.strip().upper()
        if not key or not val:
            return None
        metrics[key] = val
    return metrics or None


def _roundup(x: float) -> float:
    """CVSS v3.1 Roundup — 소수 1자리로 올림(부동소수 오차 보정 포함)."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score(metrics: dict[str, str]) -> float | None:
    """파싱된 metrics 로 CVSS v3.1 base score 계산. base 지표가 빠지면 None."""
    if any(k not in metrics for k in _REQUIRED):
        return None
    scope_changed = metrics["S"] == "C"
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        conf = _IMPACT[metrics["C"]]
        integ = _IMPACT[metrics["I"]]
        avail = _IMPACT[metrics["A"]]
    except KeyError:
        return None  # 알 수 없는 metric 값

    isc_base = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(raw, 10.0))


def severity_band(score: float | None) -> str | None:
    """CVSS 점수 → 정성 심각도 구간(CVSS v3.1 §5). 점수 없으면 None."""
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "none"
