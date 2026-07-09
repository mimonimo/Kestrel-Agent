"""Enrichment (규칙) — Collector 원본에서 CVSS·CWE·products 를 표준 형태로 정규화한다.

get_cve 실제 필드: cvssScore, cvssVector, kevListed, severity, types[], products[].
(types 가 CWE 를 담지만 응답에 비어 있을 수 있어 None 안전 처리한다.)

Cross-Validation 이 이미 보수적으로 채택한 값(adopted_values)이 있으면 그걸 우선한다.
(Enrichment 는 Cross-Validation 앞에서 도므로 최초엔 비어 있고, 저신뢰 handoff 로
 되돌아온 재실행 때 채택값이 채워져 있다.)
"""
from __future__ import annotations

from pipeline import cvss
from pipeline.agents.base import register


@register(order=20)
def enrichment(bb, ctx) -> None:  # noqa: ANN001
    rec = bb.primary_record()
    if not rec:
        return  # 수집 전/데이터 없음 — 통과

    adopted = bb.validation.adopted_values or {}
    score = adopted.get("cvssScore", rec.get("cvssScore"))
    vector = adopted.get("cvssVector") or rec.get("cvssVector")
    severity = (adopted.get("severity") or rec.get("severity") or "").strip().lower() or None
    metrics = cvss.parse_vector(vector) if vector else None
    cwes = [str(t).upper() for t in (rec.get("types") or [])
            if str(t).upper().startswith("CWE-")]

    bb.enriched = {
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "cvss_metrics": metrics or {},                       # {AV,AC,PR,UI,S,C,I,A}
        "cvss_base_recomputed": cvss.base_score(metrics) if metrics else None,
        "cwes": cwes,
        "products": list(rec.get("products") or []),
        "kev": bool(rec.get("kevListed")),
    }
