"""Collector (규칙) — kestrel_client 의 get_cve/related 로 대상 CVE 원본을 수집한다.

kestrel API 는 소스별 원본을 따로 주지 않고 병합된 뷰(get_cve) 하나를 준다. 그래서
지금은 그 병합 레코드를 primary source 로, related(관련 CVE) 목록을 참고용으로 담는다.
향후 플랫폼이 소스별 원본을 노출하면 여기서 여러 source_records 로 확장한다.

source_records 항목 형식: {source, kind, cveId, data}
  - kind='primary'  : get_cve(대상) 응답 본체
  - kind='related'  : related() 가 준 관련 CVE 각각

ctx.kestrel 이 없으면(스텁/미주입 실행) 조용히 통과한다.
"""
from __future__ import annotations

from pipeline.agents.base import register


@register(order=10)
def collector(bb, ctx) -> None:  # noqa: ANN001
    if ctx is None or getattr(ctx, "kestrel", None) is None:
        return  # 자원 미주입 — 수집 없이 통과(하위 노드는 '데이터 없음'으로 처리)
    k = ctx.kestrel

    detail = k.get_cve(bb.cve_id)  # 실패 시 예외 → supervisor 가 재시도/스킵
    bb.source_records.append(
        {"source": "kestrel", "kind": "primary", "cveId": bb.cve_id, "data": detail})

    try:
        related = k.related(bb.cve_id) or []
    except Exception:  # noqa: BLE001 — 관련 CVE 조회 실패는 본체 수집을 막지 않는다
        related = []
    for r in related:
        bb.source_records.append(
            {"source": "kestrel", "kind": "related",
             "cveId": r.get("cveId"), "data": r})
