"""텍스트 품질 지표 — 전부 결정론(LLM 없음, GPU 0). 검증 노드와 실험 로깅이 공유한다.

왜 결정론인가: 단일 GPU 를 3 페르소나가 `_OLLAMA_LOCK` 으로 직렬 공유하므로, 품질 게이트를
LLM 으로 돌리면 표본 생성률이 그만큼 깎인다. 그래서 '판정'은 규칙으로 공짜로 하고
LLM 은 **실패했을 때 고치는 데만** 쓴다(verification 노드).

여기서 내는 수치는 두 곳에서 쓰인다:
  1) verification 노드 — 재작성 트리거(환각 CVE·섹션 누락)
  2) analytics 런 이벤트 — 논문/포스터용 정량 지표(구체성·근거인용·신규성)

주의: 모두 '신호'이지 절대적 품질 점수가 아니다. 포스터에서는 arm 간 **상대 비교**로만
쓰는 것이 안전하다(같은 지표·같은 파이프라인이므로 상대 비교는 타당).
"""
from __future__ import annotations

import re

# ── 환각 검출 ────────────────────────────────────────────────
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def cited_cves(text: str) -> set[str]:
    """본문에 등장하는 CVE 식별자 집합(대문자 정규화)."""
    return {m.upper() for m in _CVE_RE.findall(text or "")}


def ungrounded_cves(body: str, facts: str, target_cve: str | None) -> list[str]:
    """사실 블록에도 없고 분석 대상도 아닌 CVE 번호 = 지어냈을 가능성이 큰 것.

    report 프롬프트가 '확실하지 않으면 실제 CVE 번호를 쓰지 말 것'을 명시하므로,
    이 목록이 비어 있지 않다는 건 지시 위반 + 검증 불가 주장이라는 뜻이다.
    """
    allowed = cited_cves(facts)
    if target_cve:
        allowed.add(target_cve.upper())
    return sorted(cited_cves(body) - allowed)


# ── 섹션 완결성 ──────────────────────────────────────────────
_SECTIONS = ("attack", "impact", "chaining", "detection", "mitigation")
_MIN_SECTION_CHARS = 80  # 헤더만 있고 내용이 사실상 빈 경우를 걸러내는 하한


def section_completeness(sections: dict[str, str]) -> dict:
    """5개 섹션이 실질적 내용을 갖췄는지. 빈/과소 섹션 목록과 충족 비율을 낸다."""
    lengths = {k: len((sections.get(k) or "").strip()) for k in _SECTIONS}
    missing = [k for k, n in lengths.items() if n < _MIN_SECTION_CHARS]
    return {
        "section_chars": lengths,
        "total_chars": sum(lengths.values()),
        "missing_sections": missing,
        "complete_ratio": round((len(_SECTIONS) - len(missing)) / len(_SECTIONS), 3),
    }


# ── 구체성(실무자가 바로 쓸 수 있는 산출물이 실제로 들어있는가) ──
# 각 항목은 '실행 가능한 구체물'의 대리 지표다. 페르소나마다 유리한 항목이 다르므로
# (방어=탐지규칙, 공격=엔드포인트) 총합뿐 아니라 항목별로도 보존해 비교에 쓴다.
_SPECIFICITY_PATTERNS: dict[str, str] = {
    # 탐지 규칙성 산출물
    "regex": r"\(\?i\)|\\b|\\d|\\s|\\w|\[\^|\.\*|regex|정규식",
    "siem_query": r"index\s*=|sourcetype|\|\s*where|\|\s*stats|SELECT\s+.+\s+FROM|event_?id\s*[=:]|sigma",
    "log_field": r"/var/log|auditd|syslog|journalctl|dmesg|EventID|winlog|logfile|로그 필드",
    # 공격면·자산 식별자
    "path_or_endpoint": r"(?<![\w:])/(?:[A-Za-z0-9_.-]+/){1,}[A-Za-z0-9_.-]*|https?://",
    "identifier": r"CWE-\d+|CVSS:\d\.\d|CAPEC-\d+",
    "version": r"\b\d+\.\d+(?:\.\d+)+\b",
    # 조치 구체물
    "command": r"\b(?:sudo|sysctl|iptables|nft|chmod|chown|systemctl|setenforce|modprobe|firewall-cmd)\b",
    "code_block": r"```",
}


def specificity(text: str) -> dict:
    """구체물 신호의 항목별 출현 수 + 총합 + 커버한 항목 종류 수."""
    body = text or ""
    counts = {name: len(re.findall(pat, body, re.IGNORECASE))
              for name, pat in _SPECIFICITY_PATTERNS.items()}
    return {
        "specificity_counts": counts,
        "specificity_total": sum(counts.values()),
        # 종류 수(=서로 다른 각도의 구체물을 몇 가지나 냈는가). 한 항목을 반복해
        # 부풀리는 것과 실제로 다각도로 구체적인 것을 구분한다.
        "specificity_kinds": sum(1 for n in counts.values() if n > 0),
    }


# ── 파이프라인 근거 인용(단일 LLM 이 흉내낼 수 없는 신호를 실제로 썼는가) ──
def evidence_citation(text: str, *, epss: float | None,
                      priority_action: str | None,
                      validation_confidence: float | None) -> dict:
    """리포트가 EPSS 실측치·우선순위 결정·교차검증 결과를 본문에서 인용했는지.

    이것이 '파이프라인이 있으나 마나'가 아님을 보이는 핵심 지표다. 프롬프트는 인용을
    지시하지만 실제로 지켰는지는 별개이므로 결과물에서 직접 확인한다.
    """
    body = text or ""
    epss_cited = False
    if epss is not None:
        # 소수점 표기를 그대로 인용했는지(반올림 왜곡 없이) — 앞 3~5자리로 관대 매칭
        needles = {f"{epss}", f"{epss:.3f}", f"{epss:.4f}", f"{epss * 100:.1f}"}
        epss_cited = any(n in body for n in needles) or "EPSS" in body.upper()
    return {
        "epss_cited": epss_cited,
        "priority_cited": bool(priority_action) and (
            priority_action.lower() in body.lower()
            or any(w in body for w in ("우선순위", "즉시", "이번 주", "모니터링"))),
        "validation_cited": validation_confidence is not None and any(
            w in body for w in ("교차검증", "다중 소스", "일관성", "보수적")),
    }


# ── 신규성(후발 분석이 peer 를 베낀 게 아니라 더한 것인지) ──
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.\-]{2,}|[가-힣]{2,}")


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "")}


def novelty(text: str, peer_texts: list[str]) -> dict:
    """peer 분석 대비 토큰 신규성.

    novel_ratio = 내 본문 토큰 중 peer 에 없던 비율 (1.0 = 완전 독립, 0.0 = 완전 중복).
    jaccard    = 겹침 정도(대칭).
    peer 가 없으면 None 을 넣어 '측정 불가'와 '겹침 0'을 구분한다(집계 시 필수).
    """
    if not peer_texts:
        return {"novel_ratio": None, "peer_jaccard": None, "peer_token_count": 0}
    mine = _tokens(text)
    theirs: set[str] = set()
    for p in peer_texts:
        theirs |= _tokens(p)
    if not mine:
        return {"novel_ratio": None, "peer_jaccard": None, "peer_token_count": len(theirs)}
    inter = len(mine & theirs)
    union = len(mine | theirs)
    return {
        "novel_ratio": round(len(mine - theirs) / len(mine), 4),
        "peer_jaccard": round(inter / union, 4) if union else None,
        "peer_token_count": len(theirs),
    }


# ── 통합 산출 ────────────────────────────────────────────────
def report_metrics(sections: dict[str, str], *, facts: str, target_cve: str | None,
                   epss: float | None, priority_action: str | None,
                   validation_confidence: float | None,
                   peer_texts: list[str] | None = None) -> dict:
    """리포트 1건의 전체 지표. verification 과 analytics 가 같은 함수를 쓴다(정의 불일치 방지)."""
    body = "\n".join((sections.get(k) or "") for k in _SECTIONS)
    out: dict = {}
    out.update(section_completeness(sections))
    out.update(specificity(body))
    out.update(evidence_citation(body, epss=epss, priority_action=priority_action,
                                 validation_confidence=validation_confidence))
    out.update(novelty(body, peer_texts or []))
    ungrounded = ungrounded_cves(body, facts, target_cve)
    out["ungrounded_cves"] = ungrounded
    out["ungrounded_cve_count"] = len(ungrounded)
    return out
