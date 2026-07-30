"""run_events.jsonl → 포스터/논문에 바로 쓰는 수치와 CSV.

외부 의존성 없음(stdlib 만) — 이 저장소의 방침을 따르고, DGX 에서 추가 설치 없이 돈다.
통계는 표본이 짝지어져 있다는 점을 살려 비모수 검정을 쓴다(정규성 가정 불필요):
  · 부호검정(sign test) — 정확 이항, 표본 적어도 타당
  · Wilcoxon 부호순위 — 정규근사(n≥10 권장), 효과 크기까지
  · 부트스트랩 신뢰구간 — 중앙값 차이의 불확실성(시드 고정으로 재현 가능)
  · Fleiss' κ — 3 페르소나의 우선순위 판정 일치도(단일 에이전트로는 산출 불가한 지표)

핵심 비교(포스터의 주장):
  A. 협업 효과 — 같은 CVE 안에서 '선발(peer 참조 0)' vs '후발(peer 참조 ≥1)' 짝비교.
     같은 CVE 라 난이도가 통제되므로 관측 연구 중에서는 강한 설계다.
  B. arm 비교 — peer 참조를 끈 대조군(control) vs 플랫폼(platform).
  C. 다관점 산출물 — 단일 에이전트가 원리적으로 만들 수 없는 것(합의도·커버리지 속도).

교란 요인 통제(v2 에서 추가) — 이게 없으면 위 수치는 전부 못 믿는다:
  1. **파이프라인 버전 분리** — 프롬프트를 바꾸면 분량·구체성의 기준선 자체가 달라진다.
     서로 다른 버전을 한 표에 합산하면 '협업 효과'가 아니라 '내가 프롬프트를 언제 고쳤나'를
     재게 된다. 기본값은 **가장 최근 버전만** 사용한다(`--pipeline-version all` 로 해제).
  2. **페르소나 보정** — 페르소나마다 쓰는 분량·구체성 기준선이 다르다(설계상 의도한 차이다).
     선발/후발 또는 arm 사이에 페르소나 구성이 다르면 그 차이가 그대로 '효과'로 둔갑한다.
     짝비교는 페르소나 중앙값을 뺀 뒤 차분하고, arm 비교는 **공통 페르소나만** 쓴다.
  3. **구체성 지표의 방어 편향 명시** — specificity 패턴(정규식·SIEM 쿼리·로그 필드)은
     방어적 산출물을 더 잘 잡는다(실측: 방어 탐지섹션 중앙값 9.0 vs 공격 공격섹션 0.0).
     페르소나를 가로지르는 구체성 비교는 보정 없이는 부당하므로, 편향을 표로 드러낸다.

사용:
  python3 export_metrics.py                      # 요약을 화면에(최신 파이프라인 버전만)
  python3 export_metrics.py --pipeline-version all   # 전 버전 합산(권장하지 않음)
  python3 export_metrics.py --csv out.csv        # 원자료 CSV 동시 출력(필터 미적용, 전량)
  python3 export_metrics.py --md poster.md       # 마크다운 리포트 저장
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

_BASE = Path(__file__).resolve().parent

# 비교 대상 지표: (키, 표시명, 클수록 좋은가)
METRICS: list[tuple[str, str, bool]] = [
    ("specificity_total", "구체성 총합(정규식·쿼리·명령어 등)", True),
    ("specificity_kinds", "구체성 종류 수(다각도)", True),
    ("total_chars", "리포트 분량(자)", True),
    ("complete_ratio", "섹션 완결률", True),
    ("ungrounded_cve_count", "환각 CVE 수", False),
    ("elapsed_sec", "생성 소요(초)", False),
]
RATE_METRICS: list[tuple[str, str]] = [
    ("epss_cited", "EPSS 실측 인용률"),
    ("priority_cited", "우선순위 근거 인용률"),
    ("validation_cited", "교차검증 언급률"),
]


# ── 로드·평탄화 ──────────────────────────────────────────────
def load(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def flat(ev: dict) -> dict:
    """중첩 레코드 → 1단계 dict(CSV·집계용)."""
    out = {k: v for k, v in ev.items()
           if k not in ("config", "metrics", "peer_personas", "cwes",
                        "validation_mismatches", "quality_flags", "audit_log",
                        "verification_failures", "report_sections", "revision")}
    for k, v in (ev.get("config") or {}).items():
        out[f"cfg_{k}"] = v
    for k, v in (ev.get("revision") or {}).items():
        out[f"rev_{k}"] = v
    for k, v in (ev.get("metrics") or {}).items():
        if k in ("section_chars", "specificity_counts", "ungrounded_cves"):
            continue  # 중첩/가변 — CSV 에서는 제외(요약 수치로 대체)
        out[k] = v
    for k, v in ((ev.get("metrics") or {}).get("section_chars") or {}).items():
        out[f"chars_{k}"] = v
    for k, v in ((ev.get("metrics") or {}).get("specificity_counts") or {}).items():
        out[f"spec_{k}"] = v
    out["peer_personas"] = "|".join(ev.get("peer_personas") or [])
    out["cwes"] = "|".join(ev.get("cwes") or [])
    out["quality_flags"] = "|".join(ev.get("quality_flags") or [])
    out["verification_failures"] = "|".join(ev.get("verification_failures") or [])
    return out


def analyzable(rows: list[dict]) -> list[dict]:
    """생성이 실제로 이뤄진 표본만(스킵된 건 품질 비교 대상이 아니다)."""
    return [r for r in rows if r.get("outcome") in ("published", "queued_429")
            and (r.get("metrics") or {}).get("total_chars")]


def _version_of(r: dict) -> str:
    return (r.get("config") or {}).get("pipeline_version") or "unknown"


def latest_version(rows: list[dict]) -> str | None:
    """가장 최근 이벤트가 속한 파이프라인 버전.

    '가장 많은 버전'이 아니라 '가장 최근 버전'을 쓰는 이유: 프롬프트를 개선한 직후에는
    구버전 표본이 아직 더 많다. 개수로 고르면 방금 고친 개선이 통째로 버려진다.
    """
    stamped = [r for r in rows if r.get("ts")]
    if not stamped:
        return None
    return _version_of(max(stamped, key=lambda r: r["ts"]))


def filter_version(rows: list[dict], version: str | None) -> list[dict]:
    """version=None 또는 'all' 이면 전량. 아니면 해당 파이프라인 버전만."""
    if not version or version == "all":
        return rows
    return [r for r in rows if _version_of(r) == version]


# ── 통계(stdlib) ─────────────────────────────────────────────
def sign_test(diffs: list[float]) -> tuple[int, int, float]:
    """부호검정 — (양수 개수, 유효 표본, 양측 p). 정확 이항이라 소표본에서도 타당."""
    pos = sum(1 for d in diffs if d > 0)
    neg = sum(1 for d in diffs if d < 0)
    n = pos + neg
    if n == 0:
        return 0, 0, 1.0
    k = min(pos, neg)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return pos, n, min(1.0, 2 * tail)


def wilcoxon_p(diffs: list[float]) -> float | None:
    """Wilcoxon 부호순위 정규근사 양측 p. n<10 이면 근사가 부실하므로 None."""
    d = [x for x in diffs if x != 0]
    n = len(d)
    if n < 10:
        return None
    order = sorted(range(n), key=lambda i: abs(d[i]))
    ranks = [0.0] * n
    i = 0
    while i < n:  # 동순위 평균 랭크
        j = i
        while j + 1 < n and abs(d[order[j + 1]]) == abs(d[order[i]]):
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    w_plus = sum(ranks[i] for i in range(n) if d[i] > 0)
    mu = n * (n + 1) / 4
    sigma = math.sqrt(n * (n + 1) * (2 * n + 1) / 24)
    if sigma == 0:
        return None
    z = (w_plus - mu) / sigma
    return math.erfc(abs(z) / math.sqrt(2))  # 양측


def bootstrap_ci(vals: list[float], *, iters: int = 2000, seed: int = 20260729,
                 stat=statistics.median) -> tuple[float, float] | None:
    """중앙값(기본)의 95% 부트스트랩 신뢰구간. 시드 고정 → 재현 가능."""
    if len(vals) < 5:
        return None
    rng = random.Random(seed)
    n = len(vals)
    reps = [stat([vals[rng.randrange(n)] for _ in range(n)]) for _ in range(iters)]
    reps.sort()
    return reps[int(0.025 * iters)], reps[int(0.975 * iters) - 1]


def mannwhitney_p(a: list[float], b: list[float]) -> tuple[float | None, float | None]:
    """Mann-Whitney U 정규근사(동순위 보정) → (양측 p, 효과크기 rank-biserial).

    arm 비교는 짝지을 수 없는(같은 CVE 를 두 arm 이 항상 함께 보진 않는) 독립 2표본이라
    부호검정을 못 쓴다. 효과크기까지 같이 내는 이유: n 이 커지면 p 는 사소한 차이에도
    작아지므로, 포스터에는 '얼마나 다른가'가 함께 있어야 한다.
    """
    n1, n2 = len(a), len(b)
    if n1 < 3 or n2 < 3:
        return None, None
    pool = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    ranks = [0.0] * len(pool)
    ties: list[int] = []
    i = 0
    while i < len(pool):
        j = i
        while j + 1 < len(pool) and pool[j + 1][0] == pool[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = avg
        ties.append(j - i + 1)
        i = j + 1
    r1 = sum(ranks[k] for k in range(len(pool)) if pool[k][1] == 0)
    u1 = r1 - n1 * (n1 + 1) / 2
    mu = n1 * n2 / 2
    n = n1 + n2
    tie_term = sum(t ** 3 - t for t in ties)
    var = n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1)))
    if var <= 0:
        return None, None
    z = (u1 - mu) / math.sqrt(var)
    p = math.erfc(abs(z) / math.sqrt(2))
    return p, 2 * u1 / (n1 * n2) - 1  # rank-biserial: +1=a 가 항상 큼, -1=반대


def fleiss_kappa(items: list[list[str]]) -> tuple[float | None, int, int]:
    """Fleiss' κ — items[i] = 그 CVE 에 대한 평정자들의 범주 목록.

    평정자 수가 같은 항목만 사용(Fleiss 전제). 반환 (κ, 사용 항목 수, 평정자 수).
    """
    if not items:
        return None, 0, 0
    n_mode = Counter(len(it) for it in items).most_common(1)[0][0]
    use = [it for it in items if len(it) == n_mode]
    if n_mode < 2 or len(use) < 2:
        return None, len(use), n_mode
    cats = sorted({c for it in use for c in it})
    N, n = len(use), n_mode
    p_j = {c: 0.0 for c in cats}
    P_i = []
    for it in use:
        cnt = Counter(it)
        for c in cats:
            p_j[c] += cnt[c]
        P_i.append((sum(cnt[c] ** 2 for c in cats) - n) / (n * (n - 1)))
    for c in cats:
        p_j[c] /= (N * n)
    P_bar = sum(P_i) / N
    P_e = sum(v ** 2 for v in p_j.values())
    if P_e >= 1.0:
        return None, N, n
    return (P_bar - P_e) / (1 - P_e), N, n


def _fmt(x, nd=3):
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "예" if x else "아니오"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def _stars(p: float | None) -> str:
    if p is None:
        return ""
    return " ***" if p < 0.001 else " **" if p < 0.01 else " *" if p < 0.05 else ""


# ── 분석 1: 기술통계 ─────────────────────────────────────────
def describe(rows: list[dict], out: list[str]) -> None:
    out.append("## 1. 표본 개요\n")
    if not rows:
        out.append("_run_events.jsonl 에 데이터가 없습니다._\n")
        return
    ts = sorted(r.get("ts", "") for r in rows if r.get("ts"))
    span_h = None
    if len(ts) >= 2:
        try:
            span_h = (datetime.fromisoformat(ts[-1]) - datetime.fromisoformat(ts[0])).total_seconds() / 3600
        except ValueError:
            pass
    ok = analyzable(rows)
    out.append(f"- 총 런 이벤트: **{len(rows)}건** (분석 가능 표본 **{len(ok)}건**)")
    out.append(f"- 고유 CVE: **{len({r.get('cve') for r in rows})}개**")
    if span_h:
        out.append(f"- 관측 기간: {span_h:.1f}시간 (표본 생성률 **{len(ok)/span_h:.1f}건/시간**)")
    out.append(f"- 결과 분포: {dict(Counter(r.get('outcome') for r in rows))}")
    out.append(f"- 파이프라인 버전: {dict(Counter(_version_of(r) for r in rows))}")
    out.append(f"- arm 분포: {dict(Counter(r.get('arm') for r in rows))}")
    out.append(f"- 페르소나 분포: {dict(Counter(r.get('persona') for r in rows))}")
    out.append(f"- peer 참조 분포: {dict(sorted(Counter(r.get('peer_ref_used') for r in ok).items()))}")
    out.append("")


# ── 분석 2: 협업 효과(같은 CVE 내 짝비교) ────────────────────
def _mean_of(rows: list[dict], key: str) -> float | None:
    vals = []
    for r in rows:
        v = (r.get("metrics") or {}).get(key, r.get(key))
        if isinstance(v, bool):
            v = int(v)
        if isinstance(v, (int, float)):
            vals.append(float(v))
    return statistics.mean(vals) if vals else None


def persona_baseline(rows: list[dict], key: str) -> dict[str, float]:
    """페르소나별 지표 중앙값 — 페르소나 고유의 기준선(설계상 의도한 차이).

    이걸 빼고 나서 차분해야 '협업 때문에 좋아진 것'과 '원래 그 페르소나가 길게 쓰는 것'이
    분리된다. 표준화(z-score) 대신 중앙값만 빼는 이유: 지표 단위(자·개수)를 유지해야
    포스터에서 '몇 자 늘었다'로 읽힌다.
    """
    by: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        v = _mean_of([r], key)
        if v is not None:
            by[str(r.get("persona"))].append(v)
    return {p: statistics.median(vs) for p, vs in by.items() if vs}


def _adjusted(rows: list[dict], key: str, base: dict[str, float]) -> float | None:
    """페르소나 기준선을 뺀 값의 평균(같은 그룹에 여러 건이면 평균)."""
    vals = []
    for r in rows:
        v = _mean_of([r], key)
        if v is not None:
            vals.append(v - base.get(str(r.get("persona")), 0.0))
    return statistics.mean(vals) if vals else None


def paired_peer_effect(rows: list[dict], out: list[str]) -> None:
    out.append("## 2. 협업 효과 — 같은 CVE 내 '선발 vs 후발' 짝비교\n")
    out.append("> 같은 CVE 를 선발 분석가(다른 분석을 못 봄, peer=0)와 후발 분석가"
               "(peer≥1)가 각각 분석한 쌍만 사용. CVE 난이도가 통제된다.\n")
    ok = analyzable(rows)
    by_cve: dict[str, list[dict]] = defaultdict(list)
    for r in ok:
        by_cve[r.get("cve")].append(r)

    pairs = []
    for cve, rs in by_cve.items():
        first = [r for r in rs if (r.get("peer_ref_used") or 0) == 0]
        later = [r for r in rs if (r.get("peer_ref_used") or 0) >= 1]
        if first and later:
            pairs.append((cve, first, later))
    out.append(f"- 짝지은 CVE: **{len(pairs)}쌍**")
    if len(pairs) < 3:
        out.append("\n_짝 표본이 부족합니다. 상시 운영으로 축적되면 자동으로 채워집니다._\n")
        return

    # 페르소나 구성 점검 — 선발/후발의 구성이 다르면 보정이 필수라는 근거를 표에 남긴다.
    f_mix = Counter(str(r.get("persona")) for _c, first, _l in pairs for r in first)
    l_mix = Counter(str(r.get("persona")) for _c, _f, later in pairs for r in later)
    out.append(f"- 선발 페르소나 구성: {dict(sorted(f_mix.items()))}")
    out.append(f"- 후발 페르소나 구성: {dict(sorted(l_mix.items()))}")
    skewed = set(f_mix) != set(l_mix) or any(
        abs(f_mix[p] / max(1, sum(f_mix.values())) - l_mix[p] / max(1, sum(l_mix.values()))) > 0.15
        for p in set(f_mix) | set(l_mix))
    out.append("- 구성 균형: " + ("**불균형 — 페르소나 보정 필수**" if skewed else "대체로 균형")
               + " (아래 표는 어느 쪽이든 보정 후 수치)\n")

    out.append("| 지표 | 선발(peer=0) | 후발(peer≥1) | 차이(보정, 중앙값) | 95% CI | 개선 비율 | p(부호) | p(Wilcoxon) |")
    out.append("|---|---|---|---|---|---|---|---|")
    for key, label, higher_better in METRICS:
        base = persona_baseline(ok, key)  # 기준선은 전체 표본에서 잡는다(쌍에 국한하지 않음)
        diffs, f_vals, l_vals = [], [], []
        for _cve, first, later in pairs:
            a, b = _adjusted(first, key, base), _adjusted(later, key, base)
            raw_a, raw_b = _mean_of(first, key), _mean_of(later, key)
            if a is None or b is None:
                continue
            f_vals.append(raw_a)   # 표시는 원값(해석 가능해야 하므로)
            l_vals.append(raw_b)
            diffs.append((b - a) if higher_better else (a - b))  # 항상 '양수=개선'
        if len(diffs) < 3:
            continue
        pos, n, p_sign = sign_test(diffs)
        p_w = wilcoxon_p(diffs)
        ci = bootstrap_ci(diffs)
        ci_s = f"[{ci[0]:.2f}, {ci[1]:.2f}]" if ci else "—"
        med = statistics.median(diffs)
        # ▲=개선 / ▼=악화. 지표 방향(클수록 좋음/나쁨)은 이미 diffs 부호에 반영돼 있다.
        arrow = "▲" if med > 0 else ("▼" if med < 0 else "－")
        # n=0 은 모든 쌍이 완전 동률(예: 섹션 완결률 둘 다 1.0) — 검정 자체가 무의미하다.
        ratio = f"{pos}/{n} ({pos / n * 100:.0f}%)" if n else "동률"
        out.append(
            f"| {label} | {_fmt(statistics.median(f_vals),2)} | {_fmt(statistics.median(l_vals),2)} "
            f"| {arrow}{abs(med):.2f} | {ci_s} | {ratio} "
            f"| {p_sign:.4f}{_stars(p_sign)} | {_fmt(p_w,4)}{_stars(p_w)} |")
    out.append("")
    out.append("_'개선 비율'은 후발이 선발보다 나았던 쌍의 비율. **▲=개선, ▼=악화**로, "
               "'클수록 좋은 지표'와 '작을수록 좋은 지표'(환각 수·소요시간)의 부호를 통일했다._")
    out.append("_'차이(보정)'는 각 표본에서 **그 페르소나의 전체 중앙값을 뺀 뒤** 차분한 값이다. "
               "선발/후발의 페르소나 구성이 다를 때 그 구성 차이가 협업 효과로 둔갑하는 것을 막는다. "
               "좌우 두 열은 해석 편의를 위한 원값이므로 '차이(보정)'과 산술적으로 맞지 않을 수 있다._\n")

    # 근거 인용률(이항 지표)
    out.append("| 근거 인용 | 선발(peer=0) | 후발(peer≥1) |")
    out.append("|---|---|---|")
    for key, label in RATE_METRICS:
        f_r = [_mean_of(first, key) for _c, first, _l in pairs]
        l_r = [_mean_of(later, key) for _c, _f, later in pairs]
        f_r = [v for v in f_r if v is not None]
        l_r = [v for v in l_r if v is not None]
        if f_r and l_r:
            out.append(f"| {label} | {statistics.mean(f_r)*100:.1f}% | {statistics.mean(l_r)*100:.1f}% |")
    out.append("")

    # 신규성 — 후발이 베낀 게 아님을 보이는 핵심 반증 지표
    nov = [v for r in analyzable(rows)
           if (v := (r.get("metrics") or {}).get("novel_ratio")) is not None]
    jac = [v for r in analyzable(rows)
           if (v := (r.get("metrics") or {}).get("peer_jaccard")) is not None]
    if nov:
        out.append(f"**신규성 검증(복붙 반증)** — 후발 분석 {len(nov)}건의 토큰 신규성 중앙값 "
                   f"**{statistics.median(nov):.3f}** "
                   f"(1.0=완전 독립), peer 와의 Jaccard 중앙값 "
                   f"{statistics.median(jac):.3f}. "
                   "협업이 '베끼기'가 아니라 '덧붙이기'임을 보인다.\n")


# ── 분석 3: arm 비교(대조군) ─────────────────────────────────
def arm_compare(rows: list[dict], out: list[str]) -> None:
    ok = analyzable(rows)
    arms = {r.get("arm") for r in ok}
    out.append("## 3. arm 비교 — 플랫폼 vs 대조군\n")
    if len(arms) < 2:
        out.append(f"_현재 arm 이 하나뿐입니다({arms or '없음'}). "
                   "`AGENT_ARM=control` + `AGENT_PEER_REFERENCE=false` 로 대조군 에이전트를 "
                   "띄우면 이 절이 자동으로 채워집니다._\n")
        return
    names = sorted(arms)
    mix = {a: Counter(str(r.get("persona")) for r in ok if r.get("arm") == a) for a in names}
    out.append(f"- arm: {', '.join(names)}")
    out.append("- 표본: " + ", ".join(f"{a}={sum(mix[a].values())}건" for a in names))
    for a in names:
        out.append(f"  - {a} 페르소나 구성: {dict(sorted(mix[a].items()))}")

    # 페르소나 매칭 — arm 마다 페르소나 구성이 다르면(대조군=analyst 전원 vs 플랫폼=3종 혼합)
    # 여기서 나오는 차이는 '협업 효과'가 아니라 '페르소나 구성 차이'다. 모든 arm 에
    # 공통으로 존재하는 페르소나만 남겨 비교해야 그 교란이 사라진다.
    common = set.intersection(*(set(mix[a]) for a in names)) if names else set()
    common.discard("None")
    if not common:
        out.append("\n_arm 사이에 공통 페르소나가 없어 공정한 비교가 불가능합니다. "
                   "대조군 페르소나를 플랫폼 쪽과 일치시켜야 합니다._\n")
        return
    matched = [r for r in ok if str(r.get("persona")) in common]
    out.append(f"\n**페르소나 매칭 비교** — 공통 페르소나 `{', '.join(sorted(common))}` 만 사용 "
               "(구성 차이가 arm 효과로 둔갑하는 것을 차단)")
    out.append("- 매칭 표본: " + ", ".join(
        f"{a}={sum(1 for r in matched if r.get('arm') == a)}건" for a in names) + "\n")

    ref = names[0]
    others = names[1:]
    head = ["지표"] + [f"{a} (중앙값)" for a in names]
    if len(names) == 2:
        head += [f"차이({others[0]}−{ref})", "p(Mann-Whitney)", "효과크기 r"]
    out.append("| " + " | ".join(head) + " |")
    out.append("|---" * len(head) + "|")

    def _cells(key: str, agg, scale: float, suffix: str) -> list[str]:
        per = {a: [v for r in matched if r.get("arm") == a
                   and (v := _mean_of([r], key)) is not None] for a in names}
        row = [f"{agg(per[a])*scale:.2f}{suffix}" if per[a] else "—" for a in names]
        if len(names) == 2:
            a_vals, b_vals = per[ref], per[others[0]]
            if a_vals and b_vals:
                d = agg(b_vals) - agg(a_vals)
                p, eff = mannwhitney_p(a_vals, b_vals)
                row += [f"{d*scale:+.2f}{suffix}",
                        f"{_fmt(p, 4)}{_stars(p)}",
                        _fmt(-eff if eff is not None else None, 3)]
            else:
                row += ["—", "—", "—"]
        return row

    for key, label, _hb in METRICS:
        out.append(f"| {label} | " + " | ".join(_cells(key, statistics.median, 1.0, "")) + " |")
    for key, label in RATE_METRICS:
        out.append(f"| {label} | " + " | ".join(_cells(key, statistics.mean, 100.0, "%")) + " |")
    out.append("")
    out.append(f"_효과크기 r 은 rank-biserial: +1 이면 `{others[0] if others else '?'}` 가 항상 큼, "
               "−1 이면 반대, 0 이면 구분 불가. n 이 크면 p 는 사소한 차이에도 작아지므로 "
               "포스터에는 r 을 함께 싣는 편이 안전하다._\n")


# ── 분석 4: 다관점 산출물(단일 에이전트 불가) ────────────────
def multi_perspective(rows: list[dict], out: list[str]) -> None:
    ok = analyzable(rows)
    out.append("## 4. 다관점 산출물 — 단일 에이전트가 원리적으로 만들 수 없는 것\n")
    by_cve: dict[str, list[dict]] = defaultdict(list)
    for r in ok:
        by_cve[r.get("cve")].append(r)

    cov = Counter(len({r.get("persona") for r in rs}) for rs in by_cve.values())
    out.append(f"- CVE 당 관점 수 분포: {dict(sorted(cov.items()))}")
    multi = sum(v for k, v in cov.items() if k >= 2)
    out.append(f"- **2개 이상 관점이 붙은 CVE: {multi}개** "
               f"({multi/max(1,len(by_cve))*100:.1f}%)\n")

    for field, label in (("priority_action", "우선순위 판정"),
                         ("exploitability_grade", "악용 난이도 등급")):
        items = []
        for rs in by_cve.values():
            per: dict[str, str] = {}
            for r in rs:
                v = r.get(field)
                if v and r.get("persona"):
                    per[r["persona"]] = str(v)
            if len(per) >= 2:
                items.append(sorted(per.values()))
        k, N, n = fleiss_kappa(items)
        if k is None:
            out.append(f"- {label} 합의도: 표본 부족(항목 {N}, 평정자 {n})")
            continue
        interp = ("거의 완전" if k > 0.8 else "상당" if k > 0.6 else "중간" if k > 0.4
                  else "약함" if k > 0.2 else "미미")
        unanimous = sum(1 for it in items if len(set(it)) == 1) / max(1, len(items))
        out.append(f"- **{label} 합의도(Fleiss' κ) = {k:.3f}** ({interp}) "
                   f"— 항목 {N}개, 평정자 {n}명, 만장일치 {unanimous*100:.1f}%")
    out.append("")
    out.append("> κ 는 서로 다른 관점의 에이전트가 **독립적으로** 같은 결론에 도달하는지를 "
               "재는 지표다. 에이전트가 하나뿐이면 정의 자체가 성립하지 않는다.\n")

    # 커버리지 속도 — 첫 분석 → 다관점 확보까지
    lags = []
    for rs in by_cve.values():
        stamps = sorted((r.get("ts"), r.get("persona")) for r in rs if r.get("ts"))
        seen, t0 = set(), None
        for ts, p in stamps:
            try:
                t = datetime.fromisoformat(ts)
            except (TypeError, ValueError):
                continue
            if t0 is None:
                t0 = t
            seen.add(p)
            if len(seen) >= 2:
                lags.append((t - t0).total_seconds() / 60)
                break
    if lags:
        out.append(f"- **다관점 확보 소요**: 첫 분석 후 두 번째 관점까지 중앙값 "
                   f"**{statistics.median(lags):.1f}분** (n={len(lags)})\n")


# ── 분석 5: 검증 노드 효과 ───────────────────────────────────
def verification_effect(rows: list[dict], out: list[str]) -> None:
    ok = analyzable(rows)
    out.append("## 5. 검증 노드 효과\n")
    if not ok:
        out.append("_표본 없음._\n")
        return
    on = [r for r in ok if (r.get("config") or {}).get("verify_report")]
    off = [r for r in ok if not (r.get("config") or {}).get("verify_report")]
    rep = sum(1 for r in ok if r.get("verification_repaired"))
    out.append(f"- 재작성 발동: **{rep}건 / {len(ok)}건 ({rep/len(ok)*100:.1f}%)** "
               "— 나머지는 GPU 추가 비용 0")
    fails = Counter(f for r in ok for f in (r.get("verification_failures") or []))
    out.append(f"- 잔존 실패 항목: {dict(fails) or '없음'}")
    for name, grp in (("검증 ON", on), ("검증 OFF(ablation)", off)):
        if not grp:
            continue
        hall = [float((r.get("metrics") or {}).get("ungrounded_cve_count") or 0) for r in grp]
        rate = sum(1 for h in hall if h > 0) / len(hall)
        out.append(f"- {name}: 환각 CVE 포함 리포트 비율 **{rate*100:.1f}%** "
                   f"(평균 {statistics.mean(hall):.2f}건/리포트, n={len(grp)})")
    out.append("")
    hr = sum(1 for r in ok if r.get("needs_human_review"))
    out.append(f"- 사람 검토 플래그: {hr}건 ({hr/len(ok)*100:.1f}%)\n")


# ── 분석 6: 지표 편향 점검(구체성) ───────────────────────────
_SECTION_LABELS = (("attack", "공격 기법"), ("impact", "영향"), ("chaining", "체이닝"),
                   ("detection", "탐지"), ("mitigation", "완화"))


def specificity_bias(rows: list[dict], out: list[str]) -> None:
    """구체성 지표가 방어 산출물에 유리하다는 점을 숨기지 않고 표로 드러낸다.

    왜 필요한가: specificity 패턴은 정규식·SIEM 쿼리·로그 필드·명령어를 센다. 이건 탐지/완화
    산출물의 형태다. 공격 관점의 '원리 중심 서술'은 같은 깊이로 써도 점수가 낮게 나온다.
    이 표가 없으면 '방어 페르소나가 더 구체적이다' 라는 잘못된 결론이 포스터에 실린다.
    """
    ok = analyzable(rows)
    out.append("## 6. 지표 편향 점검 — 구체성 지표는 방어 편향이 있다\n")
    have = [r for r in ok if (r.get("report_sections") or {})]
    if len(have) < 10:
        out.append("_섹션 본문이 기록된 표본이 부족합니다(구버전 레코드)._\n")
        return
    try:
        from pipeline.metrics import specificity as _spec
    except Exception:  # noqa: BLE001 — 저장소 밖에서 CSV 만 볼 때도 죽지 않게
        out.append("_pipeline.metrics 를 불러올 수 없어 생략합니다._\n")
        return

    personas = sorted({str(r.get("persona")) for r in have if r.get("persona")})
    out.append("**페르소나 × 섹션별 구체성 점수(중앙값)**\n")
    out.append("| 페르소나 | " + " | ".join(l for _k, l in _SECTION_LABELS) + " |")
    out.append("|---" * (len(_SECTION_LABELS) + 1) + "|")
    for p in personas:
        grp = [r for r in have if str(r.get("persona")) == p]
        cells = []
        for key, _label in _SECTION_LABELS:
            vals = [float(_spec((r.get("report_sections") or {}).get(key) or "")["specificity_total"])
                    for r in grp]
            cells.append(f"{statistics.median(vals):.1f}" if vals else "—")
        out.append(f"| {p} (n={len(grp)}) | " + " | ".join(cells) + " |")
    out.append("")
    out.append("> 대각선(각 페르소나의 focus 섹션)이 높으면 페르소나 분화가 작동한다는 뜻이다. "
               "동시에 **탐지·완화 열의 절대값이 공격·영향 열보다 구조적으로 높다면** 그것은 "
               "품질 차이가 아니라 지표의 형태 편향이다. 따라서 **구체성은 같은 페르소나끼리만 "
               "비교**하고, 페르소나를 가로지를 때는 2절의 보정값을 쓴다.\n")


def revision_effect(rows: list[dict], out: list[str]) -> None:
    """개정 전후 짝비교 — 자연실험보다 통제가 강한 설계.

    2절(선발 vs 후발)은 '다른 에이전트끼리' 비교라 페르소나·모델·시점이 전부 다르다.
    여기서는 **같은 에이전트가 같은 CVE 를 다시 쓴 것**이라 달라진 것이 커뮤니티 입력뿐이다.
    페르소나 보정이 아예 필요 없다(같은 페르소나이므로 차분에서 소거된다).

    또 하나 중요한 것은 대조군이 위약(placebo)으로 작동한다는 점이다. 대조군도 같은
    조건에서 개정을 트리거하지만 report 노드가 동료 분석·댓글을 조회하지 않는다. 따라서
    대조군의 전후 변화는 '다시 쓰기만 해도 생기는 변화'이고, 처치군에서 이것을 빼야
    남는 것이 '커뮤니티 정보 때문에 생긴 변화'다.
    """
    out.append("## 7. 개정 효과 — 같은 에이전트·같은 CVE 의 전후 비교\n")
    revs = [r for r in rows if (r.get("revision") or {}).get("revision_of")]
    if not revs:
        out.append("_개정 표본 없음(아직 개정 사이클이 돌지 않았습니다)._\n")
        return

    # 원판 찾기: 같은 arm·같은 CVE 의 revision_index=0 게시본 중 가장 최근 것.
    by_key: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        by_key[(str(r.get("arm")), str(r.get("cve")))].append(r)

    pairs: list[tuple[dict, dict]] = []
    for rev in revs:
        pool = [r for r in by_key[(str(rev.get("arm")), str(rev.get("cve")))]
                if int(r.get("revision_index") or 0) < int(rev.get("revision_index") or 1)
                and r.get("ts") and rev.get("ts") and r["ts"] < rev["ts"]]
        if pool:
            pairs.append((max(pool, key=lambda r: r["ts"]), rev))
    if not pairs:
        out.append(f"_개정 {len(revs)}건이 있으나 대응하는 원판을 찾지 못했습니다._\n")
        return

    out.append(f"- 개정 쌍: **{len(pairs)}쌍** (arm × CVE 기준, 원판→개정본)\n")
    by_arm: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for before, after in pairs:
        by_arm[str(before.get("arm") or "default")].append((before, after))

    head = ["지표", *(f"{a} (n={len(v)})" for a, v in sorted(by_arm.items()))]
    out.append("| " + " | ".join(head) + " |")
    out.append("|---" * len(head) + "|")
    for key, label, nd in (("total_chars", "분량 변화(자)", 1),
                           ("specificity_total", "구체성 변화(개)", 2),
                           ("cve_refs", "CVE 참조 변화(개)", 2)):
        cells = [label]
        for _arm, ps in sorted(by_arm.items()):
            diffs = []
            for b, a in ps:
                x, y = _mean_of([b], key), _mean_of([a], key)
                if x is not None and y is not None:
                    diffs.append(y - x)
            if not diffs:
                cells.append("—")
                continue
            _pos, _neg, p = sign_test(diffs)
            cells.append(f"{statistics.mean(diffs):+.{nd}f} {_stars(p)}")
        out.append("| " + " | ".join(cells) + " |")
    out.append("")

    # 흡수율 — 분량 대신 '동료가 말한 것이 실제로 반영됐는가'를 직접 본다.
    out.append("**정보 흡수율** — 동료에게만 있던 토큰 중 개정본에 들어온 비율\n")
    out.append("| arm | n | 흡수율(adopted_ratio) | 자체 추가 비율(self_added) |")
    out.append("|---|---|---|---|")
    for arm, ps in sorted(by_arm.items()):
        ad = [v for _b, a in ps
              if (v := (a.get("metrics") or {}).get("adopted_ratio")) is not None]
        se = [v for _b, a in ps
              if (v := (a.get("metrics") or {}).get("self_added_ratio")) is not None]
        ad_cell = f"{statistics.mean(ad)*100:.1f}% ({len(ad)}건)" if ad else "— (동료 정보 없음)"
        se_cell = f"{statistics.mean(se)*100:.1f}%" if se else "—"
        out.append(f"| {arm} | {len(ps)} | {ad_cell} | {se_cell} |")
    out.append("")
    out.append("> 흡수율은 대조군에서 **정의상 측정 불가**(동료 텍스트가 0이라 분모가 없다)여야 "
               "정상이다. 대조군에 값이 잡히면 arm 격리가 깨진 것이므로 먼저 그것을 고쳐야 한다. "
               "처치군 흡수율이 0 에 가깝다면 '커뮤니티를 봤지만 반영하지 않았다'는 뜻이라, "
               "분량이 늘었더라도 협업 효과로 주장할 수 없다.\n")


# ── 메인 ─────────────────────────────────────────────────────
def build_report(rows: list[dict], *, version: str | None = None) -> str:
    """version=None → 최신 파이프라인 버전만. 'all' → 전 버전 합산(교란 있음)."""
    chosen = latest_version(rows) if version is None else version
    scoped = filter_version(rows, chosen)
    out: list[str] = ["# Kestrel 다중 에이전트 플랫폼 — 정량 분석\n",
                      f"_생성: {datetime.now().strftime('%Y-%m-%d %H:%M')} · "
                      f"원자료: run_events.jsonl_\n"]
    if chosen and chosen != "all":
        out.append(f"> **분석 범위: 파이프라인 `{chosen}` 표본 {len(scoped)}건만** "
                   f"(전체 {len(rows)}건 중). 프롬프트가 바뀌면 분량·구체성의 기준선이 달라져 "
                   "버전을 섞으면 협업 효과와 프롬프트 개선 효과가 분리되지 않는다. "
                   "전 버전을 보려면 `--pipeline-version all`.\n")
    else:
        out.append("> ⚠️ **전 버전 합산 모드** — 파이프라인 버전이 섞여 있으면 아래 수치는 "
                   "협업 효과와 프롬프트 변경 효과가 뒤섞인 값이다. 논문 인용 금지.\n")
    describe(scoped, out)
    paired_peer_effect(scoped, out)
    arm_compare(scoped, out)
    multi_perspective(scoped, out)
    verification_effect(scoped, out)
    specificity_bias(scoped, out)
    revision_effect(scoped, out)
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="run_events.jsonl → 포스터용 수치·CSV")
    ap.add_argument("--events", default=str(_BASE / "run_events.jsonl"))
    ap.add_argument("--csv", help="평탄화한 원자료 CSV 출력 경로(필터 미적용, 전량)")
    ap.add_argument("--md", help="마크다운 리포트 저장 경로")
    ap.add_argument("--pipeline-version", dest="pipeline_version", default=None,
                    help="분석할 파이프라인 버전. 생략하면 최신 버전만, 'all' 이면 전량")
    args = ap.parse_args()

    rows = load(Path(args.events))
    report = build_report(rows, version=args.pipeline_version)
    print(report)

    if args.csv and rows:
        flats = [flat(r) for r in rows]
        cols: list[str] = []
        for f in flats:
            for k in f:
                if k not in cols:
                    cols.append(k)
        with open(args.csv, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(flats)
        print(f"\n[CSV] {args.csv} — {len(flats)}행 × {len(cols)}열")
    if args.md:
        Path(args.md).write_text(report, encoding="utf-8")
        print(f"[MD] {args.md}")


if __name__ == "__main__":
    main()
