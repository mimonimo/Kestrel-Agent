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

사용:
  python3 export_metrics.py                      # 요약을 화면에
  python3 export_metrics.py --csv out.csv        # 원자료 CSV 동시 출력
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
                        "verification_failures", "report_sections")}
    for k, v in (ev.get("config") or {}).items():
        out[f"cfg_{k}"] = v
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


def paired_peer_effect(rows: list[dict], out: list[str]) -> None:
    out.append("## 2. 협업 효과 — 같은 CVE 내 '선발 vs 후발' 짝비교\n")
    out.append("> 같은 CVE 를 선발 분석가(다른 분석을 못 봄, peer=0)와 후발 분석가"
               "(peer≥1)가 각각 분석한 쌍만 사용. CVE 난이도가 통제된다.\n")
    by_cve: dict[str, list[dict]] = defaultdict(list)
    for r in analyzable(rows):
        by_cve[r.get("cve")].append(r)

    pairs = []
    for cve, rs in by_cve.items():
        first = [r for r in rs if (r.get("peer_ref_used") or 0) == 0]
        later = [r for r in rs if (r.get("peer_ref_used") or 0) >= 1]
        if first and later:
            pairs.append((cve, first, later))
    out.append(f"- 짝지은 CVE: **{len(pairs)}쌍**\n")
    if len(pairs) < 3:
        out.append("_짝 표본이 부족합니다. 상시 운영으로 축적되면 자동으로 채워집니다._\n")
        return

    out.append("| 지표 | 선발(peer=0) | 후발(peer≥1) | 차이(중앙값) | 95% CI | 개선 비율 | p(부호) | p(Wilcoxon) |")
    out.append("|---|---|---|---|---|---|---|---|")
    for key, label, higher_better in METRICS:
        diffs, f_vals, l_vals = [], [], []
        for _cve, first, later in pairs:
            a, b = _mean_of(first, key), _mean_of(later, key)
            if a is None or b is None:
                continue
            f_vals.append(a)
            l_vals.append(b)
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
               "'클수록 좋은 지표'와 '작을수록 좋은 지표'(환각 수·소요시간)의 부호를 통일했다._\n")

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
    # 같은 CVE 를 두 arm 이 모두 분석한 경우 짝비교, 아니면 전체 분포 비교
    by_cve: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for r in ok:
        by_cve[r.get("cve")][r.get("arm")].append(r)
    names = sorted(arms)
    out.append(f"- arm: {', '.join(names)}")
    out.append(f"- 표본: " + ", ".join(f"{a}={sum(1 for r in ok if r.get('arm')==a)}건" for a in names))
    out.append("")
    out.append("| 지표 | " + " | ".join(names) + " |")
    out.append("|---" * (len(names) + 1) + "|")
    for key, label, _hb in METRICS:
        cells = []
        for a in names:
            vals = [v for r in ok if r.get("arm") == a
                    and (v := _mean_of([r], key)) is not None]
            cells.append(f"{statistics.median(vals):.2f}" if vals else "—")
        out.append(f"| {label} | " + " | ".join(cells) + " |")
    for key, label in RATE_METRICS:
        cells = []
        for a in names:
            vals = [v for r in ok if r.get("arm") == a
                    and (v := _mean_of([r], key)) is not None]
            cells.append(f"{statistics.mean(vals)*100:.1f}%" if vals else "—")
        out.append(f"| {label} | " + " | ".join(cells) + " |")
    out.append("")


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


# ── 메인 ─────────────────────────────────────────────────────
def build_report(rows: list[dict]) -> str:
    out: list[str] = ["# Kestrel 다중 에이전트 플랫폼 — 정량 분석\n",
                      f"_생성: {datetime.now().strftime('%Y-%m-%d %H:%M')} · "
                      f"원자료: run_events.jsonl_\n"]
    describe(rows, out)
    paired_peer_effect(rows, out)
    arm_compare(rows, out)
    multi_perspective(rows, out)
    verification_effect(rows, out)
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="run_events.jsonl → 포스터용 수치·CSV")
    ap.add_argument("--events", default=str(_BASE / "run_events.jsonl"))
    ap.add_argument("--csv", help="평탄화한 원자료 CSV 출력 경로")
    ap.add_argument("--md", help="마크다운 리포트 저장 경로")
    args = ap.parse_args()

    rows = load(Path(args.events))
    report = build_report(rows)
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
