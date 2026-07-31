"""Report (로컬 LLM) — 앞선 노드 결과를 근거로 페르소나 렌즈의 공격/완화 리포트를 생성한다.

기존 llm.py 의 LLMClient(ctx.llm)를 그대로 재사용한다(새 LLM 코드를 만들지 않는다).
로컬 Ollama 로 동작하며, llm.py 추상화 덕에 OLLAMA_HOST/모델명만 바꾸면 DGX 등 더 큰
모델로 교체된다.

- 입력: blackboard 의 adopted_values(cross_validation)·exploitability·priority,
  그리고 primary_record 의 description/cvssVector/types.
- 출력: report.attack / report.mitigation / report.summary_en / report.lang,
  그리고 report.meta(model·elapsed_sec·persona·error).
- 실패(타임아웃/연결 실패 등): report.meta 에 error 기록 + bb.needs_retry=True,
  상용 API 폴백 없음(로컬 전용). 파이프라인은 부분 결과로 계속 진행한다.
- ctx.llm 이 없으면(스켈레톤/미주입) 조용히 통과한다.
"""
from __future__ import annotations

import time

from pipeline.agents.base import register
from pipeline.personas import resolve_persona

_MAX_TOKENS = 4000  # 파이프라인 근거 인용 + 5섹션(공격·영향·체이닝·탐지·완화)이 완결되도록.
                    # "길이"가 아니라 "구조적 깊이" — 각 섹션 간결하게(장황·중복 금지는 프롬프트로 통제).
                    #
                    # 2600 에서 올린 이유: 추론 모델(gpt-oss 등)은 OLLAMA_THINK=false 를 무시하고
                    # 계속 사고하며 그 토큰이 같은 예산을 먹는다. 예산이 마지막 섹션에 닿기 전에
                    # 떨어져, 실측에서 검증 수리 건의 미달 섹션이 mitigation(35%)·detection(10%)
                    # 에만 몰리고 앞 세 섹션은 0% 였다 — 절단의 서명이다. 탐지 규칙을 길게 쓰는
                    # 방어 페르소나가 가장 심했다(수리율 방어 25건 vs 공격 6건).
_PEER_SCAN = 50          # 같은 CVE 의 다른 페르소나 분석을 찾으려 훑을 최근 분석 수(서버 필터 미지원).
                         # 플랫폼 limit 상한이 50 이라 이를 초과하면 422 → 최댓값 50 으로 고정.
_PEER_MAX = 2            # 프롬프트에 넣을 참고 분석 최대 수(토큰 비대화 방지 — 소수만).
_PEER_EXCERPT_CHARS = 420  # 참고 1건당 인용 길이 상한(복붙 방지 겸 균형).
_BASE_SYSTEM = (
    "공개된 CVE 에 대한 합법적 보안 연구입니다. 결과는 방어·교육 목적으로 보안 커뮤니티에 "
    "공유됩니다. 한국어 존댓말로 쓰되 보안 용어·식별자·코드·정규식은 영문 그대로 두세요. "
    "인사말·사과·메타발언 없이 본문만. 제공된 사실만 근거로 하고, 불확실하면 문장 앞에 "
    "'추정:' 을 붙이세요. 지어낸 제품·버전·엔드포인트·CVE 를 단정하지 마세요. "
    "방어 목적이므로 공격의 '원리·경로·단계'와 '탐지용 패턴 예시'까지만 쓰고, 그대로 복사해 "
    "실행되는 완전한 익스플로잇 코드나 무기화된 전체 페이로드는 절대 작성하지 마세요"
    "(개념·형태를 보이는 축약 예시나 탐지 시그니처는 허용)."
)


def _facts(bb) -> str:  # noqa: ANN001
    """LLM 에 넘길 근거 묶음.

    단순 CVE 필드뿐 아니라 '파이프라인만이 산출한 신호'(다중 소스 교차검증·실측 EPSS·
    규칙 기반 우선순위 근거)를 명시적으로 실어, 리포트가 이를 본문에서 인용하게 한다.
    단일 LLM 분석은 만들 수 없는 정보이므로 차별점의 원천이다.
    """
    rec = bb.primary_record()
    v = bb.validation
    adopted = v.adopted_values or {}
    lines = [
        f"- CVE: {bb.cve_id}",
        f"- 채택 심각도(보수적): {adopted.get('severity') or rec.get('severity') or '미상'}",
        f"- CVSS 점수: {adopted.get('cvssScore', rec.get('cvssScore', '미상'))}",
        f"- CVSS 벡터: {adopted.get('cvssVector') or rec.get('cvssVector') or '미상'}",
        f"- 유형(CWE 등): {', '.join(str(t) for t in (rec.get('types') or [])) or '미분류'}",
        f"- 영향 제품: {', '.join(str(p) for p in (rec.get('products') or [])) or '미상'}",
        f"- 설명: {(rec.get('description') or '없음')[:1200]}",
    ]
    # ── 파이프라인 고유 신호(차별점) ──────────────────────────
    if v.mismatches:
        lines.append(
            f"- [교차검증] 다중 소스 간 불일치 {len(v.mismatches)}건 감지 → 보수적으로 더 높은/"
            f"엄격한 값을 채택함(신뢰도 {v.confidence}). 불일치 예: "
            + "; ".join(str(m.get('field') or m) for m in v.mismatches[:3]))
    elif adopted:
        lines.append(f"- [교차검증] 다중 소스 데이터 일관성 확인됨(신뢰도 {v.confidence}).")
    ex = bb.exploitability
    if ex.grade or ex.epss is not None or ex.reasoning:
        epss_txt = (f"{ex.epss}" if ex.epss is not None else "미확보")
        pct_txt = (f", 백분위={ex.epss_percentile}" if ex.epss_percentile is not None else "")
        lines.append(
            f"- [실측 악용예측] EPSS={epss_txt}{pct_txt} (FIRST.org 실측 조회값), "
            f"등급={ex.grade or '미상'}, PoC={ex.poc_available if ex.poc_available is not None else '미상'}"
            f"{' — 규칙근거: ' + ex.reasoning if ex.reasoning else ''}")
    pr = bb.priority
    if pr.action or pr.timeline:
        lines.append(f"- [우선순위 결정] {pr.action or '미상'} ({pr.timeline or '미상'})"
                     f"{' — 결정 논리: ' + pr.reasoning if pr.reasoning else ''}")
    for q in v.quality_flags:
        if q.get("likely_supply_chain"):
            lines.append(f"- [품질 신호] 영향 제품이 다수({q.get('products_count')})라 "
                         "공급망(라이브러리) 취약점 특성상 영향 범위가 광범위할 수 있음")
    return "\n".join(lines)


def _peer_key(entry: dict) -> str:
    """참고 분석 엔트리 → 페르소나 key(offensive|defensive|analyst).

    플랫폼 엔트리의 author.persona('[공격]' 등)와 title('[방어] 분석 — …')로 해석한다.
    resolve_persona 의 alias 부분일치를 그대로 재사용(공격/방어/분석 등)."""
    author = entry.get("author") or {}
    src = f"{author.get('persona', '')} {entry.get('title', '')}"
    return resolve_persona(src).key


def _peer_reference(bb, ctx, own_key: str) -> tuple[str, list[dict]]:  # noqa: ANN001
    """같은 CVE 의 '다른 페르소나' 기존 분석을 가드가 붙은 참고 블록으로 만든다.

    반환: (프롬프트에 끼울 참고 블록, 실제 사용한 참고 엔트리 목록). 아래 경우 모두 ("", []) 로
    그레이스풀하게 독립 분석이 되게 한다:
      - kestrel 미주입(스켈레톤/테스트) 또는 cve_id 없음,
      - 조회 실패(네트워크/API 오류 — 예외를 여기서 흡수해 봇이 멈추지 않게),
      - 같은 CVE 의 다른 페르소나 분석이 없음(초기엔 대부분 이 경우).
    맹신·획일화·비대화 방지 지침은 블록 안에 명시하고, 참고 수는 _PEER_MAX,
    인용 길이는 _PEER_EXCERPT_CHARS 로 제한한다.
    """
    kestrel = getattr(ctx, "kestrel", None) if ctx is not None else None
    cve_id = getattr(bb, "cve_id", None)
    # 대조군(peer_reference=False)은 조회 자체를 하지 않는다 — '플랫폼 협업 없음' arm.
    if ctx is not None and not getattr(ctx, "peer_reference", True):
        return "", []
    if kestrel is None or not cve_id:
        return "", []
    try:
        rows = kestrel.analyses_for_cve(cve_id, scan=_PEER_SCAN)
    except Exception:  # noqa: BLE001 — 참고 조회 실패는 독립 분석으로 흡수(그레이스풀)
        return "", []
    # 개정 트리거는 '원판 작성 시점 대비 늘어난 수'로 판정하므로, 프롬프트에 **쓴** 수가 아니라
    # 그 시점에 **존재하던 총수**가 기준선이어야 한다(쓴 수는 _PEER_MAX 로 잘린다).
    bb.report.meta["peer_total"] = len(rows or [])

    # 자기 페르소나 제외 + 인용할 내용(excerpt) 있는 것만, 페르소나 다양성 우선으로 소수 선택.
    picked: list[dict] = []
    seen: set[str] = set()
    for a in rows or []:
        if not isinstance(a, dict):
            continue
        pk = _peer_key(a)
        if pk == own_key or pk in seen:
            continue
        if not (a.get("excerpt") or "").strip():
            continue
        seen.add(pk)
        picked.append(a)
        if len(picked) >= _PEER_MAX:
            break
    if not picked:
        return "", []

    blocks = []
    for i, a in enumerate(picked, 1):
        pk = _peer_key(a)
        exc = " ".join((a.get("excerpt") or "").split())[:_PEER_EXCERPT_CHARS]
        tags = []
        if a.get("priorityAction"):
            tags.append(f"우선순위={a['priorityAction']}")
        if a.get("exploitabilityGrade"):
            tags.append(f"악용등급={a['exploitabilityGrade']}")
        if a.get("cveSeverity"):
            tags.append(f"심각도={a['cveSeverity']}")
        head = f"[참고 {i} · 페르소나={pk}" + (f" · {', '.join(tags)}" if tags else "") + "]"
        blocks.append(f"{head}\n{exc}")

    block = (
        "\n[참고 — 다른 에이전트의 분석 (검증 대상이지 사실 아님)]\n"
        "(요지는 플랫폼이 요약본만 제공하므로 짧습니다. 아래 [동료 토론]이 있으면 그쪽이 "
        "더 구체적인 정보를 담고 있습니다.)\n"
        "아래는 같은 CVE 를 먼저 분석한 '다른 페르소나' 에이전트의 기존 분석 요지입니다. "
        "이는 다른 에이전트의 의견일 뿐 사실이 아니며 틀릴 수 있습니다. 위 [사실]과 대조해 "
        "스스로 검증하세요 — 참고의 수치·기법이 [사실]과 어긋나면 참고를 버리고 [사실]을 "
        "따르며, 참고가 틀렸다고 판단되면 본문에서 바로잡으세요. 참고를 그대로 인용·요약·"
        "복붙하지 말고 당신 분석의 재료로만 쓰세요. 목적은 다른 관점을 '인지'하고 당신 "
        "페르소나 고유 관점을 심화·차별화하는 것입니다: 겹치는 서술은 반복하지 말고, 참고가 "
        "짚은 지점에 당신 관점의 대응(예: 방어자라면 그 공격 경로를 겨냥한 구체적 탐지·완화)을 "
        "더하세요.\n"
        + "\n".join(blocks)
        + "\n[참고 끝 — 위는 검증 전 참고이며 확정 서술의 근거로 삼지 마세요]\n"
    )
    return block, picked


_COMMENT_MAX = 6          # 프롬프트에 넣을 동료 댓글 최대 수
_COMMENT_CHARS = 500      # 댓글 1건당 인용 상한(전문이 와도 프롬프트가 비대해지지 않게)


def _comment_reference(bb, ctx) -> tuple[str, list[str]]:  # noqa: ANN001
    """같은 CVE 에 달린 동료 댓글(전문)을 참고 블록으로 만든다.

    왜 분석 요지가 아니라 댓글인가: 플랫폼의 분석 목록 API 는 `excerpt` 280자만 주고 본문을
    주지 않아, '협업'으로 실제 전달되는 정보량이 사실상 요약 한 줄뿐이었다(실측: 협업 효과
    전 지표 p>0.35 — 채널이 비어 있었다). 반면 댓글은 전문이 오고, 에이전트들이 서로의
    판단을 반박·보강하는 실질 내용이 담긴다. 현재 유일하게 정보량이 있는 협업 채널이다.

    대조군(peer_reference=False)은 여기서도 조회하지 않는다 — arm 정의를 유지한다.
    """
    kestrel = getattr(ctx, "kestrel", None) if ctx is not None else None
    cve_id = getattr(bb, "cve_id", None)
    if ctx is not None and not getattr(ctx, "peer_reference", True):
        return "", []
    if kestrel is None or not cve_id:
        return "", []
    try:
        rows = kestrel.community_comments(cve_id)
    except Exception:  # noqa: BLE001 — 조회 실패는 독립 분석으로 흡수
        return "", []
    bb.report.meta["comment_total"] = len(rows or [])  # 개정 트리거 판정의 기준선

    texts, blocks = [], []
    for c in (rows or [])[:_COMMENT_MAX]:
        if not isinstance(c, dict):
            continue
        body = " ".join(str(c.get("content") or "").split())[:_COMMENT_CHARS]
        if len(body) < 20:
            continue
        texts.append(body)
        blocks.append(f"[{c.get('authorName') or '동료'}] {body}")
    if not blocks:
        return "", []

    block = (
        "\n[동료 토론 — 이 CVE 에 달린 다른 에이전트의 의견 (검증 대상이지 사실 아님)]\n"
        "동료들이 이 취약점을 두고 실제로 주고받은 지적입니다. 반박·이견이 섞여 있으며 "
        "틀린 주장도 있을 수 있습니다. [사실]과 대조해 스스로 판단하되, **당신이 놓쳤거나 "
        "과소평가한 지점이 지적됐다면 본문에 반영하고**, 동의하지 않으면 왜 동의하지 않는지 "
        "당신 관점으로 반박하세요. 그대로 인용하지 말고 재료로만 쓰세요.\n"
        + "\n".join(blocks)
        + "\n[동료 토론 끝]\n"
    )
    return block, texts


def _revision_block(ctx) -> str:  # noqa: ANN001
    """개정 실행일 때 '이전 판'을 프롬프트에 싣고 개정 지침을 준다.

    핵심 지침은 '길게 늘리지 말 것'이다. 분량을 늘리라고 하면 모델은 새 정보가 없어도
    문장을 부풀려 분량 지표만 올린다 — 그러면 개정 효과 측정이 통째로 무효가 된다.
    """
    prior = (getattr(ctx, "prior_body", "") or "").strip()
    if not prior:
        return ""
    idx = getattr(ctx, "revision_index", 0) or 1
    return (
        f"\n[개정 대상 — 당신이 이전에 쓴 분석 (제{idx}차 개정)]\n"
        "아래는 **당신 자신이 앞서 작성한** 같은 CVE 분석입니다. 이번에는 새로 쓰는 것이 "
        "아니라 이것을 개정합니다. 그동안 올라온 위 [참고]·[동료 토론]의 새 정보를 반영해 "
        "다음을 하세요:\n"
        "  1) 틀렸거나 근거가 약했던 판단을 바로잡는다(무엇을 왜 바꿨는지 본문에 드러낸다).\n"
        "  2) 동료가 짚었는데 내가 빠뜨린 지점을 채운다.\n"
        "  3) 새 정보가 없는 부분은 **그대로 두거나 오히려 줄인다** — 분량을 늘리는 것이 "
        "목적이 아니다. 새로 넣을 근거가 없으면 늘리지 마세요.\n"
        f"{prior[:6000]}\n"
        "[개정 대상 끝]\n"
    )


# 섹션별 지침 — (헤더, 깊게 쓸 때, 짧게 쓸 때).
# 페르소나의 focus 섹션에만 상세 지침을 주고 나머지는 축약본을 준다. 전원에게 같은 번호
# 스캐폴드를 주면 모델이 그대로 복창해 세 리포트가 구조까지 같아지기 때문이다.
_SECTION_SPECS: tuple[tuple[str, str, str, str], ...] = (
    ("attack", "## 공격 기법",
     "트리거 조건(어떤 입력/요청이 어떤 결함을 건드리는지), 정찰→초기접근→실행·권한 획득→"
     "지속→영향의 단계와 각 단계의 전제조건·관측 지표, 공격 표면(노출 엔드포인트·파라미터·"
     "프로토콜), CVSS 벡터(AV/AC/PR/UI)를 실제 공격 조건에 연결. 원리와 축약된 개념 예시까지만, "
     "복사-실행 가능한 완전한 코드·무기화된 전체 페이로드는 금지",
     "이 취약점이 어떻게 촉발되고 어디까지 이어지는지 핵심만. 복사-실행 가능한 코드는 금지"),
    ("impact", "## 영향 분석",
     "악용 성공 시의 결과만. 기술적 위험은 이 CVE 에 실제로 해당하는 것만(데이터 유출·시스템 "
     "장악·서비스 중단·횡적 이동 등), 그리고 비즈니스 영향(가용성·규제/컴플라이언스·신뢰). "
     "영향 제품·노출 규모를 근거로 삼되 과장 금지, 해당 없는 위험은 적지 말 것",
     "악용 성공 시 실제로 무엇이 위험해지는지 핵심만. 해당 없는 위험은 적지 말 것"),
    ("chaining", "## 관련 취약점·체이닝",
     "이 결함이 다른 결함과 어떻게 이어질 수 있는지를 '유형·패턴' 수준으로(예: 정보 노출 → "
     "권한 상승 → RCE). ★실제 CVE 번호는 확실하지 않으면 절대 쓰지 말 것(지어내면 안 됨). "
     "근거가 없으면 취약점 '유형'(CWE 계열)과 일반적 체이닝 패턴만 쓰고 '추정:' 을 붙일 것",
     "유형·패턴 수준의 연계 가능성만 짧게. ★실제 CVE 번호는 확실하지 않으면 절대 쓰지 말 것"),
    ("detection", "## 탐지",
     "로그 지표(어떤 로그의 어떤 필드에 어떤 패턴이 남는지), 탐지 규칙 1~3개(소스/필드/조건/"
     "임계값을 갖춘 SIEM 쿼리 형태 또는 정규식 포함 탐지 의사코드), 오탐 시나리오와 튜닝 방법",
     "무엇을 어디서 보면 잡히는지 핵심 지표만 짧게"),
    ("mitigation", "## 완화 방안",
     "계층별로. **즉시(긴급 차단)**: 지금 당장 할 임시 조치(설정 변경·ACL·기능 비활성화). "
     "**단기(완화)**: 패치 전까지 위험을 낮추는 조치. **근본(해결)**: 패치·수정 버전과 업그레이드 "
     "절차. 각 조치마다 구현 난이도·운영 영향(가용성·성능·마찰)·검증 방법을 한 마디씩",
     "즉시 조치와 근본 해결(패치)을 중심으로 짧게"),
)


def _sections_block(persona, body_lang: str) -> str:  # noqa: ANN001
    """페르소나 focus 에 따라 섹션별 지침 깊이를 다르게 조립한다."""
    out = []
    for key, header, deep, brief in _SECTION_SPECS:
        focused = key in getattr(persona, "focus", ())
        depth = "★핵심 섹션 — 가장 깊고 구체적으로. " if focused else "간략히. "
        out.append(f"{header}\n<{body_lang}. {depth}{deep if focused else brief}>")
    return "\n\n".join(out)


def _prompt(bb, persona, report_lang: str, peer_block: str = "") -> tuple[str, str]:  # noqa: ANN001
    body_lang = "영어" if str(report_lang).startswith("en") else "한국어"
    system = f"{persona.system} {_BASE_SYSTEM} 어조: {persona.tone}"
    user = (
        "아래 사실만 근거로 이 CVE 리포트를 실무 방어자가 대응할 수 있게 구체적으로 작성하세요.\n"
        "=== 사실 ===\n"
        f"{_facts(bb)}\n"
        "============\n\n"
        f"[관점] {persona.emphasis}\n\n"
        f"{peer_block}"
        "[파이프라인 근거 — 본문에 반드시 녹여 인용] 이 리포트는 단일 AI 요약이 아니라 "
        "다중 소스 교차검증 + 실측 EPSS 조회 + 규칙 기반 우선순위 결정을 거친 결과입니다. "
        "위 [교차검증]·[실측 악용예측]·[우선순위 결정] 신호를 본문에서 근거로 인용하세요:\n"
        "  · 교차검증: 소스 간 불일치가 있었으면 '보수적으로 높은 값을 채택했다'는 점을, 없었으면 "
        "'다중 소스에서 일관성이 확인됐다'는 점을 명시(단일 LLM은 소스 비교 자체가 불가).\n"
        "  · EPSS: 수치를 해석과 함께 인용하되 실측값이므로 소수점을 유지하고 반올림해 100%로 "
        "만들지 마세요(예: 'EPSS 0.99959는 이론적 심각도(CVSS)와 독립적으로 실제 악용 예측이 "
        "최고 수준임을 뜻함'). 왜 이 수치가 우선순위에 중요한지 설명.\n"
        "  · 우선순위: 결정 논리를 풀어 쓰세요(예: 'KEV 등재로 즉시 대응으로 상향'). 규칙 기반이라 "
        "설명 가능하다는 점이 차별점입니다.\n\n"
        "각 섹션은 구체적이되 간결하게(핵심을 불릿으로, 장황·중복 금지 — 길이가 아니라 깊이). "
        "확정할 수 없는 값은 지어내지 말고 '추정:' 을 붙이세요.\n"
        "★서술 방식: 아래 지침은 '무엇을 담을지'이지 '어떤 순서로 쓸지'가 아닙니다. 지침의 "
        "항목을 번호대로 옮겨 적지 말고, 당신 관점에서 중요한 것부터 당신의 구성으로 쓰세요. "
        "다른 관점의 분석가와 똑같이 시작하는 글이 되지 않게 하세요.\n"
        "정확히 아래 헤더·형식으로만 출력하세요(다른 머리말·코드펜스 금지):\n\n"
        "SUMMARY_EN: <취약점과 최우선 조치를 요약한 영어 한 문장. 당신 관점이 드러나게>\n\n"
        f"{_sections_block(persona, body_lang)}\n"
    )
    return system, user


def _section_of(head: str) -> str | None:
    """헤더 텍스트(소문자) → 섹션 키. 순서 중요(체이닝을 완화보다 먼저)."""
    if "공격" in head or "attack" in head:
        return "attack"
    if "영향" in head or "impact" in head:
        return "impact"
    if "체이닝" in head or "chain" in head or "연계" in head or "관련" in head:
        return "chaining"
    if "탐지" in head or "detect" in head:
        return "detection"
    if "완화" in head or "방어" in head or "mitig" in head:
        return "mitigation"
    return None


def _parse(text: str) -> dict[str, str]:
    """LLM 출력 → {summary_en, attack, impact, chaining, detection, mitigation}. 헤더 관대 매칭."""
    buckets: dict[str, list[str]] = {
        "attack": [], "impact": [], "chaining": [], "detection": [], "mitigation": []}
    summary_en = ""
    section = None
    for line in (text or "").splitlines():
        s = line.strip()
        upper = s.upper()
        if upper.startswith("SUMMARY_EN:") or upper.startswith("SUMMARY:"):
            summary_en = s.split(":", 1)[1].strip()
            section = "sum"
            continue
        if s.startswith("#"):
            section = _section_of(s.lstrip("# ").strip().lower())
            continue
        if section in buckets:
            buckets[section].append(line)
        elif section == "sum" and not summary_en and s:
            summary_en = s  # 요약이 다음 줄로 넘어간 경우
    out = {k: "\n".join(v).strip() for k, v in buckets.items()}
    out["summary_en"] = summary_en.strip()
    return out


def _model_name(client) -> str:
    return (getattr(client, "model", None) or getattr(client, "_model", None) or "unknown")


@register(order=70)
def report(bb, ctx) -> None:  # noqa: ANN001
    client = getattr(ctx, "llm", None) if ctx is not None else None
    if client is None:
        return  # LLM 미주입 — 통과(부분 파이프라인)

    persona = resolve_persona(bb.persona)
    report_lang = getattr(ctx, "report_lang", "ko") or "ko"
    model = getattr(ctx, "model", None) or None  # 지정 분석 모델(없으면 클라이언트 기본)
    used_model = model or _model_name(client)
    # 단계2: 같은 CVE 의 다른 페르소나 분석을 (있으면) 가드와 함께 참고로 주입.
    # 실패·없음이면 빈 문자열 → 기존과 동일한 독립 분석(그레이스풀).
    peer_block, picked = _peer_reference(bb, ctx, persona.key)
    peer_used = len(picked)
    # 동료 댓글(전문) — 분석 excerpt(280자)보다 정보량이 큰 유일한 협업 채널.
    comment_block, comment_texts = _comment_reference(bb, ctx)
    # 개정 실행이면 이전 판을 함께 싣는다(신규 분석이면 빈 문자열).
    revision_block = _revision_block(ctx)
    # 실험 계측용 보존 — 협업(peer) 노출량과 그 원문은 플랫폼 이점 분석의 독립변수다.
    bb.report.peer_personas = [_peer_key(a) for a in picked]
    bb.report.peer_excerpts = [(a.get("excerpt") or "") for a in picked]
    bb.report.peer_comments = comment_texts
    bb.report.facts = _facts(bb)
    system, user = _prompt(bb, persona, report_lang,
                           peer_block + comment_block + revision_block)

    started = time.time()
    try:
        raw = client.complete(system, user, max_tokens=_MAX_TOKENS, effort="medium", model=model)
    except Exception as e:  # noqa: BLE001 — llm.LLMError 포함. 로컬 실패는 재시도 대상.
        # 참고 조회에서 채워둔 총수(peer_total/comment_total)를 잃지 않도록 병합한다.
        bb.report.meta = {**bb.report.meta,
                          "model": used_model, "persona": persona.key,
                          "elapsed_sec": round(time.time() - started, 2),
                          "peer_ref_used": peer_used, "error": str(e)}
        bb.needs_retry = True
        return

    p = _parse(raw)
    core_empty = not (p["attack"] or p["detection"] or p["mitigation"])
    if core_empty:
        # 형식 붕괴 시 1회 더 강하게 요청(핵심 3섹션 헤더를 명시)
        strict = user + "\n\n[재요청] 반드시 'SUMMARY_EN:' 줄과 '## 공격 기법', '## 탐지', " \
                        "'## 완화 방안' 헤더를 그대로 쓰세요."
        try:
            raw2 = client.complete(system, strict, max_tokens=_MAX_TOKENS, effort="medium",
                                   model=model)
            p2 = _parse(raw2)
            p2["summary_en"] = p["summary_en"] or p2["summary_en"]
            p, raw = p2, raw2
            core_empty = not (p["attack"] or p["detection"] or p["mitigation"])
        except Exception:  # noqa: BLE001 — 재시도 실패는 아래 폴백으로
            pass
    if core_empty:
        p["attack"] = (raw or "").strip()  # 최후 폴백: 원문을 공격 서술에 담고 표식

    bb.report.summary_en = p["summary_en"]
    bb.report.attack = p["attack"]
    bb.report.impact = p["impact"]
    bb.report.chaining = p["chaining"]
    bb.report.detection = p["detection"]
    bb.report.mitigation = p["mitigation"]
    bb.report.lang = ("en" if str(report_lang).startswith("en") else "ko") + \
                     ("+en" if p["summary_en"] else "")
    bb.report.meta = {
        **bb.report.meta,          # peer_total/comment_total 보존
        "model": used_model,
        "persona": persona.key,
        "elapsed_sec": round(time.time() - started, 2),
        "peer_ref_used": peer_used,
        "comment_ref_used": len(comment_texts),
        "revision_index": getattr(ctx, "revision_index", 0) if ctx is not None else 0,
        "unparsed": not p["mitigation"] and not p["summary_en"],
    }
