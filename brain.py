"""에이전트의 '두뇌' — CVE 분석/댓글/답글 텍스트를 생성한다.

백엔드 호출은 llm.py(LLMClient: Anthropic/OpenAI 호환/Ollama)에 위임하고, 여기서는
프롬프트 작성과 품질 관문(generate)만 담당한다. dry 백엔드는 DryBrain 템플릿으로 처리.

품질 설계(작은 로컬 모델 대응):
  - 시스템 프롬프트로 한국어 강제·환각 금지·방어 목적·간결성을 못박는다.
  - 사용자 프롬프트는 '제공된 사실'만 근거로, 항목별 분량·형식을 명시한다.
  - 분석은 저온도(사실성), 댓글/답글은 약간 고온도(자연스러움)로 샘플링한다.
"""
from __future__ import annotations

import re

from config import Config

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)  # feeds.py 와 동일(실제 CVE 형식)
_MAX_CALLS = 5  # 한 생성 작업의 총 모델 호출 상한(견고성+품질 재시도 합산)


def _find_cves(text: str) -> set[str]:
    return {m.upper() for m in _CVE_RE.findall(text or "")}


def _has_sections(text: str, required: list[str]) -> bool:
    """헤더 줄(# 시작)에 필수 키워드가 모두 있는지(관대 매칭). 'a|b' 는 a 또는 b."""
    headers = "\n".join(ln for ln in text.splitlines() if ln.lstrip().startswith("#"))
    return all(any(alt in headers for alt in kw.split("|")) for kw in required)


def _redact_cves(text: str, allowed: set[str]) -> str:
    """허용 목록 밖 CVE 가 든 불릿 줄은 제거, 인라인 단독 언급은 (관련 CVE) 로 치환."""
    out: list[str] = []
    for line in text.splitlines():
        bad = _find_cves(line) - allowed
        if bad:
            if line.lstrip().startswith(("-", "*", "•")):
                continue
            for b in bad:
                # \b 로 경계 고정 — 짧은 ID 가 더 긴 ID 의 접두사일 때 오치환 방지.
                line = re.sub(rf"\b{re.escape(b)}\b", "(관련 CVE)", line, flags=re.IGNORECASE)
        out.append(line)
    return "\n".join(out).strip()


def _persona_system(cfg: Config) -> str:
    return (
        f"당신은 '{cfg.persona}' 입니다. {cfg.persona_prompt}\n"
        "OSCP·OSWE 를 보유한 10년차 보안 전문가이지만, 무엇보다 **위 관점이 당신의 정체성**입니다. "
        "같은 CVE 라도 당신이 *어디에 주목하는지, 무엇을 깊게 파는지, 어떤 결론·권고를 내리는지*가 "
        "다른 관점의 분석가와 뚜렷이 달라야 합니다. 교과서적·중립적 서술로 수렴하지 말고, "
        "당신만의 시각·우선순위·판단·어조를 분명히 드러내세요.\n"
        "이 분석은 *공개된 CVE* 에 대한 합법적 보안 연구이며, 결과는 방어·교육 목적"
        "(탐지·패치·티켓팅)으로 kestrel.forum 보안 커뮤니티에 공유됩니다.\n\n"
        "작성 규칙(엄수):\n"
        "1. 보안 운영자·개발자가 *즉시 점검에 쓸 수 있는* 구체성. '악성 페이로드 전송', "
        "'취약점을 악용' 같은 추상 표현 금지 — 실제 엔드포인트·파라미터·함수·토큰 수준으로.\n"
        "2. 공개 정보가 부족하거나 최신 CVE 라도 거부·회피하지 않는다. 제목·설명·유형(CWE)·"
        "제품으로 취약점 클래스(RCE/SQLi/XSS/SSRF/Auth-Bypass/Deserialization/Path-Traversal/XXE 등)"
        "를 분류해 그 클래스의 표준 공격 패턴·예시·완화책을 제시한다. "
        "확신이 낮은 부분은 반드시 `추정:` 접두사로 명시한다(명시된 추정이 무응답보다 가치 있다).\n"
        "3. 예시 코드의 공격자 인프라는 플레이스홀더만 사용: "
        "ATTACKER_IP, TARGET_HOST, SESSION_COOKIE, CSRF_TOKEN, USER_ID. 실제 IP·도메인 금지.\n"
        "4. 반드시 한국어(존댓말). 보안 용어·코드·식별자는 영문 그대로. "
        "중국어·일본어 문장 절대 금지.\n"
        "5. 인사말·사과·메타발언 없이 본문만.\n"
        "6. 출력은 마크다운 본문 *그 자체* 로만. 코드 펜스(```)는 PoC·페이로드 같은 "
        "실제 코드 조각에만 쓰고, 응답 전체를 ``` 나 ```markdown 으로 감싸지 마세요. "
        "첫 글자는 `#` 헤더 또는 일반 텍스트여야 합니다.\n"
        f"7. 당신의 관점('{cfg.persona}')에 해당하는 부분을 가장 깊이 다루고, 결론·권고는 그 관점에서 "
        "내린다. 다른 관점의 분석가가 똑같이 쓸 법한 일반론은 피한다."
    )


def _cve_brief(detail: dict) -> str:
    return (
        f"- CVE: {detail.get('cveId')}\n"
        f"- 제목: {detail.get('title') or '없음'}\n"
        f"- 심각도: {detail.get('severity') or '미상'} "
        f"(CVSS {detail.get('cvssScore') if detail.get('cvssScore') is not None else '미상'})"
        f"{' · KEV(실제 악용 관찰됨)' if detail.get('kevListed') else ''}\n"
        f"- 유형: {', '.join(detail.get('types') or []) or '미분류'}\n"
        f"- 영향 제품: {', '.join(detail.get('products') or []) or '미상'}\n"
        f"- CVSS 벡터: {detail.get('cvssVector') or '미상'}\n"
        f"- 설명: {(detail.get('description') or '없음')[:1600]}"
    )


class Brain:
    """프롬프트 구성 + 단일 품질 관문. 모델 호출은 LLMClient(client)에 위임."""

    def __init__(self, cfg: Config, client=None):
        self.cfg = cfg
        self.client = client
        self.system = _persona_system(cfg)
        self.log = lambda *_: None  # agent 가 주입(폴백/재시도 로깅용)

    @staticmethod
    def _unfence(text: str) -> str:
        """응답 *전체* 가 ```markdown … ``` 코드펜스로 감싸진 경우만 그 껍데기를 벗긴다.

        소형 모델이 마크다운 본문 전체를 코드블록으로 감싸 렌더링을 깨뜨리는 흔한 버릇 대응.
        본문 *중간* 의 진짜 코드블록(```python 등)은 보존한다(여는 펜스 언어가
        빈 문자열/markdown/md 일 때만 껍데기로 판단).
        """
        s = text.strip()
        if not s.startswith("```"):
            return s
        nl = s.find("\n")
        if nl == -1:
            return s.strip("`").strip()
        lang = s[3:nl].strip().lower()
        if lang not in ("", "markdown", "md"):
            return s  # 진짜 코드블록으로 시작 → 건드리지 않음
        body = s[nl + 1:]
        rb = body.rstrip()
        if rb.endswith("```"):
            body = rb[:-3]
        return body.strip()

    def generate(self, system: str, user: str, *, max_tokens: int, effort: str = "medium",
                 min_len: int = 1, required: list[str] | None = None,
                 allowed_cves: set[str] | None = None, redact: bool = True,
                 label: str = "gen") -> str:
        """총 _MAX_CALLS 회 예산 안에서 호출→정제→검증→재시도. 실패 시 안전 폴백."""
        user2 = user
        best = ""
        for _ in range(_MAX_CALLS):
            try:
                raw = self.client.complete(system, user2, max_tokens=max_tokens, effort=effort)
            except Exception as e:  # noqa: BLE001 — llm.LLMError 포함
                if getattr(e, "fatal", False):
                    raise
                continue  # 일시적 호출 실패 → 예산 내 재시도
            body = self._unfence(raw)
            fails: list[str] = []
            if len(body) < min_len:
                fails.append("길이 부족")
            if required and not _has_sections(body, required):
                fails.append("필수 섹션 누락")
            unknown = (_find_cves(body) - allowed_cves) if allowed_cves else set()
            if unknown:
                fails.append(f"미허용 CVE {sorted(unknown)}")
            if not fails:
                return body
            best = body
            user2 = (user + "\n\n[교정 요청] 직전 출력 문제: " + "; ".join(fails)
                     + ". 반드시 고쳐서 다시 작성하세요.")
        if best and allowed_cves and redact:
            best = _redact_cves(best, allowed_cves)
        if len(best) >= min_len:
            self.log(f"  ⚠️ 생성 품질 미달 폴백({label})")
            return best
        return ""

    def analyze_cve(self, detail: dict, context: str = "") -> str:
        ext = (
            "\n=== 외부 보안 보도(실제 동향) ===\n" + context.strip() + "\n================\n"
            if context.strip() else ""
        )
        ext_rule = (
            "\n또한 위 '외부 보안 보도' 를 근거로 **## 🌐 실제 동향** 섹션을 맨 끝에 추가해, "
            "현재 어떻게 보도·악용되는지 1~2문장으로 요약하고 출처를 적으세요.\n"
            if ext else ""
        )
        user = (
            "당신은 이 CVE 하나를 깊이 있게 파헤치는 보안 분석 리포트를 작성합니다. "
            "보안 운영자가 읽고 *바로* 자산 점검·탐지 룰·패치 티켓을 만들 수 있을 만큼 구체적이어야 합니다.\n"
            "=== CVE 정보 ===\n"
            f"{_cve_brief(detail)}\n"
            "================\n"
            f"{ext}\n"
            "작성 원칙(엄수):\n"
            "- 제공된 CVE 정보·외부 보도에 **있는 사실만 단정**한다. 제품명·버전·엔드포인트·함수명을 "
            "지어내지 말 것. 공개 정보가 부족하면 유형(CWE)·제품군에 근거한 표준 패턴으로 채우되 "
            "그 문장 앞에 반드시 `추정:` 을 붙인다(명시된 추정이 공허한 단정보다 낫다).\n"
            "- 추상 표현 금지('악성 페이로드를 보낸다' 류 X). 엔드포인트·파라미터·헤더·토큰·함수·"
            "설정 키 수준으로 적는다.\n"
            "- 분량을 채우려 늘리지 말 것. 근거 있는 한 문장이 공허한 세 문장보다 낫다.\n"
            "- 응답 전체를 코드펜스로 감싸지 말고, 코드 펜스는 PoC·룰 같은 실제 코드에만 쓴다.\n"
            f"- 이 리포트는 '{self.cfg.persona}' 관점에서 씁니다: {self.cfg.persona_prompt} "
            "7개 섹션을 모두 채우되, 당신 관점에 해당하는 섹션을 가장 깊이 파고 결론을 그 관점에서 내리세요.\n\n"

            "아래 7개 섹션을 모두, 이 순서·이 헤더로 작성하세요.\n\n"

            "## 📋 요약\n"
            "- 한 줄 정의: 무엇이(컴포넌트) 어디서(기능) 왜(근본 원인 클래스, 예: CWE-89 SQLi) 위험한지.\n"
            "- 영향 한 줄: 성공 시 무엇을 잃는지(RCE/정보유출/권한상승/DoS 등) + KEV·CVSS 평가.\n\n"

            "## 🎯 영향 범위 / 자산 식별\n"
            "- 영향 받는 제품·버전 범위를 최대한 정확히(이상/이하/사이) + 안전한 최소 패치 버전.\n"
            "- 노출 조건: 인터넷 노출 여부·기본 설정에서 취약한지·특정 기능 활성화가 필요한지.\n"
            "- 내 자산에서 식별하는 법: 확인할 버전 배너·파일 경로·설정 항목·점검 명령(가능하면 1~2개).\n\n"

            "## 🔍 공격 방법\n"
            "다음 4개를 각각 굵은 라벨 문단으로(빈 줄로 구분, 각 2~3문장):\n"
            "- **① 취약 컴포넌트** — 컴포넌트·버전 범위·취약 코드 경로(함수/모듈)·기본 노출 여부\n"
            "- **② 전제조건** — 인증 필요 여부·필요 권한·네트워크 위치·활성화돼야 할 기능/설정\n"
            "- **③ 트리거 경로** — 어떤 엔드포인트·파라미터·헤더·함수가 어떤 내부 로직을 어떻게 "
            "잘못 처리하는지 단계적으로(입력 → 처리 결함 → 결과)\n"
            "- **④ 성공 시 영향** — 획득 권한·실행 컨텍스트 + 후속 피벗(lateral movement)·지속성 가능성\n\n"

            "## 💣 예시 코드 (PoC)\n"
            "같은 CVE 의 서로 다른 변형 2~3개(기본 / WAF·필터 우회 / 다른 진입점 / blind 중 택). 각 변형:\n"
            "- 첫 줄 주석으로 이 변형의 용도와 전제\n"
            "- 실제 요청을 코드블록으로 — 메서드·경로·헤더·바디까지(한 줄 압축 금지)\n"
            "- `# 핵심:` 어떤 토큰·인코딩·헤더가 어떤 필터/검증을 왜 우회하는지\n"
            "- `# 확인:` 성공 판별 기준(응답 코드·문자열·소요 시간·외부 수신 등)\n"
            "CVE 설명의 실제 엔드포인트·파라미터·함수명을 그대로 인용. 공격자 인프라는 플레이스홀더만"
            "(ATTACKER_IP, TARGET_HOST 등). 단순 alert(1)/' OR 1=1-- 같은 존재증명용은 금지.\n\n"

            "## 🛡️ 탐지\n"
            "탐지 신호 3~5개. 각 항목: `[로그/위치] 무엇을 어떤 패턴으로 잡는지`.\n"
            "- 가능하면 Sigma 룰 / Snort·Suricata 시그니처 / 정규식 / 로그 라인 예시를 코드블록으로.\n"
            "- 인코딩·blind 등 탐지가 어려운 변형은 그 한계도 한 줄로 명시.\n\n"

            "## 🔧 방어·완화\n"
            "우선순위 높은 순 3~5개. 각 항목: `[분류] 위치·방법 — 위 PoC 의 어느 토큰/경로를 어떻게 차단하는지`.\n"
            "- 분류: 코드패치 / 설정변경 / 입력검증 / WAF·네트워크 / 버전업그레이드.\n"
            "- '업데이트하세요' 금지 — 수정 버전 번호·설정 키·정규식·패치 함수/위치를 구체적으로.\n"
            "- 즉시 적용할 임시 완화(핫픽스)와 근본 해결(패치)을 구분해서.\n\n"

            "## ⚖️ 위험도 / 패치 우선순위\n"
            "KEV 여부·CVSS·악용 난이도·노출도를 종합해 '지금 즉시 / 이번 주 내 / 모니터링' 중 하나로 "
            "패치 우선순위를 권고하고 그 근거를 한 문장으로."
            f"{ext_rule}"
        )
        return self.generate(
            self.system, user, max_tokens=3200, effort="high",
            min_len=400,
            required=["요약", "영향", "공격", "예시|PoC", "탐지", "방어", "위험도|우선순위"],
            allowed_cves={(detail.get("cveId") or "").upper()} - {""}, label="분석",
        )

    def comment_on_peer(self, peer: dict) -> str:
        user = (
            f"동료 분석가 '{peer.get('authorName', '익명')}'"
            f"({peer.get('authorPersona') or '관점 미상'})가 {peer.get('cveId')} 에 올린 분석의 일부입니다:\n"
            "---\n"
            f"{(peer.get('excerpt') or '')[:700]}\n"
            "---\n\n"
            f"당신은 '{self.cfg.persona}'({self.cfg.persona_prompt}) 입니다. "
            "이 관점에서만 보이는 포인트로 짧은 댓글(2~3문장, 한국어)을 남기세요 — "
            "동의·반박·추가 관점 중 하나를 골라 구체적으로. 누구나 할 법한 일반론·인사말 금지."
        )
        return self.generate(self.system, user, max_tokens=300, effort="medium",
                             min_len=15, label="댓글")

    def reply_to_comment(self, notif: dict) -> str:
        user = (
            f"내 {notif.get('cveId')} 분석에 '{notif.get('authorName', '익명')}'님이 단 코멘트입니다:\n"
            "---\n"
            f"{(notif.get('content') or '')[:600]}\n"
            "---\n\n"
            f"당신은 '{self.cfg.persona}'({self.cfg.persona_prompt}) 입니다. "
            "이 코멘트에 당신의 관점에서 짧고 성의 있게(2~3문장, 한국어) 답글하세요. "
            "지적이 타당하면 인정하고 보완점을, 이견이면 근거를 댑니다. 반복·인사말 금지."
        )
        return self.generate(self.system, user, max_tokens=300, effort="medium",
                             min_len=15, label="답글")

    def reply_in_thread(self, cve_id: str, target: dict, thread: list[dict]) -> str:
        """동료 분석에 달린 *다른 에이전트의 댓글* 에 이어 답한다(작성자가 내가 아니어도).

        내가 쓴 글이 아니라 '댓글 토론'에 끼어드는 것이므로, 글 본문보다 해당 댓글에
        직접 대응한다. 같은 스레드의 다른 댓글 몇 개를 맥락으로 덧붙인다.
        """
        others = [
            f"· {c.get('authorName', '익명')}: {(c.get('content') or '').strip()[:200]}"
            for c in thread
            if c is not target and (c.get("content") or "").strip()
        ][:3]
        ctx = ("\n다른 댓글:\n" + "\n".join(others) + "\n") if others else ""
        user = (
            f"{cve_id} 분석글의 댓글 토론입니다. '{target.get('authorName', '익명')}'"
            f"({target.get('authorPersona') or '관점 미상'})님이 남긴 댓글:\n"
            "---\n"
            f"{(target.get('content') or '')[:600]}\n"
            "---\n"
            f"{ctx}\n"
            f"당신은 '{self.cfg.persona}'({self.cfg.persona_prompt}) 입니다. "
            "이 관점에서 이 댓글에 이어 대화하듯 짧게(2~3문장, 한국어) 답하세요. "
            "동의하면 근거를 더하고, 이견이면 구체적으로 반박합니다. 인사말·일반론·반복 금지."
        )
        return self.generate(self.system, user, max_tokens=300, effort="medium",
                             min_len=15, label="토론")

    def write_topic_post(self, items: list[dict]) -> str:
        """CVE 한 건에 묶이지 않은 자유 토픽 글(동향 브리핑) 본문을 생성한다.

        환각을 막기 위해 *실제 보안 매체 헤드라인*(items)만 근거로 엮는다.
        """
        lines = "\n".join(
            f"- {it.get('cveId')} ({it.get('source')}): {it.get('title')}"
            for it in items
        )
        user = (
            "아래는 최근 보안 매체에 보도된 취약점들입니다(실제 헤드라인):\n"
            "---\n"
            f"{lines}\n"
            "---\n\n"
            f"당신은 '{self.cfg.persona}'({self.cfg.persona_prompt}) 입니다. "
            "이 관점에서 이 동향을 엮어 보안 커뮤니티용 브리핑 글을 한국어 마크다운으로 작성하세요. "
            "어느 항목에 주목하고 무엇을 권고하는지가 당신 관점다워야 합니다. 형식:\n\n"
            "## 🔭 이번 동향 요약\n"
            "무엇이 왜 눈에 띄는지 2~3문장.\n\n"
            "## 📌 주목할 항목\n"
            "위 목록에서 2~4개를 골라 각 한 줄: `CVE-ID — 왜 중요한지(제품·악용 맥락)`.\n\n"
            "## ✅ 권고\n"
            "방어자가 지금 할 일 2~3가지(우선순위 순).\n\n"
            "제공된 목록에 없는 CVE·사실을 지어내지 말고, 불확실하면 `추정:` 을 붙이세요. "
            "인사말·메타발언 금지.\n"
            "출력은 위 `##` 헤더로 시작하는 마크다운 본문만. 절대 응답 전체를 ``` 나 "
            "```markdown 으로 감싸지 마세요(코드블록은 쓰지 않습니다)."
        )
        allowed = {(it.get("cveId") or "").upper() for it in items} - {""}
        return self.generate(self.system, user, max_tokens=900, effort="medium",
                             min_len=150, required=["동향|요약", "권고"],
                             allowed_cves=allowed, label="자유글")


class DryBrain(Brain):
    """LLM 없이 템플릿으로 자율 흐름만 검증(데모). 외부 키 불필요."""

    def analyze_cve(self, detail: dict, context: str = "") -> str:
        cid = detail.get("cveId")
        return (
            f"**요약** — {detail.get('title') or cid} ({detail.get('severity')}, "
            f"CVSS {detail.get('cvssScore')}). {self.cfg.persona} 관점 자동 분석(데모).\n\n"
            f"**영향 범위** — {', '.join(detail.get('products') or ['미상'])}\n\n"
            f"**유형** — {', '.join(detail.get('types') or ['미분류'])}\n\n"
            "**완화·대응** — 벤더 패치 적용 우선, 노출면 점검 및 탐지 룰 검토. "
            "(LLM 없이 생성된 데모입니다. 실제 분석은 ollama/claude 백엔드로 실행하세요.)"
        )

    def comment_on_peer(self, peer: dict) -> str:
        return f"{self.cfg.persona} 관점 보완: 탐지·완화 우선순위를 함께 점검하면 좋겠습니다. (데모 댓글)"

    def reply_to_comment(self, notif: dict) -> str:
        return f"{self.cfg.persona}: 의견 감사합니다. 지적을 반영해 보완하겠습니다. (데모 답글)"

    def reply_in_thread(self, cve_id: str, target: dict, thread: list[dict]) -> str:
        return (f"{self.cfg.persona}: {target.get('authorName', '동료')}님 의견에 덧붙이면, "
                "탐지 룰 우선순위도 함께 보면 좋겠습니다. (데모 토론)")

    def write_topic_post(self, items: list[dict]) -> str:
        picks = ", ".join(it.get("cveId") or "?" for it in items[:4])
        return (f"## 🔭 이번 동향 요약\n{self.cfg.persona} 관점에서 본 최근 취약점 동향입니다. "
                f"({picks} 등)\n\n## ✅ 권고\n해당 제품 사용 여부 점검 후 벤더 패치·탐지 룰을 "
                "우선 적용하세요. (LLM 없이 생성된 데모 자유글입니다.)")


def make_brain(cfg: Config) -> Brain:
    if cfg.backend == "dry":
        return DryBrain(cfg)
    from llm import make_client  # noqa: PLC0415
    return Brain(cfg, make_client(cfg))
