"""에이전트의 '두뇌' — CVE 분석/댓글/답글 텍스트를 생성한다.

백엔드(교체 가능):
  - OllamaBrain : 로컬 Ollama(무료·기본). exaone3.5(한국어 특화) 권장.
  - ClaudeBrain : Anthropic Claude(유료·최고 품질). adaptive thinking.
  - DryBrain    : LLM 없이 템플릿. 키 없이 자율 흐름 확인(데모/테스트).

품질 설계(작은 로컬 모델 대응):
  - 시스템 프롬프트로 한국어 강제·환각 금지·방어 목적·간결성을 못박는다.
  - 사용자 프롬프트는 '제공된 사실'만 근거로, 항목별 분량·형식을 명시한다.
  - 분석은 저온도(사실성), 댓글/답글은 약간 고온도(자연스러움)로 샘플링한다.
"""
from __future__ import annotations

import json
import threading
import urllib.request
from abc import ABC, abstractmethod

from config import Config

# 여러 에이전트(스레드)가 한 Ollama 서버를 공유할 때 생성을 직렬화한다.
# 모델이 병목이라 동시 실행은 자원을 쪼개 오히려 느리고 타임아웃을 유발한다.
# 한 번에 하나씩 풀스피드로 처리하는 편이 전체 처리량이 더 높다.
_OLLAMA_LOCK = threading.Lock()


def _persona_system(cfg: Config) -> str:
    return (
        "당신은 OSCP·OSWE 보유, 10년차 침투 테스터 겸 취약점 연구원입니다. "
        f"동시에 '{cfg.persona}' 관점을 갖습니다. {cfg.persona_prompt}\n"
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
        "첫 글자는 `#` 헤더 또는 일반 텍스트여야 합니다."
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


class Brain(ABC):
    """프롬프트 구성은 공통, 텍스트 생성(_complete)만 백엔드별로 구현."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.system = _persona_system(cfg)

    @abstractmethod
    def _complete(self, system: str, user: str, max_tokens: int = 1400,
                  temperature: float = 0.4) -> str: ...

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
            "다음 CVE 를 보안 운영자가 즉시 점검·티켓팅에 쓸 수 있는 수준으로 분석하세요.\n"
            "=== CVE 정보 ===\n"
            f"{_cve_brief(detail)}\n"
            "================\n"
            f"{ext}\n"
            "아래 구조의 마크다운으로 작성하세요(코드는 ``` 펜스 사용). 공개 정보가 부족하면 "
            "유형 기반 표준 패턴으로 채우되 그 부분에 `추정:` 을 붙입니다.\n\n"

            "## 📋 요약\n"
            "무엇이 왜 위험한지, 영향 받는 제품·버전 포함 2~3문장.\n\n"

            "## 🔍 공격 방법\n"
            "다음 4개를 각각 굵은 라벨 문단으로(빈 줄로 구분, 추상 표현 금지):\n"
            "- **① 취약 컴포넌트** — 컴포넌트·버전 범위·기본 설정 노출 여부\n"
            "- **② 전제조건** — 인증 필요 여부·네트워크 위치·활성화돼야 할 기능/설정\n"
            "- **③ 트리거 경로** — 엔드포인트·파라미터·헤더·함수가 어떤 내부 로직을 어떻게 잘못 처리하는지\n"
            "- **④ 성공 시 영향** — 획득 권한 + 후속 피벗(lateral movement) 가능성\n\n"

            "## 💣 예시 코드 (PoC)\n"
            "같은 CVE 의 서로 다른 변형 2~3개(기본 / WAF·필터 우회 / 다른 진입점 / blind 중 택). 각 변형 형식:\n"
            "- 첫 줄 주석으로 이 변형의 용도\n"
            "- 실제 페이로드·요청 본체를 코드블록으로(한 줄 압축 금지)\n"
            "- 중간에 `# 핵심:` 어떤 토큰·인코딩·헤더가 어떤 필터를 왜 우회하는지\n"
            "- 끝에 `# 확인:` 성공 판별 기준(외부 수신/응답 문자열/소요 시간 등)\n"
            "CVE 설명에 등장한 실제 엔드포인트·파라미터·함수명을 그대로 인용. "
            "플레이스홀더만(ATTACKER_IP 등). 단순 alert(1)/' OR 1=1-- 같은 존재증명 금지.\n\n"

            "## 🛡️ 탐지\n"
            "점검할 로그·이벤트·시그니처 2~4개. 가능하면 Sigma/Snort 룰·정규식·로그 패턴 형태로.\n\n"

            "## 🔧 방어·완화\n"
            "우선순위 높은 순 3~4개. 각 항목: `[분류] 위치·방법 — 위 PoC 의 어느 토큰을 어떻게 차단하는지`. "
            "분류는 코드패치/설정변경/입력검증/WAF·네트워크/버전업그레이드 중. "
            "단순 '업데이트하세요' 금지 — 수정 버전·설정 키·정규식·패치 위치를 구체적으로."
            f"{ext_rule}"
        )
        return self._unfence(self._complete(self.system, user, max_tokens=2400, temperature=0.35))

    def comment_on_peer(self, peer: dict) -> str:
        user = (
            f"동료 분석가 '{peer.get('authorName', '익명')}'"
            f"({peer.get('authorPersona') or '관점 미상'})가 {peer.get('cveId')} 에 올린 분석의 일부입니다:\n"
            "---\n"
            f"{(peer.get('excerpt') or '')[:700]}\n"
            "---\n\n"
            f"'{self.cfg.persona}' 관점에서 이 분석에 짧은 댓글(2~3문장, 한국어)을 남기세요. "
            "동의·반박·추가 관점 중 하나를 골라 구체적으로. 일반론·인사말 금지."
        )
        return self._unfence(self._complete(self.system, user, max_tokens=300, temperature=0.6))

    def reply_to_comment(self, notif: dict) -> str:
        user = (
            f"내 {notif.get('cveId')} 분석에 '{notif.get('authorName', '익명')}'님이 단 코멘트입니다:\n"
            "---\n"
            f"{(notif.get('content') or '')[:600]}\n"
            "---\n\n"
            "이 코멘트에 짧고 성의 있게(2~3문장, 한국어) 답글하세요. "
            "지적이 타당하면 인정하고 보완점을 적습니다. 반복·인사말 금지."
        )
        return self._unfence(self._complete(self.system, user, max_tokens=300, temperature=0.6))

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
            f"'{self.cfg.persona}' 관점에서 이 댓글에 이어 대화하듯 짧게(2~3문장, 한국어) 답하세요. "
            "동의하면 근거를 더하고, 이견이면 구체적으로 반박합니다. 인사말·일반론·반복 금지."
        )
        return self._unfence(self._complete(self.system, user, max_tokens=300, temperature=0.6))

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
            f"'{self.cfg.persona}' 관점에서 이 동향을 엮어 보안 커뮤니티용 브리핑 글을 "
            "한국어 마크다운으로 작성하세요. 형식:\n\n"
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
        return self._unfence(self._complete(self.system, user, max_tokens=900, temperature=0.5))


class OllamaBrain(Brain):
    """로컬 Ollama(무료). OLLAMA_HOST / OLLAMA_MODEL."""

    def _complete(self, system: str, user: str, max_tokens: int = 1400,
                  temperature: float = 0.4) -> str:
        payload = json.dumps({
            "model": self.cfg.ollama_model,
            "system": system,
            "prompt": user,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": 0.9,
                "repeat_penalty": 1.1,
                "num_ctx": 8192,         # 설명+프롬프트가 잘리지 않도록
                "num_predict": max_tokens,
            },
        }).encode()
        req = urllib.request.Request(
            f"{self.cfg.ollama_host.rstrip('/')}/api/generate",
            data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with _OLLAMA_LOCK:  # 에이전트 간 생성 직렬화(자원 경합·타임아웃 방지)
            with urllib.request.urlopen(req, timeout=600) as r:
                return (json.loads(r.read().decode()).get("response") or "").strip()


class ClaudeBrain(Brain):
    """Anthropic Claude. adaptive thinking + effort high (temperature 미사용)."""

    def __init__(self, cfg: Config):
        super().__init__(cfg)
        try:
            import anthropic  # noqa: PLC0415
        except ImportError as e:
            raise SystemExit(
                "anthropic 패키지가 없습니다. `pip install -r requirements.txt` 를 실행하세요."
            ) from e
        self._client = anthropic.Anthropic(api_key=cfg.anthropic_api_key)

    def _complete(self, system: str, user: str, max_tokens: int = 1400,
                  temperature: float = 0.4) -> str:
        # Opus 4.x 는 temperature 미지원 — adaptive thinking 으로 대체.
        resp = self._client.messages.create(
            model=self.cfg.anthropic_model,
            max_tokens=max(max_tokens, 1024),
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in resp.content if b.type == "text").strip()


class DryBrain(Brain):
    """LLM 없이 템플릿으로 자율 흐름만 검증(데모). 외부 키 불필요."""

    def _complete(self, system: str, user: str, max_tokens: int = 1400,
                  temperature: float = 0.4) -> str:  # pragma: no cover
        return ""

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
    return {"ollama": OllamaBrain, "claude": ClaudeBrain, "dry": DryBrain}[cfg.backend](cfg)
