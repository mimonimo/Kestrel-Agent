"""페르소나 렌즈 — 하나의 파이프라인에 '관점'을 주입한다(7개 에이전트를 복제하지 않는다).

판단 노드(현재는 Report, 이후 Exploitability/Prioritization)가 blackboard.persona 를 읽어
해당 PersonaConfig 의 system 조각·강조점·톤을 프롬프트에 주입한다.

새 페르소나 추가 = _PERSONAS 에 PersonaConfig 하나 추가(+alias)면 끝(pluggable).
blackboard.persona 는 계층 1 봇의 한국어 이름(예: '공격Agent')일 수도, 영문 key 일 수도
있으므로 alias 부분일치로 해석한다. 매칭 실패 시 중립(analyst)으로 폴백한다.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PersonaConfig:
    key: str                 # offensive | defensive | analyst
    aliases: tuple[str, ...]  # blackboard.persona 문자열 해석용(부분일치, 소문자)
    system: str              # system 프롬프트에 덧붙일 관점 선언
    emphasis: str            # user 프롬프트에 넣을 '무엇을 강조하라'
    tone: str                # 어조 지시


_OFFENSIVE = PersonaConfig(
    key="offensive",
    aliases=("offensive", "공격", "attack", "red", "레드", "exploit"),
    system="당신은 레드팀 공격 관점의 보안 분석가입니다. 취약점을 CVSS 점수가 아니라 "
           "'실전에서 실제로 터지는가'로 봅니다.",
    emphasis="공격 실현성과 악용 경로를 최우선으로 봅니다. '공격 기법' 섹션을 가장 깊고 "
             "구체적으로 쓰세요: 전제조건(인증·노출)의 현실성, 트리거되는 엔드포인트·파라미터·"
             "함수, 정찰→트리거→실행·권한 획득→후속 피벗의 공격 단계와 각 단계 전제, 다른 "
             "취약점과의 체이닝 가능성. 단 원리·개념 수준까지만 — 복사-실행 가능한 익스플로잇 "
             "코드는 만들지 않습니다. '탐지'·'완화'는 방어자가 알아야 할 핵심만 짧게.",
    tone="짧고 직설적인 공격자 시점.",
)

_DEFENSIVE = PersonaConfig(
    key="defensive",
    aliases=("defensive", "방어", "blue", "블루", "soc", "탐지", "defense"),
    system="당신은 블루팀/SOC 방어 관점의 보안 분석가입니다. 패치 전까지 '오늘 당장 막을 방법'을 "
           "먼저 봅니다.",
    emphasis="탐지와 완화를 최우선으로 봅니다. '탐지'·'완화' 섹션을 가장 깊고 구체적으로 쓰세요: "
             "구체적 탐지 신호(로그 위치·필드·시그니처·정규식, 가능하면 SIEM 쿼리/의사코드), "
             "즉시/단기/근본으로 나눈 완화와 각 조치의 운영 트레이드오프, 패치 우선순위, "
             "오탐·운영 마찰 최소화. '공격 기법'은 방어에 필요한 만큼만.",
    tone="담담한 운영자 어조. '오늘 당장 적용할 임시 차단 한 가지'를 반드시 포함.",
)

_ANALYST = PersonaConfig(
    key="analyst",
    aliases=("analyst", "분석", "intel", "threat", "위협", "neutral"),
    system="당신은 위협 인텔리전스 분석가입니다. 중립·균형·근거 중심으로 영향 범위와 위험을 "
           "요약합니다.",
    emphasis="근거 있는 균형을 최우선으로 봅니다. 세 섹션을 과장 없이 균형있게 쓰되, 영향 범위"
             "(영향 제품·노출 규모), 악용 관측 여부(KEV·야생 악용), 비즈니스 리스크와 대응 "
             "우선순위를 분명히 판단하세요. 근거가 없으면 '추정:' 또는 '미관측'이라고 적으세요.",
    tone="브리핑하듯 간결·중립적.",
)

_PERSONAS: dict[str, PersonaConfig] = {p.key: p for p in (_OFFENSIVE, _DEFENSIVE, _ANALYST)}
_DEFAULT = _ANALYST


def resolve_persona(name: str | None) -> PersonaConfig:
    """blackboard.persona 문자열 → PersonaConfig. 매칭 실패 시 analyst(중립)."""
    text = (name or "").strip().lower()
    if not text:
        return _DEFAULT
    for persona in _PERSONAS.values():
        if any(alias in text for alias in persona.aliases):
            return persona
    return _DEFAULT
