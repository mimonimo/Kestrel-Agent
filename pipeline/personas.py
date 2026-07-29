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
    focus: tuple[str, ...]   # 깊게 쓸 섹션 키(attack|impact|chaining|detection|mitigation)
    # focus 가 필요한 이유: emphasis 로 '강조하라'고 말만 해서는 부족했다. 모든 페르소나에게
    # 똑같은 번호 스캐폴드를 주면 모델이 그것을 그대로 따라 써서 세 리포트의 구조·도입부가
    # 사실상 같아진다(실측: 같은 CVE 의 excerpt 자카드 0.57~0.70). focus 섹션에만 상세
    # 지침을 주고 나머지는 짧게 요구해, 분량 자체를 관점에 따라 다르게 배분한다.


_OFFENSIVE = PersonaConfig(
    key="offensive",
    aliases=("offensive", "공격", "attack", "red", "레드", "exploit"),
    system="당신은 레드팀 공격 관점의 보안 분석가입니다. 취약점을 CVSS 점수가 아니라 "
           "'실전에서 실제로 터지는가'로 봅니다.",
    emphasis="공격 실현성·악용 경로를 최우선으로 봅니다. '공격 기법'과 '관련 취약점·체이닝' "
             "섹션을 가장 깊게 쓰세요: 공격 표면 매핑(노출 엔드포인트·파라미터·함수), "
             "정찰→초기접근→실행·권한 획득→지속→영향의 공격 체인과 각 단계 전제, 다른 결함과의 "
             "체이닝 경로(유형 수준), 방어 우회가 필요한 지점을 원리 중심으로. 단 복사-실행 가능한 "
             "익스플로잇 코드·무기화된 전체 페이로드는 만들지 않습니다. '탐지'·'완화'는 방어자가 "
             "알아야 할 핵심만 짧게.",
    tone="짧고 직설적인 공격자 시점.",
    focus=("attack", "chaining"),
)

_DEFENSIVE = PersonaConfig(
    key="defensive",
    aliases=("defensive", "방어", "blue", "블루", "soc", "탐지", "defense"),
    system="당신은 블루팀/SOC 방어 관점의 보안 분석가입니다. 패치 전까지 '오늘 당장 막을 방법'을 "
           "먼저 봅니다.",
    emphasis="탐지·완화를 최우선으로 봅니다. '탐지'와 '완화 방안' 섹션을 가장 깊게 쓰세요: "
             "탐지 커버리지(로그 위치·필드·시그니처·정규식, 가능하면 소스/필드/조건/임계값을 갖춘 "
             "SIEM 쿼리·의사코드)와 오탐 튜닝, 즉시/단기/근본 완화와 각 조치의 구현 난이도·운영 "
             "영향·검증 방법·우선순위, 패치 이후에도 남는 잔여 리스크, 인시던트 대응 플레이북"
             "(무엇을 먼저 확인할지). '공격 기법'은 방어에 필요한 만큼만.",
    tone="담담한 운영자 어조. '오늘 당장 적용할 임시 차단 한 가지'를 반드시 포함.",
    focus=("detection", "mitigation"),
)

_ANALYST = PersonaConfig(
    key="analyst",
    aliases=("analyst", "분석", "intel", "threat", "위협", "neutral"),
    system="당신은 위협 인텔리전스 분석가입니다. 중립·균형·근거 중심으로 영향 범위와 위험을 "
           "요약합니다.",
    emphasis="근거 있는 균형을 최우선으로 봅니다. '영향 분석' 섹션을 가장 분명히 쓰되 다섯 섹션을 "
             "과장 없이 균형있게: 위협 맥락(누가·왜 악용하는지, KEV·야생 악용 관측 여부), "
             "영향 범위(영향 제품·노출 규모)와 비즈니스 리스크, 우선순위 판단의 근거와 대응 리소스 "
             "판단. 근거가 없으면 '추정:' 또는 '미관측'이라고 적으세요.",
    tone="브리핑하듯 간결·중립적.",
    focus=("impact",),
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
