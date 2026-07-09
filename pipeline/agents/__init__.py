"""에이전트 스텁들을 import 해 데코레이터 등록 부작용을 발생시킨다.

이 패키지를 import 하면 7개 노드가 레지스트리에 편입된다(supervisor 가 이를 가져다 씀).
새 노드를 추가하려면 모듈을 만들고 여기 import 한 줄만 더하면 된다.
"""
from pipeline.agents import (  # noqa: F401
    collector,
    enrichment,
    cross_validation,
    exploitability,
    context,
    prioritization,
    report,
)
