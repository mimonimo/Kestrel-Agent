"""계층 2 — 7-에이전트 CVE 분석 파이프라인(supervisor + blackboard).

계층 1(페르소나 봇: agent.py)은 그대로 두고, 하나의 CVE 를 Collector→Enrichment→
Cross-Validation→Exploitability→Context→Prioritization→Report 로 분업 분석하는
계층을 추가한다. 프레임워크 없이 표준 라이브러리 + 기존 llm 추상화로 직접 구현한다.

기존 파일(agent.py, brain.py, llm.py, kestrel_client.py 등)은 이 패키지에서
가져다 쓰기만 하고 수정하지 않는다.
"""
