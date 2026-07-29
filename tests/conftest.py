"""테스트가 실제 운영 데이터 파일을 건드리지 않게 격리한다.

계측 파일(run_events.jsonl)은 논문 표본의 원자료라, 테스트가 저장소 루트에 가짜 레코드를
append 하면 분석 결과가 조용히 오염된다. 세션 시작 시 임시 디렉터리로 돌린다.
"""
from __future__ import annotations

import os
import tempfile

os.environ.setdefault("AGENT_EVENTS_DIR", tempfile.mkdtemp(prefix="kestrel-test-events-"))
