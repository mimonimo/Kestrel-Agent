"""Blackboard — 파이프라인 공유 상태 모델(dataclass).

7개 에이전트가 순차로 읽고 쓰는 단일 상태 객체. 각 에이전트는 자기 구획만 채우고
나머지는 통과시킨다. 하위 result 들은 스텁 단계에서 기본값(빈/None)으로 시작하며,
다음 단계들에서 실제 값으로 채워진다.

PipelineContext 는 에이전트들이 공유하는 외부 자원(설정·kestrel 클라이언트·리포트용
LLM·사용자 자산 CPE 목록)을 담는다. 기존 모듈에 대한 import 결합을 피하려고
타입은 느슨하게(object|None) 둔다 — 실제 주입은 계층 1과 연결하는 단계에서 한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    """Cross-Validation 결과 — 소스 간 불일치 탐지 + 보수적 채택 + 규칙 기반 신뢰도.

    confidence 는 결정론적으로 확실한 규칙(severity_score_band/vector_format/
    vector_score_match)만으로 산출한다. quality_flags 는 confidence·handoff 에 반영하지
    않는 참고용 데이터 품질 신호(예: products↔description 불일치 — 공급망 CVE 오탐 소지).
    """
    confidence: float = 0.0
    mismatches: list[dict] = field(default_factory=list)
    adopted_values: dict = field(default_factory=dict)
    quality_flags: list[dict] = field(default_factory=list)


@dataclass
class ExploitabilityResult:
    """Exploitability 결과 — 규칙(EPSS/KEV/CVSS벡터) + LLM(난이도 서술).

    grade·epss·reasoning 은 규칙(수치·결정론)이 채우고, narrative 는 로컬 LLM 의 서술이다.
    LLM 실패/미주입 시 narrative 만 비고 grade 는 유지된다.
    """
    grade: str | None = None          # easy | moderate | hard (규칙 산출)
    poc_available: bool | None = None  # Exploit-DB 연동 전에는 None(KEV 로 대체 판단)
    epss: float | None = None          # FIRST.org EPSS 확률(미확보 시 None)
    reasoning: str = ""               # 규칙 근거(결정론)
    narrative: str = ""               # LLM 서술(persona 렌즈). 실패/미주입 시 빈 문자열


@dataclass
class ContextResult:
    """Context 결과 — 사용자 자산 CPE 와 매칭해 실제 영향 자산·범위 판정."""
    affected_assets: list[str] = field(default_factory=list)
    in_scope: bool | None = None


@dataclass
class PriorityResult:
    """Prioritization 결과 — CVSS/EPSS/KEV/exploitability/자산 융합."""
    action: str | None = None      # 예: patch_now / patch_this_week / monitor
    timeline: str | None = None
    reasoning: str = ""


@dataclass
class ReportResult:
    """Report 결과 — 로컬 LLM 이 페르소나 렌즈로 쓴 공격·완화 서술.

    meta 에는 model(모델명)·elapsed_sec(소요시간)·persona·error(있으면) 를 담는다.
    """
    attack: str = ""
    mitigation: str = ""
    summary_en: str = ""            # 영어 요약 한 줄(논문·해외 공유용)
    lang: str = ""                  # 산출 언어 표기(예: ko+en)
    meta: dict = field(default_factory=dict)


@dataclass
class Blackboard:
    """파이프라인 한 번(=CVE 한 건) 동안 공유되는 전체 상태."""
    cve_id: str
    persona: str = ""

    source_records: list[dict] = field(default_factory=list)  # Collector: 다중소스 원본
    enriched: dict = field(default_factory=dict)              # Enrichment: 정규화 결과
    validation: ValidationResult = field(default_factory=ValidationResult)
    exploitability: ExploitabilityResult = field(default_factory=ExploitabilityResult)
    context: ContextResult = field(default_factory=ContextResult)
    priority: PriorityResult = field(default_factory=PriorityResult)
    report: ReportResult = field(default_factory=ReportResult)

    # 라우팅·감사
    handoff: str | None = None          # 에이전트가 되돌려 보내고 싶은 대상 이름
    handoff_count: int = 0              # 누적 회귀 횟수(한도 초과 시 사람 검토)
    needs_human_review: bool = False
    needs_retry: bool = False           # LLM 호출 실패 등 일시적 사유로 재시도가 필요함
    audit_log: list[dict] = field(default_factory=list)  # [{agent, status}]

    def primary_record(self) -> dict:
        """Collector 가 수집한 원본 중 대상 CVE 본체(kind='primary')의 data 를 돌려준다.

        아직 수집 전이거나 없으면 빈 dict — 호출부는 '검증할 데이터 없음'으로 처리한다.
        """
        for rec in self.source_records:
            if rec.get("kind") == "primary":
                return rec.get("data") or {}
        return {}


@dataclass
class PipelineContext:
    """에이전트 공유 외부 자원. 스텁 단계에서는 쓰이지 않으며 계층 1 연결 시 주입한다."""
    cfg: object | None = None       # config.Config
    kestrel: object | None = None   # kestrel_client.Kestrel
    brain: object | None = None     # brain.Brain (계층 1 연결용, Report 는 llm 을 직접 씀)
    llm: object | None = None       # llm.LLMClient (Report 노드가 그대로 재사용)
    assets: list[str] = field(default_factory=list)  # 사용자 자산 CPE 목록(Context 매칭용)
    data_dir: str | None = None     # 산출물(validation_events.jsonl 등) 기록 위치. None → repo 루트
    report_lang: str = "ko"         # Report 본문 언어(ko|en). 항상 영어 요약 한 줄은 함께 낸다
    epss_fetch: object | None = None  # callable(cveId)->{'epss','percentile'}|None. None→FIRST.org 기본 조회
