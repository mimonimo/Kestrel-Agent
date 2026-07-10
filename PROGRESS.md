# PROGRESS

## 2026-07-10 — 파이프라인 LLM(로컬 Ollama) 제약 발견 및 모델 확정

DGX 로컬 Ollama 로 계층2 파이프라인 Report 품질을 검증하는 과정에서 로컬
thinking 모델과 파이프라인 LLM 배선에 관한 제약 3건을 발견하고 수정했다.

### 발견

1. **thinking 모델은 `response` 를 비운다 (핵심).**
   qwen3:32b·gemma4:31b 등 Ollama 의 thinking 계열 모델은 사고과정이 켜져 있으면
   `num_predict` 예산을 사고 토큰이 소진하고 `/api/generate` 의 `response` 가 빈
   문자열로 온다(`done_reason=length`). 배포된 `OllamaClient` 는 `response` 만 읽으므로
   리포트가 통째로 빈다(7.8B 소형 모델의 "지시 무시" 와는 다른 원인). **로컬에 pull 된
   ~30B 급은 전부 thinking 이었다**(qwen3:32b, gemma4:31b, kanana-instruct, qwen3.5-coder).
   비-thinking 은 gemma3:12b(소형)·llama3.3:70b(대형)뿐.
   → 대응: `OllamaClient` 에 `OLLAMA_THINK`(기본 false) 추가. false 면 요청에 `think:false`
     를 실어 답변이 `response` 로 바로 오게 한다. 비-thinking 모델은 이 값을 무시(하위 호환).
     이로써 thinking 모델(gemma4:31b 등)도 모델명 교체만으로 파이프라인에서 사용 가능.

2. **파이프라인 LLM 노드가 지정 분석 모델을 안 썼다.**
   report·exploitability 노드가 `client.complete()` 를 `model=` 없이 호출해 항상 base
   `OLLAMA_MODEL` 만 썼다. `AGENT_ANALYSIS_MODEL` 설정이 파이프라인엔 무효였다.
   → 대응: `PipelineContext.model` 추가. 두 노드가 `model=ctx.model` 로 호출.
     `agent.py` 가 `ctx.model = cfg.analysis_model` 로 배선 →
     **`AGENT_ANALYSIS_MODEL` 이 파이프라인 리포트 모델을 결정**(없으면 `OLLAMA_MODEL` 폴백).
     `report.meta["model"]` 도 실제 사용 모델을 기록하도록 수정. `.env.example` 문서화.

3. **exploitability 서술이 400 토큰에서 잘렸다.** → `_NARRATIVE_MAX_TOKENS` 700 으로
   상향(Report 본문 1200 과 균형). 검증에서 1295자 서술이 잘리지 않고 완결 확인.

### 모델 확정
- **gemma4:31b** (계층2 파이프라인 분석 모델). `OLLAMA_THINK=false`(기본)로 사용.
- EXAONE-4.5-33B GGUF 는 CLIP projector blob 손상(`wrong number of tensors`)으로 Ollama
  로드 실패 → 배제. 업스트림 패키징 문제일 수 있어 재-pull 은 별도 처리(미해결).
- qwen3:32b 도 동작하나 gemma4:31b 로 확정.

### 검증 결과 (CVE-2021-44228, 실게시 없음, gemma4:31b via 배포 OllamaClient)
- summary_en: offensive/defensive 모두 채워짐(영어 한 줄, 정확). 7.8B 에선 비었던 항목.
- 리포트 품질: 실무급. formatMsgNoLookups, LDAP/RMI 포트(389/636/1099), WAF 정규식,
  EDR 자식프로세스(java→sh/cmd) 탐지 등 정확·구체. 환각 없음.
- offensive vs defensive: 뚜렷이 다름(공격=PoC·체이닝·피벗 / 방어=탐지 시그니처·임시차단·오탐마찰).
- 구조화 필드: kev=True, confidence=1.0, epss=0.99999/pct=1.0(라이브 FIRST.org),
  grade=easy, priority=immediate. 7노드 전부 ok.
- model 배선 확인: base 를 센티넬로 두고 ctx.model=gemma4:31b → meta.model=gemma4:31b, err=None.
- 소요 시간: report 호출 ~34s 로 일관. 전체 wall 은 offensive 65.9s / defensive 315.6s.
  **defensive 의 315s 는 exploitability 서술 호출이 ~280s 로 튄 이상치** — 공유 DGX GPU
  경합/모델 리로드로 추정(정상 GPU 속도면 서술 700토큰 ≈ 20~35s). 운영 시 전용 GPU/큐잉
  없으면 지연 편차가 큼. 명목상 CVE·페르소나당 1~1.5분, 경합 시 수 분까지 스파이크.

### 변경 파일
config.py, llm.py, agent.py, pipeline/state.py, pipeline/agents/report.py,
pipeline/agents/exploitability.py, .env.example (+43/-8). 기존 테스트 63건 통과.

### 남은 일
- EXAONE-4.5-33B blob 복구(재-pull 또는 텍스트 전용 quant) 후 재검증(선택).
- 소요 시간 재측정: 유휴 GPU 에서 서술 호출 지연 편차 확인(운영 부담 확정).
