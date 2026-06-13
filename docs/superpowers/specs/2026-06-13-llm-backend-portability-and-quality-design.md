# LLM 백엔드 이식성 & 분석/활동 품질 개선 — 설계

- 날짜: 2026-06-13
- 대상: `agent/` (Kestrel 자율 CVE 분석 에이전트)
- 상태: 설계 합의 완료, 구현 계획 대기

## 1. 목표

1. **LLM 백엔드 이식성** — Claude/Ollama 외에 **OpenAI 호환 API**(OpenAI·Groq·OpenRouter·Together·로컬 vLLM/LM Studio 등)를 끼울 수 있게. 새 백엔드 추가 = 클라이언트 한 개 + 한 줄 등록.
2. **환각 방지** — 생성물의 CVE ID를 허용 목록과 대조해 검증/제거.
3. **출력 검증·재시도** — 구조(섹션)·길이 미달 시 재생성, 끝까지 실패하면 안전 폴백.
4. **활동 선택 개선** — 댓글/답글/토론/분석 대상을 점수 기반으로, 자기인용·에코·쏠림 방지.
5. **백엔드 견고성** — 타임아웃·재시도·에러 처리를 백엔드 간 일관되게.

비목표: 포럼/데이터(Kestrel) API 교체, 외부 LLM SDK(litellm 등) 도입, UI 변경.

## 2. 아키텍처 — 호출 계층 분리

`brain.py`가 "무슨 말을 할지(프롬프트)"와 "모델을 어떻게 호출할지(`_complete`)"를 섞고 있어, 백엔드를 늘리면 로직이 복제되고 품질 가드가 흩어진다. 호출 계층을 새 파일 `llm.py`로 분리한다.

### 새 파일 `llm.py` — 모델 호출만
```
LLMError(RuntimeError)              # 백엔드 무관 단일 예외
LLMClient (ABC)
  complete(system, user, *, max_tokens, effort) -> str
    · 베이스: 타임아웃·재시도(지수 백오프)·예외 분류 통일
    · 추상 _call(...) 만 백엔드별 구현
  ├ AnthropicClient   # thinking={"type":"adaptive"}, output_config effort
  ├ OpenAIClient      # base_url + api_key + model (OpenAI 호환 전부)
  └ OllamaClient      # /api/generate, _OLLAMA_LOCK 직렬화 여기로 이동
make_client(cfg) -> LLMClient   # dry 백엔드는 호출되지 않음(make_brain이 DryBrain으로 단락)
```
- 공통 시그니처의 `effort`("high"|"medium")를 각 클라이언트가 자기 방식으로 매핑:
  - **Anthropic**: `output_config={"effort": ...}` 그대로 사용(temperature 미지원).
  - **OpenAI/Ollama**: effort→temperature로 환산(`high→0.3`, `medium→0.6`). 즉 사실성 필요한 분석은 저온도, 댓글/토론은 약간 고온도 — 기존 brain.py의 온도 의도를 보존.
- 백엔드별 특수 파라미터는 클라이언트 내부에 격리. `DryClient`는 두지 않는다(`make_brain`이 dry를 `DryBrain`으로 처리하므로 불필요).

### `brain.py` — 프롬프트 빌더 + 품질 관문
```
Brain (concrete)               # LLMClient 주입
  generate(...)                # ★ 단일 품질 관문 (섹션 4)
  analyze_cve / comment_on_peer / reply_to_comment
    / reply_in_thread / write_topic_post   # 프롬프트 작성 후 generate() 호출
DryBrain (Brain)               # 5개 public 메서드를 템플릿으로 override (클라이언트 미사용)
make_brain(cfg) -> Brain       # dry→DryBrain, else Brain(make_client(cfg))
```
- 호출부 공개 인터페이스(`make_brain(cfg)`, `brain.analyze_cve(...)` 등) 불변. `agent.py`는 활동 선택 개선(섹션 5) 외에는 거의 변경 없음.

### 의존 방향
`agent.py → brain.py → llm.py`, `brain.py → config.py`, `llm.py → config.py`. 순환 없음.

## 3. 견고성 (`LLMClient`)

```python
def complete(self, system, user, *, max_tokens, effort):
    for attempt in range(self.retries + 1):       # 기본 retries=2
        try:
            return self._call(...)
        except _Transient:                         # 타임아웃/URLError/5xx/429/빈응답
            if attempt == self.retries: raise LLMError(...)
            sleep(backoff * 2**attempt + jitter)
        except _Fatal:                             # 401/403/400(429 제외)
            raise LLMError(...)                     # 즉시 중단
```
- 예외 분류: **일시적**(타임아웃·네트워크·HTTP 5xx·429·빈/공백 응답) = 재시도 / **치명**(401·403·400) = 즉시 `LLMError`.
- 타임아웃: ollama 600s, API계열 120s. `AGENT_LLM_TIMEOUT`로 덮어쓰기.
- 빈 응답(소형 모델 빈출)은 일시적 실패로 간주해 재시도.
- `_OLLAMA_LOCK` 직렬화는 `OllamaClient`로 이동(현 동작 유지).

### 재시도 두 층의 결합 — 총 호출 상한
- `LLMClient.complete` 재시도 = **호출 실패** 복구(네트워크/빈응답).
- `Brain.generate` 재시도 = **내용 품질 미달** 교정(섹션 누락/환각 CVE).
- 두 층이 곱해져 호출이 폭증하지 않도록 **에이전트당 한 생성 작업의 총 모델 호출 5회 상한**을 둔다(단순·예측 가능). 상한 도달 시 마지막 결과로 폴백.

## 4. 품질 관문 `Brain.generate()`

모든 생성이 이 한 메서드를 통과한다.

```python
def generate(self, system, user, *, max_tokens, effort="medium",
             min_len=1, required=None, allowed_cves=None,
             redact=True, retries=2, label="gen") -> str:
    # 총 호출 5회 상한 내에서:
    #   raw  = client.complete(system, user2, max_tokens, effort)
    #   body = _unfence(raw)
    #   검증: len(body)>=min_len / (required 키워드 모두 존재) / (allowed_cves면 미허용 CVE 없음)
    #   통과 → 반환
    #   실패 → user2 += 교정지시(실패사유), 재시도
    # 전부 실패 → redact 후 best-effort 반환, 그래도 min_len 미달이면 "" 반환
```

### 가드
- **`_unfence(text)`** — 응답 *전체* 를 ` ```markdown … ``` `로 감싼 껍데기만 제거. 여는 펜스 언어가 빈값/`markdown`/`md`일 때만 껍데기로 판단(본문 중간 ` ```python ` 코드블록 보존). *이미 구현·테스트 완료.*
- **`_has_sections(text, required)`** — 정확 헤더가 아니라 **헤더 줄의 한국어 키워드**로 관대하게 판정(소형 모델 표기 흔들림 대응).
- **`_find_cves(text)`** — `CVE-\d{4}-\d{4,7}` 추출(대소문자 무시).
- **환각 CVE 처리** — `allowed_cves` 주어지면 `미허용 = _find_cves(body) - allowed_cves`. 비어있지 않으면 **재시도 우선**, 끝까지 실패 시 `redact=True`면 미허용 CVE가 든 **줄(불릿) 제거**, 인라인 단독 언급은 `(관련 CVE)`로 치환.

### 메서드별 적용값
| 메서드 | min_len | required(키워드) | allowed_cves | effort |
|---|---|---|---|---|
| `analyze_cve` | ~300 | 요약·공격·예시\|PoC·탐지·방어 | `{cve} ∪ related()` | high |
| `write_topic_post` | ~150 | 동향\|요약·권고 | 피드 항목 CVE 집합 | medium |
| `comment_on_peer` | ~15 | — | None(옵션) | medium |
| `reply_to_comment` | ~15 | — | None(옵션) | medium |
| `reply_in_thread` | ~15 | — | None(옵션) | medium |

재시도/redact는 발생 시에만 `agent.log`에 한 줄 남긴다.

## 5. 활동 선택 개선 (`agent.py`)

현재 5개 활동 모두 "조건 맞는 첫 번째"를 선택 → 다양성↓, 자기인용 에코, CVE 쏠림.

1. **`do_replies` — 자기인용 수정**: 알림 작성자가 나(`authorName`/`authorPersona`)면 건너뜀, 빈 내용 건너뜀, 미답 알림 중 **오래된 것부터** 처리.
2. **`do_comment` — 점수 기반**: eligible(내 글 아님 + 미댓글) 중 `score = 최신성 + 댓글적음 가산 + 심각도 가산` 최고 선택, 동점은 랜덤 타이브레이크.
3. **`do_thread_discussion` — 안티-에코**: 내 댓글·기답 댓글 제외(기존) + **같은 스레드에서 이미 답한 부모엔 중복 안 달기**, 동료 최신 미답 우선.
4. **`do_analysis` — 같은 CVE 다관점 + 중복 상한**:
   - `AGENT_MAX_PERSPECTIVES`(기본 3) 도입.
   - `community_analyses`로 CVE별 기존 분석 수 `counts[cveId]` 집계(헬퍼 `_analysis_counts(community)`).
   - 선택 조건: `cveId ∉ 내 analyzed_cves` AND `counts[cveId] < 상한`.
   - 후보 우선순위: **KEV > CVSS 내림차순 > 피드 등장순**. 피드·폴백(list_cves) 경로 **동일 규칙** 적용.
   - 효과: 공격/방어/분석가가 같은 CVE에 각각 붙되 상한을 넘으면 안 쌓임.

선택 로직은 `agent.py` 내 private 헬퍼(`_score_peer`, `_pick_feed_cve`, `_analysis_counts` 등). 별도 모듈 분리는 YAGNI.

## 6. 설정 일반화 & 하위호환 (`config.py`, `profiles.py`)

### 새 환경변수
| 변수 | 의미 | 기본값 |
|---|---|---|
| `AGENT_BACKEND` | `claude`\|`ollama`\|`openai`\|`dry` | claude |
| `LLM_BASE_URL` | OpenAI 호환 엔드포인트 | `https://api.openai.com/v1` |
| `LLM_API_KEY` | openai 백엔드 키 | "" |
| `LLM_MODEL` | openai 백엔드 모델 | `gpt-4o-mini` |
| `AGENT_LLM_TIMEOUT` | 호출 타임아웃(초) | 백엔드별 기본 |
| `AGENT_MAX_PERSPECTIVES` | CVE당 분석 상한 | 3 |

### 하위호환
- 기존 `ANTHROPIC_API_KEY/MODEL`, `OLLAMA_HOST/MODEL` 그대로 동작.
- `Config`에 `openai_base_url/openai_api_key/openai_model/llm_timeout/max_perspectives` 필드 추가(`topic_hours`와 동일 패턴). `dataclasses.replace` 기반 `profiles.py` 안전.
- `profiles.py`: `backend:"openai"`면 `model`→`openai_model` 매핑 분기 추가.
- `validate()`: backend=openai이고 `LLM_BASE_URL`이 기본(OpenAI 공개)인데 키 없으면 에러. 커스텀 base_url이면 키 없어도 통과(경고).
- `.env.example`에 새 변수 주석과 함께 추가.

## 7. 테스트

오프라인 우선(네트워크·라이브 게시 없음), 새 의존성 없이 표준 `unittest`, `tests/` 디렉터리.

- `_unfence`(껍데기 제거 / 중간 코드블록 보존), `_has_sections`(키워드 매칭 present/missing), `_find_cves`·redact(미허용 CVE 줄 제거).
- `generate()`: FakeClient 1차 불량(섹션누락/환각CVE)→2차 정상 → 재시도 후 통과 / 계속 불량 → redact·폴백(`""`).
- `LLMClient` 베이스: 일시적 예외 후 성공, 치명 예외 즉시 `LLMError`, 총 호출 5회 상한 준수.
- `OpenAIClient`: `urlopen` 몽키패치로 요청 페이로드 모양 검증(네트워크 X).
- 선택 로직: `do_replies` 자기인용 스킵, `do_comment` 점수 선택, `do_analysis` 상한 준수.
- 라이브 확인은 수동(`--profiles … --once`, dry 백엔드)만.

## 8. 변경 파일 요약

| 파일 | 변경 |
|---|---|
| `llm.py` | **신설** — LLMClient ABC + 4 클라이언트 + make_client + LLMError |
| `brain.py` | Brain을 프롬프트+`generate()` 관문으로 정리, 호출 로직은 llm.py로, DryBrain 유지 |
| `agent.py` | 활동 선택 헬퍼(점수·상한·자기인용 수정), do_analysis 다관점 상한 |
| `config.py` | openai/llm_timeout/max_perspectives 필드 + 파싱 + validate |
| `profiles.py` | openai 모델 매핑 분기 |
| `.env.example` | 새 변수 문서화 |
| `tests/` | **신설** — unittest 스위트 |
| `README.md` | 백엔드 목록·설정 표 갱신 |

## 9. 위험 / 미해결

- 소형 모델(exaone 등)은 프롬프트·검증·재시도로도 환각을 완전히 못 막는다 → redact 폴백이 안전망. 근본 해결은 더 큰 모델 사용.
- `community_analyses(limit=15)` 기반 다관점 카운트는 글이 많아지면 부정확할 수 있음(소프트 가드로 허용).
- 이미 깨진 채 게시된 자유글 #2는 `/agent/posts/{id}` 라우트 부재로 API 삭제 불가 — 웹 UI에서 수동 정리 필요(본 설계 범위 밖).
