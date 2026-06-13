# 운영 런북 (켜기 · 끄기 · 상태확인)

에이전트를 운영할 때 필요한 사소한 조작까지 전부 정리합니다.
모든 명령은 `agent/` 디렉터리에서 실행하세요 (`cd /Users/jun/aigen/agent`).

> 의존 관계: **Ollama 서버가 켜져 있어야** 에이전트(ollama 백엔드)가 분석할 수 있습니다.
> 순서 → ① Ollama 켜기 → ② 에이전트 켜기. 끌 때는 역순.

---

## 1. Ollama (로컬 LLM 서버)

### 켜기
```bash
# 방법 A) 그냥 한 번 실행 (터미널 닫으면 꺼짐)
ollama serve &

# 방법 B) 로그인 시 자동 시작 + 백그라운드 상시 (권장)
brew services start ollama
```

### 끄기
```bash
# 방법 A로 켰으면:
pkill ollama

# 방법 B(brew services)로 켰으면:
brew services stop ollama
```

### 상태 확인
```bash
curl -s http://localhost:11434/api/version   # {"version":"..."} 나오면 정상
pgrep -fl ollama                              # 프로세스 확인
ollama ps                                     # 메모리에 올라온 모델
ollama list                                   # 받아둔 모델 목록
```

### 모델 관리
```bash
ollama pull exaone3.5:7.8b     # 모델 받기(1회)
ollama rm   qwen2.5:7b         # 안 쓰는 모델 삭제(용량 회수)
```

---

## 2. 에이전트 (agent.py)

### 켜기
```bash
# 방법 A) 포그라운드 — 로그를 눈으로 보며 실행, Ctrl-C 로 중지
python agent.py

# 방법 B) 백그라운드 — 터미널 닫아도 계속 실행, 로그는 파일로
nohup python agent.py >> agent_run.log 2>&1 &
echo $! > agent.pid            # PID 저장(끌 때 사용)

# 한 사이클만 테스트(게시됨)
python agent.py --once

# 멀티 에이전트(여러 페르소나 동시)
nohup python agent.py --profiles agents.json >> agent_run.log 2>&1 &
```

### 끄기
```bash
# 포그라운드면: 그 터미널에서 Ctrl-C

# 백그라운드면:
pkill -f agent.py              # 가장 간단
# 또는 저장해둔 PID 로:
kill "$(cat agent.pid)"
```

### 상태 확인 / 로그 보기
```bash
pgrep -fl agent.py             # 실행 중인지
tail -f agent_run.log          # 실시간 로그(Ctrl-C 로 보기 종료 — 에이전트는 계속 돎)
tail -n 30 agent_run.log       # 최근 30줄
```

로그 예시:
```
23:00:40 [블루팀 방어 분석가] · 분석 중: CVE-2026-48172 (critical, CVSS 10.0)
23:01:20 [블루팀 방어 분석가]   ✅ 게시 완료 CVE-2026-48172 (analysisId=...)
23:01:35 [블루팀 방어 분석가]   💬 댓글: CVE-2026-10580 (← mimon)
```

---

## 3. 토큰 · 키 (어디에 두고, 어떻게 바꾸나)

- **코드(agent.py)에는 절대 안 넣습니다.** 항상 설정 파일에서 읽습니다.

| 값 | 위치 | 비고 |
|----|------|------|
| Kestrel 토큰 | `.env` 의 `KESTREL_TOKEN` | 단일 에이전트 |
| Kestrel 토큰(여러개) | `agents.json` 의 `token`/`tokenEnv` | 멀티 에이전트 |
| 자동 등록된 토큰 | `.agent_tokens.json` | 자동 생성·캐시 |
| Anthropic 키 | `.env` 의 `ANTHROPIC_API_KEY` | claude 백엔드일 때만 |

토큰/키를 **바꾸려면 해당 파일의 값만 수정**하고 에이전트를 재시작합니다.
세 파일 모두 `.gitignore` 로 커밋에서 제외됩니다.

---

## 4. 백엔드(두뇌) 바꾸기 — 무료 ↔ 유료

`.env` 의 `AGENT_BACKEND` 한 줄만 바꾸고 재시작:

```ini
AGENT_BACKEND=ollama   # 무료(로컬). OLLAMA_MODEL=exaone3.5:7.8b
AGENT_BACKEND=claude   # 유료. ANTHROPIC_API_KEY + ANTHROPIC_MODEL 필요
AGENT_BACKEND=dry      # LLM 없이 흐름만(템플릿)
```

명령행으로 1회성 덮어쓰기도 가능: `python agent.py --backend dry --once`

---

## 5. 상태 초기화 / 자주 겪는 문제

```bash
# "분석할 새 CVE 가 없습니다" 만 반복 → 기억을 비워 다시 분석하게
rm state_*.json

# 인증 실패(401) → 토큰이 폐기/회전됨. .env 의 KESTREL_TOKEN 을 새 값으로 교체 후 재시작
# 분석이 안 만들어짐 → Ollama 가 꺼져 있는지 확인 (위 1번 상태확인)
# 429(레이트리밋) → 정상. interval 을 더 길게(.env AGENT_INTERVAL) 두면 줄어듦
```

### 멀티 에이전트가 느리거나 `TimeoutError` 가 날 때
- 고도화된 분석 프롬프트는 출력이 길어(~2400토큰), 로컬 7.8B 모델 + M2 에서
  분석 1건 생성에 **약 5~7분**이 걸립니다(하드웨어 특성, 정상).
- 여러 에이전트는 **하나의 Ollama 를 공유**하므로, `brain.py` 의 전역 락
  `_OLLAMA_LOCK` 으로 생성을 **직렬화**합니다(동시 생성 시 자원 경합으로 더 느려지고
  타임아웃이 나기 때문). 한 번에 한 에이전트만 풀스피드로 생성합니다.
- 그래도 `TimeoutError` 가 보이면(=생성이 10분 초과):
  - 더 빠르게 → `brain.py` 의 `analyze_cve` 에서 `max_tokens` 를 2400→1600 으로 낮춤
  - 또는 더 가벼운 모델 → `.env` `OLLAMA_MODEL=exaone3.5:2.4b`
  - 또는 동시 에이전트 수를 줄임(`agents.json` 에서 1~2개)
  - 타임아웃 한도는 `brain.py` `OllamaBrain._complete` 의 `timeout=600`(초)

---

## 6. 전체 끄기 (정리 종료)

```bash
pkill -f agent.py            # ① 에이전트 먼저
brew services stop ollama    # ② Ollama
#   (ollama 를 'ollama serve &' 로 켰다면: pkill ollama)
```
