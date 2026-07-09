#!/usr/bin/env bash
# 에이전트 간편 제어기 — 켜기/끄기/상태/로그를 한 단어로.
#
#   ./agentctl.sh start     # 백그라운드 실행(터미널 닫아도 계속 돎)
#   ./agentctl.sh stop      # 종료 + GPU 에 올라온 모델까지 내려 메모리 회수
#   ./agentctl.sh restart   # 재시작
#   ./agentctl.sh status     # 실행 여부·최근 로그·올라온 모델
#   ./agentctl.sh logs      # 실시간 로그(Ctrl-C 로 보기만 종료, 에이전트는 계속)
#   ./agentctl.sh free      # 에이전트는 두고 모델만 메모리에서 내림
#
# 옵션: 멀티 프로필로 켜려면  ./agentctl.sh start --profiles agents.json
set -euo pipefail

cd "$(dirname "$0")"

PID_FILE="agent.pid"
LOG_FILE="agent_run.log"
PY="${PYTHON:-python3}"
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"

_running() {  # PID 파일이 가리키는 프로세스, 없으면 agent.py 프로세스 자체를 탐지
  if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    return 0
  fi
  pgrep -f "agent\.py" >/dev/null 2>&1   # 스크립트 밖(직접 nohup 등)에서 켠 경우까지
}

_unload_models() {  # ollama 메모리에 상주 중인 모델을 모두 내려 RAM/GPU 회수
  command -v ollama >/dev/null 2>&1 || return 0
  local models
  models=$(ollama ps 2>/dev/null | awk 'NR>1 {print $1}')
  if [ -n "$models" ]; then
    echo "  · 모델 메모리 회수: $(echo "$models" | tr '\n' ' ')"
    echo "$models" | while read -r m; do [ -n "$m" ] && ollama stop "$m" >/dev/null 2>&1 || true; done
  fi
}

cmd_start() {
  if _running; then
    echo "이미 실행 중 (PID $(cat "$PID_FILE")). 'restart' 또는 'status' 를 쓰세요."
    return 0
  fi
  # ollama 백엔드면 서버가 떠 있는지 가볍게 확인
  if grep -q '^AGENT_BACKEND=ollama' .env 2>/dev/null; then
    if ! curl -s "$OLLAMA_HOST/api/version" >/dev/null 2>&1; then
      echo "⚠️  Ollama 서버가 응답하지 않습니다($OLLAMA_HOST)."
      echo "    먼저 켜세요:  brew services start ollama   (또는  ollama serve &)"
      return 1
    fi
  fi
  nohup "$PY" agent.py "$@" >> "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  echo "▶️  시작 (PID $(cat "$PID_FILE")).  로그: ./agentctl.sh logs"
}

cmd_stop() {
  if _running; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    sleep 1
  fi
  pkill -f "agent\.py" 2>/dev/null || true   # 혹시 PID 파일이 어긋났을 때 대비
  rm -f "$PID_FILE"
  echo "⏹  에이전트 종료."
  _unload_models
  echo "✅ 정리 완료 — 컴퓨터 자원이 회수됐습니다."
}

cmd_status() {
  if _running; then
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "● 실행 중 (PID $(cat "$PID_FILE"))"
    else
      echo "● 실행 중 (PID $(pgrep -f 'agent\.py' | tr '\n' ' ') — 스크립트 밖에서 시작됨)"
    fi
  else
    echo "○ 정지됨"
  fi
  echo "--- 최근 로그 (tail -n 8) ---"
  [ -f "$LOG_FILE" ] && tail -n 8 "$LOG_FILE" || echo "(로그 없음)"
  echo "--- 메모리에 올라온 모델 (ollama ps) ---"
  command -v ollama >/dev/null 2>&1 && ollama ps || echo "(ollama 없음)"
}

case "${1:-}" in
  start)   shift; cmd_start "$@" ;;
  stop)    cmd_stop ;;
  restart) shift; cmd_stop; sleep 1; cmd_start "$@" ;;
  status)  cmd_status ;;
  logs)    tail -f "$LOG_FILE" ;;
  free)    _unload_models; echo "✅ 모델 메모리 회수 완료(에이전트는 그대로)." ;;
  *) echo "사용법: ./agentctl.sh {start|stop|restart|status|logs|free} [--profiles agents.json]"; exit 1 ;;
esac
