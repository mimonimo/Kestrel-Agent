#!/usr/bin/env bash
# 새 DGX 노드 부트스트랩 — SSH 로 붙어서 한 번만 실행하면 되는 설치 스크립트.
#
#   ssh <user>@<DGX-x호기>
#   git clone https://github.com/mimonimo/Kestrel-Agent.git agent && cd agent
#   ./setup_node.sh
#
# 하는 일: 사전조건 점검 → venv/의존성 → 설정 파일 준비 → 설정 검증 →
#          systemd user 서비스 설치. **자동으로 시작하지는 않습니다** —
#          토큰이 안 채워진 채로 뜨면 계정 없이 로그만 쌓이기 때문입니다.
#
# 다시 실행해도 안전합니다(이미 있는 것은 건드리지 않음).
set -euo pipefail

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${BASE}/.venv/bin/python"
UNIT_DIR="${HOME}/.config/systemd/user"
UNIT="${UNIT_DIR}/kestrel-agent.service"
FAIL=0

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✘\033[0m %s\n' "$*"; FAIL=1; }

# ── 1. 사전조건 ────────────────────────────────────────────────
say "1/5 사전조건"
command -v python3 >/dev/null || { bad "python3 없음"; exit 1; }
ok "python3 $(python3 -V 2>&1 | awk '{print $2}')"

if ! python3 -c 'import venv' 2>/dev/null; then
    bad "python3-venv 모듈 없음 → sudo apt install python3-venv"
    exit 1
fi

# Ollama 는 이 스크립트가 설치하지 않는다(드라이버·GPU 구성이 노드마다 다름).
OLLAMA_HOST_URL="${OLLAMA_HOST:-http://localhost:11434}"
if curl -sf --max-time 5 "${OLLAMA_HOST_URL}/api/version" >/dev/null 2>&1; then
    ok "ollama 응답 ($(curl -sf --max-time 5 "${OLLAMA_HOST_URL}/api/version"))"
else
    bad "ollama 응답 없음 (${OLLAMA_HOST_URL}) → 'ollama serve &' 로 띄우세요"
fi

# ── 2. venv · 의존성 ──────────────────────────────────────────
say "2/5 파이썬 환경"
if [ ! -x "$PY" ]; then
    python3 -m venv "${BASE}/.venv"
    ok "venv 생성"
else
    ok "venv 이미 있음"
fi
"${BASE}/.venv/bin/pip" install -q --upgrade pip
"${BASE}/.venv/bin/pip" install -q -r "${BASE}/requirements.txt"
ok "의존성 설치 완료"

# ── 3. 설정 파일 ──────────────────────────────────────────────
say "3/5 설정 파일"
if [ ! -f "${BASE}/.env" ]; then
    cp "${BASE}/.env.node.example" "${BASE}/.env"
    warn ".env 를 예시에서 만들었습니다 — ★ 표시된 값을 채우세요"
else
    ok ".env 이미 있음(건드리지 않음)"
fi

if [ ! -f "${BASE}/agents.json" ]; then
    warn "agents.json 이 없습니다. 이 노드의 역할에 맞는 예시를 복사하세요:"
    printf '      처치군:  cp %s/agents.platform.example.json %s/agents.json\n' "$BASE" "$BASE"
    printf '      대조군:  cp %s/agents.control.example.json  %s/agents.json\n' "$BASE" "$BASE"
else
    ok "agents.json 이미 있음(건드리지 않음)"
fi

# ── 4. 설정 검증 ──────────────────────────────────────────────
# 여기서 잡는 실수들이 전부 "며칠 돌린 뒤에야 표본이 못 쓰게 된 걸 알게 되는" 종류다.
say "4/5 설정 검증"
if grep -q '★' "${BASE}/.env" 2>/dev/null; then
    bad ".env 에 채우지 않은 ★ 자리표시자가 남아 있습니다"
fi
if [ -f "${BASE}/agents.json" ] && grep -q '★' "${BASE}/agents.json"; then
    bad "agents.json 에 채우지 않은 ★ 자리표시자가 남아 있습니다"
fi
if [ -f "${BASE}/agents.json" ]; then
    python3 -c "import json,sys; json.load(open('${BASE}/agents.json'))" 2>/dev/null \
        && ok "agents.json JSON 문법 정상" \
        || bad "agents.json JSON 문법 오류"

    # arm 이 비어 있으면 모든 레코드가 'default' 로 찍혀 노드 구분이 불가능해진다.
    python3 - "$BASE" <<'PYEOF' || FAIL=1
import json, sys, pathlib
base = pathlib.Path(sys.argv[1])
try:
    prof = json.loads((base / "agents.json").read_text(encoding="utf-8"))
except Exception:
    sys.exit(0)                       # 문법 오류는 위에서 이미 보고했다
arms, toks = set(), []
for a in prof.get("agents", []):
    arms.add(a.get("arm", ""))
    toks.append(a.get("token") or a.get("tokenEnv") or "")
if "" in arms:
    print("  \033[31m✘\033[0m arm 이 비어 있는 에이전트가 있습니다 — 노드 구분이 불가능해집니다")
    sys.exit(1)
real = [t for t in toks if t and not t.startswith("kxa_★")]
if len(set(real)) != len(real):
    print("  \033[31m✘\033[0m 같은 토큰을 쓰는 에이전트가 있습니다 — 중복 게시가 납니다")
    sys.exit(1)
print(f"  \033[32m✔\033[0m arm={sorted(arms)}, 에이전트 {len(toks)}개, 토큰 중복 없음")
PYEOF
fi

# 모델이 실제로 받아져 있는지 — 없으면 첫 사이클에서 전부 실패한다.
MODEL="$(grep -E '^(AGENT_ANALYSIS_MODEL|OLLAMA_MODEL)=' "${BASE}/.env" 2>/dev/null \
         | tail -1 | cut -d= -f2- | tr -d '"'"'"' ' || true)"
if [ -n "${MODEL:-}" ]; then
    if curl -sf --max-time 5 "${OLLAMA_HOST_URL}/api/tags" 2>/dev/null | grep -q "\"${MODEL}\""; then
        ok "모델 ${MODEL} 준비됨"
    else
        bad "모델 ${MODEL} 이 없습니다 → ollama pull ${MODEL}"
    fi
fi

# ── 5. systemd user 서비스 ────────────────────────────────────
say "5/5 systemd user 서비스"
mkdir -p "$UNIT_DIR"
cat > "$UNIT" <<EOF
[Unit]
Description=Kestrel CVE Analysis Agents (${HOSTNAME:-node})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${BASE}
ExecStart=${PY} ${BASE}/agent.py --profiles ${BASE}/agents.json
Restart=always
RestartSec=15
StandardOutput=append:${BASE}/agent_run.log
StandardError=append:${BASE}/agent_run.log

[Install]
WantedBy=default.target
EOF
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
systemctl --user daemon-reload
systemctl --user enable kestrel-agent >/dev/null 2>&1 || true
ok "유닛 설치: ${UNIT}"

# SSH 로 붙어서 쓰는 경우의 핵심 함정. linger 가 없으면 마지막 SSH 세션이 끊기는
# 순간 user manager 가 죽고 에이전트도 같이 죽는다.
if [ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null)" = "yes" ]; then
    ok "linger 활성 — SSH 를 끊어도 계속 돕니다"
else
    warn "linger 비활성 — SSH 를 끊으면 에이전트가 함께 죽습니다."
    printf '      sudo loginctl enable-linger %s\n' "$(id -un)"
fi

# ── 마무리 ────────────────────────────────────────────────────
if [ "$FAIL" -ne 0 ]; then
    printf '\n\033[31m설정이 아직 완료되지 않았습니다.\033[0m 위 ✘ 항목을 고친 뒤 ./setup_node.sh 를 다시 실행하세요.\n'
    exit 1
fi
cat <<EOF

$(printf '\033[32m준비 완료.\033[0m') 다음 순서로 띄우세요.

  1) 스모크 테스트 — CVE 1건을 파이프라인에 태우되 게시는 안 함(모델·GPU·속도 확인):
       ${PY} smoke_node.py
  2) 서비스 시작:
       export XDG_RUNTIME_DIR=/run/user/\$(id -u)
       systemctl --user start kestrel-agent
  3) 3개 페르소나가 다 떴는지 확인:
       grep "동시 실행" agent_run.log | tail -1
  4) 정지:
       systemctl --user stop kestrel-agent
EOF
