#!/usr/bin/env bash
# Sentinel Vault: one command to set up, run and test everything. See README.
#
#   ./run.sh           setup (if needed) + start all services + smoke test
#   ./run.sh test      full test suite (no services needed)
#   ./run.sh verify    lint + type check + tests with coverage gate
#   ./run.sh stop      stop services
#   ./run.sh reset     stop + delete local data, keys and logs (keeps .venv)
#   ./run.sh status    show which services are running
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv"
PY="$VENV/bin/python"
RUN_DIR="$ROOT/.run"
LOG_DIR="$RUN_DIR/logs"
PID_DIR="$RUN_DIR/pids"
STAMP="$VENV/.sentinel-installed"
SPACY_MODEL="en_core_web_lg"

API_PORT="${SV_API_PORT:-8000}"
KMS_PORT="${KMS_PORT:-8100}"
LLM_PORT="${LLM_PORT:-8200}"

# name|port|uvicorn factory target
SERVICES=(
  "customer-kms|$KMS_PORT|customer_kms.app:create_app"
  "mock-llm|$LLM_PORT|mock_llm.app:create_app"
  "sentinel-api|$API_PORT|sentinel_vault.api.app:create_app"
)

ok()   { printf '[ok]   %s\n' "$*"; }
info() { printf '[..]   %s\n' "$*"; }
fail() { printf '[fail] %s\n' "$*" >&2; exit 1; }

find_python() {
  for c in python3.12 python3; do
    if command -v "$c" >/dev/null 2>&1 &&
       "$c" -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)'; then
      command -v "$c"; return 0
    fi
  done
  return 1
}

deps_hash() {
  "$PY" -c 'import hashlib,pathlib; print(hashlib.sha256(b"".join(pathlib.Path(f).read_bytes() for f in ("pyproject.toml","requirements.lock") if pathlib.Path(f).exists())).hexdigest())'
}

cmd_setup() {
  local py
  py="$(find_python)" || fail "Python 3.12 not found — install it (e.g. 'brew install python@3.12' or 'uv python install 3.12')"
  ok "python $("$py" --version 2>&1 | cut -d' ' -f2)"

  if [[ ! -x "$PY" ]]; then
    info "creating virtualenv"
    "$py" -m venv "$VENV" || fail "venv creation failed"
  fi
  ok "virtualenv .venv"

  mkdir -p "$RUN_DIR"
  local want; want="$(deps_hash)"
  if [[ ! -f "$STAMP" || "$(cat "$STAMP")" != "$want" ]]; then
    info "installing dependencies (first run takes a few minutes)"
    "$PY" -m pip install -q --upgrade pip >"$RUN_DIR/pip.log" 2>&1 || true
    local constraint=()
    [[ -f requirements.lock ]] && constraint=(-c requirements.lock)
    "$PY" -m pip install -q ${constraint[@]+"${constraint[@]}"} -e '.[dev]' >"$RUN_DIR/pip.log" 2>&1 \
      || fail "pip install failed — see $RUN_DIR/pip.log"
    echo "$want" > "$STAMP"
    rm -f "$RUN_DIR/pip.log"
  fi
  ok "dependencies"

  if ! "$PY" -c "import $SPACY_MODEL" >/dev/null 2>&1; then
    info "downloading spaCy model $SPACY_MODEL (~400 MB, once)"
    "$PY" -m spacy download "$SPACY_MODEL" >/dev/null 2>&1 \
      || fail "spaCy model download failed — check network, then re-run ./run.sh"
  fi
  ok "spaCy model $SPACY_MODEL"

  mkdir -p "$LOG_DIR" "$PID_DIR"
  "$PY" -m sentinel_vault.bootstrap || fail "bootstrap failed"
  "$PY" -m customer_kms.cli register-principal sentinel-svc "$ROOT/.secrets/service_ed25519.pub.pem" \
    || fail "KMS principal registration failed"
}

is_running() { [[ -f "$PID_DIR/$1.pid" ]] && kill -0 "$(cat "$PID_DIR/$1.pid")" 2>/dev/null; }

port_free() {
  "$PY" - "$1" <<'EOF'
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try: s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError: sys.exit(1)
finally: s.close()
EOF
}

wait_healthy() {
  local name="$1" port="$2"
  for _ in $(seq 1 60); do
    if "$PY" -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:$port/health', timeout=1).status == 200 else 1)" 2>/dev/null; then
      return 0
    fi
    is_running "$name" || return 1
    sleep 0.5
  done
  return 1
}

cmd_up() {
  cmd_setup
  for svc in "${SERVICES[@]}"; do
    IFS='|' read -r name port target <<<"$svc"
    if is_running "$name"; then ok "$name already running on :$port"; continue; fi
    port_free "$port" || fail "port $port is in use — stop that process or set a different port env var"
    nohup "$PY" -m uvicorn --factory "$target" --host 127.0.0.1 --port "$port" \
      --no-access-log >"$LOG_DIR/$name.log" 2>&1 &
    echo $! > "$PID_DIR/$name.pid"
    wait_healthy "$name" "$port" || fail "$name did not become healthy — see $LOG_DIR/$name.log"
    ok "$name on http://127.0.0.1:$port  (docs: /docs)"
  done
  cmd_smoke
  "$PY" -m reviewer_kit.seed || fail "seeding failed — see $LOG_DIR/sentinel-api.log"
  cat <<EOF

Sentinel Vault is up.
  API          http://127.0.0.1:$API_PORT/docs
  Customer KMS http://127.0.0.1:$KMS_PORT/docs
  Mock LLM     http://127.0.0.1:$LLM_PORT/docs
  Logins       $ROOT/.secrets/reviewer-credentials.txt
  Logs         $LOG_DIR/
Next: ./run.sh demo | attack | simulate | test | stop
EOF
}

cmd_smoke() {
  for svc in "${SERVICES[@]}"; do
    IFS='|' read -r name port _ <<<"$svc"
    wait_healthy "$name" "$port" || fail "smoke: $name /health failed"
  done
  ok "smoke test (all /health endpoints)"
}

cmd_stop() {
  for svc in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ <<<"$svc"
    if is_running "$name"; then
      kill "$(cat "$PID_DIR/$name.pid")" 2>/dev/null || true
      for _ in $(seq 1 20); do is_running "$name" || break; sleep 0.25; done
      ok "stopped $name"
    fi
    rm -f "$PID_DIR/$name.pid"
  done
}

cmd_status() {
  for svc in "${SERVICES[@]}"; do
    IFS='|' read -r name port _ <<<"$svc"
    if is_running "$name"; then echo "running  $name :$port"; else echo "stopped  $name"; fi
  done
}

cmd_test()   { cmd_setup >/dev/null; "$PY" -m pytest -q "$@"; }

cmd_verify() {
  cmd_setup >/dev/null
  "$PY" -m ruff check src customer_kms mock_llm reviewer_kit tests || fail "ruff found issues"
  ok "ruff"
  "$PY" -m mypy src customer_kms mock_llm reviewer_kit || fail "mypy found type errors"
  ok "mypy --strict"
  "$PY" -m pytest -q -rf --cov=sentinel_vault --cov=customer_kms --cov=mock_llm --cov=reviewer_kit \
    --cov-branch --cov-report=term-missing:skip-covered --cov-fail-under=85 \
    || fail "tests failed or coverage below 85%"
  ok "tests + coverage >= 85%"
}

cmd_reset() {
  [[ -x "$PY" ]] && cmd_stop || true
  rm -rf "$ROOT/.run" "$ROOT/.secrets"
  ok "removed .run/ and .secrets/ (virtualenv kept)"
}

case "${1:-up}" in
  up)     cmd_up ;;
  setup)  cmd_setup ;;
  test)   shift; cmd_test "$@" ;;
  verify) cmd_verify ;;
  stop)   cmd_stop ;;
  status) cmd_status ;;
  reset)  cmd_reset ;;
  demo)     cmd_up >/dev/null; "$PY" -m reviewer_kit.demo ;;
  attack)   cmd_up >/dev/null; "$PY" -m reviewer_kit.attack ;;
  simulate) cmd_up >/dev/null; "$PY" -m reviewer_kit.simulate ;;
  *) fail "unknown command '$1' (use: up | demo | attack | simulate | test | verify | stop | status | reset)" ;;
esac
