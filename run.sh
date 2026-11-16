#!/usr/bin/env bash
# Sentinel Vault: one command to set up, run and test everything. See README.
#
#   ./run.sh              setup (if needed) + start services + seed 10 tenants + smoke test
#   ./run.sh demo         guided walkthrough   (--pause: wait for Enter between steps)
#   ./run.sh attack       4 threat actors against the live services
#   ./run.sh simulate     10 tenants x 3 users x 2 sessions at once
#   ./run.sh logs         follow all service logs, readable (already redacted)
#   ./run.sh test         full test suite (no services needed)
#   ./run.sh verify       lint + type check + tests with coverage gate
#   ./run.sh status | stop | reset
#
# Flags (any command): -v / --verbose  show full pip / spaCy / pytest output
# Env: NO_COLOR=1 disables colors (also off automatically when output is piped)
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

# name|port|uvicorn factory target|what it is
SERVICES=(
  "customer-kms|$KMS_PORT|customer_kms.app:create_app|the customer's key vault (holds the master keys)"
  "mock-llm|$LLM_PORT|mock_llm.app:create_app|the external LLM (records everything it receives)"
  "sentinel-api|$API_PORT|sentinel_vault.api.app:create_app|our service (stores only ciphertext)"
)

# --- flags -------------------------------------------------------------------------------
VERBOSE=0
ARGS=()
for a in "$@"; do
  case "$a" in
    -v|--verbose) VERBOSE=1 ;;
    *) ARGS+=("$a") ;;
  esac
done
set -- ${ARGS[@]+"${ARGS[@]}"}

# --- output ------------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_OK=$'\033[32m'; C_FAIL=$'\033[1;31m'; C_INFO=$'\033[34m'; C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'; TTY=1
else
  C_OK=""; C_FAIL=""; C_INFO=""; C_DIM=""; C_BOLD=""; C_OFF=""; TTY=0
fi

STEP=0
STEPS=0
T0=$SECONDS
ok()   { printf '%s[ok]%s   %s\n' "$C_OK" "$C_OFF" "$*"; }
info() { printf '%s[..]%s   %s\n' "$C_INFO" "$C_OFF" "$*"; }
note() { printf '       %s%s%s\n' "$C_DIM" "$*" "$C_OFF"; }
fail() { printf '%s[fail]%s %s\n' "$C_FAIL" "$C_OFF" "$*" >&2; exit 1; }
step() {
  STEP=$((STEP + 1))
  printf '\n%s[%d/%d] %s%s %s(+%ds)%s\n' "$C_BOLD" "$STEP" "$STEPS" "$1" "$C_OFF" \
    "$C_DIM" "$((SECONDS - T0))" "$C_OFF"
}

# run_quiet "<label>" "<logfile>" cmd...  — spinner + elapsed time; full output with -v.
run_quiet() {
  local label="$1" log="$2"; shift 2
  if [[ $VERBOSE == 1 ]]; then
    "$@" 2>&1 | tee "$log"; return "${PIPESTATUS[0]}"
  fi
  "$@" >"$log" 2>&1 &
  local pid=$! start=$SECONDS i=0 frames='|/-\'
  while kill -0 "$pid" 2>/dev/null; do
    if [[ $TTY == 1 ]]; then
      printf '\r%s[%s]%s   %s  %ds ' "$C_INFO" "${frames:$((i % 4)):1}" "$C_OFF" "$label" \
        "$((SECONDS - start))"
    elif (( i > 0 && i % 100 == 0 )); then
      info "$label… still working ($((SECONDS - start))s)"
    fi
    i=$((i + 1)); sleep 0.1
  done
  [[ $TTY == 1 ]] && printf '\r\033[K'
  wait "$pid"
}

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
  step "Python 3.12"
  py="$(find_python)" || fail "Python 3.12 not found — install it (e.g. 'brew install python@3.12' or 'uv python install 3.12')"
  ok "python $("$py" --version 2>&1 | cut -d' ' -f2) at $py"

  step "Virtualenv (.venv)"
  if [[ ! -x "$PY" ]]; then
    info "creating virtualenv"
    "$py" -m venv "$VENV" || fail "venv creation failed"
  fi
  ok "virtualenv ready"

  step "Python packages"
  mkdir -p "$RUN_DIR"
  local want; want="$(deps_hash)"
  if [[ ! -f "$STAMP" || "$(cat "$STAMP")" != "$want" ]]; then
    note "FastAPI, cryptography, Presidio, spaCy … pinned in requirements.lock (≈2 min first run)"
    run_quiet "upgrading pip" "$RUN_DIR/pip.log" "$PY" -m pip install --upgrade pip || true
    local constraint=()
    [[ -f requirements.lock ]] && constraint=(-c requirements.lock)
    run_quiet "installing packages" "$RUN_DIR/pip.log" \
      "$PY" -m pip install ${constraint[@]+"${constraint[@]}"} -e '.[dev]' \
      || fail "pip install failed — see $RUN_DIR/pip.log (or re-run with --verbose)"
    echo "$want" > "$STAMP"
    rm -f "$RUN_DIR/pip.log"
    ok "packages installed"
  else
    ok "packages already installed (unchanged)"
  fi

  step "PII model (spaCy $SPACY_MODEL)"
  if ! "$PY" -c "import $SPACY_MODEL" >/dev/null 2>&1; then
    note "named-entity model used to find names and places (~400 MB, downloaded once)"
    run_quiet "downloading $SPACY_MODEL" "$RUN_DIR/spacy.log" \
      "$PY" -m spacy download "$SPACY_MODEL" \
      || fail "spaCy model download failed — check network, see $RUN_DIR/spacy.log, then re-run ./run.sh"
    rm -f "$RUN_DIR/spacy.log"
    ok "model downloaded"
  else
    ok "model already present"
  fi

  step "Keys and identities"
  note "our service gets an Ed25519 signing key (.secrets/, mode 0600); the customer KMS"
  note "learns its public key as principal 'sentinel-svc' (like an IAM role)"
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
  STEPS=8
  printf '%sSentinel Vault%s — BYOK envelope encryption + PHI protection for agentic RAG\n' \
    "$C_BOLD" "$C_OFF"
  cmd_setup
  step "Start services (loopback only)"
  for svc in "${SERVICES[@]}"; do
    IFS='|' read -r name port target what <<<"$svc"
    if is_running "$name"; then ok "$name already running on :$port"; continue; fi
    port_free "$port" || fail "port $port is in use — stop that process or set a different port env var"
    nohup "$PY" -m uvicorn --factory "$target" --host 127.0.0.1 --port "$port" \
      --no-access-log >"$LOG_DIR/$name.log" 2>&1 &
    echo $! > "$PID_DIR/$name.pid"
    [[ $name == sentinel-api ]] && info "starting $name (loads the PII model, ~5 s)"
    wait_healthy "$name" "$port" || fail "$name did not become healthy — see $LOG_DIR/$name.log"
    ok "$name on 127.0.0.1:$port — $what"
  done

  step "Smoke test"
  cmd_smoke

  step "Seed 10 synthetic customers"
  "$PY" -m reviewer_kit.seed || fail "seeding failed — see $LOG_DIR/sentinel-api.log (./run.sh logs)"

  cat <<EOF

${C_OK}${C_BOLD}Sentinel Vault is up${C_OFF} ${C_DIM}($((SECONDS - T0))s)${C_OFF}
  API          http://127.0.0.1:$API_PORT/docs
  Customer KMS http://127.0.0.1:$KMS_PORT/docs
  Mock LLM     http://127.0.0.1:$LLM_PORT/docs
  Logins       $ROOT/.secrets/reviewer-credentials.txt
  Logs         ./run.sh logs   ($LOG_DIR/)

Try next:
  ./run.sh demo       13-step walkthrough (add --pause to step through it)
  ./run.sh attack     11 live attacks by 4 threat actors
  ./run.sh simulate   60 concurrent sessions across 10 tenants
  ./run.sh test       full test suite
  ./run.sh stop       stop everything
EOF
}

cmd_smoke() {
  for svc in "${SERVICES[@]}"; do
    IFS='|' read -r name port _ _ <<<"$svc"
    wait_healthy "$name" "$port" || fail "smoke: $name /health failed"
  done
  ok "all /health endpoints answer"
}

cmd_stop() {
  local any=0
  for svc in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ _ <<<"$svc"
    if is_running "$name"; then
      kill "$(cat "$PID_DIR/$name.pid")" 2>/dev/null || true
      for _ in $(seq 1 20); do is_running "$name" || break; sleep 0.25; done
      ok "stopped $name"; any=1
    fi
    rm -f "$PID_DIR/$name.pid"
  done
  [[ $any == 0 ]] && ok "nothing was running" || true
}

cmd_status() {
  for svc in "${SERVICES[@]}"; do
    IFS='|' read -r name port _ what <<<"$svc"
    if is_running "$name"; then
      printf '%srunning%s  %-13s :%s  %s%s%s\n' "$C_OK" "$C_OFF" "$name" "$port" "$C_DIM" "$what" "$C_OFF"
    else
      printf '%sstopped%s  %-13s\n' "$C_DIM" "$C_OFF" "$name"
    fi
  done
}

# Ensure services are up without the full setup banner (used by demo/attack/simulate).
ensure_up() {
  local all=1
  mkdir -p "$RUN_DIR"
  for svc in "${SERVICES[@]}"; do
    IFS='|' read -r name _ _ _ <<<"$svc"
    is_running "$name" || all=0
  done
  if [[ $all == 1 && -x "$PY" ]]; then ok "services running"; return; fi
  info "services not running — starting them first (./run.sh)"
  cmd_up >"$RUN_DIR/up.log" 2>&1 || { cat "$RUN_DIR/up.log"; fail "startup failed"; }
  ok "services started"
}

pytest_flags() { [[ $VERBOSE == 1 ]] && echo "-v" || echo "-q"; }

cmd_test() {
  cmd_setup >/dev/null
  info "running unit, integration and attack-suite tests (≈1–2 min, no services needed)"
  "$PY" -m pytest "$(pytest_flags)" -rf "$@" || fail "tests failed — names of failing tests are listed above"
  ok "all tests passed"
}

cmd_verify() {
  STEPS=3
  cmd_setup >/dev/null
  STEP=0
  step "Lint (ruff)"
  "$PY" -m ruff check src customer_kms mock_llm reviewer_kit tests || fail "ruff found issues"
  ok "ruff"
  step "Types (mypy --strict)"
  "$PY" -m mypy src customer_kms mock_llm reviewer_kit || fail "mypy found type errors"
  ok "mypy --strict"
  step "Tests + coverage gate (≥ 85%)"
  "$PY" -m pytest "$(pytest_flags)" -rf --cov=sentinel_vault --cov=customer_kms --cov=mock_llm \
    --cov=reviewer_kit --cov-branch --cov-report=term-missing:skip-covered --cov-fail-under=85 \
    || fail "tests failed or coverage below 85%"
  ok "tests + coverage >= 85%"
}

cmd_reset() {
  [[ -x "$PY" ]] && cmd_stop || true
  rm -rf "$ROOT/.run" "$ROOT/.secrets"
  ok "removed .run/ and .secrets/ (all data and keys; virtualenv kept)"
  note "undo: none — run ./run.sh to recreate fresh tenants and keys"
}

cmd_logs() {
  [[ -x "$PY" ]] || fail "not set up yet — run ./run.sh first"
  "$PY" -m reviewer_kit.logview --dir "$LOG_DIR" "$@"
}

cmd="${1:-up}"
[[ $# -gt 0 ]] && shift
case "$cmd" in
  up)       cmd_up ;;
  setup)    STEPS=5; cmd_setup ;;
  test)     cmd_test "$@" ;;
  verify)   cmd_verify ;;
  stop)     cmd_stop ;;
  status)   cmd_status ;;
  reset)    cmd_reset ;;
  logs)     cmd_logs "$@" ;;
  demo)     ensure_up; "$PY" -m reviewer_kit.demo "$@" ;;
  attack)   ensure_up; "$PY" -m reviewer_kit.attack ;;
  simulate) ensure_up; "$PY" -m reviewer_kit.simulate ;;
  -h|--help|help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) fail "unknown command '$cmd' (use: up | demo | attack | simulate | logs | test | verify | status | stop | reset)" ;;
esac
