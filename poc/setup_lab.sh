#!/usr/bin/env bash
# Disposable EverOS lab for the CORS + file:// proof.
# Defaults: source checkout in ~/ResearchAIRedTeam/EverOS, root /tmp/everos-poc-lab.
#
#   ./poc/setup_lab.sh
#   BASE=http://127.0.0.1:18777 python3 poc/exploit.py --json /tmp/transcript.json
#
#   WITH_ALLOWLIST=1 ./poc/setup_lab.sh   # also starts :18778 with an allowlist
#   BASE=... ALLOWLIST_BASE=http://127.0.0.1:18778 \
#     ALLOWED_FILE=/tmp/everos-poc-allowed/canary.txt python3 poc/exploit.py
#
# Nothing leaves the machine. Stop with: kill "$(cat "$LAB_ROOT/server.pid")"
set -euo pipefail

SRC="${EVEROS_SRC:-$HOME/ResearchAIRedTeam/EverOS}"
LAB="${LAB_ROOT:-/tmp/everos-poc-lab}"
PORT="${PORT:-18777}"
ALLOWLIST_PORT="${ALLOWLIST_PORT:-18778}"
ALLOWED_DIR="${ALLOWED_DIR:-/tmp/everos-poc-allowed}"

command -v uv >/dev/null || { echo "uv is required" >&2; exit 1; }
[ -d "$SRC" ] || { echo "EverOS source not found: $SRC (set EVEROS_SRC)" >&2; exit 1; }

mkdir -p "$LAB"
cd "$SRC"
uv sync --frozen

if [ ! -f "$LAB/everos.toml" ]; then
  uv run everos init --root "$LAB"
fi

common_env=(
  EVEROS_API__HOST=127.0.0.1
  EVEROS_LLM__API_KEY=sk-dummy
  EVEROS_LLM__BASE_URL=http://127.0.0.1:18999/v1
  EVEROS_MULTIMODAL__API_KEY=sk-dummy
  EVEROS_MULTIMODAL__BASE_URL=http://127.0.0.1:18999/v1
)

start_server() {
  local root="$1" port="$2" log="$3" pidfile="$4"
  if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    echo "[*] already running: pid $(cat "$pidfile") on :$port"
    return
  fi
  env "${common_env[@]}" EVEROS_API__PORT="$port" \
    nohup uv run everos server start --root "$root" --port "$port" \
    >"$log" 2>&1 &
  echo $! >"$pidfile"
  for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$port/health" >/dev/null; then
      echo "[+] EverOS on http://127.0.0.1:$port (root $root, pid $(cat "$pidfile"))"
      return
    fi
    sleep 0.5
  done
  echo "[-] server did not become healthy; see $log" >&2
  tail -40 "$log" >&2 || true
  exit 1
}

start_server "$LAB" "$PORT" "$LAB/server.log" "$LAB/server.pid"

if [ "${WITH_ALLOWLIST:-0}" = "1" ]; then
  ALLOW_LAB="${ALLOWLIST_ROOT:-/tmp/everos-poc-lab-allowlist}"
  mkdir -p "$ALLOW_LAB" "$ALLOWED_DIR"
  printf 'ALLOWED-CANARY-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" >"$ALLOWED_DIR/canary.txt"
  if [ ! -f "$ALLOW_LAB/everos.toml" ]; then
    uv run everos init --root "$ALLOW_LAB"
  fi
  env "${common_env[@]}" \
    EVEROS_API__PORT="$ALLOWLIST_PORT" \
    EVEROS_MULTIMODAL__FILE_URI_ALLOW_DIRS="[\"$ALLOWED_DIR\"]" \
    nohup uv run everos server start --root "$ALLOW_LAB" --port "$ALLOWLIST_PORT" \
    >"$ALLOW_LAB/server.log" 2>&1 &
  echo $! >"$ALLOW_LAB/server.pid"
  for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$ALLOWLIST_PORT/health" >/dev/null; then
      echo "[+] allowlist instance on http://127.0.0.1:$ALLOWLIST_PORT (root $ALLOW_LAB)"
      echo "    ALLOWED_FILE=$ALLOWED_DIR/canary.txt"
      break
    fi
    sleep 0.5
  done
fi

echo
echo "next:"
echo "  BASE=http://127.0.0.1:$PORT python3 poc/exploit.py --json /tmp/everos-transcript.json"
if [ "${WITH_ALLOWLIST:-0}" = "1" ]; then
  echo "  BASE=http://127.0.0.1:$PORT ALLOWLIST_BASE=http://127.0.0.1:$ALLOWLIST_PORT \\"
  echo "    ALLOWED_FILE=$ALLOWED_DIR/canary.txt python3 poc/exploit.py"
fi
