# EverOS — Security Audit: Multiple Vulnerabilities

**A security audit of EverOS 1.7.1 (`EverMind-AI/EverOS`, Python/FastAPI) found multiple vulnerabilities — including an unauthenticated local file exfiltration chain exploitable by any website a victim visits.**

All findings verified against a live instance at upstream HEAD `6ac3898` (unfixed).

## Vulnerabilities found

| ID | Vulnerability | Severity | CVSS 3.1 | Status |
|---|---|---|---|---|
| **2026-01** | **Local file exfiltration via `file://` ingestion + permissive CORS** — any website reads arbitrary local files (≤50 MB/item) through the unauthenticated API | **High** | 8.2 `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` | Submitted — VulnCheck `31e5306f…`, Vulners CNA emailed |
| **2026-02** | **Unauthenticated SSRF** — `uri` content items fetch arbitrary http(s) URLs server-side (redirects followed, no private-IP filtering); response readable via `/memory/search` | **High** | 7.4 `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N` (8.6 if `UI:N`) | Verified — draft ready, pending vendor contact |
| **2026-03** | **Knowledge document IDOR** — `doc_id`/`topic_id` operations ignore `app_id`/`project_id` scope; cross-tenant read and delete | **Medium** | 6.8 `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` (9.1 if tenant-proxied) | Verified — draft ready, pending vendor contact |
| — | Missing `Origin` validation on mutating routes (CSRF write/delete) | Medium | 6.1 | Hardening note |
| — | Unauthenticated `POST /cascade/quiesce` → permanent indexing DoS until restart | Med-Low | 6.5 | Hardening note |
| — | Absolute server paths leaked in `original_file_path` responses | Low | 5.3 | Hardening note |

Details, evidence, and PoCs: [`audit-2026-11-24/`](audit-2026-11-24/report.md) · Submission drafts: [`submission/`](submission/) · Vendor addendum: [`advisory/`](advisory/)

---

## EVEROS-2026-01 — file:// exfiltration via CORS (submitted)

Two insecure defaults combine into browser-mediated local file disclosure:

1. **`file://` ingestion is unrestricted.** `file_uri_allow_dirs` defaults to `[]`, which the code treats as "allow any readable file".
2. **CORS allows everything.** The unauthenticated API defaults to `allow_origins=["*"]` + `allow_credentials=True`.

A victim's browser ingests `file:///etc/hostname` via `POST /api/v2/memory/add`, then reads the parsed content back via `POST /api/v2/memory/search` — all cross-origin. Demonstrated end-to-end in headless Chromium.

| | |
|---|---|
| **CWE** | CWE-73, CWE-942, CWE-306 (contributing) |
| **Affected** | EverOS 1.7.1 `e5778ed` … main HEAD `6ac3898` — **unfixed** |
| **Prerequisite** | `[multimodal]` parser configured; victim visits attacker page |
| **Disclosure** | Vendor notified 2026-11-20 · VulnCheck case `31e5306f-1a5c-4489-b142-4097d39c9af9` · Vulners CNA emailed 2026-11-24 |
| **Reporter** | Teycir — analysis LLM-assisted, PoC executed and verified manually |

### Reproduce in 30 seconds

```bash
curl -X POST http://127.0.0.1:18777/api/v2/memory/add \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{"session_id":"poc","messages":[{"sender_id":"u1","role":"user","timestamp":1,"content":[{"type":"doc","name":"h.txt","uri":"file:///etc/hostname","ext":"txt"}]}],"defer_extraction":true}'

curl -X POST http://127.0.0.1:18777/api/v2/memory/search \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{"session_id":"poc","user_id":"attacker","query":"hostname"}'
# → parsed_content == "<hostname>\n"
```

Browser drive-by PoC: [`poc/`](poc/) · Full write-up: [`report.md`](report.md)

### Why it works

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

### Remediation

- Default `file_uri_allow_dirs` to deny-all when unset; resolve symlinks before the check.
- Default CORS to no origins and `allow_credentials=False`.
- Add per-instance bearer-token auth on all API routes — loopback binding is not authorization.
- Return content references, not `parsed_content`/bytes, in search/list responses.
- Reject `Origin: null` and non-allowlisted origins before routing.

## EVEROS-2026-02 — SSRF (draft ready)

`uri` content items with `http(s)` schemes are fetched server-side by everalgo's httpx client — `follow_redirects=True`, **no private/loopback IP filtering** (its docstring delegates egress policy to the caller, and EverOS sets none). Fetched content is stored and readable via `/memory/search`.

Verified three paths: direct loopback fetch, **302 redirect to a second internal host**, and `gopher://` correctly rejected (negative control). CWE-918.

## EVEROS-2026-03 — Knowledge IDOR (draft ready)

Knowledge `doc_id`/`topic_id` operations ignore `app_id`/`project_id` scope: upload scope is taken from form fields, but read/delete take scope from query params and **never enforce it**. Scoped *list* correctly isolates tenants — proving isolation is intended — while get/delete-by-id bypasses it entirely.

Verified: wrong-scope `GET` → 200, wrong-scope `DELETE` → 204. CWE-639, CWE-862.

## Hardening notes (documented, not submitted)

- **CSRF/origin gap** — only `/purge` validates `Origin`; every other mutating route lacks the check (write half of the browser attack).
- **Quiesce DoS** — unauthenticated `POST /cascade/quiesce` permanently stops indexing (`index_emptied: true`) until restart.
- **Path disclosure** — absolute server paths returned in `original_file_path` fields.

## Disclosure timeline

| Date (UTC) | Event |
|---|---|
| 2026-11-20 | Vendor notice → `evermind@shanda.com` (evidence zip `fd739c25…`) |
| 2026-11-23/24 | Re-verified unfixed at HEAD `6ac3898` |
| 2026-11-24 | VulnCheck submitted (case above) · Vulners CNA emailed · second audit added |
