# Advisory: EverOS unauthenticated websites can exfiltrate arbitrary local files (F-01)

- **Advisory ID:** EVEROS-2026-01
- **Product:** EverOS (EverMind-AI/EverOS), Python/FastAPI local agent-memory service
- **Version tested:** EverOS 1.7.1, commit `e5778edb4cbac71e359ea375f38cf805aae32b0c`
- **Current status:** **UNFIXED** — upstream HEAD `f476836` still vulnerable; no fix released
- **Severity:** High
- **CVSS 3.1:** 8.2 `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`
- **CWE:** CWE-73 (External Control of File Name or Path), CWE-942 (Permissive Cross-domain Policy), CWE-306 (Missing Authentication for Critical Function, contributing)
- **CVE:** None assigned yet
- **GHSA:** None assigned yet
- **Reporter:** Teycir (independent)
- **Submission channel:** Email to `evermind@shanda.com` per `SECURITY.md` (GitHub private advisory not enabled on the repo), 2026-11-20T16:36:50Z

## Summary

EverOS is a local-first agent-memory service. Its `SECURITY.md` declares "HTTP API exposure to untrusted network" out of scope and documents that the API has no built-in authentication. This advisory tests whether that threat model survives a browser: an arbitrary web page is not "the network", but it can issue cross-origin requests to `127.0.0.1`.

Two independent defaults combine into full local-file exfiltration:

1. **Root cause A — unrestricted `file://` ingestion.** `POST /api/v2/memory/add` accepts a `ContentItem` with `uri: file:///...`. With the default `file_uri_allow_dirs = []`, any file readable by the EverOS process is hydrated, parsed, and its text is stored as `parsed_content` and returned by the search API.
2. **Root cause B — permissive CORS on an unauthenticated API.** CORS defaults are `allow_origins=["*"]` **and** `allow_credentials=True`. For cross-origin requests Starlette reflects the `Origin` and returns `Access-Control-Allow-Credentials: true`, so any website can call the unauthenticated API and read the responses.

Result, demonstrated end-to-end in a real browser: a victim visiting a malicious page has arbitrary local files (up to 50 MB per item) read by EverOS and exfiltrated to an attacker-controlled collector, and attacker-chosen memory written — with no prompt and no victim interaction beyond loading the page.

## Affected endpoints

| Endpoint | Guard | Problem |
|---|---|---|
| `POST /api/v2/memory/add` | None (no auth) | Accepts `uri: file:///...`; `file_uri_allow_dirs=[]` allows any readable file |
| `POST /api/v2/memory/search` | None (no auth) | Returns `parsed_content` verbatim, including file contents ingested via root cause A |
| CORS (all `/api/v1/*`, `/api/v2/*`) | `allow_origins=["*"]`, `allow_credentials=True` | Any origin can read cross-origin responses |

## Root cause

`src/everos/config/settings.py:610`: `file_uri_allow_dirs: list[str] = []` — empty list is treated as "allow any readable file" in `src/everos/component/parser/input.py:105` (`if allow and not any(...)` skips the check when the list is empty).

`src/everos/entrypoints/api/middleware/cors.py`: `DEFAULT_CORS_ORIGINS = ["*"]`, `DEFAULT_CORS_ALLOW_CREDENTIALS = True`.

The API has no authentication by documented design, so CORS is the only gate between an arbitrary website and the loopback API.

## Proof of concept

Full transcript and hashes: `evidence/` and `report.md`.
Reproducer: `poc/setup_local.sh` then `poc/exploit.py` or `poc/browser_driveby.sh`.

```http
POST /api/v2/memory/add HTTP/1.1
Origin: http://evil.example:8000
Content-Type: application/json

{"uri": "file:///etc/hostname", "type": "text", "ext": "txt"}

HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://evil.example:8000
Access-Control-Allow-Credentials: true
```

```http
POST /api/v2/memory/search HTTP/1.1
Origin: http://evil.example:8000
Content-Type: application/json

{"query": "hostname"}

HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://evil.example:8000
Access-Control-Allow-Credentials: true
{"results":[{"content":[{"type":"text","parsed_content":"teycir-G5-KF5"}]}]}
```

Browser verification: headless Chromium from `http://evil.example:8000` (mapped to loopback via `--host-resolver-rules`) read `file:///etc/hostname`, obtained `teycir-G5-KF5`, and POSTed it to an attacker-controlled collector.

## Fix verification — upstream HEAD `f476836` (2026-11-23 17:23 UTC)

Cloned `https://github.com/EverMind-AI/EverOS.git` at HEAD `f476836`.
Inspected `src/everos/config/settings.py`, `src/everos/entrypoints/api/middleware/cors.py`, `src/everos/component/parser/input.py`.

| Finding | Status | Detail |
|---|---|---|
| F-01 — Browser-mediated local file exfiltration (High 8.2) | **UNFIXED** | `file_uri_allow_dirs` still defaults to `[]` (allow any); CORS still `allow_origins=["*"]` + `allow_credentials=True`; `_validated_file_path` skips allowlist check when empty. No commits after v1.7.1 touch these settings. No v1.7.2 release. |

**Conclusion: F-01 remains fully exploitable.** No fix released, no CVE/GHSA assigned yet.

## Remediation

- Default `file_uri_allow_dirs` to deny-all when unset; require explicit opt-in directories; resolve symlinks before the check.
- Default CORS to no origins and `allow_credentials=False`; require explicit allowlists.
- Introduce per-instance bearer token authentication for all API routes; never rely on loopback binding as authorization.
- Do not return `parsed_content` or content bytes in search/list DTOs; return references only.
- Reject `Origin: null` and non-allowlisted origins before routing.

## References

- Full report: `report.md`
- Evidence: `evidence/`
- PoC: `poc/`
- Disclosure contact log: `disclosure/contact-log.md`
- CWE-73: https://cwe.mitre.org/data/definitions/73.html
- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- OWASP API1:2023 BOLA: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
