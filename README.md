# EverOS CORS / `file://` Local File Exfiltration (F-01)

EverOS 1.7.1 (Python/FastAPI) combines two insecure defaults into browser-mediated local file disclosure:
- **Root cause A** — `file_uri_allow_dirs` defaults to `[]`, which the code treats as "allow any readable file".
- **Root cause B** — CORS defaults to `allow_origins=["*"]` + `allow_credentials=True` on an unauthenticated API.

Any website a victim visits can read arbitrary local files (up to 50 MB/item) through `POST /api/v2/memory/add` + `POST /api/v2/memory/search`, and write attacker-chosen memories. Demonstrated end-to-end in headless Chromium from a cross-origin hostname mapped to loopback.

## Report metadata

| Field | Value |
|---|---|
| Target | EverOS 1.7.1 (`EverMind-AI/EverOS`), commit `e5778edb4cbac71e359ea375f38cf805aae32b0c` |
| Severity | High — CVSS 3.1 8.2 (`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`) |
| CWE | CWE-73, CWE-942, CWE-306 (contributing) |
| Advisory | none assigned yet — reported privately to `evermind@shanda.com` 2026-11-20 |
| Repo | `https://github.com/Teycir/everos-cors-file-exfil` (this repo) |
| Full report | `report.md` |
| PoC | `poc/` |

## Disclosure timeline

| Date (UTC) | Event |
|---|---|
| 2026-11-20 15:37 | Report finalised (F-01, CVSS 8.2) — `report.md`, `evidence/`, `poc/` |
| 2026-11-20 16:36 | Vendor notice sent to `evermind@shanda.com` with evidence zip (`fd739c25…`) |
| 2026-11-20 16:36 | This repo made public (report + evidence + PoC) |
| 2026-11-23 17:23 | Upstream re-checked: cloned `EverMind-AI/EverOS` at HEAD `f476836`; **no fix** for F-01 |
| 2026-11-24 | Re-verified at HEAD `6ac3898`: **no fix**. Submitted to VulnCheck — case `31e5306f-1a5c-4489-b142-4097d39c9af9` (see `submission/vulncheck/`) |

## Fix verification — upstream `EverMind-AI/EverOS`

Cloned `https://github.com/EverMind-AI/EverOS.git` at HEAD `f476836` (commit `feat(memtrace): add smartcomment execution tracing (#612)`, past v1.7.1 release `f1fa762`).
Re-verified 2026-11-24 at HEAD `6ac3898` (24 commits past v1.7.1, still no new tag).
Inspected `src/everos/config/settings.py`, `src/everos/entrypoints/api/middleware/cors.py`, `src/everos/component/parser/input.py`.

| Setting / file | Value at HEAD `f476836` | Value at HEAD `6ac3898` (2026-11-24) | Fixed? |
|---|---|---|---|
| `file_uri_allow_dirs` default (`settings.py:610`) | `[]` — empty = allow any readable file | `[]` — unchanged | **NO** |
| `file_uri_max_bytes` (`settings.py`) | `50 * 1024 * 1024` | `50 * 1024 * 1024` | N/A (size cap, not the issue) |
| `DEFAULT_CORS_ORIGINS` (`cors.py`) | `["*"]` | `["*"]` — file untouched since v1.7.1 | **NO** |
| `DEFAULT_CORS_ALLOW_CREDENTIALS` (`cors.py`) | `True` | `True` | **NO** |
| `_validated_file_path` allowlist check (`input.py:106`) | `if allow and not any(...)` — empty allowlist skips the check | identical — `input.py` has zero diff since v1.7.1 | **NO** |
| Any authentication on API routes | none | none — no auth dependency anywhere in `entrypoints/api` | **NO** |
| Any commit after v1.7.1 touching CORS / `file_uri` / `input.py` | None | None (24 commits; `settings.py` churn is unrelated features) | **NO** |

No commits between v1.7.1 (`f1fa762`) and HEAD (`6ac3898`) touch `cors.py`, the `file_uri_allow_dirs` validation path, or `input.py`. The latest tag is still v1.7.1 — there is no v1.7.2.

**Conclusion: F-01 remains fully exploitable at HEAD `6ac3898`.** No fix released, no CVE/GHSA assigned yet.

## Affected

- EverOS 1.7.1 (commit `e5778edb4cbac71e359ea375f38cf805aae32b0c`), default configuration
- Current main HEAD `f476836` — unfixed
- Configuration: HTTP API enabled, `[multimodal]` parser configured (required for `file://` hydration)

## Proven chain (low-privilege, no authentication)

1. Victim loads an attacker-controlled page in a browser on the same machine as EverOS.
2. Browser issues cross-origin preflight + data requests to `127.0.0.1:18777`.
3. CORS reflects `Origin` and returns `Access-Control-Allow-Credentials: true` (root cause B).
4. `POST /api/v2/memory/add` with `{"uri": "file:///etc/hostname", "type": "text", "ext": "txt"}` reads the file (root cause A).
5. `parsed_content` is stored and returned by `POST /api/v2/memory/search`, exfiltrated cross-origin.

Negative controls verified: allowlist set → symlink, `..` traversal, `file://localhost/` all rejected; `/etc/shadow` unreadable → HTTP 500.

## Remediation (short)

- Default `file_uri_allow_dirs` to deny-all when unset; require explicit opt-in directories; resolve symlinks before the check.
- Default CORS to no origins and `allow_credentials=False`; require explicit allowlists.
- Introduce per-instance bearer token authentication for all API routes; never rely on loopback binding as authorization.
- Do not return `parsed_content` or content bytes in search/list DTOs; return references only.
- Reject `Origin: null` and non-allowlisted origins before routing.
