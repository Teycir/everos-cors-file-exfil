# EverOS — Unauthenticated server-side request forgery via `uri` content items, with response readback (EVEROS-2026-02)

## Severity

- **High** — CVSS 3.1 **7.5** — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N`
  - Calculator: https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N
  - `UI:R` because the practical remote path is a victim's browser (same reachability mechanism as EVEROS-2026-01); score rises if the API is bound to a non-loopback interface.
- **CWE:** CWE-918 (Server-Side Request Forgery)

## Affected product

EverOS @ `6ac3898e7755dfc41002bfdc9704279009a82b81` (origin/main, 2026-11-24; v1.7.1 line and later). Requires the `[multimodal]` parser configured — the same precondition as EVEROS-2026-01. The API has no authentication.

## Summary

`POST /api/v2/memory/add` accepts a content item with an arbitrary `uri`. For `http(s)` URIs, EverOS delegates fetching to `everalgo-parser`, which retrieves the URL with `httpx` (`follow_redirects=True`) and **explicitly does not block private, loopback, or link-local addresses** — its own documentation states the caller is responsible for filtering untrusted URIs. EverOS performs no such filtering: there is no scheme allowlist beyond what everalgo enforces (`http`/`https` only), no host or IP policy, and no response-size cap.

The fetched response body is parsed and stored as `parsed_content`, which `POST /api/v2/memory/search` returns to the caller — so this is not blind SSRF: response content is exfiltrated through the memory API.

## Verified attack paths (live, 2026-11-24T18:31Z)

| `uri` submitted | Result |
|---|---|
| `http://127.0.0.1:18099/canary.txt` | Server fetched it (listener log); `parsed_content` returned `SSRF-CANARY-7f3a9c internal-only-marker` via `/memory/search` |
| `http://127.0.0.1:18098/redir` (HTTP 302 → `http://127.0.0.1:18099/canary2.txt`) | **Redirect followed to a second internal host**; second canary content exfiltrated |
| `gopher://127.0.0.1:18099/_x` | Rejected (`UNSUPPORTED_FORMAT`) — only http(s) is fetched; negative control |

Requests were sent cross-origin (`Origin: http://evil.example:8000`) with `Access-Control-Allow-Credentials: true` reflected — the EVEROS-2026-01 CORS defect makes this reachable from any website the victim visits, not only local processes.

## Impact

- Reach internal HTTP services: loopback admin panels, RFC-1918 hosts, link-local addresses, and cloud metadata endpoints (`169.254.169.254`).
- Exfiltrate response content through the searchable memory store.
- No authentication, no rate limit, no fetch timeout shorter than 30 s, no size cap (large responses are buffered fully in memory — secondary DoS angle).

## Steps to reproduce

Full transcripts, listener logs, the stub-provider lab recipe, and runnable scripts are in the report repository:

**https://github.com/Teycir/everos-cors-file-exfil** → `audit-2026-11-24/` (`report.md`, `evidence/`, `pocs/ssrf.sh`, `pocs/stub_llm.py`, `pocs/redir_server.py`, `SHA256SUMS`)

Minimal reproduction (local EverOS with `[multimodal]` configured):

```bash
# canary server on :18099 serving canary.txt, then:
curl -s -X POST http://127.0.0.1:18777/api/v2/memory/add \
  -H 'Content-Type: application/json' -H 'Origin: http://evil.example:8000' \
  -d '{"session_id":"ssrf","messages":[{"sender_id":"u1","role":"user","timestamp":1,"content":[{"type":"html","uri":"http://127.0.0.1:18099/canary.txt"}]}],"defer_extraction":true}'

curl -s -X POST http://127.0.0.1:18777/api/v2/memory/search \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"attacker","query":"canary","method":"keyword","filters":{"session_id":"ssrf"}}'
# -> data.unprocessed_messages[0].content[0].parsed_content contains the canary body
```

## Root cause locations

- `src/everos/entrypoints/api/schemas/memorize.py:36-42` — `ContentItemDTO.uri`, no validation
- `src/everos/component/parser/input.py:47-49` — every non-`file` URI wrapped verbatim in `RawFile(uri=...)`
- `src/everos/memory/extract/parser/enrich.py` — `aparse_file` → `everalgo.parser.aparse` → `everalgo.utils.fetch_uri`
- `everalgo/utils/http.py:19-51` — httpx fetch, `follow_redirects=True`, no private-IP filtering (documented as caller's responsibility)

## Suggested remediation

- In `build_raw_file`/`to_raw_file`, enforce a URI egress policy before delegating: scheme allowlist (`http`/`https`), optional host allowlist, and deny loopback/RFC-1918/link-local/metadata IPs after DNS resolution (re-check after redirects, or disable redirect following for untrusted URIs).
- Add a fetch size cap and shorter timeout for caller-supplied URIs.
- Consider an `[multimodal] uri_allow_hosts` setting mirroring `file_uri_allow_dirs`.

## Disclosure status

- Reporter: Teycir. LLM-assisted analysis/drafting; all exploitation executed and verified by the reporter against a live local build.
- Vendor contact for this finding: _pending_ (see report repo `disclosure/contact-log.md`).
- Related: EVEROS-2026-01 (CORS + `file://` exfil) is the delivery mechanism that makes this reachable from a browser; the SSRF itself is a distinct root cause (missing egress policy).
