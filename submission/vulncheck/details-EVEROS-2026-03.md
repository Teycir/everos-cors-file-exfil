# EverOS — Knowledge document IDOR: `doc_id`/`topic_id` operations ignore tenant scope (EVEROS-2026-03)

## Severity

- **Medium** — CVSS 3.1 **6.8** — `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`
  - Calculator: https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N
  - `AC:H` because exploitation requires knowing a `doc_id` (48-bit, unguessable but leakable via search hits, logs, URLs). `UI:R` because the practical remote path is a victim's browser (CORS defect, EVEROS-2026-01).
  - **Alternate scenarios:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1** (Critical) if a reverse proxy maps tenants to `app_id`/`project_id` and doc IDs are known/enumerable; `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.4** for a purely local attacker.
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-862 (Missing Authorization)

## Affected product

EverOS @ `6ac3898e7755dfc41002bfdc9704279009a82b81` (origin/main, 2026-11-24). Knowledge feature enabled (requires `[embedding]` + `[rerank]` providers configured).

## Summary

EverOS scopes knowledge data by caller-supplied `app_id`/`project_id`. List endpoints enforce the scope, and `docs/knowledge.md` claims "data is fully isolated per tenant pair". However, every operation keyed by `doc_id` or `topic_id` **ignores scope entirely**:

- `KnowledgeCatalog.get_document(doc_id)` / `get_topics(...)` accept no scope argument (`src/everos/memory/ports/stores.py:714-747`); `doc_id` is the sole PRIMARY KEY of `knowledge_documents`.
- `KnowledgeService.get_document` / `get_topic` accept `app_id`/`project_id` parameters and silently drop them (`src/everos/service/knowledge/__init__.py:266-306` → `_queries.py:42-60`).
- Mutations (`replace`, `delete`, `patch`) resolve the document's *real* scope from the catalog record, not the caller's — so a caller with the wrong scope can still delete or overwrite the document.

Net effect: anyone who learns a `doc_id` (48-bit `d_<hex12>`, leaked via search hits, logs, URLs, `md_path`s, or any scope they can list) can read the full document detail — including the absolute `original_file_path` — and delete or replace it, regardless of tenant scope. Combined with the API's lack of authentication (by design) and permissive CORS, this is reachable from any local process or any website in the victim's browser.

## Verified (live, 2026-11-24T18:34Z)

Document `d_0d264fe85a89` uploaded under `app_id=tenantA&project_id=tenantA`:

| Request | Result |
|---|---|
| `GET /knowledge/documents/{id}?app_id=tenantB&project_id=tenantB` | **HTTP 200** — full detail incl. `original_file_path` |
| `GET /knowledge/documents/{id}` (no scope → `default`) | **HTTP 200** |
| `GET /knowledge/documents?app_id=tenantB...` (list) | `documents: []` — scoped list correctly isolates |
| `GET /knowledge/documents?app_id=tenantA...` (list) | contains `d_0d264fe85a89` |
| `DELETE /knowledge/documents/{id}?app_id=tenantB&project_id=tenantB` | **HTTP 204** — document tombstoned |

Evidence: `audit-2026-11-24/evidence/idor_get_scopes.txt`, `idor_list_scopes.txt`, `idor_delete_wrong_scope.txt`, `catalog_rows.txt` (sqlite ground truth shows real scope `tenantA/tenantA`).

## Impact

- Cross-tenant read of document metadata, summaries, topic content, and stored-original paths.
- Cross-tenant **delete** and **replace/patch** — integrity and availability loss.
- In deployments where a reverse proxy maps tenants to `app_id`/`project_id`, this is a direct authorization bypass; in the default single-user model it breaks the documented tenant-isolation invariant.

## Steps to reproduce

Report repository: **https://github.com/Teycir/everos-cors-file-exfil** → `audit-2026-11-24/` (`report.md`, `evidence/`, `pocs/idor.sh`).

```bash
# upload (scope is FORM fields on upload, QUERY params on read/delete)
curl -X POST http://127.0.0.1:18777/api/v2/knowledge/documents \
  -F 'file=@doc.md' -F 'title=Secret' -F 'app_id=tenantA' -F 'project_id=tenantA'
# -> doc_id d_<hex12>; wait for cascade catalog indexing (startup scan catches up)

# read with wrong scope -> 200
curl 'http://127.0.0.1:18777/api/v2/knowledge/documents/<doc_id>?app_id=tenantB&project_id=tenantB'
# delete with wrong scope -> 204
curl -X DELETE 'http://127.0.0.1:18777/api/v2/knowledge/documents/<doc_id>?app_id=tenantB&project_id=tenantB'
```

## Suggested remediation

- Thread `app_id`/`project_id` through `KnowledgeCatalog.get_document`/`get_topics` (or verify `document.app_id == app_id and document.project_id == project_id` → 404) in `_queries.get_document`/`get_topic`.
- Apply the same scope check in `DocumentManager.replace`/`delete`/`patch` before acting on the resolved document.
- Validate read-route scope IDs with the same `PATH_SAFE_CHARSET` used on write routes (currently bare `str` — hardening gap, no injection found today).

## Disclosure status

- Reporter: Teycir. LLM-assisted analysis/drafting; exploitation verified by the reporter against a live local build.
- Vendor contact for this finding: _pending_.
- Related: EVEROS-2026-01 supplies browser reachability; this finding is a distinct authorization flaw.
