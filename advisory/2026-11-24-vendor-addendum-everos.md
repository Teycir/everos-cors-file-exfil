To: evermind@shanda.com
Subject: EverOS security follow-up — 2 additional verified findings (SSRF, tenant IDOR)

Hello,

Following our report of 2026-11-20 (CORS + file:// local file exfiltration,
F-01), we completed a second audit pass over upstream main at commit
6ac3898e7755dfc41002bfdc9704279009a82b81 (2026-11-24). We verified two
additional findings against a live local instance of the EverOS 1.7.1 line.
Both have working PoCs and captured evidence.

1. EVEROS-2026-02 — Unauthenticated SSRF via `uri` content items (High,
   CVSS 7.5, CWE-918). POST /api/v2/memory/add accepts arbitrary http(s)
   URIs; everalgo-parser fetches them with follow_redirects=True and no
   private/loopback/link-local filtering (its docs state the caller owns
   this). Fetched content is stored and returned by /memory/search.
   Demonstrated: direct loopback fetch, 302-redirect to a second internal
   host, and gopher:// rejection as a negative control.

2. EVEROS-2026-03 — Knowledge document IDOR (Medium-High, CWE-639/862).
   doc_id/topic_id-keyed operations ignore app_id/project_id scope;
   KnowledgeCatalog lookups take no scope argument and doc_id is the sole
   primary key. Demonstrated: a document uploaded under tenantA was read
   (HTTP 200) and deleted (HTTP 204) using tenantB scope parameters, while
   scoped list endpoints correctly isolate.

(We also noted several lower-severity hardening items — missing Origin
checks on mutating routes, unauthenticated /cascade/quiesce, and absolute
paths in knowledge responses — documented in the same report but not
pursued as separate vulnerabilities.)

Full technical report, request/response evidence, sha256 manifest, and
runnable PoCs:
https://github.com/Teycir/everos-cors-file-exfil (audit-2026-11-24/)

We would appreciate acknowledgement and would like to coordinate disclosure
timing for these findings together with F-01. Happy to share the raw
evidence archive on request.

Reporter: Teycir
