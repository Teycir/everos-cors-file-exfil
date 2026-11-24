To: evermind@shanda.com
Subject: EverOS security follow-up — 5 additional verified findings (SSRF, tenant IDOR, CSRF, DoS, path disclosure)

Hello,

Following our report of 2026-11-20 (CORS + file:// local file exfiltration,
F-01), we completed a second audit pass over upstream main at commit
6ac3898e7755dfc41002bfdc9704279009a82b81 (2026-11-24). We verified the
following additional findings against a live local instance of EverOS 1.7.1
line code. All have working PoCs and captured evidence.

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

3. EVEROS-2026-04 — Missing Origin validation on all mutating routes
   (Medium, CWE-352). Only POST /purge checks Origin vs Host; every other
   state-changing route lacks it, so the permissive CORS defaults also
   enable cross-site writes/deletes, not just reads.

4. EVEROS-2026-05 — Unauthenticated POST /cascade/quiesce permanently stops
   indexing until process restart (Medium-Low, CWE-306/400). Verified:
   single POST returned {"quiesced":true} and the index projection was
   emptied.

5. EVEROS-2026-06 — Absolute server filesystem paths disclosed in
   knowledge API responses via original_file_path (Low, CWE-200).

Full technical report, request/response evidence, sha256 manifest, and
runnable PoCs:
https://github.com/Teycir/everos-cors-file-exfil (audit-2026-11-24/)

We would appreciate acknowledgement and would like to coordinate disclosure
timing for these findings together with F-01. Happy to share the raw
evidence archive on request.

Reporter: Teycir
