To: evermind@shanda.com
Subject: EverOS security — follow-up: 2 additional verified vulnerabilities (SSRF, tenant IDOR)

Hello,

This is a follow-up to our vulnerability report sent on 2026-11-20
("EverOS — unauthenticated websites can exfiltrate arbitrary local files
via file:// ingestion and permissive CORS"). We have not received an
acknowledgement; your SECURITY.md commits to a response within 5 business
days, so we wanted to check the report reached the right channel.

Since then we completed a second audit pass over upstream main at commit
6ac3898e7755dfc41002bfdc9704279009a82b81 (2026-11-24). We verified two
additional findings against a live local instance of the EverOS 1.7.1
line. Both have working PoCs and captured request/response evidence.

1. EVEROS-2026-02 — Unauthenticated SSRF via `uri` content items
   (High, CVSS 3.1 7.4 — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N; 8.6 if the
   API is network-exposed, CWE-918).
   POST /api/v2/memory/add accepts arbitrary http(s) URIs; everalgo-parser
   fetches them with follow_redirects=True and no private/loopback/
   link-local filtering (its docs state the caller owns this policy, and
   EverOS sets none). Fetched content is stored and returned by
   /memory/search. Demonstrated: direct loopback fetch, 302-redirect to a
   second internal host, and gopher:// rejection as a negative control.

2. EVEROS-2026-03 — Knowledge document IDOR (Medium, CVSS 3.1 6.8 —
   AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N; 9.1 if a proxy maps tenants to
   app_id/project_id, CWE-639/CWE-862).
   doc_id/topic_id-keyed operations ignore app_id/project_id scope;
   KnowledgeCatalog lookups take no scope argument and doc_id is the sole
   primary key. Demonstrated: a document uploaded under tenantA was read
   (HTTP 200) and deleted (HTTP 204) using tenantB scope parameters, while
   scoped list endpoints correctly isolate — isolation is intended but
   bypassed on doc-keyed operations.

(We also documented several lower-severity hardening items — missing
Origin checks on mutating routes, unauthenticated /cascade/quiesce, and
absolute paths in knowledge responses — in the same report but are not
pursuing them as separate vulnerabilities.)

Full technical report, request/response evidence, sha256 manifest, and
runnable PoCs:
https://github.com/Teycir/everos-cors-file-exfil (audit-2026-11-24/)

We would appreciate acknowledgement of both emails and would like to
coordinate disclosure timing for all three findings together. Happy to
share the raw evidence archives on request.

Reporter: Teycir
