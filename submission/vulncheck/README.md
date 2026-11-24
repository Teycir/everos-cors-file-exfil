# VulnCheck submission — EverOS F-01

Status: **submitted to VulnCheck 2026-11-24 — case ID `31e5306f-1a5c-4489-b142-4097d39c9af9`.**

- Finding: F-01 — unauthenticated websites can exfiltrate arbitrary local files via `file://` ingestion + permissive CORS (CVSS 8.2, CWE-73/942/306)
- Report repo: https://github.com/Teycir/everos-cors-file-exfil — **currently PRIVATE on GitHub** (details text references it as the repro package; flip public per coordinated-disclosure timing)
- Vendor contact: evermind@shanda.com, 2026-11-20T16:36:50Z (see `../../disclosure/contact-log.md`)

## Send gate

Vendor `SECURITY.md` commits to acknowledgement within 5 business days of
2026-11-20T16:36:50Z → window closes ~**2026-11-27**. Options:

- Wait for ack/no-ack, then submit (matches the mem0 precedent).
- Submit now with "Coordinate disclosure? = Yes — VulnCheck handles vendor
  outreach" if you want VulnCheck to take over coordination.

## Files

| File | Purpose |
|---|---|
| `form-answers.md` | Paste-ready value for every web-form field |
| `details-EVEROS-2026-01.md` | Body for the "Vulnerability Details" field |
| `EVEROS-2026-01.cve.json` | CVE 5.1 record draft (placeholders: CVE-2026-XXXXX, dates) |
| `timeline.md` | UTC disclosure timeline |
| `email-to-disclosure.txt` | Fallback channel body (disclosure@vulncheck.com) |
| `SHA256SUMS` | Integrity manifest for this directory |

## Checklist before submit

- [ ] `date -u` — decide on the 5-business-day vendor window (~2026-11-27)
- [ ] Report repo flipped to public on GitHub (currently PRIVATE)
- [ ] `sha256sum -c SHA256SUMS` passes here
- [ ] Turnstile captcha — user completes in browser
- [ ] Record VulnCheck case ID in `timeline.md` after submit
