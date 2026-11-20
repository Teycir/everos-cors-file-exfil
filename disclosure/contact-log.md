# Disclosure contact log — EverOS CORS / file:// exfiltration (F-01)

Target: EverOS 1.7.1 (`EverMind-AI/EverOS`, commit `e5778edb4cbac71e359ea375f38cf805aae32b0c`)
Channel: email per `SECURITY.md` — private vulnerability reporting is NOT enabled on the repo.

| # | Contact | Address | Purpose | Status | Date (UTC) | Reference |
|---|---------|---------|---------|--------|------------|-----------|
| 1 | EverMind AI (EverOS maintainers) | evermind@shanda.com | Vendor notice + report + evidence zip | sent | 2026-11-20T16:36:50Z | Message-ID `<9A3MkanWMWkzoljMrJwoZ4i9h2FILM3S1GTdPGBahFvUXOlxABULGaxnVBHDk-lqYUyyBwnrs-nS8XBq1H7y2FaQC2v_RbUOUmL8LEE-f70=@protonmail.com>`; raw copy `sent/20261120T163650Z-vendor-notice-everos.eml` |

## Sent package

- Attachment: `everos-cors-file-exfil-evidence.zip`
- Zip SHA-256: `fd739c2565bb627dc28de795be175f4052283166f804782face61eec0b76b446`
- Contents: `report.md` (final, single chained finding F-01, CVSS 8.2), `evidence/` raw captures, `poc/` scripts + browser exfil logs, `sha256sums.txt` (49 entries)
- Repo: https://github.com/Teycir/everos-cors-file-exfil (private)

## Vendor expectations (from SECURITY.md)

- Acknowledgement within 5 business days (~by 2026-11-27).
- Fix or mitigation targeted before any public disclosure.
- Confirmed issues published as GitHub Security Advisories; reporter credited unless opted out.
- Threat-model note: untrusted *network* exposure of the API is out of scope — the report's argument is browser-mediated access (victim's browser as the path), which does not require network exposure. Be ready to reiterate this if triage pushes back.

## Watch items

- [ ] Vendor acknowledgement
- [ ] CVE/GHSA assignment — record here and update `report.md` if assigned
- [ ] Fix release — re-verify against `poc/` before any public disclosure
- [ ] Disclosure deadline: per SECURITY.md they aim to fix before public disclosure; no fixed date given — keep private until fix ships or mutual agreement
