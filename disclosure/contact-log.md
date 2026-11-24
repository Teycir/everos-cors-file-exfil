# Disclosure contact log — EverOS CORS / file:// exfiltration (F-01)

Target: EverOS 1.7.1 (`EverMind-AI/EverOS`, commit `e5778edb4cbac71e359ea375f38cf805aae32b0c`)
Channel: email per `SECURITY.md` — private vulnerability reporting is NOT enabled on the repo.

| # | Contact | Address | Purpose | Status | Date (UTC) | Reference |
|---|---------|---------|---------|--------|------------|-----------|
| 1 | EverMind AI (EverOS maintainers) | evermind@shanda.com | Vendor notice + report + evidence zip | sent | 2026-11-20T16:36:50Z | Message-ID `<9A3MkanWMWkzoljMrJwoZ4i9h2FILM3S1GTdPGBahFvUXOlxABULGaxnVBHDk-lqYUyyBwnrs-nS8XBq1H7y2FaQC2v_RbUOUmL8LEE-f70=@protonmail.com>`; raw copy `sent/20261120T163650Z-vendor-notice-everos.eml` |
| 2 | VulnCheck | web form | CVE assignment request (F-01) | submitted | 2026-11-24 | Case ID `31e5306f-1a5c-4489-b142-4097d39c9af9`; package `submission/vulncheck/` |
| 3 | Vulners (CNA) | cna@vulners.com | CVE ID request (F-01, same body as VulnCheck) | sent | 2026-11-24T18:07:23Z | Message-ID `<WBeFwALsQ4y2S6GY2DqvKRIhJOprRs5nKeIVIQLPnmIj-VJ10NqTF7A3S7m_5i0J7Jlsu5ZcwQAOkuDoHGIzgcRWtVu6sfTAh-yWo3yEGkw=@protonmail.com>`; raw copy `submission/vulners/sent/20261124T180723Z-cna-vulners.eml` |
| 4 | EverMind AI (EverOS maintainers) | evermind@shanda.com | Follow-up: no ack received on #1; adds EVEROS-2026-02 (SSRF) + EVEROS-2026-03 (IDOR) | sent | 2026-11-24T19:07:27Z | Message-ID `<R9tdEAIZAtL3T4AOQc6xaz3bOjtzzWASmx1kP3P7i7efcR0t4viAniWNOeQj8szZbY4x9NVNoNIG0barH7AN43xFB_G_UFSGjJDjaIEa0-4=@protonmail.com>`; sha256 `1c526550…`; raw copy `advisory/sent/20261124T190727Z-vendor-followup-everos.eml`; body source `advisory/2026-11-24-vendor-addendum-everos.md` |
| 5 | VulnCheck | web form | CVE assignment request (EVEROS-2026-02 SSRF) | submitted | 2026-11-24 | Case ID `49f5469c-f397-4415-991a-64383446ec2b`; details `submission/vulncheck/details-EVEROS-2026-02.md` |
| 6 | VulnCheck | web form | CVE assignment request (EVEROS-2026-03 IDOR) | submitted | 2026-11-24 | Case ID `e8eefb98-f949-40e3-945f-33ca00a0eb6f`; details `submission/vulncheck/details-EVEROS-2026-03.md` |

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
