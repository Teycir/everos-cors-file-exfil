# VulnCheck web form — field values (EverOS F-01)

Source: <https://vulncheck.com/advisories/report>. Values are ready to paste.
**SUBMITTED 2026-11-24 — VulnCheck case ID `31e5306f-1a5c-4489-b142-4097d39c9af9`.** Kept for the record / any resubmission.

## Shared fields

| Field | Value |
|---|---|
| Name to Credit | Teycir |
| Email | teycir@users.noreply.github.com |
| GitHub Username | Teycir |
| On behalf of someone else? | No — I discovered this myself |
| Vendor name | EverMind AI |
| Product name | EverOS — local agent-memory service, HTTP API (Python/FastAPI), `EverMind-AI/EverOS` repository |
| Product URL | https://github.com/EverMind-AI/EverOS |
| Tested Version(s) | EverOS 1.7.1, commit `e5778edb4cbac71e359ea375f38cf805aae32b0c`. Re-verified unfixed at main HEAD `6ac3898e7755dfc41002bfdc9704279009a82b81` (2026-11-24; latest tag still v1.7.1). |
| Coordinate disclosure? | **Decision needed** — vendor's SECURITY.md commits to ack within 5 business days (~2026-11-27). If submitting before that window closes, choose "Yes — VulnCheck handles vendor outreach". If waiting for the window, either answer works; vendor was already contacted directly. |
| Already reported to supplier? | Yes — email to `evermind@shanda.com` (the channel designated in the project's `SECURITY.md`) on 2026-11-20T16:36:50Z with the full report + evidence archive (zip SHA-256 `fd739c2565bb627dc28de795be175f4052283166f804782face61eec0b76b446`). Private vulnerability reporting is not enabled on the repo. |
| Previously requested CVE from MITRE w/o response? | No |
| Already publicly disclosed? | **No** — keep this answer until the report repo is flipped public at send time; then answer honestly and the repo URL is already inside the Vulnerability Details text. NOTE: repo is currently PRIVATE on GitHub — flip to public before submitting (see checklist). |
| Generated with AI? | Yes — LLM assistant used for source analysis and report drafting; reporter executed and verified the PoC end-to-end in a real browser. |
| Validated on production code? | Yes — EverOS 1.7.1 release source built and run locally; exploit verified against the live HTTP API and in headless Chromium. |
| Shodan/Fofa query | N/A — self-hosted localhost software, no internet-wide fingerprint |
| Plan to publish on/after coordinated date? | Yes |

## Vulnerability Details

Paste the full contents of `details-EVEROS-2026-01.md` in this field.
It already contains: severity + CVSS 3.1 vector (8.2) + calculator link, CWE IDs,
affected product/versions, summary, attack path, impact, repro steps, the public
report-repo URL, suggested remediation, and the disclosure timeline.

## Request 2 — EVEROS-2026-02 (SSRF, High) — **SUBMITTED 2026-11-24**

**VulnCheck case ID: `49f5469c-f397-4415-991a-64383446ec2b`**

Shared fields: same as Request 1 (Name Teycir, teycir@users.noreply.github.com, GitHub Teycir,
vendor EverMind AI, product EverOS / https://github.com/EverMind-AI/EverOS,
tested version `EverOS @ 6ac3898e7755dfc41002bfdc9704279009a82b81` (origin/main, v1.7.1 line),
AI-assisted=Yes, validated on production code=Yes, Shodan/Fofa=N/A, plan to publish=Yes).

- **Vulnerability title/details:** paste `details-EVEROS-2026-02.md`
- **Already reported to supplier?** Yes — email to `evermind@shanda.com` on 2026-11-24T19:07:27Z (follow-up covering this finding; first vendor notice 2026-11-20T16:36:50Z). No acknowledgement received as of submission.
- **Coordinate disclosure?** Same decision as Request 1 — vendor contacted, no response; recommend "Yes — VulnCheck handles vendor outreach" if you want them to run point, or "No" since you've already done direct outreach.
- **Already publicly disclosed?** No — repo is public as of 2026-11-24; the details text links to it.

## Request 3 — EVEROS-2026-03 (IDOR, Medium) — **SUBMITTED 2026-11-24**

**VulnCheck case ID: `e8eefb98-f949-40e3-945f-33ca00a0eb6f`**

Shared fields: same as Request 1/2 (Name Teycir, teycir@users.noreply.github.com, GitHub Teycir,
vendor EverMind AI, product EverOS / https://github.com/EverMind-AI/EverOS,
tested version `EverOS @ 6ac3898e7755dfc41002bfdc9704279009a82b81` (origin/main, v1.7.1 line),
AI-assisted=Yes, validated on production code=Yes, Shodan/Fofa=N/A, plan to publish=Yes).

- **Vulnerability title/details:** paste `details-EVEROS-2026-03.md`
- **Already reported to supplier?** Yes — email to `evermind@shanda.com` on 2026-11-24T19:07:27Z (follow-up covering this finding; first vendor notice 2026-11-20T16:36:50Z). No acknowledgement received as of submission.
- **Coordinate disclosure?** Same as Request 2 — recommend "Yes — VulnCheck handles vendor outreach".
- **Already publicly disclosed?** No — repo is public as of 2026-11-24; the details text links to it.
