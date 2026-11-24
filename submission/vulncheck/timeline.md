# Disclosure timeline — EverOS F-01 (all UTC)

| Date | Event |
|---|---|
| 2026-11-20T15:37Z | Report finalised (F-01, CVSS 8.2) — `report.md`, `evidence/`, `poc/` |
| 2026-11-20T16:36:50Z | Vendor notice sent to `evermind@shanda.com` with evidence zip (SHA-256 `fd739c2565bb627dc28de795be175f4052283166f804782face61eec0b76b446`). Message-ID `<9A3MkanWMWkzoljMrJwoZ4i9h2FILM3S1GTdPGBahFvUXOlxABULGaxnVBHDk-lqYUyyBwnrs-nS8XBq1H7y2FaQC2v_RbUOUmL8LEE-f70=@protonmail.com>`; raw `.eml` archived at `../../disclosure/sent/20261120T163650Z-vendor-notice-everos.eml` |
| 2026-11-23T17:23Z | Upstream re-check: HEAD `f476836`, no fix |
| 2026-11-24 | Upstream re-check: HEAD `6ac3898` (24 commits past v1.7.1, latest tag still v1.7.1) — **no fix**; `file_uri_allow_dirs` still `[]`, CORS still `*`+credentials, no API auth |
| ~2026-11-27 | Vendor acknowledgement window (5 business days per SECURITY.md) closes |
| 2026-11-24 | **Submitted to VulnCheck** — case ID `31e5306f-1a5c-4489-b142-4097d39c9af9` |
| 2026-11-24T18:07:23Z | **Sent to Vulners CNA** (`cna@vulners.com`) — same body as VulnCheck submission. Message-ID `<WBeFwALsQ4y2S6GY2DqvKRIhJOprRs5nKeIVIQLPnmIj-VJ10NqTF7A3S7m_5i0J7Jlsu5ZcwQAOkuDoHGIzgcRWtVu6sfTAh-yWo3yEGkw=@protonmail.com>`; raw copy `../vulners/sent/20261124T180723Z-cna-vulners.eml` (sha256 `7ed1d776…`) |
| 2026-11-24T19:07:27Z | Vendor follow-up sent to `evermind@shanda.com` — no ack on first notice; adds EVEROS-2026-02 (SSRF) + EVEROS-2026-03 (IDOR). Message-ID `<R9tdEAIZAtL3T4AOQc6xaz3bOjtzzWASmx1kP3P7i7efcR0t4viAniWNOeQj8szZbY4x9NVNoNIG0barH7AN43xFB_G_UFSGjJDjaIEa0-4=@protonmail.com>`; raw copy `../../advisory/sent/20261124T190727Z-vendor-followup-everos.eml` (sha256 `1c526550…`) |
| 2026-11-24 | **EVEROS-2026-02 (SSRF) submitted to VulnCheck** — case ID `49f5469c-f397-4415-991a-64383446ec2b` |
| 2026-11-24 | **EVEROS-2026-03 (IDOR) submitted to VulnCheck** — case ID `e8eefb98-f949-40e3-945f-33ca00a0eb6f` |
| TBD | CVE/GHSA assignment — _pending_ (F-01: `31e5306f…`; SSRF: `49f5469c…`; IDOR: `e8eefb98…`) |
