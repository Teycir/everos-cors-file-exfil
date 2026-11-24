# Disclosure timeline — EverOS F-01 (all UTC)

| Date | Event |
|---|---|
| 2026-11-20T15:37Z | Report finalised (F-01, CVSS 8.2) — `report.md`, `evidence/`, `poc/` |
| 2026-11-20T16:36:50Z | Vendor notice sent to `evermind@shanda.com` with evidence zip (SHA-256 `fd739c2565bb627dc28de795be175f4052283166f804782face61eec0b76b446`). Message-ID `<9A3MkanWMWkzoljMrJwoZ4i9h2FILM3S1GTdPGBahFvUXOlxABULGaxnVBHDk-lqYUyyBwnrs-nS8XBq1H7y2FaQC2v_RbUOUmL8LEE-f70=@protonmail.com>`; raw `.eml` archived at `../../disclosure/sent/20261120T163650Z-vendor-notice-everos.eml` |
| 2026-11-23T17:23Z | Upstream re-check: HEAD `f476836`, no fix |
| 2026-11-24 | Upstream re-check: HEAD `6ac3898` (24 commits past v1.7.1, latest tag still v1.7.1) — **no fix**; `file_uri_allow_dirs` still `[]`, CORS still `*`+credentials, no API auth |
| ~2026-11-27 | Vendor acknowledgement window (5 business days per SECURITY.md) closes |
| 2026-11-24 | **Submitted to VulnCheck** — case ID `31e5306f-1a5c-4489-b142-4097d39c9af9` |
| TBD | CVE/GHSA assignment — _pending_ |
