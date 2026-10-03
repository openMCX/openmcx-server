# Specifications followed

The versions the openMCX code follows (docs/CODING_STYLE.md section 2.2). A file header names the specifications of
that file; the versions are these unless the header says otherwise. The texts are kept outside the repositories
(ETSI copyright), as `~/openMCX/specs/ts_<number>.txt`, converted from the ETSI PDFs; `tools/check-spec-refs` reads
them there.

## 3GPP (Release 19, as published by ETSI)

| Specification | Title (short) | Version | Date |
|---|---|---|---|
| TS 23.280 | Common functional architecture for MC services | V19.10.1 | 2026-05 |
| TS 23.281 | MCVideo functional architecture | V19.10.0 | 2026-04 |
| TS 23.282 | MCData functional architecture | V19.10.0 | 2026-04 |
| TS 23.379 | MCPTT functional architecture | V19.11.0 | 2026-08 |
| TS 24.281 | MCVideo signalling control | V19.6.0 | 2026-08 |
| TS 24.282 | MCData signalling control | V19.7.0 | 2026-08 |
| TS 24.379 | MCPTT call control | V19.7.0 | 2026-08 |
| TS 24.380 | MCPTT media plane control (floor control) | V19.2.0 | 2026-08 |
| TS 24.481 | MC services group management | V19.3.0 | 2026-07 |
| TS 24.482 | MC services identity management | V19.1.0 | 2026-07 |
| TS 24.483 | MC services management object | V19.2.0 | 2026-01 |
| TS 24.484 | MC services configuration management | V19.6.0 | 2026-07 |
| TS 24.581 | MCVideo media plane control (transmission control) | V19.2.0 | 2026-08 |
| TS 24.582 | MCData media plane control | V19.0.0 | 2025-10 |
| TS 26.281 | MCVideo codecs and media handling | V19.0.0 | 2025-10 |
| TS 33.180 | Security of the MC services | V19.4.0 | 2026-02 |

## Cited, text not yet kept locally

References to these are written in the same form but not yet checked against the text:

| Specification | Title (short) |
|---|---|
| TS 24.545 | SEAL location management |
| TS 24.229 | IP multimedia call control based on SIP and SDP (IMS) |
| TS 29.283 | Diameter data management applications |
| TS 23.032 | Universal geographical area description (GAD) |
| TS 23.434 | SEAL functional architecture |

## IETF

RFCs are cited by number and section (`RFC 3261 section 10.2`); their text is stable and not pinned.
