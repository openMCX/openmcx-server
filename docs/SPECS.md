# Specifications followed

The versions the OpenMCX code follows (docs/CODING_STYLE.md section 2.2). A file header names the specifications of
that file; the versions are these unless the header says otherwise. The texts are kept outside the repositories
(ETSI copyright), as `~/openMCX/specs/ts_<number>.txt`, converted from the ETSI PDFs, to check the clauses the code
cites against the text.

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
| TS 26.179 | MCPTT codecs and media handling | V19.0.0 | 2025-10 |
| TS 26.281 | MCVideo codecs and media handling | V19.0.0 | 2025-10 |
| TS 29.214 | Policy and charging control over Rx | V19.3.0 | 2026-02 |
| TS 33.180 | Security of the MC services | V19.4.0 | 2026-02 |

## Scope and interoperability (kept locally, not cited per clause)

The stage 1 requirements decide what the services offer; the Plugtests scenarios are how independent implementations
test against each other. Neither is followed clause by clause in the code.

| Specification | Title (short) | Version | Date |
|---|---|---|---|
| TS 22.280 | MC services common requirements (stage 1) | V19.7.0 | 2026-01 |
| TS 22.179 | MCPTT requirements (stage 1) | V19.3.0 | 2026-01 |
| TS 22.281 | MCVideo requirements (stage 1) | V19.0.0 | 2025-10 |
| TS 22.282 | MCData requirements (stage 1) | V19.0.0 | 2025-10 |
| ETSI TS 103 564 | Plugtests scenarios for mission critical services | V1.6.1 | 2024-04 |

## Cited, text not yet kept locally

References to these are written in the same form but not yet checked against the text:

| Specification | Title (short) |
|---|---|
| TS 24.545 | SEAL location management |
| TS 24.229 | IP multimedia call control based on SIP and SDP (IMS) |
| TS 29.283 | Diameter data management applications |
| TS 29.229 | Cx and Dx interfaces (Supported-Features AVP) |
| TS 29.213 | Policy and charging control signalling flows and QoS parameter mapping |
| ETSI TS 183 017 | Resource and admission control: DIAMETER protocol (Reservation-Priority AVP) |
| TS 23.032 | Universal geographical area description (GAD) |
| TS 23.434 | SEAL functional architecture |
| TS 29.514 | 5G policy authorization service (N5) |
| TS 29.500 | 5G service based architecture: technical realization |
| TS 29.510 / TS 29.513 | NRF services / policy and charging signalling flows (5G) |
| TS 23.501 / TS 23.503 | 5G system architecture / policy and charging control framework |
| TS 29.212 | Policy and charging control (Gx) |
| TS 29.061 / TS 29.273 | Interworking with packet data networks / EPS AAA interfaces |
| TS 33.210 / TS 33.220 | Network domain security / generic bootstrapping architecture |
| TS 23.289 | MC services over 5G system |
| TS 23.003 | Numbering, addressing and identification |

## IETF

RFCs are cited by number and section (`RFC 3261 section 10.2`); their text is stable and not pinned.
