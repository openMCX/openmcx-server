# MCPTT Phase 1 reference-point inventory

Status: architectural mapping, not implemented-interface coverage.

Baseline: supplied TS 23.280 V19.10.1 §7.3.1.2 and §§7.4–7.5, supplemented by
TS 23.379 V19.11.0 §7.5. Read alongside the
architecture.

## Common application plane

| Reference point | Endpoints | Phase 1 disposition |
|---|---|---|
| CSC-1 | Identity management client ↔ IdMS | User authentication; direct HTTPS, outside HTTP proxy |
| CSC-2 | Group management client ↔ GMS | On-network group configuration |
| CSC-3 | MC service server ↔ GMS | Group information/policy and applicable dynamic data |
| CSC-4 | Configuration client ↔ CMS | On-network configuration |
| CSC-5 | MC service server ↔ CMS | Service configuration |
| CSC-7 | GMS ↔ GMS | Multiple group-management servers; not used |
| CSC-8 | Key management client ↔ KMS | Client key management; permitted direct or proxy HTTPS path |
| CSC-9 | MC service server ↔ KMS | Server key management |
| CSC-10 | GMS ↔ KMS | Group key-management relationship |
| CSC-11 / CSC-12 | Configuration/group clients ↔ respective servers | Off-network configuration paths; outside IP on-network milestone |
| CSC-13 | CMS ↔ MC service user database | Application profile configuration |
| CSC-14 | Location client ↔ LMS | UE-supplied location; independent of 5G SA |
| CSC-15 | LMS ↔ MC service server | Application use of location |
| CSC-16 | GMS ↔ GMS in different MC systems | Not in this edition |
| CSC-17 | CMS ↔ CMS in different MC systems | Not in this edition |
| MCX-1 | MC service servers | Within one system, between the participating and controlling servers; gateway paths are not in this edition |
| CSC-19 | GMS ↔ MC gateway | Not in this edition |
| CSC-20 | CMS ↔ MC gateway | Not in this edition |
| CSC-21 | MC gateways in different MC systems | Not in this edition |
| CSC-22 | LMS ↔ LMS in different MC systems | Not in this edition |
| CSC-23 | LMS ↔ MC gateway | Not in this edition |
| CSC-24 | LMS ↔ CMS | Location-related configuration |
| CSC-25 | GMS ↔ CMS | Explicitly out of scope of this specification version (§7.5.2.25a); no protocol is invented |
| ACM-1 / ACM-2 / ACM-3 | ACM client/server, peer ACM server | Optional administrative configuration feature; not enabled |
| Le | LMS ↔ 3GPP core LCS | Not used in the IP lab |
| REC-1 through REC-5 | Recording/replay and supporting entities | Recording/replay outside first milestone; REC-5 is out of scope of this specification version |

There is no invented CSC-6 or CSC-18 service. Use the reference-point definitions
and void clauses as published rather than filling gaps in numbering.

## Signalling control plane

| Reference point | Endpoints | Governing relationship / deployment |
|---|---|---|
| SIP-1 | Signalling UA ↔ SIP core | Profiled Gm; registration, security, events, session/media negotiation |
| SIP-2 | SIP core ↔ SIP AS | ISC/Ma; registration notification, application signalling and events |
| SIP-3 | SIP core ↔ SIP core | Not in this edition (inter-system SIP signalling) |
| HTTP-1 | HTTP client ↔ HTTP proxy | Client-facing TLS connection |
| HTTP-2 | HTTP proxy ↔ HTTP server | Proxy-to-service path within its trust model |
| HTTP-3 | HTTP proxy ↔ HTTP proxy | Not in this edition (inter-system HTTP) |
| AAA-1 | SIP database ↔ SIP core | Required compatibility if exposed; private DB access is not an AAA protocol implementation |
| AAA-2 | SIP core ↔ Diameter proxy | Only when the deployment uses this Diameter relationship |

Application reference points and signalling reference points are not alternative
names for containers. For example, MCPTT-1 traverses SIP-1 and SIP-2; CSC-7 can
use SIP-2. See figure 7.3.1.2-3 and its notes.

## MCPTT application plane

| Reference point | Endpoints | Phase 1 disposition |
|---|---|---|
| MCPTT-1 | MCPTT client ↔ MCPTT server | Call and service control under TS 24.379 |
| MCPTT-2 | MCPTT server ↔ MCPTT user database | Intra-network Diameter management application under TS 29.283 |
| MCPTT-3 | MCPTT server ↔ MCPTT server | Implemented: participating and controlling roles across the servers of one system |
| MCPTT-4 | Floor participant ↔ floor control server | Unicast floor control under TS 24.380 |
| MCPTT-5 / MCPTT-6 | MCPTT server ↔ EPS | Not deployed for the IP-only milestone |
| MCPTT-7 | UE media mixer ↔ media distribution function | Unicast speech path |
| MCPTT-8 / MCPTT-9 | Multicast media / floor endpoints | Not deployed for the unicast milestone |
| MCPTT-10 | MC gateways in different MCPTT systems | Not in this edition |
| IWF-1 | MCPTT server ↔ legacy interworking function | Legacy-system interworking outside first milestone |

## Split servers

The participating and controlling functions of one MC system can run on separate servers (roles `participating`,
`controlling` and `both`). They exchange SIP directly over MCPTT-3 with configured, trusted peers; floor and media
pass through each user's participating server. Interconnection of two MC systems, MC gateway servers and migration
are not in this edition.
