# The openMCX features

Project openMCX is a working implementation of **3GPP Release 19 mission-critical services (MCX)** for an IP network: the
common service core, **MCPTT** (mission-critical push to talk), **MCData** (mission-critical data) and **MCVideo**
(mission-critical video), within one MC system. It runs as a set
of containers — a SIP core, application servers, common services and clients — and every feature listed here is
exercised by an automated scenario in a fresh lab, with the SIP and media captured and checked against the
specifications by decoders written independently of the implementation.

This page is the map of what the implementation supports. It is not a conformance claim: see
[what is not supported](#what-is-not-supported) and the per-feature coverage gaps linked from each test document.

- **Acceptance matrices** (clause-by-clause, with evidence): [MCPTT](architecture/mcptt-standards-and-acceptance.md),
  [MCData](architecture/mcdata-standards-and-acceptance.md), [MCVideo](architecture/mcvideo-standards-and-acceptance.md).
- **Test index**: [MCPTT](../tests/README.md), [MCData](../tests/MCDATA_TEST.md), [MCVideo](../tests/MCVIDEO_TEST.md).
- **Unimplemented items and why**: [blockers](development/unimplemented-blockers.md).

## Mission-critical services in Release 19

A mission-critical system gives emergency services and other critical users communication that ordinary telephony does
not: group calls that start in under a second, floor control so one person speaks at a time, emergency and
imminent-peril priority that pre-empts other traffic, and data services for messages, files and telemetry. 3GPP
specifies it as an IMS application: clients register with a SIP core and talk to application servers that hold the
group, floor and priority state.

| Layer | What it does | Specifications |
|---|---|---|
| Common services | Identity (IdMS), group management (GMS), configuration management (CMS), location (LMS), key management (KMS); group documents of TS 24.481 addressed by group ID, with the member-list authorisation of §7.2.12 and retrieval without members (§6.3.16) | TS 23.280, TS 24.481, TS 24.482, TS 24.484 |
| MCPTT | Group, private, broadcast, chat and ad hoc voice calls with floor control and priority | TS 23.379, TS 24.379, TS 24.380 |
| MCData | Short data (SDS), file distribution (FD), communication release, enhanced status, IP connectivity | TS 23.282, TS 24.282, TS 24.582 |
| Security | Identity binding, key distribution, protected media, end-to-end protected MCData payloads, and for MCData, CSK-protected signalling and encrypted sensitive XML content | TS 33.180 |

The two services share one architecture: the same clients, the same SIP core, the same identity and group management,
the same affiliation model, and the same split of **participating** (serving a user) and **controlling** (owning a
call or a group) functions.

## Common service core

| Feature | Detail |
|---|---|
| Identity | OIDC authorisation code with PKCE and RS256, SIP digest registration, and the binding of access token, SIP identity and client identity |
| Group management | Group documents over XCAP: membership, group type, priority policy, call policy, per-service flags for MCPTT and MCData. They are created, changed and deleted with XCAP under the §7.2.12 authorisations, and their changes are notified to subscribers: clients and the MCPTT and MCData servers as MCS servers. A GMC has the GMS form temporary groups (TS 24.481 §6.3.2 to §6.3.15; [tests](../tests/mcptt/GROUP_MANAGEMENT_TEST.md), [temporary groups](../tests/mcptt/TEMPORARY_GROUP_TEST.md)) |
| Configuration management | User profile documents: the TS 24.484 `<ruleset>` actions each service enforces, target lists and limits. An administrator replaces a profile (TS 24.484 V19.4.0 §6.3.4), and the client and the servers subscribe to its changes (§6.3.13) |
| Key management | KMS identity provisioning, ECCSI/SAKKE MIKEY, group key transport (GKTP), AES-GCM SRTP/SRTCP for protected media |
| Location and user database | Location reporting through the participating functions (TS 24.379 clause 13, TS 24.282 clause 17); the SEAL location management server of TS 24.545 over HTTP in the LMS: configuration, periodic and history reports, subscriptions and notifications for the MCPTT server and on-demand requests ([tests](../tests/mcptt/LOCATION_TEST.md#seal-location-management-server-sl-01-to-sl-06-isl-01-to-isl-06)); MCPTT-2 user-profile pull over freeDiameter (application 16777351) with SCTP CER/CEA and DPR/DPA, protected with TLS on the RFC 6733 secure port and mutual certificate authentication (TS 33.210) |
| Transport | Mutual TLS for SIP and HTTPS for the services; a debug profile with clear SIP for capture-based testing |
| QoS for call media | The MCPTT and MCVideo servers as AF: N5 to a PCF for 5G UEs (TS 29.514) and Rx to a PCRF for EPS UEs (TS 29.214, MCPTT-5), chosen by the UE's address; no request for a UE on WLAN (TS 24.379 clause 4.13). Best effort unless required ([how](POLICY.md)) |

## MCPTT

Voice services over a floor-controlled session. Every call type below works with a combined server and with separate
participating and controlling servers.

| Call type | Supported | Reference |
|---|---|---|
| Prearranged group call | On-demand setup, explicit affiliation, floor-gated media, late entry, leave and rejoin, conference rosters, simultaneous groups, session refresh | TS 24.379 §10.1.1 |
| Private call | Automatic, manual and forced commencement; decline, CANCEL and timeout; caller and called-party rulesets (107/124/125/126/143/144/145); call-back, transfer and forwarding; with or without floor control (an offer without `m=application`: both parties speak at once and only the clients end the call) | §11.1.1, §11.1.2, §11.1.7 |
| Broadcast group call | `broadcast-ind` fan-out, initiator-only transmission, receive-only Floor Deny cause 5, B-bit coding, release at the end of the transmission, group-broadcast and user-broadcast groups, override | §10.1.3, TS 24.380 §8.2.3.15 |
| Chat group call | Join-based sessions with no fan-out, call-type checks (117/118), capacity (122/486), rosters, release on inactivity, implicit affiliation | §10.1.2 |
| Ad hoc group call | Participant lists and criteria-based participants, generated ad hoc group identity, participant modification, rejoin (188), warnings 185–189 | §17 |
| First-to-answer call | Several invitees ring, the first answer wins, the rest are cancelled or released as "not selected"; emergency variant with MEPP save and restore | §11.1.4 |
| Remotely initiated call | One user asks another user's device to place a group or private call, with requester authorisation (157/158) and outcome reporting | §10.1.5, §11.1.7 |
| Ambient listening call | Remote-init and local-init: no indication at the listened-to device, `recvonly`/`sendonly` offers, automatic answer, ruleset checks (154/107/144/127) | §11.1.6 |

| Service | Supported |
|---|---|
| Emergency and imminent peril | Group emergency and imminent-peril calls with authorisation, in-progress group state, cancellation, floor precedence and pre-emption (D and E bits), emergency alerts with encoded location; emergency private call (MEPP); emergency and imminent-peril chat, broadcast and ad hoc calls |
| Floor control | RTCP APP floor messages, one talker at a time, ACK and retry timers, T3 grace, queueing with position reports, floor confirmation, priority pre-emption |
| Speech | AMR-WB modes 0–8, bandwidth-efficient and octet-aligned payloads, RTP, and decoding to WAV for verification |
| Affiliation | Explicit affiliation and de-affiliation, implicit affiliation for chat and ad hoc calls, `<MaxAffiliationsN2>` limits; the server side of the remote change of a user's selected group (TS 24.379 10.1.4), shared with MCVideo and exercised with the MCVideo client ([MCVideo tests](../tests/mcvideo/MCVIDEO_GROUP_SELECTION_TEST.md)) |
| Regroup | A regroup using a preconfigured group. In a group regroup an authorised user combines groups into a temporary group that takes its configuration from a preconfigured group and its members from the constituents, which are refused calls of their own (148) until it is removed. In a user regroup the members are named users, whose participating functions notify them and consider them affiliated, so they take its calls without selecting it |
| Functional aliases | Activation, activation limits, take-over and deactivation; aliases used in private, first-to-answer and ad hoc calls; the server side of status subscriptions (a user's aliases and an alias's users, TS 24.379 9A.2.2.2.4) and of binding an alias to groups (9A.4), shared with MCVideo and exercised with the MCVideo client ([MCVideo tests](../tests/mcvideo/MCVIDEO_FUNCTIONAL_ALIAS_TEST.md)) |
| Location | The participating function configures each client's reporting at log-on, receives its reports, and answers authorised users' requests (refresh, area filters, sharing rights), also for users of another participating function or system. Authorised users can change others' reporting. Emergency alert areas raise an alert, and group geographic areas drive affiliation. The clients evaluate every Annex F.3 trigger against a simulated position and radio (TS 24.379 clause 13, §6.3.2.4; [tests](../tests/mcptt/LOCATION_TEST.md)) |
| Protected media | Group key distribution (GMK) and end-to-end private call keys (PCK) for private, first-to-answer, ambient listening and emergency private calls, on one server, and across separate participating and controlling servers (SPK); encrypted speech and floor control; replay and tamper rejection, including 488 with warning 136 for an I_MESSAGE that fails authentication |
| XML protection | The sensitive XML content of MCPTT signalling (identities, access token, client ID, indicators, location) encrypted hop by hop under each client's CSK or the SPK between servers, including at service authorisation, and every XML body signed (xmldsig, HMAC-SHA256); 403 with warning 140 or 139 for content that cannot be decrypted or verified (TS 24.379 §6.6.2, §6.6.3; [tests](../tests/mcptt/XML_PROTECTION_TEST.md)) |
| Split servers | Server roles `both`, `participating` and `controlling` within one system; participating servers register their users and affiliations with the controlling peers, relay calls, messages and conference subscriptions, and pass speech and floor packets unchanged |

## MCData

Data services over the signalling control plane and over an MSRP media plane.

| Feature | Supported | Reference |
|---|---|---|
| Service authorisation and affiliation | Authorisation by PUBLISH with the access token and client ID, the MCData ID binding, affiliation and de-affiliation, affiliation status subscription and fetch, implicit affiliation | TS 24.282 §7.3, §8.3, §8.4 |
| Standalone SDS | One-to-one and group short data over the signalling plane, with the full transmission control (200, 202, 203, 204, 206, 207, 208, 217, 218, 229, 230) and the group checks (116, 120, 148, 163, 167, 198, 201) | §9.2.2 |
| Conversations and applications | Conversation and message identifiers, replies (InReplyTo), application-ID payloads, application priority (`<user-requested-priority>` returned as `<used-priority>`) | §9.2.1, §9.2.2 |
| Payload, signalling and XML protection | Signalling bodies in SIP and MSRP protected hop by hop with a CSK each client uploads at service authorisation (§9.5), and the sensitive XML content of TS 24.282 §4.6 encrypted with it (§9.3: xmlenc elements and encrypted URIs, including the access token). Optionally each DATA PAYLOAD is signed with its sender's ECCSI key (§8.5.5). End-to-end protection of SDS on both planes, SDS sessions, files over the media plane and one-to-one files over HTTP: one-to-one with a PCK (in an application/mikey body or the SDP a=key-mgmt), group with the group's GMK; 606 or 488 with warning 136 for an I_MESSAGE that fails authentication | TS 33.180 §8; TS 24.282 §6.6, §9.2, §10.2 |
| Disposition notifications | Delivery, read and delivered-and-read notifications, aggregation of a group's notifications with TDC1, and UNDELIVERED storage with re-delivery (TDP1) | §12.2 |
| SDS over the media plane | Standalone SDS in MSRP, SDS sessions that stay open with in-band notifications, and ad hoc group sessions | §9.2.3, §9.2.4, TS 24.582 §6 |
| Priority communications | Emergency one-to-one communications (MDEPC), emergency and imminent-peril group communications (MDEGC, MDEG, MDIGC, MDIG) with the in-progress group state, the three Resource-Priority levels, an emergency alert sent with the request, and the notification of affiliated non-participants | §6.2.8, §6.3.7 |
| Group emergency alert | Activation with location, receipts, late alerts, cancellation of one's own and of another user's alert | §16.2 |
| File distribution over HTTP | Upload to and download from the media storage function, the FD request with a FILEURL payload, one-to-one and group distribution, accept/reject/defer/complete notifications, the file availability timer TDC2, mandatory download and auto-receive, discovery of the media storage function | §10.2.1–§10.2.4, §12.4 |
| File distribution over the media plane | The RFC 5547 file attributes in SDP, the file itself in MSRP, acceptance or a 480/110 decline, size and hash verification, and the completion notification | §10.2.5, TS 24.582 §7 |
| Communication release | Release of a file distribution (FD HTTP TERMINATION, the FILE DELETED notification, 223/224), server-initiated release with prior indication (TDC3) and extension requests, and release over the media plane | §13 |
| Enhanced status | The group's operational values from the group document, published as a group standalone SDS and rendered by every affiliated member | §14 |
| IP connectivity | One-to-one sessions carrying IP packets through a GRE-in-UDP tunnel with the server in the path, transmission control and the release procedures | §20, TS 24.582 §13 |
| Functional aliases | Status change, SDS to an alias with 300 (Multiple Choices), presentation of the sender's alias, aliases in ad hoc lists | §22 |
| Message store | The users' storage areas (objects, flags, folders, search, synchronisation, subscriptions and notification channels), deposit of the communications each user chose to store, and upload by reference of a stored file ([tests](../tests/mcdata/MCDATA_MESSAGE_STORE_TEST.md)) | §21, §10.2.2 |
| Location | The MCPTT procedures for MCData, with the location XML encrypted under the CSK when confidentiality protection is on ([tests](../tests/mcdata/MCDATA_LOCATION_TEST.md)) | §17, §6.3.7.1.6–7 |

## MCVideo

Video services of TS 24.281 and TS 24.581 within one MC system and between two, on the same core as MCPTT
(`mcvideo-server` runs it with the MCVideo service profile). H.264 video is checked picture by picture at every receiver.

| Feature | Supported | Reference |
|---|---|---|
| Service authorisation and affiliation | Authorisation by PUBLISH with the MCVideo access token and the CSK, affiliation and its status subscription | TS 24.281 clauses 7, 8 |
| Group calls | Prearranged and chat group calls, conference events, transmission control with queueing, revocation, implicit request and end of transmission, reception control | §9.2.1-9.2.3; TS 24.581 |
| Private calls | With and without transmission control, the commencement modes, the private call ruleset; calls to a functional alias | §10.2 |
| Priority | Emergency and imminent peril group calls, emergency private call, emergency alert, ad hoc group emergency alert | §6.2.8, §11.2, §12.1A |
| Video pull and push | One-to-one and to or from the server with its recording, remote transmission request and cancel | §12.2, §13.2 |
| Ambient viewing | Remotely and locally initiated, with the release capability | clause 15 |
| Ad hoc group calls | By list and by criteria | clause 22 |
| Regroup | Group and user regroups using a preconfigured group | clause 21 |
| Functional aliases | Activation, limits, take-over, status subscriptions, binding to groups, aliases in calls | clause 20 |
| Remote group selection | Remote change of a user's selected group | §9.2.4 |
| Location | Configuration, reports, requests, configuration changes, group and emergency alert areas | clause 18 |
| Security | MCVideo CS-IDs; GMK-protected group calls and PCK-protected private and ambient viewing calls (SRTP), SRTCP transmission control under the CSK; XML confidentiality and integrity of MCVideo signalling | §4.7, §4.8, §6.6; TS 33.180 |
| Split servers | Participating and controlling MCVideo functions on different servers, video and transmission control relayed, SPK-protected between them | §6.3.2-6.3.4; TS 24.581 §6.4 |

The CMS serves the MCVideo user profile document (TS 24.484 §9.3), which the MCVideo client reads.

The tests are indexed in the [MCVideo test index](../tests/MCVIDEO_TEST.md). Not supported: several devices of one
user (deferred), multiplexing (optional in §6.2.10), MBMS/MBS, off-network and the non-controlling function's own
session (open task T10).

## Verification

Every feature is backed by evidence that is regenerated on each build:

- **Unit tests** for the codecs and the protocol machinery, including byte-exact fixtures for the MCData clause 15
  messages and the MCPTT floor control messages.
- **Scenario tests** that drive real clients in a fresh Docker lab and assert on the state each side reports.
- **Wire verification**: the SIP, RTCP floor, MSRP and MCData bodies are decoded from the capture by independent
  Python decoders and checked against the clause they come from.
- **Regression**: `tools/regress.py` runs the whole lab matrix (every MCPTT call type on combined and split servers,
  the MCData suites clear and protected) in parallel on one
  image before each increment is accepted; see [using the lab](USAGE.md).

## What is not supported

| Area | Status |
|---|---|
| Off-network (ProSe/PC5) | Not implemented: the procedures need direct radio, which an IP lab does not have (MCPTT §10.2, §10.3, §11.2; MCData §9.3) |
| 5G SA and MBS delivery | Out of scope for this phase; broadcast bearers would change how group media is delivered |
| Pre-established sessions | Kept unsupported: TS 24.379 §8.1 requires resource sharing through the SIP core or PCC/Rx, which the lab has neither of; setup requests are refused with 403 and warning 100 |
| Interconnection, MC gateways and migration | Not in this edition: two MC systems interconnected over MCPTT-3, MCData-3 and MCVideo-3 or through MC gateway servers, group documents, files, location and key management across systems (CSC-16, CSC-22, External KMS), and migration of users to a partner system (CSC-17) |
| MCData protection | Ad hoc group communications stay clear; XML integrity protection (xmlsig) is not implemented for MCData; MCPTT XML confidentiality and integrity are implemented ([tests](../tests/mcptt/XML_PROTECTION_TEST.md)) |
| MCData message store | Implemented from TS 24.282 clause 21 without the OMA NMS and NotificationChannel specifications; LongPolling notification channels only; SDS and FD over HTTP are deposited, not media plane communications ([tests](../tests/mcdata/MCDATA_MESSAGE_STORE_TEST.md)) |
| Physical devices | No validation against real handsets or a deployed network; the checklists exist but have not been run |

Each item, with what would unblock it, is in the [blocker register](development/unimplemented-blockers.md).

## Current limits

Within what is implemented:

- **Security profile.** The default lab keeps media and floor protection off; the protected fixtures use an explicitly
  configured E.6 numeric wire profile that has not been qualified against an independent peer (see the
  [security audit](development/protected-media-implementation-audit.md)). SIP uses mutually authenticated TLS, not a
  qualified TS 33.203 Gm profile, and the servers' Diameter uses TLS rather than NDS/IP. MCData XML integrity (xmlsig) is not
  implemented.
- **Documents.** The IdMS, group and configuration documents and the management APIs implement a documented subset:
  user profiles carry the `<ruleset>` actions and lists that are enforced, group documents the group elements that are
  enforced, and neither follows the complete TS 24.484 and OMA XCAP schemas yet. Temporary groups formed by the GMS
  (TS 24.481 6.3.14) are applied as group regroups; merging ongoing calls of the constituent groups is not implemented.
- **Group calls.** Pre-established sessions are not supported, and there is no production RTP jitter, loss and
  reordering scheduler.
- **Private calls.** The forwarding settings MESSAGE and warning 174 are not implemented. Private calls without floor control are on-demand only (no `mc_no_floor_ctrl` pre-established variant).
- **Broadcast group calls.** Group-broadcast and user-broadcast hierarchies are a project profile, because TS 24.379
  §4.12 defines no procedure for them.
- **Ad hoc group calls.** End-to-end security is not implemented; the calls are clear.
- **Functional aliases.** The MCPTT server serves status subscriptions and group binding, but the MCPTT lab client has no commands for them; MCData has neither. Activations do not expire, the status reports only activated aliases, and the alias-to-alias call policy (warnings 171 and 172) is not implemented.
- **Location.** Positions and radio measurements are simulated. The SEAL location management server (TS 24.545) has
  no CoAP, SIP-based subscription, location-based query or trigger other than the periodic one.
- **Interfaces and deployment.** Speech is read from and written to WAV files; there is no microphone or speaker
  interface and no 5G SA integration. The lab's common-service configuration shares credentials between services and
  needs further secret isolation for production.
