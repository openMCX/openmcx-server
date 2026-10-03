# MCVideo standards and acceptance

Traceability from the supplied specifications to the MCVideo increments of the
MCVideo plan. Each row names the
procedure, the acceptance evidence required before it is claimed, and its status.
Status values: **Planned**, **In progress**, **Blocked** (reason given), **Done**
(with a link to its test document).

## Baseline documents

| Document | Supplied version | Notes |
|---|---|---|
| TS 23.280 | V19.10.1 | Common functional architecture (shared with MCPTT and MCData) |
| TS 23.281 | V19.10.0 | MCVideo functional architecture and information flows |
| TS 24.281 | V19.6.0 | MCVideo signalling control |
| TS 24.581 | V19.2.0 | MCVideo media plane control (transmission and reception control) |
| TS 26.281 | V19.0.0 | Codecs and media handling: H.264 (AVC) mandatory, H.265 optional, RTP and SRTP |
| TS 24.484 | V19.6.0 | MCVideo user profile and service configuration documents |
| TS 24.483 | V19.2.0 | MC services management object (UE initial configuration) |
| TS 24.481 | V19.3.0 | Group documents |
| TS 24.482 | V19.1.0 | Identity management |
| TS 33.180 | V19.4.0 | Security of MC services |
| TS 24.229 | V19.7.0 | IMS SIP and SDP profile |
| TS 29.283 | Not supplied | MCVideo-2; not used (profile from the CMS) |

## Identifiers used on the wire

| Item | Value | Reference |
|---|---|---|
| ICSI | `urn:urn-7:3gpp-service.ims.icsi.mcvideo` | 24.281 Annex E.2 |
| Media feature tag | `+g.3gpp.mcvideo`; `+g.3gpp.mcvideo.ambient-viewing-call-release` | Annex D.2, D.3 |
| MCVideo information | `application/vnd.3gpp.mcvideo-info+xml`, namespace `urn:3gpp:ns:mcvideoInfo:1.0` | Annex F.1 |
| Affiliation | `urn:3gpp:ns:mcvideoPresInfo:1.0` in PIDF | Annex F.4, clause 8.3 |
| Location | `application/vnd.3gpp.mcvideo-location-info+xml` | Annex F.3 |
| Transmission request | `application/vnd.3gpp.mcvideo-transmission-request+xml` | Annex F.5 |
| Regroup | `application/vnd.3gpp.mcvideo-regroup+xml` | Annex F.6 |
| Transmission control | RTCP APP names `MCV0`, `MCV1`, `MCV2` | 24.581 §9.1 |
| Warnings | 24.281 §4.4.2: 100 to 196, numbered independently of TS 24.379 (for example 191 is the invalid location target list in MCVideo) | §4.4.2 |

## Phase A: standalone

| ID | Procedure | Reference | Acceptance evidence | Increment | Status |
|---|---|---|---|---|---|
| MV-CORE-01 | Call logic of `mcptt-server` split into a service-parameterised core, MCPTT unchanged | — | Full MCPTT and MCData regression passes with no behaviour change | V1a | Done ([shared-core tests](../../tests/mcvideo/MCVIDEO_SHARED_CORE_TEST.md), SC-09) |
| MV-AUTH-01 | Service authorisation by REGISTER and by PUBLISH with the MCVideo access token, shared registration with MCPTT and MCData, 101 on failure | 24.281 §7.1-7.3 | Clients authorised; wire check of bodies; negative 101 | V1 | Done by PUBLISH ([affiliation tests](../../tests/mcvideo/MCVIDEO_AFFILIATION_TEST.md), MV-AF-01, MV-AF-04); authorisation by REGISTER (§7.2.1, §7.3.2) not implemented |
| MV-AUTH-02 | MCVideo service settings, subscription and notification of settings, PUBLISH with Expires 0 | §7.2.3, §7.2.4, §7.3.4-7.3.6 | Scenario with wire checks | V1 | Planned |
| MV-AFF-01 | Affiliation and de-affiliation, affiliation status subscription, 102 | §8.2, §8.3; 6.3.6 | Affiliation visible at client and server; negatives | V1 | Done ([affiliation tests](../../tests/mcvideo/MCVIDEO_AFFILIATION_TEST.md), MV-AF-02, MV-AF-05 to MV-AF-07) |
| MV-CODEC-01 | `mcvideo-info` and the other MCVideo XML bodies | Annex F | Literal fixtures, round trip, rejection of malformed content | V1 | Done for `<mcvideoinfo>` and the affiliation PIDF (unit tests); the location, transmission request and regroup bodies follow their services |
| MV-MEDIA-01 | H.264 over RTP (RFC 6184), SDP offer and answer, codec check of the participating and controlling functions | §6.2.1, §6.2.2; 26.281 §4 | Receiver decodes frames of the test pattern; SDP rejected without H.264 | V2, V3 | Done: H.264 relayed and decoded at every receiver with equal checksums ([group call tests](../../tests/mcvideo/MCVIDEO_GROUP_CALL_TEST.md)); RTCP key-frame requests not implemented (not required by TS 26.281) |
| MV-TC-01 | Transmission control messages (request, granted, rejected, release, arbitration taken and released, revoked, queue position, end request and response) | 24.581 §9.2 | Byte-exact fixtures per message | V3 | Done: byte-level unit tests; 15 message types on the wire ([group call tests](../../tests/mcvideo/MCVIDEO_GROUP_CALL_TEST.md)) |
| MV-TC-02 | Transmission participant and server state machines, queueing, revocation, implicit transmit media request | 24.581 §6.2-6.4; 24.281 §6.4 | Scenario with pcap checks of MCV0/MCV1/MCV2 | V3 | Done for request, grant, rejection, queueing, grant from the queue, revocation, release, end of transmission, idle and the implicit request ([group call tests](../../tests/mcvideo/MCVIDEO_GROUP_CALL_TEST.md)); acknowledgement and priority pre-emption remain |
| MV-TC-03 | Reception control: receive media request and response, media transmission and reception notifications | 24.581 §6.2.5, §6.3.6, §9.2.13-9.2.16 | Scenario with pcap checks | V3 | Done: notification, acceptance, end of reception ([group call tests](../../tests/mcvideo/MCVIDEO_GROUP_CALL_TEST.md)) |
| MV-GRP-01 | Prearranged group call | 24.281 §9.2.1 | Group scenario with video decoded at every affiliated receiver | V3 | Done for the on-demand prearranged call with video end to end ([group call tests](../../tests/mcvideo/MCVIDEO_GROUP_CALL_TEST.md)) |
| MV-GRP-02 | Chat group call, join and leave | §9.2.2 | Scenario | V3 | Done for joining, a late joiner and leaving ([group call tests](../../tests/mcvideo/MCVIDEO_GROUP_CALL_TEST.md)) |
| MV-GRP-03 | Conference event package | §9.2.3 | Subscription and notifications on the wire | V3 | Done: subscription and participant NOTIFYs ([group call tests](../../tests/mcvideo/MCVIDEO_GROUP_CALL_TEST.md)) |
| MV-PRIV-01 | Private call with and without transmission control, commencement modes, ending by client and server, private-call ruleset warnings | §10.2, §6.2.3-6.2.6 | Scenario and one negative case per warning | V4 | Done ([private call tests](../../tests/mcvideo/MCVIDEO_PRIVATE_CALL_TEST.md)); emergency private calls are V5 |
| MV-EMER-01 | Emergency and imminent-peril group calls, in-progress states, priority call conditions | §4.6, §6.2.8, §9.2.5; Annex G | Scenario with state checks | V5 | Done ([emergency tests](../../tests/mcvideo/MCVIDEO_EMERGENCY_TEST.md)) |
| MV-EMER-02 | Emergency private call | §4.6.2, §10.2 | Scenario | V5 | Done for origination ([emergency tests](../../tests/mcvideo/MCVIDEO_EMERGENCY_TEST.md)); upgrade and cancellation of a private call remain |
| MV-EMER-03 | Emergency alert and ad hoc group emergency alert | §11.2, §12.1A | Scenario | V5 | Done: the emergency alert ([emergency tests](../../tests/mcvideo/MCVIDEO_EMERGENCY_TEST.md)) and, in V8, the ad hoc group emergency alert with its receipt and cancellation ([ad hoc tests](../../tests/mcvideo/MCVIDEO_ADHOC_TEST.md), MV-AH-06); participant modification of the alert is not exercised |
| MV-EMER-04 | Priority sharing | §6.7 | Scenario | V5 | Not applicable: priority sharing is TS 24.229 bearer priority sharing, which needs PCC |
| MV-PULL-01 | Video pull | §12.2 | Scenario | V6 | Done 2026-09-27: one-to-one and from the server ([tests](../../tests/mcvideo/MCVIDEO_PULL_PUSH_TEST.md), MV-PP-02, MV-PP-04) |
| MV-PUSH-01 | Video push, remote transmission request and cancel | §13.2; 24.581 §9.2.22-9.2.25 | Scenario | V6 | Done 2026-09-27: one-to-one and to the server with the recording URL in INFO; remote request and cancel with a Result field, a documented project choice ([tests](../../tests/mcvideo/MCVIDEO_PULL_PUSH_TEST.md), MV-PP-01, MV-PP-03, MV-RT-01 to MV-RT-05) |
| MV-CAP-01 | Capability information sharing | §14.2 | Scenario | V6 | Not applicable: §14.2 of V19.6.0 has no on-network procedure |
| MV-AMB-01 | On-demand ambient viewing call and its release | §15.1-15.4 (not 15.2.2); Annex D.3 | Scenario; 154 negative | V7 | Done 2026-09-27: remote- and locally initiated, release capability, server release ([tests](../../tests/mcvideo/MCVIDEO_AMBIENT_VIEWING_TEST.md), MV-AV-01 to MV-AV-05) |
| MV-SVC-01 | Remote change of an MCVideo user's selected group | §9.2.4 | Scenario | V8 | Done 2026-09-27 (V8d): the change with and without affiliation of the target, the outcome to the requester, refusals 155, 120 and 167 ([tests](../../tests/mcvideo/MCVIDEO_GROUP_SELECTION_TEST.md), MV-SG-01 to MV-SG-07); the requester's 200 comes when the request is relayed, not when the target answers |
| MV-SVC-02 | Functional aliases and binding to groups | clause 20 | Scenario; 171, 172, 176-178 | V8 | Done 2026-09-27 (V8c): status change with limits and take-over, status subscriptions per user and per alias, aliases in group and private calls, the private call to an alias (300), group binding with 176 and 178 ([tests](../../tests/mcvideo/MCVIDEO_FUNCTIONAL_ALIAS_TEST.md), MV-FA-01 to MV-FA-12); 171 and 172 (alias-to-alias call policy), location-based activation, expiry and the activating and deactivating states are not implemented |
| MV-SVC-03 | Regroup using a preconfigured group | clause 21 | Scenario; 160, 161, 165 | V8 | Done 2026-09-27 (V8b): group and user regroups with their notifications and calls, 148 on a regrouped group, 160 and 161, removal; members affiliate to the regroup as in the MCPTT scenario ([tests](../../tests/mcvideo/MCVIDEO_REGROUP_TEST.md)) |
| MV-SVC-04 | Ad hoc group call | clause 22 | Scenario; 184-190, 194, 195 | V8 | Done 2026-09-27 (V8a) for on-demand setup by list and criteria, the ad hoc group identity and refusal 185; modification, leave and rejoin, and priority ad hoc calls not exercised ([tests](../../tests/mcvideo/MCVIDEO_ADHOC_TEST.md)) |
| MV-SVC-05 | Support for multiple devices, multiplexing, info packages | §6.8, §6.2.10; Annex I | Scenario | V8 | Decided 2026-09-27 (V8f). Multiple devices deferred: a second device of the same MCVideo ID is refused, so `<multiple-devices-ind>` is never sent (blocker S18). Multiplexing, optional in §6.2.10, is not supported: no `mc_transmission_ssrc` is offered and `<multiplex-support>` is not sent. Info packages: `g.3gpp.mcvideo-info` (I.2) is used for the in-call priority and video push URL INFOs; `g.3gpp.mcvideo-transmission-request` (I.1) comes with the non-controlling function's own session (open task T10, decided in V12) |
| MV-LOC-01 | Location reporting configuration, request and report | clause 18, §6.2.9 | Scenario; 191-193 | V8 | Done 2026-09-27 (V8e): the core's location procedures in the MCVideo namespace, configuration, reports, requests, configuration changes, refusals 191 to 193, group geographic and emergency alert areas ([tests](../../tests/mcvideo/MCVIDEO_LOCATION_TEST.md), MV-LC-01 to MV-LC-12); no SEAL |
| MV-SEC-01 | Media protection with GMK and PCK, SRTCP for transmission control | §4.7.1; 33.180 | Protected scenario, negative key cases | V9 | Done 2026-09-27 (V9a to V9f): group calls with MCVideo CS-IDs, CSK upload, GMK by GKTP, SRTCP transmission control, SRTP video relayed unchanged and (V9f) PCK-protected private calls with and without transmission control and ambient viewing calls ([tests](../../tests/mcvideo/MCVIDEO_PROTECTED_TEST.md), MV-SE-01 to MV-SE-09); pull and push to and from the server stay clear |
| MV-SEC-02 | CSK download and signalling protection, XML confidentiality and integrity | §4.7.2, §4.8, §6.6, §7.2.5, §7.3.1A, §7.3.7 | Protected scenario; 139, 140 | V9 | Done 2026-09-27 (V9g): the CSK uploaded at MCVideo service authorisation as the XPK, the sensitive MCVideo elements and URI attributes encrypted and every XML body signed between client and server ([tests](../../tests/mcvideo/MCVIDEO_XML_PROTECTION_TEST.md), MV-XP-01 to MV-XP-07); the refusals 139 and 140 are not exercised for MCVideo, and the SPK between MCVideo servers is in use since V10c |

## Phase B: split servers (interconnection of two systems is not in this edition)

| ID | Procedure | Reference | Acceptance evidence | Increment | Status |
|---|---|---|---|---|---|
| MV-INTER-01 | Participating and controlling functions on different servers | §6.3.2-6.3.4; 24.581 §6.4, §6.5 | Split-server group and private calls | V10 | Done 2026-09-28 (subset): split servers with video relayed and SPK-protected transmission control ([tests](../../tests/mcvideo/MCVIDEO_SPLIT_TEST.md)); the non-controlling function's own session (24.581 §6.5.2-§6.5.5) not implemented, as for MCPTT; a group in another system is not in this edition |
| MV-INTER-02 | MCVideo gateway server as exit and entry point, local policy, 179 and 180 | §5.5, §6.9 | - | V11 | Not in this edition |
| MV-INTER-03 | Priority calls, pull and push, ambient viewing, regroup, location and protected calls across systems | V5-V9 clauses over MCVideo-3 and MCVideo-10 | - | V12 | Not in this edition |

## Phase C: migration (not in this edition)

| ID | Procedure | Reference | Acceptance evidence | Increment | Status |
|---|---|---|---|---|---|
| MV-MIG-01 | Migration service authorisation and deauthorisation, authorisation notification, primary and partner gateway procedures, CSK download | 24.281 clause 7A; 24.484 §4.2.2.1.2; 24.482; 33.180 §5.1.4-5.1.5 | - | V13 | Not in this edition |
| MV-MIG-02 | Calls to and from a migrated user, forwarding with 196 | clause 7A, clauses 10 and 22 | - | V14 | Not in this edition |

## Out of scope

| Area | Reference | Reason |
|---|---|---|
| Off-network calls, alerts, pull, push, capability sharing, MONP messages | 24.281 §9.3, §9.4, §10.3, §11.3, §12.3, §13.3, clause 17; 24.581 clause 7 | No ProSe radio (H3) |
| MBMS and MBS | 24.281 §5.3.4, §5.3.5, clause 16; 24.581 `MCV3` to `MCV5` | No multicast bearers (H4) |
| UE-to-network relay, gateway UE, service continuity | §5.4, §5.6, clause 19 | No relay UE or SCC AS |
| Pre-established sessions | §15.2.2 and the pre-established variants | No PCC (H8) |
| Resource management over Rx, N5 or N33 | §4.11 | No PCC |
