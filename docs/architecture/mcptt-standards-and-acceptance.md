# MCPTT standards baseline and acceptance matrix

Status: initial implementation with partial coverage. The acceptance contract below
is broader than the implemented lab subset; see the implementation snapshot at
the end. This is not an exhaustive Release 19 conformance list.

## Supplied normative baseline

| Specification | Verified PDF cover | Role |
|---|---|---|
| TS 23.280 | V19.10.1, May 2026 | Governing common functional model, entities, reference points and identities |
| TS 23.379 | V19.11.0, August 2026 | MCPTT functional entities and information flows |
| TS 24.379 | V19.7.0, August 2026 | MCPTT call-control protocol |
| TS 24.545 | V19.4.0, February 2026 | SEAL location management protocol: the location management server over HTTP (configuration, reports, history, subscriptions, notifications, on-demand requests) alongside the TS 24.379 clause 13 procedures |
| TS 24.484 | V19.4.0, February 2026 | Configuration management: user profile replacement and subscriptions to configuration documents (§6.3.4, §6.3.13) |

The supplied TS 23.282 and TS 24.282 files remain available but are not part of
the current MCPTT implementation scope.

SHA-256 of the supplied MCPTT baseline:

```text
4c6b219117af8f4af1cb11f4f83c858ba23c24d1ebfbbe65136029275de23548  ETSI TS 123 280.pdf
31c657e0016751a613516f43486361e489174d7859db5749698451f697bb3309  ETSI TS 123 379.pdf
d428996a5a51df04895c459a7fe6817f2186d375140d98cf63a045740d420f99  ETSI TS 124 379.pdf
7e764c1a0c66dcde191f79532561fcd0263714afe799e4a1304fd13183d5c0a5  ETSI TS 124 545.pdf
dab0e7a49e8d55ac8ee0d6ef5c74b27023446b193cdbb9221987d3febab3a04e  ETSI TS 124 484.pdf
```

## Referenced dependencies

TS 24.379 clause 2 references additional specifications needed for a working
MCPTT service. TS 24.380, TS 24.481 and TS 33.180 were later supplied
(versions in `dependencies.lock.json`); the others are not.

| Dependency | Version identified during research | Required work before dependent implementation |
|---|---|---|
| [TS 24.380](https://www.etsi.org/deliver/etsi_ts/124300_124399/124380/19.02.00_60/ts_124380v190200p.pdf) | V19.2.0; supplied 2026-09-24 | On-network floor state machines, timers, coding and SDP implemented (Floor row below); exhaustive conformance open |
| [TS 26.179](https://www.etsi.org/deliver/etsi_ts/126100_126199/126179/19.00.00_60/ts_126179v190000p.pdf) | V19.0.0; codec/media clauses inspected online | Qualify AMR-WB encode/decode, mandatory modes, payload format, RTP/SRTP and loss handling |
| [TS 33.180](https://www.etsi.org/deliver/etsi_ts/133100_133199/133180/19.04.00_60/ts_133180v190400p.pdf) | V19.4.0; supplied 2026-09-25 | Selected key-management and protection profile implemented (Security row below); independent-peer interoperability open |
| [TS 24.481](https://www.etsi.org/deliver/etsi_ts/124400_124499/124481/) | V19.3.0; supplied 2026-09-24 | Group document management, subscriptions and temporary groups implemented (Common services row below); group and GMOP documents validated against the §7.2.4 and §7.3.3 schemas (CFG-01) |
| [TS 24.482](https://www.etsi.org/deliver/etsi_ts/124400_124499/124482/) | V19.1.0 listed by ETSI | Obtain and inspect identity-management protocol |
| [TS 24.483](https://www.etsi.org/deliver/etsi_ts/124400_124499/124483/) | V19.2.0 listed by ETSI | Obtain and inspect applicable management objects |
| [TS 24.484](https://www.etsi.org/deliver/etsi_ts/124400_124499/124484/) | V19.6.0 listed by ETSI | V19.4.0 is supplied (above); inspect the later version's configuration-management changes |
| TS 23.002, TS 24.229 and referenced IETF protocols | Referenced by supplied baseline; exact dependency versions not yet qualified | Select and record compatible Release 19 versions and RFC dependencies for exposed SIP reference points |
| TS 29.283 | Referenced by 23.379 §7.5.2.3 and 24.379; exact dependency version not yet qualified | Implement intra-network MCPTT-2 Diameter profile access and applicable update procedures |

Research date: 2026-09-20. Direct shell downloads from ETSI returned HTTP 403;
online sources were used where available. No supplemental PDF was added to the
repository at that date. Publication discovery is not recorded as a complete normative review.
Freeze source URLs, document versions and file hashes when acquiring dependencies
for implementation; do not silently use an older release if retrieval fails.

## Proposed acceptance contract

The rows below define acceptance requirements. Current results and gaps are
recorded in the implementation snapshot; the table itself is not a passing checklist.

| ID | Required behaviour / independent evidence | Specification anchor | Increment |
|---|---|---|---|
| ARCH-01 | Every deployed service and exposed interface maps to a functional entity/reference point | 23.280 §7.3.1.2 and §§7.4–7.5 | Architecture |
| ID-01 | MC ID, MCPTT ID, SIP identity, client ID and group ID have explicit mappings; changing fixture values does not change product code | 23.280 §8; 24.379 §§4.2, 4.10 | Standalone |
| AUTH-01 | Distinguish MC login, SIP registration and MCPTT authorization; bad credentials and expired authorization fail | 23.280 CSC-1/SIP-1; 24.379 §7 | Standalone |
| AUTH-02 | Exercise the selected service-authorization procedure and reject untrusted asserted identities | 24.379 §§7.2–7.3 | Standalone |
| CFG-01 | Retrieve actual applicable configuration and group documents; validate schema, identity and policy applicability | 23.280 CSC-2/3/4/5/13; 24.481/24.484 | Standalone. Schema validation done 2026-09-27: group documents against TS 24.481 §7.2.4 (with the OMA group schema) and §7.3.3, user profiles against TS 24.484 §8.3.2.3, with the RFC 4825 §8.2.5 errors and the §7.2.7, OMA §5.1.6 and §8.3.2.6 constraints ([schema validation tests](../../tests/mcptt/GROUP_MANAGEMENT_TEST.md#schema-validation)) |
| PROFILE-01 | Retrieve the authorized user's profile through the MCPTT-2 Diameter application; reject wrong-user access and handle database failure | 23.379 §7.5.2.3; 24.379 §7.3; 29.283 | Standalone |
| AFF-01 | Explicit affiliation/de-affiliation has correct PUBLISH/XML and responses; non-members fail | 24.379 §§9.2–9.3 | Standalone |
| CALL-01 | On-demand prearranged INVITE uses the participating-function Request-URI and group ID in MCPTT XML; required feature tags and service indication survive the core | 24.379 §10.1.1.2.1.1 | Standalone |
| CALL-02 | Participating and controlling decisions are independently exercised; only permitted users receive invitations | 24.379 §§10.1.1.3–10.1.1.4 | Standalone |
| SDP-01 | Offer/answer negotiates speech and floor channels with correct addresses, parameters and SSRC handling; incompatible offers fail | 24.379 §§6.2.1–6.2.2; 24.380 | Standalone |
| FLOOR-01 | Floor contention gives only the permitted talker access; request, grant, deny/queue as applicable, release and transfer match packet/state fixtures | 24.380 on-network procedures and §8 coding | Standalone |
| FLOOR-02 | Applicable timer expiry, acknowledgement loss, duplication and participant departure do not leave a stuck or duplicated floor owner | 24.380 selected state machines | Standalone |
| MEDIA-01 | Both clients can send and decode AMR-WB speech; capture negotiated RTP fields and retain received audio | 26.179 §4; 23.379 MCPTT-7 | Standalone |
| MEDIA-02 | The client supports mandatory codec modes and required payload/transport options; loss/reordering and unauthorized media are handled correctly | 26.179 §4; applicable security policy | Standalone |
| SEC-01 | Demonstrate token validity, protected key delivery, configured signalling/media protection and invalid-key rejection | 24.379 §§4.7–4.8; 33.180 | Standalone |
| END-01 | Cancel/leave/release and de-affiliation reclaim dialogs, floor, ports and timers; duplicate requests have correct outcomes | 24.379 §§6.2.4–6.2.6, 9, 10.1.1 | Standalone |
| OPS-01 | Clean Docker build, readiness, repeatable startup, persistent configuration, and documented failure/recovery | Project deployment requirement | Standalone |
| PRIVATE-01 | Private call setup, authorized floor operation and release, including permitted commencement modes | 23.379 §10.7; corresponding 24.379 procedures | Additional MCPTT |
| PRIORITY-01 | Authorized emergency/imminent-peril transitions and priority handling; unauthorized priority requests fail | 24.379 §4.6 and §6.2.8; 24.380 | Additional MCPTT |
| SESSION-01 | Pre-established sessions and late-entry procedures have their own protocol traces | 24.379 §8 and §10.1.1 | Additional MCPTT |
| INTER-01 | Split servers: participating and controlling functions of one system on separate servers preserve one controlling owner per call | 23.379 MCPTT-3 | Split servers |
| INTER-02 | Gateway call, floor and media forwarding succeeds for an authorized peer and rejects an untrusted peer | 23.379 MCPTT-10; 23.280 CSC-19/20/21/23 | Not in this edition |
| INTER-03 | Common-service interconnection honours ownership, authorization and selected direct/gateway topology | 23.280 CSC-7/16/17/22 and HTTP-3 | Not in this edition |

Before a row becomes executable, record its applicable conditions, precise
wire assertions, expected errors, fixtures, implementation path, and test command.
Positive client/server round trips alone cannot validate shared packet codecs:
use externally derived fixtures or an independent decoder for wire assertions.

Each integration run records component versions, configuration fingerprints,
scenario results, state-transition logs, packet captures and received audio.
Secrets must not appear in those artifacts. Conformance claims are limited to
the requirements and scenarios actually evidenced.

## Implementation snapshot — 2026-09-26

The inventory above remains the acceptance contract. The current code implements
an initial subset; a row is not fully satisfied merely because its happy path
works. Supplemental PDFs were subsequently downloaded and inspected locally;
exact versions, URLs and hashes are recorded in `dependencies.lock.json`.

| Area | Implemented scope | Remaining acceptance gap |
|---|---|---|
| Identity/authentication | HTTPS lab OIDC code/PKCE/RS256, SIP digest registration, token/SIP/client identity binding, authorization PUBLISH | Full TS 24.482/33.180 qualification; production credential isolation |
| Common services | Independent IdMS, GMS, CMS, LMS, KMS and HTTPS proxy processes. Group documents are written with XCAP (creation, update, deletion, and element and attribute operations, TS 24.481 §6.3.2 to §6.3.12), and their changes are notified through xcap-diff subscriptions (§6.3.13; [group management tests](../../tests/mcptt/GROUP_MANAGEMENT_TEST.md)). The MCData server subscribes as an MCS server (§6.3.13.2.2) through the subscription proxy function the MCPTT server provides; clients and servers follow the user profile document through the CMS (TS 24.484 V19.4.0 §6.3.13), and an administrator replaces it (§6.3.4). The GMS and the CMS refuse group, GMOP and user profile documents that do not conform to the TS 24.481 and TS 24.484 schemas and constraints, and serve conforming ones (CFG-01). The GMS forms and tears down temporary groups (§6.3.14, §6.3.15; [temporary group tests](../../tests/mcptt/TEMPORARY_GROUP_TEST.md)) | OMA XDM access permissions; UE initial configuration and service configuration documents not subscribed to or replaceable; CSK protection of subscription bodies (§6.3.13.2.1 step d) |
| MCPTT-2 | freeDiameter application 16777351; SCTP CER/CEA and DPR/DPA 8388728; profile pull and unknown-user/peer rejection; TLS over SCTP on the secure port (RFC 6733) with certificates from the lab CA naming each Diameter identity (TS 33.210). Checked 2026-09-25: the peers reach STATE_OPEN over TLS, the group scenario passes, and an SCTP capture holds 68 TLS application-data records and no MCPTT ID. Checked 2026-09-27 (user database failure): in the `inter` lab, `mcx-user-db` was killed with `docker kill` three times, with client-a and client-b re-authorising during each outage, and restarted each time. mcptt-server, mcptt-part-1 and mcptt-part-2 log `Fatal GNUTLS error: Error in the pull function`, stay up with the same instance, and refuse PUBLISH during the outage; no double free was seen (4 lab runs, 200 SIGKILLs of a TLS/SCTP peer under load with AddressSanitizer). Before the fix, the restarted `mcx-user-db` got a new address and the servers, which kept the address freeDiameter resolved at startup, never reconnected. Now `mcx-user-db` connects to the servers itself and the peers are OPEN again within a second; the restarted clients are service authorised at once, and `diameter_sctp` covers a killed and restarted peer. `tools/regress.py --select smoke` passes over TCP | IPsec (NDS/IP Za/Zb) is not used; remaining push/update/error procedures |
| XML/SDP | Bounded namespace-aware MCPTT/PIDF, multipart, AMR-WB/floor offer-answer parsing | Complete optional documents and negotiation combinations |
| Group call | Combined server, or separate participating and controlling servers (H2), explicit affiliation, on-demand prearranged call, floor-gated media, late entry/rejoin, simultaneous groups and emergency/imminent/alert state; regroups and GMS-formed temporary groups | Merging ongoing constituent calls into a temporary group's call (§10.1.1.5.2.3); a constituent in an emergency state not refused (166); pre-established sessions (H8) |
| Private call (PRIVATE-01) | On-demand private call via a combined server or separate participating and controlling servers: `resource-lists` called party, TS 24.484 ruleset subset from CMS (warnings 107/124/125/126/143/144/145), called-party authorization (127/159), automatic/manual/forced commencement, decline relay, setup and private call timers, session refresh, floor-controlled clear speech, and speech without floor control (§11.1.2, both parties at once, ended only by the clients; see [private calls without floor control](../../tests/mcptt/PRIVATE_NO_FLOOR_TEST.md)); emergency private (MEPP), call-back, unannounced and announced transfer (§11.1.8.2.3), immediate and no-answer forwarding (§6.3.2.5); end-to-end PCK on one server and across servers with an SPK; see [private-call tests](../../tests/mcptt/PRIVATE_CALL_TEST.md) | Interoperability with an independent MIKEY-SAKKE peer ([protected private-call tests](../../tests/mcptt/PROTECTED_PRIVATE_CALL_TEST.md)); the forwarding-settings MESSAGE and warning 174; the pre-established `mc_no_floor_ctrl` variant of §11.1.2; `<ListOfAllowedFAsToBeCalledFrom>`; pre-established (H8) and off-network (H3) variants |
| Broadcast group call | `broadcast-ind` prearranged call, optional `broadcast_members` authorization, receive-only Floor Deny cause 5, B-bit and Permission to Request 0 coding, release at transmission end, conference SUBSCRIBE 480/105, late entry; group-broadcast/user-broadcast hierarchies (project profile), override, emergency/imminent broadcast (B+D/B+E local policy); see [broadcast tests](../../tests/mcptt/BROADCAST_CALL_TEST.md) | Stage-3 interoperability of hierarchies and priority broadcast (no procedure in TS 24.379), pre-established (H8), chat-model and off-network (H3) variants |
| Chat group call | GMS group type `chat`; join-based session with no fan-out, 117/118 call-type checks, 486/122 capacity, conference rosters, release when one participant remains or on inactivity; emergency/imminent chat, implicit affiliation, 167/148 restrictions and capacity preemption; chat calls on a regroup and on a GMS-formed temporary group (§10.1.2.4.1 steps 5, 5a); see [chat tests](../../tests/mcptt/CHAT_CALL_TEST.md) | Invitation of each constituent's non-controlling function (§10.1.2.4.1 step 11b); the Resource-Priority UPDATE correction (§6.3.3.1.8); chat-model broadcast; pre-established chat (H8) |
| Ad hoc group call | Participant-list ad hoc call with a generated ad hoc group identity, implicit affiliation, warnings 185/186/187/189, rejoin (188), release on initiator leave, TNG3 or inactivity; criteria-based participants, participant modification, emergency/imminent ad hoc and the ad hoc emergency alert, functional-alias and broadcast ad hoc (including emergency broadcast); see [ad hoc tests](../../tests/mcptt/ADHOC_CALL_TEST.md) | End-to-end security (S16, deferred with H1), pre-established ad hoc (H8) |
| Emergency and imminent-peril calls (PRIORITY-01) | Group emergency and imminent peril with authorization, in-progress state, floor precedence and preemption (D/E bits), alerts with encoded location, cancellation and TNG2; emergency private (MEPP), first-to-answer, chat and ad hoc variants; see [emergency](../../tests/mcptt/EMERGENCY_CALL_TEST.md) and [imminent-peril](../../tests/mcptt/IMMINENT_PERIL_CALL_TEST.md) tests | The alert carries the configured location, not a reported position; simulated positioning; persistence across restart; radio QoS mapping |
| First-to-answer call | Multi-invitee ringing with forced manual commencement, first-answer selection, cancellation or "not selected" release, list filtering, emergency first-to-answer with MEPP save/restore; see [first-to-answer tests](../../tests/mcptt/FIRST_TO_ANSWER_TEST.md) | Emergency to a functional alias (refused); pre-established (H8) and off-network (H3) variants |
| Remotely initiated call | A user asks another user's device to place a group call (§10.1.5) or private call (§11.1.7); requester authorization 157/158, preconfigured-use-only group 167, controlling affiliation check 120, silent variant, outcome reporting with the called group relayed in `<mcptt-calling-group-id>`; `<ric-app-level-priority>` carried as the Resource-Priority of the follow-up call; see [remotely initiated tests](../../tests/mcptt/REMOTE_INITIATED_TEST.md) | Pre-established sessions (H8); a request to call a group the remote user is not affiliated to (the lab has one group per client) |
| Ambient listening call | On-demand remote-init and local-init calls (§11.1.6): ruleset checks 154/107/144/127, busy 480/486, `recvonly`/`sendonly` offers with `mc_implicit_request`, automatic answer, null alert and no indication at the listened-to device, D.3 release permission, floor held by the listened-to user (Floor Deny cause 5 to the listener), server release with each `<release-reason>` (administrator, private call timer, a call by or to the listened-to user); see [ambient listening tests](../../tests/mcptt/AMBIENT_LISTENING_TEST.md) | Pre-established sessions (H8); location-info relay; `mc_implicit_request` not required by the server |
| Location (LOC-01) | TS 24.379 clause 13, §6.3.2.4, §12.1.1.4, §12.1.1.6: Annex F.3 configuration, request and report; the configuration at service authorisation; client triggers (radio identities, periodic, travelled distance, signalling events, geographical areas with borders, adaptive) with the minimumReportInterval timer and the emergency triggers; authorised requests (refresh, LocationFilter, functional alias) and reporting changes, refusals 141/192/193/194; forwarding to the participating function of another participating function's user and relaying its report back; emergency alert areas and group geographic areas; the SEAL location management server (TS 24.545 V19.4.0) over HTTP: configuration, periodic and history reports, subscriptions and notifications for the MCPTT server and on-demand requests ([location tests](../../tests/mcptt/LOCATION_TEST.md)) | Simulated positioning; SEAL LM without CoAP, the SIP-based subscription (6.2.6.2.1), triggers other than the periodic one, location-based queries (6.2.9), group-based subscriptions (TS 23.280 §10.9.3.5 step 3) or the MCData server as a subscriber |
| Interconnection (INTER-03) | Not in this edition: group management across MC systems (CSC-16) | |
| Migration (MIG) | Not in this edition: migration of users to a partner MC system (CSC-17) | |
| Protected calls across systems (INTER-04) | Not in this edition: External KMS, the GMK transferred between GMSs and the IS proxy | |
| Interconnection (INTER-02) | Not in this edition: MC gateway servers between two systems | |
| Split servers (INTER-01) | Server roles `both`/`participating`/`controlling` within one system; participating servers register users and affiliations with controlling peers, relay calls, MESSAGEs and conference subscriptions, and pass speech and floor packets unchanged; implicit affiliation at the participating function; every implemented call type and private call service runs across the split with one controlling owner per call; the N2 affiliation limit; every configured peer trusted; see the split-server labs | Emergency first-to-answer and unauthorised-request rejections not run across the split |
| Floor | Literal RTCP APP fixtures, one talker, ACK/retry timers, T3 grace, queueing, confirmation and priority preemption | Exhaustive TS 24.380 conformance and independent peer qualification |
| Speech | Native AMR-WB modes 0–8, bandwidth-efficient/octet-aligned payload helpers, RTP and decoded WAV | Production jitter/loss/reordering scheduler, bundling/interleaving, complete RTCP reporting |
| Security | Verified HTTPS/mutual TLS SIP; KMS identity provisioning, ECCSI/SAKKE MIKEY, GKTP, AES-GCM SRTP/SRTCP; SPKs between servers and systems; MCPTT XML confidentiality and xmldsig integrity under the CSK or SPK (TS 24.379 §6.6.2, §6.6.3; [XML protection tests](../../tests/mcptt/XML_PROTECTION_TEST.md)) | Qualified Gm security, independent E.6 wire-profile interoperability, complete optional protection profiles |
| Deployment | Pinned PJSIP/Kamailio/Go source, generated runtime configuration, separate service containers, freshness-aware readiness | Deployment qualification beyond the tested Linux/Docker lab |

The default lab remains a clear-media profile. Protected fixtures require an
explicit E.6 numeric wire profile and fail closed on missing keys. The new KMS
serves authenticated provisioning requests and reports readiness only after
initializing its persistent authority. See the protected-media audit
for unresolved specification/interoperability limits. These features do not
constitute a full Release 19 conformance claim.

Executable evidence is retained under `artifacts/integration/`; the README
provides rerun commands. Unit and integration results must be read alongside
these limits, not as a Release 19 conformance certificate.
