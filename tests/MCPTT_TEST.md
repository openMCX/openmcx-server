# MCPTT test index

Index of performed MCPTT tests, organized by call type. MCData tests are in the [MCData test index](MCDATA_TEST.md). Prearranged group-call evidence was reviewed on **2026-09-21** without rerunning those tests. Private-call, broadcast, chat and ad hoc tests were run on the same date for their own sections. Results describe the recorded builds and scenarios, not complete standards conformance. Artifact links refer to local lab files, which may be absent in a fresh checkout.

## One server for all call types

The separate four-client labs (`prearranged-lab`, `private-lab`, `broadcast-lab`, `chat-lab`, `adhoc-lab`, …) are **test fixtures only**. Every lab runs the same `openmcx-mcptt-server` and `mcx-client` binaries; they differ only in generated configuration (groups, group type, user rulesets, timers) and in the image tag of the build under test. A new tag per build means a new lab never disturbs one that is already running. One server instance handles every implemented call type at the same time, keeping sessions apart by call type. The chat and ad hoc images prove this: all earlier call-type scenarios passed against a single server instance of each (CH-12, AH-13).

## Call types

| Call type | Recorded coverage |
|---|---|
| [On-network, on-demand prearranged group call](#prearranged-group-call) | Two-client baseline; four-client lifecycle, concurrent groups, floor control, priority/emergency and protected media |
| [On-network, on-demand private call](#private-call) | Automatic, manual and forced commencement; decline, CANCEL and timeout; caller and called-party profile authorization; busy limit; coexistence with a group call; private call timer and session refresh; first-to-answer calls (clear media only); emergency private calls; call-back, remotely initiated call, transfer and forwarding |
| [On-network, on-demand broadcast group call](#broadcast-group-call) | Initiator-only transmission, receive-only denial (cause 5), B-bit floor coding, release at transmission end, conference rejection, authorization/conflict rejection, late entry; group-broadcast and user-broadcast hierarchies (project profile); override |
| [On-network, on-demand chat group call](#chat-group-call) | Join-based sessions with no fan-out, call-type checks (117/118), capacity (122), creator leave and rejoin, release when one participant remains or on inactivity, coexistence with a prearranged call; emergency and imminent peril; implicit affiliation; 167/148 restrictions and priority preemption |
| [On-network, on-demand ad hoc group call](#ad-hoc-group-call) | Participant-list setup with a generated ad hoc group, implicit affiliation, warnings 185/187/189, manual answer and decline, rejoin, release on initiator leave or call timer, coexistence with a group call; emergency and imminent peril; criteria and participant modification; ad hoc emergency alert |
| [Emergency calls](#emergency-calls) | Emergency group call: authorization, in-progress state, floor precedence and preemption, alerts with location, cancellation, TNG2; plus the emergency private, first-to-answer, chat and ad hoc variants |
| [Imminent-peril group calls](#imminent-peril-group-calls) | Imminent-peril initial call and upgrade, authorization, emergency precedence, floor E-bit; chat and ad hoc variants |
| [First-to-answer calls](#first-to-answer-calls) | Several invitees ring, the first answer wins, the others are cancelled; declines, CANCEL, concurrent answers, list filtering; emergency first-to-answer with MEPP save/restore |
| [Remotely initiated calls](#remotely-initiated-calls) | A user asks another user's device, by SIP MESSAGE, to place a group or private call; authorization (157/158), affiliation check (120), silent variant, busy and outcome reporting |
| [Ambient listening calls](#ambient-listening-calls) | Remote-init and local-init: no indication at the listened-to device, floor held by the listened-to user, release rules (D.3), server release with each release reason, authorization (154/144/127) and busy (480) |
| [Functional aliases](mcptt/FUNCTIONAL_ALIAS_TEST.md) | Activation, limit, take-over and deactivation; private, first-to-answer and ad hoc calls to an alias; alias presentation; broadcast ad hoc call |
| [Group management](mcptt/GROUP_MANAGEMENT_TEST.md) | Group documents created, changed and deleted with XCAP, the §7.2.12 authorisations, and subscriptions to their changes |
| [XML protection](mcptt/XML_PROTECTION_TEST.md) | The sensitive XML content of MCPTT signalling encrypted hop by hop under the CSK or the SPK, including the access token at service authorisation |
| [Location management](mcptt/LOCATION_TEST.md) | Reporting configuration and triggers, reports, authorised requests with refresh and area filters, reporting changes, refusals 192/193/194, emergency alert and group geographic areas and the SEAL location management server (TS 24.545) |
| [Temporary groups formed by the GMS](mcptt/TEMPORARY_GROUP_TEST.md) | A GMC has the GMS combine groups into a temporary group (TS 24.481 6.3.14, 6.3.15): authorisation, identity in use, a constituent group combined once, 148 on a constituent group, group and chat calls on the temporary group, and tear down |
| [Regroup using a preconfigured group](mcptt/REGROUP_TEST.md) | An authorised user combines groups (group regroup) or named users (user regroup) into a temporary group that takes its configuration from a preconfigured group; authorisation (160/161), identity in use (165), constituents regrouped (148), a call on the regroup that user-regroup members take without selecting it, and removal (163 when unknown) |
| Other call types | Off-network calls and pre-established sessions are not implemented (hard blockers H3, H8) |

## Soft-blocker completion run — 2026-09-22

Image `openmcx:0.17` (`7a42efef3b69`); clear media, debug SIP. Every report records **PASS**. The per-block evidence is in each call type's document.

| Run | Fixture | Result |
|---|---|---|
| Private calls incl. first-to-answer, emergency private, refresh | `--private-call --private-refresh` | 95 assertions; SIP wire 45; floor decode 4,398 packets |
| Private call services and client profile enforcement | `--private-call --private-services` | 32 assertions |
| Functional aliases and broadcast ad hoc | `--private-call --adhoc --functional-alias` | 33 assertions; SIP wire 11 |
| Chat incl. emergency, implicit affiliation, variants | `--chat` | 67 assertions; SIP wire 12; floor decode 3,771 packets |
| Broadcast incl. hierarchies and override | `--broadcast` | 56 assertions; SIP wire 17 |
| Ad hoc incl. priority, criteria, modification, alert | `--adhoc` | 81 assertions; SIP wire 19 |
| Every call type on one server instance | `--private-call --broadcast --chat --adhoc` via `tests/integration/run_all_call_types.sh` | All six scenarios pass: prearranged 21, failure/refresh 15, broadcast 56, private 96, chat 67, ad hoc 81 (336 assertions) |

External Wireshark dissection (tshark 4.2.2) of the private, chat, broadcast and ad hoc captures found zero expert diagnostics across 544 RTCP floor frames. The native suite (17/17, excluding the SCTP Diameter test) and the Go tests passed in the image build. S8 (pre-established sessions) was not implemented: it needs resource sharing that the lab cannot provide (H8 in the blocker guide).

## All-call-types run — 2026-09-22 (ambient and remote group added)

Image `openmcx:0.21-fixes` (`a2ddb25a01bf`), built from the tree committed as `bec8c19`; fixture `--private-call --broadcast --chat --adhoc`, clear media, debug SIP. `tests/integration/run_all_call_types.sh` ran all eight scenarios against one server instance (`sRODZY123lLYpG1bjAoL-kqDrnNiRMFPyiJ4Dy-BBT0`), restarting only the clients between them. Every report records **PASS**: prearranged 21, failure/refresh 15, broadcast 56, private 96, chat 67, ad hoc 81, remote group 20, ambient listening 51 (407 assertions). Reports are under `artifacts/all-types-lab/artifacts/integration/`, and the run log is `artifacts/all-types-lab/run.log`.

## Prearranged group call

A group with two participants is still a **group call**, not a private call. Four-client fixtures exercise different participant combinations; not every scenario keeps all four clients in one call.

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Two-client baseline and call flow](mcptt/MCPTT_TWO_CLIENT_TEST.md) | Setup, two-way speech, competing floor request, teardown and restart |
| [Four-client prearranged tests and call flow](mcptt/PREARRANGED_TEST.md) | Late entry, leave/rejoin, conference rosters, simultaneous groups, failure recovery, refresh and queued floor |
| [Four-client emergency and protected tests](mcptt/EMERGENCY_PROTECTED_TEST.md) | Priority/emergency, alerts, key provisioning, encrypted speech/floor and security |

### Performed scenarios

All reports linked in this table record **PASS**. Historical baseline and clear-media runs precede the final protected build; they are not presented as reruns on that build. Counts are assertions within a scenario, not distinct calls.

| ID | Test / coverage | Fixture and transport | Result evidence |
|---|---|---|---|
| PGC-01 | Two-way decoded speech, floor contention and teardown | 2 clients; clear media; debug SIP / TLS | Debug (`artifacts/integration/speech-debug-results.json`), TLS (`artifacts/integration/speech-tls-results.json`) |
| PGC-02 | Client restart and reauthorization without server restart | 2 clients; debug SIP / TLS | Debug (`artifacts/integration/restart-debug-results.json`), TLS (`artifacts/integration/restart-tls-results.json`) |
| PGC-03 | TLS reconnect | Baseline TLS lab | Report (`artifacts/integration/tls-reconnect-results.json`) |
| PGC-04 | SIP signaling and floor dissection after malformed-field fixes | Baseline lab; debug SIP / TLS | SIP (`artifacts/integration/sip-debug-results.json`), debug wire (`artifacts/integration/wire-debug-results.json`), TLS wire (`artifacts/integration/wire-results.json`) |
| PGC-05 | Authorization rejection probes | Baseline lab; debug SIP / TLS | Debug: 11 checks (`artifacts/integration/security-debug-results.json`), TLS: 11 checks (`artifacts/integration/security-results.json`) |
| PGC-06 | Late entry, leave/rejoin, conference roster, concurrent groups and independent teardown | 4 clients; clear media / debug SIP | 21 checks (`artifacts/prearranged-lab/artifacts/integration/prearranged-results.json`) |
| PGC-07 | Manual rejection, caller CANCEL, setup timeout, session survival and cleanup | 4-client clear-media fixture; selected pair | 15 checks (`artifacts/prearranged-lab/artifacts/integration/prearranged-failure-results.json`) |
| PGC-08 | Floor queue query, cancellation, requeue, grant confirmation and abandoned-grant cleanup | Clear-media fixture; queued participants | 19 checks (`artifacts/prearranged-lab/artifacts/integration/prearranged-floor-results.json`) |
| PGC-09 | Accepted SIP refreshes, conference notifications and cross-group media isolation | Clear-media capture v6 | Wire report (`artifacts/prearranged-lab/artifacts/integration/prearranged-v6-wire.json`) |
| PGC-10 | Floor fields, repeated-acquisition SSRCs and zero RTCP expert diagnostics | Clear-media capture v6 | Floor report (`artifacts/prearranged-lab/artifacts/integration/prearranged-v6-floor-wire.json`) |
| PGC-11 | Authorized numeric/emergency preemption, imminent/emergency transitions, alerts, locations, cancellation and late entry | 4-client clear-media priority fixture; image6 | 43 checks (`artifacts/priority-lab/artifacts/integration/passed-image6-priority-results.json`) |
| PGC-12 | Emergency timeout downgrades priority while retaining the call | Priority fixture; short configured timer; image6 | 7 checks (`artifacts/priority-lab/artifacts/integration/passed-image6-priority-timer-results.json`) |
| PGC-13 | Protected lifecycle, concurrent groups and actual GKTP renewal preserving manual deaffiliation | 4 clients; protected media / debug SIP; image6 | 22 checks (`artifacts/protected-lab/artifacts/integration/prearranged-results.json`) |
| PGC-14 | Protected queued-floor procedures | Protected media / debug SIP; image6 | 19 checks (`artifacts/protected-lab/artifacts/integration/prearranged-floor-results.json`) |
| PGC-15 | Priority/emergency procedures with protected speech and floor | 4-client protected fixture / debug SIP; image7 | 43 checks (`artifacts/protected-lab/artifacts/integration/prearranged-priority-results.json`) |
| PGC-16 | Protected rejection, CANCEL, setup timeout and session survival | Protected fixture / debug SIP; image7 | 15 checks (`artifacts/protected-lab/artifacts/integration/prearranged-failure-results.json`) |
| PGC-17 | Live SRTP/SRTCP replay and tamper rejection; valid speech continues | Protected fixture / debug SIP | Report (`artifacts/protected-lab/artifacts/integration/protected-negative-results.json`) |
| PGC-18 | SAVP negotiation, CSK/GKTP exchanges and byte-identical encrypted relay | Protected capture v6 | Wire verification (`artifacts/protected-lab/artifacts/integration/protected-v6-wire-verification.json`), decoded-audio evidence (`artifacts/protected-lab/artifacts/integration/decoded-audio-evidence.json`) |
| PGC-19 | Accepted refresh transactions and conference notifications | Protected calls / debug SIP; image7 | Wire report (`artifacts/protected-lab/artifacts/integration/protected-refresh-v7-wire.json`) |
| PGC-20 | Protected lifecycle, late entry, rejoin and concurrent groups | 4 clients / TLS; final image7 | 21 checks (`artifacts/protected-tls-lab/artifacts/integration/passed-image7-normal-results.json`) |
| PGC-21 | Protected priority/emergency, alert locations and cancellation | 4-client fixture / TLS; final image7 | 43 checks (`artifacts/protected-tls-lab/artifacts/integration/passed-image7-priority-results.json`) |
| PGC-22 | Protected queued-floor procedures | TLS; final image7 | 19 checks (`artifacts/protected-tls-lab/artifacts/integration/passed-image7-floor-results.json`) |
| PGC-23 | Protected rejection, CANCEL, timeout and session survival | TLS; final image7 | 15 checks (`artifacts/protected-tls-lab/artifacts/integration/passed-image7-failure-results.json`) |
| PGC-24 | SIP/HTTPS security, including rejection of another certificate's matching CANCEL | Protected TLS fixture | 14 checks (`artifacts/protected-tls-lab/security-peer-after.json`) |
| PGC-25 | Supporting native protocol, SIP, floor, crypto and Go service regressions | Native/service suite | 16 native tests and Go package results (`artifacts/protected-lab/artifacts/integration/native-go-tests.log`), final image build (`artifacts/protected-lab/artifacts/integration/image7-build.log`) |

Final image7 is `8d2c91f1439c`; TLS container identities (`artifacts/protected-tls-lab/artifacts/integration/image7-containers.txt`) record the deployment. Supporting native/service tests cover shared components and are not additional end-to-end call scenarios.

### Packet captures

| Capture | Contents |
|---|---|
| Baseline server (`artifacts/integration/mcptt-debug.pcap`), baseline SIP core (`artifacts/integration/sip-debug.pcap`) | Clear SIP, RTP and floor; core capture includes registration |
| Clear-media four-client v6 (`artifacts/prearranged-lab/artifacts/integration/prearranged-v6.pcap`) | Lifecycle, concurrent groups, refresh and queued floor |
| Priority/emergency v6 (`artifacts/priority-lab/artifacts/integration/priority-emergency-v6.pcap`) | Clear-SIP priority and emergency procedures |
| Protected v6 (`artifacts/protected-lab/artifacts/integration/protected-v6.pcap`) | Readable debug SIP, key-distribution signaling and encrypted media/floor |
| Protected negative tests (`artifacts/protected-lab/artifacts/integration/protected-negative.pcap`) | Injected replay/tamper packets |
| Protected refresh v7 (`artifacts/protected-lab/artifacts/integration/protected-refresh-v7.pcap`) | Readable SIP refresh and conference transactions |
| Protected TLS image7 (`artifacts/protected-tls-lab/artifacts/integration/protected-tls-image7.pcap`) | Encrypted SIP and protected media/floor |

TLS captures alone do not prove decrypted SIP contents. Debug SIP disables SIP TLS only; protected media/floor remain encrypted. The wire verifier checks encrypted relay bytes separately from the clients' decoded-audio evidence.

### Historical failures and qualification limits

The original user capture retains the malformed RTCP packets; capture analysis documents the investigation. Failed development runs and superseded captures remain in their artifact directories; they are not passing acceptance evidence.

See prearranged validation notes, priority/emergency audit and protected-media audit. Protected tests use an explicit local numeric wire profile and synthetic configured alert coordinates. Full standards conformance and external interoperability remain unqualified.

### Physical-setup validation — not yet performed

The recorded integration evidence comes from Docker labs. The following checklist is proposed acceptance work on physical clients and a deployed network; none is marked passed by the lab results above. Use at least four independently connected clients, real microphones/speakers or calibrated audio endpoints, and the intended server/Kamailio/common-service deployment. Record device/software versions, network topology, policy, timestamps and results for each run.

| ID | Physical test to perform | What to validate and retain |
|---|---|---|
| PGC-P01 | Four-device basic group call | Register/authorize/affiliate A–D; originate a call; each device takes and releases the floor and hears the other speakers. Verify participant identities, conference rosters, contention handling and teardown with synchronized endpoint/server logs and captures. |
| PGC-P02 | Late entry, leave and rejoin | Start A/B, add C/D, leave and rejoin while another participant speaks. Verify the existing session survives, membership/floor state synchronizes and departed devices stop receiving media. Test configured initiator-leave policy separately. |
| PGC-P03 | Two simultaneous groups | Use distinct memberships and simultaneous speech sources. Verify independent floors, no cross-group audio or notifications, and independent teardown at the receiving devices. |
| PGC-P04 | Real PTT controls and audio | Measure button-to-floor-grant, button-to-audible-speech and mouth-to-ear delay, first-syllable clipping, intelligibility and audio continuity. Test repeated presses, long talk bursts and competing requests. Agree deployment acceptance thresholds before the run; no physical timing limits have been validated here. |
| PGC-P05 | Radio/network impairment and mobility | Introduce controlled loss, jitter, delay, reordering, brief outage and coverage return; exercise handover if the deployment supports it. Check floor retry/recovery, stale ownership, media resumption, duplicate legs and user-visible failure behavior. Preserve impairment settings and radio/core logs. |
| PGC-P06 | Deployed addressing and transport | Test intended routing, firewalls, DNS, MTU and any NAT path; verify SIP dialog routing and bidirectional media/floor reachability. Exercise mutual TLS trust, wrong/expired certificates and reconnect. Treat failure on an unsupported topology as a gap, not a passed scenario. |
| PGC-P07 | Priority/emergency under contention | Exercise authorized and unauthorized activation/cancellation, numeric preemption, imminent/emergency transitions, alerts, late entry and timeout while real speech flows. Verify old-speaker transmission stops and the new speaker is heard. Separately verify any claimed radio/core QoS priority under congestion; SIP priority alone is insufficient evidence. |
| PGC-P08 | Deployed protected keying and media | Verify intended KMS/GMS identities and wire profile, provisioning, renewal, membership changes, key expiry, identity-period rollover and rejection of stale/replayed keys. Check end-device audio, packet confidentiality and replay/tamper rejection; do not export secrets into shared reports. Qualify the local test profile before claiming interoperability. |
| PGC-P09 | Failures and recovery | Power-cycle a client; interrupt SIP transport; restart server, proxy and key/common services separately. Check cleanup, reauthorization, fresh key establishment, rejected stale traffic and recovery behavior. Record lost calls/state explicitly; seamless failover is not established by current tests. |
| PGC-P10 | Admission and release policies | Exercise live membership/authorization removal, receive-only users, participant limits, minimum-member policies, inactivity and maximum-duration release using deployment settings. Verify rejected/removed participants cannot transmit or receive and resources are reclaimed. |
| PGC-P11 | Capacity and endurance | Increase groups/participants to the intended deployment load; repeat joins, floor contention, key renewal and long-running calls. Measure CPU/memory, ports/dialogs, packet loss and recovery. Four-client lab success establishes no production capacity limit. |
| PGC-P12 | Independent implementation | Repeat selected scenarios against an independently implemented client/server and intended KMS/GMS. Compare signaling, key documents, SDP, floor fields and media behavior; retain peer versions and agreed profiles. |

### Prearranged-group-call coverage gaps

“Not validated” below does not necessarily mean “not implemented.” This separates missing physical evidence from known implementation/profile limits.

| Area | Current gap / limit |
|---|---|
| Physical endpoints and access network | No recorded real-device PTT/audio, radio handover/coverage, carrier QoS, deployed NAT/firewall, capacity or endurance acceptance; validate PGC-P01–P12 as applicable. |
| Standards and independent peers | No complete clause-by-clause conformance campaign or external interoperability result. Protected fixtures require an explicit local E.6 numeric wire profile; cryptographic vector tests do not resolve that interoperability qualification. |
| Pre-established-session variant | Pre-established association, REFER-based procedures, ICE and resource-sharing work remain outside the delivered on-demand profile; see the procedure plan. |
| Multiple MCPTT servers/systems | Distinct participating/controlling and non-controlling server roles and multi-system interworking are outside current single-system evidence. |
| Emergency location and authorization profile | Positions are simulated. Location triggers, freshness and requests are implemented ([location tests](mcptt/LOCATION_TEST.md)); the MCPTT location XML is encrypted with the rest of the XML under XML protection ([XML protection tests](mcptt/XML_PROTECTION_TEST.md)); GPS and radio measurement and full standardized user/group XML authorization mapping remain outside the implemented profile. |
| Restart persistence | Emergency/originator state is held in memory. Key replay/ordering protections are process-local, not a persistent replay database. Existing client-restart tests do not establish server-restart continuity or anti-replay protection across a restart. |
| Key lifecycle qualification | Seamless identity-period handover, operational recovery and independent KMS/peer compatibility are not established. Unsupported key-document/profile extensions fail closed; expiry handling is not proof of uninterrupted rekey. |
| Conditional group procedures | The SEAL location management server (TS 24.545) is implemented over HTTP ([location tests](mcptt/LOCATION_TEST.md#seal-location-management-server-sl-01-to-sl-06-isl-01-to-isl-06)). |
| Exhaustive policies and fault combinations | Existing scenarios cover selected policies, timers and failures. They do not establish every membership/admission combination, all timer races, network partition behavior or high-availability failover. |

Private, broadcast, chat and ad hoc calls have their own sections ([private](#private-call), [broadcast](#broadcast-group-call), [chat](#chat-group-call), [ad hoc](#ad-hoc-group-call)). Off-network calls need their own future call-type entry; it is not a passing prearranged-call variant in this index.

## Private call

A call between exactly two MCPTT users that is not tied to a group (TS 24.379 §11.1.1). The called party is named in a `resource-lists` body, and group affiliation is not required. The full profile, commands, fixture, call flows and gaps are in the [private-call test document](mcptt/PRIVATE_CALL_TEST.md).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Protected calls across servers (SPK)](mcptt/PROTECTED_SPLIT_TEST.md) | Protected group and private calls with separate participating and controlling servers; floor control re-keyed between CSK and SPK |
| [Protected private-call tests](mcptt/PROTECTED_PRIVATE_CALL_TEST.md) | End-to-end PCK for private, first-to-answer, ambient listening and emergency private calls; tampered I_MESSAGE (136); I_MESSAGE and SRTP wire verification |
| [Four-client private-call tests and call flows](mcptt/PRIVATE_CALL_TEST.md) | Commencement modes, decline/CANCEL/timeout, caller and called-party ruleset warnings, busy limit, coexistence with a group call, affiliation independence, private call timer, session refresh, first-to-answer, SIP/floor wire verification |
| [Private calls without floor control](mcptt/PRIVATE_NO_FLOOR_TEST.md) | Offers and answers without `m=application`, both parties speaking at once, no server-initiated end (past the private call timer), manual commencement, combined and split servers, SDP wire verification |

### Performed scenarios

Recorded on 2026-09-21 against image `openmcx:0.8-fta` (`6e367912416c`), 4-client clear-media fixture with `--private-refresh`, debug SIP. All reports record **PASS**. Assertion counts and evidence links for each ID are in the [test document](mcptt/PRIVATE_CALL_TEST.md#performed-tests).

| ID | Test / coverage | Result evidence |
|---|---|---|
| PC-01–PC-07 | Automatic, manual and forced commencement; two-way speech and contention; decline (480 + warning 110); CANCEL; 408 setup timeout | Scenario report (`artifacts/private-lab/artifacts/integration/private-call-results.json`) |
| PC-08–PC-09 | Rejections 107/126/143/144, called-party 127/159, unregistered callee 480, busy 486 at `max_calls` | Same report |
| PC-10–PC-12 | Alongside a group call, deaffiliated callee, 70 s private call timer spanning the session refresh | Same report |
| PC-13–PC-14 | SIP wire (37 checks, including private-dialog refresh and first-to-answer) and floor/RTP decoding from the server capture | SIP wire (`artifacts/private-lab/artifacts/integration/private-call-sip-wire.json`), floor wire (`artifacts/private-lab/artifacts/integration/private-call-floor-wire.json`), capture (`artifacts/private-lab/artifacts/integration/private-call.pcap`) |
| PC-15 | Regression on the same image: group lifecycle and failure in the private lab; every call type (266 checks in total) in a combined fixture on one server instance | Lifecycle (`artifacts/private-lab/artifacts/integration/prearranged-results.json`), failure (`artifacts/private-lab/artifacts/integration/prearranged-failure-results.json`), combined lab (`artifacts/combined-lab/artifacts/integration`) |
| PC-16 | First-to-answer: forced manual ringing, 183, first answer selected, others cancelled, concurrent answers, all declining → 480, filtering and 153/156 | Scenario report (`artifacts/private-lab/artifacts/integration/private-call-results.json`) |
| PC-17 | Unit tests for the codecs, caller/callee rulesets, first-to-answer authorization and CMS policy; native 17/17 and Go tests | `tools/mcx test` |

### Private-call coverage gaps

End-to-end PCK media protection is covered by the [protected private-call tests](mcptt/PROTECTED_PRIVATE_CALL_TEST.md). Pre-established and off-network private calls are not implemented; announced transfer and forwarding on no answer are. See the [full gap table](mcptt/PRIVATE_CALL_TEST.md#coverage-gaps). Physical-device validation (PC-P01–P05) has not been performed.

## Broadcast group call

A prearranged group call started with `<broadcast-ind>true` (TS 24.379 §4.12). Only the initiator may transmit, and the call ends when that transmission completes. The full profile, commands, fixture, call flow and gaps are in the [broadcast test document](mcptt/BROADCAST_CALL_TEST.md).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Four-client broadcast tests and call flow](mcptt/BROADCAST_CALL_TEST.md) | Fan-out with `broadcast-ind`, receive-only floor denial, B-bit/Permission to Request coding, automatic release, conference rejection, authorization and conflict rejection, late entry, SIP/floor wire verification |

### Performed scenarios

Recorded on 2026-09-21 against image `openmcx:0.3-broadcast` (`8041823d997c`) on a 4-client clear-media fixture with debug SIP. All reports record **PASS**. Assertion counts and evidence links for each ID are in the [test document](mcptt/BROADCAST_CALL_TEST.md#performed-tests).

| ID | Test / coverage | Result evidence |
|---|---|---|
| BC-01–BC-05 | Setup to all members, no conference subscription, cause-5 denial (idle floor and during transmission), speech to all receivers, release 0.15 s after the transmission ends | Scenario report (`artifacts/broadcast-lab/artifacts/integration/broadcast-call-results.json`) |
| BC-06–BC-08 | Conference SUBSCRIBE 480/105, initiator hangup ends the call, 403 for an unauthorised initiator, 486 during an ongoing group call | Same report |
| BC-09–BC-10 | A later normal call keeps normal floor rules; a late entrant joins a broadcast as a receiver | Same report |
| BC-11–BC-12 | SIP and floor wire checks (15, zero violations) and independent floor/RTP decode | SIP/floor wire (`artifacts/broadcast-lab/artifacts/integration/broadcast-call-sip-wire.json`), floor decode (`artifacts/broadcast-lab/artifacts/integration/broadcast-call-floor-wire.json`), capture (`artifacts/broadcast-lab/artifacts/integration/broadcast-call.pcap`) |
| BC-13 | Regression on the same image: prearranged lifecycle 21, failure 15, private call 53 checks | Lifecycle (`artifacts/broadcast-lab/artifacts/integration/prearranged-results.json`), failure (`artifacts/broadcast-lab/artifacts/integration/prearranged-failure-results.json`), private (`artifacts/broadcast-lab/artifacts/integration/private-call-results.json`) |
| BC-14 | Unit tests for B-bit floor coding, cause 5 and `broadcast-ind`; native 17/17 | `tools/mcx test` |

### Broadcast coverage gaps

Group-broadcast and user-broadcast hierarchies (subordinate-call preemption), broadcast override and priority, emergency/imminent broadcast, pre-established, chat-model and off-network broadcast are not implemented. See the [full gap table](mcptt/BROADCAST_CALL_TEST.md#coverage-gaps). Physical-device validation (BC-P01–P04) has not been performed.

## Chat group call

A group call in which each affiliated member joins the group's session individually (TS 24.379 §10.1.2). The first join creates the session, and the server never invites anyone. The full profile, commands, fixture, call flow and gaps are in the [chat test document](mcptt/CHAT_CALL_TEST.md).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Four-client chat group-call tests and call flow](mcptt/CHAT_CALL_TEST.md) | Join/create, no fan-out, rosters, floor and speech, capacity, creator leave/rejoin, release rules, call-type checks, coexistence, SIP/floor wire verification |

### Performed scenarios

Recorded on 2026-09-21 against image `openmcx:0.4-chat` (`8bbbd3fed314`) on a 4-client clear-media fixture with debug SIP. All reports record **PASS**. Assertion counts and evidence links for each ID are in the [test document](mcptt/CHAT_CALL_TEST.md#performed-tests).

| ID | Test / coverage | Result evidence |
|---|---|---|
| CH-01–CH-04 | The first joiner creates the session with no invites; joins share one session URI and rosters; contention and two-way speech; 486 warning 122 at capacity | Scenario report (`artifacts/chat-lab/artifacts/integration/chat-call-results.json`) |
| CH-05–CH-07 | The creator leaves and rejoins; release when one participant remains; lone joiner released after 20 s inactivity | Same report |
| CH-08–CH-09 | Warnings 117/118 for mismatched call types; chat and prearranged sessions run concurrently | Same report |
| CH-10–CH-11 | SIP and floor wire checks (11) and independent floor/RTP decode | SIP/floor wire (`artifacts/chat-lab/artifacts/integration/chat-call-sip-wire.json`), floor decode (`artifacts/chat-lab/artifacts/integration/chat-call-floor-wire.json`), capture (`artifacts/chat-lab/artifacts/integration/chat-call.pcap`) |
| CH-12 | Regression on the same image: prearranged 21 + 15, broadcast 32, private 53 checks | Lifecycle (`artifacts/chat-lab/artifacts/integration/prearranged-results.json`), failure (`artifacts/chat-lab/artifacts/integration/prearranged-failure-results.json`), broadcast (`artifacts/chat-lab/artifacts/integration/broadcast-call-results.json`), private (`artifacts/chat-lab/artifacts/integration/private-call-results.json`) |
| CH-13 | Go group-type test; native 17/17 | `tools/mcx test` |

### Chat coverage gaps

Emergency and imminent-peril chat, implicit affiliation, preconfigured-use-only and regrouped chat groups, chat calls on regroups and temporary groups, and participant preemption at capacity are implemented; chat-model broadcast and pre-established chat are not. See the [full gap table](mcptt/CHAT_CALL_TEST.md#coverage-gaps). Physical-device validation (CH-P01–P04) has not been performed.

## Ad hoc group call

A group call among users the initiator lists at call time (TS 24.379 clause 17). The server creates a temporary ad hoc group, invites the listed users (implicitly affiliated), and deletes the group when the call ends. The full profile, commands, fixture, call flow and gaps are in the [ad hoc test document](mcptt/ADHOC_CALL_TEST.md).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Four-client ad hoc group-call tests and call flow](mcptt/ADHOC_CALL_TEST.md) | Participant-list setup, generated group identity, implicit affiliation, rosters, floor and speech, leave/rejoin, release rules, authorization warnings, manual answer and decline, coexistence, call timer, SIP/floor wire verification |

### Performed scenarios

Recorded on 2026-09-21 against image `openmcx:0.6-adhoc` (`e29489f3ef0b`) on a 4-client clear-media fixture with debug SIP. All reports record **PASS**. Assertion counts and evidence links for each ID are in the [test document](mcptt/ADHOC_CALL_TEST.md#performed-tests).

| ID | Test / coverage | Result evidence |
|---|---|---|
| AH-01–AH-03 | Listed users invited into a generated ad hoc group (an unaffiliated invitee joins, an unlisted user is not invited); rosters; contention and two-way speech | Scenario report (`artifacts/adhoc-lab/artifacts/integration/adhoc-call-results.json`) |
| AH-04–AH-06 | Leave and rejoin by session identity; a lone initiator keeps the call; the initiator leaving releases it; a new identity per call | Same report |
| AH-07–AH-08 | Warnings 185/189/187 and 480; manual answer; a decline does not fail the call | Same report |
| AH-09–AH-10 | Runs alongside a prearranged call; TNG3 timer release at 30.03 s | Same report |
| AH-11–AH-12 | SIP and floor wire checks (15) and independent floor/RTP decode | SIP/floor wire (`artifacts/adhoc-lab/artifacts/integration/adhoc-call-sip-wire.json`), floor decode (`artifacts/adhoc-lab/artifacts/integration/adhoc-call-floor-wire.json`), capture (`artifacts/adhoc-lab/artifacts/integration/adhoc-call.pcap`) |
| AH-13 | Regression on the same image: prearranged 21 + 15, broadcast 32, private 53, chat 35 checks | Lifecycle (`artifacts/adhoc-lab/artifacts/integration/prearranged-results.json`), failure (`artifacts/adhoc-lab/artifacts/integration/prearranged-failure-results.json`), broadcast (`artifacts/adhoc-lab/artifacts/integration/broadcast-call-results.json`), private (`artifacts/adhoc-lab/artifacts/integration/private-call-results.json`), chat (`artifacts/adhoc-lab/artifacts/integration/chat-call-results.json`) |
| AH-14 | `test_adhoc_call` and Go ad hoc policy test; native 18/18 | `tools/mcx test` |

### Ad hoc coverage gaps

Criteria-based participants, participant modification, emergency/imminent-peril ad hoc, ad hoc emergency alerts, end-to-end security, broadcast ad hoc and pre-established ad hoc are not implemented. See the [full gap table](mcptt/ADHOC_CALL_TEST.md#coverage-gaps). Physical-device validation (AH-P01–P04) has not been performed.

## Emergency calls

A group or private call raised to emergency priority by an authorised user (TS 24.379 §6.2.8). The full profile, commands, fixture, call flow and gaps are in the [emergency test document](mcptt/EMERGENCY_CALL_TEST.md).

Recorded on 2026-09-22 against image `openmcx:0.18-emergency` (`18502ee52297`). All reports record **PASS**.

| ID | Test / coverage | Result evidence |
|---|---|---|
| EM-01–EM-08 | Emergency initial call and upgrade, alerts with location, unauthorised requests, late entry, preemption, second emergency user, cancellation, independent alerts (43-check group priority run) | Priority report (`artifacts/emergency-lab/artifacts/integration/prearranged-priority-results.json`) |
| EM-09 | TNG2 downgrades without releasing the call | Timer report (`artifacts/emergency-lab/artifacts/integration/prearranged-priority-timer-results.json`) |
| EM-10 | SIP and floor wire checks (10) | Wire report (`artifacts/emergency-lab/artifacts/integration/group-priority-sip-wire.json`) |
| EM-11 | Emergency private, chat, ad hoc and first-to-answer variants (69 checks) | See the [emergency test document](mcptt/EMERGENCY_CALL_TEST.md#performed-tests) |

## Imminent-peril group calls

A group call raised to a priority below emergency (TS 24.379 §6.2.8.1.9–13); group calls only. See the [imminent-peril test document](mcptt/IMMINENT_PERIL_CALL_TEST.md).

| ID | Test / coverage | Result evidence |
|---|---|---|
| IP-01–IP-05 | Imminent initial call, upgrade from normal, upgrade to emergency, unauthorised activation, wire E-bit and Resource-Priority | Priority report (`artifacts/emergency-lab/artifacts/integration/prearranged-priority-results.json`), wire report (`artifacts/emergency-lab/artifacts/integration/group-priority-sip-wire.json`) |
| IP-06 | Imminent-peril chat and ad hoc variants (6 checks) | Chat (`artifacts/fta-lab/artifacts/integration/chat-call-results.json`), ad hoc (`artifacts/fta-lab/artifacts/integration/adhoc-call-results.json`) |

## First-to-answer calls

A call offered to several users at once that continues with whoever answers first (TS 24.379 §11.1.1). See the [first-to-answer test document](mcptt/FIRST_TO_ANSWER_TEST.md).

| ID | Test / coverage | Result evidence |
|---|---|---|
| FA-01–FA-05 | Ringing, 183, first-answer selection, cancellation of others, declines, CANCEL, concurrent answers, list filtering and 156/107/153 (27 checks) | Private report (`artifacts/fta-lab/artifacts/integration/private-call-results.json`) |
| FE-01–FE-08 | Emergency first-to-answer: MEPP 2 while ringing, selection states, MEPP restore on cancel/decline, D-bit, in-dialog cancellation, recipient filtering, alert withdrawal (29 checks) | Emergency report (`artifacts/fta-lab/artifacts/integration/first-to-answer-emergency-results.json`) |
| FE-09 | Emergency first-to-answer wire checks (10) | Wire report (`artifacts/fta-lab/artifacts/integration/fta-emergency-sip-wire.json`) |

The combined run of all call types on the same image passed 336 assertions on one server (prearranged 21 + 15, broadcast 56, private 96, chat 67, ad hoc 81).

## Remotely initiated calls

One authorised user asks another user's device to place a call on their behalf (TS 24.379 §10.1.5 group, §11.1.7 private). See the [remotely initiated test document](mcptt/REMOTE_INITIATED_TEST.md).

Recorded on 2026-09-22 against image `openmcx:0.21-fixes` (`a2ddb25a01bf`). All reports record **PASS**. The first run, on `openmcx:0.19-remote` (`14f31e875a3b`), passed the same scenario and the 8 wire checks that existed then.

| ID | Test / coverage | Result evidence |
|---|---|---|
| RG-01–RG-06 | Group variant: remote user places the group call, silent request, 157 (unauthorised) and 120 (remote user not affiliated), busy remote user reports failure (20 checks) | Scenario report (`artifacts/fixes-lab/artifacts/integration/remote-group-call-results.json`) |
| RG-07 | Group-request SIP wire checks (10), including the called group in the response and its relay | Wire report (`artifacts/fixes-lab/artifacts/integration/remote-group-call-sip-wire.json`) |
| RG-08 | Private variant and regression: the private-call scenario (96) exercises the remotely initiated private call, transfer, forwarding and call-back; private services 32 | Private report (`artifacts/fixes-lab/artifacts/integration/private-call-results.json`) |

## Ambient listening calls

One user hears the surroundings of another user's device without that user being made aware of it (TS 24.379 §11.1.6, TS 23.379 §10.14). See the [ambient listening test document](mcptt/AMBIENT_LISTENING_TEST.md).

Recorded on 2026-09-22 against image `openmcx:0.21-fixes` (`a2ddb25a01bf`). All reports record **PASS**.

| ID | Test / coverage | Result evidence |
|---|---|---|
| AL-01–AL-13 | Remote-init and local-init calls, one-way media, Floor Deny cause 5, release permissions, administrator release, a failed call command that keeps the call (AL-09a), release by a call from or to the listened-to user, private call timer, 154/144/127 rejections, busy 480 (51 checks) | Scenario report (`artifacts/fixes-lab/artifacts/integration/ambient-listening-results.json`) |
| AL-14 | SIP wire checks (12) | Wire report (`artifacts/fixes-lab/artifacts/integration/ambient-listening-sip-wire.json`) |

## Unimplemented features

The blockers and implementation guide lists every not-implemented item across call types. It separates hard blockers (specification decisions, a second system, radio hardware, Phase-2 scope) from implementation effort, and gives an outline, code locations and a test plan for each, with a recommended order.

## Adding another call type

Add a row to the call-type table and a dedicated section with its own stable test ID prefix. Record the call mode, client count, transport/media protection, tested build, scenario, result, test-description link and capture/report links. Keep planned scenarios separate from performed tests, and preserve historical evidence when replacing a result.
