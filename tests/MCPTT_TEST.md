# MCPTT test index

The MCPTT tests, by call type: what each scenario checks, with a link to the report that holds its commands, call
flows, checks and coverage gaps. MCData tests are in the [MCData test index](MCDATA_TEST.md) and MCVideo tests in the
[MCVideo test index](MCVIDEO_TEST.md). How to run them is in the [developer guide](../docs/DEVELOPER_GUIDE.md#9-testing);
`tools/regress.py` runs every lab of the matrix. A passing scenario shows the procedure working in the lab, not
complete conformance to the specification.

## One server for all call types

The labs of the regression (`smoke`, `call-types`, `priority`, `first-to-answer`, …; `tools/regress.py --list`) are **test fixtures only**. Every lab runs the same `openmcx-mcptt-server` and `mcx-client` binaries; they differ only in generated configuration (groups, group type, user rulesets, timers). One server instance handles every implemented call type at the same time, keeping sessions apart by call type: the `call-types` lab of the regression runs every call-type scenario against one server instance. With `--split` the same binary runs as one controlling and two participating servers, and the same scenarios run unchanged ([multiple servers](#multiple-servers)).

## Call types

| Call type | Coverage |
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
| [Service authorisation by REGISTER](mcptt/REGISTER_AUTHORISATION_TEST.md) | The access token and client ID in the client's REGISTER, passed to the server by the SIP core's third-party REGISTER; de-registration at log-off |
| [XML protection](mcptt/XML_PROTECTION_TEST.md) | The sensitive XML content of MCPTT signalling encrypted hop by hop under the CSK or the SPK, including the access token at service authorisation |
| [Location management](mcptt/LOCATION_TEST.md) | Reporting configuration and triggers, reports, authorised requests with refresh and area filters, reporting changes, refusals 192/193/194, emergency alert and group geographic areas and the SEAL location management server (TS 24.545) |
| [Temporary groups formed by the GMS](mcptt/TEMPORARY_GROUP_TEST.md) | A GMC has the GMS combine groups into a temporary group (TS 24.481 6.3.14, 6.3.15): authorisation, identity in use, a constituent group combined once, 148 on a constituent group, group and chat calls on the temporary group, and tear down |
| [Regroup using a preconfigured group](mcptt/REGROUP_TEST.md) | An authorised user combines groups (group regroup) or named users (user regroup) into a temporary group that takes its configuration from a preconfigured group; authorisation (160/161), identity in use (165), constituents regrouped (148), a call on the regroup that user-regroup members take without selecting it, and removal (163 when unknown) |
| [Multiple servers](#multiple-servers) | Participating and controlling functions on separate servers (every call-type scenario) |
| Other call types | Off-network calls and pre-established sessions are not in the present edition; a pre-established session setup is refused with 403 warning 100 |

## Prearranged group call

A group with two participants is still a **group call**, not a private call. Four-client fixtures exercise different participant combinations; not every scenario keeps all four clients in one call.

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Two-client baseline and call flow](mcptt/MCPTT_TWO_CLIENT_TEST.md) | Setup, two-way speech, competing floor request, teardown and restart |
| [Four-client prearranged tests and call flow](mcptt/PREARRANGED_TEST.md) | Late entry, leave/rejoin, conference rosters, simultaneous groups, failure recovery, refresh and queued floor |
| [Four-client emergency and protected tests](mcptt/EMERGENCY_PROTECTED_TEST.md) | Priority/emergency, alerts, key provisioning, encrypted speech/floor and security |

### Scenarios

Counts are checks within a scenario, not distinct calls.

| ID | Test / coverage | Fixture and transport |
|---|---|---|
| PGC-01 | Two-way decoded speech, floor contention and teardown | 2 clients; clear media; debug SIP / TLS |
| PGC-02 | Client restart and reauthorization without server restart | 2 clients; debug SIP / TLS |
| PGC-03 | TLS reconnect | Baseline TLS lab |
| PGC-04 | SIP signalling and floor control dissected by Wireshark without malformed fields | Baseline lab; debug SIP / TLS |
| PGC-05 | Authorization rejection probes | Baseline lab; debug SIP / TLS |
| PGC-06 | Late entry, leave/rejoin, conference roster, concurrent groups and independent teardown | 4 clients; clear media / debug SIP |
| PGC-07 | Manual rejection, caller CANCEL, setup timeout, session survival and cleanup | 4-client clear-media fixture; selected pair |
| PGC-08 | Floor queue query, cancellation, requeue, grant confirmation and abandoned-grant cleanup | Clear-media fixture; queued participants |
| PGC-09 | Accepted SIP refreshes, conference notifications and cross-group media isolation | Clear-media capture |
| PGC-10 | Floor fields, repeated-acquisition SSRCs and zero RTCP expert diagnostics | Clear-media capture |
| PGC-11 | Authorized numeric/emergency preemption, imminent/emergency transitions, alerts, locations, cancellation and late entry | 4-client clear-media priority fixture |
| PGC-12 | Emergency timeout downgrades priority while retaining the call | Priority fixture; short configured timer |
| PGC-13 | Protected lifecycle, concurrent groups and actual GKTP renewal preserving manual deaffiliation | 4 clients; protected media / debug SIP |
| PGC-14 | Protected queued-floor procedures | Protected media / debug SIP |
| PGC-15 | Priority/emergency procedures with protected speech and floor | 4-client protected fixture / debug SIP |
| PGC-16 | Protected rejection, CANCEL, setup timeout and session survival | Protected fixture / debug SIP |
| PGC-17 | Live SRTP/SRTCP replay and tamper rejection; valid speech continues | Protected fixture / debug SIP |
| PGC-18 | SAVP negotiation, CSK/GKTP exchanges and byte-identical encrypted relay | Protected capture |
| PGC-19 | Accepted refresh transactions and conference notifications | Protected calls / debug SIP |
| PGC-20 | Protected lifecycle, late entry, rejoin and concurrent groups | 4 clients / TLS |
| PGC-21 | Protected priority/emergency, alert locations and cancellation | 4-client fixture / TLS |
| PGC-22 | Protected queued-floor procedures | TLS |
| PGC-23 | Protected rejection, CANCEL, timeout and session survival | TLS |
| PGC-24 | SIP/HTTPS security, including rejection of another certificate's matching CANCEL | Protected TLS fixture |
| PGC-25 | Supporting native protocol, SIP, floor, crypto and Go service regressions | Native/service suite |

Supporting native and service tests cover shared components and are not additional end-to-end call scenarios.

### Prearranged-group-call coverage gaps

“Not validated” below does not necessarily mean “not implemented”: some rows are missing evidence, others known limits.

| Area | Current gap / limit |
|---|---|
| Physical endpoints and access network | The scenarios run in Docker labs; group calls on Android phones over Wi-Fi are exercised in tutorials 1 and 2. Radio handover and coverage, carrier QoS, deployed NAT and firewalls, capacity and endurance are not validated. |
| Standards and independent peers | No complete clause-by-clause conformance campaign or external interoperability result. Protected fixtures require an explicit local E.6 numeric wire profile; cryptographic vector tests do not resolve that interoperability qualification. |
| Pre-established sessions | Not in present edition: they need resource sharing in the PCRF or PCF ([limitations](../docs/LIMITATIONS.md)). |
| Multiple MCPTT servers and systems | Separate participating and controlling servers in one system are tested ([multiple servers](#multiple-servers)); the non-controlling function's own session is not implemented; several MC systems are not in the present edition. |
| Emergency location and authorization profile | Positions are simulated. Location triggers, freshness and requests are implemented ([location tests](mcptt/LOCATION_TEST.md)); the MCPTT location XML is encrypted with the rest of the XML under XML protection ([XML protection tests](mcptt/XML_PROTECTION_TEST.md)); GPS and radio measurement and full standardized user/group XML authorization mapping remain outside the implemented profile. |
| Restart persistence | Emergency/originator state is held in memory. Key replay/ordering protections are process-local, not a persistent replay database. Existing client-restart tests do not establish server-restart continuity or anti-replay protection across a restart. |
| Key lifecycle qualification | Seamless identity-period handover, operational recovery and independent KMS/peer compatibility are not established. Unsupported key-document/profile extensions fail closed; expiry handling is not proof of uninterrupted rekey. |
| Exhaustive policies and fault combinations | Existing scenarios cover selected policies, timers and failures. They do not establish every membership/admission combination, all timer races, network partition behavior or high-availability failover. |

Private, broadcast, chat and ad hoc calls have their own sections ([private](#private-call), [broadcast](#broadcast-group-call), [chat](#chat-group-call), [ad hoc](#ad-hoc-group-call)). Off-network calls are not in the present edition.

## Private call

A call between exactly two MCPTT users that is not tied to a group (TS 24.379 §11.1.1). The called party is named in a `resource-lists` body, and group affiliation is not required. The full profile, commands, fixture, call flows and gaps are in the [private-call test document](mcptt/PRIVATE_CALL_TEST.md).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Protected calls across servers (SPK)](mcptt/PROTECTED_SPLIT_TEST.md) | Protected group and private calls with separate participating and controlling servers; floor control re-keyed between CSK and SPK |
| [Protected private-call tests](mcptt/PROTECTED_PRIVATE_CALL_TEST.md) | End-to-end PCK for private, first-to-answer, ambient listening and emergency private calls; tampered I_MESSAGE (136); I_MESSAGE and SRTP wire verification |
| [Four-client private-call tests and call flows](mcptt/PRIVATE_CALL_TEST.md) | Commencement modes, decline/CANCEL/timeout, caller and called-party ruleset warnings, busy limit, coexistence with a group call, affiliation independence, private call timer, session refresh, first-to-answer, SIP/floor wire verification |
| [Private calls without floor control](mcptt/PRIVATE_NO_FLOOR_TEST.md) | Offers and answers without `m=application`, both parties speaking at once, no server-initiated end (past the private call timer), manual commencement, combined and split servers, SDP wire verification |

### Scenarios

| ID | Test / coverage |
|---|---|
| PC-01–PC-07 | Automatic, manual and forced commencement; two-way speech and contention; decline (480 + warning 110); CANCEL; 408 setup timeout |
| PC-08–PC-09 | Rejections 107/126/143/144, called-party 127/159, unregistered callee 480, busy 486 at `max_calls` |
| PC-10–PC-12 | Alongside a group call, deaffiliated callee, 70 s private call timer spanning the session refresh |
| PC-13–PC-14 | SIP wire (37 checks, including private-dialog refresh and first-to-answer) and floor/RTP decoding from the server capture |
| PC-16 | First-to-answer: forced manual ringing, 183, first answer selected, others cancelled, concurrent answers, all declining → 480, filtering and 153/156 |
| PC-17 | Unit tests for the codecs, caller/callee rulesets, first-to-answer authorization and CMS policy (C++ and Go) |

### Private-call coverage gaps

End-to-end PCK media protection is covered by the [protected private-call tests](mcptt/PROTECTED_PRIVATE_CALL_TEST.md). Pre-established and off-network private calls are not in the present edition; announced transfer and forwarding on no answer are implemented. See the [full gap table](mcptt/PRIVATE_CALL_TEST.md#coverage-gaps). The scenarios run in Docker labs, not on physical devices.

## Broadcast group call

A prearranged group call started with `<broadcast-ind>true` (TS 24.379 §4.12). Only the initiator may transmit, and the call ends when that transmission completes. The full profile, commands, fixture, call flow and gaps are in the [broadcast test document](mcptt/BROADCAST_CALL_TEST.md).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Four-client broadcast tests and call flow](mcptt/BROADCAST_CALL_TEST.md) | Fan-out with `broadcast-ind`, receive-only floor denial, B-bit/Permission to Request coding, automatic release, conference rejection, authorization and conflict rejection, late entry, SIP/floor wire verification |

### Scenarios

| ID | Test / coverage |
|---|---|
| BC-01–BC-05 | Setup to all members, no conference subscription, cause-5 denial (idle floor and during transmission), speech to all receivers, release 0.15 s after the transmission ends |
| BC-06–BC-08 | Conference SUBSCRIBE 480/105, initiator hangup ends the call, 403 for an unauthorised initiator, 486 during an ongoing group call |
| BC-09–BC-10 | A later normal call keeps normal floor rules; a late entrant joins a broadcast as a receiver |
| BC-11–BC-12 | SIP and floor wire checks (15, zero violations) and independent floor/RTP decode |
| BC-14 | Unit tests for B-bit floor coding, cause 5 and `broadcast-ind` |
| BC-15–BC-17 | Group-broadcast and user-broadcast hierarchies, override |
| BC-18–BC-22 | Emergency and imminent-peril broadcast: B+D and B+E floor coding, receivers still receive-only, initiator-only in-dialog change |

### Broadcast coverage gaps

Chat-model broadcast is not implemented; pre-established and off-network broadcast are not in the present edition. Hierarchies and emergency or imminent-peril broadcast follow a project or local policy: TS 24.379 has no stage-3 procedure for them to check interoperability against. See the [full gap table](mcptt/BROADCAST_CALL_TEST.md#coverage-gaps). The scenarios run in Docker labs, not on physical devices.

## Chat group call

A group call in which each affiliated member joins the group's session individually (TS 24.379 §10.1.2). The first join creates the session, and the server never invites anyone. The full profile, commands, fixture, call flow and gaps are in the [chat test document](mcptt/CHAT_CALL_TEST.md).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Four-client chat group-call tests and call flow](mcptt/CHAT_CALL_TEST.md) | Join/create, no fan-out, rosters, floor and speech, capacity, creator leave/rejoin, release rules, call-type checks, coexistence, SIP/floor wire verification |

### Scenarios

| ID | Test / coverage |
|---|---|
| CH-01–CH-04 | The first joiner creates the session with no invites; joins share one session URI and rosters; contention and two-way speech; 486 warning 122 at capacity |
| CH-05–CH-07 | The creator leaves and rejoins; release when one participant remains; lone joiner released after 20 s inactivity |
| CH-08–CH-09 | Warnings 117/118 for mismatched call types; chat and prearranged sessions run concurrently |
| CH-10–CH-11 | SIP and floor wire checks (11) and independent floor/RTP decode |
| CH-13 | Go group-type test |

### Chat coverage gaps

Chat calls on regroups and temporary groups are implemented, without the INVITE to the other constituent groups' non-controlling functions (§10.1.2.4.1 step 11b). Chat-model broadcast is not implemented and pre-established chat is not in the present edition. See the [full gap table](mcptt/CHAT_CALL_TEST.md#coverage-gaps). The scenarios run in Docker labs, not on physical devices.

## Ad hoc group call

A group call among users the initiator lists at call time (TS 24.379 clause 17). The server creates a temporary ad hoc group, invites the listed users (implicitly affiliated), and deletes the group when the call ends. The full profile, commands, fixture, call flow and gaps are in the [ad hoc test document](mcptt/ADHOC_CALL_TEST.md).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Four-client ad hoc group-call tests and call flow](mcptt/ADHOC_CALL_TEST.md) | Participant-list setup, generated group identity, implicit affiliation, rosters, floor and speech, leave/rejoin, release rules, authorization warnings, manual answer and decline, coexistence, call timer, SIP/floor wire verification |

### Scenarios

| ID | Test / coverage |
|---|---|
| AH-01–AH-03 | Listed users invited into a generated ad hoc group (an unaffiliated invitee joins, an unlisted user is not invited); rosters; contention and two-way speech |
| AH-04–AH-06 | Leave and rejoin by session identity; a lone initiator keeps the call; the initiator leaving releases it; a new identity per call |
| AH-07–AH-08 | Warnings 185/189/187 and 480; manual answer; a decline does not fail the call |
| AH-09–AH-10 | Runs alongside a prearranged call; TNG3 timer release at 30.03 s |
| AH-11–AH-12 | SIP and floor wire checks (15) and independent floor/RTP decode |
| AH-14 | `test_adhoc_call` and the Go ad hoc policy test |

### Ad hoc coverage gaps

End-to-end security is not implemented (the calls are clear) and pre-established ad hoc calls are not in the present edition. See the [full gap table](mcptt/ADHOC_CALL_TEST.md#coverage-gaps). The scenarios run in Docker labs, not on physical devices.

## Emergency calls

A group or private call raised to emergency priority by an authorised user (TS 24.379 §6.2.8). The full profile, commands, fixture, call flow and gaps are in the [emergency test document](mcptt/EMERGENCY_CALL_TEST.md).

| ID | Test / coverage |
|---|---|
| EM-01–EM-08 | Emergency initial call and upgrade, alerts with location, unauthorised requests, late entry, preemption, second emergency user, cancellation, independent alerts (43-check group priority run) |
| EM-09 | TNG2 downgrades without releasing the call |
| EM-10 | SIP and floor wire checks (10) |
| EM-11 | Emergency private, chat, ad hoc and first-to-answer variants (69 checks) |
| BC-18, AH-15b | Emergency broadcast group call and emergency broadcast ad hoc call |

## Imminent-peril group calls

A group call raised to a priority below emergency (TS 24.379 §6.2.8.1.9–13); group calls only. See the [imminent-peril test document](mcptt/IMMINENT_PERIL_CALL_TEST.md).

| ID | Test / coverage |
|---|---|
| IP-01–IP-05 | Imminent initial call, upgrade from normal, upgrade to emergency, unauthorised activation, wire E-bit and Resource-Priority |
| IP-06 | Imminent-peril chat and ad hoc variants (6 checks) |
| BC-19 | Imminent-peril broadcast: initiator upgrade in-dialog, B+E floor coding |

## First-to-answer calls

A call offered to several users at once that continues with whoever answers first (TS 24.379 §11.1.1). See the [first-to-answer test document](mcptt/FIRST_TO_ANSWER_TEST.md).

| ID | Test / coverage |
|---|---|
| FA-01–FA-05 | Ringing, 183, first-answer selection, cancellation of others, declines, CANCEL, concurrent answers, list filtering and 156/107/153 (27 checks) |
| FE-01–FE-08 | Emergency first-to-answer: MEPP 2 while ringing, selection states, MEPP restore on cancel/decline, D-bit, in-dialog cancellation, recipient filtering, alert withdrawal (29 checks) |
| FE-09 | Emergency first-to-answer wire checks (10) |

## Remotely initiated calls

One authorised user asks another user's device to place a call on their behalf (TS 24.379 §10.1.5 group, §11.1.7 private). See the [remotely initiated test document](mcptt/REMOTE_INITIATED_TEST.md).

| ID | Test / coverage |
|---|---|
| RG-01–RG-06 | Group variant: remote user places the group call, silent request, 157 (unauthorised) and 120 (remote user not affiliated), busy remote user reports failure (20 checks) |
| RG-07 | Group-request SIP wire checks (10), including the called group in the response and its relay |
| RG-08 | Private variant and regression: the private-call scenario (96) exercises the remotely initiated private call, transfer, forwarding and call-back; private services 32 |

## Ambient listening calls

One user hears the surroundings of another user's device without that user being made aware of it (TS 24.379 §11.1.6, TS 23.379 §10.14). See the [ambient listening test document](mcptt/AMBIENT_LISTENING_TEST.md).

| ID | Test / coverage |
|---|---|
| AL-01–AL-13 | Remote-init and local-init calls, one-way media, Floor Deny cause 5, release permissions, administrator release, a failed call command that keeps the call (AL-09a), release by a call from or to the listened-to user, private call timer, 154/144/127 rejections, busy 480 (51 checks) |
| AL-14 | SIP wire checks (12) |

## Multiple servers

Separate participating and controlling servers in one system (TS 23.379 MCPTT-3).

| ID | Test / coverage |
|---|---|
| MS-01 | Split system (`--split`: one controlling and two participating servers): every call-type scenario runs unchanged (prearranged, failure and refresh, broadcast, private, chat, ad hoc, remote group, ambient listening) |
| MS-02 | Split system, the other scenarios: emergency first-to-answer, functional aliases, private call services, group priority, floor queue |
| MS-03 | [Protected calls across servers](mcptt/PROTECTED_SPLIT_TEST.md): group and private calls with floor control re-keyed between the CSK and the SPK |

## Not covered

What the present edition does not include, and the known limits of what it implements, are in the [limitations](../docs/LIMITATIONS.md).

## Adding another call type

Add a row to the call-type table and a section with its own stable test ID prefix, the call mode, client count, transport and media protection, the scenario and a link to its report.
