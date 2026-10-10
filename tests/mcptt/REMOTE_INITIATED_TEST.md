# Remotely initiated call tests

These tests cover **remotely initiated calls**: one authorised user asks another user's device, by SIP MESSAGE, to place a call on their behalf (TS 24.379 §10.1.5 group, §11.1.7 private). The remote user's device originates a normal call and reports the outcome back to the requester. The recorded results cover the implemented subset below, not complete conformance. Pre-established sessions are not implemented; see [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md). Related: [private calls](PRIVATE_CALL_TEST.md), [prearranged group calls](PREARRANGED_TEST.md).

## How remotely initiated calls work

- **Request.** The requesting user sends a SIP MESSAGE to the service URI carrying a `request-type` (`remotely-initiated-group-call-request` or `remotely-initiated-private-call-request`), a `resource-lists` body naming the **remote user** to act, and — for a group call — the targeted group in `<mcptt-request-uri>`. A `notify-remote-user` flag says whether the remote user may be told.
- **Authorization.** The server checks the requester's ruleset: `allow-request-remote-init-group-call` (else 403/157) or `allow-request-remote-init-private-call` (else 403/158). For a group request it also acts as the controlling function: calls on a `<preconfigured-group-use-only>` group are refused (403/167), and the remote user must be affiliated to the group (else 403/120).
- **Relay.** The server relays the request to the remote user, moving the group into `<mcptt-calling-group-id>` and setting `<mcptt-request-uri>` to the remote user (§10.1.5.4 step 7a).
- **Application priority.** The request may carry `<ric-app-level-priority>`, an RFC 8101 `namespace.priority` value (§10.1.5.2.1 step 3dD, §11.1.7.2.1). The remote user's device puts it in the Resource-Priority header of the call it places (§10.1.5.2.2 step 2b, §11.1.7.2.2 step 3b). The server otherwise accepts only the provisioned normal, emergency and imminent peril values; it remembers the value of each request it relays and accepts it once, on the follow-up call to the requested group or user within 60 s. The emergency and imminent peril values stay reserved for those calls.
- **Remote origination.** The remote user's device places the call — a normal group call to the targeted group, or a private call to the target in the requested commencement mode. When `notify-remote-user` is false the device does not indicate the request to its user; the lab still records it in the status file and event log so the test harness can verify it.
- **Outcome.** The remote user's device sends a response MESSAGE back to the requester with `remotely-initiated-call-outcome` = success or fail. For a group call the response names the called group in `<mcptt-request-uri>`, and the server moves it to `<mcptt-calling-group-id>` when relaying, as for the request. Success is reported when the placed call reaches a provisional or 2xx response; a busy or unauthorised remote user reports fail. (For a private call, no report is sent when the requester itself was the successfully called target.)

## Variants

| Variant | Command | Detail | Tests |
|---|---|---|---|
| Remotely initiated **group** call | `remote-group-call <remote> <group> [silent] [priority=<ns.value>]` | The remote user places a prearranged group call to the group and becomes its initiator (§10.1.5) | RG-01–RG-11 below |
| Remotely initiated **private** call | `remote-call <remote> <target> [auto\|manual\|force-auto] [silent] [priority=<ns.value>]` | The remote user places a private call to the target in the requested commencement mode (§11.1.7) | [PS-04, PS-04a, PS-05](PRIVATE_CALL_TEST.md#private-call-services) |

## Implemented profile (group variant)

| Step | Behavior | Reference |
|---|---|---|
| Request | SIP MESSAGE to the service URI: `request-type` remotely-initiated-group-call-request, `resource-lists` = remote user, `<mcptt-request-uri>` = group, `notify-remote-user` true/false | 24.379 §10.1.5.2.1 |
| Client check | The requesting client refuses a group whose document has `<preconfigured-group-use-only>` true. The group server serves documents to members only, so for other groups the server decides | §10.1.5.2.1 step 1A |
| Requester authorization | `allow-request-remote-init-group-call`; else 403 `157 user not authorised to request a remotely initiated group call` | §10.1.5.3.1 step 3 |
| Preconfigured-use-only group | 403 `167 call is not allowed on the preconfigured group`, for the request and the response | §10.1.5.4 step 2A |
| Controlling check | The remote user must be affiliated to the group; else 403 `120 user is not affiliated to this group` | §10.1.5.4 step 3 |
| Application priority | `<ric-app-level-priority>` relayed unchanged; the remote user's INVITE carries it as Resource-Priority, accepted for that follow-up call only | §10.1.5.2.1 step 3dD; §10.1.5.2.2 step 2b |
| Relay | The group moves to `<mcptt-calling-group-id>`, `<mcptt-request-uri>` becomes the remote user, `<mcptt-calling-user-id>` the requester | §10.1.5.4 step 7 |
| Remote origination | The remote user places a normal prearranged group call (10.1.1.2.1.1); `notify-remote-user` false suppresses user indication | §10.1.5.2.2 |
| Outcome | Response MESSAGE with `remotely-initiated-call-outcome` success or fail and the called group in `<mcptt-request-uri>`; the server relays it to the requester with the group in `<mcptt-calling-group-id>` | §10.1.5.2.2 step 1e; §10.1.5.4 step 7 |

The group-call ruleset is served by the CMS as `group_call` on the internal user resource and as the `<allow-request-remote-init-group-call>` action in the user profile document. Provision it per user in `config/lab.json` with `"group_call": {"remote_init": true}`.

### Client commands and status

```bash
mcx-client --config FILE --command 'remote-group-call sip:bob.mcptt@mcx.test sip:operations@mcx.test'
mcx-client --config FILE --command 'remote-group-call sip:bob.mcptt@mcx.test sip:operations@mcx.test silent'
mcx-client --config FILE --command 'remote-group-call sip:bob.mcptt@mcx.test sip:operations@mcx.test priority=mcptt.5'
mcx-client --config FILE --command 'remote-call sip:bob.mcptt@mcx.test sip:carol.mcptt@mcx.test manual'
```

The requester's status shows `service_outcomes["remotely-initiated-group-call-response"]` (success/fail) and `last_service_result` (the MESSAGE status, e.g. 403 with warning 157 or 120). The remote user records `service_outcomes["remote-group"]`.

## Separate four-client fixture

```bash
docker build -t openmcx:0.21-fixes -f docker/Dockerfile .
python3 tools/prepare-prearranged-test.py --directory artifacts/fixes-lab --project openmcx-fixes \
  --debug-sip --private-call --image openmcx:0.21-fixes
mkdir -p artifacts/fixes-lab/artifacts/speech
cp artifacts/speech/{alpha,bravo}.wav artifacts/fixes-lab/artifacts/speech/
.cache/deps/docker-compose-linux-x86_64 -p openmcx-fixes -f artifacts/fixes-lab/compose.json up -d
```

The `--private-call` fixture grants client-a `group_call.remote_init`; clients b–d do not have it, so they are the unauthorised cases. It also defines the preconfigured-use-only group `<group>-ric-preconf` with members b, c and d but not a: the group management server serves a group document to members only, so client-a's request for that group reaches the server (167), while member client-c refuses it itself (step 1A).

Capture the server namespace, then run and verify:

```bash
SERVER=$(.cache/deps/docker-compose-linux-x86_64 -p openmcx-fixes -f artifacts/fixes-lab/compose.json ps -q mcptt-server)
docker run --rm --name openmcx-fixes-capture --network "container:$SERVER" --cap-drop ALL --cap-add NET_RAW \
  openmcx-dev:0.1 tcpdump -Z root -i eth0 -U -s 0 -w - '(udp and not port 53) or tcp port 5060' \
  > artifacts/fixes-lab/artifacts/integration/remote-group-call.pcap &
python3 tests/integration/remote_group_call_scenario.py \
  --compose artifacts/fixes-lab/compose.json --artifacts artifacts/fixes-lab/artifacts --project openmcx-fixes
sleep 5  # let the capture flush before stopping it
docker stop openmcx-fixes-capture
python3 tests/integration/verify_remote_group_call.py artifacts/fixes-lab/artifacts/integration/remote-group-call.pcap \
  --service sip:mcptt@mcx.test --group sip:operations@mcx.test \
  --output artifacts/fixes-lab/artifacts/integration/remote-group-call-sip-wire.json
```

Stopping the capture container straight after the scenario can drop the last packets (the RG-06 exchange), which fails the success-and-fail outcome check; wait a few seconds first.

## Performed tests

Recorded on **2026-09-22** against image `openmcx:0.21-fixes` (`a2ddb25a01bf`), built from branch `feat/mcptt-phase1` at the tree committed as `bec8c19`. The fixture ran clear media with debug SIP. Every report records **PASS**. The group scenario made 20 assertions: 17 numbered, plus readiness, idle-start and unchanged-server checks. All ran on one server instance. The first run on `openmcx:0.19-remote` (`14f31e875a3b`) passed the same 20 assertions and the 8 wire checks that existed then.

| ID | Scenario | Checks | Result evidence |
|---|---|---|---|
| RG-01 | Authorised request: the remote user (client-b) places the group call, all four members join, the remote user is the initiator (not the requester), and both sides record success | 4 | Scenario report (`artifacts/fixes-lab/artifacts/integration/remote-group-call-results.json`) |
| RG-02 | Speech in the resulting call reaches the other members; floor release; teardown | 3 | Same report |
| RG-03 | A silent request (`notify-remote-user` false) still establishes the call and reports success | 3 | Same report |
| RG-04 | An unauthorised requester (client-c, no `group_call` ruleset) is rejected with 403/157 and no call is created | 2 | Same report |
| RG-05 | A request naming a group the remote user is not affiliated to is rejected with 403/120 | 1 | Same report |
| RG-06 | A busy remote user reports failure to the requester without disturbing its own call | 4 | Same report |
| RG-07 | SIP wire checks (10): originating requests to the service URI with one resource-lists remote user and the group in `mcptt-request-uri`; `notify-remote-user` true and silent both present; the relayed request carries the group in `mcptt-calling-group-id` and the remote user in `mcptt-request-uri`; responses name the called group in `mcptt-request-uri`; the relayed response carries the group in `mcptt-calling-group-id` and the requester in `mcptt-request-uri`; 200 OK to accepted requests; 157 and 120 rejections; success and fail response outcomes; a normal group INVITE from the remote user | 10 | Wire report (`artifacts/fixes-lab/artifacts/integration/remote-group-call-sip-wire.json`), capture (`artifacts/fixes-lab/artifacts/integration/remote-group-call.pcap`) |
| RG-08 | Regression on the same image: the private-call scenario 96 (which exercises the remotely initiated **private** call, transfer, forwarding and call-back), private services 32, and the all-call-types run on one server instance (see the [test index](../MCPTT_TEST.md#one-server-for-all-call-types)) | 128 | Private (`artifacts/fixes-lab/artifacts/integration/private-call-results.json`), services (`artifacts/fixes-svc-lab/artifacts/integration/private-services-results.json`), all types (`artifacts/all-types-lab/run.log`) |

### Application priority and preconfigured-use-only groups — 2026-09-25

Image `openmcx:item4-e` (`132768e2c262`), built from branch `mcptt-mcdata` on `e55382c` with these changes. The group scenario made **29 assertions**, all **PASS**, on the combined server (`call-types` lab) and on separate participating and controlling servers (`call-types-split` lab) of `tools/regress.py --select mcptt` (21 labs, all passing). A separate capture on `openmcx:item4-b` passed all 13 wire checks.

| ID | Scenario | Checks |
|---|---|---|
| RG-09 | A request with `<ric-app-level-priority>` mcptt.5: the call is placed and reported as a success, the remote user's INVITE carries Resource-Priority mcptt.5, and the server accepts it for that user and group | 5 |
| RG-10 | A request for the preconfigured-use-only group from client-a, which is not a member and so cannot read its document, is rejected 403/167 and creates no call | 2 |
| RG-11 | Member client-c refuses the same request itself (step 1A), and no MESSAGE reaches the server | 2 |
| RG-07 (added) | Wire: a 403/167 rejection; `<ric-app-level-priority>` relayed unchanged to the remote user; the remote user's group INVITE carries it as Resource-Priority | 3 |

The private variant's priority is PS-04a in the [private call services](PRIVATE_CALL_TEST.md#private-call-services).

## High-level call flow (group variant)

Kamailio and floor detail are omitted. The requester A and remote user B are both served by the one combined MCPTT server.

```mermaid
sequenceDiagram
    participant A as Requesting user A
    participant S as MCPTT server
    participant B as Remote user B
    participant G as Other group members
    A->>S: MESSAGE request-type remotely-initiated-group-call-request, resource-lists B, mcptt-request-uri group
    Note over S: Authorise A (157), refuse a preconfigured-use-only group (167), check B affiliated to group (120)
    S->>B: MESSAGE, mcptt-calling-group-id group, mcptt-request-uri B, calling user A
    S-->>A: 200 OK
    B-->>S: 200 OK
    Note over B: Place a normal group call (unless silent, with no user indication)
    B->>S: INVITE group
    S->>A: INVITE (fan-out)
    S->>G: INVITE (fan-out)
    A-->>S: 200 OK
    G-->>S: 200 OK
    S-->>B: 200 OK
    B->>S: MESSAGE response-type remotely-initiated-group-call-response, outcome success, mcptt-request-uri group, resource-lists A
    S->>A: MESSAGE outcome success, mcptt-calling-group-id group
    A-->>S: 200 OK
```

## Physical-setup validation — not yet performed

| ID | Physical test to perform | What to validate and retain |
|---|---|---|
| RG-P01 | Remote group call to a real device | The remote device places the call; the requester sees the outcome |
| RG-P02 | Silent remote request | No indication of any kind on the remote device (display, audio, haptic) |
| RG-P03 | Busy and unauthorised remote users | Correct failure reporting; the remote device's own call undisturbed |

## Coverage gaps

The blockers and implementation guide describes each item.

| Area | Gap |
|---|---|
| Targeted group vs the remote user's group | The lab configures one group per client, so the remote user places the call only to its own affiliated group. A remote user asked to call a different group it is not affiliated to returns 120. |
| Pre-established sessions | Remotely initiated calls over a pre-established session (§10.1.5.2.2 step 3) are not implemented (H8). |
| Multiple servers | Both variants pass on the H2 split system. |
| Wire qualification | In-repository decoders only; no independent-peer run. |
