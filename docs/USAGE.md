# Using the OpenMCX lab

How to build and run the lab, drive the clients, verify the services and read the SIP in Wireshark. What the implementation supports is in the [feature list](FEATURES.md).

## Build and run

Requirements: Linux with Docker, SCTP kernel support, Python 3, and OpenSSL.
The build installs protocol dependencies inside containers. It does not install
host packages or modify other Docker projects.

```bash
tools/mcx fetch
tools/mcx provision                  # reads config/lab.json; preserves existing secrets
tools/mcx build
tools/mcx speech
tools/mcx up
tools/mcx compose ps
```

The lab clients run `mcx-client`, which lives in the
[openmcx-client](https://github.com/openMCX/openmcx-client) repository (directory `linux/`) and
builds against this repository's protocol libraries. Check it out beside this repository
(`../openmcx-client`); `tools/mcx build` then also builds the client image `openmcx-client:0.1`
with its `linux/tools/build-image`. Set `MCX_CLIENT_DIR` if it is elsewhere.

Edit [config/lab.json](../config/lab.json) before provisioning to change the domain,
users and group. Generated credentials and certificates live in the ignored,
private `config/generated/` directory. Do not publish it.

```bash
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command call
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'ptt /artifacts/speech/alpha.wav'
tools/mcx compose exec -T client-b mcx-client --config /config/client-b.json --status
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command hangup
```

For a private call, name the called MCPTT ID and a commencement mode (`auto`,
`manual` or `force-auto`). The callee uses `answer` or `reject` when its call rings:

```bash
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'private sip:bob.mcptt@mcx.test auto'
```

Private calls are authorized by each user's `private_call` ruleset in
[config/lab.json](../config/lab.json) and do not require affiliation. Related commands:

- `private <id> [mode] emergency [alert]`, and `emergency on|off [alert]` during a
  private call, for emergency private calls;
- `private <id> [mode] no-floor` for a private call without floor control, where both
  users speak at once (`ptt <wav>` starts speaking without a floor request);
- `first-to-answer <id> <id>…` rings several users and connects the first to answer;
- `callback <id> [low|normal|high]`, `callback-cancel <id>`, `callback-fulfil <id>`;
- `remote-call <remote id> <target id> [mode] [silent]`, `transfer <id>` during a call,
  and `forward <id>` while a call rings.

See the [private-call tests](../tests/mcptt/PRIVATE_CALL_TEST.md).

`call broadcast` starts a broadcast group call. Only the initiator can talk
(other members' floor requests are denied as receive-only, unless they are listed
in `call_policy.broadcast_overriders`), and the call ends when the transmission
completes. On a `group-broadcast` or `user-broadcast` GMS group, the broadcast
first releases the ongoing calls of the users it reaches. See the
[broadcast tests](../tests/mcptt/BROADCAST_CALL_TEST.md).

On a chat group (GMS `"type": "chat"`), each member runs `chat` to create or
join the group's session. The server invites nobody unless the call becomes an
emergency or imminent-peril call (`chat emergency`, `chat imminent`). An
unaffiliated member is affiliated implicitly when it joins. See the
[chat tests](../tests/mcptt/CHAT_CALL_TEST.md).

`adhoc [broadcast] [emergency|imminent] <MCPTT ID or alias> …` starts an ad hoc
group call with the listed users; `adhoc criteria affiliated:<group>` selects them
by criteria instead. The server creates a temporary ad hoc group for the call and
deletes it when the call ends. `adhoc-modify add|remove <id>…` changes the
participants, and `adhoc-alert <criteria>` / `adhoc-alert cancel` raises an ad hoc
group emergency alert. See the [ad hoc tests](../tests/mcptt/ADHOC_CALL_TEST.md).

`call emergency` / `call imminent` start emergency and imminent-peril group calls,
and `emergency on|off`, `imminent on|off` and `alert on|off` change a running call.
`first-to-answer <id> <id> … [emergency [alert]]` rings several users and keeps
whoever answers first. See the [emergency](../tests/mcptt/EMERGENCY_CALL_TEST.md),
[imminent-peril](../tests/mcptt/IMMINENT_PERIL_CALL_TEST.md) and
[first-to-answer](../tests/mcptt/FIRST_TO_ANSWER_TEST.md) tests.

`remote-group-call <remote> <group>` and `remote-call <remote> <target>` ask another
user's device to place a group or private call (TS 24.379 §10.1.5, §11.1.7). See the
[remotely initiated tests](../tests/mcptt/REMOTE_INITIATED_TEST.md).

`fa activate|takeover|deactivate <alias>` manages functional aliases,
`fa use <alias>` presents one on outgoing calls, and `private-fa <alias>` and
`first-to-answer-fa <alias>` call one. See the
[functional-alias tests](../tests/mcptt/FUNCTIONAL_ALIAS_TEST.md).

Other commands: `release`, `deaffiliate`, `quit`. Status and received 16 kHz mono
WAV audio are written under `artifacts/client-a/` and `artifacts/client-b/`.
A client first authenticates with IdMS, retrieves configuration/group documents,
registers with the SIP core, authorizes MCPTT service, and affiliates.
PTT is permitted only in an established call; the server forwards only the
current authorized floor owner's negotiated RTP stream.

## MCData commands

The MCData client runs inside `mcx-client` and shares its SIP registration. It
authorises with `mcdata-server` (public service identity `sip:mcdata@DOMAIN`)
and affiliates to its MCData group. Standalone SDS messages (TS 24.282 §9.2.2)
go one-to-one or to a group, with delivery and read notifications:

```bash
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds delivery sip:bob.mcdata@mcx.test Hello'
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds-group read sip:operations@mcx.test All units'
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds-adhoc sip:bob.mcdata@mcx.test Meet at gate 3'
tools/mcx compose exec -T client-b mcx-client --config /config/client-b.json --command 'sds-display <message id>'
tools/mcx compose exec -T client-b mcx-client --config /config/client-b.json --command 'mcdata-fa activate sip:desk.fa@mcx.test'   # alias defined in the CMS
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds-fa sip:desk.fa@mcx.test Call the desk'
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'mcdata-alert'          # group emergency alert; 'mcdata-alert cancel' ends it
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'fd-send completed sip:bob.mcdata@mcx.test /tmp/report.txt'
tools/mcx compose exec -T client-b mcx-client --config /config/client-b.json --command 'fd-accept <message id>'   # or fd-reject, fd-defer
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds-media sip:bob.mcdata@mcx.test Hello'   # over MSRP
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds-session group=sip:operations@mcx.test emergency'   # or imminent
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds-session send delivery All units'
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds-session group=sip:operations@mcx.test emergency alert'
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds-session emergency cancel'
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'fd-media mandatory completed sip:bob.mcdata@mcx.test /tmp/report.txt'
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'sds-session adhoc=sip:bob.mcdata@mcx.test,sip:client-c.mcdata@mcx.test'   # ad hoc group session
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'ipcon sip:bob.mcdata@mcx.test'   # IP connectivity
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'ipcon-ping 10.77.0.2 5'
```

SDS also travels over the media plane in MSRP (TS 24.282 §9.2.3, §9.2.4 with
TS 24.582), as standalone messages or in a session that stays open and can become
an emergency or imminent peril communication, and a file can be distributed the same
way (§10.2.5) instead of being uploaded to the content server. `sds-media`,
`sds-session` and `fd-media` also take an ad hoc group (clause 24):
`adhoc=<ID,ID,...>`, `adhoc=criteria=<criteria>` or `adhoc=group=<ad hoc group>`. See the
[media plane tests](../tests/mcdata/MCDATA_MEDIA_TEST.md).

IP connectivity (§20 with TS 24.582 §13) opens a one-to-one GRE-in-UDP tunnel
between two clients through `mcdata-server`. Each client acts as a small IPv4
endpoint at its `mcdata.ipconn.address` that answers ICMP echo. See the
[IP connectivity tests](../tests/mcdata/MCDATA_IPCONN_TEST.md).

Communications over the media plane are released by policy, on the server's time
and data limits, by an operator or by an authorised user, with or without an
announced intent that the originator can answer with an extension request
(clause 13); `mcdata-release` drives it from a client. See the
[communication release tests](../tests/mcdata/MCDATA_RELEASE_TEST.md).
`sds-status <group> <id>` shares an enhanced status, one of the group's
operational values (§14.2); see the [enhanced status tests](../tests/mcdata/MCDATA_STATUS_TEST.md).

Files are uploaded to the `content-server` container (the media storage function of
the MCData content server) and distributed by their URL (TS 24.282 §10.2.4).

See the [MCData test index](../tests/MCDATA_TEST.md), the [MCData SDS tests](../tests/mcdata/MCDATA_SDS_TEST.md), the
[MCData file distribution tests](../tests/mcdata/MCDATA_FD_TEST.md), the
MCData Phase 1 design
and the [MCData acceptance matrix](architecture/mcdata-standards-and-acceptance.md).

## MCVideo server

`mcvideo-server` is the `openmcx-mcvideo-server` executable (with `"service": "mcvideo"` in its configuration); the
SIP core routes its public service identity `sip:mcvideo@DOMAIN` to it. It serves the MCVideo procedures of the
[feature list](FEATURES.md#mcvideo) (TS 24.281, TS 24.581). It is in the `mcvideo` Compose profile, and a lab adds it
with `--mcvideo`:

```bash
python3 tools/prepare-prearranged-test.py --debug-sip --mcvideo
tools/mcx compose --profile mcvideo up -d                  # the default lab, with mcvideo-server
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'options sip:mcvideo@mcx.test'
```

`options <SIP URI>` sends a SIP OPTIONS through the core and records the final status
under `options` in the client's `status.json`. See the
[shared-core tests](../tests/mcvideo/MCVIDEO_SHARED_CORE_TEST.md).

## Verify

See the [test index by call type](../tests/MCPTT_TEST.md), the [two-client test description](../tests/mcptt/MCPTT_TWO_CLIENT_TEST.md), the
[extended prearranged group-call scenarios and call flow](../tests/mcptt/PREARRANGED_TEST.md) and the
[private-call scenarios and call flows](../tests/mcptt/PRIVATE_CALL_TEST.md) and the
[broadcast group-call scenarios and call flow](../tests/mcptt/BROADCAST_CALL_TEST.md) and the
[chat group-call scenarios and call flow](../tests/mcptt/CHAT_CALL_TEST.md) and the
[ad hoc group-call scenarios and call flow](../tests/mcptt/ADHOC_CALL_TEST.md), the
[emergency](../tests/mcptt/EMERGENCY_CALL_TEST.md), [imminent-peril](../tests/mcptt/IMMINENT_PERIL_CALL_TEST.md)
and [first-to-answer](../tests/mcptt/FIRST_TO_ANSWER_TEST.md) call tests, the
[remotely initiated call tests](../tests/mcptt/REMOTE_INITIATED_TEST.md), and the
[functional-alias scenarios](../tests/mcptt/FUNCTIONAL_ALIAS_TEST.md).
The [feature list](FEATURES.md) distinguishes verified behavior from what is not supported.

```bash
tools/mcx test
tools/test-lab
```

The lab scenario requires an idle, running lab. It captures only the MCPTT
server network namespace with `NET_RAW`, then establishes both call
legs, checks floor contention, sends different spoken phrases in both
directions, verifies decoded sample count and energy, and tears down the call.
It also independently decodes floor/RTP packet headers and verifies client
restart recovery. The packet checker validates Audio SSRC field lengths and reserved
bytes. If `tshark` is on PATH (or `MCX_TSHARK` names its executable), it also
requires every floor packet to decode without Wireshark expert diagnostics.
Results, packet capture and logs are retained in
`artifacts/integration/`.

For local C++ development, `tools/mcx test` builds native binaries under
`build/`. Mount those binaries with:

```bash
tools/mcx compose -f compose.dev.yaml up -d
```

Use default `tools/mcx up` after rebuilding the image for deployment verification.
Stop this project's containers with `tools/mcx down`; persistent service data
and generated credentials are retained.

### Regression matrix

`tools/regress.py` prepares, runs and tears down every lab of the matrix, in parallel, and writes a summary table:

```bash
tools/regress.py --list
tools/regress.py --image openmcx:<tag> --client-image openmcx-client:<tag> --all --jobs 4
tools/regress.py --image openmcx:<tag> --client-image openmcx-client:<tag> --select smoke,mcdata --duration 4h   # soak
```

A soak stops early when a whole round fails within a minute, since that means the labs could not start.

Over debug TCP SIP (the default), each scenario that has a wire verifier (`tests/integration/verify_*.py`) is also
checked on the wire: `tests/integration/wire_check.py` captures at the scenario's server from before the clients sign
in, and the verifier checks the messages themselves (their order, bodies and the messages that must not be sent),
independently of the C++ code. The summary reports it as `<scenario>/wire`; the capture and the verifier's report are
kept as `integration/<scenario>-wire.pcap` and `-wire.json`. Labs over TLS and split labs skip it. Some verifiers
need `tshark`.

## Readable SIP in Wireshark

Both native executables accept `--disable-tls` for isolated-lab SIP debugging.
It selects TCP port 5060 and TCP Contacts/routes; HTTPS common services continue
using verified TLS. SIP digest authentication remains enabled. This mode exposes
SIP bodies and access tokens and replaces SIP certificate identity with source
address checks, so use it only on the isolated lab network. TLS remains the default.

```bash
# Switch the SIP core, server and both clients together.
tools/mcx compose -f compose.debug.yaml up -d --force-recreate sip-core mcptt-server client-a client-b
tools/test-lab --disable-tls
```

Open `artifacts/integration/sip-debug.pcap` in Wireshark and filter `sip` or
`tcp.port == 5060`. It includes registration, authorization, affiliation and call
signaling captured at the SIP core. `mcptt-debug.pcap` includes the server's SIP,
RTP and floor-control traffic. Debug captures are separate from `mcptt.pcap`.
Tests leave the lab in debug mode so you can observe another call live.

For standalone process invocation, append `--disable-tls` to
`mcx-client --config FILE` or `openmcx-mcptt-server --config FILE`. Optional configuration
fields `sip.debug_port` and `sip.debug_core_uri` override port 5060 and
`sip:<trusted_core>:5060;transport=tcp`; match them to the SIP core's listener.

Restore normal TLS operation with:

```bash
tools/mcx compose up -d --force-recreate sip-core mcptt-server client-a client-b
```
