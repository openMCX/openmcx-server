# Using the OpenMCX lab

The lab runs the whole system on one computer, for development and tests: the SIP core, the servers, the common
services and headless clients (`mcx-client`). To try OpenMCX with phones or a dispatcher, start with the
[tutorials](../tutorials/README.md); what the implementation supports is in the [feature list](FEATURES.md).

| Section | What it covers |
|---|---|
| [1. Build](#1-build) | The images, in Docker |
| [2. Run](#2-run) | Configure, start and stop the lab |
| [3. MCPTT commands](#3-mcptt-commands) | Group, private, broadcast, chat, ad hoc, emergency calls, functional aliases |
| [4. MCData commands](#4-mcdata-commands) | SDS, file distribution, IP connectivity, release, enhanced status |
| [5. MCVideo](#5-mcvideo) | The MCVideo server in the lab |
| [6. Tests](#6-tests) | Unit tests, the lab test and the regression matrix |
| [7. Troubleshooting: logs and readable SIP](#7-troubleshooting-logs-and-readable-sip) | The debug log, the TLS key file for Wireshark, SIP without TLS |

## 1. Build

Requirements: Linux with Docker, SCTP kernel support, Python 3 and OpenSSL. Everything builds in Docker; nothing is
installed on the host. Check out [openmcx-client](https://github.com/openMCX/openmcx-client) beside this repository
(`../openmcx-client`, or set `MCX_CLIENT_DIR`) for the client image.

```bash
tools/mcx build                 # development image, SIP core, SIP database, openmcx:0.1 and openmcx-client:0.1
tools/build-images 0.1          # or one image per program: openmcx-<program>:0.1
```

The images, their Dockerfiles and the build options are in [BUILD.md](BUILD.md).

## 2. Run

```bash
tools/mcx fetch                 # the pinned docker-compose binary
tools/mcx provision             # config/lab.json -> config/generated/ (keeps existing secrets)
tools/mcx speech                # the test speech, artifacts/speech/alpha.wav and bravo.wav
tools/mcx up
tools/mcx compose ps
tools/mcx down                  # stops the lab and deletes its volumes; config/generated/ is kept
```

| File | Holds |
|---|---|
| [`config/lab.json`](../config/lab.json) | Domain, users, groups and their rights; edit it before `provision` |
| `config/generated/` | Generated credentials and certificates: private, ignored by git, never publish it |
| `artifacts/client-a/`, `artifacts/client-b/` | Each client's `status.json` and the received speech (16 kHz mono WAV) |

Each container's log is capped at 30 MB (three files of 10 MB, Docker's `json-file` rotation, set in the compose
files): `docker logs` shows the latest part.

A client signs in with the IdMS, reads its configuration and group documents, registers with the SIP core,
authorises its services and affiliates to its groups. Every command below runs in a client:

```bash
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command '<command>'
tools/mcx compose exec -T client-b mcx-client --config /config/client-b.json --status
```

## 3. MCPTT commands

| Command | What it does | Tests |
|---|---|---|
| `call` / `hangup` / `release` | Prearranged group call: start, leave, release | [prearranged](../tests/mcptt/PREARRANGED_TEST.md) |
| `ptt /artifacts/speech/alpha.wav` | Request the floor and talk; only in an established call | |
| `call emergency`, `call imminent`; `emergency on\|off`, `imminent on\|off`, `alert on\|off` | Emergency and imminent-peril calls and alerts | [emergency](../tests/mcptt/EMERGENCY_CALL_TEST.md), [imminent peril](../tests/mcptt/IMMINENT_PERIL_CALL_TEST.md) |
| `private <id> auto\|manual\|force-auto [emergency [alert]] [no-floor]`; `answer`, `reject` | Private call; the callee answers or rejects | [private](../tests/mcptt/PRIVATE_CALL_TEST.md) |
| `first-to-answer <id> <id>… [emergency [alert]]` | Ring several users, keep the first to answer | [first to answer](../tests/mcptt/FIRST_TO_ANSWER_TEST.md) |
| `callback <id> [low\|normal\|high]`, `callback-cancel <id>`, `callback-fulfil <id>`; `transfer <id>`, `forward <id>` | Call-back, transfer and forwarding | [private](../tests/mcptt/PRIVATE_CALL_TEST.md) |
| `call broadcast` | Broadcast group call: only the initiator talks | [broadcast](../tests/mcptt/BROADCAST_CALL_TEST.md) |
| `chat [emergency\|imminent]` | Create or join the chat group's session | [chat](../tests/mcptt/CHAT_CALL_TEST.md) |
| `adhoc [broadcast] [emergency\|imminent] <id>…`, `adhoc criteria affiliated:<group>`; `adhoc-modify add\|remove <id>…`; `adhoc-alert <criteria>\|cancel` | Ad hoc group call and alert | [ad hoc](../tests/mcptt/ADHOC_CALL_TEST.md) |
| `remote-group-call <remote> <group>`, `remote-call <remote> <target> [mode] [silent]` | Ask another user's device to place a call | [remotely initiated](../tests/mcptt/REMOTE_INITIATED_TEST.md) |
| `fa activate\|takeover\|deactivate <alias>`, `fa use <alias>`, `private-fa <alias>`, `first-to-answer-fa <alias>` | Functional aliases | [functional aliases](../tests/mcptt/FUNCTIONAL_ALIAS_TEST.md) |
| `deaffiliate`, `quit` | Leave the group, stop the client | |

Rights come from the users' rulesets in `config/lab.json` (for example `private_call`); private calls need no
affiliation, and a chat or ad hoc call affiliates implicitly.

## 4. MCData commands

The MCData client runs in `mcx-client` and shares its SIP registration; the MCData server is `sip:mcdata@<domain>`.

| Command | What it does | Tests |
|---|---|---|
| `sds [delivery\|read] <id> <text>`, `sds-group <mode> <group> <text>`, `sds-adhoc <id> <text>`, `sds-display <message id>` | Short data, one-to-one, group and ad hoc, with notifications | [SDS](../tests/mcdata/MCDATA_SDS_TEST.md) |
| `sds-media <id> <text>`; `sds-session group=<group> [emergency\|imminent]`, `sds-session send <mode> <text>`, `sds-session emergency cancel` | SDS over the media plane (MSRP) and SDS sessions | [media plane](../tests/mcdata/MCDATA_MEDIA_TEST.md) |
| `fd-send <mode> <id> <file>`; `fd-accept\|fd-reject\|fd-defer <message id>`; `fd-media mandatory <mode> <id> <file>` | File distribution over HTTP (content server) or the media plane | [file distribution](../tests/mcdata/MCDATA_FD_TEST.md) |
| `ipcon <id>`, `ipcon-ping <address> <count>` | IP connectivity: a GRE-in-UDP tunnel between two clients | [IP connectivity](../tests/mcdata/MCDATA_IPCONN_TEST.md) |
| `mcdata-release` | Release a communication over the media plane | [release](../tests/mcdata/MCDATA_RELEASE_TEST.md) |
| `sds-status <group> <id>` | Share an enhanced status | [enhanced status](../tests/mcdata/MCDATA_STATUS_TEST.md) |
| `mcdata-alert [cancel]` | Group emergency alert | [emergency alert](../tests/mcdata/MCDATA_EMERGENCY_ALERT_TEST.md) |
| `mcdata-fa activate <alias>`, `sds-fa <alias> <text>` | Functional aliases | [functional aliases](../tests/mcdata/MCDATA_FUNCTIONAL_ALIAS_TEST.md) |

`sds-media`, `sds-session` and `fd-media` also take an ad hoc group: `adhoc=<id,id,…>`, `adhoc=criteria=<criteria>`
or `adhoc=group=<ad hoc group>`.

## 5. MCVideo

`mcvideo-server` serves `sip:mcvideo@<domain>`; it is in the `mcvideo` Compose profile:

```bash
python3 tools/prepare-prearranged-test.py --debug-sip --mcvideo
tools/mcx compose --profile mcvideo up -d
tools/mcx compose exec -T client-a mcx-client --config /config/client-a.json --command 'options sip:mcvideo@mcx.test'
```

The MCVideo procedures are in the [feature list](FEATURES.md#mcvideo) and the [MCVideo test index](../tests/MCVIDEO_TEST.md).

## 6. Tests

```bash
tools/mcx test                  # C++ unit tests (ctest) and Go tests, in the development image; binaries in build/
tools/test-lab                  # on a running, idle lab: a group call with floor contention and speech both ways
tools/regress.py --list
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select smoke
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --all --transport both --jobs 2
```

- `tools/test-lab` checks the decoded speech, the floor and RTP packets and a client restart, and keeps its results,
  capture and logs in `artifacts/integration/`.
- `tools/regress.py` prepares, runs and tears down every lab of the matrix and writes a summary. Over TCP SIP (the
  default) each scenario with a wire verifier is also checked on the wire, independently of the C++ code; the
  capture and report are kept as `integration/<scenario>-wire.pcap` and `-wire.json`. `--duration 4h` repeats the
  selection as a soak.
- To run the binaries from `build/` in the lab: `tools/mcx compose -f docker/compose/compose.dev.yaml up -d`.

### Another vendor's IdMS (Keycloak)

`--keycloak <image>` makes Keycloak the lab's IdMS instead of OpenMCX's, as an IdMS of another vendor at a Plugtest
(TS 33.180 annex B). It answers as `idms` with the issuer `https://idms:8443/realms/openmcx` and signs with the lab's
IdMS key; the realm `generated/keycloak/openmcx.json` holds the users with their MC service IDs, the MC scopes and the
mappers for the claims of annex B.2. The clients have no password: `tools/keycloak-sign-in.py` signs them in on
Keycloak's login page and leaves each a refresh token, with which they start.

```bash
python3 tools/prepare-prearranged-test.py --directory <lab> --project kc --private-call --mcdata \
  --images <tag> --client-image openmcx-client:<tag> --keycloak quay.io/keycloak/keycloak:26.3.3
C=".cache/deps/docker-compose-linux-x86_64 -p kc -f <lab>/compose.json"
$C up -d --wait idms
docker run --rm -u "$(id -u):$(id -g)" --network kc_mcx -v <lab>:<lab> -v "$PWD/tools:/tools:ro" openmcx-dev:0.1 \
  python3 /tools/keycloak-sign-in.py <lab>
$C up -d --wait
```

The tokens of OpenMCX's IdMS carry claims of its own as well (`mc_id`, `sip_uri`, `mc_client_id`), which bind them to
the user's SIP identity and client; a Keycloak token has the claims of annex B.2 only, and the servers check those.

The tests are described in the [MCPTT](../tests/MCPTT_TEST.md), [MCData](../tests/MCDATA_TEST.md) and
[MCVideo](../tests/MCVIDEO_TEST.md) test indexes.

## 7. Troubleshooting: logs and readable SIP

### Debug log

Off by default. With it on, every OpenMCX program writes a human-readable line on stderr, after its startup banner,
for each SIP message it receives (`SIP <-`) and sends (`SIP ->`) (servers and clients) and each HTTP request it
answers (common services and HTTP proxy), named in brackets by program (`mcptt-server`, `client`, `cms`, ...). The JSON events on stdout are unchanged. Message bodies, query strings, headers and tokens are never
written.

```
2026/10/13 09:14:02 OpenMCX DEBUG [mcptt-server] SIP <- INVITE sip:mcptt@mcx.test | from <sip:alice@mcx.test> | to <sip:mcptt@mcx.test> | call-id 5f1c0e2a-... | cseq 2 INVITE | 172.31.19.10:5061 TLS | 2310 bytes
2026/10/13 09:14:02 OpenMCX DEBUG [mcptt-server] SIP -> 100 | from <sip:alice@mcx.test> | to <sip:mcptt@mcx.test> | call-id 5f1c0e2a-... | cseq 2 INVITE | 172.31.19.10:5061 TLS | 412 bytes
2026/10/13 09:14:01 OpenMCX DEBUG [cms] HTTP GET /xcap-root/... | 200 | 3 ms | 172.31.19.30:51844
```

| Switch | Where |
|---|---|
| `"log_level": "debug"` | in a program's JSON configuration (`"info"` is the default) |
| `MCX_LOG=debug` | environment variable of a container; overrides the configuration |
| `--log-level debug` | `tools/prepare-prearranged-test.py`: sets `MCX_LOG=debug` on every OpenMCX service of the lab |

The debug log never turns on the TLS key file below: that has a switch of its own.

```bash
docker logs <container> 2>&1 | grep 'OpenMCX DEBUG'
```

### TLS key file for Wireshark

The SIP core terminates TLS on every SIP hop (client to core, core to server), so its TLS session secrets decrypt all
the SIP of a capture taken anywhere in the system. The file decrypts everything, access tokens included:
**troubleshooting only, never in production.**

1. Turn it on with its own switch, off by default and independent of the debug log (`log_level` and `MCX_LOG` never
   turn it on): `"sip_core": {"tls_keylog": true}` in `config/lab.json` before `tools/mcx provision`, or
   `tools/prepare-prearranged-test.py --tls-keylog`, or `-A TLS_KEYLOG` in the `sip-core` command of a Compose file.
   The SIP core then writes `/tmp/kamailio-tls-keylog.txt`.
2. Capture (for example `tcpdump -i any -w sip.pcap port 5061` in the SIP core's network namespace).
3. Copy the key file out: `docker cp <sip-core container>:/tmp/kamailio-tls-keylog.txt .`
4. In Wireshark, **Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename**: the key file. The SIP
   then shows decrypted (filter `sip`).

### SIP without TLS

`--disable-tls` switches SIP to TCP port 5060 for an isolated lab: the SIP bodies and access tokens are then readable
on the network, so use it only there. HTTPS to the common services and SIP digest authentication stay on.

```bash
tools/mcx compose -f docker/compose/compose.debug.yaml up -d --force-recreate sip-core mcptt-server client-a client-b
tools/test-lab --disable-tls
tools/mcx compose up -d --force-recreate sip-core mcptt-server client-a client-b      # back to TLS
```

`artifacts/integration/sip-debug.pcap` holds the SIP at the SIP core (registration, authorisation, affiliation,
calls) and `mcptt-debug.pcap` the server's SIP, RTP and floor control; filter `sip` in Wireshark. A program started
by hand takes `--disable-tls` after `--config FILE`; `sip.debug_port` and `sip.debug_core_uri` in its configuration
override port 5060 and the SIP core address.
