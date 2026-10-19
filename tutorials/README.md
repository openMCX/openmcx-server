# The OpenMCX Tutorials

Step-by-step guides that run a complete OpenMCX system from the published Docker images.

## End to End Tutorials

A whole system with real or simulated access: Android phones over Wi-Fi, a dispatcher position, 4G and 5G cores
and RANs.

| # | Tutorial | What you build |
|---|---|---|
| 1 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;App](end-to-end/01-mcx-over-wlan-android/README.md) | The OpenMCX servers on one computer; two Android phones on its Wi-Fi make calls, messages and video calls. |
| 2 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;Phones&nbsp;and&nbsp;Dispatcher&nbsp;client](end-to-end/02-dispatcher-with-android/README.md) | Tutorial 1 plus a dispatcher position in the browser, in group calls with the phones. |
| 3 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;RAN&nbsp;(RFSIM)](end-to-end/03-mcx-over-oai-5g/README.md) | Tutorial 1 plus the OAI 5G core and RAN (simulated radio); the dispatcher over 5G, with MCPTT QoS over N5. |
| 4 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;srsRAN&nbsp;(ZeroMQ)](end-to-end/04-mcx-over-srsran-5g/README.md) | Tutorial 3 with the srsRAN gNB and srsUE (simulated radio); the call falls back to the default QoS flow. |
| 5 | [MCX&nbsp;over&nbsp;a&nbsp;4G&nbsp;core&nbsp;(Open5GS)&nbsp;and&nbsp;the&nbsp;OAI&nbsp;LTE&nbsp;RAN&nbsp;(RFSIM)](end-to-end/05-mcx-over-4g-open5gs-oai/README.md) | Tutorial 3 on 4G: Open5GS EPC and OAI LTE RAN (simulated radio); MCPTT QoS over Rx, a QCI 65 bearer. |
| 6 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;RAN&nbsp;(RFSIM)&nbsp;on&nbsp;Kubernetes](end-to-end/06-mcx-over-oai-5g-kubernetes/README.md) | Tutorial 3 on a one-node kind cluster, installed with Helm: the OpenMCX chart and a chart for the OAI 5G core, gNB and nr-UE. |
| 7 | [Sign&nbsp;in&nbsp;with&nbsp;Keycloak&nbsp;as&nbsp;IdMS](end-to-end/07-keycloak-idms/README.md) | Keycloak in the place of OpenMCX's IdMS: two Android phones and a dispatcher sign in on its page (TS 33.180 annex B.4.2), and the servers accept its tokens. `develop` images. |

Each tutorial has its own folder in `end-to-end/` with its Docker Compose file and `.env.example`; tutorial 6 has its
Helm chart and values instead.

## Unit Test Tutorials

One MC service feature each, on one computer with headless clients and no phones, numbered from 1 in `unit-tests/`.
Each is built on a scenario of the regression tests and runs from the same published images, with SIP in clear and a
capture of every SIP, speech and floor control packet to follow in Wireshark, and ends with the feature's call flow.

| # | Tutorial | What you build |
|---|---|---|
| 1 | [MCPTT&nbsp;prearranged&nbsp;group&nbsp;call&nbsp;with&nbsp;floor&nbsp;control&nbsp;and&nbsp;late&nbsp;entry](unit-tests/01-group-call-basics/README.md) | Four headless clients in a group call: speech, late entry, leave and rejoin, release by the initiator, two groups. |
| 2 | [MCPTT&nbsp;floor&nbsp;control&nbsp;with&nbsp;queue,&nbsp;confirmation&nbsp;and&nbsp;pre-emption](unit-tests/02-floor-queue-priority/README.md) | Four headless clients: a queued request, leaving the queue, accepted and lapsed queued grants, pre-emption. |
| 3 | [MCPTT&nbsp;private&nbsp;calls&nbsp;with&nbsp;and&nbsp;without&nbsp;floor&nbsp;control,&nbsp;answer&nbsp;modes](unit-tests/03-private-calls/README.md) | Four headless clients: auto and manual answer, decline, cancel, busy, refused, and both talking at once. |
| 4 | [MCPTT&nbsp;call-back,&nbsp;transfer,&nbsp;forwarding&nbsp;and&nbsp;first-to-answer&nbsp;calls](unit-tests/04-private-call-services/README.md) | Four headless clients: call-back, remote call, unannounced and announced transfer, three forwardings, first-to-answer. |
| 5 | [MCPTT&nbsp;emergency&nbsp;and&nbsp;imminent&nbsp;peril&nbsp;group&nbsp;calls&nbsp;and&nbsp;their&nbsp;alerts](unit-tests/05-emergency-imminent-peril/README.md) | Four headless clients: imminent peril, emergency and alerts, refused requests, late entry, emergency floor. |
| 6 | [MCPTT&nbsp;broadcast&nbsp;group&nbsp;calls:&nbsp;receive&nbsp;only,&nbsp;late&nbsp;entry&nbsp;and&nbsp;override](unit-tests/06-broadcast-group-call/README.md) | Four headless clients: one talks, three only listen; refusals, release at transmission end, late entry, override. |
| 7 | [MCPTT&nbsp;chat&nbsp;group&nbsp;calls:&nbsp;joining,&nbsp;capacity&nbsp;and&nbsp;implicit&nbsp;affiliation](unit-tests/07-chat-group-calls/README.md) | Four headless clients join one by one: limit, creator leaving, release, call-type checks, implicit affiliation. |
| 8 | [MCPTT&nbsp;ad&nbsp;hoc&nbsp;group&nbsp;calls:&nbsp;lists,&nbsp;refusals,&nbsp;modification&nbsp;and&nbsp;timers](unit-tests/08-adhoc-group-calls/README.md) | Four headless clients: list calls, leave and rejoin, refusals, manual answer, modification, TNG2 and TNG3. |
| 9 | [MCPTT&nbsp;remotely&nbsp;initiated&nbsp;group&nbsp;calls&nbsp;and&nbsp;ambient&nbsp;listening&nbsp;calls](unit-tests/09-remote-ambient-calls/README.md) | Four headless clients: one asks another's device to call; listening unseen, server releases, refusals. |
| 10 | [MCPTT&nbsp;regroups:&nbsp;group,&nbsp;user&nbsp;and&nbsp;GMS-formed&nbsp;temporary&nbsp;groups](unit-tests/10-dynamic-groups/README.md) | Four headless clients in two groups: group regroup, user regroup, temporary group, calls and removal. |
| 11 | [MCPTT&nbsp;functional&nbsp;aliases:&nbsp;activation,&nbsp;take-over,&nbsp;calls,&nbsp;presentation](unit-tests/11-functional-aliases/README.md) | Four headless clients take on roles: limits, take-over, calls to an alias, presentation, broadcast ad hoc. |
| 12 | [MCPTT&nbsp;protected&nbsp;calls:&nbsp;the&nbsp;keys,&nbsp;SRTP&nbsp;and&nbsp;SRTCP,&nbsp;XML&nbsp;protection](unit-tests/12-protected-media/README.md) | Four headless clients: CSK, GMK and PCK on the wire, encrypted group and private calls, a refused tampered key. |
| 13 | [MCData&nbsp;short&nbsp;data&nbsp;service,&nbsp;delivery&nbsp;reports&nbsp;and&nbsp;status&nbsp;messages](unit-tests/13-mcdata-sds-status/README.md) | Four headless clients: one-to-one and group SDS, delivery and read reports, refusals, enhanced status. |
| 14 | [MCData&nbsp;file&nbsp;distribution&nbsp;by&nbsp;HTTP&nbsp;and&nbsp;MSRP,&nbsp;and&nbsp;the&nbsp;message&nbsp;store](unit-tests/14-mcdata-files-msgstore/README.md) | Four headless clients: a file to one user and to a group, a file in MSRP, storage switched on, deposits found again. |
| 15 | [MCData&nbsp;IP&nbsp;connectivity:&nbsp;a&nbsp;GRE-in-UDP&nbsp;tunnel&nbsp;between&nbsp;two&nbsp;users](unit-tests/15-mcdata-ip-connectivity/README.md) | Four headless clients: a session, pings both ways, stray and stranger packets, busy, refusals, an alias. |
| 16 | [MCPTT&nbsp;and&nbsp;MCData&nbsp;location:&nbsp;reports,&nbsp;triggers,&nbsp;requests&nbsp;and&nbsp;areas](unit-tests/16-location/README.md) | Four headless clients: configuration, trigger reports, requests with filters and refusals, group and alert areas. |
| 17 | [MCVideo&nbsp;group&nbsp;and&nbsp;private&nbsp;calls&nbsp;with&nbsp;transmission&nbsp;control](unit-tests/17-mcvideo-calls/README.md) | Four headless clients: a group call with grant, reception, queue, reject and revoke; private calls with and without transmission control. |
| 18 | [MCVideo&nbsp;pull&nbsp;and&nbsp;push&nbsp;of&nbsp;video,&nbsp;and&nbsp;ambient&nbsp;viewing&nbsp;calls](unit-tests/18-mcvideo-pull-push-ambient/README.md) | Four headless clients: push and pull to and from a user and the server's recording, remote transmission, ambient viewing, refusals. |
| 19 | [MCVideo&nbsp;emergency,&nbsp;ad&nbsp;hoc&nbsp;and&nbsp;regrouped&nbsp;video&nbsp;calls](unit-tests/19-mcvideo-emergency-adhoc-regroup/README.md) | Four headless clients: emergency and imminent peril calls, pre-emption, alerts, ad hoc group calls, group and user regroups. |
| 20 | [Identity&nbsp;and&nbsp;tokens:&nbsp;MCX&nbsp;Admin&nbsp;activation&nbsp;and&nbsp;token&nbsp;refresh](unit-tests/20-admin-activation-token-refresh/README.md) | Five headless clients: a device activated from MCX Admin, access tokens renewed by refresh token, a call past expiry. |
| 21 | [Resilience:&nbsp;server&nbsp;restart&nbsp;and&nbsp;SIP&nbsp;outbound&nbsp;flows](unit-tests/21-resilience-restart-outbound/README.md) | Four headless clients: a client and the MCPTT server restart, sign-in again after a 412, a client reached over its flow. |

Each has its own folder in `unit-tests/` with its Docker Compose file, `run.sh` and a reference capture. A title without a
link is planned; it gets its link when the tutorial is published.

## Good to know

- **Captures**: tutorials 3, 4 and 5 link a reference capture (core signalling, GTP-U and SIP), explained in their step
  "Look at the capture".
- **Debug log**: set `MCX_LOG=debug` in the tutorial's `.env` (end to end) or run `MCX_LOG=debug ./run.sh` (unit
  tests); each program then logs one line per SIP message and HTTP request (`docker logs <container>`), without bodies
  or tokens.
- **Log size**: each container's log is capped at 30 MB.
- **tshark on Ubuntu 26.04** reads captures only under `/tmp` (AppArmor). Copy the capture there, or allow your home
  directory once:

  ```bash
  echo 'owner @{HOME}/** r,' | sudo tee /etc/apparmor.d/local/tshark
  sudo apparmor_parser -r /etc/apparmor.d/tshark
  ```
