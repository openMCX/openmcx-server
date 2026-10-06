# The openMCX Tutorials

Step-by-step guides that run a complete openMCX system from the published Docker images.

## End to End Tutorials

A whole system with real or simulated access: Android phones over Wi-Fi, a dispatcher position, 4G and 5G cores
and RANs.

| # | Tutorial | What you build |
|---|---|---|
| 1 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;App](01-mcx-over-wlan-android/README.md) | The openMCX servers on one computer; two Android phones on its Wi-Fi make calls, messages and video calls. |
| 2 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;Phones&nbsp;and&nbsp;Dispatcher&nbsp;client](02-dispatcher-with-android/README.md) | Tutorial 1 plus a dispatcher position in the browser, in group calls with the phones. |
| 3 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;RAN&nbsp;(RFSIM)](03-mcx-over-oai-5g/README.md) | Tutorial 1 plus the OAI 5G core and RAN (simulated radio); the dispatcher over 5G, with MCPTT QoS over N5. |
| 4 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;srsRAN&nbsp;(ZeroMQ)](04-mcx-over-srsran-5g/README.md) | Tutorial 3 with the srsRAN gNB and srsUE (simulated radio); the call falls back to the default QoS flow. |
| 5 | [MCX&nbsp;over&nbsp;a&nbsp;4G&nbsp;core&nbsp;(Open5GS)&nbsp;and&nbsp;the&nbsp;OAI&nbsp;LTE&nbsp;RAN&nbsp;(RFSIM)](05-mcx-over-4g-open5gs-oai/README.md) | Tutorial 3 on 4G: Open5GS EPC and OAI LTE RAN (simulated radio); MCPTT QoS over Rx, a QCI 65 bearer. |

Each tutorial has its own folder with its Docker Compose file, its `.env.example` and its setup.

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

Each has its own folder with its Docker Compose file, `run.sh` and a reference capture.
