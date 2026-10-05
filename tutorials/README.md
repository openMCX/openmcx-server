# openMCX tutorials

Step-by-step guides that run a complete openMCX system from the published Docker images.

| # | Tutorial | What you build |
|---|---|---|
| 1 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;App](01-mcx-over-wlan-android/README.md) | openMCX servers on one computer; two Android phones on its Wi-Fi make calls, messages and video calls. |
| 2 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;Phones&nbsp;and&nbsp;Dispatcher&nbsp;client](02-dispatcher-with-android/README.md) | Tutorial 1 plus a dispatcher position in the browser, in group calls with the phones. |
| 3 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;RAN&nbsp;(RFSIM)](03-mcx-over-oai-5g/README.md) | Tutorial 1 plus the OAI 5G core and RAN (simulated radio); the dispatcher over 5G, with MCPTT QoS over N5. |
| 4 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;srsRAN&nbsp;(ZeroMQ)](04-mcx-over-srsran-5g/README.md) | Tutorial 3 with the srsRAN gNB and srsUE (simulated radio); the call falls back to the default QoS flow. |
| 5 | [MCX&nbsp;over&nbsp;a&nbsp;4G&nbsp;core&nbsp;(Open5GS)&nbsp;and&nbsp;the&nbsp;OAI&nbsp;LTE&nbsp;RAN&nbsp;(RFSIM)](05-mcx-over-4g-open5gs-oai/README.md) | Tutorial 3 on 4G: Open5GS EPC and OAI LTE RAN (simulated radio); MCPTT QoS over Rx, a QCI 65 bearer. |

Each tutorial has its own folder with its Docker Compose file, its `.env.example` and its setup.
