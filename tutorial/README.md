# openMCX tutorials

Step-by-step guides that run a complete openMCX system from the published Docker images.

| # | Tutorial | What you build |
|---|---|---|
| 1 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;app](01-mcx-over-wlan-android/README.md) | One computer runs the MCPTT, MCData and MCVideo servers, the common services, the SIP core and MCX Admin; two Android phones on its Wi-Fi activate from MCX Admin and make private and group calls, messages and video calls. |
| 2 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;phones&nbsp;and&nbsp;dispatcher&nbsp;client](02-dispatcher-with-android/README.md) | Tutorial 1 plus a dispatcher position in the browser, on the same or another computer: it activates from MCX Admin and talks to the phones in a group call. |
| 3 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;RAN&nbsp;(rfsim)](03-mcx-over-oai-5g/README.md) | Tutorial 1 plus the OAI 5G core, gNB and an nr-UE over the rfsimulator: the dispatcher works over 5G, and the MCPTT server asks the core for MCPTT QoS over N5 (5QI 65). |

Each tutorial has its own folder with its Docker Compose file, its `.env.example` and its setup.
