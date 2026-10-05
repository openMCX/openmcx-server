# openMCX tutorials

Step-by-step guides that run a complete openMCX system from the published Docker images.

| # | Tutorial | What you build |
|---|---|---|
| 1 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;App](01-mcx-over-wlan-android/README.md) | One computer runs the MCPTT, MCData and MCVideo servers, the common services, the SIP core and MCX Admin; two Android phones on its Wi-Fi activate from MCX Admin and make private and group calls, messages and video calls. |
| 2 | [MCX&nbsp;over&nbsp;WLAN&nbsp;with&nbsp;the&nbsp;Android&nbsp;Phones&nbsp;and&nbsp;Dispatcher&nbsp;client](02-dispatcher-with-android/README.md) | Tutorial 1 plus a dispatcher position in the browser, on the same or another computer: it activates from MCX Admin and talks to the phones in a group call. |
| 3 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;RAN&nbsp;(RFSIM)](03-mcx-over-oai-5g/README.md) | Tutorial 1 plus the OAI 5G core, gNB and an nr-UE over the rfsimulator (simulated RAN, no radio hardware): the dispatcher works over 5G, and the MCPTT server asks the core for MCPTT QoS over N5 (5QI 65). |
| 4 | [MCX&nbsp;over&nbsp;the&nbsp;OAI&nbsp;5G&nbsp;core&nbsp;and&nbsp;srsRAN&nbsp;(ZeroMQ)](04-mcx-over-srsran-5g/README.md) | Tutorial 3 with the srsRAN gNB and srsUE over ZeroMQ (simulated RAN, no radio hardware): the dispatcher works over 5G, the MCPTT server asks for MCPTT QoS over N5, the RAN refuses the 5QI 65 flow (srsUE has one QoS flow) and the call continues on the default flow. |

Each tutorial has its own folder with its Docker Compose file, its `.env.example` and its setup.
