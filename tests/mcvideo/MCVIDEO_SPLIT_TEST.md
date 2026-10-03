# MCVideo participating and controlling servers

These tests cover **steps V10a to V10c of the MCVideo plan**: the participating MCVideo function (TS 24.281 V19.6.0 §6.3.2) and the controlling MCVideo function (§6.3.3) on different servers of one system, with the participating function in the media path forwarding transmission control and video (TS 24.581 V19.2.0 §6.4).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-INTER-01).

## How it works

- **Servers.** `tools/prepare-prearranged-test.py --split --mcvideo` gives MCVideo the topology MCPTT has with `--split`: `mcvideo-server` is the controlling function of every call, `mcvideo-part-1` serves client-a and client-c, `mcvideo-part-2` client-b and client-d. Each runs the shared core with `mcvideo.role`, `mcvideo.servers` and `mcvideo.controller`; the MCVideo service settings of the lab are the same on all three.
- **Routing.** The SIP core sends a user's request for the MCVideo PSI to the participating MCVideo server serving that user (`route[SERVICE_AS]`, generated per lab), and accepts all three servers as asserting the MCVideo PSI. Server-to-server requests go directly, as for MCPTT.
- **Registration with the controlling function.** A participating server publishes each served user's affiliations to the controlling server (the shared core's peer registration, in the MCVideo presence namespace). A publication without groups, before the first affiliation or after the last de-affiliation, names MCVideo by the namespace of its `p-id`.
- **Media.** A participating server relays each call through one port per stream: audio, transmission control and, for MCVideo, video (`media.video_port`, same offset as the audio). The SDP towards each side advertises the relay's ports; RTP, SRTP and transmission control pass unchanged (TS 24.581 §6.4.2, §6.4.3), and under a CSK and SPK the transmission control is re-protected as MCPTT's floor control is.
- **Early transmission control.** With a relay in the path, the controlling function's Transmission Granted for an implicit request can reach the client before the 200 (OK) that the SIP core carries. The client holds up to eight transmission control packets received before the SDP answer, and processes them once the answer names their source.

## Test cases

Lab `mcvideo-split` (`tools/regress.py --select =mcvideo-split`): the affiliation, group call, private call and emergency scenarios of V1, V3 to V5, unchanged except where they look at the controlling server's capture.

| ID | What is checked | Result |
|---|---|---|
| MV-SP-01 | Authorisation and affiliation of the four clients at their participating servers, known to the controlling server; a second group; de-affiliation withdrawn at the controlling server (MV-AF-01 to MV-AF-07) | Passed |
| MV-SP-02 | Prearranged and chat group calls, conference events, transmission control with queueing, rejection, revocation, implicit request and reception control, every receiver decoding pictures equal to the sender's (MV-GC-01 to MV-GC-13) | Passed |
| MV-SP-03 | At the controlling server: the INVITE with the MCVideo ICSI, the offer with `mc_implicit_request` and its answer, 15 transmission control messages and H.264 RTP exchanged with both participating servers; each participating server relayed video (MV-GC-07) | Passed |
| MV-SP-04 | Private calls with and without transmission control, commencement modes, decline and rulesets across servers (MV-PC-01 to MV-PC-08) | Passed |
| MV-SP-05 | Emergency and imminent peril group calls, emergency private call and emergency alert across servers (MV-EM-01 to MV-EM-08) | Passed |

Run 2026-09-28 on `openmcx:v10b` and `openmcx-client:v10b`, debug TCP: two consecutive rounds, 8 of 8 scenarios (`artifacts/v10b-split-soak/`): affiliation 17 checks, group call 75, private call 41, emergency 26.
The MCVideo, split and smoke labs on the same images passed 36 of 36 (`artifacts/v10b-guard/`), `mcvideo-split` included.

### Protected calls across servers (V10c)

Lab `mcvideo-protected-split` (`--split --mcvideo --protected --key-parameters-iei 0x79`): the protected scenario of V9 (MV-SE-01 to MV-SE-09) on the split servers. Each pair of MCVideo servers holds an SPK (TS 33.180 §5.5). A participating server re-protects transmission control from its client's CSK to the SPK towards the controlling server and back (§9.4.5), and relays the SRTP video under the GMK or PCK unchanged (TS 24.281 §4.7.1).

| ID | What is checked | Result |
|---|---|---|
| MV-SP-06 | GMK-protected group video from two senders and PCK-protected private calls with and without transmission control and ambient viewing, decoded picture by picture across the participating servers; replay and tamper rejection (MV-SE-01 to MV-SE-09, 34 checks as on one server) | Passed |
| MV-SP-07 | At each participating server: transmission control re-keyed between CSK and SPK (28 and 24 packets), SRTP video relayed (166 and 126 packets), none refused or dropped | Passed |

Run 2026-09-28 on the same images (`artifacts/v10c-protected-split/`).

Defects found by the runs and fixed:
- A participating MCVideo server's peer registration without groups was refused (403) by the controlling server: the PIDF carried no `<affiliation>` element, so it parsed as MCPTT. It now takes its service from the `p-id` namespace (unit test in `test_protocol`).
- The relay had no video port: its SDP kept the far side's video port, and video was not forwarded.
- Transmission Granted for an implicit request was lost when it overtook the 200 (OK) at the client (the client change above).
- The scenarios' capture parser joined TCP segments of all connections in capture order, so a SIP message split across segments could be broken by another connection's segment; it now joins them per connection (group call and protected scenarios).
