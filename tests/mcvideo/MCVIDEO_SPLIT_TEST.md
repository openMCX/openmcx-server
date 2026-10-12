# MCVideo participating and controlling servers

The participating MCVideo function (TS 24.281 §6.3.2) and the controlling MCVideo function (§6.3.3) on different servers of one system, with the participating function in the media path forwarding transmission control and video (TS 24.581 §6.4).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-INTER-01).

## How it works

- **Servers.** `tools/prepare-prearranged-test.py --split --mcvideo` gives MCVideo the topology MCPTT has with `--split`: `mcvideo-server` is the controlling function of every call, `mcvideo-part-1` serves client-a and client-c, `mcvideo-part-2` client-b and client-d. Each runs the shared core with `mcvideo.role`, `mcvideo.servers` and `mcvideo.controller`; the MCVideo service settings of the lab are the same on all three.
- **Routing.** The SIP core sends a user's request for the MCVideo PSI to the participating MCVideo server serving that user (`route[SERVICE_AS]`, generated per lab), and accepts all three servers as asserting the MCVideo PSI. Server-to-server requests go directly, as for MCPTT.
- **Registration with the controlling function.** A participating server publishes each served user's affiliations to the controlling server (the shared core's peer registration, in the MCVideo presence namespace). A publication without groups, before the first affiliation or after the last de-affiliation, names MCVideo by the namespace of its `p-id`.
- **Media.** A participating server relays each call through one port per stream: audio, transmission control and, for MCVideo, video (`media.video_port`, same offset as the audio). The SDP towards each side advertises the relay's ports; RTP, SRTP and transmission control pass unchanged (TS 24.581 §6.4.2, §6.4.3), and under a CSK and SPK the transmission control is re-protected as MCPTT's floor control is.
- **Early transmission control.** With a relay in the path, the controlling function's Transmission Granted for an implicit request can reach the client before the 200 (OK) that the SIP core carries. The client holds up to eight transmission control packets received before the SDP answer, and processes them once the answer names their source.

## Running the tests

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-split
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-protected-split
```

## Tests

Lab `mcvideo-split`: the affiliation, group call, private call and emergency scenarios of the single-server labs, unchanged except where they look at the controlling server's capture. They make 17, 75, 41 and 26 checks.

| ID | What is checked |
|---|---|
| MV-SP-01 | Authorisation and affiliation of the four clients at their participating servers, known to the controlling server; a second group; de-affiliation withdrawn at the controlling server (MV-AF-01 to MV-AF-07) |
| MV-SP-02 | Prearranged and chat group calls, conference events, transmission control with queueing, rejection, revocation, implicit request and reception control, every receiver decoding pictures equal to the sender's (MV-GC-01 to MV-GC-13) |
| MV-SP-03 | At the controlling server: the INVITE with the MCVideo ICSI, the offer with `mc_implicit_request` and its answer, 15 transmission control messages and H.264 RTP exchanged with both participating servers; each participating server relayed video (MV-GC-07) |
| MV-SP-04 | Private calls with and without transmission control, commencement modes, decline and rulesets across servers (MV-PC-01 to MV-PC-08) |
| MV-SP-05 | Emergency and imminent peril group calls, emergency private call and emergency alert across servers (MV-EM-01 to MV-EM-08) |

### Protected calls across servers

Lab `mcvideo-protected-split` (`--split --mcvideo --protected --key-parameters-iei 0x79`): the [protected call scenario](MCVIDEO_PROTECTED_TEST.md) (MV-SE-01 to MV-SE-09) on the split servers. Each pair of MCVideo servers holds an SPK (TS 33.180 §5.5). A participating server re-protects transmission control from its client's CSK to the SPK towards the controlling server and back (§9.4.5), and relays the SRTP video under the GMK or PCK unchanged (TS 24.281 §4.7.1).

| ID | What is checked |
|---|---|
| MV-SP-06 | GMK-protected group video from two senders and PCK-protected private calls with and without transmission control and ambient viewing, decoded picture by picture across the participating servers; replay and tamper rejection (MV-SE-01 to MV-SE-09, 34 checks as on one server) |
| MV-SP-07 | At each participating server: transmission control re-keyed between CSK and SPK, SRTP video relayed, none refused or dropped |

## Coverage gaps

| Area | Gap |
|---|---|
| Other MCVideo services | Ambient viewing without protection, pull and push, remote transmission (Track Info), ad hoc calls, regroups, functional aliases, remote group selection and location are tested on a combined server only |
| Several MC systems | Interconnection through MC gateway servers and migration: not in present edition |
