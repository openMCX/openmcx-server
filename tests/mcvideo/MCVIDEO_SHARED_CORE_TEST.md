# MCVideo shared-core tests

The call-handling core of the MC service servers is parameterised by MC service, so the same code runs as the MCPTT server and as the MCVideo server (TS 24.281, TS 24.581). These tests check that the service profile, the warning tables, the SDP and the media plane control follow the server's service, that `mcvideo-server` starts and is routed to, and that the MCPTT wire format is unchanged.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-CORE-01).

## How it works

- **Service profile** (`include/mcx/service.hpp`). What tells one MC service apart on the wire and in configuration: ICSI, media feature tag, the `<prefix>info` document and its namespace, location MIME type, configuration section and IdMS ID claim. The server, the SIP engine (Contact, P-Preferred-Service, Accept-Contact), the info codec and the Accept-Contact admission check read it.
- **Warning tables** (`include/mcx/warning.hpp`). A refusal is a reason (`Warning::not_affiliated`), turned into `<code> <text>` by the table of the server's service: TS 24.379 for MCPTT, TS 24.281 §4.4.2 for MCVideo, which numbers some warnings differently (invalid location target 191).
- **Media plane control** (`include/mcx/media_control.hpp`). A call's `Session` holds a `MediaPlaneController`, made by one factory for the server's service: the TS 24.380 floor arbitrator for MCPTT, TS 24.581 transmission control for MCVideo.
- **MCVideo server container** (`mcvideo-server`). The server takes its service from the configuration's `"service"` (`mcptt` by default, or `mcvideo`). `tools/provision.py` generates `mcvideo-server.json` with the MCVideo PSI `sip:mcvideo@DOMAIN`, an `mcvideo` section, users keyed by MCVideo ID (`sip:<user>.mcvideo@DOMAIN`) and no Diameter peer (MCVideo-2 is not used; an MCPTT server refuses to start without MCPTT-2). The Compose service is in the `mcvideo` profile, and labs add it with `--mcvideo`.
- **Routing and common services.** Kamailio sends a request for the MCVideo PSI, and for an MCVideo focus URI inside a dialog, to `mcvideo-server`; the MCData and MCVideo PSIs come from one generated list of service servers (`route[SERVICE_AS]`, `service_servers` in `tools/provision.py`), each server asserting only its own PSI. Every user has an MCVideo ID (`sip:<user>.mcvideo@DOMAIN`), which the CMS serves users by (`/internal/user?mcvideo_id=`) and the IdMS carries in tokens and introspection (`mcvideo_id`). The client's `options <SIP URI>` command probes a PSI through the core.
- **Relay** (`relay_payload` in `src/media.cpp`). The media distribution function repacks AMR-WB to each destination's framing and passes any other payload, such as H.264, unchanged.
- **SDP** (`src/protocol.cpp`). A media description has a media plane control (MCPTT floor control or MCVideo transmission control) and, for MCVideo, an H.264 `m=video` section; the MCVideo layout of TS 24.281 §6.2.1 and TS 24.581 §12 and §14 is `s=MCVideo`, audio, video and `m=application … udp MCVideo`.

## Implemented profile

| Part | Behaviour | Reference |
|---|---|---|
| Service profile | MCPTT and MCVideo profiles; `<mcvideoinfo>` parsed and written with the `mcvideo` prefix, refused by the MCPTT parser; `+g.3gpp.mcvideo` with the MCVideo ICSI selects MCVideo, not MCPTT | 24.281 Annex D.2, E.2, F.1 |
| Warning tables | One reason per warning; the MCPTT table gives the TS 24.379 codes and texts, the MCVideo table those of §4.4.2; a reason MCVideo lacks (first-to-answer, call-back, transfer, forwarding, remotely initiated calls) is a programming error, never a wrong code on the wire | 24.379 §4.4, 24.281 §4.4.2 |
| SDP | MCPTT SDP byte-identical to its fixture; MCVideo audio (`i=audio component of MCVideo`), H.264 video (`42e01f`, packetization mode 1, `i=video component of MCVideo`), `a=fmtp:MCVideo` with `mc_transmission_ssrc`, `mc_queueing`, `mc_priority`, `mc_implicit_request`, `mc_granted`, `mc_audio_ssrc`, `mc_video_ssrc`; parameters sent `;`-separated, read `;`- or `:`-separated; video refused in an MCPTT SDP, an MCVideo SDP without video and non-H.264 video refused; the SIP engine parses SDP with `m=video` | 24.281 §6.2.1; 24.581 §12.1.2, §14; 26.281 §4.1 |
| Media plane control and relay | `Session` holds the controller through the interface; the factory refuses a service without one; relay repacks AMR-WB only, H.264 passes unchanged, and malformed speech is still refused with no receiver | 24.380 §6.3; 24.581 §6.3; RFC 4867, RFC 6184 |
| MCVideo server container | Service chosen by configuration; `mcvideo-server` starts ready as MCVideo with its own PSI and no Diameter, beside an unchanged `mcptt-server`; opt-in lab flag `--mcvideo` | 23.281 §6.2.2.3.2; 24.281 §4.2 |
| Routing and common services | MCVideo PSI and MCVideo focus URIs routed to `mcvideo-server`; MCData routing unchanged; `mcvideo-info` REGISTER to `mcvideo-server`; `mcvideo_id` validated (SIP URI, unique, not another service's ID), served by the CMS and carried by the IdMS | 24.281 §4.2, §7A; 23.280 §8.1 |

## Running the tests

The MCVideo server lab on its own:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =smoke-mcvideo
```

The unit tests, in the development image:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace openmcx-dev:0.2 \
  bash -lc 'cmake -S . -B build-mcvideo && cmake --build build-mcvideo -j"$(nproc)" && ctest --test-dir build-mcvideo'
```

## Tests

| ID | What is checked |
|---|---|
| SC-01 | Unit tests: the `<mcvideoinfo>` round trip and the MCVideo Accept-Contact check |
| SC-02 | `test_warning`: the MCPTT table reproduces the TS 24.379 warnings exactly, the MCVideo numbering, and the refusals |
| SC-03 | Unit tests: the byte-exact MCPTT SDP fixture, the MCVideo SDP layout and round trip, colon-separated parameters, granted SSRCs and the rejections |
| SC-04 | Unit tests: the arbitrator driven through `MediaPlaneController`, and `relay_payload` (both AMR-WB directions, H.264 unchanged, non-AMR-WB speech refused) |
| SC-05 to SC-07 | Lab `smoke-mcvideo` (`--mcvideo`), `mcvideo_server_scenario`: `mcvideo-server` ready as MCVideo and a separate instance; MCVideo PSI and no Diameter configuration; `mcptt-server` ready as MCPTT with its users; and `prearranged_scenario` with `mcvideo-server` running |
| SC-08 | `smoke-mcvideo` routing: OPTIONS from client-a to `sip:mcvideo@mcx.test` answered 200 by `mcvideo-server`, to `sip:mcdata@mcx.test` 200, to a PSI without a server 403 from the core; Kamailio configuration checked in TLS and debug modes; Go tests for the MCVideo ID lookup, claim and validation |

The MCVideo procedures on the wire are checked by the other MCVideo reports, listed in the [MCVideo test index](../MCVIDEO_TEST.md).
