# MCVideo shared-core tests

These tests cover **increment V1a of the MCVideo plan**: the call-handling core of `mcptt-server` becomes a core parameterised by MC service, so the same code can run as the MCPTT server and, later, as the MCVideo server (TS 24.281 V19.6.0, TS 24.581 V19.2.0). V1a changes no MCPTT or MCData behaviour; the evidence is that the MCPTT wire format is unchanged and the existing labs still pass.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-CORE-01).

## How it works

- **Service profile** (`include/mcx/service.hpp`). What tells one MC service apart on the wire and in configuration: ICSI, media feature tag, the `<prefix>info` document and its namespace, location MIME type, configuration section and IdMS ID claim. `mcptt-server`, the SIP engine (Contact, P-Preferred-Service, Accept-Contact), the info codec and the Accept-Contact admission check read it. `mcptt-server` still runs the MCPTT profile only; it selects its profile from configuration in V1a.5.
- **Warning tables** (`include/mcx/warning.hpp`). A refusal is a reason (`Warning::not_affiliated`), turned into `<code> <text>` by the table of the server's service: TS 24.379 for MCPTT (the texts the server has always sent), TS 24.281 §4.4.2 for MCVideo, which numbers some warnings differently (invalid location target 191).
- **Media plane control** (`include/mcx/media_control.hpp`). A call's `Session` holds a `MediaPlaneController`, made by one factory for the server's service; the TS 24.380 `FloorArbitrator` is its first implementation, and MCVideo transmission control (TS 24.581) will be the second (V3). The TS 24.380 packet encoding stays in `send_notice`/`floor_packet` until then.
- **MCVideo server container** (`mcvideo-server`). `mcptt-server` takes its service from the configuration's `"service"` (`mcptt` by default, or `mcvideo`). `tools/provision.py` generates `mcvideo-server.json` with the MCVideo PSI `sip:mcvideo@DOMAIN`, an `mcvideo` section, users keyed by MCVideo ID (`sip:<user>.mcvideo@DOMAIN`) and no Diameter peer (MCVideo-2 is not used; an MCPTT server still refuses to start without MCPTT-2). The Compose service is in the `mcvideo` profile, and labs add it with `--mcvideo`, so existing labs are unchanged. MCVideo is not routed to it until V1a.6.
- **Routing and common services.** Kamailio sends a request for the MCVideo PSI, and for an MCVideo focus URI inside a dialog, to `mcvideo-server`; the MCData and MCVideo PSIs come from one generated list of service servers (`route[SERVICE_AS]`, `service_servers` in `tools/provision.py`), each server asserting only its own PSI. Every user has an MCVideo ID (`sip:<user>.mcvideo@DOMAIN`), which the CMS serves users by (`/internal/user?mcvideo_id=`) and the IdMS carries in tokens and introspection (`mcvideo_id`). The client's `options <SIP URI>` command probes a PSI through the core.
- **Relay** (`relay_payload` in `src/media.cpp`). The media distribution function repacks AMR-WB to each destination's framing and passes any other payload, such as H.264, unchanged.
- **SDP** (`src/protocol.cpp`). A media description has a media plane control (MCPTT floor control or MCVideo transmission control) and, for MCVideo, an H.264 `m=video` section; the MCVideo layout of TS 24.281 §6.2.1 and TS 24.581 §12 and §14 is `s=MCVideo`, audio, video and `m=application … udp MCVideo`.

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| V1a.1 Service profile | MCPTT and MCVideo profiles; `<mcvideoinfo>` parsed and written with the `mcvideo` prefix, refused by the MCPTT parser; `+g.3gpp.mcvideo` with the MCVideo ICSI selects MCVideo, not MCPTT | 24.281 Annex D.2, E.2, F.1 |
| V1a.2 Warning tables | 55 reasons; MCPTT table equal to the 54 coded warnings sent before; MCVideo table from §4.4.2; a reason MCVideo lacks (first-to-answer, call-back, transfer, forwarding, remotely initiated calls) is a programming error, never a wrong code on the wire | 24.379 §4.4, 24.281 §4.4.2 |
| V1a.3 SDP | MCPTT SDP byte-identical; MCVideo audio (`i=audio component of MCVideo`), H.264 video (`42e01f` since V2, `640c1f` before, packetization mode 1, `i=video component of MCVideo`), `a=fmtp:MCVideo` with `mc_transmission_ssrc`, `mc_queueing`, `mc_priority`, `mc_implicit_request`, `mc_granted`, `mc_audio_ssrc`, `mc_video_ssrc`; parameters sent `;`-separated, read `;`- or `:`-separated; video refused in an MCPTT SDP, an MCVideo SDP without video and non-H.264 video refused; the SIP engine parses SDP with `m=video` | 24.281 §6.2.1; 24.581 §12.1.2, §14; 26.281 §4.1 |
| V1a.4 Media plane control and relay | `Session` holds the controller through the interface; the factory refuses a service without one; relay repacks AMR-WB only, H.264 passes unchanged, and malformed speech is still refused with no receiver | 24.380 §6.3; 24.581 §6.3; RFC 4867, RFC 6184 |
| V1a.5 MCVideo server container | Service chosen by configuration; `mcvideo-server` starts ready as MCVideo with its own PSI and no Diameter, beside an unchanged `mcptt-server`; opt-in lab flag `--mcvideo` | 23.281 §6.2.2.3.2; 24.281 §4.2 |
| V1a.6 Routing and common services | MCVideo PSI and MCVideo focus URIs routed to `mcvideo-server`; MCData routing unchanged; `mcvideo-info` REGISTER to `mcvideo-server`; `mcvideo_id` validated (SIP URI, unique, not another service's ID), served by the CMS and carried by the IdMS | 24.281 §4.2, §7A; 23.280 §8.1 |

## Running the tests

The MCVideo server lab on its own:

```bash
python3 tools/regress.py --image openmcx:v1a5 --select smoke-mcvideo --output artifacts/regress-mcvideo
```

```bash
# unit tests (dev image, user-owned build directory)
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace openmcx-dev:0.1 \
  bash -lc 'cmake -S . -B build-mcvideo && cmake --build build-mcvideo -j"$(nproc)" && ctest --test-dir build-mcvideo'
# smoke labs; tools/regress.py tears every lab down after its scenario
docker build -t openmcx:v1a3 -f docker/Dockerfile .
python3 tools/regress.py --image openmcx:v1a3 --select smoke --jobs 2 --output artifacts/regress-v1a3
```

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| SC-01 | 2026-09-25 | `openmcx:v1a1` (`cf3578708b75`) | Unit tests (23), including the `<mcvideoinfo>` round trip and the MCVideo Accept-Contact check; smoke labs `prearranged_scenario` and `mcdata_sds_scenario` | Passed |
| SC-02 | 2026-09-25 | `openmcx:v1a2` (`eb42ea86f554`) | Unit tests (24) with `test_warning`: the MCPTT table reproduces all 54 earlier warnings exactly, the MCVideo numbering, and the refusals; smoke labs | Passed |
| SC-03 | 2026-09-25 | `openmcx:v1a3` (`685bcb0b5483`) | Unit tests (24) with the byte-exact MCPTT SDP fixture, the MCVideo SDP layout and round trip, colon-separated parameters, granted SSRCs and the rejections; smoke labs | Passed |
| SC-04 | 2026-09-25 | `openmcx:v1a4` (`7f9026066179`) | Unit tests (24) with the arbitrator driven through `MediaPlaneController` and `relay_payload` (both AMR-WB directions, H.264 unchanged, non-AMR-WB speech refused); smoke labs plus `prearranged_floor_scenario` (queueing) and `prearranged_priority_scenario` (pre-emption, revocation), run in parallel | Passed |
| SC-05 to SC-07 | 2026-09-25 | `openmcx:v1a5` (`e2d3b2f8d408`) | New lab `smoke-mcvideo` (`--mcvideo`): `mcvideo_server_scenario` (8 checks: mcvideo-server ready as MCVideo and a separate instance; MCVideo PSI and no Diameter configuration; mcptt-server ready as MCPTT with its users; since V1 the clients also authorise at mcvideo-server, so that check was dropped) and `prearranged_scenario` with mcvideo-server running; smoke labs; unit tests (24) | Passed |
| SC-08 | 2026-09-25 | `openmcx:v1a6` (`652e393d7f68`) | `smoke-mcvideo` with routing (11 checks): OPTIONS from client-a to `sip:mcvideo@mcx.test` answered 200 by `mcvideo-server`, to `sip:mcdata@mcx.test` 200, to a PSI without a server 403 from the core; Kamailio configuration checked in TLS and debug modes; Go tests for the MCVideo ID lookup, claim and validation; unit tests (24) | Passed |
| SC-09 | 2026-09-25 | `openmcx:v1a6` (`652e393d7f68`) | **Full regression, end of V1a**: all 38 labs, 74 scenarios, four labs at a time: 72 passed. The two failures were timing races already seen before MCVideo: INT-09 (the restarted controlling server relearns its users; it failed the same way in `regress-first`) and RG-01 (the scenario read a restarted client's old `status.json` and commanded it before it had authorised). Rerun alone, `inter` and `call-types` passed 13 of 13 (`artifacts/regress-v1a6-rerun`) | Passed |

Lab logs are under `artifacts/regress-v1a1/` to `artifacts/regress-v1a6-full/` and `artifacts/regress-v1a6-rerun/`.

## Coverage gaps

| Area | Gap |
|---|---|
| Split servers | Split servers come with V10 |
| Regression depth | The smoke labs ran after each step, with the floor queueing and priority labs after V1a.4, and the full regression at the end (SC-09) |
| MCVideo on the wire | No MCVideo request has been sent yet: the MCVideo profile, warnings and SDP are proven by unit tests only, until V1 and V2 |
| Location, XML security, ambient viewing | Still MCPTT-specific in the core (location namespace, signed and encrypted element lists, the ambient listening release tag); they follow the services that need them (V7 to V9) |
