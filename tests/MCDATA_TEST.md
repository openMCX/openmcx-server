# MCData test index

Index of performed MCData tests, organized by MCData service. MCPTT tests are in the [MCPTT test index](MCPTT_TEST.md). The baseline is TS 24.282 **V19.7.0** (Release 19); earlier runs against V18.10.0 are recorded as history. Results describe the recorded builds and scenarios, not complete standards conformance. Artifact links refer to local lab files, which may be absent in a fresh checkout.

## One MCData server beside the MCPTT server

`mcdata-server` (`openmcx-mcdata-server`) is a separate container and SIP application server with its own public service identity (`sip:mcdata@DOMAIN`). It combines the participating and controlling MCData functions. The MCData client is a module of `mcx-client` and shares the UE's single SIP registration with the MCPTT client (TS 24.282 §7.1). The four-client MCData labs (`mcdata-lab`, `mcdata22-lab`, `mcdata25-lab`, `mcdata26-lab`, `mcdata27-lab`, `mcdata28-lab`, `mcdata29-lab`, `mcdata30-lab`, `mcdata31-lab`, `fd30-lab`, `fd31-lab`, `fd32-lab`, `fd33-lab`, `fd34-lab`, `fd35-lab`, `media37-lab`, `media38-lab`, `media39-lab`, `media63-lab`) are **test fixtures only**: they run the same binaries as the MCPTT labs and differ in generated configuration (`--mcdata`) and image tag. Architecture: MCData Phase 1 design, [reference points](../docs/architecture/mcdata-reference-points.md), [standards and acceptance](../docs/architecture/mcdata-standards-and-acceptance.md).

## MCData services

| Service | Recorded coverage |
|---|---|
| [Standalone SDS over the signalling control plane](#standalone-sds) | MCData service authorisation and affiliation; one-to-one and group SDS; delivery, read and delivered-and-read notifications with TDU1; conversation threading; application IDs; application priority (`used-priority`); ad hoc group SDS by participant list, criteria or ad hoc group identity; functional aliases (activation, take-over, SDS to an alias, presentation); group emergency alerts with location, receipts, late alerts and cancellation; UNDELIVERED storage and re-delivery with TDP1; group notification aggregation with TDC1; affiliation status subscription and implicit affiliation; 21 rejection warnings |
| [File distribution over HTTP](#file-distribution-over-http) | Discovery of the media storage function URI; upload and download at the media storage function; one-to-one and group FD; auto-receive; mandatory and non-mandatory download; accepted, rejected, deferred and completed notifications; the file availability timer TDC2 with its network notification; release of a distribution by its originator, by the server and by an authorised user; aggregated group notifications; FD to a functional alias; nine rejection warnings |
| [SDS and FD over the media plane](#sds-over-the-media-plane) | Standalone one-to-one and group SDS carried in MSRP over a negotiated `m=message` stream, SDS sessions that stay open with in-band disposition notifications, the emergency one-to-one, emergency group and imminent peril group communications they carry, and file distribution whose file travels in MSRP |
| [IP connectivity](#ip-connectivity) | One-to-one IP connectivity sessions: the tunnel set up through `mcdata-server` and answered only once the called client accepts, a GRE-in-UDP tunnel relayed by the server that carries IPv4 ICMP echo between the clients' built-in IP applications in both directions, sessions to a functional alias through 300, the rejections 200, 229, 230, 145 and a busy client's 486, and the release by either client |
| [Communication release](#communication-release) | The release of communications over the media plane: the leave policies, the server's time and data limits and operator release with the reason, the intent with TDC3 and the extension, the authorised user's release at once and with prior indication, IP connectivity, and the authorised user's release with prior indication over HTTP |
| [Enhanced status](#enhanced-status) | A member shares an operational value of its group, such as "On scene", as a group SDS with an ENHANCED STATUS payload; members render it from the group document or discard an unknown value |

| File distribution over the media plane | One-to-one and group, in the [media plane tests](mcdata/MCDATA_MEDIA_TEST.md) |
| IP connectivity | One-to-one, in the [IP connectivity tests](mcdata/MCDATA_IPCONN_TEST.md); clause 20 has no group variant |
| Imminent peril and emergency group communications | On a group SDS session, in the [media plane tests](mcdata/MCDATA_MEDIA_TEST.md) |
| Ad hoc group emergency alert, ad hoc group determination, functional alias status subscription | Not implemented |
| Off-network SDS, MBMS/MBS delivery | Not implemented (hard blockers H3, H4) |

## Standalone SDS

Short data messages sent in SIP MESSAGE requests through `mcdata-server`, one-to-one or to an affiliated group, with disposition notifications (TS 24.282 §9.2.2, §12.2).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Protected payload tests](mcdata/MCDATA_PROTECTED_TEST.md) | Signalling protection and XML confidentiality with each client's CSK; end-to-end protection of SDS on both planes, SDS sessions and files (media plane, and one-to-one over HTTP): PCK one-to-one, GMK group; 606 or 488 with warning 136 for an altered I_MESSAGE; wire proof that no text crosses in clear |
| [Standalone SDS tests and call flow](mcdata/MCDATA_SDS_TEST.md) | Service authorisation, affiliation, one-to-one and group SDS, disposition notifications, threading, application IDs, priority and the SDS rejections. Holds the shared four-client fixture, the client status fields and the coverage gaps |
| [Ad hoc group SDS tests](mcdata/MCDATA_ADHOC_SDS_TEST.md) | Participant lists, criteria and follow-ups to a generated ad hoc group, with the ad hoc authorisation and participation checks |
| [Functional alias tests](mcdata/MCDATA_FUNCTIONAL_ALIAS_TEST.md) | Activation, limit and take-over, SDS to an alias with the 300 redirect, aliases in ad hoc lists, presentation of the sender's alias |
| [Affiliation status tests](mcdata/MCDATA_AFFILIATION_TEST.md) | Subscription, NOTIFY of every change with the echoed p-id, fetch and de-subscription, and implicit affiliation to configured groups |
| [Disposition handling tests](mcdata/MCDATA_DISPOSITION_TEST.md) | UNDELIVERED storage and re-delivery with timer TDP1, and aggregation of a group's notifications with timer TDC1 |
| [Group emergency alert tests](mcdata/MCDATA_EMERGENCY_ALERT_TEST.md) | Alerts with location, notification of the members, receipts, late alerts and cancellation, with their call flow |
| [Message store tests](mcdata/MCDATA_MESSAGE_STORE_TEST.md) | Storage control, deposits, the message store client operations, notifications through the notification server, and upload by reference |
| [Location tests](mcdata/MCDATA_LOCATION_TEST.md) | Clause 17 location reporting, requests and reporting changes, refusals 244/245/246, emergency alert and group geographic areas, and the location XML encrypted under the CSK |

### Performed scenarios

Recorded on 2026-09-22 against image `openmcx:0.29-mcdata` (`fb662f09297d`), TS 24.282 V19.7.0. All reports record **PASS**.

| ID | Test / coverage | Result evidence |
|---|---|---|
| SD-00–SD-13 | [Standalone SDS](mcdata/MCDATA_SDS_TEST.md): authorisation and affiliation, one-to-one and group SDS, threading, delivery/read/delivered-and-read notifications with TDU1, application IDs, application priority, and the one-to-one and group rejections | [Scenario report](../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json) |
| AD-01–AD-07 | [Ad hoc group SDS](mcdata/MCDATA_ADHOC_SDS_TEST.md): participant lists, criteria, follow-ups and the ad hoc rejections | Same report |
| FA-01–FA-06 | [Functional aliases](mcdata/MCDATA_FUNCTIONAL_ALIAS_TEST.md): activation, take-over, SDS to an alias and its presentation | Same report |
| AF-01–AF-05 | [Affiliation status](mcdata/MCDATA_AFFILIATION_TEST.md): subscription and NOTIFY, fetch, de-subscription, p-id echo and implicit affiliation | Same report |
| RD-01–RD-03, AG-01–AG-02 | [Disposition handling](mcdata/MCDATA_DISPOSITION_TEST.md): re-delivery of undelivered SDS with TDP1, and aggregation with TDC1 | Same report |
| EA-01–EA-06 | [Group emergency alerts](mcdata/MCDATA_EMERGENCY_ALERT_TEST.md): alert, receipts, late alert, cancellation and the alert rejections | Same report |
| SD-14 | SIP wire checks (64) with clause 15 bodies decoded independently of the C++ codec | [Wire report](../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json), [capture](../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap) |
| SD-15 | Unit tests of the MCData codecs (byte-exact clause 15 fixtures) | `test_mcdata` in the image build (19/19 native tests) |

On the same image the MCPTT prearranged (21) and emergency (43) scenarios passed. Earlier runs on V19.7.0: `openmcx:0.28-mcdata` (`edf1f58f854e`, aggregation), 152 checks and 58 wire checks; `openmcx:0.27-mcdata` (`c36935264646`, re-delivery), 146 checks and 55 wire checks; `openmcx:0.26-mcdata` (`0e8fed6a5edb`, emergency alerts), 134 checks and 51 wire checks, and the MCPTT emergency regression (43 assertions); `openmcx:0.25-mcdata` (`cc88524522ed`, functional aliases), 108 checks and 45 wire checks; `openmcx:0.24-mcdata` (`623c54c5ce4d`, ad hoc group SDS), 81 checks and 40 wire checks; before ad hoc group SDS, `openmcx:0.23-mcdata` (`bacdc6eeb84b`), 58 checks and 33 wire checks. Earlier runs against TS 24.282 V18.10.0: `openmcx:0.22-mcdata` (`b23eb21b98a1`), 53 checks and 31 wire checks ([report](../artifacts/mcdata22-lab/artifacts/integration/mcdata-sds-results.json)); `openmcx:0.21-mcdata` (`301de09f285b`), 52 checks twice, and the MCPTT all-call-types regression on one server instance (prearranged 21, failure/refresh, broadcast 56, private 96, chat 67, ad hoc 81, remote group 20, ambient listening 51) plus emergency first-to-answer 29 ([reports](../artifacts/mcdata-all-lab/artifacts/integration/)).

### SDS coverage gaps

Over the signalling plane: persistent storage of undelivered messages across a restart, functional alias status subscription, the ad hoc group emergency alert, ad hoc group determination and modification, temporary groups and regroups, XML integrity protection (payload protection and XML confidentiality are in the [protected MCData tests](mcdata/MCDATA_PROTECTED_TEST.md)), the MCData service configuration document, negotiated and rules based affiliation, and REGISTER feature tags are not implemented. See the [full gap table](mcdata/MCDATA_SDS_TEST.md#coverage-gaps). Physical-device validation has not been performed.

## SDS over the media plane

A standalone SDS whose payload travels over MSRP rather than in the SIP MESSAGE (TS 24.282 §9.2.3, TS 24.582 §6.1.1). openMCX has its own MSRP module, since PJSIP provides none.

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Media plane tests and call flow](mcdata/MCDATA_MEDIA_TEST.md) | The MSRP module, the `m=message` offer and answer, the transfer and its delivery leg, session release, rejections, fixture and commands |

### Performed scenarios

Recorded on 2026-09-23 against image `openmcx:0.44-mcdata` (`7941277036d3`), TS 24.282 V19.7.0 with TS 24.582 V19.0.0. All reports record **PASS**.

| ID | Test / coverage | Result evidence |
|---|---|---|
| MP-01–MP-06, MP-09–MP-24 | One-to-one and group SDS over the media plane with the same Message ID delivered to each recipient, an SDS session carrying messages in both directions with in-band notifications, its upgrade to an emergency communication and the cancellation, the emergency and imminent peril group communications with the in-progress states of the group followed by every member and the 149 correction, the rejections 200, 229, 230, 201, 206, 488/207, 112, 233 and 236, file distribution over the media plane with the file carried in MSRP, verified against its size and hash selectors and answered with the completion notification, the decline of a file that is neither mandatory nor auto-received, an emergency alert sent inside the session request with its location, the SIP MESSAGE that tells an affiliated non-participant of the in-progress state, ad hoc group standalone SDS, SDS sessions and file distribution named by a participant list, criteria or the ad hoc group with the rejections 238, 240, 241 and 242, and the release of the sessions (128 checks) | [Scenario report](../artifacts/media63-lab/artifacts/integration/mcdata-media-results.json) |
| MP-07 | SIP and MSRP wire checks (63), with the MSRP frames and the clause 15 bodies decoded independently of the C++ implementation | [Wire report](../artifacts/media63-lab/artifacts/integration/mcdata-media-sip-wire.json), [capture](../artifacts/media63-lab/artifacts/integration/mcdata-media.pcap) |
| MP-08 | Unit tests of the MSRP framing, chunking over a TCP loopback connection and the `m=message` SDP | `test_msrp` in the image build |

### Media plane coverage gaps

Ad hoc group emergency and imminent peril communications, pre-established sessions, MSRP over TLS between client and server and MSRP relays are not implemented. See the [full gap table](mcdata/MCDATA_MEDIA_TEST.md#coverage-gaps).

## Enhanced status

A member shares one of its group's operational values with the other members as a group standalone SDS (TS 24.282 §14.2).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Enhanced status tests and call flow](mcdata/MCDATA_STATUS_TEST.md) | The group document values, sending, delivery, rendering and discarding, fixture and commands |

### Performed scenarios

Recorded on 2026-09-23 against image `openmcx:0.47-mcdata` (`72745e819dbc`), TS 24.282 V19.7.0. All reports record **PASS**.

| ID | Test / coverage | Result evidence |
|---|---|---|
| ES-01–ES-05 | The operational values from the group document, a status rendered by every other member, the client's refusal of a group that does not allow it and of an unknown id, the discarding of an unknown id on receipt, and the 201 transmission control (11 checks) | [Scenario report](../artifacts/status47-lab/artifacts/integration/mcdata-status-results.json) |
| ES-06 | SIP wire checks (6) with the DATA PAYLOAD decoded independently of the C++ codec | [Wire report](../artifacts/status47-lab/artifacts/integration/mcdata-status-sip-wire.json), [capture](../artifacts/status47-lab/artifacts/integration/mcdata-status.pcap) |
| ES-07 | Unit tests of the group document elements (`test_protocol`, `go test`) | Image build |

### Enhanced status coverage gaps

The group document is not validated against the full TS 24.481 schema; off-network enhanced status needs H3. See the [full gap table](mcdata/MCDATA_STATUS_TEST.md#coverage-gaps).

## Communication release

The release of an ongoing MCData communication by its participants, the MCData server or an authorised user (TS 24.282 clause 13).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Communication release tests and call flow](mcdata/MCDATA_RELEASE_TEST.md) | The COMMUNICATION RELEASE message, the leave policies, limits, intent and extension, authorised users, IP connectivity and FD over HTTP, fixture and commands |

### Performed scenarios

Recorded on 2026-09-23 against image `openmcx:0.46-mcdata` (`89f593704af5`), and again on `openmcx:0.47-mcdata` (`72745e819dbc`), TS 24.282 V19.7.0. All reports record **PASS**.

| ID | Test / coverage | Result evidence |
|---|---|---|
| REL-01–REL-12 | Leave policies for one-to-one, group and ad hoc sessions; release on the data and time limits and by operator with the reason; the intent with and without the data query, the accepted extension and TDC3 expiry; the authorised user's release at once (and 403 for others) and with prior indication; IP connectivity; FD over HTTP with an authorised user's intent (57 checks) | [Scenario report](../artifacts/release46-lab/artifacts/integration/mcdata-release-results.json) |
| REL-13 | SIP wire checks (26) with the COMMUNICATION RELEASE, DATA PAYLOAD and FD HTTP TERMINATION bodies decoded independently of the C++ codec | [Wire report](../artifacts/release46-lab/artifacts/integration/mcdata-release-sip-wire.json), [capture](../artifacts/release46-lab/artifacts/integration/mcdata-release.pcap) |
| REL-14 | Unit tests of the COMMUNICATION RELEASE codec | `test_mcdata` in the image build |

### Release coverage gaps

The minimum number of affiliated group members is not checked, limits are per server, and prior indication is not implemented for IP connectivity. See the [full gap table](mcdata/MCDATA_RELEASE_TEST.md#coverage-gaps).

## IP connectivity

A one-to-one session that carries IP packets between two MCData clients through a GRE-in-UDP tunnel relayed by `mcdata-server` (TS 24.282 clause 20, TS 24.582 clause 13).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [IP connectivity tests and call flow](mcdata/MCDATA_IPCONN_TEST.md) | The tunnel SDP, the deferred answer, the UDP relay and its source check, the built-in IP application, functional aliases, rejections, release, fixture and commands |

### Performed scenarios

Recorded on 2026-09-23 against image `openmcx:0.45-mcdata` (`1c55cb9d508d`), TS 24.282 V19.7.0 with TS 24.582 V19.0.0. All reports record **PASS**.

| ID | Test / coverage | Result evidence |
|---|---|---|
| IP-01–IP-08 | Setup through the server with the caller answered after the called client, ICMP echo of 64 and 1200 bytes in both directions through the tunnel, packets for another address dropped by the IP application, datagrams from outside the session dropped by the server, release by either client, 486 from a busy client passed back, the rejections 200, 229, 230 and 145, and a session to a functional alias through 300 (31 checks) | [Scenario report](../artifacts/ipconn45-lab/artifacts/integration/mcdata-ipconn-results.json) |
| IP-09 | SIP and tunnel wire checks (22): the SIP decoded from the capture, and every tunnel datagram decoded through UDP, GRE, IPv4 and ICMP independently of the C++ implementation, with tshark decoding the same 44 datagrams | [Wire report](../artifacts/ipconn45-lab/artifacts/integration/mcdata-ipconn-sip-wire.json), [capture](../artifacts/ipconn45-lab/artifacts/integration/mcdata-ipconn.pcap) |
| IP-10 | Unit tests of the tunnel SDP, GRE, IPv4 and ICMP codecs with byte-exact fixtures | `test_ipconn` in the image build |

### IP connectivity coverage gaps

The client is its own minimal IPv4 endpoint: there is no TUN device, no external host and no IPv6 endpoint. Implicit target determination from IP information, `<application-data>`, emergency IP connectivity and the `FAILURE_CAUSE` release are not implemented. See the [full gap table](mcdata/MCDATA_IPCONN_TEST.md#coverage-gaps).

## File distribution over HTTP

Files uploaded to the media storage function of the MCData content server and distributed by SIP MESSAGE naming their URL, one-to-one or to an affiliated group (TS 24.282 §10.2.2–10.2.4, §12.2, §12.4).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [File distribution over HTTP tests and call flow](mcdata/MCDATA_FD_TEST.md) | Content server, upload and download, FD requests and delivery, auto-receive, notifications, the file availability timer, rejections, fixture and commands |

### Performed scenarios

Recorded on 2026-09-22 against image `openmcx:0.35-mcdata` (`a346b042dd8c`), TS 24.282 V19.7.0. All reports record **PASS**.

| ID | Test / coverage | Result evidence |
|---|---|---|
| FD-01–FD-11 | One-to-one and group file distribution with identical bytes delivered and verified against the metadata hash, auto-receive, accept/reject/defer, the four FD notifications, TDC2 expiry with its network notification, release of a distribution with its TERMINATION RESPONSE and FILE DELETED notification, aggregated group notifications, the functional alias redirect, and nine rejection warnings discovery of the media storage function URI, release by the server and by an authorised user with prior indication and an extension (64 checks) | [Scenario report](../artifacts/fd35-lab/artifacts/integration/mcdata-fd-results.json) |
| FD-12 | SIP wire checks (38) with the clause 15 FD bodies decoded independently of the C++ codec | [Wire report](../artifacts/fd35-lab/artifacts/integration/mcdata-fd-sip-wire.json), [capture](../artifacts/fd35-lab/artifacts/integration/mcdata-fd.pcap) |
| FD-13–FD-14 | Unit tests of the FD codecs and of the content server (upload, download, HEAD, listing, removal, size limits, transmission and reception control) | `test_mcdata` and `go test ./...` in the image build |

On the same image the SDS scenario passed its 163 checks and 64 wire checks, covering the shared MCData server and client paths.

### FD coverage gaps

Deferred delivery is not implemented. Upload by reference of a file in the MCData message store is in the [message store tests](mcdata/MCDATA_MESSAGE_STORE_TEST.md). FD over the media plane is in the [media plane tests](mcdata/MCDATA_MEDIA_TEST.md) and the release procedures of clause 13 in the [communication release tests](mcdata/MCDATA_RELEASE_TEST.md). See the [full gap table](mcdata/MCDATA_FD_TEST.md#coverage-gaps).

## Unimplemented features

The [MCData acceptance matrix](../docs/architecture/mcdata-standards-and-acceptance.md) lists every planned and blocked MCData item with its reference and status. Hard blockers shared with MCPTT (H1–H4) are described in the blockers and implementation guide.

## Adding another MCData service

Add a row to the service table and a dedicated section with its own stable test ID prefix. Record the service, client count, protection, tested build and specification version, scenario, result, test-description link and capture/report links. Keep planned scenarios separate from performed tests, and preserve historical evidence when replacing a result.
