# MCData test index

The MCData tests, by service: what each scenario checks, with a link to the report that holds its commands, call
flows, checks and coverage gaps. MCPTT tests are in the [MCPTT test index](MCPTT_TEST.md) and MCVideo tests in the
[MCVideo test index](MCVIDEO_TEST.md). The baseline is TS 24.282 **V19.7.0** and TS 24.582 **V19.0.0** (Release 19).
How to run the tests is in the [developer guide](../docs/DEVELOPER_GUIDE.md#9-testing). A passing scenario shows the
procedure working in the lab, not complete conformance to the specification.

## One MCData server beside the MCPTT server

`mcdata-server` (`openmcx-mcdata-server`) is a separate container and SIP application server with its own public service identity (`sip:mcdata@DOMAIN`). It combines the participating and controlling MCData functions. The MCData client is a module of `mcx-client` and shares the UE's single SIP registration with the MCPTT client (TS 24.282 §7.1). The MCData labs of the regression (`smoke-mcdata`, `mcdata`, `mcdata-ipconn`, `mcdata-protected`, …; `tools/regress.py --list`) are **test fixtures only**: they run the same binaries as the MCPTT labs and differ in generated configuration (`--mcdata`). Architecture: [reference points](../docs/architecture/mcdata-reference-points.md), [standards and acceptance](../docs/architecture/mcdata-standards-and-acceptance.md).

## MCData services

| Service | Coverage |
|---|---|
| [Standalone SDS over the signalling control plane](#standalone-sds) | MCData service authorisation and affiliation; one-to-one and group SDS; delivery, read and delivered-and-read notifications with TDU1; conversation threading; application IDs; application priority (`used-priority`); ad hoc group SDS by participant list, criteria or ad hoc group identity; functional aliases (activation, take-over, SDS to an alias, presentation); group emergency alerts with location, receipts, late alerts and cancellation; UNDELIVERED storage and re-delivery with TDP1; group notification aggregation with TDC1; affiliation status subscription and implicit affiliation; 21 rejection warnings |
| [File distribution over HTTP](#file-distribution-over-http) | Discovery of the media storage function URI; upload and download at the media storage function; one-to-one and group FD; auto-receive; mandatory and non-mandatory download; accepted, rejected, deferred and completed notifications; the file availability timer TDC2 with its network notification; release of a distribution by its originator, by the server and by an authorised user; aggregated group notifications; FD to a functional alias; nine rejection warnings |
| [SDS and FD over the media plane](#sds-over-the-media-plane) | Standalone one-to-one and group SDS carried in MSRP over a negotiated `m=message` stream, SDS sessions that stay open with in-band disposition notifications, the emergency one-to-one, emergency group and imminent peril group communications they carry, and file distribution whose file travels in MSRP |
| [IP connectivity](#ip-connectivity) | One-to-one IP connectivity sessions: the tunnel set up through `mcdata-server` and answered only once the called client accepts, a GRE-in-UDP tunnel relayed by the server that carries IPv4 ICMP echo between the clients' built-in IP applications in both directions, sessions to a functional alias through 300, the rejections 200, 229, 230, 145 and a busy client's 486, and the release by either client |
| [Communication release](#communication-release) | The release of communications over the media plane: the leave policies, the server's time and data limits and operator release with the reason, the intent with TDC3 and the extension, the authorised user's release at once and with prior indication, IP connectivity, and the authorised user's release with prior indication over HTTP |
| [Enhanced status](#enhanced-status) | A member shares an operational value of its group, such as "On scene", as a group SDS with an ENHANCED STATUS payload; members render it from the group document or discard an unknown value |

| Also | Where |
|---|---|
| File distribution over the media plane | One-to-one and group, in the [media plane tests](mcdata/MCDATA_MEDIA_TEST.md) |
| IP connectivity | One-to-one, in the [IP connectivity tests](mcdata/MCDATA_IPCONN_TEST.md); clause 20 has no group variant |
| Imminent peril and emergency group communications | On a group SDS session, in the [media plane tests](mcdata/MCDATA_MEDIA_TEST.md) |
| Ad hoc group emergency alert, ad hoc group determination, functional alias status subscription | Not implemented |
| Off-network SDS, MBMS/MBS delivery | Not in present edition |

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

### Scenarios

| ID | Test / coverage |
|---|---|
| SD-00–SD-13 | [Standalone SDS](mcdata/MCDATA_SDS_TEST.md): authorisation and affiliation, one-to-one and group SDS, threading, delivery/read/delivered-and-read notifications with TDU1, application IDs, application priority, and the one-to-one and group rejections |
| AD-01–AD-07 | [Ad hoc group SDS](mcdata/MCDATA_ADHOC_SDS_TEST.md): participant lists, criteria, follow-ups and the ad hoc rejections |
| FA-01–FA-06 | [Functional aliases](mcdata/MCDATA_FUNCTIONAL_ALIAS_TEST.md): activation, take-over, SDS to an alias and its presentation |
| AF-01–AF-05 | [Affiliation status](mcdata/MCDATA_AFFILIATION_TEST.md): subscription and NOTIFY, fetch, de-subscription, p-id echo and implicit affiliation |
| RD-01–RD-03, AG-01–AG-02 | [Disposition handling](mcdata/MCDATA_DISPOSITION_TEST.md): re-delivery of undelivered SDS with TDP1, and aggregation with TDC1 |
| EA-01–EA-06 | [Group emergency alerts](mcdata/MCDATA_EMERGENCY_ALERT_TEST.md): alert, receipts, late alert, cancellation and the alert rejections |
| SD-14 | SIP wire checks (64) with clause 15 bodies decoded independently of the C++ codec |
| SD-15 | Unit tests of the MCData codecs (byte-exact clause 15 fixtures, `test_mcdata`) |

### SDS coverage gaps

Over the signalling plane: persistent storage of undelivered messages across a restart, functional alias status subscription, the ad hoc group emergency alert, ad hoc group determination and modification, temporary groups and regroups, XML integrity protection (payload protection and XML confidentiality are in the [protected MCData tests](mcdata/MCDATA_PROTECTED_TEST.md)), the MCData service configuration document, negotiated and rules based affiliation, and REGISTER feature tags are not implemented. See the [full gap table](mcdata/MCDATA_SDS_TEST.md#coverage-gaps). The scenarios run in Docker labs, not on physical devices.

## SDS over the media plane

A standalone SDS whose payload travels over MSRP rather than in the SIP MESSAGE (TS 24.282 §9.2.3, TS 24.582 §6.1.1). OpenMCX has its own MSRP module, since PJSIP provides none.

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Media plane tests and call flow](mcdata/MCDATA_MEDIA_TEST.md) | The MSRP module, the `m=message` offer and answer, the transfer and its delivery leg, session release, rejections, fixture and commands |

### Scenarios

| ID | Test / coverage |
|---|---|
| MP-01–MP-06, MP-09–MP-24 | One-to-one and group SDS over the media plane with the same Message ID delivered to each recipient, an SDS session carrying messages in both directions with in-band notifications, its upgrade to an emergency communication and the cancellation, the emergency and imminent peril group communications with the in-progress states of the group followed by every member and the 149 correction, the rejections 200, 229, 230, 201, 206, 488/207, 112, 233 and 236, file distribution over the media plane with the file carried in MSRP, verified against its size and hash selectors and answered with the completion notification, the decline of a file that is neither mandatory nor auto-received, an emergency alert sent inside the session request with its location, the SIP MESSAGE that tells an affiliated non-participant of the in-progress state, ad hoc group standalone SDS, SDS sessions and file distribution named by a participant list, criteria or the ad hoc group with the rejections 238, 240, 241 and 242, and the release of the sessions (128 checks) |
| MP-07 | SIP and MSRP wire checks (63), with the MSRP frames and the clause 15 bodies decoded independently of the C++ implementation |
| MP-08 | Unit tests of the MSRP framing, chunking over a TCP loopback connection and the `m=message` SDP |

### Media plane coverage gaps

Ad hoc group emergency and imminent peril communications, pre-established sessions, MSRP over TLS between client and server and MSRP relays are not implemented. See the [full gap table](mcdata/MCDATA_MEDIA_TEST.md#coverage-gaps).

## Enhanced status

A member shares one of its group's operational values with the other members as a group standalone SDS (TS 24.282 §14.2).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Enhanced status tests and call flow](mcdata/MCDATA_STATUS_TEST.md) | The group document values, sending, delivery, rendering and discarding, fixture and commands |

### Scenarios

| ID | Test / coverage |
|---|---|
| ES-01–ES-05 | The operational values from the group document, a status rendered by every other member, the client's refusal of a group that does not allow it and of an unknown id, the discarding of an unknown id on receipt, and the 201 transmission control (11 checks) |
| ES-06 | SIP wire checks (6) with the DATA PAYLOAD decoded independently of the C++ codec |
| ES-07 | Unit tests of the group document elements (`test_protocol`, `go test`) |

### Enhanced status coverage gaps

The group document is not validated against the full TS 24.481 schema; off-network enhanced status is not in the present edition. See the [full gap table](mcdata/MCDATA_STATUS_TEST.md#coverage-gaps).

## Communication release

The release of an ongoing MCData communication by its participants, the MCData server or an authorised user (TS 24.282 clause 13).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [Communication release tests and call flow](mcdata/MCDATA_RELEASE_TEST.md) | The COMMUNICATION RELEASE message, the leave policies, limits, intent and extension, authorised users, IP connectivity and FD over HTTP, fixture and commands |

### Scenarios

| ID | Test / coverage |
|---|---|
| REL-01–REL-12 | Leave policies for one-to-one, group and ad hoc sessions; release on the data and time limits and by operator with the reason; the intent with and without the data query, the accepted extension and TDC3 expiry; the authorised user's release at once (and 403 for others) and with prior indication; IP connectivity; FD over HTTP with an authorised user's intent (57 checks) |
| REL-13 | SIP wire checks (26) with the COMMUNICATION RELEASE, DATA PAYLOAD and FD HTTP TERMINATION bodies decoded independently of the C++ codec |
| REL-14 | Unit tests of the COMMUNICATION RELEASE codec |

### Release coverage gaps

The minimum number of affiliated group members is not checked, limits are per server, and prior indication is not implemented for IP connectivity. See the [full gap table](mcdata/MCDATA_RELEASE_TEST.md#coverage-gaps).

## IP connectivity

A one-to-one session that carries IP packets between two MCData clients through a GRE-in-UDP tunnel relayed by `mcdata-server` (TS 24.282 clause 20, TS 24.582 clause 13).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [IP connectivity tests and call flow](mcdata/MCDATA_IPCONN_TEST.md) | The tunnel SDP, the deferred answer, the UDP relay and its source check, the built-in IP application, functional aliases, rejections, release, fixture and commands |

### Scenarios

| ID | Test / coverage |
|---|---|
| IP-01–IP-08 | Setup through the server with the caller answered after the called client, ICMP echo of 64 and 1200 bytes in both directions through the tunnel, packets for another address dropped by the IP application, datagrams from outside the session dropped by the server, release by either client, 486 from a busy client passed back, the rejections 200, 229, 230 and 145, and a session to a functional alias through 300 (31 checks) |
| IP-09 | SIP and tunnel wire checks (22): the SIP decoded from the capture, and every tunnel datagram decoded through UDP, GRE, IPv4 and ICMP independently of the C++ implementation, with tshark decoding the same 44 datagrams |
| IP-10 | Unit tests of the tunnel SDP, GRE, IPv4 and ICMP codecs with byte-exact fixtures |

### IP connectivity coverage gaps

The client is its own minimal IPv4 endpoint: there is no TUN device, no external host and no IPv6 endpoint. Implicit target determination from IP information, `<application-data>`, emergency IP connectivity and the `FAILURE_CAUSE` release are not implemented. See the [full gap table](mcdata/MCDATA_IPCONN_TEST.md#coverage-gaps).

## File distribution over HTTP

Files uploaded to the media storage function of the MCData content server and distributed by SIP MESSAGE naming their URL, one-to-one or to an affiliated group (TS 24.282 §10.2.2–10.2.4, §12.2, §12.4).

### Test descriptions and commands

| Document | Scope |
|---|---|
| [File distribution over HTTP tests and call flow](mcdata/MCDATA_FD_TEST.md) | Content server, upload and download, FD requests and delivery, auto-receive, notifications, the file availability timer, rejections, fixture and commands |

### Scenarios

| ID | Test / coverage |
|---|---|
| FD-01–FD-11 | One-to-one and group file distribution with identical bytes delivered and verified against the metadata hash, auto-receive, accept/reject/defer, the four FD notifications, TDC2 expiry with its network notification, release of a distribution with its TERMINATION RESPONSE and FILE DELETED notification, aggregated group notifications, the functional alias redirect,, nine rejection warnings, discovery of the media storage function URI, release by the server and by an authorised user with prior indication and an extension (64 checks) |
| FD-12 | SIP wire checks (38) with the clause 15 FD bodies decoded independently of the C++ codec |
| FD-13–FD-14 | Unit tests of the FD codecs and of the content server (upload, download, HEAD, listing, removal, size limits, transmission and reception control) |

### FD coverage gaps

Deferred delivery is not implemented. Upload by reference of a file in the MCData message store is in the [message store tests](mcdata/MCDATA_MESSAGE_STORE_TEST.md). FD over the media plane is in the [media plane tests](mcdata/MCDATA_MEDIA_TEST.md) and the release procedures of clause 13 in the [communication release tests](mcdata/MCDATA_RELEASE_TEST.md). See the [full gap table](mcdata/MCDATA_FD_TEST.md#coverage-gaps).

## Not covered

The [MCData acceptance matrix](../docs/architecture/mcdata-standards-and-acceptance.md) gives the status of each MCData procedure with its reference; what the present edition does not include, and the known limits of what it implements, are in the [limitations](../docs/LIMITATIONS.md).

## Adding another MCData service

Add a row to the service table and a section with its own stable test ID prefix, the service, client count, protection, the scenario and a link to its report.
