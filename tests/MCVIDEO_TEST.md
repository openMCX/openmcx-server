# MCVideo test index

The MCVideo tests, by service: what each scenario checks, with a link to the report that holds its commands, call
flows, checks and coverage gaps. MCPTT tests are in the [MCPTT test index](MCPTT_TEST.md) and MCData tests in the
[MCData test index](MCDATA_TEST.md). The baseline is TS 24.281 **V19.6.0** and TS 24.581 **V19.2.0** (Release 19).
How to run the tests is in the [developer guide](../docs/DEVELOPER_GUIDE.md#9-testing). A passing scenario shows the
procedure working in the lab, not complete conformance to the specification.

Architecture: [reference points](../docs/architecture/mcvideo-reference-points.md),
[standards and acceptance](../docs/architecture/mcvideo-standards-and-acceptance.md).

## MCVideo services

| Service | Coverage |
|---|---|
| [Participating and controlling servers](mcvideo/MCVIDEO_SPLIT_TEST.md) | The participating and controlling MCVideo functions on different servers: authorisation and affiliation known to the controlling server, group, private and emergency calls with transmission control and video relayed by the participating servers, decoded equal at every receiver; protected video with transmission control re-keyed under an SPK between servers (MV-SP-01 to MV-SP-07) |
| [XML protection](mcvideo/MCVIDEO_XML_PROTECTION_TEST.md) | MCVideo signalling encrypted and signed under the MCVideo CSK in the MCVideo element names, beside the MCPTT signalling under its own CSK; no sensitive MCVideo data in clear on the wire (MV-XP-01 to MV-XP-07) |
| [Protected calls](mcvideo/MCVIDEO_PROTECTED_TEST.md) | MCVideo CS-IDs, KMS and GMS keying of MCVideo identities, CSK upload at MCVideo authorisation, GMK by GKTP, SRTCP transmission control and SRTP video relayed unchanged and decoded picture by picture from two senders; PCK-protected private calls with and without transmission control and ambient viewing (MV-SE-01 to MV-SE-09) |
| [Location](mcvideo/MCVIDEO_LOCATION_TEST.md) | Configuration at service authorisation, reports on log-on, distance, zone, call and periodic triggers, authorised requests with refresh and filters, sharing rights, configuration changes, refusals 191 to 193, group geographic area affiliation and emergency alert area (MV-LC-01 to MV-LC-12) |
| [Remote group selection](mcvideo/MCVIDEO_GROUP_SELECTION_TEST.md) | Remote change of a user's selected group, with the target affiliating first when asked; a call on the newly selected group; refusals 155, 120 and 167 (MV-SG-01 to MV-SG-07) |
| [Functional aliases](mcvideo/MCVIDEO_FUNCTIONAL_ALIAS_TEST.md) | Activation, limits, take-over and deactivation; status subscriptions to a user's aliases and to an alias's users, with notifications of every change; the alias presented in group and private calls, and left out when no longer held; a private call to an alias redirected with 300, and 145 for an alias no one holds; binding to a group, shown in the conference event, with refusals 176 and 178 (MV-FA-01 to MV-FA-12) |
| [Regroup](mcvideo/MCVIDEO_REGROUP_TEST.md) | Group and user regroups using a preconfigured group, their notifications and calls with video equal at the receiver; 148 for a call on a regrouped group; refusals 160 and 161; removal (MV-RG-01 to MV-RG-07) |
| [Ad hoc group call](mcvideo/MCVIDEO_ADHOC_TEST.md) | Ad hoc group calls by list and by criteria with the server-assigned ad hoc group identity; video equal at every receiver; the originator leaving ends the call; refusal `185`; the ad hoc emergency alert (MV-AH-01 to MV-AH-06) |
| [Ambient viewing](mcvideo/MCVIDEO_AMBIENT_VIEWING_TEST.md) | Remotely and locally initiated ambient viewing calls with video equal to the viewed-to user's; the release capability (annex D.3) and a refused release; refusal `154`; server release when the viewed-to user is called (MV-AV-01 to MV-AV-05) |
| [Video pull, push and remote transmission](mcvideo/MCVIDEO_PULL_PUSH_TEST.md) | One-to-one video push and pull; push to the server with the recording URL in a SIP INFO, and pull of that recording with every picture equal to the pushed ones; refusals; remote transmission request and cancel with their Result (MV-PP-01 to MV-PP-06, MV-RT-01 to MV-RT-05) |
| [Emergency and imminent peril](mcvideo/MCVIDEO_EMERGENCY_TEST.md) | Emergency and imminent peril group calls, cancellation, refusal of an unauthorised user, pre-emption of a normal transmission, emergency private call, emergency alert with location and its cancellation (MV-EM-01 to MV-EM-08) |
| [Private call](mcvideo/MCVIDEO_PRIVATE_CALL_TEST.md) | Private calls with and without transmission control, video both ways with checksums equal to the sender's; automatic, manual and forced commencement; decline (480 `110`); refusals `107`, `144`, `127`, `159`; ending by either party (MV-PC-01 to MV-PC-08) |
| [Group call](mcvideo/MCVIDEO_GROUP_CALL_TEST.md) | Prearranged and chat group calls, conference events, the implicit request; transmission control with queueing, rejection, revocation and end of transmission; reception control; H.264 video decoded at every receiver with checksums equal to the sender's; SIP, 15 transmission control messages and RTP on the wire (MV-GC-01 to MV-GC-13) |
| [Video media](mcvideo/MCVIDEO_MEDIA_TEST.md) | H.264 at 240p from OpenH264, RFC 6184 packetization and reassembly with loss handling, the SDP codec check (MV-VM-01 to MV-VM-03) |
| [Service authorisation and affiliation](mcvideo/MCVIDEO_AFFILIATION_TEST.md) | Four clients authorise at `mcvideo-server` by PUBLISH and affiliate after their status subscription, beside MCPTT; 101 for a refused token, 403 for a non-member, a second group, de-affiliation (MV-AF-01 to MV-AF-07) |
| [Shared core](mcvideo/MCVIDEO_SHARED_CORE_TEST.md) | Service profile, per-service warning tables, MCVideo SDP, the media plane control interface and the codec-aware relay, proven by unit tests; the `mcvideo-server` container runs beside the MCPTT server and the SIP core routes the MCVideo PSI to it, with no change to MCPTT behaviour (SC-01 to SC-08) |

## Not covered

What the present edition does not include, and the known limits of what it implements, are in the
[limitations](../docs/LIMITATIONS.md); the status of each MCVideo procedure is in the
[acceptance matrix](../docs/architecture/mcvideo-standards-and-acceptance.md).
