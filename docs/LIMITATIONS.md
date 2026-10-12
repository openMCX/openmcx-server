# The OpenMCX limitations

What the standalone edition of OpenMCX does not do, and the limits of what it does. What it supports is in the
[feature list](FEATURES.md). Each item was checked against the code of release 1.0.0.

## Not in this edition

| Area | Status |
|---|---|
| Off-network (ProSe/PC5), relays, isolated operation (IOPS) | Not implemented: the procedures need direct radio, which this edition does not have (MCPTT §10.2, §10.3, §11.2; MCData §9.3) |
| Interconnection, MC gateways and migration | Not in this edition: two MC systems interconnected over MCPTT-3, MCData-3 and MCVideo-3 or through MC gateway servers, group documents, files, location and key management across systems (CSC-16, CSC-22, external KMS), and the migration of users to a partner system (CSC-17). Separate participating and controlling servers within one system are supported |
| Interworking with LMR and other non-3GPP systems | Not in this edition |
| MBS and eMBMS delivery | Not implemented: group media is unicast. Unicast over 5G SA (QoS over N5) and 4G (QoS over Rx) is in tutorials 3 to 5 |
| Pre-established sessions (TS 24.379 clause 8) | Not supported: they need resource sharing in the PCRF or PCF, which the cores of the tutorials (Open5GS, OAI) do not offer. A setup request is refused with 403 and warning 100; private calls without floor control are on-demand only |
| QoS interfaces | The MCPTT and MCVideo servers are the application function over Rx (4G) and N5 (5G); N33 through the NEF and the SIP core as application function are not implemented |
| Several devices of one user | A user is logged in on one device at a time |
| Group call options | Audio cut-in, multi-talker groups, override with simultaneous talkers, and the acknowledged group call options (TNG1: proceed or convert on timeout, the list of members who did not acknowledge; a call missing required members is abandoned) |
| MCVideo | One transmitter at a time; no video conferencing, video modes (urgent, non-urgent, non real time), remote camera control or multiplexing (optional in TS 24.281 §6.2.10); the non-controlling function's own session is not implemented |
| MCData data streaming | Not implemented; TS 24.282 has no procedure for it |
| Discreet listening, MC logging and recording, lawful interception, charging | Not implemented (the MCVideo server's recording of pushed video is not MC logging) |
| Performance | Access time, mouth-to-ear latency and MOS have not been measured |

## Known limitations

### Security and keys

- **Registration.** The service authorisation by third-party REGISTER (TS 24.379 clause 7.3.2) is not supported; the
  clients authorise by PUBLISH (clause 7.3.3).
- **Keys.** The servers and the GMS fetch keys from the KMS over an internal interface, not with the access-token
  request of TS 33.180 annex D.2; a KMS of another vendor would not serve them.
- **Profile.** The default lab keeps media and floor protection off; the protected fixtures use an explicitly configured
  E.6 numeric wire profile that has not been qualified against an independent peer.
- **Transport.** SIP uses mutually authenticated TLS, not a qualified TS 33.203 Gm profile, and the servers' Diameter
  uses TLS rather than NDS/IP. The lab's common-service configuration shares client credentials between the services
  and needs further secret isolation for production.

### Media and floor control

- **Media addresses.** The servers accept media only from the address and port in a client's SDP and send to them;
  they do not learn the address from the received media, so a client behind NAT is reachable only if the address it
  advertises is.
- **Floor Granted duration.** The duration in Floor Granted comes from the server's maximum talk time, while the
  transmission timer T2 runs from the CMS transmit time limit; when the two are configured differently, the client is
  told a duration the server does not apply (TS 24.380 clause 6.3.4.4.2).
- **Re-granted floor.** A queued user granted the floor again gets the full T2, not the time remaining (clause
  6.3.4.4.8).
- **Media without the floor.** It is dropped, but no Floor Revoke with cause #3 is sent (clause 6.3.5.4.6).
- **Jitter.** There is no production RTP jitter, loss and reordering scheduler.

### MCPTT

- **Private calls.** The forwarding settings MESSAGE and warning 174 are not implemented;
  forwarding is manual only.
- **Broadcast group calls.** Group-broadcast and user-broadcast hierarchies are a project profile, because TS 24.379
  §4.12 defines no procedure for them.
- **Ad hoc group calls.** End-to-end security is not implemented; the calls are clear (488).
- **Functional aliases.** Activations do not expire, the status lists the activated aliases and those the user may take
  over, leaving out deactivated and refused ones, and the alias-to-alias call policy (warnings 171 and 172) is not
  implemented.
- **Temporary groups** formed by the GMS (TS 24.481 6.3.14) are applied as group regroups; merging ongoing calls of the
  constituent groups is not implemented.

### MCData

- **Protection.** Ad hoc group communications stay clear, and XML integrity protection (xmlsig) is not implemented for
  MCData (MCPTT signs its XML).
- **Ad hoc priority over the media plane.** An emergency or imminent-peril ad hoc group communication over the media
  plane is refused with 403.
- **File distribution over the media plane.** A finished transfer is not removed from the server's memory; a
  long-running server with many such transfers grows until restarted.
- **Message store.** Implemented from TS 24.282 clause 21 without the OMA NMS and NotificationChannel specifications:
  LongPolling notification channels only, answers in JSON only, no `listFilter` query. SDS and file distribution over
  HTTP are deposited, communications over the media plane are not.

### Documents and location

- **Documents.** The GMS and CMS validate every group and profile document they accept against the full 3GPP and OMA
  schemas, but enforce a documented subset: the `<ruleset>` actions and lists of the user profiles and the group
  elements the services act on.
- **Location.** Positions and radio measurements are simulated. The SEAL location management server (TS 24.545) has
  no CoAP, SIP-based subscription, location-based query or trigger other than the periodic one.

## Clients

- **Linux client** (`mcx-client`). It reads and writes speech as WAV files, with no microphone or speaker interface;
  the Android app and the dispatcher position have one.
- **Android app.** A debug build, run on real phones over Wi-Fi (tutorials 1 and 2), not yet over a 4G or 5G radio.
  Not supported: MCPTT chat calls and the conference subscription, first-to-answer calls, ambient listening, call-back,
  transfer and forwarding, functional aliases, floor queueing, MCPTT media and XML protection, MCData over MSRP, IP
  connectivity, enhanced status and the message store, and the SIP subscriptions to the CMS and GMS documents (it reads
  them with XCAP).

## Deployment

MCX runs over 5G SA cores with QoS over N5 and over a 4G core with QoS over Rx in tutorials 3 to 5, with a simulated
RAN; it has not been run on a production network. The Helm chart is experimental: it renders and validates, and has not
yet been installed on a cluster. It is not an interoperability-certified implementation: it has not yet been tested
against independent implementations.
