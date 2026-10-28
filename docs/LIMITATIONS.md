# The OpenMCX limitations

What the present standalone edition of OpenMCX does not do, and the limits of what it does. What it supports is in the
[feature list](FEATURES.md). Each item was checked against the code of release 1.0.0.

## Not in present edition

| Area | Status |
|---|---|
| Off-network (ProSe/PC5), relays, isolated operation (IOPS) | Not in present edition: the procedures need direct radio (MCPTT §10.2, §10.3, §11.2; MCData §9.3) |
| Interconnection, MC gateways and migration | Not in present edition |
| Separate participating and controlling servers of different vendors | Not in present edition: the link between the two servers is OpenMCX-specific, a deviation from 3GPP to be fixed. Affiliation passes as one PUBLISH per user, not one per group (TS 24.379 §9.2.2.2.6, §9.2.2.3.3), and relayed requests carry the user's identity instead of the participating server's PSI (§6.3.2.1.3); MCVideo the same (TS 24.281). Because of the per-user PUBLISH, a de-affiliation forbidden by the group document for an activated functional alias (§9.2.2.3.3 step 10 a0) is refused only by a single server. With both servers OpenMCX, the split layout works |
| Interworking with LMR, GSM-R, PSTN and other non-3GPP systems | Not in present edition |
| FRMCS (railway) extensions | Not in present edition |
| MBS and eMBMS delivery | Over pre-activated MBMS bearers emulated on the IP network (no BM-SC, no MB2, no radio): bearer announcement, listening status reports and MBMS subchannel control (TS 24.379 clause 14, TS 24.380 clause 10) for MCPTT and MCVideo group calls with the Linux client, over EPS MBMS bearers and 5G MBS sessions (TS 24.379 clause 14B): floor and transmission control over the subchannel, MSCCK and MuSiK, suspension and de-announcement, group dynamic data. Not covered: MB2/BM-SC or 5G MBSF interfaces, ROHC, FEC, IPv6, split servers, eMBMS/MBS co-existence in one announcement ([tests](../tests/mcptt/MULTICAST_TEST.md)) |
| Pre-established sessions (TS 24.379 clause 8) | Not in present edition: they need resource sharing in the PCRF or PCF, which the cores of the tutorials (Open5GS, OAI) do not offer. A setup request is refused with 403 and warning 100; private calls without floor control are on-demand only |
| QoS through N33 (NEF) and the SIP core as application function | Not in present edition |
| Several devices of one user | Not in present edition: a user is logged in on one device at a time. The service configuration documents set `<max-simultaneous-authorizations>` to 1, a user profile above 1 is refused, and a second client of a logged-on user is answered 486 with warning 164 (MCVideo 166, MCData 228) until the first one logs off or its authorisation ends (TS 24.379 clause 7.3.3 steps 3a and 3b; the second binding of step 5b is what is left out) |
| Group call options | Not in present edition: audio cut-in, multi-talker groups, override with simultaneous talkers, and the acknowledged group call options (TNG1: proceed or convert on timeout, the list of members who did not acknowledge; a call missing required members is abandoned) |
| MCVideo | Not in present edition: more than one transmitter at a time, video conferencing, video modes (urgent, non-urgent, non real time), remote camera control and multiplexing (optional in TS 24.281 §6.2.10), the non-controlling function's own session |
| Discreet listening, MC logging and recording, lawful interception, charging | Not in present edition (the MCVideo server's recording of pushed video is not MC logging) |
| Performance | Not in present edition: access time, mouth-to-ear latency and MOS have not been measured |

## Known limitations

### Security and keys

- **Registration.** The service authorisation by third-party REGISTER (TS 24.379, TS 24.281 and TS 24.282 clause
  7.3.2) is offered by the Linux client only (`mcptt.authorise_by_register`); the Android client authorises by PUBLISH
  (clause 7.3.3). A server that refuses an authorisation by third-party REGISTER cannot tell the client, which got its
  200 (OK) from the SIP core's registrar.
- **Keys.** The MC servers and the GMS fetch their keys with the requests of TS 33.180 annex D.2, with an access token
  of their own (clause 5.3.3). TS 33.180 gives access tokens to MC users only (clause 5.1, annex B) and does not say how
  a server or the GMS obtains one or which identity it names; OpenMCX makes each a confidential OAuth client of the
  IdMS that obtains its token with the client credentials grant (RFC 6749 section 4.4), with its public service
  identity (the GMS URI) as subject. A KMS of another vendor serves them if it accepts such tokens of the IdMS.
- **Profile.** The default lab keeps media and floor protection off; the protected fixtures use an explicitly configured
  E.6 numeric wire profile that has not been qualified against an independent peer.
- **SIP core access.** TS 33.180 clause 6.2.1 requires IMS AKA (TS 33.203) for SIP core access, also with a SIP core
  that is not an IMS, and TS 33.203 annexes N.1 and O.1.1 exclude SIP digest and TLS access security on access networks
  defined by 3GPP. OpenMCX chooses the scheme per private user identity, as the HSS stores it (TS 29.228 clause 6.3.1
  step 4): an identity provisioned for IMS AKA registers through the P-CSCF with a software ISIM (K and OPc of its own,
  MILENAGE, or the test algorithm of TS 34.108 clause 8.1.2 for a conformance test system), the security agreement and
  IPsec ESP security associations in transport mode, SIP over TCP or UDP inside them (UDP: requests of 1300 bytes or
  more over TCP, RFC 3261 section 18.1.1; no SIP outbound over UDP, which would need STUN keepalives); every other
  identity uses SIP digest over TLS. IMS AKA is used by the Linux client inside the UE of [tutorials
  3](../tutorials/end-to-end/03-mcx-over-oai-5g/README.md), [4](../tutorials/end-to-end/04-mcx-over-srsran-5g/README.md)
  (5G) and [5](../tutorials/end-to-end/05-mcx-over-4g-open5gs-oai/README.md) (4G) and by the `aka` and `aka-udp`
  regression labs; the SIP core makes the vectors itself (Kamailio `ims_auth`, no HSS over Cx), offering AKAv2-SHA-256
  and then AKAv1-MD5. Its SQN is kept in memory: after a restart of the SIP core each UE resynchronises once (AUTS). Not
  done yet: emergency registration (TS 24.229 clause 5.1.6); IPv6 (the IMS AKA path is tested on IPv4 only); a complete
  clean-up of the old security associations after a re-registration (TS 33.203 clause 7.4); a lab that exercises a
  resynchronisation (AUTS) over existing security associations, at a re-registration; the discovery of the P-CSCF (TS
  24.229 clause 9.2.1: its address is configured). The MCX Admin activation and the Credential Service issue digest
  credentials only (an identity provisioned for IMS AKA gets none), so the clients that MCX Admin activates keep SIP
  digest over TLS, also where they run on 3GPP access: the dispatcher inside the 5G or 4G UE of tutorials 3, 4 and 5 is
  a deviation from TS 33.180 clause 6.2.1. The Android app would need carrier privileges to run AKA on the phone's SIM.
  On non-3GPP access (Wi-Fi, a control room, the labs) TS 33.180 allows SIP digest with TLS (TS 33.203 annexes N and O;
  ETSI TS 103 765-2 clause 6.1.1 does the same for FRMCS on-board applications), but OpenMCX departs from those annexes
  in three points: the challenge offers MD5 only, without SHA-256, and without qop "auth" (annex N.2.1.1, TS 24.229
  clause 5.4.1.2.1B); the 200 (OK) carries no Authentication-Info for the client to authenticate the network (annex
  N.2.1.1); and the SIP core requests a client certificate, which annex O.2.1 forbids (the client is authenticated by
  digest only).
- **Transport.** SIP of the digest identities uses TLS 1.2 or later with client certificates (see SIP core access), not
  a qualified TS 33.203 Gm profile, and the servers' Diameter uses TLS rather than NDS/IP. The lab's common-service
  configuration shares client credentials between the services and needs further secret isolation for production. Every
  TLS client and server (HTTP, SIP, MSRP, the SIP core and P-CSCF, MCX Admin) follows the TLS profile of TS 33.210
  clause 6.2 that TS 33.180 clause 6.1 refers to: TLS 1.2 and 1.3, TLS 1.2 only with ECDHE and AEAD suites, no finite
  field Diffie-Hellman (include/mcx/tls_profile.hpp; checked by tests/integration/tls_profile_check.py). SIP over TLS of
  the C++ programs offers P-256, P-384 and P-521 but not x25519 (pjproject names no x25519 group). A test system whose
  PIXIT only allows TLS 1.2 RSA, PSK or NULL suites (TS 37.579-5 px_MCX_TLS_CipherSuite) is refused.

### Media and floor control

- **Media addresses.** The servers accept media only from the address and port in a client's SDP and send to them;
  they do not learn the address from the received media, so a client behind NAT is reachable only if the address it
  advertises is.
- **Jitter.** There is no production RTP jitter, loss and reordering scheduler.

### MCPTT

- **Private calls.** The forwarding settings MESSAGE and warning 174 are not implemented;
  forwarding is manual only.
- **Broadcast group calls.** Group-broadcast and user-broadcast hierarchies are a project profile, because TS 24.379
  §4.12 defines no procedure for them.
- **Ad hoc group calls.** End-to-end security is not implemented; the calls are clear (488). The participant lists
  of an ad hoc group emergency alert (the total list and the users who have not acknowledged it, TS 24.379
  §6.3.3.1.24) are not sent.
- **Functional aliases.** Activations do not expire, and the alias-to-alias call policy (warnings 171 and 172) is not
  implemented. On separate participating and controlling servers, a user can follow its own aliases but not the users
  of an alias (TS 24.379 clause 9A.2.2.2.10). The status lists only the aliases being changed, activated or offered for
  take-over: deactivated and refused ones are left out.
- **Temporary groups** formed by the GMS (TS 24.481 6.3.14) are applied as group regroups; merging ongoing calls of the
  constituent groups is not implemented.

### MCData

- **Data streaming.** TS 24.282 defines no procedure for MCData data streaming, so there is nothing to implement yet.
- **Protection.** Ad hoc group communications stay clear, and XML integrity protection (xmlsig) is not implemented for
  MCData (MCPTT signs its XML).
- **Ad hoc priority over the media plane.** An emergency or imminent-peril ad hoc group communication over the media
  plane is refused with 403: TS 23.282 clause 7.17.2.1 names the indicators, but TS 24.282 defines no procedure for
  them (clause 24 and the upgrade clauses 9.2.4.4.5 and 9.2.4.4.6 cover none).
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
  transfer and forwarding, location-based functional alias activation, MCPTT media and XML protection, MCData over
  MSRP, IP connectivity, enhanced status and the message store, and the SIP subscriptions to the CMS and GMS documents
  (it reads them with XCAP).

## Deployment

MCX runs over 5G SA cores with QoS over N5 and over a 4G core with QoS over Rx in tutorials 3 to 6, with a simulated
RAN; it has not been run on a production network. The Helm chart is experimental: tutorial 6 installs it on a one-node
kind cluster; it has not been run on a cluster of several nodes or on OpenShift. It is not an interoperability-certified implementation: it has not yet been tested
against independent implementations.
