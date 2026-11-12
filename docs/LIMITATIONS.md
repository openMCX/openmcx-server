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
| Pre-established sessions (TS 24.379 clause 8) | Implemented on a combined server only: not with separate participating and controlling servers. Resource sharing is declared by `mcptt.resource_sharing` (the cores of the tutorials, Open5GS and OAI, offer no PCRF or PCF resource sharing; `none` keeps the 403 with warning 100). Not done: the SIP INFO with a release reason of an ambient listening call over a session (§11.1.6.2.2.4), and MCVideo and MCData over a session |
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
- **KMS request security (TrK/InK).** The KMS and the key management clients use direct HTTPS (TS 33.180 clause 5.3.2,
  where the TrK and InK "may" be used). With a user's pre-provisioned TrK and InK (the Linux client's and the KMS's
  `security.transport_keys`; the Android client's from the `transport_keys` of its provisioning file, moved into the
  Android Keystore at import), KMS requests are signed and the KMS verifies them (annex D.2.2; the time window is the
  KMS's `security.kms_request_window_seconds`, which the clause leaves to the KMS), and KMS responses are signed and
  their key set wrapped under the TrK (annexes D.3.1 and D.3.3.2); the InK signs, else the TrK. Where the texts leave
  details open (reported):
  - the Signature-ID and TrK-ID elements are not sent and, when received, not read: annexes D.2.2 and D.3.1 say
    Signature-ID "shall be present" when a signature is applied (TrK-ID when confidentiality is required), but annex
    D.3.5.3 types them xsd:string and no clause gives their text form; the signing key is named by the KeyName (the
    base64 XPK-ID, clause 9.3.5);
  - the 257-octet SAKKE RSK and the 65-octet ECCSI PVT do not meet the input length of the AES-256 key wrap of
    RFC 3394 (clause 9.3, which says it "shall be supported"), and the text does not say which other wrap a KMS uses:
    the padding of the ETSI test suite for TS 37.579 is used (n - 1 zero octets and one octet n before RFC 3394), as
    that test system's reading, not a 3GPP rule;
  - the References of signed KMS messages point to the schema's Id attribute, which annex D.3.5.1 types xsd:string
    rather than xsd:ID: it is resolved as an ID, as the ETSI test suite does (that test system's reading);
  - AES-128-GCM "shall be supported" for an encrypted KmsResponse (annex D.3.1) under the 256-bit TrK, and the text
    does not say which 128-bit key it uses: not implemented, such a response is refused;
  - a Time without a time zone (xsd:dateTime allows it; the annex D examples use it) is refused: it names no instant
    and the text does not say which zone it is in;
  - the KMS URI the KMS's documents carry (clause 3.1, a security domain identifier) and the address the KMS is
    contacted at (TS 24.484 clause 7.2.2.7 `<kms>`) can differ, and no configuration item gives the first: the Linux
    and Android clients' `security.kms_id`, by default the address;
- **MIKEY-SAKKE UID form** (spec defect, reported). TS 33.180 annex F.2.1.1 says "The full 256-bit output shall be
  used as the identifier within MIKEY-SAKKE (referred to as 'ID' in IETF RFC 6507 [9] and 'a' or 'b' within IETF
  RFC 6508 [10]. The resulting UID shall be base64 encoded." It does not say whether ECCSI (RFC 6507) and SAKKE
  (RFC 6508) take the 32 octets of the SHA-256 output or their base64 text. The KMS, the MC servers and the clients
  use the base64 text, as the KMS key set's UserID carries it (annex D.3.3.2); the ETSI test suite for TS 37.579 uses
  the 32 octets. The KMS, the MC servers and the GMS therefore do not interwork with a KMS or peer that uses the 32
  octets. The Linux and Android clients find the form at key provisioning: they validate the key set (RFC 6507 clause
  5.1.2, RFC 6508 clause 6.1.2) for the 32 octets first, then for the text, and use the form that validates for every
  ECCSI and SAKKE operation under that KMS (the ETSI test suite's reading where the KMS's keys are for the 32 octets,
  not a 3GPP rule; the Linux client's status file shows it as `key_management.uid_form`).
- **Home HTTP proxy** (TS 24.482 annex A.2.1.2). With `<http-proxy>` configured, the Linux and Android clients send
  their HTTP requests over a TLS tunnel to the proxy in absolute-form, the IdMS's directly. Not implemented, as the
  texts leave them open (reported): mutual TLS tunnel authentication with a certificate (TS 24.484 clause 7.2.2.7 g)
  gives the `<x509>` certificate but no private key) or with a pre-shared key (no PSK identity); a configuration that
  asks for either is refused. The KMS requests stay direct: TS 24.482 A.2.1.2 sends every request but the IdMS's
  through the proxy, TS 33.180 clause 5.3.2 lets the KMS be used without it, and no configuration item tells the UE
  which applies (reported). The Linux and Android clients' `security.kms_via_proxy` (off by default) sends them through the proxy,
  as the ETSI test system for TS 37.579 expects (that test system's reading, not a 3GPP rule), and then requires a
  TrK for each MC service user (clause 5.3.2: "for public safety users the TrK shall be used"). The MC servers and the GMS reach the other servers directly, not through the proxy with
  X-3GPP-Asserted-Identity (TS 24.482 annex A.2.1.3).
- **CSK key download** (TS 24.379 and TS 24.281 clauses 7.3.7 and 7.2.5, TS 33.180 clauses 5.8 and 9.2.1.4). The
  MCPTT and MCVideo servers send it only on the operator command `csk-download <MC service ID>` (the specifications
  give no renewal period); the MCData server does not send it, because TS 24.282 clause 7.3.7 step 5 requires the
  MCData signalling algorithm in the MIKEY message and no specification defines where or how it is coded (spec
  defect, reported). The Linux client accepts it for all three services, but not with identity hiding (an IDRi of
  type UID, clause 7.2.5 step 1 b)), and keeps DP_AES_128_GCM for MCData signalling (step 1 f), same defect). The
  Android client does not accept it.
- **XML content under an unknown XPK-ID** (spec defects, reported). A received SIP request whose signatures or
  encrypted XML elements name an XPK-ID (ds:KeyName) the receiver does not hold is refused with 403 and warning 139 or
  140 by the MC servers and the Linux and Android clients: the XPK of TS 24.379 clause 6.6.3.4.2 step 4 cannot be
  obtained, so the signature validation fails (step 5), and the decryption of clause 6.6.2.4.2 fails (step 3), although
  neither clause names the case (TS 24.281 and TS 24.282 the same). Where the texts give no outcome, today's behaviour
  is kept: in a SIP response (the only failure action, a 403, cannot answer a response; this holds for every
  verification or decryption failure in a response) the signatures under an unknown XPK-ID are not verified and the
  content stays encrypted; encrypted URI attributes (clause 6.6.2.4.3 has no failure step, no clause of 6.6.1.4 calls
  it, and its step 1 writes the parameter as ";=key-id") are left as received; a body without a ds:KeyName, whose key
  TS 33.180 clauses 9.3.4.2 and 9.3.5 leave "known ... through other means", is handled as before.
- **Profile.** The default lab keeps media and floor protection off; the protected fixtures use an explicitly configured
  E.6 numeric wire profile that has not been qualified against an independent peer. TS 33.180 assigns no code to
  DP_AES_128_GCM or DP_AES_256_GCM (table 8.5.4.1-1, spec defect, reported): DP_AES_256_GCM, which OpenMCX accepts for
  MCData signalling under the CSK (annex F.1.5), is recognised only when the profile names its code
  (`key_parameter_profile.algorithm_256`), and OpenMCX sends DP_AES_128_GCM (the default of NOTE 6).
- **SSRCs under shared keys.** Each endpoint keeps the history of RFC 7714 section 8.4: an SSRC it issued, or one it
  holds a stream for under its keys, is not given out again. The MC client and the MC server both protect SRTCP under
  the client's CSK. The SSRC the other side allocates for an endpoint's floor or transmission control messages (TS
  24.380 and TS 24.581 clause 4.3.3.1) is refused for a new stream when it is the endpoint's own or one already used
  under the key for another stream (an offer with 488 before the request changes anything, an answer by ending the
  dialog); a call going on keeps its SSRC, and a re-INVITE changing it is refused with 488. An endpoint does not give
  out an SSRC the other side has allocated for a call under way, even before its first packet. TS 33.180 gives no
  SSRC partition between client and server (RFC 7714 sections 8.4 and 9.4 ask that no SSRC
  repeats under one key), so two allocations made at the same time by the two sides cannot be kept apart; a
  coordinated allocation between the two is not designed yet (open, not a proved spec defect).
- **Key expiry and CSK renewal.** A key past its Expiry time (TS 33.180 annex E.6.10, "shall no longer be used") is
  neither used to protect nor to unprotect: media and floor control packets under it are not sent or are dropped, and
  XML or MCData signalling under an expired CSK is refused, never sent in clear; where the MCData server's answer to a
  request would need the expired CSK, the SIP engine's local error handling answers 500 (no response is specified)
  and no XML goes out. Call handling is unchanged: a private
  call whose PCK expires stays up without media; what a call should do then is not defined by the specifications
  (reported). The renewal of a CSK before its Expiry time, the end of the identity key period, is not implemented
  yet: TS 33.180 clauses 9.2.1.2 and 9.2.1.4 define it (the MC server's key download, sent by OpenMCX on the operator
  command `csk-download` only), and the Linux client's service authorisation PUBLISH carries the CSK only the first
  time (TS 24.379 clause 7.2.2 item 3 asks for it in each). Until then a client with XML protection loses its service
  authorisation at the next token renewal after the end of its identity key period.
- **MCData between servers.** The MCData server has no XML protection towards other MCData servers
  (`<protection-between-mcdata-servers>` is read but not applied).
- **CRLs.** Certificates are checked against the CRLs of the configured file (`tls.crl_file`) only; CRLs are not
  retrieved from the distribution point a certificate names (TS 33.310 clauses 6.1a and 7.1, to be implemented; its
  fetch timeout, maximum size and cache bound are not chosen yet).
- **Push and pull of video (protected).** The PCK of an MCVideo push or pull is encrypted to the MCVideo server's PSI:
  TS 33.180 clauses 7.2.7.2 and 7.2.8.2 name "the identity of the MCVideo server" without defining it (reported).
- **GMKs of other groups (Linux client).** The client holds the GMKs of its selected group, its monitored groups and the
  preconfigured groups of the regroups it was told of (TS 33.180 clauses 7.3.11 and 7.3.12), and keys each call with
  its group's GMK. Not done yet: a protected broadcast hierarchy call on a broadcast group that is none of these (TS
  33.180 clauses 7.3.4 and 7.3.5, the broadcast group's own GMK) is refused with 488, as the client learns of the
  broadcast group only from the call; the MCVideo part of the client keys its calls with its selected group's GMK only.
- **SIP core access.** TS 33.180 clause 6.2.1 requires IMS AKA (TS 33.203) for SIP core access, also with a SIP core
  that is not an IMS, and TS 33.203 annexes N.1 and O.1.1 exclude SIP digest and TLS access security on access networks
  defined by 3GPP. OpenMCX chooses the scheme per private user identity, as the HSS stores it (TS 29.228 clause 6.3.1
  step 4): an identity provisioned for IMS AKA registers through the P-CSCF with a software ISIM (K and OPc of its own,
  MILENAGE, or the test algorithm of TS 34.108 clause 8.1.2 for a conformance test system; see below), the security agreement and
  IPsec ESP security associations in transport mode, SIP over TCP or UDP inside them (UDP: requests of 1300 bytes or
  more over TCP, RFC 3261 section 18.1.1; no SIP outbound over UDP, which would need STUN keepalives); every other
  identity uses SIP digest over TLS. IMS AKA is used by the Linux client inside the UE of [tutorials
  8](../tutorials/end-to-end/08-ims-aka-over-oai-5g/README.md), 4,
  [5](../tutorials/end-to-end/05-mcx-over-srsran-5g/README.md) (5G, with the compose profile `ims-aka`) and
  [6](../tutorials/end-to-end/06-mcx-over-4g-open5gs-oai/README.md) (4G) and by the `aka` and `aka-udp`
  regression labs; the SIP core makes the vectors itself (Kamailio `ims_auth`, no HSS over Cx), offering AKAv2-SHA-256
  and then AKAv1-MD5. The UE and the P-CSCF offer and select the integrity and encryption algorithms of TS 33.203
  annexes H and I (AES-GCM, AES-GMAC, HMAC-SHA-256-128, HMAC-SHA-1-96, AES-CBC, NULL). After a re-registration
  the P-CSCF keeps sending over the old set until the UE's first message over the new one, and both ends delete the
  old set once its pending transactions are over; the new set of a failed authentication goes likewise (clause 7.4).
  A new challenge deletes the earlier incomplete registration SAs of the same UE, and a temporary set ends after
  reg-await-auth (clause 7.4.2a, TS 24.229 clause 5.2.2.2). The P-CSCF refuses a REGISTER that starts an
  authentication (400, over the set it came on) while three sets of its IMPI, six SAs per direction, would stay over
  all its contacts (clause 7.1 rule 3), counted and reserved in one step. Every refusal of a request received over a
  set goes back over that set, over UDP from port_pc to the UE's port_us (clause 7.1). The SIP core keeps the
  registrations and its SQN in memory and has no S-CSCF restoration: after its restart it answers each UE's next
  reregistration with 500 (TS 24.229 clause 5.4.1.2.3A), the UE registers anew (clause 5.1.1.4.1: initial
  registration after a 403, 408, 500 or 504 to a reregistration) and resynchronises once (AUTS). An AUTS over the set
  in use (a stale SQN at a reregistration the core still knows) cannot occur with this SIP core and is not tested. Not done yet: the P-CSCF's early switch to the new set when "the old
  SAs have only a short time left before expiring" (clause 7.4.2a, open implementation point: the text gives no value
  for it; the P-CSCF switches at the UE's next message over the new set or at the old set's expiry); emergency
  registration (TS 24.229 clause 5.1.6); IPv6 (the IMS AKA path is tested on IPv4 only); the discovery of the P-CSCF (TS 24.229 clause 9.2.1: its
  address is configured). The Credential Service issues digest credentials only (an identity provisioned for IMS AKA
  gets none), so the dispatcher inside the 5G or 4G UE of tutorials 3, 5 and 6 keeps SIP digest over TLS on 3GPP
  access: a deviation from TS 33.180 clause 6.2.1. The MCX Admin activation can offer IMS AKA to the Android app
  (`activation.ims_aka.pcscf`, the P-CSCF it registers through). The app registers with IMS AKA when the phone's card
  gives it carrier privileges, the card's ISIM holds its identities and the activation offers IMS AKA, on Wi-Fi as on
  mobile data: the AKA runs on the card, the security associations are the platform's (Android IpSecManager, one per
  socket). Without such a card it uses SIP digest over TLS on Wi-Fi and does not register on mobile data; it never
  falls back to digest after an IMS AKA failure (TS 33.203 clause O.1.1 NOTE 2). The card's public user identity is
  barred and its registration binds the MC user's identity, the default one of the subscription's implicit set (TS
  23.228 clauses 4.3.3.3 and 4.3.3.4); `tools/load-card-keys.py` puts the card's subscription and keys into the SIP
  core's database from an owner-only key file. Own deviation: Android's IPsec API (up to API level 37) has no
  AES-GMAC, which TS 33.210 clause 5.3.4 says "shall be supported" for the ESP profile of TS 33.203 annex H; the app
  offers the other algorithm pairs, the P-CSCF selects among them. Checked on one Android 16 phone with a
  sysmoISIM-SJA5 card over Wi-Fi (registration, reregistration on a new set after a network-initiated
  re-authentication, private call, SDS, MC log-off, de-REGISTER), not yet over a 4G or 5G radio. The carrier-privilege
  rule on that card (ARA-M) names the debug build's signing certificate: for the lab only; a release needs the
  operator's rule for the release certificate.
  The Linux client is a research and test client, not a client for operational use. It uses SIP digest over TLS for
  identities provisioned with a digest password, on non-3GPP access (the regression labs, tutorials 1 and 2, the
  unit-test tutorials), and IMS AKA for identities provisioned with an IMS AKA subscription, with its credentials held
  in software. On a terminal without 3GPP access (the `aka` labs,
  [tutorial 10](../tutorials/end-to-end/10-openmcx-ue-conformance-check/README.md), a PC, a VPN to a test system) and on a device behind
  an MC gateway UE that routes for it (TS 23.280 clause 11, TS 33.180 clause 5.12.1), these are the IM credentials that
  TS 33.180 clause 6.2.1 allows for "non-3GPP-only MC UEs not equipped with UICC" (TS 33.203 clause 9, TS 24.229
  clause 5.1.1.1B.1). **For testing and debugging only**, the client also runs inside the emulated UEs of tutorials 4,
  5, 6 and 8, which emulate their own USIM in software: there its software credentials are a deviation from TS 33.203
  clauses 4 ("IMS authentication keys and functions at the user side shall be stored on a UICC") and 9 ("The IMC
  shall not used if ISIM or USIM is present"), a deviation of these test beds, never a configuration for operational
  use.
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

- **Reg event package** (RFC 3680; TS 24.229 clauses 5.1.1.3, 5.2.3 and 5.4.2.1) is served by the SIP core to the
  Linux client, the Android app and the P-CSCF; the operator starts a network-initiated deregistration or
  re-authentication (shortened registration, TS 33.203 clauses 5.1.2 and 6.1.4) with the commands in USAGE.md. Own
  deviations not fixed yet: the Linux client keeps its TLS session after a
  deregistration by the network over SIP digest (clause 5.1.1.7: "the UE shall delete all security associations or
  TLS sessions towards the P-CSCF"; over IMS AKA the security associations go); the P-Charging-Vector (charging
  correlation, TS 32.260) is carried only in the P-CSCF's reg event dialog (clauses 5.2.3, 5.2.4, 5.2.5.2, 5.4.2.1.1
  and 5.4.2.1.2): the P-CSCF's REGISTER (clause 5.2.2.1 item 3) and the other requests and responses of the P-CSCF
  and the SIP core carry none, so neither do the UEs' own reg event dialogs; reginfo.shorten marks every contact of the address-of-record "shortened"
  (clause 5.4.1.6 NOTE 2: only the contacts "originally registered by this UE"; the labs and tutorials have one
  contact per user).
- **sec-agree option-tag in Proxy-Require** (spec defect, to report). After the security agreement the Linux client
  sends Security-Verify and `Require: sec-agree` in every request (RFC 3329 section 2.3.1) but ACK and CANCEL (RFC 3329
  table 1, TS 24.229 tables A.7 and A.23, RFC 3261 sections 8.2.2.3 and 9.1) and PRACK, and `Proxy-Require: sec-agree`
  in INVITE and OPTIONS only: for the other methods TS 24.229 annex A gives Proxy-Require "n/a" for the UE, against
  the RFC 3329 MUST it imports, with no text for the weaker status (clause A.1.1); for PRACK RFC 3329 contradicts itself
  (section 2.3.1 "all the subsequent SIP requests", table 1 "-") and TS 24.229 table A.91 has no Security-Verify. The P-CSCF removes the sec-agree option-tags and Security-Verify before the
  SIP core (TS 24.229 annex A, proxy role: Security-Verify "x"). Own deviation not fixed yet: the P-CSCF checks
  Security-Verify only in a REGISTER, not in the later requests (RFC 3329 section 2.3.1: "The server MUST check that
  the security mechanisms listed in the Security-Verify header field of incoming requests correspond to its static
  list"; 494 otherwise).
- **P-Access-Network-Info** (TS 24.229 clauses 5.1.1.2.1 h) and 5.1.2A.1.1, "if available to the UE (as defined in the
  access technology specific annexes)"). The clients never send it: on 5GS and EPS (annexes U and L, "The UE shall
  always include the P-Access-Network-Info header field where indicated") it needs the serving cell, which the Linux
  client inside the UE of the tutorials cannot read from the modem (own deviation, tutorials 4, 5, 6 and 8); no
  annex defines it for plain IP or a VPN. For a test system, `sip.access_network_info` (off by default) gives the
  value the Linux client inserts in every request but CANCEL and ACK and every response but those to CANCEL, the
  initial REGISTER included as the ETSI test suite for TS 37.579 expects (its reading; TS 24.229 asks for it there
  only with a security association or TLS session).
- **Media feature tags of RFC 3840** (spec gaps, reported). TS 24.229 clauses 5.1.1.2.1 c), 5.1.3.1 and 5.1.4.1:
  "The UE shall include the media feature tags defined in RFC 3840 [62] and RFC 5688 [120] for all supported streaming
  media types" in the REGISTER Contact, the initial INVITE and the responses to it. RFC 3840 section 10 ties each tag
  to an SDP media type, so the Linux and Android clients send `audio`, `application` (the floor control,
  transmission control and IP connectivity streams are `m=application`) and, with MCVideo, `video`. Left open by the
  texts: MCData's MSRP stream (`m=message`) has its tag `+sip.message` in RFC 4569, which TS 24.229 does not cite, so
  it is not sent; and whether RFC 5688's `sip.app-subtype` applies to the `m=application ... udp MCPTT` and `MCVideo`
  formats, for which TS 24.380 clause 12.1.1 and TS 24.581 register no media type: it is not sent.

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
- **Implicit floor request.** The MCPTT server accepts it in the answer to an initial INVITE that initiates a call
  (TS 24.380 clause 14.3.5) and grants the floor with Floor Granted; it never grants by `mc_granted` in the 200 (OK),
  which is optional (clause 14.3.4). Not done yet: the implicit floor request of an upgrade to an emergency or imminent
  peril call by re-INVITE (TS 24.379 clause 6.4, TS 24.380 clauses 6.3.4.3.6 and 6.3.4.4.12), which is handled as a
  request without it; the 'G: Initialising' state of a temporary group session (TS 24.380 clause 6.3.4.8), so the
  initiator of a call on a temporary group is granted as in any other call; the location body the Linux client is to
  send with an implicit floor request when `<allow-location-info-when-talking>` is set (TS 24.379 clause 10.1.1.2.1.1
  step 16a); the Android client offers no implicit floor request.

### MCData

- **Data streaming.** TS 24.282 defines no procedure for MCData data streaming, so there is nothing to implement yet.
- **Protection.** Ad hoc group communications stay clear.
- **Protected files.** A protected file carries a length prefix before its protected payload: TS 33.180 clause 8.5.1
  and TS 24.282 clause 10.2.2.1 define no framing for it (reported), so another implementation may frame it otherwise.
- **Protected SDS or file to a functional alias.** The first protected SDS or file to a functional alias that is not
  yet resolved to an MCData ID is refused locally: no PCK target exists before the resolution (reported); sending it in
  clear would break the protection rule.
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
- **Service configuration at the servers.** The MC servers read their service configuration document (the
  Resource-Priority values and the XML signalling protection of `<signalling-protection>` and
  `<protection-between-*-servers>`) from the CMS's internal view, not by subscribing to it and retrieving it as TS
  24.484 clauses 6.3.x specify for an MC server. A deviation, to be fixed.
- **CMS subscription proxy PSI** (spec gap). TS 24.484 clause 6.3.13.2.2 step b) 2) sends the configuration management
  SUBSCRIBE to "the configured public service identity for performing subscription proxy function of the CMS", but no
  configuration item for that PSI is defined (TS 24.483 has no CMS counterpart of GMSURI; `<cms>` of TS 24.484 clause
  7.2.2.7 is "the URI used to contact the configuration management server"). The Linux and Android clients send it to
  the MCPTT PSI until the specification names the item, or to the PSI configured (Linux `cms.subscription_psi`,
  Android `mcptt.cms_subscription_psi`), as the ETSI test
  system for TS 37.579 names such a PSI (that test system's reading, not a 3GPP rule). The group document and group key subscriptions go to the configured
  GMS-URI (`gms.subscription_psi`).
- **Location.** Positions and radio measurements are simulated. The SEAL location management server (TS 24.545) has
  no CoAP, SIP-based subscription, location-based query or trigger other than the periodic one.

## Clients

- **Linux client** (`mcx-client`). It reads and writes speech as WAV files, with no microphone or speaker interface;
  the Android app and the dispatcher position have one.
- **Android app.** A debug build, run on real phones over Wi-Fi (tutorials 1 and 2), not yet over a 4G or 5G radio.
  Not supported: MCPTT chat calls and the conference subscription, first-to-answer calls, ambient listening, call-back,
  transfer and forwarding, location-based functional alias activation, protected media in ad hoc group calls,
  MCData over MSRP, IP connectivity, enhanced status and the message store. Supported, as in the Linux client: MCPTT
  and MCVideo media and transmission control protection (PCK, GMK, CSK), XML signalling protection (confidentiality
  and integrity under the CSK of each service, enabled by the service configuration document; an absent element
  enables it), and MCData signalling and payload protection (PCK one-to-one, GMK group, one-to-one files, signed
  payloads). The app does not start a service whose service configuration document it could not read, or that
  requires protection without a configured KMS, and shows why. At activation the app, as the Linux client, takes its
  KMS from the `<kms>` of MCX Admin's UE initial configuration (TS 24.484 clause 7.2.2.1); whether it protects MCPTT
  media and transmission control stays a setting of its provisioning, as for the Linux client.

## Deployment

MCX runs over 5G SA cores with QoS over N5 and over a 4G core with QoS over Rx in tutorials 3 to 7, with a simulated
RAN; it has not been run on a production network. The Helm chart is experimental: tutorial 7 installs it on a one-node
kind cluster; it has not been run on a cluster of several nodes or on OpenShift. It is not an interoperability-certified implementation: it has not yet been tested
against independent implementations.
