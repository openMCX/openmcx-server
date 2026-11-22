# reSIProcate as the SIP stack: prototype

A prototype, not part of any program: does reSIProcate 1.14 (Vovida licence, BSD-style) cover what OpenMCX's SIP
engine (`src/sip/`, today on pjproject, GPL-2.0-or-later) needs, inside one OpenMCX-owned event loop?

`resip_probe.cpp` runs two user agents, alice and bob, on loopback TCP in one process and one epoll poll group
(`resip::FdPollGrp`, given to both `SipStack`s), with an OpenMCX-style UDP media socket registered in the same poll
group. It checks:

| Check | Specification | Result |
|---|---|---|
| INVITE carries Session-Expires | RFC 4028 | ok |
| 183 with RSeq and Require: 100rel, carrying the SDP answer | RFC 3262 sections 3 and 5 | ok |
| PRACK reaches the callee, then 200 (OK) and ACK | RFC 3262, RFC 3261 | ok |
| 200 (OK) carries Session-Expires with a refresher | RFC 4028 section 10 | ok |
| The caller refreshes the session at half the interval (`--refresh`, about 45 s) | RFC 4028 section 10 | ok (UPDATE) |
| SUBSCRIBE, 200, NOTIFY with a body, a second NOTIFY, termination | RFC 6665 | ok |
| The same with the initial NOTIFY reaching the subscriber before its 200 | RFC 6665 section 4.1.2.4 | ok with patch 0001 only |
| A MESSAGE in the dialog with a multipart/mixed body (SDP, MC service XML, binary octets with CRLFs, a near-boundary line, NUL and every octet value), built as `MultipartMixedContents` and written as text: the three parts arrive octet for octet | RFC 3428, RFC 2046 section 5.1 | ok |
| Media packets handled within 1 ms (p99) with SIP and media in one epoll | | ok: median 50 to 100 us, p99 about 0.2 ms |

## Findings

- **One event loop works.** Our sockets join reSIProcate's epoll poll group (`addPollItem`), and each turn of the
  loop is one `epoll_wait` for SIP and media together, then `SipStack::process` (timers) and `DialogUsageManager::process`
  of each user agent. A media packet is handled within about 0.1 ms of being sent (sender in another thread, so
  arrivals are asynchronous to the loop). Today's server loop (`src/server/server.cpp`) waits up to 5 ms in
  `pjsip_endpt_handle_events` before it reads the media sockets: measured on the regression captures, a median of
  2.75 ms and a p99 of 7.4 ms per relayed packet.
- **NOTIFY before the 200 (RFC 6665 section 4.1.2.4): a reSIProcate defect, patched.** DUM 1.14 (and master of
  2026-11-21) answers 481 to a NOTIFY that reaches the subscriber before the 200 to its SUBSCRIBE (`DialogSet::dispatch`
  refuses any NOTIFY with a To tag for which no dialog exists yet), and the notifier then ends the subscription. On TCP
  this happens when the NOTIFY comes on a connection of the notifier's while the 200 comes on the subscriber's: it was
  first seen in a `--refresh` run. The probe forces that order (bob sends the 200 only after alice answered the
  NOTIFY): the unpatched library fails, `dependencies/resiprocate/0001-dum-NOTIFY-before-the-2xx-of-its-SUBSCRIBE.patch`
  lets the NOTIFY create the dialog when its dialog set sent the SUBSCRIBE (or REFER), which DUM's `Dialog` already
  supports. A candidate for upstream.
- **API notes for the port.** reSIProcate parses message contents lazily from the buffer it was given (keep SDP text
  alive with its `SdpContents`). A notifier sets `Subscription-State` itself (`setSubscriptionState(Active)` before
  `accept`; otherwise the NOTIFY carries no usable state and reaches `onUpdateExtension`). With the UAS in "Required"
  mode, DUM sends provisional responses reliably and waits for the PRACK.

## IMS AKA through the lab's P-CSCF, TCP and UDP

`aka_probe.cpp` registers the lab's `sip:aka-probe@mcx.test` subscriber (its own ISIM, provisioned in the HSS)
through the lab's Kamailio P-CSCF (`ims_ipsec_pcscf`), in the TCP and the UDP case of TS 33.203 clause 7.1. The
requests are written as text and sent through reSIProcate's transaction layer; the ISIM, digest, sec-agree
mechanisms and ESP keys are OpenMCX's `include/mcx/ims_aka.hpp`, the SAs its `include/mcx/xfrm.hpp`.
`run-aka-probe.sh ... tcp|udp` builds it, prepares and starts the lab (`udp`: as the regression's `aka-udp` lab),
runs the probe in a container with CAP_NET_ADMIN, and tears the lab down (about 90 s).

| Step | Specification | TCP | UDP |
|---|---|---|---|
| 401 to the unprotected initial REGISTER, AKAv2-SHA-256 challenge, the ISIM accepts it | TS 24.229 clause 5.1.1.2.2, RFC 3310, TS 33.102 clause 6.3.3 | ok | ok |
| A mechanism of the Security-Server (alg null, ealg aes-gcm-us); four SAs installed | TS 33.203 clauses 7.1 and 7.2 | ok | ok |
| 200 to the protected REGISTER, sent from port_uc to port_ps; the 200 on the connection from port_uc (TCP) or to port_us (UDP) | TS 24.229 clause 5.1.1.5.1, TS 33.203 clause 7.1 | ok | ok |
| SUBSCRIBE to the own reg event; its NOTIFY comes to port_us (TCP: on the P-CSCF's connection; UDP: the probe's 200 leaves from port_uc) and is not retransmitted | TS 24.229 clause 5.1.1.3, RFC 3680, TS 33.203 clause 7.1 | ok | ok |
| A MESSAGE of 2,866 bytes goes over TCP from port_uc; its response on that connection | RFC 3261 section 18.1.1, TS 24.229 clause 4.2A | | ok (403 from the lab's core, see below) |
| Reregistration with a new offer: 401, a new set, its REGISTER's 200, the old SAs deleted | TS 24.229 clauses 5.1.1.4 and 5.1.1.5.1, TS 33.203 clause 7.4 | | ok |
| Deregistration over the set in use | TS 24.229 clause 5.1.1.6.2 | ok | ok |
| On the wire (TCP run, capture in the probe's namespace): the protected leg is ESP only | TS 33.203 clause 7.1 | ok: 15 ESP, 0 plaintext | |

Findings:

- **No reSIProcate patch replaces the pjproject patches.**
  - TCP (pjproject `0001-tcp-client-port.patch`): a TCP transport on port_uc in "symmetric connections" mode
    (`RESIP_TRANSPORT_FLAG_SYMMETRIC_CONNECTIONS`) sets up its connections from port_uc; the top Via's sent-by
    chooses it. The Via then names port_uc (pjsip: port_us); Kamailio accepts it (`dependencies/kamailio/0002`).
  - UDP (pjproject `0002-udp-to-tcp.patch` and the engine's `aka_udp_send`): `ProtectedUdpTransport`, a
    `resip::UdpTransport` on port_us that overrides `send`: what the stack sends on it (requests with Via port_us,
    and responses to the P-CSCF's requests) leaves from a socket on port_uc of the set in use, to port_ps; nothing
    without a set. A request of 1300 bytes or more is sent over TCP from port_uc instead (the engine decides from
    its size; reSIProcate does not switch by itself).
- **The next hop is a forced target.** `SipStack::sendTo(message, Tuple)` does not override the target the
  transaction resolves; `SipMessage::setForceTarget` with the P-CSCF's numeric address and port does.
- **What the engine already does, the port must keep:** a REGISTER over the set in use carries a new Security-Client
  offer (else 400, "protected client port already in use"); every request over the set carries Security-Verify and
  Require and Proxy-Require "sec-agree" (else 494).
- The lab's SIP core relays requests between users only through an application server (403 "Route forbidden" to the
  MESSAGE to the own identity), so a large request from the P-CSCF over TCP to port_us in the UDP case is not
  exercised; the TCP case shows the P-CSCF's requests on its connection to port_us.

## SIP over TLS with OpenMCX's TLS profile

`tls_probe.cpp` runs a TLS listener and a TLS client on reSIProcate with the profile of `include/mcx/tls_profile.hpp`
(TS 33.210 clause 6.2), as `src/sip/lifecycle.cpp` sets it on pjsip: `ProfileSecurity` applies TLS 1.2 to 1.3, the
TLS 1.2 ECDHE AEAD suites and the profile's groups to every SSL_CTX the stack creates (its own and, through
`createDomainCtx`, each TLS transport's); the listener requires a client certificate
(`SecurityTypes::Mandatory`). `run-tls-probe.sh` makes test certificates and judges it by the regression's rules
(`tests/integration/tls_profile_check.py`: its refused handshakes, its allowed suites and groups):

| Check | Specification | Result |
|---|---|---|
| A call over TLS with a client certificate gets its 200 | TS 33.180 clause 6.1 | ok |
| The listener accepts the profile's suites and refuses RSA key exchange, ECDHE with CBC, DHE, ffdhe2048 only, TLS 1.1 | TS 33.210 clause 6.2 | ok |
| The listener refuses a client without a certificate | TS 33.180 clause 6.1 | ok |
| The client's ClientHello offers only TLS 1.3 suites, the six TLS 1.2 ECDHE AEAD suites and the SCSV, and the groups X25519, P-256, P-384, P-521 | TS 33.210 clause 6.2 | ok |
| The client refuses a server whose certificate another CA issued | RFC 3261 section 26.2 | ok |

## Not yet covered

- Resynchronisation (AUTS) and refused challenges; shutdown; load (phases 3 and 6 of `PLAN.md`).

## Running it

The loopback probe (no lab needed):

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace openmcx-dev:0.4 bash -lc '
  dependencies/resiprocate/build.sh /tmp/resiprocate /tmp/resiprocate-build &&
  cmake -S . -B /tmp/build-resip -DCMAKE_PREFIX_PATH=/tmp/resiprocate >/dev/null &&
  cmake --build /tmp/build-resip -j8 --target test_resip_probe && /tmp/build-resip/test_resip_probe'
```

`test_resip_probe --refresh` also waits for the session refresh. `PROBE_LOG=Info` (or `Debug`) shows reSIProcate's
log, `PROBE_TRACE=1` the subscription callbacks.

SIP over TLS with the TLS profile, on loopback (about 30 s):

```sh
prototype/resiprocate/run-tls-probe.sh
```

The IMS AKA registration against a lab (server and client images of a tag; about 90 s):

```sh
prototype/resiprocate/run-aka-probe.sh sakke1 openmcx-client:sakke1 tcp
prototype/resiprocate/run-aka-probe.sh sakke1 openmcx-client:sakke1 udp
```
