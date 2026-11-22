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

## IMS AKA registration through the lab's P-CSCF

`aka_probe.cpp` registers the lab's `sip:aka-probe@mcx.test` subscriber (its own ISIM, provisioned in the HSS)
through the lab's Kamailio P-CSCF (`ims_ipsec_pcscf`), TCP case of TS 33.203 clause 7.1. The REGISTERs are written
as text and sent through reSIProcate's transaction layer; the ISIM, digest, sec-agree mechanisms and ESP keys are
OpenMCX's `include/mcx/ims_aka.hpp`, the SAs its `include/mcx/xfrm.hpp`. `run-aka-probe.sh` builds everything,
prepares and starts the lab, runs the probe in a container with CAP_NET_ADMIN, and tears the lab down (about 90 s).

| Check | Specification | Result |
|---|---|---|
| 401 to the unprotected initial REGISTER, with an AKA challenge (AKAv2-SHA-256) | TS 24.229 clause 5.1.1.2.2, RFC 3310 | ok |
| The ISIM accepts RAND and AUTN | TS 33.102 clause 6.3.3 | ok |
| A mechanism of the Security-Server is chosen (alg null, ealg aes-gcm-us) | TS 33.203 clause 7.2 | ok |
| The four SAs are installed | TS 33.203 clause 7.1 | ok |
| 200 to the protected REGISTER, on a TCP connection from port_uc to port_ps; P-Associated-URI and Service-Route | TS 24.229 clause 5.1.1.5.1, TS 33.203 clause 7.1 | ok |
| 200 to the deregistration over the set in use | TS 24.229 clause 5.1.1.6.2 | ok |
| On the wire (capture in the probe's namespace): the protected leg is ESP only, no plaintext SIP on its ports | TS 33.203 clause 7.1 | ok: 15 ESP, 0 plaintext |

Findings:

- **The fixed TCP client port needs no patch.** pjproject needs `dependencies/pjproject/0001-tcp-client-port.patch`
  for the connection from port_uc. In reSIProcate, a TCP transport on port_uc in "symmetric connections" mode
  (`RESIP_TRANSPORT_FLAG_SYMMETRIC_CONNECTIONS`) sets up its connections from port_uc, and the top Via's sent-by
  chooses that transport for a request. The Via then names port_uc, not port_us as with pjsip; Kamailio accepts it
  (`dependencies/kamailio/0002`, any Via port).
- **The next hop is a forced target.** `SipStack::sendTo(message, Tuple)` does not override the target the
  transaction resolves (the Request-URI's domain, here unresolvable: a local 503); `SipMessage::setForceTarget` with
  the P-CSCF's numeric address and port does.
- **A REGISTER over the set in use carries a new offer** (new SPIs and port_uc in its Security-Client), as
  `src/sip/ims_aka.cpp` does: the P-CSCF refuses one that offers the set's port_uc again ("protected client port
  already in use", 400).

## Not yet covered

- The UDP case of TS 33.203 clause 7.1: requests pinned to the set's UDP port_uc, large requests and dialogs whose
  route set names TCP over the TCP connection (`dependencies/pjproject/0002-udp-to-tcp.patch` today).
- Requests of the P-CSCF to port_us (the reg event NOTIFY), re-registration with the switch to the new set and the
  deletion of the old one, the resynchronisation (AUTS) and refused challenges.
- TLS, multipart bodies (MIKEY and XML together), shutdown, and load.

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

The IMS AKA registration against a lab (server and client images of a tag; about 90 s):

```sh
prototype/resiprocate/run-aka-probe.sh sakke1 openmcx-client:sakke1
```
