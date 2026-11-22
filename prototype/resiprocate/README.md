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

## Not yet covered

- REGISTER with IMS AKA through the lab's Kamailio, and the two transport behaviours of the pjproject patches
  (`dependencies/pjproject`): the fixed TCP client port of a security association (reSIProcate's "symmetric
  connections" mode binds client sockets to the listener's port, which may cover it) and TCP requests pinned to a UDP
  security association.
- TLS, multipart bodies (MIKEY and XML together), SIP over UDP with large requests, shutdown, and load.

## Running it

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace openmcx-dev:0.4 bash -lc '
  dependencies/resiprocate/build.sh /tmp/resiprocate /tmp/resiprocate-build &&
  cmake -S . -B /tmp/build-resip -DCMAKE_PREFIX_PATH=/tmp/resiprocate >/dev/null &&
  cmake --build /tmp/build-resip -j8 --target test_resip_probe && /tmp/build-resip/test_resip_probe'
```

`test_resip_probe --refresh` also waits for the session refresh. `PROBE_LOG=Info` (or `Debug`) shows reSIProcate's
log, `PROBE_TRACE=1` the subscription callbacks.
