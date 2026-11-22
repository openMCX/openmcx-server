# Migrating the SIP engine from pjproject to reSIProcate

Why: pjproject is GPL-2.0-or-later and statically linked into every OpenMCX program (the MCPTT, MCVideo and MCData
servers, mcx-keytool, the Linux client and the dispatcher), which blocks selling OpenMCX under a commercial licence.
reSIProcate is under the Vovida licence (BSD-style). The prototype (`README.md` here) showed that it covers what the
engine needs.

## What changes

The SIP engine's interface, `include/mcx/sip.hpp`, stays as it is: about 30 operations (register, request and
respond, INVITE, answer, re-INVITE, UPDATE, BYE, subscribe, notify, refer, publish, poll) on plain strings and
structs, with no pjproject types. Behind it, about 5,800 lines in `src/sip/` and `src/media/ice.cpp` use pjproject.
The servers and the Linux client use only the header (the client compiles the same engine). Not affected: the Android
app (its own Kotlin SIP), Kamailio (a separate program).

## Strategy

A second implementation of `sip.hpp` on reSIProcate, chosen at build time (`MCX_SIP_STACK=pjsip|resip`). Both build
and pass the same tests until the switch: every step is compared against the current engine, and either can be
rolled back until pjproject is removed.

## Phases

| # | Phase | Work | Done when | Estimate |
|---|---|---|---|---|
| 0 | Prototype (done) | One event loop, 100rel, session timers, subscriptions, IMS AKA over TCP; reSIProcate patch 0001 (NOTIFY before its 200) | Probes pass on loopback and against the AKA lab | done |
| 1 | Remaining risks | IMS AKA over UDP (send from port_uc, Via port_us, requests of 1300 bytes or more over TCP); requests of the P-CSCF to port_us with responses from port_uc; re-registration with the switch to the new set of SAs; TLS with OpenMCX's cipher profile; multipart bodies (MIKEY and XML) | Probes pass in the `aka-udp` and `tls_profile_check` labs | 1 to 2 weeks |
| 2 | Foundations | reSIProcate in `docker/Dockerfile.dev` (`dependencies/resiprocate/build.sh` with its patches); the CMake switch | The development image builds both | 1 week |
| 3a | Engine core | start, stop, poll; UDP, TCP and TLS transports; requests and responses outside dialogs; message and body conversion; the body protection filters; deferred responses | The core cases of `test_sip` pass with `resip` | 1 to 2 weeks |
| 3b | Registration | Digest; the port of `src/sip/ims_aka.cpp` (about 1,200 lines: only its pjsip transport hooks change) | `test_ims_aka_sip`, the `aka` and `aka-udp` labs pass | 1 to 2 weeks |
| 3c | Dialogs | INVITE as caller and callee, answer, re-INVITE and UPDATE, 100rel, session timers, BYE, `dialog_identifiers` | The call scenarios pass | 1 to 2 weeks |
| 3d | Subscriptions and the rest | subscribe, notify, `subscription_count`, refer, publish | All C++ tests pass on both | 1 week |
| 4 | One event loop | The engine takes media and floor control sockets into its epoll; the server and client loops drop the 5 ms SIP poll | Wire captures show relay delay near 0.1 ms (today a median of 2.75 ms) | 1 week |
| 5 | ICE without pjnath | OpenMCX's own ICE agent: host candidates, STUN binding checks, nomination | `test_ice`, `test_ice_sdp` and the pre-established session labs pass | 1 to 2 weeks |
| 6 | Verification | The full IP regression (no RAN labs) over TCP and TLS on both; the MCPTT, MCData and MCVideo conformance suites; a client on one and a server on the other; a soak run; call setup time and CPU | No new failures compared with pjproject | 2 weeks |
| 7 | Switch and remove | `resip` the default; pjproject removed from the development images, `dependencies/lock.json`, `dependencies/pjproject` and the NOTICE files of both repositories; the binaries checked for pjsip symbols; the licence scan repeated | No GPL code linked into any OpenMCX program | 1 week |

In all, about 11 to 15 weeks, mostly phases 3 and 6.

## Decisions

1. **Which reSIProcate layer** (decided 2026-11-22, at phase 3c): the transaction layer only, with the engine's own
   dialog layer (`src/sip_resip/dialogs.cpp`), not DUM. The engine's API needs per-request header fields and
   handlers on INFO, MESSAGE and BYE, UPDATE offers in a confirmed dialog, provisional answers to deferred
   re-INVITEs, a Contact per answer and pinned route sets; under DUM each would be a rewrite of messages DUM built.
   Requests are written as text as the rest of the engine's are, so the outgoing protection and the IMS AKA hop
   apply to every one. DUM is no longer linked by the engine (the prototype's probe still uses it).
2. **Patch 0001 stays OpenMCX's** (decided 2026-11-22: not proposed upstream). reSIProcate is kept in OpenMCX's fork
   (github.com/openMCX/resiprocate, decided 2026-11-22): the release with OpenMCX's commits on `openmcx-1.14`, pinned by
   tag (`dependencies/resiprocate/README.md`); a new upstream release gets a new branch with the commits cherry-picked. With decision 1 it only matters to the prototype's DUM probe; it can go
   once the engine's subscriptions (phase 3d) replace that probe's coverage.
3. **The event loop (phase 4) within this project**: the main performance gain, but it changes the server and client
   main loops, so it is verified in the same pass.

## Risks

- DUM answers some requests by itself (the prototype found its 481 to a NOTIFY before the 200); the conformance
  suites are what finds the others.
- One main maintainer upstream (217 of 299 commits in the last year); the licence lets OpenMCX carry fixes itself.
- IMS AKA over UDP is the last transport behaviour without a known reSIProcate equivalent: phase 1 takes it first.

## Progress

- Phase 0: done (`README.md`; commits `d80f9ea`, `12f08f6`).
- Phase 2, in part: reSIProcate in `docker/Dockerfile.dev` (`/opt/resiprocate`, with its licence) and in
  `dependencies/lock.json` as an image dependency; the `MCX_SIP_STACK` switch (`pjsip` by default; `resip` stops until
  phase 3a); the prototype builds and its loopback probe runs in the development image's ctest (58 tests). Done.
- Phase 1, in part: IMS AKA over UDP and TCP against the lab (registration, a request of the P-CSCF to port_us,
  a large request over TCP, reregistration with the switch to the new set, deregistration); no reSIProcate patch
  needed for either pjproject patch (`README.md`).
- Phase 1: done. Also SIP over TLS with the TLS profile, judged by the regression's TLS checks, and multipart
  bodies octet for octet (`README.md`).
- Phase 3a, step 1: the stack-independent helpers (configuration checks, identities, Contact and service tags, SDP
  origin, header lookup) moved to `src/sip_common`, shared by both engines (`daa4f6a`).
- Phase 3a, step 2: the engine core on reSIProcate in `src/sip_resip` (built with `-DMCX_SIP_STACK=resip`): the stack
  in one epoll poll group driven from `SipEngine::poll`, TLS with the TLS profile and a client certificate required,
  or debug TCP; requests outside dialogs with the core Route, written as text as the pjproject engine's are and sent
  on the transaction layer (no DUM yet); received requests and responses as `SipMessage` and `SipResponse` with their
  parts; both body filters, on the next hop's or the source's address; deferred responses; 420 before the application
  for an unknown required extension; the later phases' operations throw naming their phase. `test_sip`'s self-loop
  test is split: its dialog half (SUBSCRIBE 482, INVITE collision, failed answer) is left out with `MCX_SIP_RESIP`,
  and `sip_tls` runs the self-loop only (`run_sip_tls.py ... core`). Results: `resip` 57 of 57 (no `sip_tcp`, whose
  runner has only two-process roles), `pjsip` 58 of 58.
  Left for later phases, found while writing it:
  - digest authentication of requests outside dialogs (a 401 or 407 retry) goes with registration in phase 3b;
  - the body filters are not run by any test on `resip` yet (the self-loop sets none): the server suites of phase 5
    are the first; a test of their own belongs in 3b;
  - the Via sent-by names the listen address for reSIProcate's transport choice and is rewritten to the advertised
    address once the transport is chosen (a message decorator): to check with a wildcard listen address in 3b;
  - reSIProcate logs a missing `$HOME/.sipCerts` at error level on every start (ctest sets `HOME` to the build
    directory); the log mapping of phase 6 should drop it.
- Phase 3b: registration on reSIProcate.
  - Digest (`src/sip_resip/requests.cpp`): REGISTER with the registration's Call-ID and rising CSeq through the core,
    the refresh 600 s before expiry or half way (TS 24.229 clause 5.1.1.4.1), Expires 0 to remove it, the TLS
    connection closed 2 s after `registration_ended`; every request outside a dialog answered 401 or 407 is retried
    once with credentials (reSIProcate's `Helper::addAuthorization`, CSeq incremented). New two-process test: the
    `register-digest` role against a raw registrar in `run_sip_tls.py` (401 on REGISTER, refresh after 2 s of a 4 s
    grant, 407 on a MESSAGE, removal), passing on both engines over TLS and TCP.
  - IMS AKA (`src/sip_resip/ims_aka.cpp`, the port of `src/sip/ims_aka.cpp`, same procedure and timers): the receive
    filter of TS 33.203 clause 7.1 rules 4 and 7 is in the transports, before the transaction layer
    (`aka_transports.hpp`: `pushRxMsgUp`); each set adds its own TCP transport on port_uc in symmetric-connections mode
    (and over UDP a UDP one), removed with the set; the UDP transport of port_us sends from port_uc of the set in use;
    a request of 1300 bytes or more over UDP moves to TCP before it is handed to the stack. The Via of a protected
    request names port_us after the transport is chosen (the message decorator): the prototype's port_uc Via, which
    leaned on the lab's Kamailio patch, is gone.
  - `tests/run_ims_aka.py` (needs `--cap-add NET_ADMIN`, skipped by ctest): scenarios 1 to 4 pass on both engines
    (registration, the filter, deregistration, resynchronisation, reregistration with a new set and the old set's
    deletion, MAC failure, the TS 34.108 test algorithm). Two problems found on main, not the migration's:
    - the test's `Security-Client` check still expected HMAC-SHA-1-96 with AES-CBC first; the engine offers AES-GCM
      first since `2fdc66b`. Fixed here (the combination must be among the offers).
    - scenario 5 (UDP) fails on both engines: with eight mechanisms the initial REGISTER is over 1300 bytes, so the
      engine sends it over TCP (RFC 3261 section 18.1.1) to a test P-CSCF that listens on UDP only. Undecided: fewer
      offers over UDP, or the test (and the lab's P-CSCF) taking the REGISTER over TCP.
  - Not yet run: the `aka` and `aka-udp` labs, which need the client on reSIProcate (subscriptions, phase 3d); a
    wildcard listen address.
- Phase 3c: INVITE sessions on reSIProcate's transaction layer (`src/sip_resip/dialogs.cpp`, decision 1): the UAC's
  INVITE (Allow, Supported and Require "timer", Session-Expires, Min-SE, the MCPTT service, as captured from the
  pjproject engine on the wire), early dialogs, ACK of the 2xx and of its retransmissions, CANCEL through the stack and
  BYE after a 2xx that crossed it; the UAS dialog with immediate or deferred answers (the final one keeping the last
  provisional's header fields but Alert-Info), 487 to a cancelled or locally ended INVITE, the 2xx retransmitted over
  UDP until its ACK (64*T1, then BYE); re-INVITE and UPDATE offers both ways with 491 for a crossing offer, deferred
  re-INVITE answers, in-dialog INFO and MESSAGE, BYE both ways (the application sees a received BYE first), 481 and
  the CSeq check of RFC 3261 section 12.2.2, 482 for a Call-ID collision, PRACK both ways, the session timer (refresh
  by UPDATE or re-INVITE half way, BYE before expiry, 422 below Min-SE), digest retries in dialogs, REFER outside a
  dialog. `stop()` lets the stack write what was queued last (pjsip sends at once).
  - Tests: `test_sip`'s self-loop has its INVITE half back (only the SUBSCRIBE check waits for 3d); `sip_tls` and
    `sip_tcp` run every two-process role but the subscription ones and `transaction-failure` (a SUBSCRIBE), with the
    `nosubscriptions` argument: the call roles and the BYE digest retry pass over TLS and TCP. resip 58 of 58, pjsip 58
    of 58; `run_ims_aka.py` scenarios 1 to 4 still pass on resip.
  - Written but run by no test yet: the session refresh and expiry (the tests' sessions last 1800 s), the 2xx
    retransmission over UDP, PRACK (no peer of the tests sends reliable provisional responses), 422, 491 glare, a digest
    retry of an INVITE, dialogs over IMS AKA (scenario 5 of `run_ims_aka.py`, blocked on main).
- Phase 3d: subscriptions on the same dialog layer (`dialogs.cpp`): the subscriber's dialog from SUBSCRIBE, made by
  its 2xx or by a NOTIFY that comes first (RFC 6665 section 4.1.2.4, the case of the fork's DUM commit), ended by a
  failure of the initial SUBSCRIBE; the notifier's dialog of an accepted SUBSCRIBE (at once or deferred), with its
  Contact in the 2xx; NOTIFY and SUBSCRIBE refreshes both ways through the application; a terminating NOTIFY, sent and
  answered or received and accepted, ends the dialog; `subscription_count`. Every operation of `include/mcx/sip.hpp`
  is now written on reSIProcate: phase 3 is done.
  - Tests: `test_sip` runs whole on both stacks again (`MCX_SIP_RESIP` and `nosubscriptions` are gone); a new
    `notify-first` role against a raw notifier in `run_sip_tls.py` sends the NOTIFY on its own connection before the
    200 (both stacks, TLS and TCP). resip 58 of 58, pjsip 58 of 58, on `openmcx-dev:0.4-resip` rebuilt with the fork's
    `openmcx-1.14.0-1`.
  - Seen: reSIProcate logs an `SSL_shutdown` error when a TLS connection closes at stop (noise, for phase 6).
- Phase 4: one event loop. `SipEngine::poll(timeout, wake_sockets)`: the application's sockets end the wait as soon as
  one is readable. On reSIProcate they form an epoll set of their own (kept by descriptor and inode, since a closed
  descriptor leaves the set and its number comes back), itself one item of the stack's poll group; pjsip waits as
  before. The MCPTT/MCVideo server passes the sockets of its legs, relays and pre-established sessions, the client
  (openmcx-client branch `resiprocate-prototype`) its floor control, audio, live audio and video, MCVideo, multicast,
  MBMS, pre-established and IP connectivity sockets; the MCData server, whose media plane is MSRP in its tick, keeps
  its loop. Both images take `--build-arg MCX_SIP_STACK=resip` (on `openmcx-dev:0.4-resip`).
  - Measured (`prototype/resiprocate/relay_delay.py` on the server's capture of the `smoke` lab, 692 relayed RTP
    packets, the same code on both stacks): pjsip median 2.265 ms, p90 4.845, p99 7.732; reSIProcate median 0.056 ms,
    p90 0.079, p99 1.799. Phase 4 is done.
  - `tools/regress.py --select smoke`: 8 of 8 on both stacks, the first run of the servers and the client on
    reSIProcate. It found three engine defects, fixed:
    - send order: reSIProcate resolves next hops asynchronously, SRV then A for a Route without port (a proxy's
      Record-Route), so a NOTIFY sent before an INVITE left after it, and a client refused the late-entry INVITE as not
      yet affiliated. Every request now gets a forced target with host, port and transport (one A lookup, as pjsip's
      `getaddrinfo`; the host stays a name for TLS).
    - a dangling dialog identifier given to `on_call_state` after the dialog was erased (`terminate`), and dialog
      references kept across application callbacks; the SIP tests run clean under ASan and UBSan.
    - the stack's own ACK of a failure response named the listen address in Via: outside IMS AKA the advertised
      sent-by is now written directly.
  - Behaviour that differs and stays: reSIProcate joins repeated list header fields on one line (`P-Preferred-Service:
    a, b`, RFC 3261 section 7.3.1). `tests/integration/verify_mcdata_sds.py` now reads list header fields value by
    value; the other wire verifiers may need the same (phase 6).
  - Seen once: `sip_tcp` failed under load during an image build (quiet output, not reproduced in 12 runs since).
- Phase 6, under way (2026-11-22): the full IP regression (93 labs, TCP and TLS) on both stacks, then the MCPTT, MCData
  and MCVideo conformance suites (openmcx-conformance-tests, the SS emulator in place of the MCx server, the DUT client
  on each engine and nothing else changed). Defects found and fixed, each with a test that fails without the fix:
  - engine (`1695c88`): the response to this side's CANCEL (it has the INVITE's transaction identifier) was taken for
    the INVITE's final response; the advertised Via sent-by host was replaced by the stack's address (hostnames now
    kept, also on the stack's own CANCEL and failure ACK).
  - client (openmcx-client `0d97581`): after log-off and log-on, Kamailio's first reg NOTIFY still lists the binding
    the log-off removed, under the same REGISTER Call-ID; the client took it for its own and stayed deregistered
    (bootstrap-recovery BR-04). A contact whose cseq is below the current REGISTER's is stale (RFC 3680 section 5.1).
    reSIProcate exposed it by subscribing 1 ms after the 200, pjsip 75 ms.
  - engine (`9c97d05`): `SipStack::process(timeout)` waits out its timeout with a message queued for the transaction
    user, so an answer left a poll timeout (5 ms) after the 100: call setup median 7.7 ms against pjsip's 2.5 ms in the
    regression's TCP captures.
  - engine (`b854b01`): a message left at the end of the poll instead of in the call that sends it, so an HTTP GET the
    client issued after its FD NOTIFICATION "accepted" reached the wire first (MCData 6.2.2, 6.2.4, 6.2.6, 6.2.8,
    D.4.4); a Content-Type with Content-Length 0 reached the application as an empty document, and the final NOTIFY of
    a functional alias subscription was answered 400 (MCData 5.7, MCPTT 5.8, MCVideo 5.6).
  - wire verifiers: tshark JSON merged several SIP messages of one frame (`--no-duplicate-keys`).
  - Conformance before `b854b01` (DUT pjsip / reSIProcate): MCPTT 117+1 inconclusive / 116+1 fail+1 inconclusive,
    MCData 120 / 114+6 fail, MCVideo 144+3 N/A / 143+1 fail+3 N/A; every difference is one of the two defects above.
  - Resource use over the 306 labs of both regressions (before `9c97d05`): CPU about 3 % more on reSIProcate beyond a
    2 % run-wide difference, peak memory lower but for the MCVideo server (+2 MB).
  - Left: the regression, the conformance suites, both mixed pairs (pjsip servers with the reSIProcate client and the
    reverse) and the soak (`--select smoke,mcdata --duration 3h`, both stacks at once) on the images with all fixes.
  - Not changed: the wire verifiers' exact P-Preferred-Service compares (`verify_mcdata_media.py`,
    `verify_mcdata_fd.py`): one ICSI per request on both engines, and the regression passes.
