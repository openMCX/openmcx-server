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
| 2 | Foundations | reSIProcate in `docker/Dockerfile.dev` (`dependencies/resiprocate/build.sh` with its patches); the CMake switch; patch 0001 proposed upstream | The development image builds both | 1 week |
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

1. **Which reSIProcate layer.** Its dialog layer (DUM) for INVITE sessions and subscriptions; its transaction layer
   for REGISTER with IMS AKA and for requests the engine builds itself (as the AKA probe does). Confirmed or changed
   after phase 3a.
2. **Patch 0001 upstream**, so that OpenMCX carries less of its own.
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
  phase 3a); the prototype builds and its loopback probe runs in the development image's ctest (58 tests). Still to
  do: patch 0001 proposed upstream.
- Phase 1, in part: IMS AKA over UDP and TCP against the lab (registration, a request of the P-CSCF to port_us,
  a large request over TCP, reregistration with the switch to the new set, deregistration); no reSIProcate patch
  needed for either pjproject patch (`README.md`).
- Phase 1: done. Also SIP over TLS with the TLS profile, judged by the regression's TLS checks, and multipart
  bodies octet for octet (`README.md`).
