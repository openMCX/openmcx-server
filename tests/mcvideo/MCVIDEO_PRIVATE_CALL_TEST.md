# MCVideo private call tests

On-network MCVideo private calls with transmission control (TS 24.281 §10.2.2) and without it (§10.2.3), in the commencement modes of §6.2.3, ended by either party (§10.2.4), and refused by the private-call rulesets of the MCVideo user profiles, with H.264 video carried both ways.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-PRIV-01).

## How it works

- **Call setup.** The caller sends INVITE to the MCVideo PSI with `session-type` private, its MCVideo ID as `<mcvideo-calling-user-id>`, the called MCVideo ID in an `application/resource-lists+xml` body, and the commencement mode: `Answer-Mode: Auto` or `Manual`, or `Priv-Answer-Mode: Auto` to force automatic commencement (§10.2.2.2.1, §6.2.3). `mcvideo-server` runs the shared core's private call as the controlling function and invites the called user with the same mode.
- **Rulesets.** The MCVideo server reads each user's MCVideo profile: the CMS serves it under `mcvideo` (TS 24.484), with rulesets in the form of the MCPTT ones naming MCVideo IDs. `user_profile()` in the core returns this view for an MCVideo server, so the private-call checks of TS 24.379 apply unchanged with MCVideo's warnings (TS 24.281 §4.4.2).
- **Commencement.** Automatic commencement answers at once. With manual commencement the called client rings (180 with its prepared answer) until the user answers or declines; a decline is 480 with warning `110`. `Priv-Answer-Mode: Auto` is answered at once whatever the local setting.
- **With transmission control** the call is the group call's transmission control between two parties: one transmits at a time.
- **Without transmission control** (§10.2.3) the offer has audio and video and no `m=application`; nothing is arbitrated, both parties send at once, and the media distribution function relays each party's video to the other, checked against the SSRC of that party's SDP (`a=ssrc`, RFC 5576).
- **Conference events** are not subscribed to in a private call; the package describes group sessions.

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Private call setup | `session-type` private, called MCVideo ID in resource-lists, commencement headers | 24.281 §10.2.2.2.1, §10.2.2.3, §10.2.2.4 |
| Commencement | Automatic, manual (ringing, answer, decline with 480 `110`), forced automatic | §6.2.3 |
| Ending | By either party; both sides idle | §10.2.4 |
| Rulesets | `107` no private calls, `144` target not in the caller's list, `127` target not callable, `159` caller not in the target's incoming list | §4.4.2 with the MCVideo user profile |
| With transmission control | One transmitter at a time; video decoded by the other party | §10.2.2; 24.581 §6 |
| Without transmission control | No `m=application`; both send at once; video decoded both ways | §10.2.3 |

Configuration: the lab of `tools/prepare-prearranged-test.py --mcvideo` gives each user an MCVideo private-call ruleset in its `mcvideo` profile: client-a every commencement mode to client-b and client-c; client-b automatic and manual to anyone; client-c automatic only, called only by client-a; client-d neither calls nor is called. `mcvideo-server` has `mcvideo.private_call` with a 5 s setup timer.

### Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-private <MCVideo ID> [auto|manual|force-auto] [no-control]'
mcx-client --config FILE --command 'mcvideo-answer'   # or mcvideo-reject, for a ringing call
```

`status.json` adds `mcvideo_call_type`, `mcvideo_peer` and `mcvideo_transmission_control`; a refused call is in `mcvideo_last_call` with its status and warning.

## Running the tests

The scenario runs in the `mcvideo` lab, beside the affiliation and group call scenarios:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo
```

The scenario makes 41 checks. Over TLS the wire checks (MV-PC-07) are skipped.

## Tests

| ID | What is checked |
|---|---|
| MV-PC-01 | client-a calls client-b (automatic); each knows the other; nobody else is in the call; client-a transmits and client-b decodes its pictures, all equal; client-b transmits and client-a decodes its pictures, all equal |
| MV-PC-02 | client-b ends the call; both are idle |
| MV-PC-03 | Manual commencement: client-b rings while client-a waits, then answers; both active |
| MV-PC-04 | client-b declines a manual call; client-a gets 480 `399 mcx "110 user declined the call invitation"` |
| MV-PC-05 | client-d calls client-a: 403 `107`; client-a calls client-d: 403 `144`; client-b calls client-d: 403 `127`; client-b calls client-c: 403 `159` |
| MV-PC-06 | client-a forces automatic commencement at client-c; answered at once; client-c ends it |
| MV-PC-08 | client-a calls client-b without transmission control; both send at once; each decodes the other's pictures, all equal |
| MV-PC-07 | Captured at `mcvideo-server`: private INVITEs to the MCVideo PSI, the called MCVideo ID in resource-lists, `Answer-Mode: Auto`, `Answer-Mode: Manual` and `Priv-Answer-Mode: Auto`, offers with and without `m=application` |

## Coverage gaps

| Area | Gap |
|---|---|
| Emergency private calls | Setting one up is tested in the [emergency tests](MCVIDEO_EMERGENCY_TEST.md) (MV-EM-06); upgrade, cancellation and the in-progress states (§10.2.2.2.4, §10.2.2.2.5, §10.2.2.4.3 to §10.2.2.4.6) are not exercised |
| Server-initiated end | §10.2.5 (the private call timers ending a call) is not exercised |
| Functional aliases | Calling a functional alias is tested in the [functional alias tests](MCVIDEO_FUNCTIONAL_ALIAS_TEST.md) (MV-FA-09) |
| Timers | Private call setup and duration timers of the shared core apply; only the setup timer is configured |
| Security | Private call keys (PCK) are tested in the [protected call tests](MCVIDEO_PROTECTED_TEST.md) |
