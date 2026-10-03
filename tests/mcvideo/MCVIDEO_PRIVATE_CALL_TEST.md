# MCVideo private call tests

These tests cover **increment V4 of the MCVideo plan**: on-network MCVideo private calls with transmission control (TS 24.281 V19.6.0 §10.2.2) and without it (§10.2.3), in the commencement modes of §6.2.3, ended by either party (§10.2.4), and refused by the private-call rulesets of the MCVideo user profiles, with H.264 video carried both ways.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-PRIV-01).

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

```bash
python3 tools/regress.py --image openmcx:v4 --select =mcvideo --output artifacts/regress-v4
```

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| MV-PC-01 | 2026-09-26 | `openmcx:v4` (`4ad3622659bf`) | client-a calls client-b (automatic); each knows the other; nobody else is in the call; client-a transmits and client-b decodes 20 pictures, all equal; client-b transmits and client-a decodes 22, all equal | Passed |
| MV-PC-02 | 2026-09-26 | same | client-b ends the call; both are idle | Passed |
| MV-PC-03 | 2026-09-26 | same | Manual commencement: client-b rings while client-a waits, then answers; both active | Passed |
| MV-PC-04 | 2026-09-26 | same | client-b declines a manual call; client-a gets 480 `399 mcx "110 user declined the call invitation"` | Passed |
| MV-PC-05 | 2026-09-26 | same | client-d calls client-a: 403 `107`; client-a calls client-d: 403 `144`; client-b calls client-d: 403 `127`; client-b calls client-c: 403 `159` | Passed |
| MV-PC-06 | 2026-09-26 | same | client-a forces automatic commencement at client-c; answered at once; client-c ends it | Passed |
| MV-PC-08 | 2026-09-26 | same | client-a calls client-b without transmission control; both send at once; each decodes 21 of the other's pictures, all equal | Passed |
| MV-PC-07 | 2026-09-26 | same | Captured at `mcvideo-server`: 9 private INVITEs to the MCVideo PSI, the called MCVideo ID in resource-lists, `Answer-Mode: Auto`, `Answer-Mode: Manual` and `Priv-Answer-Mode: Auto`, offers with and without `m=application` | Passed |

The scenario made 41 checks (`artifacts/regress-v4/mcvideo/`, capture `artifacts/integration/mcvideo-private-call.pcap`); the affiliation (17) and group call (74) scenarios passed on the same image, and so did 14 MCPTT scenarios on the shared private-call path (the smoke labs, `private_services_scenario`, `first_to_answer_emergency_scenario` and the eight call types of `call-types`, `artifacts/regress-v4-mcptt/`). Defects found by the runs and fixed: the shared private-call path built the MCPTT-only transfer and forwarding warnings for every call, which the MCVideo warning table refuses; the ringing client sent a 180 without its prepared answer, so the later 200 never completed; a failure the INVITE's response reported after the dialog had ended was lost; the client subscribed to the conference package in a private call; and the server offered `mc_queueing` in a call without transmission control.

## Coverage gaps

| Area | Gap |
|---|---|
| Emergency private calls | Upgrade, cancellation and the in-progress states (§10.2.2.2.4, §10.2.2.2.5, §10.2.2.4.3 to §10.2.2.4.6) come with V5 |
| Server-initiated end | §10.2.5 (the private call timers ending a call) is not exercised |
| Functional aliases | Calling a functional alias comes with V8 |
| Timers | Private call setup and duration timers of the shared core apply; only the setup timer is configured |
| Security | Private call keys (PCK) come with V9 |
