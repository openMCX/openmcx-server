# MCVideo ad hoc group call tests

These tests cover **step V8a of increment V8 of the MCVideo plan**: on-network ad hoc group calls with on-demand sessions (TS 24.281 V19.6.0 clause 22). A call is set up with a list of MCVideo users or with participant criteria, the server assigns the ad hoc group identity, and H.264 video is checked picture by picture.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SVC-04).

## How it works

- **Shared with MCPTT.** The call is the shared core's ad hoc group call (TS 24.379 clause 17), which clause 22 follows. The core already chose MCVideo's warning table, so it answers with the MCVideo texts (185 to 190).
- **One element name differs.** The participant criteria are `<call-participants-criteria>` in TS 24.281 F.1, but `<call-participants-criterias>` in TS 24.379 F.1. The protocol code now takes the name from the service.
- **Setup** (§22.2.2.1.1):
  - The client sends INVITE to the MCVideo PSI with `session-type` adhoc. It names the users in a resource-lists body, or the criteria in `<call-participants-criteria>`.
  - `mcvideo-server` invites them, and returns the ad hoc group identity it assigned in `<mcvideo-calling-group-id>` of the 200 (OK) (2xx step 4).
  - The invited clients see the same identity.
- **Transmission control** is the group call's, one transmitter at a time. With `end_when_initiator_leaves`, the originator leaving ends the call.
- **Configuration.**
  - `mcvideo-server` has `mcvideo.adhoc_call` (enabled, 3 participants besides the originator, timers).
  - Each user's MCVideo profile has `adhoc_call.allow`, for `<allow-adhoc-group-call>`. client-d is not allowed; client-a may also modify participants.

## Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-adhoc <MCVideo ID> [<MCVideo ID>...]'
mcx-client --config FILE --command 'mcvideo-adhoc criteria affiliated:<MCVideo group>'
```

`status.json` adds `mcvideo_group`: the group of the call, or the ad hoc group's identity. `mcvideo_call_type` is `adhoc`.

## Running the tests

```bash
tools/regress.py --image openmcx:v8 --client-image openmcx-client:v8 --select mcvideo-adhoc
```

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| MV-AH-01 | 2026-09-27 | `openmcx:v8` (`4e45ae571c62`), `openmcx-client:v8` (`ee09aeb3bc8b`) | client-a calls client-b and client-c. All three share one ad hoc group identity, assigned by the server and different from the preconfigured group; client-d is not invited. client-a transmits, and client-b and client-c decode 16 and 17 pictures, all equal. Then client-b transmits and client-c decodes it, 10 of 10 equal | Passed |
| MV-AH-02 | 2026-09-27 | same | The originator leaves and the call ends for all | Passed |
| MV-AH-03 | 2026-09-27 | same | Criteria `affiliated:<MCVideo group>`: every affiliated user is invited, and all four are in one ad hoc call | Passed |
| MV-AH-04 | 2026-09-27 | same | client-d is refused with 403 `185 user not authorised to initiate the adhoc group call` | Passed |
| MV-AH-05 | 2026-09-27 | same | Captured at `mcvideo-server`: ad hoc INVITEs to the MCVideo PSI; the called MCVideo IDs in resource-lists; the criteria in `<call-participants-criteria>`; the 200 (OK) naming the ad hoc group in `<mcvideo-calling-group-id>` | Passed |
| MV-AH-06 | 2026-09-27 | `openmcx:v8g` (`d58f835e1979`), `openmcx-client:v8g` (`5b98924fe43c`) | Ad hoc group emergency alert (§12.1A). client-a's alert to the users affiliated to the group is answered 200 with its ad hoc group, confirmed to client-a with `<adhoc-alert-ind-rcvd>` and received by client-b, client-c and client-d; its cancellation clears it everywhere; client-b, without `<allow-activate-adhoc-group-emergency-alert>`, is refused with 403. On the wire the alert carries `<adhoc-alert-ind>true`, the criteria and an MCVideo location body | Passed |

The scenario made 22 checks (`artifacts/regress-v8a-try1/mcvideo-adhoc/`, capture `artifacts/integration/mcvideo-adhoc.pcap`). The smoke labs passed on the same images. With MV-AH-06 it makes 28 (`artifacts/regress-v8-adhoc-alert/`).

MV-AH-06 uses the shared core's ad hoc alert (TS 24.379 12.1A, which TS 24.281 12.1A follows) and the client command `mcvideo-adhoc-alert <criteria>|cancel`. `status.json` adds `mcvideo_adhoc_alert_state` (annex G.20: 1 none, 2 confirm pending, 3 initiated), `mcvideo_adhoc_alert_group`, `mcvideo_received_adhoc_alerts` and `mcvideo_adhoc_alert_result`.

## Coverage gaps

| Area | Gap |
|---|---|
| Modification | Modifying the participant list or criteria (§22.2.6) is implemented in the shared core for MCPTT, but not driven for MCVideo here |
| Leave and rejoin | §22.2.4 and §22.2.5 are not exercised |
| Priority | Emergency and imminent peril ad hoc calls are not exercised for MCVideo; for the ad hoc emergency alert (§12.1A), participant modification (12.1A.3.4), the late alert to a newly matching user and the not-acknowledged list are not exercised |
| Participant limit | Warning 189 is exercised by the MCPTT ad hoc tests on the shared code |
| Pre-established sessions | §22.2.2.2 and the related clauses are unsupported (H8) |
| Security | End-to-end security for ad hoc calls (S16) is unsupported |
