# MCVideo ad hoc group call tests

On-network ad hoc group calls with on-demand sessions (TS 24.281 clause 22). A call is set up with a list of MCVideo users or with participant criteria, the server assigns the ad hoc group identity, and H.264 video is checked picture by picture. The ad hoc group emergency alert (§12.1A) is tested here too.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SVC-04).

## How it works

- **Shared with MCPTT.** The call is the shared core's ad hoc group call (TS 24.379 clause 17), which clause 22 follows. The core uses MCVideo's warning table, so it answers with the MCVideo texts (185 to 190).
- **One element name differs.** The participant criteria are `<call-participants-criteria>` in TS 24.281 F.1, but `<call-participants-criterias>` in TS 24.379 F.1. The protocol code takes the name from the service.
- **Setup** (§22.2.2.1.1):
  - The client sends INVITE to the MCVideo PSI with `session-type` adhoc. It names the users in a resource-lists body, or the criteria in `<call-participants-criteria>`.
  - `mcvideo-server` invites them, and returns the ad hoc group identity it assigned in `<mcvideo-calling-group-id>` of the 200 (OK) (2xx step 4).
  - The invited clients see the same identity.
- **Transmission control** is the group call's, one transmitter at a time.
- **Release** (§6.3.8.1): the call is released when one or no participant is left (item 2) or TNG3 expires (item 5). The initiator leaving does not end it (item 3 is for pre-arranged group calls), unlike an MCPTT ad hoc group call (TS 24.379 §6.3.8.1 item 3, local policy).
- **Ad hoc group emergency alert.** The shared core's ad hoc alert (TS 24.379 12.1A, which TS 24.281 12.1A follows). A cancellation is confirmed to the originator by a receipt with `<adhoc-alert-ind>` false and `<adhoc-alert-ind-rcvd>` true (§12.1A.3.2 step 4 g)).
- **Configuration.**
  - `mcvideo-server` has `mcvideo.adhoc_call` (enabled, 3 participants besides the originator, timers).
  - Each user's MCVideo profile has `adhoc_call.allow`, for `<allow-adhoc-group-call>`. client-d is not allowed; client-a may also modify participants.

## Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-adhoc <MCVideo ID> [<MCVideo ID>...]'
mcx-client --config FILE --command 'mcvideo-adhoc criteria affiliated:<MCVideo group>'
mcx-client --config FILE --command 'mcvideo-adhoc-alert <criteria>|cancel'
```

`status.json` adds `mcvideo_group`: the group of the call, or the ad hoc group's identity. `mcvideo_call_type` is `adhoc`. For the alert it adds `mcvideo_adhoc_alert_state` (annex G.20: 1 none, 2 confirm pending, 3 initiated, 4 cancel pending until the receipt), `mcvideo_adhoc_alert_group`, `mcvideo_received_adhoc_alerts` and `mcvideo_adhoc_alert_result`.

## Running the tests

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-adhoc
```

The scenario makes 28 checks. Over TLS the wire checks (MV-AH-05) are skipped.

## Tests

| ID | What is checked |
|---|---|
| MV-AH-01 | client-a calls client-b and client-c. All three share one ad hoc group identity, assigned by the server and different from the preconfigured group; client-d is not invited. client-a transmits, and client-b and client-c decode its pictures, all equal. Then client-b transmits and client-c decodes it, all pictures equal |
| MV-AH-02 | The originator leaves and the call goes on for the others (TS 24.281 §6.3.8.1 item 3 is for pre-arranged calls only); when one participant is left, the call is released (item 2) |
| MV-AH-03 | Criteria `affiliated:<MCVideo group>`: every affiliated user is invited, and all four are in one ad hoc call |
| MV-AH-04 | client-d is refused with 403 `185 user not authorised to initiate the adhoc group call` |
| MV-AH-05 | Captured at `mcvideo-server`: ad hoc INVITEs to the MCVideo PSI; the called MCVideo IDs in resource-lists; the criteria in `<call-participants-criteria>`; the 200 (OK) naming the ad hoc group in `<mcvideo-calling-group-id>` |
| MV-AH-06 | Ad hoc group emergency alert (§12.1A). client-a's alert to the users affiliated to the group is answered 200 with its ad hoc group, confirmed to client-a with `<adhoc-alert-ind-rcvd>` and received by client-b, client-c and client-d; its cancellation clears it everywhere; client-b, without `<allow-activate-adhoc-group-emergency-alert>`, is refused with 403. On the wire the alert carries `<adhoc-alert-ind>true`, the criteria and an MCVideo location body |

## Coverage gaps

| Area | Gap |
|---|---|
| Modification | Modifying the participant list or criteria (§22.2.6) is implemented in the shared core for MCPTT, but not driven for MCVideo |
| Leave and rejoin | §22.2.4 and §22.2.5 are not exercised |
| Priority | Emergency and imminent peril ad hoc calls are not exercised for MCVideo. For the ad hoc emergency alert (§12.1A), participant modification (12.1A.3.4), the late alert to a newly matching user and the not-acknowledged list are not exercised |
| Participant limit | Warning 189 is exercised by the MCPTT ad hoc tests on the shared code |
| Pre-established sessions | §22.2.2.2 and the related clauses: not in present edition |
| Security | End-to-end security for ad hoc calls is not implemented; the calls are clear |
