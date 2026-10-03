# MCVideo emergency and imminent peril tests

These tests cover **increment V5 of the MCVideo plan**: MCVideo emergency and imminent peril group calls, emergency private calls and emergency alerts (TS 24.281 V19.6.0 §4.6, §6.2.8, §9.2.1, §10.2.2, §11.2), with pre-emptive transmission control for a user in the emergency state (TS 24.581 V19.2.0 §4.1.1.2).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (rows MV-EMER-01 to MV-EMER-04).

## How it works

- **Group settings.** A group's MCVideo settings (`mcvideo` in the GMS: members, `priority_policy`, `call_policy`, ...) name MCVideo IDs and replace the MCPTT ones for `mcvideo-server`; the shared core's priority procedures (TS 24.379 behaviour) then apply unchanged. The policy says who may raise and cancel emergency and imminent peril and alerts, and the Resource-Priority values (RFC 4412 with the RFC 8101 namespaces, as TS 24.281 §4.6.1 asks).
- **Emergency group call.** The caller's INVITE carries `<emergency-ind>` true with `<alert-ind>` false and the emergency Resource-Priority (§6.2.8.1.1); the controlling function puts the group in the in-progress emergency state and invites the members with it. A participant upgrades a call or cancels the emergency by re-INVITE in its dialog (§6.2.8.1.4); the others learn the new state in the call. Imminent peril works the same way with `<imminentperil-ind>`.
- **Pre-emption.** A Transmission Request of a user in the call's emergency (or imminent peril) state is pre-emptive: the arbitrator revokes the normal transmission and grants the emergency user.
- **Emergency private call.** `<emergency-ind>` in the private call's INVITE, authorised by the caller's MCVideo private-call ruleset (§6.2.8.3).
- **Emergency alert.** A SIP MESSAGE to the MCVideo PSI with `<alert-ind>` true and the UE's location in `application/vnd.3gpp.mcvideo-location-info+xml` (namespace `urn:3gpp:ns:mcvideoLocationInfo:1.0`, Annex F.3); the controlling function tells the other affiliated members, with the location; a MESSAGE with `<alert-ind>` false cancels it (§11.2).

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Emergency group call | Origination with `<emergency-ind>` and `<alert-ind>` false; every member in the emergency state | 24.281 §4.6.1, §6.2.8.1.1, §9.2.1 |
| Cancellation, upgrade | re-INVITE with the MCVideo Accept-Contact, P-Preferred-Service and Resource-Priority | §6.2.8.1.4 |
| Authorisation | Only users listed in the group's MCVideo `priority_policy`; others 403 | §6.2.8.1 with the group document |
| Imminent peril | Raise and end, every member follows | §4.6.4, §6.2.8.1.9 |
| Pre-emption | An emergency user's request revokes the normal transmitter | 24.581 §4.1.1.2 |
| Emergency private call | Established with both parties in the emergency state | 24.281 §6.2.8.3 |
| Emergency alert | MESSAGE with the MCVideo location body, delivered to the other members, then cancelled | §11.2 |

Configuration: the lab of `tools/prepare-prearranged-test.py --mcvideo` gives group operations an MCVideo `priority_policy`: client-a and client-b may raise and cancel emergency, imminent peril and alerts (only client-a cancels alerts); client-c may not. client-a's MCVideo private-call ruleset allows emergency private calls to anyone. Clients and `mcvideo-server` have `mcvideo.resource_priority` (`mcptt.0`, `mcptt.10`, `mcptt.15`).

### Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-call emergency'           # or imminent
mcx-client --config FILE --command 'mcvideo-emergency on'             # upgrade or cancel in the call: on|off
mcx-client --config FILE --command 'mcvideo-imminent on'              # on|off
mcx-client --config FILE --command 'mcvideo-private <MCVideo ID> auto emergency'
mcx-client --config FILE --command 'mcvideo-alert on'                 # on|off
```

`status.json` adds `mcvideo_priority` (emergency, imminent or normal, as the server last said), `mcvideo_priority_result` (the outcome of the last change or alert), `mcvideo_alerting` and `mcvideo_alerts` (received alerts by originator, with location).

## Running the tests

```bash
python3 tools/regress.py --image openmcx:v5 --select =mcvideo-emergency --output artifacts/regress-v5
```

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| MV-EM-01 | 2026-09-26 | `openmcx:v5` (`6f83939420cb`) | client-a calls operations as an emergency group call; all four join; all four in the emergency state | Passed |
| MV-EM-02 | 2026-09-26 | same | client-a cancels the emergency (200); all four back to normal | Passed |
| MV-EM-03 | 2026-09-26 | same | client-c, not authorised, raises an emergency: 403 (not the `150` of a malformed request); the call stays normal | Passed |
| MV-EM-04 | 2026-09-26 | same | client-b raises imminent peril; all four follow; client-b ends it | Passed |
| MV-EM-05 | 2026-09-26 | same | client-c transmits; client-a raises the emergency and requests transmission; client-a is granted and client-c revoked | Passed |
| MV-EM-06 | 2026-09-26 | same | client-a's emergency private call to client-b; both in the emergency state | Passed |
| MV-EM-07 | 2026-09-26 | same | client-a's emergency alert reaches client-b, client-c and client-d with its location; its cancellation withdraws it everywhere | Passed |
| MV-EM-08 | 2026-09-26 | same | Captured at `mcvideo-server`: an emergency INVITE with `<emergency-ind>` and `Resource-Priority: mcptt.15`; `Resource-Priority: mcptt.10` for imminent peril; an alert MESSAGE with the MCVideo location body and namespace | Passed |

The scenario made 26 checks (`artifacts/regress-v5/mcvideo-emergency/`). On the same image the other MCVideo scenarios (17, 74 and 41 checks) and the MCPTT smoke, `priority`, `location` and `first-to-answer` labs passed (`artifacts/regress-v5-all/`); three labs of that run did not start because Docker reported "No such container" while starting `sip-core` with four labs in parallel, and passed when rerun two at a time (`artifacts/regress-v5-rerun/`). Defects found by the runs and fixed: the client's re-INVITE lacked the MCVideo Accept-Contact, which the server requires; an upgrade to emergency lacked `<alert-ind>`, and an alert carried `<emergency-ind>` (both refused with `150`, which also made the first MV-EM-03 pass for the wrong reason until the check was tightened); the transmission control server passed no pre-emption level, so an emergency user never pre-empted; the client's MCPTT handling parsed the MCVideo server's MESSAGEs as MCPTT; and a finished call's last conference NOTIFY was refused.

## Coverage gaps

| Area | Gap |
|---|---|
| Ad hoc group emergency alert | Done in V8: see MV-AH-06 in the [ad hoc tests](MCVIDEO_ADHOC_TEST.md) |
| Emergency alert areas | Location-triggered alerts come with the location work of V8 |
| Priority sharing | §6.7 is IMS bearer priority sharing (TS 24.229), which needs PCC; not applicable to the lab |
| In-progress state machines | The states of Annex G are those of the shared core (TS 24.379 behaviour); only their visible outcome is checked |
| Emergency private call cancellation | Upgrading and cancelling an established private call are not exercised |
