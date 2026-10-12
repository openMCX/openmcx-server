# MCData functional alias tests

These tests cover **MCData functional aliases** (TS 24.282 V19.7.0 clause 22): activation and take-over by PUBLISH, SDS addressed to an alias with the 300 Multiple Choices redirect, aliases in ad hoc participant lists, and presentation of the sender's alias.

Back to the [MCData test index](../MCDATA_TEST.md). The shared four-client fixture, the client status fields and the MCData deployment are described in the [standalone SDS tests](MCDATA_SDS_TEST.md), which also holds the shared coverage gaps. Acceptance: [MCData acceptance matrix](../../docs/architecture/mcdata-standards-and-acceptance.md).

## How it works

- **Status change.** PUBLISH `presence` with a PIDF in the `urn:3gpp:ns:mcdataPresInfoFA:1.0` namespace sets the user's active aliases; Expires 0 deactivates them all.
- **Addressing an alias.** A one-to-one SDS with `<call-to-functional-alias-ind>` is answered with 300 Multiple Choices naming one activated user; the client then sends the message to that user with `<called-functional-alias-URI>`.

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Functional aliases | Status subscription by SUBSCRIBE `presence` with `<request-type>` `functional-alias-status-determination`, the client's own status only. Status change by PUBLISH `presence` with the `urn:3gpp:ns:mcdataPresInfoFA:1.0` PIDF: a nonzero Expires sets the user's active aliases to the listed ones, Expires 0 deactivates them all, other values get 423. Past the participating checks (403 when the request URI is not the sender), the PUBLISH is answered 200. The server then decides each alias as the owning server does, and the NOTIFY with the change's `p-id-fa` gives the outcome. An activated alias is listed `activated`. At the limit, a user allowed to take over (`<allow-takeover>` and the user's `<allow-takeover-functional-alias-other-user>`) is offered `take-over-possible`. An unknown alias, a user outside `<mcdata-user-list>` or a refused take-over is left out. A user that loses an alias to a take-over is notified. Activations and subscriptions end with log-off or authorisation expiry. A one-to-one SDS with `<call-to-functional-alias-ind>` gets 300 Multiple Choices naming one activated user (403 `145` if none, after the one-to-one checks, so the target list of §11.1 step 1A applies to the alias); the client sends a new request to that user with `<called-functional-alias-URI>`. An ad hoc participant list may name aliases, which stand for their activated users. The sender's `<functional-alias-URI>` is delivered only while the alias is active for the sender. | V19.7.0 §22.2.1.2, §22.2.1.3, §22.2.2.2.3 to §22.2.2.2.5, §22.2.2.3.3, §22.2.2.3.6, §9.2.2.2.1, §9.2.2.3.1 step 12A, §9.2.2.4.2 steps 5b-ii and 6A b-ii |

### Client commands

```bash
mcx-client --config FILE --command 'sds-fa [delivery|read|both] [app=<n>] [priority=<n>] <functional alias> <text>'
mcx-client --config FILE --command 'mcdata-fa activate|takeover|deactivate <alias>...'   # or: mcdata-fa use <alias>|none
```

## Performed tests

The tests run in the SDS scenario (`mcdata_sds_scenario.py`, 163 assertions) and its wire verifier (`verify_mcdata_sds.py`, 64 checks), clear SIP (debug mode), on one MCData server instance; the regression runs them in the `mcdata` lab. The scenario and the wire report cover every MCData SDS feature, so the evidence below is shared with the other MCData SDS documents.

| ID | Scenario | Result evidence |
|---|---|---|
| FA-01 | The client subscribes to its status first. Alias activation (200, NOTIFY `activated`); beyond the limit, a user allowed to take over is offered `take-over-possible`; that user's take-over replaces the holder, which is notified; a user outside the alias list and an unknown alias are refused in the NOTIFY (200); two users within a limit of two | Scenario report (`artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/integration/mcdata-sds.pcap`) |
| FA-02–FA-03 | SDS to an alias: 300 then a new request to the selected user, delivered with `<called-functional-alias-URI>`; 145 for an alias nobody holds; 229 when the alias is outside the sender's one-to-one list | Scenario report (`artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/integration/mcdata-sds.pcap`) |
| FA-04 | The recipient sees the sender's active alias; a former holder, told of the take-over, no longer presents it | Scenario report (`artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/integration/mcdata-sds.pcap`) |
| FA-05 | An ad hoc participant list naming an alias reaches its activated users with the alias; users without participation permission are skipped; 145 when nobody holds it | Scenario report (`artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/integration/mcdata-sds.pcap`) |
| FA-06 | Deactivation of the last alias is Expires 0 (200, NOTIFY without it) | Scenario report (`artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/integration/mcdata-sds.pcap`) |

## Coverage gaps

| Area | Gap |
|---|---|
| Functional aliases | Not implemented: the subscription to the users of an alias (§22.2.1.3 with an alias as request URI), the deactivating state and timer F, location-based activation (§22.2.1.4), functional alias to group binding (§22.4), and separate serving and owning servers (MCData has one server). |
