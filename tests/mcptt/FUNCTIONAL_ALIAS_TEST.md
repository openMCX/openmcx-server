# Functional alias tests

These tests cover **functional aliases** (TS 24.379 clause 9A) and their use in private, first-to-answer, group and ad hoc calls. They also cover the **broadcast ad hoc call**, which shares the fixture. They do not certify complete functional-alias conformance; see [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented profile

One MCPTT server serves the users and owns the aliases. The CMS holds the alias definitions.

| Step | Behavior | Reference |
|---|---|---|
| Definition | `functional_aliases` in the site configuration: alias URI, permitted `users` (`<mcptt-user-list>`), `max_simultaneous_activations`, `allow_takeover`. A user's `functional_alias_takeover` mirrors `<allow-takeover-functional-alias-other-user>`. Served at the CMS `/internal/functional-alias`. | 23.280 §7.4.2.2.13 |
| Status change | The client sends a PUBLISH to the service URI with `Event: presence`, an `mcptt-info` body naming itself, and a PIDF using `urn:3gpp:ns:mcpttPresInfoFA:1.0`: entity = MCPTT ID, tuple id = client ID, one `<functionalAlias functionalAliasID=…>` per alias, optional `<take-over>true`. `Expires: 4294967295` activates or refreshes; `0` deactivates. | 24.379 §9A.2.1.2, §9A.3.1.2 |
| Checks | Unknown alias, user not in the user list, or the activation limit reached → 403. Take-over replaces the current holder when both the alias and the user allow it, otherwise 403. Another nonzero Expires → 423 with `Min-Expires: 4294967295`. All listed aliases are checked before any change. | §9A.2.2.3.3 |
| Lifetime | Activations end when the user's service authorization ends. | §9A.2.2.3.6 |
| Private call to an alias | `private-fa <alias>` sends `call-to-functional-alias-ind` true. The server resolves an activated user (not the caller) and answers **300 Multiple Choices** with `mcptt-request-uri` = that user and `called-functional-alias-URI` = the alias. The client then calls that user, carrying the called alias. No activated user → 403/145. The follow-up INVITE is an ordinary private call, so the caller's `<PrivateCall>` list applies. | §11.1.1.4.2 step 8a, §11.1.1.2.1.1 (300 handling) |
| First-to-answer to an alias | `first-to-answer-fa <alias>` rings every activated user; the first answer wins. | §11.1.1.4.2 step 12 |
| Presentation | `fa use <alias>` adds `<functional-alias-URI>` to outgoing calls. The server presents it on terminating INVITEs and conference rosters only while the alias is activated for the caller. | §10.1.1.3.1.1 step 6a |
| Ad hoc | A participant-list entry that is an alias stands for the users that activated it, and each invitation carries `called-functional-alias-URI`. | §17.4.2.2 step 12b |
| Broadcast ad hoc | `adhoc broadcast <ids>` sets `broadcast-ind`: invitees are receive-only (Floor Deny cause 5), and the call ends with the initiator's transmission. | §17, §4.12 |

### Client commands

```bash
mcx-client --config FILE --command 'fa activate sip:medic.alias@mcx.test'
mcx-client --config FILE --command 'fa takeover sip:dispatcher.alias@mcx.test'
mcx-client --config FILE --command 'fa deactivate sip:medic.alias@mcx.test'
mcx-client --config FILE --command 'fa use sip:dispatcher.alias@mcx.test'      # or: fa use none
mcx-client --config FILE --command 'private-fa sip:medic.alias@mcx.test auto'
mcx-client --config FILE --command 'first-to-answer-fa sip:medic.alias@mcx.test'
mcx-client --config FILE --command 'adhoc sip:medic.alias@mcx.test'
mcx-client --config FILE --command 'adhoc broadcast sip:bob.mcptt@mcx.test sip:client-c.mcptt@mcx.test'
```

The status file reports `requested_functional_aliases`, `last_fa_result`, `functional_alias`, `functional_alias_redirect`, and the received `calling_functional_alias` / `called_functional_alias`. The server status reports `functional_aliases` (alias → activated MCPTT IDs in activation order).

## Separate four-client fixture

```bash
python3 tools/prepare-prearranged-test.py --directory artifacts/alias-lab --project openmcx-alias \
  --debug-sip --private-call --adhoc --functional-alias --image openmcx:0.17
mkdir -p artifacts/alias-lab/artifacts/speech && cp artifacts/speech/{alpha,bravo}.wav artifacts/alias-lab/artifacts/speech/
.cache/deps/docker-compose-linux-x86_64 -p openmcx-alias -f artifacts/alias-lab/compose.json up -d
python3 tests/integration/functional_alias_scenario.py --compose artifacts/alias-lab/compose.json \
  --artifacts artifacts/alias-lab/artifacts
python3 tests/integration/verify_functional_alias.py artifacts/alias-lab/artifacts/integration/capture.pcap \
  --service sip:mcptt@mcx.test --output artifacts/alias-lab/artifacts/integration/functional-alias-sip-wire.json
```

Capture the server namespace as in the [private-call tests](PRIVATE_CALL_TEST.md#separate-four-client-fixture), using `tcpdump --immediate-mode`, and stop it a few seconds after the scenario ends. Otherwise buffered final packets can be lost.

| Alias | Users | Limit | Take-over |
|---|---|---|---|
| `dispatcher.alias` | client-a, client-b | 1 | allowed; only client-b has the user permission |
| `medic.alias` | client-c, client-d | 2 | no |
| `reserve.alias` | client-a | 1 | never activated |

In this fixture client-d is callable (unlike the plain `--private-call` fixture), so both medic users can be reached.

## Performed tests

Recorded on **2026-09-22** against image `openmcx:0.17` (`7a42efef3b69`), fixture `--private-call --adhoc --functional-alias`, clear media, debug SIP. The scenario made **33 assertions**, all **PASS**, on one server instance. Evidence: `artifacts/final-alias/artifacts/integration/` (`functional-alias-results.json`, `functional-alias-sip-wire.json`, `capture.pcap`).

| ID | Scenario | Assertions |
|---|---|---|
| FA-01 | Two permitted users activate `medic` within its limit of 2 | 2 |
| FA-02 | Activation by a user outside the alias user list → 403 | 1 |
| FA-03 | `dispatcher` activated by a; a second activation beyond the limit → 403 | 2 |
| FA-04 | Permitted take-over by b replaces a; a take-over without the user permission → 403 and changes nothing | 2 |
| FA-05 | `private-fa medic` → 300 naming the first activated user; the caller re-invites that user, who is told the called alias | 4 |
| FA-06 | An activated caller alias is presented on a private call and on a group call to every member; a requested alias that is not activated is not presented | 6 |
| FA-07 | `first-to-answer-fa medic` rings both activated users; the first answer wins and the other is cancelled | 3 |
| FA-08 | An ad hoc list entry naming `medic` invites both activated users, each told the called alias | 2 |
| FA-09 | Broadcast ad hoc call: receiver request denied with cause 5; receivers get the speech; release at transmission end | 4 |
| FA-10 | Deactivation removes the user; the alias then resolves to the remaining user | 3 |
| FA-11 | An alias with no activated user → 403/145 | 1 |

Independent SIP wire checks (11, `verify_functional_alias.py`): PUBLISH with the presence event and the FA PIDF extension; Expires 4294967295/0; entity, tuple and alias IDs; 200 and 403 outcomes; the take-over element; `call-to-functional-alias-ind` INVITEs; a 300 naming the selected MCPTT ID and called alias; re-INVITE of that ID without the indicator; 403/145; presentation on terminating INVITEs; and no presentation of a non-activated alias.

An earlier run's capture lost its last second, because it was copied as the scenario ended. The recorded run uses `tcpdump --immediate-mode` and a 3 s delay.

## Coverage gaps

| Area | Gap |
|---|---|
| Status determination | The SUBSCRIBE/NOTIFY status procedures (§9A.2.1.3, §9A.2.2.3.4–5) are not implemented. The PUBLISH response reports the outcome, and take-over is attempted directly rather than after a `take-over-possible` notification. |
| Location-based activation | §9A.2.1.4 and the manual-deactivation restriction are not implemented. |
| Group binding | Functional alias to group binding (§9A.4, warning 176) is not implemented. |
| Call-list restrictions | `<ListOfAllowedFAsToCall>` and `<ListOfAllowedFAsToBeCalledFrom>` (warnings 171/172) are not evaluated. |
| Multiple servers | The functional-alias scenario passes with separate participating and controlling servers: activation goes to the server owning the aliases (H2). |
