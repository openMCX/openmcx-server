# Functional alias tests

These tests cover **functional aliases** (TS 24.379 clause 9A) and their use in private, first-to-answer, group and ad hoc calls. They also cover the **broadcast ad hoc call**, which shares the fixture. They do not certify complete functional-alias conformance; see [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented profile

One MCPTT server serves the users and owns the aliases. The CMS holds the alias definitions.

| Step | Behavior | Reference |
|---|---|---|
| Definition | `functional_aliases` in the site configuration: alias URI, permitted `users` (`<mcptt-user-list>`), `max_simultaneous_activations`, `allow_takeover`. A user's `functional_alias_takeover` mirrors `<allow-takeover-functional-alias-other-user>`. Served at the CMS `/internal/functional-alias`. | 23.280 §7.4.2.2.13 |
| Status subscription | Before its first status change the client subscribes to its own functional alias status: SUBSCRIBE to the service URI with `Event: presence`, `Expires: 4294967295`, and an `mcptt-info` body naming itself with `<request-type>functional-alias-status-determination</request-type>`. Each NOTIFY carries the per-user PIDF: one `<functionalAlias functionalAliasID=… status="activated">` per activated alias, `status="take-over-possible"` for an alias the user asked for that is at its limit and that it may take over, and the `<p-id-fa>` of the PUBLISH that caused it. | 24.379 §9A.2.1.1, §9A.2.1.3, §9A.2.2.2.4–5 |
| Status change | The client sends a PUBLISH to the service URI with `Event: presence`, an `mcptt-info` body naming itself, and a PIDF using `urn:3gpp:ns:mcpttPresInfoFA:1.0`: entity = MCPTT ID, tuple id = client ID, one `<functionalAlias functionalAliasID=…>` per alias, a new `<p-id-fa>`, and `<take-over>true` only for aliases the last NOTIFY offered as `take-over-possible` (`fa takeover` of an alias not yet offered sends an activation and takes over once offered). `Expires: 4294967295` activates or refreshes; `0` deactivates. | 24.379 §9A.2.1.2, §9A.3.1.2 |
| Participating checks | `mcptt-request-uri` not the sender → 403. An alias the user may not change → 403 with warning `201 user not authorized to change the functional alias status`; OpenMCX has no `<FunctionalAliasList>` in the user profile, so the aliases whose user list names the user stand for it (an unknown alias fails too). Another nonzero Expires → 423 with `Min-Expires: 4294967295`. Otherwise **200**: the outcome is not in the response. | §9A.2.2.2.3 steps 4–8 |
| Owning checks | Per alias, on its own: user not in the user list, no activation allowed, or the limit reached → refused (left out of the NOTIFY; at the limit, `take-over-possible` when the alias has `allow_takeover` and the user `functional_alias_takeover`). A `<take-over>` replaces the current holder when both allow it, otherwise refused. The previous holder is notified too. A PUBLISH relayed by a participating server (split setup) gets the owning outcome as its response (403), all aliases checked before any change. | §9A.2.2.3.3, §9A.2.2.2.5 |
| Lifetime | Activations end when the user's service authorization ends. | §9A.2.2.3.6 |
| Private call to an alias | `private-fa <alias>` sends `call-to-functional-alias-ind` true. The server resolves an activated user (not the caller) and answers **300 Multiple Choices** with `mcptt-request-uri` = that user and `called-functional-alias-URI` = the alias. The client then calls that user, carrying the called alias. No activated user → 403/145. The follow-up INVITE is an ordinary private call, so the caller's `<PrivateCall>` list applies. | §11.1.1.4.2 step 8a, §11.1.1.2.1.1 (300 handling) |
| First-to-answer to an alias | `first-to-answer-fa <alias>` rings every activated user; the first answer wins. | §11.1.1.4.2 step 12 |
| Presentation | `fa use <alias>` adds `<functional-alias-URI>` to outgoing calls. The server presents it on terminating INVITEs and conference rosters only while the alias is activated for the caller. | §10.1.1.3.1.1 step 6a |
| Ad hoc | A participant-list entry that is an alias stands for the users that activated it, and each invitation carries `called-functional-alias-URI`. | §17.4.2.2 step 12b |
| Broadcast ad hoc | `adhoc broadcast <ids>` sets `broadcast-ind`: invitees are receive-only (Floor Deny cause 5), and the call ends with the initiator's transmission. | §17, §4.12 |

### Client commands

```bash
mcx-client --config FILE --command 'fa activate sip:patrol-car-12.alias@mcx.test'
mcx-client --config FILE --command 'fa takeover sip:duty-officer.alias@mcx.test'
mcx-client --config FILE --command 'fa deactivate sip:patrol-car-12.alias@mcx.test'
mcx-client --config FILE --command 'fa use sip:duty-officer.alias@mcx.test'      # or: fa use none
mcx-client --config FILE --command 'private-fa sip:patrol-car-12.alias@mcx.test auto'
mcx-client --config FILE --command 'first-to-answer-fa sip:patrol-car-12.alias@mcx.test'
mcx-client --config FILE --command 'adhoc sip:patrol-car-12.alias@mcx.test'
mcx-client --config FILE --command 'adhoc broadcast sip:bob.mcptt@mcx.test sip:client-c.mcptt@mcx.test'
```

The status file reports `requested_functional_aliases`, `last_fa_result` (action, aliases, status code, warning, `p_id_fa`, `take_over`, and per alias the outcome from the NOTIFY: `activated`, `deactivated`, `take-over-possible` or `refused`), `functional_alias_subscription_result`, `active_functional_aliases`, `takeover_possible_functional_aliases`, `functional_alias`, `functional_alias_redirect`, and the received `calling_functional_alias` / `called_functional_alias`. The server status reports `functional_aliases` (alias → activated MCPTT IDs in activation order).

## Running the tests

The functional-alias scenario runs in the `functional-alias` lab of the regression:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =functional-alias
```

The lab uses `--private-call --adhoc --functional-alias`. Over debug TCP SIP the run also captures at the MCPTT server
and checks the capture with `tests/integration/verify_functional_alias.py`.

| Alias | Users | Limit | Take-over |
|---|---|---|---|
| `duty-officer.alias` | client-a, client-b | 1 | allowed; only client-b has the user permission |
| `patrol-car-12.alias` | client-c, client-d | 2 | no |
| `incident-commander.alias` | client-a | 1 | never activated |

In this fixture client-d is callable (unlike the plain `--private-call` fixture), so both patrol-car-12 users can be reached.

## Checks

| ID | What is checked |
|---|---|
| FA-01 | The client subscribes to its own status first; two permitted users activate `patrol-car-12` within its limit of 2 (200, then NOTIFY `activated`) |
| FA-02 | Activation by a user outside the alias user list → 403 with warning 201 |
| FA-03 | `duty-officer` activated by a; b's activation beyond the limit → 200, then NOTIFY `take-over-possible` |
| FA-04 | b's take-over after the offer replaces a (NOTIFY `activated`), and a is notified it lost the alias; a, offered nothing, sends an activation without `<take-over>` → 200, refused in the NOTIFY, nothing changes |
| FA-05 | `private-fa patrol-car-12` → 300 naming the first activated user; the caller re-invites that user, who is told the called alias |
| FA-06 | An activated caller alias is presented on a private call and on a group call to every member; a requested alias that is not activated is not presented |
| FA-07 | `first-to-answer-fa patrol-car-12` rings both activated users; the first answer wins and the other is cancelled |
| FA-08 | An ad hoc list entry naming `patrol-car-12` invites both activated users, each told the called alias |
| FA-09 | Broadcast ad hoc call: receiver request denied with cause 5; receivers get the speech; release at transmission end |
| FA-10 | Deactivation (200, then NOTIFY without the alias) removes the user; the alias then resolves to the remaining user |
| FA-11 | An alias with no activated user → 403/145 |

Independent SIP wire checks (`verify_functional_alias.py`): PUBLISH with the presence event and the FA PIDF extension; Expires 4294967295/0; entity, tuple and alias IDs; answers 200, or 403 only with warning 201; a status SUBSCRIBE (`<request-type>functional-alias-status-determination`, Expires 4294967295) by every publishing user; a NOTIFY with the `<p-id-fa>` of each accepted PUBLISH; NOTIFYs with `status="activated"` and `status="take-over-possible"`; the take-over element only for an offered alias; `call-to-functional-alias-ind` INVITEs; a 300 naming the selected MCPTT ID and called alias; re-INVITE of that ID without the indicator; 403/145; presentation on terminating INVITEs; and no presentation of a non-activated alias.

## Coverage gaps

| Area | Gap |
|---|---|
| Status determination | The client follows its own status only (§9A.2.1.3 step 2). With separate participating and owning servers, the participating server refuses a subscription to the users of an alias (§9A.2.2.2.10). On a single server the `activating`/`deactivating` states never show, because the owning decision is immediate. The server owning the alias offers no take-over between servers, so the participating server offers it when the owning server refuses an activation the user could take over. A `take-over-possible` offer stays until the user's next request for that alias. |
| Location-based activation | §9A.2.1.4 and the manual-deactivation restriction are not implemented. |
| Group binding | Functional alias to group binding (§9A.4, warning 176) is not implemented. |
| Call-list restrictions | `<ListOfAllowedFAsToCall>` and `<ListOfAllowedFAsToBeCalledFrom>` (warnings 171/172) are not evaluated. |
| Multiple servers | Covered: the `functional-alias-split` lab runs the same scenario on separate participating and controlling servers. The participating server answers the client and passes each change on to the controlling server, which owns the aliases (per-alias PUBLISH, §9A.2.2.2.6). It follows the outcome by subscription (§9A.2.2.2.7, §9A.2.2.3.4), and the client sees `activating`, then the outcome. |
