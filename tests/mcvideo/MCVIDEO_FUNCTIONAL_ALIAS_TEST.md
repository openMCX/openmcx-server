# MCVideo functional alias tests

Functional aliases (TS 24.281 clause 20): the status change (activation, take-over, deactivation), the status determination subscriptions, the alias presented in calls, a private call to an alias, and the binding of an alias to a group.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SVC-02).

## How it works

- **Shared with MCPTT.** Clause 20 follows TS 24.379 clause 9A, and the shared core serves both services.
  - The status subscriptions and the group binding are served for MCPTT too (TS 24.379 9A.2.2.2.4, 9A.4).
  - The MCPTT lab client has no commands for them.
- **Definitions.** The CMS keeps each alias with its `<mcvideo-user-list>` (`mcvideo_users`, TS 24.484 9.4.2), its activation limit and whether take-over is allowed.
  - `mcvideo-server` checks an activation against `mcvideo_users`; `mcptt-server` uses the MCPTT list (`users`).
  - The MCVideo profile rights are `functional_alias_takeover` (`<allow-takeover-functional-alias-other-user>`) and `functional_alias_binding` (`<allow-functional-alias-binding-with-group>`).
- **Status change (§20.2.1.2).**
  - The client sends a PUBLISH to the MCVideo PSI with its mcvideo-info and a PIDF in `urn:3gpp:ns:mcvideoPresInfoFA:1.0`.
  - Expires 4294967295 activates the listed aliases, and a `<take-over>true</take-over>` takes them over. Expires 0 deactivates them.
  - The client sends `<take-over>` only for aliases its own status NOTIFY offered as `take-over-possible` (step 6 d)). A take-over asked before the offer goes as an activation and follows once offered.
  - The participating function answers 200 (§20.2.2.2.3 step 8; TS 24.281 has no step 4B). The owning checks decide each alias on its own, and the outcome reaches the user only in the NOTIFY of its own status subscription (§20.2.2.2.5): the alias `activated`, `take-over-possible` (at its limit, with `allow_takeover` and the user's right), or left out when refused. A client that does not follow its own status counts an accepted request as done.
  - A PIDF of another service's namespace is refused with 400.
- **Status determination (§20.2.1.3, §20.2.2.2.4 and .5, §20.2.2.3.4 and .5).** The client sends a SUBSCRIBE (Event `presence`) with `<req-type>`:
  - `functional-alias-status-determination` for its own aliases. The NOTIFY carries the per-user status: entity the user, tuple the client ID, one `<functionalAlias functionalAliasID status="activated">` per alias, and `status="take-over-possible"` for the aliases offered for take-over.
  - `fa-user-status-determination` for the users of an alias. The NOTIFY carries the per-alias status: entity and tuple the alias, one `<functionalAlias user>` per user.
    - As local policy (§20.2.2.3.4 step 5), only the users that may activate the alias may follow it. Others get 403, as does an unknown alias.
  - Every activation, take-over, deactivation or end of service authorisation sends a NOTIFY to the subscriptions it concerns.
    - The publisher's own per-user NOTIFY and the per-alias NOTIFYs carry the PUBLISH's `<p-id-fa>`.
    - A user whose alias was taken over learns it from its own subscription.
  - Expires 0 fetches the state once. An in-dialog SUBSCRIBE with Expires 0 ends the subscription.
- **Aliases in calls.** The client presents the alias it chose (`mcvideo-fa use`) in `<functional-alias-URI>` while that alias is active.
  - The server passes it on only if the user holds the alias, and lists it in the conference event.
  - A private call to an alias (`<call-to-functional-alias-ind>`) is answered with 300 naming, in `<mcvideo-request-uri>`, a user who activated it.
  - The client then calls that user with `<called-functional-alias-URI>`.
  - An alias no user holds is refused with 403 `145`.
- **Group binding (§20.4).** The client sends a MESSAGE with `<request-type>fa-group-binding-req</request-type>`, `<binding-ind>`, the alias in `<binding-fa-uri>` or `<unbinding-fa-uri>`, and the groups in a resource-lists body.
  - Without the binding right it is refused with 403 `176`; without the alias or the groups, with 403 `177`.
  - A group bound to another alias of the same user is refused with 403 `178`.
  - The conference event lists a participant with the alias it bound to the call's group, while the alias is active, when it presents none (§6.3.3.4 step 2b-iii).
- **Alias URIs.** `<functional-alias-URI>` and `<called-functional-alias-URI>` are `contentType` in the schemas of both TS 24.379 and TS 24.281, so the URI goes in `<mcpttURI>` or `<mcvideoURI>`. A bare URI from a peer is still accepted.

## Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-fa activate|takeover|deactivate <alias>...'
mcx-client --config FILE --command 'mcvideo-fa use <alias>|none'
mcx-client --config FILE --command 'mcvideo-fa-subscribe [alias]'      # own aliases, or the users of an alias
mcx-client --config FILE --command 'mcvideo-fa-fetch [alias]'          # the same, once (Expires 0)
mcx-client --config FILE --command 'mcvideo-fa-unsubscribe [alias]'
mcx-client --config FILE --command 'mcvideo-private-fa <alias> [auto|manual|force-auto]'
mcx-client --config FILE --command 'mcvideo-fa-bind|mcvideo-fa-unbind <alias> <group>[,<group>...]'
```

`status.json` adds:
- `mcvideo_functional_aliases`: the aliases this user holds, from the 200 responses and the per-user NOTIFYs
- `mcvideo_functional_alias_in_use`, `mcvideo_functional_alias_result`, `mcvideo_functional_alias_redirect`
- `mcvideo_functional_alias_subscriptions`, `mcvideo_functional_alias_subscription_result`, `mcvideo_functional_alias_notified`, `mcvideo_alias_users`
- `mcvideo_functional_alias_binding_result`
- for a call: `mcvideo_calling_functional_alias`, `mcvideo_called_functional_alias` and `mcvideo_participant_aliases`

## Running the tests

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-functional-alias
```

The lab (`--mcvideo`) defines:
- `control-room` for client-a and client-b: one activation, take-over allowed; only client-b has the take-over right.
- `patrol-car-12-camera` for client-b and client-c: two activations.
- Only client-b may bind aliases to groups.

The scenario makes 80 checks over debug TCP; over TLS the wire checks (MV-FA-12) are skipped. The MCPTT `functional-alias` lab runs on the same shared core and codec. The native unit tests and the Go CMS tests cover the MCVideo PIDF namespace and the refused mixed namespace, the per-user and per-alias status bodies, the `contentType` alias URIs with a bare URI still accepted, warnings 176 to 178, `mcvideo_users`, and an alias equal to an MCVideo ID refused.

## Tests

| ID | What is checked |
|---|---|
| MV-FA-01 | client-c's status subscription gets the per-user status, with no alias. client-b's subscription to control-room gets the per-alias status, with no user. client-d, outside its user list, is refused with 403 |
| MV-FA-02 | client-a activates control-room with 200. The server holds it for client-a, and client-b is notified that client-a holds it |
| MV-FA-03 | client-c, not in the user list, asks for control-room: 200, and its status NOTIFY leaves the alias out. client-b's plain activation beyond the limit: 200, and its NOTIFY offers the alias as `take-over-possible`. client-a keeps the alias |
| MV-FA-04 | client-b takes control-room over with `<take-over>`, the alias is `activated` for it, and its subscription shows it as the user. client-a, without the take-over right, sends no `<take-over>` (200) and does not get the alias back |
| MV-FA-05 | client-a, not following its status, still presents control-room in a private call to client-b. The server leaves the alias out, and client-b is shown none |
| MV-FA-06 | client-b presents control-room in a group call. client-a and client-c are called by it, and the conference event lists it for client-b |
| MV-FA-07 | client-b binds control-room to the group with 200, and again with 200. Binding patrol-car-12-camera to the same group is refused with 403 `178`, and client-c's unbinding with 403 `176`. In a group call where client-b presents no alias, the members are shown no calling alias, and the conference event lists client-b with its bound alias. The unbinding is accepted with 200 |
| MV-FA-08 | client-a subscribes to its own status and learns it no longer holds control-room |
| MV-FA-09 | client-c activates patrol-car-12-camera, and its NOTIFY lists it with the `<p-id-fa>` of its PUBLISH. client-a's call to patrol-car-12-camera is answered with 300 naming client-c. client-a then calls client-c, which is told it was called by patrol-car-12-camera |
| MV-FA-10 | client-c deactivates patrol-car-12-camera with 200, and its NOTIFY lists no alias. A call to the alias is then refused with 403 `145` |
| MV-FA-11 | client-b ends its subscription to control-room. A fetch (Expires 0) then returns client-b and leaves no subscription |
| MV-FA-12 | Captured at `mcvideo-server` over debug TCP. The alias PUBLISHes use `mcvideoPresInfoFA`, and no MCPTT alias namespace; an activation has Expires 4294967295 and a deactivation Expires 0, and the take-over carries `<take-over>`. The SUBSCRIBEs carry both `<req-type>` values, and the NOTIFYs have `status="activated"` and the `user` attribute. The binding MESSAGEs carry `fa-group-binding-req`, `<binding-ind>`, `<binding-fa-uri>` or `<unbinding-fa-uri>`, and the group. The call to the alias has `<call-to-functional-alias-ind>`; the call after the 300 has `<called-functional-alias-URI>` in `<mcvideoURI>` without the indication; and the 300 names client-c |

## Coverage gaps

| Area | Gap |
|---|---|
| Status values | The per-user status reports `activated` and `take-over-possible`. The `activating` and `deactivating` states, and the `expires` attribute, are not sent: activation is decided at once. An offer stays until the user's next request for that alias |
| Refresh and expiry | Activations do not expire, so there is no refresh near expiry (§20.2.1.2) and no automatic deactivation by expiry (§20.2.2.3.6). Deactivation by an administrator is not provided |
| Other users' status | A subscription to another user's aliases (§20.2.2.2.4 step 4) is refused, since there is no policy for it |
| Separate servers | With an alias controller, the participating function relays status changes but refuses status subscriptions: it does not hold the aliases |
| Location-based aliases | Activation by location (§20.2.1.4) and `<manual-deactivation-not-allowed-if-location-criteria-met>` are not implemented |
| Alias-to-alias policy | Warnings 171 and 172, for an alias that may not call or be called by another alias, are not implemented: the alias definitions carry no such policy |
| Warning 177 | Not exercised: the client always sends the alias and the groups |
| Filters | The `application/simple-filter+xml` of §20.3.2 is neither sent nor read |
| MCPTT client | The server procedures for status subscriptions and binding apply to MCPTT, but the MCPTT lab client has no commands for them |
| MCData | The MCData server's status subscriptions and binding (TS 24.282 clause 22) are not implemented |
