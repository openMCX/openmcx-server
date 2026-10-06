# MCVideo functional alias tests

These tests cover **step V8c of increment V8 of the MCVideo plan**: functional aliases (TS 24.281 V19.6.0 clause 20). They cover the status change (activation, take-over, deactivation), the status determination subscriptions, the alias presented in calls, a private call to an alias, and the binding of an alias to a group.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SVC-02).

## How it works

- **Shared with MCPTT.** Clause 20 follows TS 24.379 clause 9A, and the shared core serves both services.
  - The status subscriptions and the group binding are new in the core, so an MCPTT server now serves them too (TS 24.379 9A.2.2.2.4, 9A.4).
  - The MCPTT lab client has no commands for them yet.
- **Definitions.** The CMS keeps each alias with its `<mcvideo-user-list>` (`mcvideo_users`, TS 24.484 9.4.2), its activation limit and whether take-over is allowed.
  - `mcvideo-server` checks an activation against `mcvideo_users`; `mcptt-server` keeps using the MCPTT list (`users`).
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
- **Codec fix.** `<functional-alias-URI>` and `<called-functional-alias-URI>` are `contentType` in the schemas of both TS 24.379 and TS 24.281, so the URI goes in `<mcpttURI>` or `<mcvideoURI>`.
  - The shared codec sent the bare URI. It now wraps it, as the MCData codec already did.
  - It still accepts a bare URI from an older peer.

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
tools/regress.py --image openmcx:v8c3 --client-image openmcx-client:v8c3 --select mcvideo-functional-alias
```

The lab (`--mcvideo`) defines:
- `video-dispatcher` for client-a and client-b: one activation, take-over allowed; only client-b has the take-over right.
- `video-medic` for client-b and client-c: two activations.
- Only client-b may bind aliases to groups.

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| MV-FA-01 | 2026-09-27 | `openmcx:v8c3` (`377058b882e6`), `openmcx-client:v8c3` (`6083c8fe2060`) | client-c's status subscription gets the per-user status, with no alias. client-b's subscription to video-dispatcher gets the per-alias status, with no user. client-d, outside its user list, is refused with 403 | Passed |
| MV-FA-02 | 2026-09-27 | same | client-a activates video-dispatcher with 200. The server holds it for client-a, and client-b is notified that client-a holds it | Passed |
| MV-FA-03 | 2026-09-27 | same | client-c, not in the user list, is refused with 403. client-b's plain activation beyond the limit is refused with 403, and client-a keeps the alias | Passed |
| MV-FA-04 | 2026-09-27 | same | client-b takes video-dispatcher over with 200, and its subscription shows it as the user. client-a, without the take-over right, is refused with 403 | Passed |
| MV-FA-05 | 2026-09-27 | same | client-a, not following its status, still presents video-dispatcher in a private call to client-b. The server leaves the alias out, and client-b is shown none | Passed |
| MV-FA-06 | 2026-09-27 | same | client-b presents video-dispatcher in a group call. client-a and client-c are called by it, and the conference event lists it for client-b | Passed |
| MV-FA-07 | 2026-09-27 | same | client-b binds video-dispatcher to the group with 200, and again with 200. Binding video-medic to the same group is refused with 403 `178`, and client-c's unbinding with 403 `176`. In a group call where client-b presents no alias, the members are shown no calling alias, and the conference event lists client-b with its bound alias. The unbinding is accepted with 200 | Passed |
| MV-FA-08 | 2026-09-27 | same | client-a subscribes to its own status and learns it no longer holds video-dispatcher | Passed |
| MV-FA-09 | 2026-09-27 | same | client-c activates video-medic, and its NOTIFY lists it with the `<p-id-fa>` of its PUBLISH. client-a's call to video-medic is answered with 300 naming client-c. client-a then calls client-c, which is told it was called by video-medic | Passed |
| MV-FA-10 | 2026-09-27 | same | client-c deactivates video-medic with 200, and its NOTIFY lists no alias. A call to the alias is then refused with 403 `145` | Passed |
| MV-FA-11 | 2026-09-27 | same | client-b ends its subscription to video-dispatcher. A fetch (Expires 0) then returns client-b and leaves no subscription | Passed |
| MV-FA-12 | 2026-09-27 | same | Captured at `mcvideo-server` over debug TCP. The alias PUBLISHes use `mcvideoPresInfoFA`, and no MCPTT alias namespace; an activation has Expires 4294967295 and a deactivation Expires 0, and the take-over carries `<take-over>`. The SUBSCRIBEs carry both `<req-type>` values, and the NOTIFYs have `status="activated"` and the `user` attribute. The binding MESSAGEs carry `fa-group-binding-req`, `<binding-ind>`, `<binding-fa-uri>` or `<unbinding-fa-uri>`, and the group. The call to the alias has `<call-to-functional-alias-ind>`; the call after the 300 has `<called-functional-alias-URI>` in `<mcvideoURI>` without the indication; and the 300 names client-c | Passed |

Run results:
- **2026-10-06, status flow (200 + NOTIFY outcome, take-over after `take-over-possible`):** images `openmcx-*:alias` (`openmcx-mcvideo-server` `b29ead2c37d4`) and `openmcx-client:alias` (`161fd41621dd`), debug TCP: 80 checks, all passed. MV-FA-03 now expects 200 with the outcome `refused` / `take-over-possible` in the NOTIFY. MV-FA-04 expects client-b's take-over (`<take-over>`) to be `activated`, and client-a's to go without `<take-over>` (200). The rows below are from the earlier runs.
- **Debug TCP:** the scenario made 76 checks (`artifacts/regress-v8c-tcp/mcvideo-functional-alias/`, capture `artifacts/integration/mcvideo-functional-alias.pcap`).
- **TLS:** it made 64 checks with the wire checks skipped (`artifacts/regress-v8c-tls/`).
- **MCPTT:** the `functional-alias` lab passed on the same images over both, since the core and the codec are shared. The `mcvideo` lab passed over TCP on the earlier V8c.1 images, which already had the codec fix.
- **Unit tests:** the native unit tests (27) and the Go CMS tests pass. They cover:
  - the MCVideo PIDF namespace, and the mixed namespace refused
  - the per-user and per-alias status bodies
  - the `contentType` alias URIs, with a bare URI still accepted
  - warnings 176 to 178
  - `mcvideo_users`, and an alias equal to an MCVideo ID refused

Defects found by the runs and fixed:
- The shared codec sent `<functional-alias-URI>` and `<called-functional-alias-URI>` as bare URIs, not in the `contentType` form of the TS 24.379 and TS 24.281 schemas.
- The client's call to an alias lost its context before the 300 arrived: the dialog's end ran before the response handler, so the redirect was dropped.
- A per-alias NOTIFY with no user has no entry to show its kind. The client now decides by the entity it subscribed to.

## Coverage gaps

| Area | Gap |
|---|---|
| Status values | The per-user status reports `activated` and `take-over-possible`. The `activating` and `deactivating` states, and the `expires` attribute, are not sent: activation is decided at once. An offer stays until the user's next request for that alias |
| Refresh and expiry | Activations do not expire, so there is no refresh near expiry (§20.2.1.2) and no automatic deactivation by expiry (§20.2.2.3.6). Deactivation by an administrator is not provided |
| Other users' status | A subscription to another user's aliases (§20.2.2.2.4 step 4) is refused, since there is no policy for it |
| Separate servers | With an alias controller, the participating function relays status changes but refuses status subscriptions: it does not hold the aliases. MCVideo on separate servers comes with V10 |
| Location-based aliases | Activation by location (§20.2.1.4) and `<manual-deactivation-not-allowed-if-location-criteria-met>` come with location (V8e) |
| Alias-to-alias policy | Warnings 171 and 172, for an alias that may not call or be called by another alias, are not implemented: the alias definitions carry no such policy |
| Warning 177 | Not exercised: the client always sends the alias and the groups |
| Filters | The `application/simple-filter+xml` of §20.3.2 is neither sent nor read |
| MCPTT client | The server procedures for status subscriptions and binding apply to MCPTT, but the MCPTT lab client has no commands for them |
| MCData | The MCData server's status subscriptions and binding (TS 24.282 clause 22) are unchanged, and still not implemented |
