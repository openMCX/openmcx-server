# Regroup using a preconfigured group

These tests cover a **regroup using a preconfigured group** (TS 24.379 V19.7.0 clause 16). An authorised user creates a temporary group that takes its whole configuration from an existing *preconfigured* group. In a **group regroup** (clause 16.2) its members come from the groups it was formed of; in a **user regroup** (clause 16.3) they are the users named in the request. The recorded results cover the implemented subset below, not complete conformance.

Back to the [MCPTT test index](../MCPTT_TEST.md). The prearranged group call the regroup carries is in the [prearranged tests](PREARRANGED_TEST.md), which describe the shared four-client fixture. Blocker entry: S13.

## How it works

- **The preconfigured group** holds the configuration. It is marked `<preconfigured-group-use-only>`, so it cannot be called directly (warning 167), and clause 16.1 says every server and client is configured with it so that the regroup can be used the moment it exists. The regroup's `<preconfigured-group-use-only>` is dropped, since the regroup itself is meant to be called.
- **Creation** (§16.2.1.1). The client sends a SIP MESSAGE to its own MCPTT service identity with an `application/vnd.3gpp.mcptt-regroup+xml` body carrying `<regroup-action>create</regroup-action>`, a unique temporary group identity, the preconfigured group and the list of constituent groups.
- **The participating function** (§16.2.2.2 step 3) authorises the user from its profile: without `<allow-regroup>` the request is refused 403 with warning **160**, and a removal with warning **161**. It then sends the request to the controlling function of the preconfigured group.
- **The controlling function** (§16.2.3.1) refuses 480 if it cannot serve the preconfigured group, and 403 with warning **165** if the proposed identity is already in use. It offers each constituent group to that group's own controlling function, which acts as a **non-controlling** function for the regroup (§16.2.4.1) and refuses with warning **148** if its group is already regrouped. Only when every one of them has accepted is the regroup stored and the client answered 200; if any refuses, the ones that accepted are told to remove it again and the client gets 480.
- **While the regroup exists**, each constituent group is regrouped: a call on it is refused with warning **148**. A call on the temporary group identity is an ordinary prearranged group call whose document is the preconfigured group's and whose members are the union of the constituent groups'.
- **A user regroup** (§16.3) is requested the same way, with `<users-for-regroup>` instead of `<groups-for-regroup>`. The controlling function of the preconfigured group splits the users by the **terminating participating function** that serves each of them (§16.3.3.1 step 4) and sends each function its own users. That function answers 200, tells each of its users of the regroup (the notice names the users and no groups) and **considers them affiliated** with it (§16.3.2.4 step 3h). The controlling function creates the regroup once any function has accepted, and answers 480 if none has. No group is regrouped, and a member is invited to a call on the regroup without having selected it.
- **Removal** (§16.2.3.2) is authorised the same way, releases any call on the regroup, frees the constituent groups and tells every member. For a user regroup, each participating function is sent its own affiliated users (step 6) and tells them with a notice that names neither list (§16.2.2.5). An unknown regroup is refused 403 with warning **163**, and a regroup whose in-progress emergency state is set with warning **169** (steps 2 and 3).

## Implemented profile

| Area | Behaviour | Reference |
|---|---|---|
| Request body | `<mcpttregroup>` with `<preconfig-group-id>`, `<mcptt-regroup-uri>`, `<groups-for-regroup>` or `<users-for-regroup>`, and `<regroup-action>`; at most 64 entries, no duplicates, and groups or users but not both. A removal carries only the identity and the action, and `<preconfigured-group>` is optional in it | §16.2.1.1, §16.2.1.2, §16.3.1.1, F.7.2, F.7.3 |
| Authorisation | `<allow-regroup>` in the user profile (`regroup` in the CMS user document); 160 on create, 161 on remove | §16.2.2.2, §16.2.2.3 |
| Creation | 480 when the preconfigured group is not served here, 403 with 165 when the identity is in use (as a regroup, as a regrouped group or as a group in the GMS), the constituent groups offered to their own controlling functions, and the regroup stored only when all accept | §16.2.3.1 |
| Non-controlling | A constituent group that is already regrouped is refused with 148; otherwise its controlling function marks it regrouped and tells its affiliated members | §16.2.4.1 |
| Use | The regroup's document is the preconfigured group's without `<preconfigured-group-use-only>`, and its members are the union of the constituent groups'; the client selects it without a document of its own | §16.1 |
| Constituent groups | A call on a regrouped group is refused 403 with warning 148 | §10.1.1.4.1 step 4c |
| User regroup creation | 480 when the preconfigured group is not served here, 165 when the identity is in use, one request per terminating participating function with its own users, and the regroup created when any function accepts (480 when none does). A user with no registration at the controlling function is taken to be served by its own participating function | §16.3.3.1 |
| User regroup members | Each participating function tells its users, without `<groups-for-regroup>`, considers them affiliated with the regroup and keeps the regroup until it is removed. The regroup's members are the named users, and no group is regrouped | §16.3.2.4 |
| User regroup calls | A member is invited to a call on the regroup without having selected it, and the client takes the call on the regroup | §16.2.1.3 step 4, §16.3.1.3 |
| Removal | 403 with warning 163 for an unknown regroup, 403 with warning 169 while the regroup is in an in-progress emergency state; otherwise the call is released, the groups are freed and every member is told. The members of a user regroup are told by their participating function, with a notice that names neither list | §16.2.1.2, §16.2.2.5, §16.2.3.2, §16.2.4.2 |
| Notification | Members of the constituent groups, and members that have already moved to the regroup, are told of the creation and of the removal of a group regroup | §16.2.1.3, §16.2.1.4 |
| Between servers | A regroup request from another MCPTT function asserts that function's identity. The receiving server handles it as the terminating participating function of a user regroup or the non-controlling function of a group regroup, and only the function that controls a regroup may change it. A participating function that passes a group regroup notice on to its user keeps the regroup until the removal notice, so the user can affiliate to it and call it | §16.2.2.4, §16.2.4, §16.3.2.4 |
| Additional members | A user that affiliates to a constituent group after the regroup exists is told of it by the function controlling that group, and can use it | §16.2.4.3 |
| Calls on a regroup | A call whose group identity is a group regroup names the constituent group it is placed from in `<mcptt-calling-group-id>`: without it the call is refused 403, and with a group that is not a constituent 403 with warning 120. Affiliation to that constituent is the affiliation the call needs (NOTE 4), so a member calls a regroup from its own group. A chat regroup carries a chat group call, since the regroup takes the preconfigured group's type | §10.1.2.4.1 steps 5, 5a, 6b; §10.1.1.4.1 |
| Regrouped constituent | A call on a regrouped group is refused 403 with warning 148, and the caller is sent a copy of the notification of the regroup its group is in, so a client that missed it learns the identity to use | §10.1.2.4.1 step 4c |
| Removal by the controlling function | `regroup-remove <tgi>` on the controlling server removes a group or user regroup it created, with the same notifications as a requested removal; the emergency state does not hold it | §16.2.3.3 |
| Across functions | A constituent group controlled by another function is offered to that function, which marks it regrouped, refuses its calls (148) and notifies its members; that function's refusal (148) reaches the requester as 480 with the warning. A user regroup's members served by another participating function are notified and held affiliated by their own function | §16.2.4.1, §16.3.2.4 |

### Client commands and status

```bash
mcx-client --config FILE --command 'regroup create <tgi> <preconfigured group> <group>[,<group>...]'
mcx-client --config FILE --command 'regroup users <tgi> <preconfigured group> <MCPTT ID>[,<MCPTT ID>...]'
mcx-client --config FILE --command 'regroup remove <tgi>'
openmcx-mcptt-server --config FILE --command 'regroup-remove <tgi>'   # 16.2.3.3: the controlling function decides
mcx-client --config FILE --command 'group <tgi>'      # use the regroup for a call
mcx-client --config FILE --command 'group <tgi> from=<group>'   # test aid: name the calling constituent, "from=" none
```

`status.json` records `regroups` (each regroup the client has been told of, with its preconfigured group and its constituent groups or users) and `regroup_result` (the action, identity, status and warning of the last request); `call_group` names the regroup of a call taken on a user regroup. The server records `regroups` (with `users`, `affiliated` and the `controller`) and `regrouped_groups`.

## Fixture and commands

`--regroup` adds a preconfigured group `operations-preconf` (marked preconfigured-use-only, all four users) and two constituent groups: `operations-north` with client-a and client-b, and `operations-south` with client-c and client-d. Each client is affiliated to its own constituent group. Only client-a has `<allow-regroup>`. The group regroup is `operations-regroup-1`; the user regroup `operations-regroup-2` names client-a and client-c.

```bash
docker build -t openmcx:0.51-regroup -f docker/Dockerfile .
python3 tools/prepare-prearranged-test.py --directory artifacts/regroup-lab --project openmcx-regroup \
  --debug-sip --regroup --image openmcx:0.51-regroup
C=".cache/deps/docker-compose-linux-x86_64 -p openmcx-regroup -f artifacts/regroup-lab/compose.json"
$C up -d mcptt-server                        # start the capture before the clients authorise
docker run -d --rm --name openmcx-regroup-capture --network "container:$($C ps -q mcptt-server)" \
  --cap-drop ALL --cap-add NET_RAW openmcx-dev:0.1 \
  sh -c "tcpdump -Z root -i eth0 -U --immediate-mode -s 0 -w /tmp/c.pcap 'tcp port 5060'"
$C up -d
python3 tests/integration/regroup_scenario.py \
  --compose artifacts/regroup-lab/compose.json --artifacts artifacts/regroup-lab/artifacts --project openmcx-regroup
docker cp openmcx-regroup-capture:/tmp/c.pcap artifacts/regroup-lab/artifacts/integration/regroup.pcap
python3 tests/integration/verify_regroup.py artifacts/regroup-lab/artifacts/integration/regroup.pcap \
  --service sip:mcptt@mcx.test --output artifacts/regroup-lab/artifacts/integration/regroup-sip-wire.json
docker rm -f openmcx-regroup-capture         # the reports and the capture are kept; the lab is not
$C down -v
```

## Performed tests

Recorded on **2026-09-24** against image `openmcx:0.52-chatregroup` (`d51a902eba46`), TS 24.379 V19.7.0, clear SIP (debug mode), in fresh labs. Every report records **PASS**: 69 scenario assertions on one server and the same 69 on the split system (`--split --regroup`: controlling function on `mcptt-server`, clients served by `mcptt-part-1` and `mcptt-part-2`), where each request crosses from a participating server. On the same image every MCPTT call type passed on one server instance and on the split system (prearranged, failure/refresh, broadcast, private, chat, ad hoc, remote-group and ambient listening). The 24 wire checks below were recorded on `openmcx:0.51-regroup` (`28e9cd400f45`) with the 42 assertions of RG-01 to RU-05.

| ID | Scenario | Result evidence |
|---|---|---|
| RG-01 | A user without `<allow-regroup>` asks for a regroup | PASS. Refused 403 with warning 160 by its own participating function, and nothing is created |
| RG-02 | An authorised user creates the regroup | PASS. Answered 200; every affiliated member of both constituent groups is told, with the preconfigured group and both constituents named; the server records it |
| RG-03 | A second regroup with the same identity | PASS. Refused 403 with warning 165 |
| RG-04 | A call on a constituent group while it is regrouped | PASS. Refused with warning 148 |
| RG-05 | A call on the temporary group identity | PASS. Each client uses the regroup without a document of its own, all four affiliate, and the call joins members of both constituent groups |
| RG-06 | A user without `<allow-regroup>` asks for removal | PASS. Refused 403 with warning 161, and the regroup is still held |
| RG-07 | Removal by an authorised user | PASS. Answered 200; every member is told, the call on the regroup is released and the server no longer holds it |
| RG-08 | The constituent groups after removal | PASS. The members select them again and a call is answered |
| RG-09 | Removing a regroup that does not exist | PASS. Refused 403 with warning 163 |
| RU-01 | A user without `<allow-regroup>` asks for a user regroup | PASS. Refused 403 with warning 160 |
| RU-02 | An authorised user creates a user regroup of client-a and client-c | PASS. Answered 200; both named users are told, with the preconfigured group and the users named and no groups; client-b and client-d are not told; the server holds the regroup with both users affiliated, and no constituent group is regrouped |
| RU-03 | A second regroup with the same identity | PASS. Refused 403 with warning 165 |
| RU-04 | A call on the user regroup | PASS. client-a selects the regroup and calls; client-c, which still has its own constituent group selected, is invited and takes the call on the regroup; client-b and client-d are not invited |
| RU-05 | Removal of the user regroup | PASS. Refused 403 with warning 161 for client-b; answered 200 for client-a; both members are told, the call is released and the server no longer holds it; a second removal is refused 403 with warning 163 |
| RG-10 | A member that affiliates after the regroup exists (16.2.4.3) | PASS. With client-d not affiliated, a regroup is created and client-d is not told; when it affiliates to its constituent group again it is told, with the preconfigured group and both constituents |
| RG-11 | The controlling function removes a group regroup on its own decision (16.2.3.3) | PASS. Every member is told, the server no longer holds it and the constituent groups are free |
| RU-06 | The same for a user regroup | PASS. Both users are told and the server no longer holds it |
| RC-01 | A regroup whose preconfigured group is a chat group | PASS. Created and notified to every member of both constituents; the regroup carries the chat configuration |
| RC-02 | A chat group call on the regroup (steps 5 and 5a) | PASS. Client-a calls from its own constituent group and is accepted; client-c joins the same session from the other constituent, each naming the group it calls from |
| RC-03 | A call naming a group that is not a constituent (step 6b) | PASS. Refused 403 with warning 120 |
| RC-04 | A call on a regroup that names no calling group (step 5a) | PASS. Refused 403, without a warning, before the affiliation check |
| RC-05 | A call on a regrouped constituent group (step 4c-ii) | PASS. Refused with warning 148, and the caller is sent a copy of the notification of the regroup its group is now in |
| RC-06 | Removal of the chat regroup | PASS. Every member is told and both constituent groups are free |

### Wire verification

[`verify_regroup.py`](../../tests/integration/verify_regroup.py) decodes the capture independently of the implementation, reading the regroup bodies against the schema of F.7.2. All 24 checks PASS over 259 SIP messages: 12 regroup requests and 12 notifications, answered 200 four times and 403 eight times.

| Check | Evidence |
|---|---|
| Request | A SIP MESSAGE to the MCPTT service identity carrying the regroup body, with the MCPTT client ID and the service identity |
| Body | Every body carries an action and a temporary group identity, and every creation its preconfigured group; no body names both groups and users; a group regroup creation names the constituent groups, a user regroup creation names the users, and a removal request names only the identity and the action |
| Outcomes | Created and removed with 200; refusals 160, 161, 165 and 163 each 403 with a Warning header field |
| Group regroup notification | Both the creation and the removal are notified; each repeats the identity, the preconfigured group and the constituents |
| User regroup notification | Both the creation and the removal are notified; a creation names the users and no groups and reaches exactly the users named, and a removal names neither list |
| Delivery | Every notification is addressed to the member and asserts the MCPTT service |
| Use | A call is placed on each temporary group identity and accepted; a member of the user regroup is invited to its call and answers; a call on a regrouped constituent group is refused with 148; the constituent carries a call again once the regroup is removed |

## Coverage gaps

| Area | Gap |
|---|---|
| User regroup across servers | Recorded on the split system. A user the controlling function holds no registration for is taken to be served by its own participating function |
| Function identity | A request from one MCPTT function to another is recognised by its source peer and an asserted identity that is not a user registered through that peer. The participating function relays a user's own request with the user's identity rather than its own (§16.2.2.2 step 5e), since the controlling function authorises the user by it |
| Emergency state | A regroup in an in-progress emergency state is not removed (warning 169), but the state is read from this server's own priority record; §16.2.1.2 leaves the check to the client as well. No recorded run puts a regroup in an emergency state |
| Client affiliation | The client takes a call on a user regroup it has been told of, but its affiliation status still reports only its selected group |
| Security | The regroup takes the preconfigured group's keys with the rest of its configuration; protected regroups using a preconfigured group were not tested. |
| Constituent fan-out | Step 11b of §10.1.2.4.1 is not implemented: the controlling function does not send the INVITE of §10.1.2.4.1.1A to the non-controlling function of each other constituent group. It reaches those members directly instead, which works because a partner system registers its users' affiliations to the regroup, but means a constituent group's own function is not in the path of the call |
| Off-network | Regroup is on-network only here (H3) |
