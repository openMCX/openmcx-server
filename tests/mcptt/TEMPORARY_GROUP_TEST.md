# Temporary groups formed by the GMS

These tests cover **temporary MCS groups formed by the group management server** (TS 24.481 V19.3.0 §6.3.14 and §6.3.15) and the group and chat calls on them (TS 24.379 V19.7.0 clause 16). A temporary group combines existing groups. Unlike the [regroup using a preconfigured group](REGROUP_TEST.md), it has a group document of its own, and the request goes to the GMS over XCAP, not to the MCPTT server over SIP.

Back to the [MCPTT test index](../MCPTT_TEST.md).

## How it works

- **Formation** (§6.3.14.2, §6.3.14.3.1). The GMC sends `POST` to its users tree, `org.openmobilealliance.groups/users/{XUI}/{document}`, with an `application/vnd.3gpp.GMOP+xml` group regroup creation request (§7.3.4.3). The request carries the temporary group's document, and that document's `<on-network-temporary>` lists the constituent groups.
- **Checks by the forming GMS.** The GMS refuses with 403 a user who may not form temporary groups (`group_management.temporary` in the user's configuration). It refuses with 409 `<uniqueness-failure>` a temporary group ID that is not free or not of its own domain, and proposes an `<alt-value>` instead.
- **Group regroup check** (§6.3.14.3.2). The GMS then checks each constituent group (§7.3.4.4): the target is the node selector `…/byGroupID/{group}/~~/group/list-service/mcpttgi:on-network-regrouped[@temporary-MCPTT-group-ID="…"]` of its document.
- **Group regroup notification.** When every check succeeds, a group regroup notification (§7.3.4.5) places the `<on-network-regrouped>` element in each constituent group's document. Only then is the temporary group's document created. The answer is 200 with a group regroup creation response carrying `<temporary-group-document-ETag>` (§7.3.4.6). If one constituent group refuses, the forming GMS answers 403 and removes the marks it already placed.
- **Protection of the documents** (§7.2.12). No one creates, changes or deletes `<on-network-temporary>` or `<on-network-regrouped>` by XCAP. A document holding `<on-network-regrouped>` cannot be deleted.
- **The MCPTT servers** read both kinds of document from their GMS every 2 seconds (`GET /internal/temporary-groups`) and apply each temporary group as a group regroup (clause 16):
  - the function controlling the temporary group holds it;
  - the function controlling each constituent group marks that group regrouped, and a call on it is refused with warning **148**;
  - each function tells the affiliated members of its own constituent groups with the regroup notice of §16.2.4.1.
- **Calls.** A call on the temporary group is a group regroup call (§10.1.2.4.1 steps 5 and 6b). Its members are those of the constituent groups, and its configuration comes from the temporary group's own document. A document typed chat carries a chat group call.
- **Keys.** A protected temporary group is keyed by the GMS that formed it, with the constituent groups' members as its members (TS 33.180 §5.7).
- **Tear down** (§6.3.15). The requester or a manager sends `DELETE` of the temporary group's document. The GMS removes each constituent group's `<on-network-regrouped>` and then the document. The servers end any call on the temporary group, tell the members and free the constituent groups.

### Local choices

| Choice | Reason |
|---|---|
| The members learn of a temporary group through the regroup notice of TS 24.379 §16.2.4.1. The notice names the temporary group as its own preconfigured group. The client then reads the temporary group's document from the GMS. | TS 24.481 lets a GMC learn of it from its subscription to a constituent group's document. The notice reuses the path of the preconfigured regroup, which the client already follows. |
| A group is combined into one temporary group at a time. | The schema allows several `<on-network-regrouped>` elements, but TS 24.379 §16.2.4.1 step 2a refuses a group already regrouped. |
| A temporary group whose document names no priorities takes the priority policy of its first constituent group that has one. | `<on-network-group-priority>` is optional in the temporary group's document, and the members' clients send their provisioned Resource-Priority. |
| The node selector uses the `mcpttgi` prefix without an `xmlns()` query. | The HTTP proxies relay the path only. The owning GMS matches the selector by its element name and attribute. |

### Client commands

```bash
mcx-client --config FILE --command 'temporary-create <document> <temporary group ID> <group>,<group>... [chat] [protected]'
mcx-client --config FILE --command 'temporary-delete <document>'
mcx-client --config FILE --command 'group <temporary group ID>'   # use it, as a regroup
```

`status.json` records the last XCAP answer in `xcap_last`, with a `seq` number per answer, and the temporary groups the client has been told of in `regroups`. The server records each one in `regroups` with `"temporary": true`, and the groups it marked in `regrouped_groups`.

## Fixture

`--regroup` (`tools/prepare-prearranged-test.py`) adds two constituent groups: `operations-north` with client-a and client-b, and `operations-south` with client-c and client-d. Client-a may form temporary groups; client-b may not.

```bash
tools/regress.py --image openmcx:item1-c --select regroup   # temporary_group_scenario.py
```

## Performed tests

Recorded on **2026-09-26** against image `openmcx:item1-c` (`6c35017730b2`), built from branch `mcptt-mcdata`. Every report records **PASS**: `temporary_group_scenario.py` passed 26 checks. `regroup_scenario.py` passed on the same lab.

| ID | Checks | Result |
|---|---|---|
| TG-01 | Client-b, which may not form temporary groups, asks to form one | PASS. 403; nothing was formed |
| TG-02 | Client-a forms a temporary group of north and south | PASS. 200 with `<temporary-group-document-ETag>`; the server holds it as a controlling temporary group and marks both groups regrouped; all four members are told, with both constituents named |
| TG-03 | The same document again; a new temporary group with north | PASS. 409; 403 (north is already combined) |
| TG-04 | A call on north while it is combined | PASS. Refused with warning 148 |
| TG-05 | A group call on the temporary group | PASS. Every member reads its document and uses it; alice's call reaches bob and a member of south |
| TG-06 | Tear down by client-b, then by client-a | PASS. Client-b is refused; client-a is answered 200; the call is released, every member is told, and both groups are free |
| TG-07 | A call on north afterwards | PASS. Answered |
| TG-08 | A chat temporary group | PASS. Alice's chat call is accepted, and client-c joins the same session from south; tear down frees both groups |

The Go unit tests cover formation and tear down (authorisation, an identity of another provider, a constituent already combined and the protected marks), and the GMOP and group document elements.

## Coverage gaps

| Area | Gap |
|---|---|
| Emergency | A constituent group in an emergency state is not refused (warning 166, TS 24.379 §10.1.1.5.2.3 step 2A). |
| Non-controlling mode | Merging ongoing calls of the constituent groups into the temporary group's call (§10.1.1.5.2.3, §10.1.1.5.5) is not implemented. The controlling function invites the members as for a group regroup. |
| MCData | An MCData server does not apply temporary groups. |
| Several marks | A group in a temporary group cannot join another one at the same time. |
