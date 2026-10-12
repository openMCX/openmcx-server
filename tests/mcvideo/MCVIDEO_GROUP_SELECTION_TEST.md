# MCVideo remote group selection tests

The remote change of an MCVideo user's selected group (TS 24.281 9.2.4): a change that makes the target affiliate first, a change to a group it is already affiliated to, a call on the newly selected group, and the refusals 155, 120 and 167.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SVC-01).

## How it works

- **Shared with MCPTT.** 9.2.4 follows TS 24.379 10.1.4. The procedure is in the shared core, beside the remotely initiated group call, which has the same shape.
  - The MCPTT server serves it too.
  - The MCPTT lab client has no command for it, and the CMS has no MCPTT form of the list below.
- **Request (9.2.4.2.1).** The requesting client sends a MESSAGE to the MCVideo PSI with:
  - `<request-type>group-selection-change-request</request-type>`
  - the group in `<mcvideo-request-uri>`
  - the targeted user in a resource-lists body.
- **Checks at the server** (combined participating and controlling function):
  - The targeted user must be in the requester's `<RemoteGroupSelectionURIList>` (`remote_group_selection` in the MCVideo profile), or the request is refused with 403 `155`.
    - Step 3a-ii of 9.2.4.3.1 names `<mcvideo-request-uri>`, which holds the group. As in the client procedure (step 1), the server checks the targeted user.
    - Warning 155 is missing from the table of TS 24.281 4.4.2, but step 3a gives its text.
  - A preconfigured-use-only group is refused with 403 `167` (9.2.4.4 step 2A).
  - A target not affiliated to the group must be a member of it, or the request is refused with 403 `120`. A member gets `<affiliation-required>true</affiliation-required>` (steps 3a and 8a).
- **Relay.** The server sends the request to the target with the group in `<mcvideo-calling-group-id>` and the requester in `<mcvideo-calling-user-id>`, and answers the requester 200.
- **Target (9.2.4.2.2).**
  - With `<affiliation-required>`, the target affiliates to the group. It waits for the NOTIFY whose `<p-id>` is that of its PUBLISH, and checks the group is affiliated there (step 1c).
  - It then selects the group. The group selected before stays affiliated, as an extra group.
  - It sends back `<response-type>group-selection-change-response</response-type>` with `<selected-group-change-outcome>` `success` or `fail`, and the requester in the resource list. The server relays this to the requester.
- **Selected group.** The target's calls without a named group, and its affiliation requests, use the selected group.

## Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-select-remote <MCVideo ID> <group>'
```

`status.json` adds:
- `mcvideo_selected_group`: the selected group
- `mcvideo_group_selection_result`: this user's last request, with its response, Warning and the target's outcome
- `mcvideo_group_selection`: the last request received, with whether it asked to affiliate, and the outcome sent

## Running the tests

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-group-selection
```

The lab (`--mcvideo`) adds:
- `video-field`, a second prearranged group of the four users, to which none is affiliated at the start. It carries the MCVideo group's priority policy, which the call on it needs.
- client-a may change the selected group of client-b and client-d.

The scenario makes 28 checks over debug TCP and 25 over TLS, where the wire checks (MV-SG-07) are skipped.

## Tests

| ID | What is checked |
|---|---|
| MV-SG-01 | client-a asks to change client-b's selected group to video-field and gets 200. client-b is asked to affiliate, and the server then holds its affiliation. client-b selects video-field, keeps its affiliation to the first group, and reports success, which client-a is told |
| MV-SG-02 | client-a and client-c affiliate to video-field. client-b's next call, naming no group, is on video-field and reaches both; client-d, not affiliated to it, is not in it |
| MV-SG-03 | A change back to the first group, to which client-b is affiliated, is accepted without asking it to affiliate, and client-b selects it |
| MV-SG-04 | client-c, whose list does not name client-b, is refused with 403 `155` |
| MV-SG-05 | Changing client-d's selected group to video-closed, of which client-d is no member, is refused with 403 `120` |
| MV-SG-06 | Changing client-b's selected group to the preconfigured-use-only video-regroup is refused with 403 `167`. client-b's selected group is unchanged |
| MV-SG-07 | Captured at `mcvideo-server` over debug TCP. The request carries `group-selection-change-request`, the group in `<mcvideo-request-uri>` and client-b listed. The server's request to client-b has the group in `<mcvideo-calling-group-id>` and `<affiliation-required>true`. The response carries `group-selection-change-response` and `<selected-group-change-outcome>success` |

## Coverage gaps

| Area | Gap |
|---|---|
| Relay of the response | The server answers the requester 200 when it has relayed the request, not when the target accepts it (9.2.4.3.1, 9.2.4.4). The outcome still reaches the requester in the response MESSAGE. This is as for the remotely initiated group call |
| Separate servers and systems | The request is tested on a combined participating and controlling function; across separate servers it is not exercised, and across MC systems it is not in present edition |
| Client-side checks | The requesting client leaves the checks of `<RemoteGroupSelectionURIList>` and preconfigured-use-only (9.2.4.2.1 steps 1 and 1A) to the server |
| MCPTT | The server procedure serves MCPTT (TS 24.379 10.1.4), but the MCPTT profile has no `RemoteGroupSelectionURIList` in the CMS and the MCPTT lab client has no command |
