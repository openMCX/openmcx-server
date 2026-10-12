# MCVideo regroup tests

Group regroup and user regroup using a preconfigured group (TS 24.281 clause 21), with their notifications, calls on the regroups, the refusal of a call on a regrouped group, removal, and the refusals of an unauthorised user.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SVC-03).

## How it works

- **Shared with MCPTT.** The regroup is the shared core's regroup using a preconfigured group (TS 24.379 clause 16), which clause 21 follows. The regroup body is the same XML in the same namespace (`urn:3gpp:ns:preconfiguredRegroup:1.0`), with the service's prefix: `application/vnd.3gpp.mcvideo-regroup+xml` carrying `<mcvideoregroup>`, `<mcvideoregroup-Params>` and `<mcvideo-regroup-uri>`. The codec and the MIME type take the service; MCPTT keeps its names.
- **Creation.**
  - An authorised client (`<allow-regroup>`, stored as `regroup` in its MCVideo profile) sends a MESSAGE to the MCVideo PSI. It carries its mcvideo-info and a regroup body: the temporary group identity, the preconfigured group, and the constituent groups or users.
  - `mcvideo-server` answers 200.
  - For a group regroup, every affiliated member of the constituent groups is told (§21.2.2.4); for a user regroup, only the users named (§21.3.2.4).
  - Each notice carries a copy of the request's mcvideo-info body and all its Accept-Contact and Reject-Contact header fields (§21.2.2.4 and §21.3.2.4 step 3 b) and d), §21.2.2.5 step 3 b) and d)): a multipart body with the mcvideo-info part first. A removal the server decides itself (§21.2.3.3) has no request to copy; its notices carry the regroup body and the `+g.3gpp.mcvideo` Accept-Contact.
- **Configuration.** The regroup takes its whole configuration from the preconfigured group, priority policy included (§21.1). The lab's preconfigured group `video-regroup` is marked preconfigured-use-only and carries the MCVideo group's settings, its priority policy among them.
- **Calls.**
  - A call on a group regroup names, in `<associated-group-id>`, the constituent group it is placed from (§9.2.1.2.1.1 step 14 d) i)). The client uses its own group if it is one of them. The function of that group passes it on in `<mcvideo-calling-group-id>` (§6.3.4.1.4 step 4 c)); `mcvideo-server` is both functions for its own users, so it reads `<associated-group-id>` from a client and `<mcvideo-calling-group-id>` from another function.
  - The invitation to each member names the regroup in `<mcvideo-calling-group-id>` and the member's constituent group in `<associated-group-id>` (§6.3.4.1.2 steps 6a and 6b).
  - TS 24.281 annex F.1 types `<associated-group-id>` as `xs:string`, so it is written as plain text, not in `<mcvideoURI>`; both forms are read, in `<mcvideo-Params>` or in `<anyExt>` (where §9.2.1.2.1.1 step 14 d) i) puts it).
  - A call on a constituent group while it is regrouped is refused with 403 and warning `148`.
- **Affiliation to the regroup.**
  - A client counts itself affiliated with a regroup it is told of (§21.2.1.3 step 4), and de-affiliated when it is removed (§21.2.1.4 step 3).
  - The server counts each member it tells of a group regroup as affiliated with it (§21.2.2.4 step 3 h)), so a call on the regroup invites them without an affiliation request of their own.
  - On removal the client drops that affiliation, so its later affiliation requests no longer name the regroup.
- **Removal** by an authorised client tells every member. An unauthorised creation is refused with 403 `160`, an unauthorised removal with 403 `161`.

## Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-regroup create <TGI> <preconfigured group> groups <group>,<group>'
mcx-client --config FILE --command 'mcvideo-regroup create <TGI> <preconfigured group> users <MCVideo ID>,<MCVideo ID>'
mcx-client --config FILE --command 'mcvideo-regroup remove <TGI>'
mcx-client --config FILE --command 'mcvideo-affiliate <TGI>'
mcx-client --config FILE --command 'mcvideo-call group=<TGI>'
```

`status.json` adds:
- `mcvideo_regroups`: the regroups the client is told of, with their groups or users and preconfigured group
- `mcvideo_regroup_result`: the answer to its last request

## Running the tests

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-regroup
```

The scenario makes 34 checks. Over TLS the wire checks (MV-RG-07) are skipped. The MCPTT `regroup` lab runs on the same shared core and codec.

## Tests

| ID | What is checked |
|---|---|
| MV-RG-01 | client-a regroups the MCVideo group with video-closed, using the preconfigured group, and gets 200. All four members are told, with the constituent groups and the preconfigured group |
| MV-RG-02 | The members affiliate to the regroup. client-a's call on it reaches all four, and client-c decodes client-a's pictures, all equal |
| MV-RG-03 | client-b's call on the regrouped MCVideo group is refused with 403 `148 group is regrouped` |
| MV-RG-04 | client-b, not authorised, is refused with 403 `160` for a creation and 403 `161` for a removal |
| MV-RG-05 | client-a removes the regroup with 200, and every member is told |
| MV-RG-06 | client-a creates a user regroup of client-b and client-c. Only they are told; client-b's call on it reaches client-c, not client-a or client-d. It is removed with 200 and its members are told |
| MV-RG-07 | Captured at `mcvideo-server`: the requests and notices carry `application/vnd.3gpp.mcvideo-regroup+xml` with `<mcvideoregroup>` and `<mcvideo-regroup-uri>`, and no MCPTT names |

## Coverage gaps

| Area | Gap |
|---|---|
| Chat regroups | A regroup of chat groups (§21.2.1.3 step 6) is not exercised for MCVideo |
| Decision to remove | Removal decided by the controlling function (§21.2.3.3) is not exercised for MCVideo |
