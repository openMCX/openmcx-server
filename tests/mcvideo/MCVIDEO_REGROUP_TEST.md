# MCVideo regroup tests

These tests cover **step V8b of increment V8 of the MCVideo plan**: group regroup and user regroup using a preconfigured group (TS 24.281 V19.6.0 clause 21), with their notifications, calls on the regroups, the refusal of a call on a regrouped group, removal, and the refusals of an unauthorised user.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SVC-03).

## How it works

- **Shared with MCPTT.** The regroup is the shared core's regroup using a preconfigured group (TS 24.379 clause 16), which clause 21 follows. The regroup body is the same XML in the same namespace (`urn:3gpp:ns:preconfiguredRegroup:1.0`), with the service's prefix: `application/vnd.3gpp.mcvideo-regroup+xml` carrying `<mcvideoregroup>`, `<mcvideoregroup-Params>` and `<mcvideo-regroup-uri>`. The codec and the MIME type now take the service; MCPTT keeps its names.
- **Creation.**
  - An authorised client (`<allow-regroup>`, stored as `regroup` in its MCVideo profile) sends a MESSAGE to the MCVideo PSI. It carries its mcvideo-info and a regroup body: the temporary group identity, the preconfigured group, and the constituent groups or users.
  - `mcvideo-server` answers 200.
  - For a group regroup, every affiliated member of the constituent groups is told (§21.2.2.4); for a user regroup, only the users named (§21.3.2.4).
  - Each notice carries a copy of the request's mcvideo-info body and all its Accept-Contact and Reject-Contact header fields (§21.2.2.4 and §21.3.2.4 step 3 b) and d), §21.2.2.5 step 3 b) and d)): a multipart body with the mcvideo-info part first. A removal the server decides itself (§21.2.3.3) has no request to copy; its notices carry the regroup body and the `+g.3gpp.mcvideo` Accept-Contact.
- **Configuration.** The regroup takes its whole configuration from the preconfigured group, priority policy included (§21.1). The lab's preconfigured group `video-regroup` is marked preconfigured-use-only and carries the MCVideo group's settings.
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
tools/regress.py --image openmcx:v8 --client-image openmcx-client:v8 --select mcvideo-regroup
```

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| MV-RG-01 | 2026-09-27 | `openmcx:v8` (`f8432c436264`), `openmcx-client:v8` (`a5c11d585fab`) | client-a regroups the MCVideo group with video-closed, using the preconfigured group, and gets 200. All four members are told, with the constituent groups and the preconfigured group | Passed |
| MV-RG-02 | 2026-09-27 | same | The members affiliate to the regroup. client-a's call on it reaches all four, and client-c decodes 16 of client-a's pictures, all equal | Passed |
| MV-RG-03 | 2026-09-27 | same | client-b's call on the regrouped MCVideo group is refused with 403 `148 group is regrouped` | Passed |
| MV-RG-04 | 2026-09-27 | same | client-b, not authorised, is refused with 403 `160` for a creation and 403 `161` for a removal | Passed |
| MV-RG-05 | 2026-09-27 | same | client-a removes the regroup with 200, and every member is told | Passed |
| MV-RG-06 | 2026-09-27 | same | client-a creates a user regroup of client-b and client-c. Only they are told; client-b's call on it reaches client-c, not client-a or client-d. It is removed with 200 and its members are told | Passed |
| MV-RG-07 | 2026-09-27 | same | Captured at `mcvideo-server`: the requests and notices carry `application/vnd.3gpp.mcvideo-regroup+xml` with `<mcvideoregroup>` and `<mcvideo-regroup-uri>`, and no MCPTT names | Passed |

The scenario made 34 checks (`artifacts/regress-v8b-try9/mcvideo-regroup/`, capture `artifacts/integration/mcvideo-regroup.pcap`). The MCPTT regroup lab (`regroup`, both scenarios) passed on the same images, as the codec is shared.

Defects found by the runs and fixed:
- `mcvideo-server` used the MCPTT regroup MIME type and names.
- The client passed every MESSAGE from the MCVideo PSI to its mcvideo-info handling, so a regroup notice failed with "MCPTT information missing".
- A call on a group regroup did not name its calling constituent group.
- The client kept the affiliation to a removed regroup, so its next affiliation request was refused with 403.
- In the lab, the preconfigured group lacked the priority policy the regroup takes from it.
- The MCVideo scenarios stopped their capture as soon as their last step ended, and the packets still on their way through docker were lost. In `mcvideo-ambient` that hid the BYE of MV-AV-04 on these images (70 of 99 packets written). They now wait 3 s first, and all 99 are written.

## Coverage gaps

| Area | Gap |
|---|---|
| Chat regroups | A regroup of chat groups (§21.2.1.3 step 6) is not exercised for MCVideo |
| Decision to remove | Removal decided by the controlling function (§21.2.3.3) is not exercised for MCVideo |
