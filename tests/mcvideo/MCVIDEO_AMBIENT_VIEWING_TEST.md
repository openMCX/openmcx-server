# MCVideo ambient viewing call tests

On-demand ambient viewing calls (TS 24.281 §15.1 to §15.4, without the pre-established session of §15.2.2), remotely and locally initiated, with the release feature capability of annex D.3 and server-initiated release. H.264 video is checked picture by picture.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-AMB-01).

## How it works

- **Shared with MCPTT ambient listening.** The call is the shared core's ambient call (TS 24.379 §11.1.6), which §15 follows step for step. The service profile names its parts:
  - the `<session-type>`: `ambient-listening` or `ambient-viewing`
  - the `<...-type>` element: `<ambient-listening-type>` or `<ambient-viewing-type>`
  - the party in the release reasons: `listened-to` or `viewed-to`
  - the release feature-capability indicator: `g.3gpp.mcptt.ambient-listening-call-release` or `g.3gpp.mcvideo.ambient-viewing-call-release`, from annex D.3 of each specification
- **Remote-init** (the originator views the target):
  - The viewed-to client is invited with `Priv-Answer-Mode: Auto` and a null alert (`Alert-Info: <file:///dev/null>`), and answers automatically.
  - Its answer carries the implicit transmission request (§15.2.1.1 step 13), and the server grants it. So its video goes to the viewing user without the viewed-to user doing anything.
  - Only the originator gets the release capability, in the 200 (OK). The viewed-to client therefore refuses its own user's release request (§15.2.1.3 step 1).
- **Local-init** (the originator asks to be viewed): the originator is the viewed-to user and transmits. The viewing user is invited with the release capability in `Feature-Caps`, so both may release.
- **Server-initiated release** (§15.4.3): a call request for the viewed-to user ends the ambient call. The viewed-to client gets a BYE first; the viewing client then gets a BYE with `<release-reason>call-request-for-viewed-to-client</release-reason>`. The new call then goes through.
- **Authorisation.** The caller's MCVideo private-call ruleset needs `<allow-request-remote-initiated-ambient-viewing>` or `<allow-request-locally-initiated-ambient-viewing>` (TS 24.484), stored as `ambient_remote` and `ambient_local` as for MCPTT. Otherwise the call is refused with 403 and warning `154`.
- **SDP direction.** TS 24.379 §6.2.1 step c requires MCPTT ambient offers to be `recvonly` (remote-init) or `sendonly` (local-init); TS 24.281 §6.2.1 has no such rule, so the MCVideo server does not require it. The client offers the direction of its role anyway (`recvonly` viewing, `sendonly` viewed-to), and answers a one-way offer with the other direction (RFC 3264 §6.1).

## Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-ambient <MCVideo ID> remote|local'
mcx-client --config FILE --command 'mcvideo-hangup'   # refused without the release capability
```

`status.json` adds:
- `mcvideo_ambient_type`: `remote-init` or `local-init`
- `mcvideo_ambient_role`: `viewing` or `viewed-to`
- `mcvideo_ambient_release`: whether the release capability was received

`mcvideo_last_call` keeps these, and the BYE's `release_reason`.

## Running the tests

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-ambient
```

The scenario makes 32 checks. Over TLS the wire checks (MV-AV-05) are skipped. `test_protocol` checks that MCVideo writes `<ambient-viewing-type>` and the viewed-to release reasons, and that MCPTT still writes `<ambient-listening-type>`.

## Tests

| ID | What is checked |
|---|---|
| MV-AV-01 | Remote-init: client-a views client-b. client-b transmits without asking, and client-a decodes its pictures, all equal, and does not transmit. client-a may release the call and client-b may not: its client refuses client-b's release and the call stays up. client-a releases and both are idle |
| MV-AV-02 | Local-init: client-a asks client-b to view it. client-a transmits without asking, and client-b decodes its pictures, all equal. Both may release; client-b releases and both are idle |
| MV-AV-03 | client-b, not authorised, is refused with 403 `154 user not authorised to make ambient viewing call` |
| MV-AV-04 | While client-a views client-b, client-c calls client-b. The ambient call ends, and client-a's BYE carries `call-request-for-viewed-to-client`. client-c's private call to client-b goes through |
| MV-AV-05 | Captured at `mcvideo-server`: INVITEs with `<session-type>ambient-viewing</session-type>` and each `<ambient-viewing-type>`; `Priv-Answer-Mode: Auto` on every one; the null alert to the viewed-to user of a remote-init call; `Feature-Caps` with `g.3gpp.mcvideo.ambient-viewing-call-release` to the viewing user of a local-init call and in a 200 (OK); the BYE with the release reason |

## Coverage gaps

| Area | Gap |
|---|---|
| Pre-established sessions | §15.2.2, §15.3.1.3, §15.3.1.4 and §15.3.2.3: not in present edition |
| Other release reasons | `administrator-action`, `private-call-expiry` and `call-request-initiated-by-viewed-to-client` are sent by the shared code (the MCPTT ambient tests exercise them) but are not driven here: the viewed-to client is busy in the ambient call and does not start another |
| Security | The PCK of §15.2.1.1 step 10 is tested in the [protected call tests](MCVIDEO_PROTECTED_TEST.md) (MV-SE-08) |
