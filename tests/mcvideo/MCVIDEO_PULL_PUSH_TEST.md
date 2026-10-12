# MCVideo video pull, video push and remote transmission tests

On-network video pull (TS 24.281 §12.2) and video push (§13.2), each one-to-one and to or from the MCVideo server, and remotely initiated and ended transmission (TS 23.281 §7.7.1.3.7 and §7.7.1.3.6.3 with TS 24.581 §9.2.22 to §9.2.25), with H.264 video checked picture by picture.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (rows MV-PULL-01, MV-PUSH-01).

## How it works

- **One-to-one video push and pull** are private calls (§10.2) whose `<session-type>` is `one-to-one video push` or `one-to-one video pull`. The controlling function passes the session type to the called client and applies the private-call rulesets. The user who sends video transmits without asking. For a push that is the caller, whose offer carries `mc_implicit_request` (§13.2.2.1, TS 24.581 §6.2). For a pull it is the called user, whose answer carries it (§12.2.2.2). The called client of a push reports the call as a push (§13.2.2.2).
- **Video push to the server** (§13.2.2.4, §13.2.3.2.3) is an INVITE to the MCVideo PSI without a resource-lists body, with automatic commencement. `mcvideo-server` answers the call itself, saves the pushed video to a file, and sends the file's URL in a SIP INFO in the call's dialog: `Info-Package: g.3gpp.mcvideo-info`, with a `<video-push-url>` (an `<anyExt>` element). The server's own call is checked against the user's push or pull authority, negotiates queueing as a private call does, and takes the default private call timers.
- **Video pull from the server** (§12.2.2.4, §12.2.3.2.5) names the video in `<video-pull-url>` (a `contentType` in `<mcvideo-Params>`). The server streams that recording as it was received, paced as recorded. The pictures keep the pushing client's SSRC and RTP timestamps, so the puller's decoded pictures can be compared with the pusher's one by one.
- **Remote transmission** (TS 23.281 §7.7.1.3.7, §7.7.1.3.6.3): in a call with transmission control, an authorised user sends a Remote Transmission request (MCV0 subtype 7), or a cancel request (subtype 8), naming another participant in its User ID field.
  - A start is arbitrated as if that participant had asked: grant, deny or queue.
  - An end revokes its grant with Transmission Revoked cause #5 ("terminate the RTP stream").
  - The server answers with a Remote Transmission response (MCV1 subtype 11) or cancel response (subtype 12).
- **Capability information sharing** (§14.2) has no on-network procedure in TS 24.281; the clause has headings only. Nothing is implemented or tested for it.

## Project choices

These are marked in the code where they apply.

| Point | Choice | Why |
|---|---|---|
| Result of a remote request | The responses carry a Result field (§9.2.3.17, ID 15): 1 done, 0 not done | Stage 2 asks for success or a failure reason, but tables 9.2.23-1 and 9.2.25-1 list no field for it; Result is the only field that carries one |
| Remote ID | Left out of the requests; the server takes the requester from the session leg | Table 9.2.3.1-1 assigns no field ID to Remote ID |
| Authority to end another user's transmission | `<allow-revoke-transmit>` of the MCVideo user profile (TS 24.484), as `allow_revoke_transmit` | The profile's element for this |
| Authority to start another user's transmission | Project profile `allow_remote_transmit` | TS 24.484 has no element for it |
| Authority to push to or pull from the server | Project profile `allow_video_push_to_server` and `allow_video_pull_from_server` | §13.2.3.2.3 and §12.2.3.2.5 require the check; TS 24.484 has no element for it |
| Authority for one-to-one push and pull | The private-call rulesets | §12.2.3.2.2 and §13.2.3.2.1 build on the private call (§10.2.2.4.2) |
| Refusal warnings | 403 with warning `100` and a reason; 404 for an unknown recording | TS 24.281 defines no warning texts for these |
| Recordings | One file per push under `recordings_dir` (default `/artifacts/mcvideo-server/recordings`). Each RTP packet is stored with its arrival offset, SSRC, timestamp, sequence number and marker. The URL is `recording_url_base` + the file's name; a pull accepts only this server's own recording URLs | How an MCVideo client learns the URL of a video is out of scope of TS 24.281 (§12.2.2.4 NOTE) |

## Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-push <MCVideo ID> [auto|manual|force-auto]'
mcx-client --config FILE --command 'mcvideo-pull <MCVideo ID> [auto|manual|force-auto]'
mcx-client --config FILE --command 'mcvideo-push-server'
mcx-client --config FILE --command 'mcvideo-pull-server <video URL>'
mcx-client --config FILE --command 'mcvideo-remote-transmit <MCVideo ID>'   # or mcvideo-remote-cancel
```

`status.json` adds:
- `mcvideo_video_mode`: the call's session type, kept in `mcvideo_last_call` as `video_mode`
- `mcvideo_push_url`: the URL from the server's INFO
- `mcvideo_remote_result`: the request, its target and the Result of the answer

`mcvideo-server`'s status counts `video_recorded` and `video_streamed` packets.

## Running the tests

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-pull-push
```

The scenario makes 61 checks. Over TLS the wire checks (MV-PP-06) are skipped. The unit tests cover the Remote Transmission messages and their Result field (`test_transmission`) and the two URL elements (`test_protocol`).

## Tests

| ID | What is checked |
|---|---|
| MV-PP-01 | client-a pushes its video to client-b. Both are in a `one-to-one video push` call, and client-a transmits without asking. client-b decodes its pictures, all equal to client-a's, and does not transmit |
| MV-PP-02 | client-a pulls client-b's video. client-b transmits without asking (the implicit request in its answer). client-a decodes its pictures, all equal, and does not transmit |
| MV-PP-03 | client-a pushes to the server and transmits without asking. It receives the `<video-push-url>` in a SIP INFO. The server records its video; nobody else is in the call |
| MV-PP-04 | client-b pulls that URL from the server. The server streams the whole recording, and client-b decodes every picture, **all equal to the ones client-a pushed**. client-b does not transmit |
| MV-PP-05 | Refusals: client-c's pull from and push to the server get 403 with warning `100`; a pull of an unknown recording gets 404; client-d's video push call is refused 403 by the private-call rules |
| MV-RT-01 | In a group call of four, client-a's Remote Transmission request for client-b is answered with Result 1. client-b transmits, and client-c decodes its pictures, all equal |
| MV-RT-02 | client-c's cancel request for client-b is answered with Result 0 (not authorised); client-b still transmits |
| MV-RT-03 | client-a's cancel request for client-b is answered with Result 1; client-b is revoked with cause #5 and stops |
| MV-RT-04 | client-c's request for client-d is answered with Result 0 and client-d does not transmit; client-a's cancel for client-d, who is not transmitting, is answered with Result 0 |
| MV-RT-05 | The group call ends for all |
| MV-PP-06 | Captured at `mcvideo-server`: INVITEs with each of the four session types; no resource-lists body in the calls to the server; the pull's `<video-pull-url>`; an INFO with `Info-Package: g.3gpp.mcvideo-info` carrying the `<video-push-url>` |

## Coverage gaps

| Area | Gap |
|---|---|
| Off-network | Off-network video pull and push (§12.3, §13.3): not in present edition |
| Remotely initiated video push | The SIP flows of TS 23.281 §7.4.2.5 and §7.4.2.6 have no on-network stage-3 procedure in TS 24.281 |
| Capability information sharing | §14.2 has no procedure |
| Remote transmission across servers | The Track Info field for a non-controlling MCVideo function is not implemented |
| Security | Push to and pull from the server stay unprotected; protected one-to-one push and pull are not exercised |
| Recordings | No deletion or retention policy; a pull accepts only this server's own URLs |
