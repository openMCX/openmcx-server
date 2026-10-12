# MCVideo group call tests

On-network MCVideo group calls, prearranged and chat (TS 24.281 §9.2.1, §9.2.2), with the conference event package (§9.2.3), the implicit transmission request (§6.4), transmission and reception control (TS 24.581 clauses 4.1.1.2, 6 and 9.2) and H.264 video carried end to end through the MCVideo server's media distribution function (TS 23.281 §6.2.2.3.3, TS 26.281 clause 4). The MCVideo user profile read at start-up (TS 24.484 §9.3.1A) is checked here too.

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (rows MV-TC-01 to MV-TC-03, MV-GRP-01 to MV-GRP-03, MV-MEDIA-01).

## How it works

- **Call setup.** The caller sends INVITE to the MCVideo PSI with P-Preferred-Service `urn:urn-7:3gpp-service.ims.icsi.mcvideo`, an `<mcvideoinfo>` body (`session-type` prearranged, the group) and the MCVideo SDP offer: `s=MCVideo`, an audio component, `m=video` with `H264/90000` and `profile-level-id=42e01f;packetization-mode=1`, and `m=application … udp MCVideo` with `a=fmtp:MCVideo mc_transmission_ssrc=…` (§6.2.1; TS 24.581 §12, §14). `mcvideo-server` runs the shared call-handling core as the controlling function and invites the other affiliated MCVideo members; each answers with the parameters of the offer only (TS 24.581 §14.3).
- **Transmission control.** A participant sends Transmission Request (MCV0, subtype 0). The server's arbitration (the floor arbitrator behind `MediaPlaneController`) answers with Transmission Granted (MCV1, 0) carrying Duration, the Audio SSRC and Video SSRC (field 23) the participant transmits with, and Priority; the others get a Media Transmission Notification (MCV1, 6) naming the transmitting MCVideo ID and its SSRCs, with the Reception Mode (§6.3.4.4.2 step 3, §6.3.6.3.3, §6.3.7.3.3); on-network the server sends no Transmission Arbitration Taken (MCV1, 2), which belongs to off-network use (§7.2), and MV-GC-07 checks that none is on the wire. A request while another transmits is answered with Transmission Rejected (MCV1, 1), queueing being off. Transmission End Request (MCV2, 0), answered with Transmission End Response (MCV2, 1), ends the transmission, and Transmission idle (MCV1, 15) tells everyone (TS 24.581 §6.2.4, §6.3.4, §9.2.4 to §9.2.10, §9.2.30); on-network a participant never sends Transmission Release (MCV0, 2), which belongs to the participating function and to off-network use (§6.5, §7.2), and MV-GC-07 checks that none is on the wire.
- **Queueing and revocation.** With `mc_queueing` negotiated by both sides, a request while another user transmits is queued (Queue Position Info, MCV1/5) and granted when the transmitter releases; without it, the request is rejected with cause 1. After the configured transmission limit the server sends Transmission Revoked (MCV1/4) with cause 2; the participant stops and releases.
- **Implicit request.** An INVITE whose SDP has `mc_implicit_request` asks for the permission to transmit; the answer accepts it, and the request is arbitrated as the originator's leg becomes active (TS 24.281 §6.4, TS 24.581 §14.2.5).
- **Chat group calls.** A member joins a chat group's session with `session-type` chat; nobody else is invited, and a late joiner decodes from the next IDR picture.
- **Conference events.** Each participant subscribes to the session's focus URI (from the Contact) with an `<mcvideoinfo>` body naming the group and gets RFC 4575 conference-info NOTIFYs listing the participants.
- **Reception control.** With `reception_control` at the server, the Media Transmission Notification of an ordinary group call says manual reception (Reception Mode '1'): the other members receive the transmission only after Receive Media Request (MCV0/4) and Receive Media Response (MCV1/7). In a broadcast, emergency or imminent peril call it says automatic reception ('0') and they receive at once (§6.3.6.3.3, §6.3.7.3.3); without `reception_control` every member receives automatically. Media Reception End Request and Response (MCV2/2, MCV2/3) stop it. A transmitter ends with Transmission End Request and Response (MCV2/0, MCV2/1).
- **Video.** The granted client encodes its test pattern (OpenH264, 240p, 15 fps) and sends it in RTP (RFC 6184) with the granted SSRC. The media distribution function relays the payload unchanged to every other participant. Receivers reassemble and decode each picture and record its checksum by SSRC and RTP timestamp; the sender records the checksum of its own reconstruction; equal checksums prove the video crossed unchanged. A new transmitting user is a new stream (its own SSRC and sequence numbers): the receiver starts reassembling and decoding afresh, and the new transmitter starts with an IDR picture. A receiver that joins late or resumes reception skips pictures until the next IDR (every 30 pictures).

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Group call | Prearranged, on demand, controlling function in `mcvideo-server`, affiliated MCVideo members invited, automatic commencement at the members | 24.281 §9.2.1 |
| SDP | MCVideo offer and answer; the answer only with offered parameters; MCPTT media refused by the MCVideo server and the reverse | 24.281 §6.2.1, §6.2.2; 24.581 §14 |
| Transmission control | Request, Granted (with the video SSRC), Rejected, Media Transmission Notification, End Request and Response, idle; unacknowledged | 24.581 §6.2.4, §6.3.4, §9.2 |
| Media distribution | The transmitting user's video relayed unchanged to the others, not back to the sender; other users' video dropped | 23.281 §6.2.2.3.3 |
| Video | H.264 Constrained Baseline at 240p, decoded at every receiver; decoding restarts on a new transmitting user, and starts at an IDR after a late join or a resumed reception | 26.281 §4.1.1; RFC 6184 |
| Queueing, revocation | Queue Position Info and grant from the queue; rejection cause 1 without queueing; revocation cause 2 at the transmission limit, answered by Transmission End Request | 24.581 §6.3.4, §9.2.6, §9.2.10, §9.2.12 |
| Implicit request | `mc_implicit_request` in the originator's offer and the answer; granted without a Transmission Request | 24.281 §6.4; 24.581 §14.2.5, §14.3 |
| Chat group call | Join by `session-type` chat, implicit affiliation, late joiner | 24.281 §9.2.2 |
| Conference events | SUBSCRIBE `conference` with `<mcvideoinfo>`; participants from full and partial NOTIFYs | 24.281 §9.2.3; RFC 4575 |
| Reception control | Notification with the Reception Mode, acceptance, refusal (cause 3 without a transmitter), end of reception, end of transmission | 24.581 §6.3.6.3.3, §6.3.7.3.3, §9.2.13 to §9.2.15, §9.2.20, §9.2.21, §9.2.26, §9.2.27 |

Configuration: the lab of `tools/prepare-prearranged-test.py --mcvideo` gives each client an MCVideo call on its own ports (`mcvideo.media`: audio 4200, control 5200, video 6200); `mcvideo-server` has `media.video_port` 6000 and, in `mcvideo`, `floor_queue`, `max_talk_ms` 15000 and `reception_control`. client-d neither queues (`queueing` false) nor accepts transmissions by itself (`auto_receive` false). Group `video-chat` is a chat group of the four users.

### Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-call [implicit]'  # prearranged group call to the configured group
mcx-client --config FILE --command 'mcvideo-chat <group>'     # join a chat group's session
mcx-client --config FILE --command 'mcvideo-transmit'         # Transmission Request
mcx-client --config FILE --command 'mcvideo-end'              # Transmission End Request (TS 24.581 clause 6.2.4.5.3)
mcx-client --config FILE --command 'mcvideo-receive'          # Receive Media Request (mcvideo-stop-receiving: end of reception)
mcx-client --config FILE --command 'mcvideo-hangup'
```

`status.json` records `mcvideo_call_state`, `mcvideo_transmitting`, `mcvideo_transmitter`, `mcvideo_frames_sent`, `mcvideo_frames_received`, `mcvideo_sent_frames` and `mcvideo_received_frames` (checksums by `<SSRC>:<timestamp>`), `mcvideo_undecoded`, `mcvideo_skipped_before_key`, `mcvideo_queue_position`, `mcvideo_revocations`, `mcvideo_reject_cause`, `mcvideo_receiving`, `mcvideo_reception_notifications`, `mcvideo_participants`, `mcvideo_session_uri` and `mcvideo_last_call`; the call fields are removed when no call is in progress.

## Running the tests

The scenario runs in the `mcvideo` lab, beside the affiliation and private call scenarios:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo
```

Over TLS the wire checks (MV-GC-07) are skipped.

## Tests

| ID | What is checked |
|---|---|
| MV-GC-01 | client-a calls group operations; all four clients are in the MCVideo call; their MCPTT stays idle |
| MV-GC-12 | Every member's conference subscription lists the four MCVideo IDs connected; the session URI is the MCVideo PSI with a session parameter |
| MV-GC-02 | client-a's Transmission Request is granted; the three others see client-a as the transmitting user |
| MV-GC-13 | Every other member gets a Media Transmission Notification with manual reception; client-d receives nothing for 1.5 s until it accepts; client-b stops receiving (no picture relayed for 1.5 s) and resumes |
| MV-GC-03 | client-b, client-c and client-d decode client-a's pictures, all equal to client-a's reconstruction; client-a receives nothing back; the server relayed the video |
| MV-GC-04 | client-a ends with Transmission End Request; client-b is granted; client-a, client-c and client-d decode its video, all compared pictures equal; no picture undecoded |
| MV-GC-05 | While client-b transmits, client-c is queued at position 1 and client-d, without queueing, rejected with cause 1 |
| MV-GC-08 | client-b releases; client-c is granted from the queue without asking again |
| MV-GC-09 | client-c is revoked after the 15 s limit with cause 2 and stops transmitting |
| MV-GC-06 | All four leave the call |
| MV-GC-10 | client-d calls with `mc_implicit_request` and is granted without a Transmission Request; the three others decode its video with equal checksums |
| MV-GC-11 | client-a and client-b join chat group video-chat, the others are not invited; client-a transmits; client-b and the late joiner client-c decode it with equal checksums |
| MV-GC-07 | Captured at `mcvideo-server`: the MCVideo INVITE and SDP, a chat join, `mc_implicit_request` in an offer and its answer, SUBSCRIBE and NOTIFY of the conference package; 14 transmission control messages (MCV0/0, /4; MCV1/0, /1, /4, /5, /6, /7, /15; MCV2/0 to /3) and none of Transmission Release (MCV0/2), Transmission Arbitration Taken (MCV1/2) or Media Reception Notification (MCV1/8); Transmission Granted with fields 1, 14, 23 and 0; H.264 RTP packets with SPS, PPS, IDR and P slices |
| MV-GC-14 | Each client read its MCVideo user profile (TS 24.484 §9.3.1A): its MCVideo ID and group operations; client-a's carries its private call targets and rights (emergency private call, modify ad hoc participants, ambient viewing, regroup, push to the server), client-d's no `<allow-private-call>`, client-b's no `<allow-regroup>` |

## Coverage gaps

| Area | Gap |
|---|---|
| Key-frame requests | Not implemented: TS 26.281 specifies RTP and SRTP only, and RTCP feedback (RFC 4585 PLI, RFC 5104 FIR) needs the AVPF profile TS 24.281 does not ask for. A receiver waits for the next IDR (at most 2 s; every new transmission starts with one) |
| Transmission control acknowledgement | Messages are sent without the ack bit and without retransmission |
| Session release policy, timers | The shared core's call release and timers apply (TS 24.379 behaviour); TS 24.281 §6.3.8 and the TS 24.581 Annex timers are not tested separately |
| Priority | Transmission priority and reception priority are not exercised here; pre-emption by an emergency user is in the [emergency tests](MCVIDEO_EMERGENCY_TEST.md) |
| Several transmitters | One transmitting user at a time; the "maximum simultaneous transmitting members" of TS 24.581 4.1.1.2 is 1 |
| Audio component | Negotiated but not sent or played by the MCVideo client |
| Security | Protected media and transmission control are tested in the [protected call tests](MCVIDEO_PROTECTED_TEST.md) |
