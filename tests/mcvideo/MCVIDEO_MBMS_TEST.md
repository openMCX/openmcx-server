# MCVideo MBMS delivery tests

These tests cover the **MBMS usage procedures** of TS 24.281 V19.6.0 §16 and the **MBMS subchannel control** of
TS 24.581 V19.2.0 §10 for an MCVideo group call, over a pre-activated MBMS bearer of the MCVideo server emulated on
the lab network (no radio, no BM-SC; the client's MBMS interface is the `mbms` block and the `mbms` commands). The
MCPTT side, and how the bearers are emulated, are in [the MCPTT MBMS tests](../mcptt/MULTICAST_TEST.md).

Back to the [test index by call type](../MCVIDEO_TEST.md).

## Implemented procedures

| Part | Behavior | Reference |
|---|---|---|
| Server | `mcvideo.mbms` as `mcptt.mbms` (users omitted: every served user). The announcement uses `application/vnd.3gpp.mcvideo-mbms-usage-info+xml`; its SDP has an `m=video` line (`video_payload_type`, default 97) and an `m=audio` line before the general purpose `m=application` lines. A granted transmission maps the conversation to a subchannel ("MCV3" Map Group To Bearer: video m-line 1 on the pool entry's port, audio m-line 2 on the port two above); each video RTP packet goes once over the subchannel for the participants that reported listening, by unicast to the others; the audio likewise on its port. Transmission Idle and Media Transmission Notification to listeners go once over the subchannel (video port), acknowledgement bit '0'. Timers as for MCPTT. | `src/server/mbms.cpp`, `src/mcvideo/video_media.cpp`; TS 24.281 §16.3, TS 24.581 §9.3, §10.2 |
| Client | Map Group To Bearer for the group of the active MCVideo group call: the client joins the subchannel's video port and reports "listening" for the session (TS 24.281 §16.2.3); the video from it is reassembled and decoded as the unicast video, the transmitting client drops its own, and a packet not newer than the last one kept of the stream is dropped as a copy. The audio port is not joined (the audio component is not played). Transmission Idle and Media Transmission Notification from the subchannel (the Map Group To Bearer's SSRC) go to the transmission participant; the transmitter's own notification is ignored. Unmap Group To Bearer: "not-listening", the subchannel left. | `src/client/mcvideo/multicast.cpp`; TS 24.581 §10.3 |

## Running the tests

```bash
python3 tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select mbms-mcvideo
```

`mbms-mcvideo-protected` adds protected media and transmission control: the bearer then has an MSCCK and a MuSiK.
`mbs-mcvideo` runs the scenario over a 5G MBS session of the MCVideo server (`application/vnd.3gpp.mcvideo-mbs-usage-info+xml`,
"MCV5" MapGroupToSessionStream; TS 24.281 clause 16A, TS 24.581 clause 9.5).

The lab is generated with `--mcvideo --multicast`: the MCVideo server's bearer has TMGI `00000299f907`, MBMS service
area `0001`, general purpose subchannel `239.10.1.2:40200` and subchannel `239.10.0.4:40006`; client-d starts outside
the service area.

## Checks

| ID | Check |
|---|---|
| MV-MB-01 | The MCVideo bearer is announced to the four users; client-a to client-c listen to its general purpose subchannel, client-d does not. |
| MV-MB-02 | client-a's granted transmission maps the conversation to the first subchannel of the pool (TS 24.581 §10.2.2.2). |
| MV-MB-03 | client-b and client-c join the subchannel and the server takes their "listening" reports for the session. |
| MV-MB-04 | Every receiver decodes 30 pictures, client-b and client-c from the subchannel, client-d (manual reception) by unicast; every decoded picture equals the sender's reconstruction. |
| MV-MB-05 | The server sent video over the subchannel; client-d received none from it, the transmitter decoded none of its own. |
| MV-MB-06 | `mbms quality bad`: client-c leaves the subchannel, the server takes it off, and it keeps decoding by unicast. |
| MV-MB-07 | `mbms quality good`: client-c rejoins on the next Map Group To Bearer; all its pictures (MBMS, unicast, MBMS) equal the sender's. |
| MV-MB-08 | client-a ends its transmission: Transmission Idle goes over the subchannel and reaches client-b and client-c, not client-d. |
| MV-MB-10 | `mbms-mcvideo-protected` only: every MCVideo user took the MSCCK of the announcement and the MuSiK download; the Transmission Idle of MV-MB-08 was SRTCP under the MuSiK. |
| MV-MB-09 | The call is released: Unmap Group To Bearer, every client left the subchannel. |

## Results

Debug TCP SIP, 2026-10-28, images from the multicast branches (`mb4` quick images): `mbms-mcvideo` 1 of 1 passed
(63 video packets over the subchannel); `mcvideo` and `smoke-mcvideo` unchanged (passed).

## Coverage gaps

| Gap | Reason |
|---|---|
| Reception control | A client listening to the subchannel receives the video whatever its reception mode: the server's reception control (Receive Media Request) governs only the unicast copies. |
| Audio over the subchannel | Sent, not verified: the client does not join the audio port. |
| FEC | Not implemented (TS 24.581 §10.4: optional). |
