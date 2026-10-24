# MCVideo video media tests

The H.264 video media of TS 26.281 clause 4, carried in RTP with the payload format of IETF RFC 6184, and its description in SDP (TS 24.281 §6.2.1), proven at unit level. Video between clients through the MCVideo server is checked by the [group call tests](MCVIDEO_GROUP_CALL_TEST.md) and the [private call tests](MCVIDEO_PRIVATE_CALL_TEST.md).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-MEDIA-01).

## How it works

- **Codec** (`include/mcx/video.hpp`, `src/video.cpp`). OpenH264 2.4.1, Cisco's BSD-licensed H.264 encoder and decoder (Ubuntu `libopenh264-dev`, pinned in `docker/Dockerfile.dev`). The encoder produces Constrained Baseline Profile Level 3.1 at 320x240 (240p, the TS 26.281 §4.1.1 minimum), 15 frames per second, one IDR picture every 30 frames, and an IDR on request (for a new receiver). The decoder shows a picture only when it decoded it without error; after a loss it waits for the next IDR.
- **Test pattern.** The lab has no camera: the sender encodes a deterministic moving pattern, and each decoded picture has an FNV-1a checksum. The receiver's picture equals the sender's own reconstruction of the same bitstream, so equal checksums on both sides prove that video crossed unchanged.
- **RTP** (RFC 6184, packetization mode 1). A NAL unit that fits the payload size goes in a Single NAL Unit packet (§5.6); a larger one is split into FU-A fragments (§5.8), and the last packet of a picture has the marker bit (§5.1). The receiver reassembles Single NAL Unit, STAP-A (§5.7.1) and FU-A packets into pictures, ends a picture at its marker or at a new timestamp, discards a picture damaged by a sequence gap, and refuses the packet types mode 1 excludes (MTAP, FU-B) and packets with the forbidden bit.
- **SDP.** The `m=video` section offers `H264/90000` with `profile-level-id=42e01f;packetization-mode=1`; the parser accepts H.264 only. Constrained High Profile decoders decode the Constrained Baseline pictures sent.

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Encoding | H.264 Constrained Baseline Level 3.1 (SPS `profile_idc` 66, `level_idc` 31), 240p, 15 fps, IDR period 30 and on request | 26.281 §4.1.1 |
| Decoding | Pictures at the sent size; none shown from a damaged access unit | 26.281 §4.1.1 |
| Packetization | Single NAL Unit and FU-A, marker on the last packet of a picture | RFC 6184 §5.1, §5.6, §5.8 |
| Depacketization | Single NAL Unit, STAP-A, FU-A; loss discards the damaged picture; MTAP, FU-B and F=1 refused | RFC 6184 §5.7.1, §5.8, §6.2 |
| SDP | `H264/90000`, `profile-level-id=42e01f`, `packetization-mode=1` | 24.281 §6.2.1; RFC 6184 §8.1 |

## Running the tests

The unit tests, in the development image:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace openmcx-dev:0.3 \
  bash -lc 'cmake -S . -B build-mcvideo && cmake --build build-mcvideo -j"$(nproc)" && ctest --test-dir build-mcvideo -R "video|protocol"'
```

## Tests

| ID | What is checked |
|---|---|
| MV-VM-01 | `test_video`: 45 frames of the test pattern encoded at 240p, packetized at a 300-byte payload size (FU-A), reassembled and decoded; every received picture equals the sender's reconstruction by checksum; the first access unit starts with an SPS of profile 66 and level 31; two IDRs in 45 frames and one on request |
| MV-VM-02 | FU-A start, end and indicator bits; a lost fragment discards that picture only; STAP-A; a picture without its marker ends at the next timestamp; MTAP, FU-B, F=1, a bad STAP-A size and an FU-A with both S and E refused |
| MV-VM-03 | `test_protocol`: the MCVideo SDP with `profile-level-id=42e01f;packetization-mode=1` round trips |

## Coverage gaps

| Area | Gap |
|---|---|
| Constrained High Profile | Not encoded (TS 26.281 "should"); received CHP streams are decoded by OpenH264 only as far as it supports them |
| H.265 | Optional in TS 26.281 §4.1.1; not implemented |
| Audio | The MCVideo audio component uses the MCPTT AMR-WB path of the shared core |
| RTCP feedback | Key-frame requests by RTCP (RFC 4585, RFC 5104) are not implemented (see the [group call tests](MCVIDEO_GROUP_CALL_TEST.md)); the encoder takes a request |
