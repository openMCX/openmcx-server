# IP multicast of group call speech tests

These tests cover the **IP multicast delivery of MCPTT group call speech**, an OpenMCX profile and not a 3GPP
procedure: the server sends a configured group's speech once to an IPv4 host group (RFC 1112) that opted-in clients
join, instead of one unicast copy per participant. There is no MBMS bearer, announcement or listening status
(TS 24.379 V19.7.0 §14) and no MBMS subchannel control (TS 24.380 V19.3.0 §10); the host group and the opt-in list
are configured on both sides, and floor control stays unicast. What the tests do not cover is listed under
[coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented profile

| Part | Behavior | Reference |
|---|---|---|
| Server | `mcptt.multicast` maps group URIs to `<host group>:<port>` and lists the opted-in MCPTT IDs (`users`). For each RTP packet of the floor owner in a prearranged, chat or broadcast group call (or a regroup) of a configured group, the server sends one copy to the host group, with time-to-live 1 from its media address, and unicast copies only to the participants that are not opted in, or whose SDP agreed another payload type or AMR-WB format. Protected speech (SRTP under the GMK) is sent unchanged. Private, ad hoc and ambient listening calls and calls without floor control stay unicast. MCPTT only, `role` `both` only. | `include/mcx/multicast.hpp`, `McServer::audio_packet`; TS 24.380 §6.3.4.4.5, TS 33.180 §7.4.2 |
| Client | `mcptt.multicast` maps the same group URIs to the same host groups. When a configured group's call becomes active the client joins the host group, and leaves it when the call ends. Speech from the host group is accepted from the server's media address on any port and takes the unicast path (SSRC of Floor Taken, payload type, SRTP). The talker drops its own speech. While joined, a packet that is not newer than the last kept one of the same SSRC is dropped as a copy. | `src/client/mcptt/multicast.cpp`; TS 24.380 §6.2.4.3.4, RFC 3550 appendix A.1 |

## Running the tests

```bash
python3 tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select multicast
```

The labs are generated with `--multicast`: client-a, client-b and client-c are on the server's opt-in list and have
the client block, with the prearranged group on `239.10.0.1:40000`; client-d has neither. `multicast-protected` adds
protected media and floor control (`--protected`).

## Checks

| ID | Check |
|---|---|
| MC-01 | The server is set up with one host group and has sent nothing; no client has joined before a call. |
| MC-02 | A prearranged group call with the four clients; client-a, client-b and client-c join the host group, client-d has no multicast. |
| MC-03 | client-a talks: for each RTP packet the server sends one copy to the host group and one by unicast (`multicast_forwarded` and `media_forwarded` grow by the same count). |
| MC-04 | client-b and client-c receive every packet from the host group, client-d every packet by unicast, client-a none of its own. |
| MC-05 | client-b talks; the same checks, with client-a now receiving from the host group and client-b none of its own. |
| MC-06 | The call is released; the three clients leave the host group. |
| MC-07 | client-c (multicast) and client-d (unicast) decoded the same speech: their received WAV files are equal. |
| Wire | `verify_multicast.py` on the capture at the MCPTT server: as many speech packets to the host group as the server counted, with time-to-live 1, from the server's address; no unicast speech from the server to client-a, client-b or client-c; one unicast packet to client-d per host group packet. |

## Results

Images `openmcx-*:mc` and `openmcx-client:mc` built from the multicast branches, debug TCP SIP, 2026-10-24:

| Lab | Result | Evidence |
|---|---|---|
| `multicast` | 2 of 2 passed (scenario and wire) | Talk bursts of 337 and 355 packets: 692 packets to the host group and 692 unicast packets to client-d on the wire, none to the opted-in clients; client-c and client-d received 13.84 s of speech each, byte-identical |
| `multicast-protected` | 2 of 2 passed (scenario and wire) | The same counts with SRTP under the GMK; the decoded speech is identical to the clear lab's |
| `smoke` (no multicast) | 2 of 2 passed | The unicast prearranged scenario and its wire check are unchanged |

## Coverage gaps

| Gap | Reason |
|---|---|
| 3GPP MBMS or MBS | Not in the present edition: no bearer, announcement, listening status, MBMS subchannel control or MB2 (TS 24.379 §14, TS 24.380 §10, TS 29.468). |
| Floor control over multicast | Floor Taken and Floor Idle carry the receiver's own SSRC, so they stay unicast. |
| Fallback to unicast | A client cannot leave multicast during a call: the opt-in list is static. A client on the server's list without the client block receives no speech. |
| Held or removed participants | A participant on hold or no longer affiliated stays joined until its call ends and receives the host group's speech. |
| Chat, broadcast and regroup calls | Implemented, but the scenario runs a prearranged call only. |
| Split servers, MCVideo, MCData | Refused by the server's configuration. |
| Android client and dispatcher | The Linux client only. |
| Several hosts | The lab runs on one Docker bridge; routing a host group across networks needs a multicast router. |
