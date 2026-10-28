# IP multicast of group call speech tests

These tests cover the **IP multicast delivery of MCPTT group call speech**, an OpenMCX profile and not a 3GPP
procedure: the server sends a configured group's speech once to an IPv4 host group (RFC 1112) that opted-in clients
join, instead of one unicast copy per participant. Of TS 24.379 V19.7.0 §14 only the **listening status report** is
used (§14.2.3, §14.2.4, §14.3.3.2): a client receives a session's speech by multicast once the server has taken its
"listening" report, and by unicast again after "not-listening" (TS 24.380 V19.2.0 §6.4.3 step 3 a). There is no MBMS
bearer, announcement or MuSiK (§14.2.2, §14.2.2.5) and no MBMS subchannel control (TS 24.380 §10); the host group,
its TMGI and the opt-in list are configured, and floor control stays unicast. What the tests do not cover is listed
under [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented profile

| Part | Behavior | Reference |
|---|---|---|
| Server, media | `mcptt.multicast` maps group URIs to a host group and a TMGI and lists the opted-in MCPTT IDs (`users`). For each RTP packet of the floor owner in a prearranged, chat or broadcast group call (or a regroup) of a configured group, the server sends one copy to the host group, with time-to-live 1 from its media address, for the participants that reported listening, and unicast copies to every other participant (not opted in, not listening, or with another payload type or AMR-WB format in its SDP). Protected speech (SRTP under the GMK) is sent unchanged. Private, ad hoc and ambient listening calls and calls without floor control stay unicast. MCPTT only, `role` `both` only. | `src/server/multicast.cpp`, `McServer::audio_packet`; TS 24.380 §6.3.4.4.5, §6.4.3, TS 33.180 §7.4.2 |
| Server, reports | A SIP MESSAGE with `application/vnd.3gpp.mcptt-mbms-usage-info+xml` from a served user: "listening" for a current session with a host group, its TMGI, from a user on the list and in the session, is taken; "not-listening" is always taken. Refused with 403: an `<announcement>`, an mcptt-info naming another MCPTT ID, and a "listening" report failing any of the conditions above. A suspension status or a report on the general purpose subchannel only is answered 200 without action. | TS 24.379 §14.2.3, §14.2.4, annex F.2 |
| Client | `mcptt.multicast` maps the same group URIs to the same host groups and TMGIs. When a configured group's call becomes active the client joins the host group and reports "listening"; a refused report leaves it. `multicast off` reports "not-listening" and leaves the host group 200 ms after the server's answer, for speech already on its way; `multicast on` joins and reports again. Speech from the host group is accepted from the server's media address on any port and takes the unicast path (SSRC of Floor Taken, payload type, SRTP). The talker drops its own speech. While joined, a packet that is not newer than the last kept one of the same SSRC is dropped as a copy, counted by the way it came. | `src/client/mcptt/multicast.cpp`; TS 24.379 §14.3.3.2, TS 24.380 §6.2.4.3.4, RFC 3550 appendix A.1 |

## Running the tests

```bash
python3 tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select multicast
```

The labs are generated with `--multicast`: the four clients have the client block, with the prearranged group on
`239.10.0.1:40000` and TMGI `00000199f907` (MBMS Service ID 000001, MCC 999, MNC 70); the server's opt-in list
names client-a, client-b and client-c, not client-d. `multicast-protected` adds protected media and floor control
(`--protected`). The labs also have one pre-activated MBMS bearer (`mcptt.mbms`, TMGI `00000199f907`, MBMS service
area `0001`, general purpose subchannel `239.10.1.1:40100`, Bearer Announcement every 5 s) announced to the four
users; client-d's emulated MBMS interface starts in area `0002`. The MB checks run before the call; the bearer
carries no group media yet (the MC checks use the static host group).

## Checks

| ID | Check |
|---|---|
| MB-01 | The MBMS bearer is announced to the four users (TS 24.379 clause 14.2.2.2); each client stores it with the general purpose subchannel of its SDP (clause 14.3.2). |
| MB-02 | client-a to client-c, in the bearer's service area, join the general purpose subchannel and the server takes their "listening" reports with `<general-purpose>` (clause 14.3.3); client-d, outside, does not listen. |
| MB-03 | The Bearer Announcement message sent over the general purpose subchannel (TS 24.380 clause 4.1.3.7) reaches the listeners, not client-d. |
| MB-04 | `mbms area 0001`: client-d enters the service area, listens and is taken. |
| MB-05 | `mbms quality bad`: client-c reports "not-listening" and leaves; `mbms quality good`: it listens again. |
| MB-06 | `mbms area 0002`: client-d leaves the service area and reports "not-listening". |
| MC-01 | The server is set up with one host group, has sent nothing and counts nobody listening; no client has joined before a call. |
| MC-02 | A prearranged group call with the four clients; client-a, client-b and client-c join the host group and the server takes their "listening" reports. |
| MC-03 | client-d's report is refused with 403; client-d leaves the host group. |
| MC-04 | Burst 1, client-a talks: every receiver receives every packet once, the talker none; the server sends one copy per packet to the host group, and as many unicast copies as arrive by unicast (all to client-d); client-b and client-c receive only from the host group. |
| MC-05 | Burst 2, client-b talks, and client-c gives `multicast off` after 60 packets from the host group: the server drops client-c from its listening list, client-c leaves the host group, and receives the rest of the burst by unicast. client-c receives every packet once (some copies arriving both ways meanwhile are dropped); the unicast copies the server sent equal those that arrived by unicast. |
| MC-06 | `multicast on`: client-c is listening again; burst 3, client-a talks, client-c receives only from the host group. |
| MC-07 | The call is released; every client has left the host group. |
| MC-08 | client-c (multicast, unicast, multicast) and client-d (unicast) decoded the same speech: their received WAV files are equal. |
| Wire | `verify_multicast.py` on the capture at the MCPTT server: as many speech packets to the host group as the server counted, with time-to-live 1, from the server's address; to each client as many unicast speech packets as arrived there by unicast (none to client-a and client-b, all to client-d). |

## Results

Debug TCP SIP, 2026-10-25, images from the multicast branches (the MCPTT server and client binaries of phase 2
layered on the full `mc2` images):

| Lab | Result | Evidence |
|---|---|---|
| `multicast` | 2 of 2 passed (scenario and wire) | Bursts of 337, 355 and 337 packets. Burst 2: client-c 75 packets by multicast and 280 by unicast, 9 copies dropped; the server sent 644 unicast copies (355 to client-d, 289 to client-c) |
| `multicast-protected` | 2 of 2 passed (scenario and wire) | The same with SRTP under the GMK; burst 2: client-c 76 by multicast, 279 by unicast, 10 copies dropped |
| `smoke` (no multicast) | 2 of 2 passed | The unicast prearranged scenario and its wire check are unchanged |
| `multicast`, `multicast-protected`, soak (`--duration 6m`) | 24 of 24 passed in 6 rounds | No packet lost at any fallback |

An earlier run lost one packet in burst 2 of the protected lab: the client left the host group as soon as the
server answered "not-listening", and the last packet sent to the host group arrived after. The client now stays
200 ms longer.

## Coverage gaps

| Gap | Reason |
|---|---|
| 3GPP MBMS or MBS | Not in the present edition: no bearer, announcement, MuSiK, MBMS subchannel control or MB2 (TS 24.379 §14.2.2, TS 24.380 §10, TS 29.468). Only the listening status report of §14 is used. |
| Floor control over multicast | Floor Taken and Floor Idle carry the receiver's own SSRC and sequence number, and protected floor control needs each user's CSK (a MuSiK would be needed, TS 24.380 §6.4.2 step 3 a iv), so they stay unicast. |
| Removed participants | A participant that the server stops treating as eligible (for example removed from the group by the GMS) while its client still listens keeps receiving the host group's speech until its call ends. |
| Suspension status | Accepted without action. |
| Chat, broadcast and regroup calls | Implemented, but the scenario runs a prearranged call only. |
| Split servers, MCVideo, MCData | Refused by the server's configuration. |
| Android client and dispatcher | The Linux client only. |
| Several hosts | The lab runs on one Docker bridge; routing a host group across networks needs a multicast router. |
