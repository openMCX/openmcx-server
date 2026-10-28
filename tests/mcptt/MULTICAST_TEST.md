# MBMS delivery of group call media tests

These tests cover the **MBMS usage procedures** of TS 24.379 V19.7.0 §14 and the **MBMS subchannel control** of
TS 24.380 V19.2.0 §10 between the participating function and the Linux client, over **pre-activated MBMS bearers**
(TS 24.380 §4.1.3.1). There is no LTE or 5G radio and no BM-SC: each bearer is emulated by IPv4 host groups (RFC
1112) on the lab network, one per general purpose subchannel and one per MBMS subchannel of its pool, and the
client's MBMS interface (its modem) is emulated by the `mbms` block of its configuration and the `mbms area` and
`mbms quality` commands. Every MCPTT message on the wire is the 3GPP one. What the tests do not cover is listed under
[coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented procedures

| Part | Behavior | Reference |
|---|---|---|
| Server, announcement | `mcptt.mbms` lists the bearers (TMGI, QCI, MBMS service areas, general purpose subchannel, subchannel pool) and the users they are announced to. After each service authorisation such a user gets the MBMS bearer announcement: a SIP MESSAGE with the SDP (`render`: one media line on port 9 for the subchannels, one `m=application` per general purpose subchannel), the MBMS usage information (one `<announcement>` per bearer, `<GPMS>`) and P-Asserted-Identity set to the service PSI. The Bearer Announcement message goes over each general purpose subchannel every `bearer_announcement_ms`. | `src/server/mbms.cpp`; TS 24.379 §14.2.2.2, TS 24.380 §4.1.3.7, §8.4.7 |
| Server, subchannel control | When the floor of a group session is granted (or media flows) and served participants listen to a bearer's general purpose subchannel, the conversation gets a subchannel of that bearer's pool: Map Group To Bearer over the general purpose subchannel, repeated every T16 (500 ms); each RTP packet goes once over the subchannel for the participants that reported listening for the session, by unicast to the others; T15 (default 30 s) restarts with each. On T15 expiry with listeners, Unmap Group To Bearer over the subchannel, repeated every T17 (200 ms) up to C17 (3) times, then the subchannel returns to the pool; without listeners it is released at once; at the end of the call one Unmap Group To Bearer. No free subchannel: unicast. Private, ad hoc and ambient calls and calls without floor control stay unicast. MCPTT, `role` `both` only. | `src/server/mbms.cpp`, `McServer::audio_packet`; TS 24.380 §10.2, §8.4.4, §8.4.5, table 11.1.4-2 |
| Server, floor control | Floor Taken and Floor Idle destined to participants listening to the conversation's subchannel go once over it (control on the media port, RFC 5761), with the server's SSRC (the Map Group To Bearer header's), a message sequence number of the conversation and the acknowledgement bit '0', and not by unicast; T15 restarts. The other floor control messages stay unicast. Under protected floor control (no MuSiK yet) everything stays unicast. | `McServer::mbms_control`, `McpttServer::send_floor_notice`; TS 24.380 §10.2.3.2 to §10.2.3.4 |
| Server, keys | With `mscck`, an MSCCK (purpose tag 5, made by the key management client on first use) goes in the "a=key-mgmt" attribute of each general purpose media line of the announcement, a MIKEY-SAKKE I_MESSAGE to each user signed by the server's PSI; Map Group To Bearer, Unmap Group To Bearer (and Application Paging) are then SRTCP under it (MKI: the MSCCK-ID); the Bearer Announcement message stays clear (it has no SSRC). With `musik`, after the announcement each user gets the default MuSiK download (a SIP MESSAGE with `<mbms-defaultMuSiK-download>` and the MuSiK's I_MESSAGE); protected floor control then goes over the subchannel as SRTCP under the MuSiK for the users that answered 200, and by unicast to the others. | `src/server/mbms.cpp`; TS 24.379 §14.2.2.2 step 5 d, §14.2.2.5, TS 24.380 §13, TS 33.180 §9.2.2, annex H |
| Server, suspension and notifications | A "suspending" report for an announced bearer moves each of its conversations to unicast (Application Paging over the subchannel, then Unmap Group To Bearer) and maps no new conversation on it until a "not-suspending" report. When a group's dynamic data changes (a call ongoing or not; the emergency or imminent peril state and who set it), Group Dynamic Data Notify goes over the general purpose subchannel of each bearer one of its affiliated members listens to (SRTCP under the MuSiK when there is one). | `src/server/mbms.cpp`; TS 24.379 §14.2.3, TS 24.380 §4.1.3.6, §10.2.3.12, §10A.1, §8.5.4 |
| Server, 5G MBS | A bearer with `"system": "mbs"` is a 5G MBS session (its `tmgi` the MBS session ID, a TMGI; `mode`, `report_join`, `fsa_ids`): it is announced in `application/vnd.3gpp.mcptt-mbs-usage-info+xml` (`<mbs-session-info>`), its subchannel control is "MCSC" (MapGroupToSessionStream and UnMapGroupFromSessionStream with the MBS session ID and the floor control SSRC, Session Announcement), and its reports come in the MBS body: listening status with `<unicast-listening-status>`, de-announcement status (as suspension: "deleting" moves its conversations to unicast) and UE session join notifications (listed in `mbs_joined`). | `src/server/mbms.cpp`, `src/server/multicast.cpp`; TS 24.379 §14B, annex F.2A, annex L.3.4, TS 24.380 §8.6, §10B |
| Server, reports | A SIP MESSAGE with `application/vnd.3gpp.mcptt-mbms-usage-info+xml` from a served user: a report on the general purpose subchannel is taken for announced TMGIs from a user on the list ("not-listening" there also ends the user's listening to the subchannels, NOTE 2); "listening" for a session is taken for a session with a subchannel, its bearer's TMGI, from a user on the list in the session; "not-listening" is always taken. Refused with 403: an `<announcement>`, an mcptt-info naming another MCPTT ID, and a report failing any of the conditions above. A suspension status is answered 200 without action. | `src/server/multicast.cpp`; TS 24.379 §14.2.3, §14.2.4 |
| Client | The `mbms` block gives the MBMS service areas the UE is in. The client stores each announcement by TMGI with its SDP, the address of the `<GPMS>` line and the MBMS PSI; while in one of the bearer's service areas with good radio conditions it joins the general purpose subchannel and reports "listening" (`<general-purpose>` true), and "not-listening" when it stops. A Bearer Announcement message is acknowledged with a report. A Map Group To Bearer message maps a group to a subchannel; for the group of the active call the client joins it and reports "listening" for the session and TMGI; speech from the subchannel takes the unicast path (SSRC of Floor Taken, payload type, SRTP), the talker drops its own, and while joined a packet not newer than the last kept one of the same SSRC is dropped as a copy. Unmap Group To Bearer: "not-listening" for the session, the subchannel left 200 ms after the server's answer. Floor Taken and Floor Idle from the subchannel (the server's address, the Map Group To Bearer's SSRC, sequence numbers of their own) go to the floor participant; the talker's own Floor Taken is ignored; no Floor Ack is sent. An "a=key-mgmt" in the general purpose media line is opened (initiator the announcing PSI, else 488 with warning 136) and the MSCCK protects that bearer's subchannel control (a clear one is then refused); a MuSiK download is opened the same way, and protected floor control from the subchannel is SRTCP under it (told apart by the MKI's purpose tag). `mbms suspend|resume <TMGI>` (the RAN's notice) reports "suspending" or "not-suspending" for a bearer reported listening to, unless the announcement said `<report-suspension>` false. Application Paging is counted (an emulated UE is always connected); Group Dynamic Data Notify is kept in the status by group. On a 5G MBS session the same procedures use the MBS body and "MCSC"; for a multicast session whose announcement asks for it, a UE session join notification ("ue-session-join", then for the session when its subchannel is joined; "ue-session-leave" when it stops) precedes the listening reports, and `mbms suspend|resume` sends the de-announcement status. | `src/client/core/mbms.cpp`, `src/client/mcptt/multicast.cpp`; TS 24.379 §14.3.2, §14.3.3, TS 24.380 §10.3, RFC 3550 appendix A.1 |

## Running the tests

```bash
python3 tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select multicast,mbs
```

The labs are generated with `--multicast`: one pre-activated bearer (`mcptt.mbms`, TMGI `00000199f907`: MBMS
Service ID 000001, MCC 999, MNC 70; MBMS service area `0001`; general purpose subchannel `239.10.1.1:40100`;
subchannels `239.10.0.2:40002` and `239.10.0.3:40004`; Bearer Announcement every 5 s; T15 10 s) announced to the
four users. client-d's emulated MBMS interface starts in area `0002`. `multicast-protected` adds protected media and
floor control (`--protected`). `mbs` (`--multicast --mbs`) runs the same scenario over a 5G MBS session (multicast
mode, UE session join notifications, "MCSC").

## Checks

| ID | Check |
|---|---|
| MB-01 | The MBMS bearer is announced to the four users (TS 24.379 §14.2.2.2); each client stores it with the general purpose subchannel of its SDP (§14.3.2). |
| MB-02 | client-a to client-c, in the bearer's service area, join the general purpose subchannel and the server takes their "listening" reports with `<general-purpose>` (§14.3.3); client-d, outside, does not listen. |
| MB-03 | The Bearer Announcement message sent over the general purpose subchannel (TS 24.380 §4.1.3.7) reaches the listeners, not client-d. |
| MB-04 | `mbms area 0001`: client-d enters the service area, listens and is taken. |
| MB-05 | `mbms quality bad`: client-c reports "not-listening" and leaves; `mbms quality good`: it listens again. |
| MB-06 | `mbms area 0002`: client-d leaves the service area and reports "not-listening". |
| MBS-01 | `mbs` only: every client stored a 5G MBS session announcement, and client-a to client-c sent the UE session join notification the server lists (TS 24.379 §14B.3.5). |
| MS-01 | A prearranged group call with the four clients; no subchannel is mapped before the floor is granted. |
| MS-02 | Warm-up burst of client-a: Map Group To Bearer gives the conversation the first subchannel of the pool (TS 24.380 §10.2.2.2). |
| MS-03 | Map Group To Bearer is repeated every T16 (§10.2.3.7). |
| MS-04 | client-a to client-c join the subchannel and the server takes their "listening" reports for the session (TS 24.379 §14.3.3.1 condition 1). |
| MS-05 | client-d, outside the service area, stays on unicast. |
| MC-04 | Burst 1, client-a talks: every receiver receives every packet once, the talker none; the server sends one copy per packet over the subchannel, and as many unicast copies as arrive by unicast (all to client-d); client-b and client-c receive only from the subchannel. |
| MC-05 | Burst 2, client-b talks, and client-c's radio turns bad (`mbms quality bad`) after 60 packets from the subchannel: its "not-listening" on the general purpose subchannel takes it off the subchannel (TS 24.379 §14.2.3 NOTE 2), it leaves, and receives the rest of the burst by unicast, every packet once. |
| MC-06 | `mbms quality good`: client-c listens again, rejoins on the next Map Group To Bearer; burst 3, client-a talks, client-c receives only from the subchannel. |
| MS-08 | The listeners received Floor Taken and Floor Idle over the subchannel, client-d none; under protected floor control none went there. |
| MS-09 | `multicast-protected` only: the server made an MSCCK (purpose tag 5) and a MuSiK (6); every client took the MSCCK of the announcement and the MuSiK download; the floor messages of MS-08 were SRTCP under the MuSiK. |
| MS-10 | With the call set up, client-a to client-c receive a Group Dynamic Data Notify over the general purpose subchannel saying a call is ongoing; client-d (outside) none (TS 24.380 §10A.1). |
| MS-06 | A silence longer than T15: Unmap Group To Bearer over the subchannel, repeated until C17, then the conversation is released (§10.2.3.6, §10.2.3.8, §10.2.3.9). |
| MS-07 | The clients reported "not-listening" and left the subchannel (§10.3.4); the server counts nobody listening. |
| MS-11 | A new talk burst maps a new conversation, listened to by client-a to client-c. |
| MS-12 | `mbms suspend`: client-b reports the bearer about to be suspended; the server sends Application Paging to the listeners (not client-d), unmaps and releases the conversation; the clients leave the subchannel (TS 24.379 §14.2.3, TS 24.380 §4.1.3.6, §10.2.3.12, §10.3.5). |
| MS-13 | While the bearer is suspended the next talk burst goes by unicast to everyone; nothing is mapped. |
| MS-14 | `mbms resume`: "not-suspending" lets the bearer take conversations again. |
| MC-07 | The call is released; every client has left the subchannel. |
| MS-15 | After the release, Group Dynamic Data Notify says no call is ongoing. |
| MC-08 | client-c (MBMS, unicast, MBMS) and client-d (unicast) decoded the same speech: their received WAV files are equal. |
| Wire | `verify_multicast.py` on the capture at the MCPTT server: as many speech packets to the subchannel as the server counted, with time-to-live 1, from the server's address; to each client as many unicast speech packets as arrived there by unicast (none to client-a and client-b, all to client-d); as many Map Group To Bearer messages to the general purpose subchannel and Unmap Group To Bearer messages to the subchannel as the server counted, and as many floor control messages to the subchannel (clear, or SRTCP with a MuSiK MKI); as many Application Paging messages; in `multicast-protected` no Map or Unmap Group To Bearer is clear. |

## Results

Debug TCP SIP, 2026-10-28, images from the multicast branches (server and client binaries layered on the full
`mb1` images):

| Lab | Result | Evidence |
|---|---|---|
| `multicast` | 2 of 2 passed (scenario and wire) | Bursts of 337 (warm-up), 337, 355 and 337 packets, all 1366 over the subchannel; burst 2: client-c 80 by MBMS, 275 by unicast; 86 Map Group To Bearer, 4 Unmap Group To Bearer |
| `multicast-protected` | 2 of 2 passed (scenario and wire) | The same with SRTP under the GMK |
| `smoke` (no MBMS) | 2 of 2 passed | The unicast prearranged scenario and its wire check are unchanged |

## Coverage gaps

| Gap | Reason |
|---|---|
| Floor Release Multi Talker | The server has no multi-talker floor control. |
| Refused key downloads | The client's 488 with warning 136 (an I_MESSAGE from another initiator or that fails) and the server's unicast fallback for a user without the MuSiK are implemented but not driven by a scenario. |
| Explicit MuSiK downloads, MuSiK per group, key renewal | The server sends one default MuSiK; the client takes explicit downloads as the default one. |
| Subscription to group dynamic data | The server has no SIP subscription to group dynamic data (TS 24.379 §9.2.1.6, §9.2.2.3.9); it sends Group Dynamic Data Notify over MBMS on every change instead of in place of a NOTIFY. Broadcast and regroup aliases are not sent. |
| Application Paging before a unicast call | Sent only when a conversation moves to unicast (§4.1.3.6), not before a call starts on unicast (§4.1.3.5). |
| eMBMS and 5G MBS co-existence | `<eMBMS-bearer-info>` in an MBS announcement is not written or read; a server announces MBMS bearers and MBS sessions in separate bodies of one MESSAGE. |
| MBS session IDs | Only TMGI-typed MBS session IDs; a source specific IP multicast address is not used. |
| MB2 to a BM-SC | Bearers are configured as activated; TS 29.468 is not used. |
| Removed participants | A participant that the server stops treating as eligible (for example removed from the group by the GMS) while its client still listens keeps receiving the subchannel until the conversation is unmapped. |
| Chat, broadcast and regroup calls | Implemented, but the scenario runs a prearranged call only. |
| Split servers, MCData | Refused by the server's configuration. |
| Android client and dispatcher | The Linux client only. |
| Several hosts | The lab runs on one Docker bridge; routing a host group across networks needs a multicast router. |
