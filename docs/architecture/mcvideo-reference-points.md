# MCVideo reference points

Inventory of the MCVideo application-plane reference points of TS 23.281 V19.10.0
§6.3 and their openMCX status. Common reference points (SIP-1/2/3, HTTP-1/2/3,
CSC-n) are in the [MCPTT inventory](mcptt-reference-points.md) and apply
unchanged to MCVideo. The increments (V0 to V14) are those of the
MCVideo plan.

| Reference point | Between | Protocol | Status |
|---|---|---|---|
| MCVideo-1 | MCVideo client – MCVideo server | SIP via SIP-1/SIP-2 (TS 24.281) | **Implemented** for service authorisation by PUBLISH and affiliation (V1, [tests](../../tests/mcvideo/MCVIDEO_AFFILIATION_TEST.md)); calls from V3 |
| MCVideo-2 | MCVideo server – MCVideo user database | Diameter, TS 29.283 (not supplied) | Not used: as for MCPTT and MCData, the server reads the user profile from the CMS. `mc-user-db` may serve it later |
| MCVideo-3 | MCVideo server – MCVideo server, and MCVideo server – MC gateway server | SIP via SIP-3 | Between the participating and controlling servers of one system: done in V10 ([tests](../../tests/mcvideo/MCVIDEO_SPLIT_TEST.md)); towards another system or a gateway: not in this edition |
| MCVideo-4 | Transmission control participant – transmission control server, unicast | RTCP APP `MCV0`, `MCV1`, `MCV2` over SGi (TS 24.581) | Planned: V3 |
| MCVideo-5 | MCVideo server – EPS | Rx | Not applicable to the IP lab (no PCC, as MCPTT-5) |
| MCVideo-6 | MCVideo server – EPS | MB2-C | Not applicable (MBMS, H4) |
| MCVideo-7 | Media distribution function – media mixer, unicast | RTP/SRTP over SGi, H.264 (TS 26.281) | Planned: V2 |
| MCVideo-8 | Media distribution function – media mixer, multicast | MB2-U | Not applicable (MBMS, H4) |
| MCVideo-9 | Transmission control participant – transmission control server, multicast | MB2-U (`MCV3` to `MCV5`) | Not applicable (MBMS/MBS, H4) |
| MCVideo-10 | MC gateway server – MC gateway server in another MCVideo system | SIP via SIP-3 | Not in this edition |

TS 23.281 §7.15 (resource management) is carried by Rx, N5 or N33 (TS 24.281
§4.11) and has no role in the IP lab. TS 23.281 §7.16 (client query) and §7.17
(adaptation) have no stage 3 procedure in TS 24.281 V19.6.0.
