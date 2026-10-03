# MCData reference points

Inventory of the MCData application-plane reference points of TS 23.282 V19.10.0
§6.4.4 to §6.8.4 and their openMCX Phase 1 status. Common reference points
(SIP-1/2, HTTP-1/2, CSC-n) are in the [MCPTT inventory](mcptt-reference-points.md)
and apply unchanged to MCData.

| Reference point | Between | Protocol | Phase 1 status |
|---|---|---|---|
| MCData-2 | MCData server – MCData user database | Diameter, TS 29.283 | Planned: `mcdata-server` to `mc-user-db`, as MCPTT-2 |
| MCData-3 | MCData server – MCData server | SIP via SIP-3 | Not in this edition: the MCData server is one combined participating and controlling function |
| MCData-6 | MCData server – EPS | Rx / N5 | Not applicable to the IP lab |
| IWF-2 | Interworking function – MCData server | TS 29.582 | Not in scope |
| MCData-7 | Message store client – MCData message store | HTTP | **Implemented** (MD-MS-01), from TS 24.282 clause 21 without the OMA NMS specifications ([message store tests](../../tests/mcdata/MCDATA_MESSAGE_STORE_TEST.md)) |
| MCData-8 | MCData message store – MCData server | HTTP | **Implemented**: deposit by the MCData server of the communications a user chose to store; SDS and FD over HTTP only (MD-MS-01) |
| MCData-9 | MC gateway server – MC gateway server | SIP | Not in this edition |
| MCData-10 | Message notification client – notification server | HTTP | **Implemented**, LongPolling notification channels only (MD-MS-01) |
| MCData-11 | MCData message store – notification server | HTTP | **Implemented** (MD-MS-01) |
| **MCData-SDS-1** | SDS distribution function – SDS function (client) | SIP MESSAGE via SIP-1/SIP-2 | **Implemented** (Milestone M1) |
| MCData-SDS-2 | SDS distribution function – SDS function, unicast | MSRP over SGi (TS 24.582) | **Implemented** (MD-MP-01, MD-MP-02, MD-MP-06) |
| MCData-SDS-3 | SDS distribution function – SDS function, multicast | MB2-U | Not applicable (H4) |
| MCData-FD-1 | FD function (client) – MCData server | SIP via SIP-1/SIP-2 | **Implemented** (MD-FD-01 to MD-FD-06) |
| MCData-FD-2 | FD functions, unicast | MSRP over SGi | **Implemented** (MD-MP-05) |
| MCData-FD-3 | FD functions, multicast | MB2-U / xMB-U | Not applicable (H4) |
| MCData-FD-4 | Media storage client – media storage function | HTTP | **Implemented** (`mcdata-content-server`) |
| MCData-FD-5 | FD function – media storage function | HTTP | **Implemented** |
| MCData-FD-7 | Media storage function – message store | HTTP | **Implemented**: upload by reference of a file in the message store (MD-FD-06), and the message store fetching a deposited file (MD-MS-01) |
| MCData-DS-1..3 | Data streaming functions | SIP / media plane | Not implemented |
| MCData-IPcon-1 | IPcon distribution function – IPcon function | SIP via SIP-1/SIP-2 | **Implemented**, one-to-one (MD-IP-01) |
| MCData-IPcon-2 | IPcon distribution – IPcon function, unicast | IP data over the media plane | **Implemented**: a GRE-in-UDP tunnel relayed by the server (MD-IP-01) |
| MCData-IPcon-3 | IPcon distribution – IPcon function, multicast | Multicast | Not applicable (H4) |

MCData-SDS-1 carries both the SDS data (when it fits the configured signalling
plane limit) and the delivered and read requests and notifications (23.282
§6.5.4.1.1). Larger payloads need MCData-SDS-2.
