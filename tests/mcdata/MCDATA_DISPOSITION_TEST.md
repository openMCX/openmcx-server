# MCData disposition handling tests

These tests cover the handling of **SDS disposition notifications beyond their delivery** (TS 24.282 V19.7.0 §12.2.2.1 steps 5–6 and §12.2.3 step 15c): storage and re-delivery of an undelivered message with timer TDP1, and aggregation of a group's notifications with timer TDC1.

Back to the [MCData test index](../MCDATA_TEST.md). The shared four-client fixture, the client status fields and the MCData deployment are described in the [standalone SDS tests](MCDATA_SDS_TEST.md), which also holds the shared coverage gaps. Architecture: MCData Phase 1 design, [standards and acceptance](../../docs/architecture/mcdata-standards-and-acceptance.md).

## How it works

- **Undelivered.** A client that cannot deliver a message reports UNDELIVERED. The participating function stores the message, starts TDP1 and re-delivers it at expiry, bounded by local policy.
- **Aggregation.** For a group message the controlling function collects the disposition notifications and sends them to the originator in one SIP MESSAGE, at TDC1 expiry or once every recipient has reported.

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Notification aggregation | For group and ad hoc group SDS, the controlling function collects the disposition notifications for a message: TDC1 (default 5 s, configurable) starts with the first one. It sends them to the originator in one SIP MESSAGE when TDC1 expires or when every recipient has sent its last expected notification (DELIVERED for a delivery request; READ or DELIVERED AND READ otherwise). That MESSAGE carries the calling group, no calling user, and one `application/vnd.3gpp.mcdata-signalling` body per notification, split at 50 per MESSAGE (NOTE 6). Notifications arriving after the aggregate are relayed individually (step 15d). Each body names its notifier in the optional Sender MCData user ID IE, which openMCX clients always set; a notification without it is relayed individually, and one naming another user is rejected with 403. Aggregation is enabled by local policy (`mcdata.aggregation`). TS 24.282 has no separate aggregate coding; the counts of TS 23.282 Table 7.4.2.1.9A-1 are implied by the bodies. | V19.7.0 §12.2.3 step 15c–15d, NOTE 6, Table F.2.2-1; TS 23.282 §7.4.2.1.9A |
| Undelivered messages | A client that cannot deliver a message to the user or application (here: its local storage is full) does not deliver it and sends an SDS NOTIFICATION `UNDELIVERED` naming the sender, whatever disposition was requested. The participating function keeps a copy of each SDS it delivers (local policy: 10 minutes, at most 1000). On `UNDELIVERED` it stores the message, starts TDP1 (default 60 s, configurable) and answers 200 without relaying it; at TDP1 expiry it re-delivers the stored message unchanged. A positive notification deletes the stored message and stops TDP1. Local policy bounds the attempts (`max_attempts`, default 3): a further `UNDELIVERED` discards the message. A recipient who has logged off, or left the group of a group SDS, is retried at the next TDP1 while the copy is retained. | V19.7.0 §6.2.3.1 step 4, §12.2.1.1, §12.2.2.1 steps 5–6, Table F.2.1-1 |

### Client commands

```bash
mcx-client --config FILE --command 'mcdata-storage full|unlimited|<n>'   # received messages the client can hold
```

## Performed tests

Recorded on **2026-09-22** against image `openmcx:0.29-mcdata` (`fb662f09297d`), TS 24.282 V19.7.0, clear SIP (debug mode), in a fresh lab captured from the first request: 163 scenario assertions and 64 wire checks on one MCData server instance. The scenario and the wire report cover every MCData SDS feature, so the evidence links below are shared with the other MCData SDS documents.

| ID | Scenario | Result evidence |
|---|---|---|
| AG-01 | The three DELIVERED notifications of SD-08 arrive in one aggregated SIP MESSAGE as soon as every recipient has reported | Scenario report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap`) |
| AG-02 | Read requested: two members read, one does not; nothing reaches the sender while TDC1 runs; at expiry one aggregate carries both READ notifications; the third member's later READ is relayed individually with the notifier as calling user | Scenario report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap`) |
| RD-01 | A client without storage reports UNDELIVERED for a one-to-one SDS and does not deliver it; the server stores it with TDP1 running; the originator receives nothing | Scenario report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap`) |
| RD-02 | TDP1 expiry re-delivers the message (undelivered again, second attempt); after storage is freed the next re-delivery reaches the user with the same Message ID, DELIVERED reaches the originator and the stored copy is deleted | Scenario report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap`) |
| RD-03 | Group SDS: the other members deliver; for the member without storage the message is discarded after the attempt limit (three UNDELIVERED), and the originator gets no notification from that member | Scenario report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap`) |

## Coverage gaps

| Area | Gap |
|---|---|
| Undelivered messages | Storage is in memory and lost on restart. The client reports UNDELIVERED only when its storage limit is reached. The UNDELIVERED path for FD is not implemented. |
| Aggregation | Aggregation is all-or-nothing by local policy, not per group or per message. Notifications collected when the originator has logged off are dropped. |
