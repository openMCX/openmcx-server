# MCData ad hoc group SDS tests

These tests cover **ad hoc group short data service** (TS 24.282 V19.7.0 §9.2.2.4.2 step 6A with the ad hoc group authorisation of clause 24): a sender names the participants, a criteria expression or an existing ad hoc group, and the server generates the ad hoc group identity and delivers with it.

Back to the [MCData test index](../MCDATA_TEST.md). The shared four-client fixture, the client status fields and the MCData deployment are described in the [standalone SDS tests](MCDATA_SDS_TEST.md), which also holds the shared coverage gaps. Acceptance: [MCData acceptance matrix](../../docs/architecture/mcdata-standards-and-acceptance.md).

## How it works

- **Request.** A SIP MESSAGE with `request-type` `ad-hoc-group-sds` and the client ID, carrying either a `resource-lists` participant list, a `<comn-participants-criteria>` expression, or the identity of an ad hoc group the sender already belongs to.
- **Resolution.** The server resolves the participants, applies the ad hoc authorisation and participation checks, generates the ad hoc group identity, records its members and delivers the message with that identity as the calling group. The 202 names the identity so that the sender can address follow-ups to it.

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Ad hoc group SDS | `request-type` `ad-hoc-group-sds` with the client ID and one of: a `resource-lists` participant list, `<comn-participants-criteria>`, or the identity of an existing ad hoc group the sender belongs to (follow-ups and replies). The server checks `<allow-adhoc-group-data-comn>` (`238`) and service support (`239`), resolves the participants, enforces the participant limit (`242`), skips participants without `<allow-adhoc-group-data-comn-participation>` (`241` if none remain), generates the ad hoc group identity, records its members and delivers with that identity in `mcdata-calling-group-id`. `240` when no participants can be determined. Criteria are local policy: comma-separated `affiliated:<MCData group>` and `member:<MCData group>`, resolved by the combined server itself. The 202 carries `mcdata-info` with the ad hoc group identity (project decision; TS 24.282 provides it through ad hoc group determination, §24.2.7.2). Warning codes follow the MCData table (§4.9.2): the procedure text cites the MCPTT codes 188 and 189 for 241 and 242. | V19.7.0 §9.2.2.2.1 step 3A, §9.2.2.3.1 step 4c, §9.2.2.4.2 step 6A, §24.3.2.1, §24.4.2, §24.4.6 |

### Client commands

```bash
mcx-client --config FILE --command 'sds-adhoc [delivery|read|both] [app=<n>] [priority=<n>] <ID,ID,...|criteria=<criteria>|group=<ad hoc group>> <text>'
```

## Performed tests

The tests run in the SDS scenario (`mcdata_sds_scenario.py`, 163 assertions) and its wire verifier (`verify_mcdata_sds.py`, 64 checks), clear SIP (debug mode), on one MCData server instance; the regression runs them in the `mcdata` lab. The scenario and the wire report cover every MCData SDS feature, so the evidence below is shared with the other MCData SDS documents.

| ID | Scenario | Result evidence |
|---|---|---|
| AD-01–AD-02 | Ad hoc group SDS to a participant list: 202 names a generated ad hoc group identity; the server records initiator and participants; only the listed users receive it with that identity; a DELIVERED notification from each naming the ad hoc group | Scenario report (`artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/integration/mcdata-sds.pcap`) |
| AD-03–AD-04 | A reply, and a follow-up addressed to the ad hoc group identity, reach the other members in the same group | Scenario report (`artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/integration/mcdata-sds.pcap`) |
| AD-05–AD-06 | Participants from criteria (`affiliated:<group>`) in a new ad hoc group; users without participation permission are skipped, both from criteria and from a list | Scenario report (`artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/integration/mcdata-sds.pcap`) |
| AD-07 | Ad hoc rejections 238, 242, 241 and 240 (no user meets the criteria, unknown criteria, unknown ad hoc group) | Scenario report (`artifacts/integration/mcdata-sds-results.json`), wire report (`artifacts/integration/mcdata-sds-sip-wire.json`), capture (`artifacts/integration/mcdata-sds.pcap`) |

## Coverage gaps

| Area | Gap |
|---|---|
| Ad hoc group SDS | Not implemented: ad hoc group determination (`ad-hoc-group-determination`, §24.2.7.2); a preconfigured group supplying the ad hoc group configuration (`<preconfigured-group>`, §24.1); the emergency-alert ad hoc group (`<adhoc-grp-emg-alert-grp-ind>`); criteria via the terminating participating functions (`get-userlist-adhoc-group-data-comn-request`, §24.4.6); participant modification and release (§24.2.3–24.2.6). The 239 path (ad hoc data communication switched off for the service) is implemented but not exercised: it is a server-wide setting, and the fixture keeps ad hoc SDS on. |
