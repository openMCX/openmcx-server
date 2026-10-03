# MCData affiliation status tests

These tests cover **MCData affiliation status determination and implicit affiliation** (TS 24.282 V19.7.0 §8.2.3, §8.3.2.4, §8.3.2.5 and §8.3.2.15): the client subscribes to its own affiliation status and the server notifies it of every change, including the groups a user is affiliated to implicitly.

Back to the [MCData test index](../MCDATA_TEST.md). The shared four-client fixture, the client status fields and the MCData deployment are described in the [standalone SDS tests](MCDATA_SDS_TEST.md), which also holds the shared coverage gaps. Architecture: MCData Phase 1 design, [standards and acceptance](../../docs/architecture/mcdata-standards-and-acceptance.md).

## How it works

- **Subscription.** SUBSCRIBE `presence` at the MCData PSI naming the user's own MCData ID. A long Expires keeps the subscription, Expires 0 on a new dialog fetches the current state once, and Expires 0 in the dialog ends it.
- **Notification.** The server NOTIFYs the per-user affiliation information whenever it changes, echoing the `<p-id>` of the PUBLISH that caused the change. The client takes its affiliation status from the NOTIFY.

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Affiliation | MCData PIDF; groups must list the user as an MCData member; Expires 0 de-affiliates, with or without a PIDF body | §8.2.2 (V19.7.0 NOTE 1), §8.3, §8.4.1 |
| Affiliation status determination | The client SUBSCRIBEs to `presence` at the MCData PSI with `mcdata-info` naming its own MCData ID, the MCData ICSI in P-Preferred-Service and `Accept: application/pidf+xml`. Expires 4294967295 keeps the subscription; Expires 0 on a new dialog fetches the current state once and Expires 0 in the dialog de-subscribes, each answered with one terminating NOTIFY. A subscription to another user's status is rejected with 403: no user is authorised to modify another user's affiliation here. The server NOTIFYs the per-user affiliation information (one tuple for the client, one `<affiliation>` per group with `status="affiliated"`) whenever the status changes, echoing the `<p-id>` of the PUBLISH that caused it, and at log-off sends a terminating NOTIFY. The client takes its affiliation status from the NOTIFY, not from the PUBLISH response, and repeats the groups it learned in its own PUBLISH so that implicit affiliations survive. | V19.7.0 §8.2.3, §8.3.2.4, §8.3.2.5, §8.4.1 |
| Implicit affiliation | `<ImplicitAffiliations>` in the user profile (`implicit_affiliations`): after service authorisation the server affiliates the user to each listed group of which it is an MCData member, and NOTIFYs the client. A group emergency alert implicitly affiliates an eligible member the same way (§16.2.3.1 step 4b-i). The N2 limit and the "affiliating" state are not modelled: the combined server also owns the groups, so affiliation is immediate. | V19.7.0 §8.3.2.12, §8.3.2.15, §8.3.3.6–8.3.3.7 |

### Client commands

```bash
mcx-client --config FILE --command 'mcdata-affiliate'      # or mcdata-deaffiliate
mcx-client --config FILE --command 'mcdata-affiliation-status fetch [<MCData ID>] | unsubscribe | subscribe'
```

## Performed tests

Recorded on **2026-09-22** against image `openmcx:0.29-mcdata` (`fb662f09297d`), TS 24.282 V19.7.0, clear SIP (debug mode), in a fresh lab captured from the first request: 163 scenario assertions and 64 wire checks on one MCData server instance. The scenario and the wire report cover every MCData SDS feature, so the evidence links below are shared with the other MCData SDS documents.

| ID | Scenario | Result evidence |
|---|---|---|
| AF-01 | Every client holds an affiliation status subscription whose NOTIFY matches the server; client-d is implicitly affiliated to its configured group and keeps it in its own PUBLISH | [Scenario report](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json), [wire report](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json), [capture](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap) |
| AF-02–AF-03 | A fetch (Expires 0) returns the current affiliations in one terminating NOTIFY; a fetch of another user's status is rejected with 403 | [Scenario report](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json), [wire report](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json), [capture](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap) |
| AF-04 | De-subscription ends with a terminating NOTIFY; a new subscription reports the unchanged affiliation | [Scenario report](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json), [wire report](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json), [capture](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap) |
| AF-05 | De-affiliation and re-affiliation are reported by NOTIFY, the second carrying the `<p-id>` of its PUBLISH | [Scenario report](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-results.json), [wire report](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds-sip-wire.json), [capture](../../artifacts/mcdata29-lab/artifacts/integration/mcdata-sds.pcap) |

## Coverage gaps

| Area | Gap |
|---|---|
| Affiliation status | Not implemented: negotiated mode (§8.2.4–8.2.5), rules based affiliation (§8.2.6), subscription to group dynamic data (§8.2.7), per-group affiliation information and the `simple-filter` body (§8.4.2), the "affiliating" and "deaffiliating" states with their expiry times and the N2 limit, and separate serving and owning servers (§8.3.2.6–8.3.2.7). The subscription is only for the user's own status. |
