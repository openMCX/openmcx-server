# MCData enhanced status tests

These tests cover **MCData enhanced status** on-network (TS 24.282 V19.7.0 clause 14.2). A member shares one of its group's operational values, such as "On scene", with the other members of an MCData group as a group standalone SDS. The recorded results cover the implemented subset below, not complete conformance.

Back to the [MCData test index](../MCDATA_TEST.md). The group SDS it travels in is described in the [standalone SDS tests](MCDATA_SDS_TEST.md), which also hold the shared four-client fixture. Acceptance row: MD-ES-01 in the [MCData acceptance matrix](../../docs/architecture/mcdata-standards-and-acceptance.md).

## How it works

- **The group document.** The GMS serves `<mcdata-allow-enhanced-status>` and `<mcdata-enhanced-status-operational-values>` in the group's `<list-service>`. The second element holds one `<status>` per value, with its `<id>`, `<shortText>` and `<description>` (TS 24.481 §7.2.4.2).
- **Sending** (§14.2.1.1). The client reads the group document. It refuses to send if enhanced status is not allowed on the group, or if the chosen id is not one of the group's operational values. Otherwise it sends a group standalone SDS (§9.2.2.2.1) whose DATA PAYLOAD holds one Payload IE of content type ENHANCED STATUS (6) carrying the id.
- **The server** treats it as any group SDS (§14.2.2, §14.2.3). The transmission control of §9.2.2.4.2 step 6 applies, and the message goes to every other affiliated member.
- **Receiving** (§14.2.1.2). The client matches the id against the operational values of the calling group's document. It renders the matching value; otherwise it discards the message.

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Group document | `<mcdata-allow-enhanced-status>` and `<mcdata-enhanced-status-operational-values>` with `<status>` entries (`<id>`, `<shortText>`), from `allow_enhanced_status` and `enhanced_status_values` of the group's MCData settings; the client rejects a malformed flag and a missing or repeated id | §14.2.1.1, §14.2.1.2 |
| Sending | Group SDS with one ENHANCED STATUS payload carrying the id; refused by the client when the group does not allow it or does not know the id | §14.2.1.1, table 15.2.13-2 |
| Delivery | As a group SDS: warning `201` without transmit permission on the group, and delivery to every other affiliated member with the calling group | §14.2.2, §14.2.3 |
| Rendering | The received id is matched against the calling group's operational values; a match is rendered with the sender and group, and anything else is discarded | §14.2.1.2 |

### Client commands and status

```bash
mcx-client --config FILE --command 'sds-status-values <group>'          # the group's operational values, into status.json
mcx-client --config FILE --command 'sds-status <group> <id>'            # share an enhanced status
mcx-client --config FILE --command 'sds-status <group> <id> force'      # test aid: skip the client's checks
```

`status.json` records `mcdata_enhanced_status_values` (per group, whether it is allowed and its values) and `mcdata_enhanced_status` (each rendered status with its message ID, sender, group, id and value). A discarded status counts in `mcdata_discarded`.

## Fixture and commands

The `--mcdata` fixture gives group `operations` enhanced status with the values `1` "On scene", `2` "En route" and `3` "Available". `operations-noemergency` has a value but does not allow enhanced status. client-c may not transmit on `operations`.

```bash
docker build -t openmcx:<tag> -f docker/Dockerfile .
python3 tools/prepare-prearranged-test.py --directory artifacts/mcdata-status-lab --project openmcx-mcdata-status \
  --debug-sip --private-call --mcdata --image openmcx:<tag>
C=".cache/deps/docker-compose-linux-x86_64 -p openmcx-mcdata-status -f artifacts/mcdata-status-lab/compose.json"
$C up -d mcdata-server                      # start the capture before the clients authorise
docker run -d --rm --name openmcx-mcdata-status-capture --network "container:$($C ps -q mcdata-server)" \
  --cap-drop ALL --cap-add NET_RAW openmcx-dev:0.4 \
  sh -c "tcpdump -Z root -i eth0 -U --immediate-mode -s 0 -w /tmp/c.pcap 'tcp port 5060'"
$C up -d
python3 tests/integration/mcdata_status_scenario.py \
  --compose artifacts/mcdata-status-lab/compose.json --artifacts artifacts/mcdata-status-lab/artifacts --project openmcx-mcdata-status
docker cp openmcx-mcdata-status-capture:/tmp/c.pcap artifacts/mcdata-status-lab/artifacts/integration/mcdata-status.pcap
python3 tests/integration/verify_mcdata_status.py artifacts/mcdata-status-lab/artifacts/integration/mcdata-status.pcap \
  --service sip:mcdata@mcx.test --output artifacts/mcdata-status-lab/artifacts/integration/mcdata-status-sip-wire.json
docker rm -f openmcx-mcdata-status-capture         # the reports and the capture are kept; the lab is not
$C down -v
```

## Performed tests

The scenario (`mcdata_status_scenario.py`) makes 11 assertions and its wire verifier (`verify_mcdata_status.py`) 6 checks, clear SIP (debug mode), on one MCData server instance; the regression runs them in the `mcdata` lab, and with protected signalling in `mcdata-xml`.

| ID | Scenario | Result evidence |
|---|---|---|
| ES-01 | The group document allows enhanced status and names the three operational values | Scenario report (`artifacts/integration/mcdata-status-results.json`) |
| ES-02 | A status is accepted with 202 and every other affiliated member renders "On scene" from its own group document; the sender does not receive it; another member reports "En route" | Same report |
| ES-03 | The client refuses a group without `<mcdata-allow-enhanced-status>` and an id the group does not know | Same report |
| ES-04 | An id without a matching operational value, sent with the test aid, is relayed by the server and discarded by each member without being rendered | Same report |
| ES-05 | A member without transmit permission on the group is rejected with 403/201 | Same report |
| ES-06 | SIP wire checks (6), with the DATA PAYLOAD decoded independently of the C++ codec: a `group-sds` to the PSI with one ENHANCED STATUS payload carrying the id, the ids sent, the delivery of the same payload to each member with the calling group and the calling user | Wire report (`artifacts/integration/mcdata-status-sip-wire.json`), capture (`artifacts/integration/mcdata-status.pcap`) |
| ES-07 | Unit tests: the enhanced status elements of a group document, and the rejection of an invalid flag and of a missing or repeated id (`test_protocol`); the GMS serving them, with XML escaping (`go test`) | Image build and `go test ./...` |

## Coverage gaps

| Area | Gap |
|---|---|
| Schema | The elements follow TS 24.481 §7.2.4.2, but the group document is validated against the elements this implementation knows, not the full schema. |
| Off-network | Enhanced status off-network (§14.3): not in present edition. |
| Presentation | The client renders a status into `status.json`; there is no user interface. The group document is read when a status is sent and cached for rendering, so a change of the group's values reaches a receiving client only after it sends or lists values again. |
