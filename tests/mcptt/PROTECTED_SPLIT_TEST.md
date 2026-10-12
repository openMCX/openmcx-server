# Protected calls across MCPTT servers (SPK)

These tests cover **protected group and private calls when the participating and controlling functions are separate servers** of one MC system (TS 33.180 V19.4.0 §5.5, §9.2.3, §9.4.5). The Signalling Protection Key (SPK) protects the floor control between the servers. The results cover one system with three MCPTT servers. Calls between two MC systems stay unprotected; see [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented profile

| Step | Behavior | Reference |
|---|---|---|
| SPK | Each pair of MCPTT servers is provisioned with one 128-bit SPK, an SPK-ID with purpose tag 3, and a 128-bit SPK-RAND. It sits in `mcptt.servers.<peer>.spk` (`id`, `key`, `rand`) on both sides, and is active with no expiry of its own. | 33.180 §5.5 |
| Floor control between servers | The SPK is the KFC, the SPK-ID the KFC-ID and the SPK-RAND the KFC-RAND. The SRTCP master key and salt come from the MIKEY PRF with CS-ID 6, and the MKI is the SPK-ID. | 33.180 §9.4.5, §9.4.6 |
| Participating server | The client's floor control arrives under the client's CSK. The participating server opens it and seals it with the SPK toward the controlling server, and does the reverse in the other direction. A packet that fails either step is dropped and counted (`relay_refused`). Speech is protected end to end, under the GMK or PCK, and passes unchanged. | 33.180 §9.4.2, §9.4.5 |
| Controlling server | For a user another server serves, it protects floor control with that server's SPK instead of the user's CSK. The refusals "protected media not supported across MCPTT servers" remain only for a peer with no SPK. | 24.379 §10.1.1.4, §11.1.1.4 |

The CS-ID of Table E.1.3-1 names only client keys (CSK and MuSiK). The implementation uses 6, the MCPTT CSK value, for the SPK too.

## Running the tests

The protected group call on separate servers runs in the `xml-protection-split` and `xml-integrity-split` labs of the
regression. The protected private calls on separate servers run by hand on a prepared lab (the preparation command
needs a new directory):

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =xml-protection-split
python3 tools/prepare-prearranged-test.py --directory artifacts/spk-lab --project openmcx-spk \
  --images <tag> --client-image openmcx-client:<tag> \
  --debug-sip --split --private-call --protected --key-parameters-iei 0x79
mkdir -p artifacts/spk-lab/artifacts/speech && cp artifacts/speech/{alpha,bravo}.wav artifacts/spk-lab/artifacts/speech/
.cache/deps/docker-compose-linux-x86_64 -p openmcx-spk -f artifacts/spk-lab/compose.json up -d --wait
python3 tests/integration/prearranged_scenario.py --compose artifacts/spk-lab/compose.json \
  --artifacts artifacts/spk-lab/artifacts --project openmcx-spk
python3 tests/integration/protected_private_scenario.py --compose artifacts/spk-lab/compose.json \
  --artifacts artifacts/spk-lab/artifacts --project openmcx-spk
```

`--split --protected` provisions an SPK for every pair of servers (mcptt-server controlling, mcptt-part-1 serving client-a and client-c, mcptt-part-2 serving client-b and client-d). Each server also gets its `security` block and KMS identity.

## Checks

| Scenario | What is checked |
|---|---|
| [Protected group call lifecycle](EMERGENCY_PROTECTED_TEST.md) on separate servers | The participating servers re-key the floor packets between CSK and SPK and refuse none; the controlling server relays the encrypted speech |
| [Protected private calls](PROTECTED_PRIVATE_CALL_TEST.md) on separate servers (PP-01 to PP-07) | The caller and callee are served by different participating servers |

## Coverage gaps

| Area | Gap |
|---|---|
| Two MC systems | Not in present edition (External KMS, the GMK transfer between systems and the IS proxy of an MC gateway). |
| SPK lifecycle | The SPK is provisioned by configuration and never renewed or revoked. |
| Signalling between servers | With `--xml-protection`, the SPK also protects the MCPTT XML between the servers ([XML protection tests](XML_PROTECTION_TEST.md)). |
