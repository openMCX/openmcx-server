# MCVideo service authorisation and affiliation tests

These tests cover **increment V1 of the MCVideo plan**: MCVideo service authorisation by SIP PUBLISH (TS 24.281 V19.6.0 §7.2.2, §7.3.3) and MCVideo affiliation with its status subscription (clause 8), between the MCVideo client module of `mcx-client` and `mcvideo-server`, beside MCPTT on the same SIP registration (§7.1).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (rows MV-AUTH-01, MV-AFF-01, MV-CODEC-01).

## How it works

- **Identities.** Each user has an MCVideo ID (`sip:<user>.mcvideo@DOMAIN`), carried in the IdMS access token (`mcvideo_id`) and served by the CMS. The MCVideo PSI is `sip:mcvideo@DOMAIN`; the SIP core routes it to `mcvideo-server`.
- **Registration.** The UE keeps one registration for all its MC services: with MCVideo configured, its Contact carries `+g.3gpp.mcptt;+g.3gpp.mcvideo` and both ICSIs in `+g.3gpp.icsi-ref` (§7.2.1AA).
- **Service authorisation.** After its MCPTT authorisation the client sends PUBLISH `poc-settings` to the MCVideo PSI with P-Preferred-Service `urn:urn-7:3gpp-service.ims.icsi.mcvideo`, an `<mcvideoinfo>` body (access token, client ID) and a `poc-settings` body (§7.2.1A, §7.2.2). The server introspects the token at the IdMS and binds the token's MCVideo ID, the client ID and the asserted SIP identity (§7.3.3 step 5); a refused token gets 403 with warning `101` (step 6).
- **Affiliation.** The client subscribes to its affiliation status (SUBSCRIBE `presence`, §8.2.1.3), then affiliates with PUBLISH `presence`: `<mcvideoinfo>` (own MCVideo ID, client ID) and a PIDF in `urn:3gpp:ns:mcvideoPresInfo:1.0` with a `p-id` (§8.2.1.2, §8.3.1). The server checks MCVideo group membership at the GMS (the group's `mcvideo` members) and answers with a NOTIFY listing the affiliated groups and echoing the `p-id`. De-affiliation is PUBLISH with Expires 0.
- **Server.** `mcvideo-server` runs the shared core with the MCVideo profile: the same authorisation and affiliation procedures as MCPTT, in the MCVideo namespaces and with the TS 24.281 warning table. It refuses an affiliation document of another service.

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Authorisation | Token introspection; MCVideo ID from the token, client ID and SIP identity must match; 403 `101` otherwise; the token's subject stays the MCPTT ID | 24.281 §7.2.1A, §7.2.2, §7.3.3 |
| Registration | One Contact with both MC services' feature tags and ICSIs | §7.1, §7.2.1AA |
| Affiliation | Status subscription first; PIDF in the MCVideo namespace with `p-id`; MCVideo membership from the GMS; 403 for a non-member or another service's document; Expires 0 de-affiliates | §8.2.1.2, §8.2.1.3, §8.2.2.2.3, §8.3.1 |
| NOTIFY `p-id` | The NOTIFY a PUBLISH triggers carries that PUBLISH's `p-id` | §8.2.2.2.5 step d |
| MCPTT | Unchanged beside MCVideo, with two spec corrections made in the shared core: a failed authorisation carries warning `101` (TS 24.379 §7.3.3 step 6) and the NOTIFY echoes the handled `p-id` (§9.2.2.2.5) | TS 24.379 §7.3.3, §9.2.2.2.5 |

Configuration: `tools/prepare-prearranged-test.py --mcvideo` gives each client an `mcvideo` section (`user_id`, `service_uri`, `group_id`) and group `operations` the four users as MCVideo members; group `video-closed` has client-a only.

### Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-affiliate [group]'   # the configured group by default
mcx-client --config FILE --command 'mcvideo-deaffiliate'
mcx-client --config FILE --command 'mcvideo-authorize [token]'   # re-authorise; a token argument probes a refusal
```

`status.json` records `mcvideo_authorized`, `mcvideo_affiliated`, `mcvideo_affiliations`, `mcvideo_affiliation_subscribed`, `mcvideo_affiliation_p_id` and `mcvideo_last_result` (action, status, warning).

## Running the tests

```bash
python3 tools/regress.py --image openmcx:v1 --select =mcvideo --output artifacts/regress-v1
```

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| MV-AF-01 | 2026-09-26 | `openmcx:v1` (`ef18357ed001`) | Four clients MCVideo authorised; the MCVideo server holds four users | Passed |
| MV-AF-02 | 2026-09-26 | same | Four clients affiliated to operations after their status subscription; four affiliated users at the server; the NOTIFY echoes the PUBLISH's `p-id` | Passed |
| MV-AF-03 | 2026-09-26 | same | MCPTT authorised and affiliated beside MCVideo; `mcptt-server` keeps its four MCPTT users | Passed |
| MV-AF-04 | 2026-09-26 | same | A PUBLISH with an invalid token gets 403 `399 mcx "101 service authorisation failed"`; the client stays authorised | Passed |
| MV-AF-05 | 2026-09-26 | same | client-b's affiliation to video-closed, where it is not an MCVideo member, gets 403; it stays affiliated to operations only | Passed |
| MV-AF-06 | 2026-09-26 | same | client-a, a member, affiliates to video-closed too; the NOTIFY lists both groups | Passed |
| MV-AF-07 | 2026-09-26 | same | client-d de-affiliates with Expires 0; three affiliated users remain; its MCPTT affiliation is untouched | Passed |

The scenario made 17 checks (`artifacts/regress-v1/mcvideo/`). The smoke labs (`prearranged_scenario`, `mcdata_sds_scenario`, `mcvideo_server_scenario` with 10 checks) passed on the same image. The first runs found two defects, both fixed before this run: the NOTIFY carried a new `p-id` instead of the handled one (a shared-core defect that MCPTT had too), and the client's affiliation to a second group sent that group alone, which the server correctly took as the client's whole set.

## Coverage gaps

| Area | Gap |
|---|---|
| Service authorisation by REGISTER | §7.2.1 and §7.3.2 (third-party registration) are not implemented; the client authorises by PUBLISH |
| Service settings | Subscription to and notification of service settings (§7.2.4, §7.3.6) and PUBLISH for settings only (§7.3.4) are not exercised |
| Affiliation variants | Negotiated mode (§8.2.1.4, §8.2.1.5), group dynamic data (§8.2.1.6), rules-based affiliation (§8.2.1.7), implicit affiliation (§8.2.2.2.15) and affiliation across servers (§8.2.2.2.6) are not exercised |
| Security | The CSK upload and protected signalling of §7.2.2 steps 3-4 and §7.2.5 come with V9 |
| Wire evidence | Checked through client and server state; SIP wire assertions follow with the call increments |
