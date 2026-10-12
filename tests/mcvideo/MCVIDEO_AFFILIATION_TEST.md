# MCVideo service authorisation and affiliation tests

MCVideo service authorisation by SIP PUBLISH (TS 24.281 §7.2.2, §7.3.3) and MCVideo affiliation with its status subscription (clause 8), between the MCVideo client module of `mcx-client` and `mcvideo-server`, beside MCPTT on the same SIP registration (§7.1).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (rows MV-AUTH-01, MV-AFF-01, MV-CODEC-01).

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
| Affiliation | Status subscription first; PIDF in the MCVideo namespace with `p-id`; MCVideo membership from the GMS; a group the user is not a member of left out of the NOTIFY (200 to the PUBLISH), 403 for another service's document; Expires 0 de-affiliates | §8.2.1.2, §8.2.1.3, §8.2.2.2.3, §8.3.1 |
| NOTIFY `p-id` | The NOTIFY a PUBLISH triggers carries that PUBLISH's `p-id` | §8.2.2.2.5 step d |
| MCPTT | Unchanged beside MCVideo; the shared core sends warning `101` on a failed authorisation (TS 24.379 §7.3.3 step 6) and echoes the handled `p-id` in the NOTIFY (§9.2.2.2.5) for both services | TS 24.379 §7.3.3, §9.2.2.2.5 |

Configuration: `tools/prepare-prearranged-test.py --mcvideo` gives each client an `mcvideo` section (`user_id`, `service_uri`, `group_id`) and group `operations` the four users as MCVideo members; group `video-closed` has client-a only.

### Client commands and status

```bash
mcx-client --config FILE --command 'mcvideo-affiliate [group]'   # the configured group by default
mcx-client --config FILE --command 'mcvideo-deaffiliate'
mcx-client --config FILE --command 'mcvideo-authorize [token]'   # re-authorise; a token argument probes a refusal
```

`status.json` records `mcvideo_authorized`, `mcvideo_affiliated`, `mcvideo_affiliations`, `mcvideo_affiliation_subscribed`, `mcvideo_affiliation_p_id` and `mcvideo_last_result` (action, status, warning).

## Running the tests

The scenario runs in the `mcvideo` lab, beside the group and private call scenarios:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo
```

The scenario makes 17 checks.

## Tests

| ID | What is checked |
|---|---|
| MV-AF-01 | Four clients MCVideo authorised; the MCVideo server holds four users |
| MV-AF-02 | Four clients affiliated to operations after their status subscription; four affiliated users at the server; the NOTIFY echoes the PUBLISH's `p-id` |
| MV-AF-03 | MCPTT authorised and affiliated beside MCVideo; `mcptt-server` keeps its four MCPTT users |
| MV-AF-04 | A PUBLISH with an invalid token gets 403 `399 mcx "101 service authorisation failed"`; the client stays authorised |
| MV-AF-05 | client-b's affiliation PUBLISH naming video-closed, where it is not an MCVideo member, gets 200 (TS 24.281 clause 8.2.2.2.3 step 8); the NOTIFY leaves video-closed out, so it stays affiliated to operations only |
| MV-AF-06 | client-a, a member, affiliates to video-closed too; the NOTIFY lists both groups |
| MV-AF-07 | client-d de-affiliates with Expires 0; three affiliated users remain; its MCPTT affiliation is untouched |

## Coverage gaps

| Area | Gap |
|---|---|
| Service authorisation by REGISTER | §7.2.1 and §7.3.2 (third-party registration) are not implemented; the client authorises by PUBLISH |
| Service settings | Subscription to and notification of service settings (§7.2.4, §7.3.6) and PUBLISH for settings only (§7.3.4) are not exercised |
| Affiliation variants | Negotiated mode (§8.2.1.4, §8.2.1.5), group dynamic data (§8.2.1.6), rules-based affiliation (§8.2.1.7), implicit affiliation (§8.2.2.2.15) and affiliation across servers (§8.2.2.2.6) are not exercised |
| Security | The CSK upload and protected signalling of §7.2.2 steps 3-4 and §7.2.5 are tested in the [protected call tests](MCVIDEO_PROTECTED_TEST.md) and the [XML protection tests](MCVIDEO_XML_PROTECTION_TEST.md) |
| Wire evidence | These tests check client and server state; the call tests check the SIP on the wire |
