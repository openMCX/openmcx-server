# Service authorisation by REGISTER tests

These tests cover the **service authorisation by third-party REGISTER** (TS 24.379 V19.7.0 §7.2.1 and §7.3.2, with TS 24.229 §5.4.1.7): the client sends its access token and client ID in its REGISTER instead of the poc-settings PUBLISH of §7.2.2, and the SIP core passes that REGISTER to the MCPTT server in a third-party REGISTER. What the tests do not cover is listed under [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented profile

| Procedure | Behavior | Reference |
|---|---|---|
| Client | With `mcptt.authorise_by_register`, the Linux client sends, after its initial registration, a REGISTER on the same registration carrying the mcptt-info (access token, client ID) and the CSK upload when there is one. A token renewal sends such a REGISTER again. The steps after a successful authorisation (MCData and MCVideo authorisation, the configuration and affiliation status subscriptions) are those of a PUBLISH. | §7.2.1, TS 33.180 §9.2.1.3 |
| SIP core | After the registration is saved, Kamailio sends a third-party REGISTER to the server of each MC service whose information the client's REGISTER carries: From and Contact the SIP core, To the user's public user identity, the client's REGISTER (request line, From, To, Call-ID, Contact, Expires and body, not its Authorization) as a `message/sip` body. A de-registration (expiry 0) goes to every MC service server. | TS 24.229 §5.4.1.7 |
| MCPTT and MCVideo servers | The user is the To of the third-party REGISTER (step 1). The mcptt-info (or mcvideo-info) of the client's REGISTER is authorised as a service authorisation PUBLISH is (steps 3, 4 and 4a; §7.3.3), and a re-registration of the same client refreshes the binding without ending its calls. A REGISTER whose body carries no such information is answered 200 without a change. Expiry 0 removes the binding, as a log-off does. | §7.3.2, §7.3.5; TS 24.281 §7.3.2 |
| MCData server | The same, with the mcdata-info; the poc-settings that a PUBLISH carries is not required. | TS 24.282 §7.3.2 |

## Running the tests

```bash
python3 tools/regress.py --select =register-auth --transport both
```

The lab is generated with `--register-auth`, which sets `mcptt.authorise_by_register` for the four clients.

## Checks

| ID | Check |
|---|---|
| RA-01 | The four clients are authorised and affiliated. |
| RA-02 | The MCPTT server authorised the four users from third-party REGISTERs (`service_authorized_by_register`). |
| RA-03 | A group call with the four clients is set up and released. |
| RA-04 | The log-off of client-d de-registers it; the SIP core's third-party REGISTER with Expires 0 removes its binding at the MCPTT server. |
| Wire | `verify_third_party_register.py` on the capture at the MCPTT server: every REGISTER comes from the SIP core with a `message/sip` body holding the client's REGISTER with its mcptt-info and without its Authorization; each is answered 200; a de-registration carries the client's REGISTER with Expires 0; no client authorised by a poc-settings PUBLISH. |

## Coverage gaps

| Gap | Reason |
|---|---|
| MCData and MCVideo authorisation by REGISTER | The Linux client puts only the mcptt-info in its REGISTER and authorises MCData and MCVideo by PUBLISH, so the servers' MCData and MCVideo paths are not exercised. |
| Android client | It authorises by PUBLISH only. |
| Split servers | The lab runs one MCPTT server. |
