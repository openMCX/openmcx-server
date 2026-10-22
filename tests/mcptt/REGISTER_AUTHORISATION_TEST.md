# Service authorisation by REGISTER tests

These tests cover the **service authorisation by third-party REGISTER** (TS 24.379 V19.7.0, TS 24.282 V19.7.0 and TS 24.281 V19.6.0 §7.2.1 and §7.3.2, with TS 24.229 §5.4.1.7): the client sends its access token and client ID for each MC service in a REGISTER instead of the poc-settings PUBLISH of §7.2.2, and the SIP core passes that REGISTER to the service's server in a third-party REGISTER. What the tests do not cover is listed under [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented profile

| Procedure | Behavior | Reference |
|---|---|---|
| Client | With `mcptt.authorise_by_register`, the Linux client authorises each MC service in a REGISTER of its own on its registration, instead of the poc-settings PUBLISH: the mcptt-info, mcdata-info or mcvideo-info (access token, client ID; encrypted with the service's CSK when XML protection is on) and that service's CSK upload when there is one. One REGISTER per service keeps each server's CSK in the REGISTER the SIP core passes to it. The REGISTERs go one at a time (a registration has one transaction). A token renewal sends them again. The steps after a successful authorisation (the configuration, affiliation status and key subscriptions) are those of a PUBLISH. | §7.2.1, TS 24.282 and TS 24.281 §7.2.1, TS 33.180 §9.2.1.3 |
| SIP core | After the registration is saved, Kamailio sends a third-party REGISTER to the server of each MC service whose information the client's REGISTER carries: From and Contact the SIP core, To the user's public user identity, the client's REGISTER (request line, From, To, Call-ID, Contact, Expires and body, not its Authorization) as a `message/sip` body. A de-registration (expiry 0) goes to every MC service server. | TS 24.229 §5.4.1.7 |
| MCPTT and MCVideo servers | The user is the To of the third-party REGISTER (step 1). The mcptt-info (or mcvideo-info) of the client's REGISTER is authorised as a service authorisation PUBLISH is (steps 3, 4 and 4a; §7.3.3), and a re-registration of the same client refreshes the binding without ending its calls. A REGISTER whose body carries no such information is answered 200 without a change. Expiry 0 removes the binding, as a log-off does. | §7.3.2, §7.3.5; TS 24.281 §7.3.2 |
| MCData server | The same, with the mcdata-info; the poc-settings that a PUBLISH carries is not required. The third-party REGISTER asserts no identity: the client's REGISTER it carries is opened with the user's keys (a renewal is signed and its XML encrypted). | TS 24.282 §7.3.2, §6.5.2, §6.6.3 |

## Running the tests

```bash
python3 tools/regress.py --select =register-auth,register-auth-protected --transport both
```

The labs are generated with `--register-auth --mcvideo`, which sets `mcptt.authorise_by_register` for the four clients with MCPTT, MCData and MCVideo. `register-auth-protected` adds protected signalling, media and XML and a token lifetime of 120 s.

## Checks

| ID | Check |
|---|---|
| RA-01 | The four clients are authorised for MCPTT, MCData and MCVideo, and affiliated. |
| RA-02 | The MCPTT, MCData and MCVideo servers each authorised the four users from third-party REGISTERs (`service_authorized_by_register`, `mcdata_authorised_by_register`). |
| RA-03 | A group call with the four clients is set up and released. |
| RA-05 | (`register-auth-protected`) Each client renews its token and authorises again by REGISTER at the three servers, and stays authorised. |
| RA-04 | The log-off of client-d de-registers it; the SIP core's third-party REGISTER with Expires 0 removes its binding at the three servers. |
| Wire | `verify_third_party_register.py` on the capture at the MCPTT server: every REGISTER comes from the SIP core with a `message/sip` body holding the client's REGISTER with its mcptt-info and without its Authorization; each is answered 200; a de-registration carries the client's REGISTER with Expires 0; no client authorised by a poc-settings PUBLISH. In the protected lab, encrypted XML stands in for the access token and client ID. The capture is at the MCPTT server only. |

## Coverage gaps

| Gap | Reason |
|---|---|
| Outcome at the client | The 200 (OK) to a REGISTER comes from the SIP core's registrar, before the server has authorised the user (TS 24.229 §5.4.1.7); a refusal by the server does not reach the client, which counts itself authorised. The scenario therefore checks the servers. |
| MCData and MCVideo on the wire | The capture is at the MCPTT server; the MCData and MCVideo third-party REGISTERs are checked by the servers' events. |
| Android client | It authorises by PUBLISH only. |
| Split servers | The lab runs one MCPTT server. |
