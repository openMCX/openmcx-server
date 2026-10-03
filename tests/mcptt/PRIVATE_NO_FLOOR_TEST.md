# Private calls without floor control

These tests cover on-network MCPTT private calls without floor control (TS 24.379 V19.7.0 §11.1.2). The caller's offer has no floor control section, both parties speak at once, and only the clients end the call (§11.1.4.1 NOTE). They run on a combined server and on separate participating and controlling servers.

Back to the [MCPTT test index](../MCPTT_TEST.md). Private calls with floor control are in the [private-call tests](PRIVATE_CALL_TEST.md).

## How it works

- **Call setup.** The caller sends the usual private-call INVITE (`session-type` private, called MCPTT ID in `resource-lists`, commencement headers) with an SDP offer that has `m=audio` and no `m=application` (§11.1.2.2 steps 12-13). It announces the SSRC it speaks with in `a=ssrc` (RFC 5576).
- **Participating function.** A participating server passes an offer without floor control on (§11.1.2.3.1); the controlling function decides whether the call allows it.
- **Controlling function.** An offer without a media-floor control section asks for a private call without floor control (§11.1.2.4.2). The server accepts it for private and first-to-answer calls only; group, ad hoc and ambient listening calls still need floor control and get 488. It invites the called user with an offer that has no `m=application` either, and rejects an answer or re-INVITE whose floor control differs from the offer.
- **Media.** Nothing is arbitrated and no floor control message is sent. The media distribution function relays each party's speech to the other unchanged, checked against the SSRC of that party's SDP when it announced one.
- **Ending.** Only the clients end the call: the server runs neither T4 (Inactivity) nor the private call timer (§6.3.8.2 items 1-2) for it. A party's BYE still ends the call for both (item 3).

## Implemented profile

| Step | Behaviour | Reference |
|---|---|---|
| Offer | `m=audio` with `a=ssrc`, no `m=application`, no floor parameters | 24.379 §11.1.2.2; 24.380 §14 |
| Participating function | Passes the offer on, both ways | §11.1.2.3.1, §11.1.2.3.2 |
| Controlling function | Accepts it for a private or first-to-answer call; 488 for any other call type | §11.1.2.4.2 |
| Callee | Answers without `m=application` | §11.1.2.2 last paragraph |
| Speech | Both parties at once; relayed unchanged | §11.1.2 |
| Ending | By a client only; no T4 or private call timer | §11.1.4.1 NOTE; §6.3.8.2 |

Configuration: the lab of `tools/prepare-prearranged-test.py --private-call` (client-a may call client-b in every commencement mode; `mcptt-server` has `mcptt.private_call` with a 5 s setup timer and a 30 s private call timer). The `private-no-floor-split` lab adds `--split`: client-a and client-b are served by two participating servers, `mcptt-part-1` and `mcptt-part-2`, and `mcptt-server` is the controlling function.

### Client commands and status

```bash
mcx-client --config FILE --command 'private <MCPTT ID> [auto|manual|force-auto] [emergency [alert]] no-floor'
mcx-client --config FILE --command 'ptt <wav>'   # speaks at once, without a floor request
```

A client answers an offer without floor control without one. `status.json` adds `floor_control` (false during such a call); `talking`, `sent_packets` and `received_packets` show the speech.

## Running the tests

```bash
python3 tools/regress.py --image openmcx:nofloor --client-image openmcx-client:nofloor \
    --select =private-no-floor,=private-no-floor-split --output artifacts/regress-no-floor
```

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| PNF-01 | 2026-09-28 | server `openmcx:nofloor` (`44702362fc44`), client `openmcx-client:nofloor` (`54fefc8a7520`) | client-a calls client-b without floor control (automatic); both active, `floor_control` false at both; each knows the other; nobody else is in the call | Passed |
| PNF-02 | 2026-09-28 | same | Both speak at once: client-a sends 337 frames and client-b 355; client-b receives 337 and client-a 355, while both talk; no floor denial; the call stays up after the speech | Passed |
| PNF-03 | 2026-09-28 | same | The call is still up 35.1 s after it was set up, past the 30 s private call timer | Passed |
| PNF-04 | 2026-09-28 | same | client-b ends the call; both are idle | Passed |
| PNF-05 | 2026-09-28 | same | Manual commencement without floor control: client-b rings, answers and speaks at once; client-a hears it; client-a ends the call | Passed |
| PNF-06 | 2026-09-28 | same | The next private call has floor control again; client-a is granted the floor | Passed |
| PNF-07 | 2026-09-28 | same | Captured at `mcptt-server`: two client offers to the MCPTT PSI and two server offers to the callee without `m=application`; four 200 answers without it; the client offers carry `a=ssrc`; the following call offers `udp MCPTT` | Passed |

Both labs made 56 checks each: `private-no-floor` on a combined server, and `private-no-floor-split` through the participating servers. As a negative control, the same scenario fails at PNF-01 against the previous server image (`openmcx:v9g`), which answers the offer with 400. On the new server image the smoke, `mcvideo`, `mcvideo-ambient`, `first-to-answer`, `private-services`, `protected-private` and the eight `call-types` scenarios also passed.

## Coverage gaps

| Area | Gap |
|---|---|
| Pre-established sessions | The `mc_no_floor_ctrl` REFER of §11.1.2.3.1 is not implemented; pre-established sessions are refused |
| First-to-answer | Accepted by the server; mcx-client offers no floor-free first-to-answer call, so it is not exercised |
| Protected media | The server relays PCK-protected speech unchanged; not exercised without floor control |
| Refusal of other call types | Group, ad hoc and ambient listening offers without floor control get 488; covered by review, not by a scenario |
| SSRC assignment | The server relays each party's own SSRC and announces none of its own (the Editor's Note of §6.3.3.2.1 leaves this open) |
