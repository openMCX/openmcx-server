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

The scenario runs in the `private-no-floor` lab (one server) and the `private-no-floor-split` lab (through the
participating servers) of the regression:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =private-no-floor,=private-no-floor-split
```

## Checks

| ID | What is checked |
|---|---|
| PNF-01 | client-a calls client-b without floor control (automatic); both active, `floor_control` false at both; each knows the other; nobody else is in the call |
| PNF-02 | Both speak at once: each receives every frame the other sends, while both talk; no floor denial; the call stays up after the speech |
| PNF-03 | The call is still up after the private call timer would have ended a call with floor control |
| PNF-04 | client-b ends the call; both are idle |
| PNF-05 | Manual commencement without floor control: client-b rings, answers and speaks at once; client-a hears it; client-a ends the call |
| PNF-06 | The next private call has floor control again; client-a is granted the floor |
| PNF-07 | Captured at `mcptt-server`: the client offers to the MCPTT PSI and the server offers to the callee have no `m=application`; the 200 answers have none either; the client offers carry `a=ssrc`; the following call offers `udp MCPTT` |

## Coverage gaps

| Area | Gap |
|---|---|
| Pre-established sessions | The `mc_no_floor_ctrl` REFER of §11.1.2.3.1: not in present edition; pre-established sessions are refused |
| First-to-answer | Accepted by the server; mcx-client offers no floor-free first-to-answer call, so it is not exercised |
| Protected media | The server relays PCK-protected speech unchanged; not exercised without floor control |
| Refusal of other call types | Group, ad hoc and ambient listening offers without floor control get 488; covered by review, not by a scenario |
| SSRC assignment | The server relays each party's own SSRC and announces none of its own (the Editor's Note of §6.3.3.2.1 leaves this open) |
