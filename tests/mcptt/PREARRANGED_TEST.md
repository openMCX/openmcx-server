# Prearranged group call tests

These tests exercise **on-network, on-demand prearranged group calls**. A two-member group remains a group call, not a private call. They do not certify complete MCPTT or all prearranged-call variants; remaining scope is explicit.

## Running the tests

The lifecycle scenario runs in the `smoke` lab, the failure and refresh scenario in the `call-types` lab, and the queued
floor scenario in the `floor-queue` lab of the regression:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =smoke
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =call-types
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =floor-queue
```

| Scenario | What is checked |
|---|---|
| Lifecycle | Two-member setup, third-member late entry, participant leave, rejoin using the same session URI, exact conference rosters, initiator-policy teardown |
| Concurrent groups | Separate session identities and member sets, simultaneous floor owners and speech delivery, independent teardown |
| Failure and refresh | Manual rejection, caller CANCEL, unanswered setup timeout, cleanup, a pre-established session setup refused with 403 warning 100 (TS 24.379 §8.2.2 step 5), established call surviving its first 90-second SIP session timer refresh |
| Queued floor | Queue-position query, cancellation before release timeout, requeue, explicit queued-grant confirmation, speech, abandoned grant without transmitted RTP |

Each lab writes its JSON results under its `artifacts/integration/`. Speech packet counts alone do not exclude cross-group mixing; correlate captured RTP streams with source/destination endpoints for that assertion. A live call alone does not prove session refresh: the wire verifier checks the request and accepted response.

## High-level call flow

Registration, service authorization and affiliation precede this diagram. Each SIP arrow passes through Kamailio. Authentication challenges/retries and per-message TCP acknowledgements are omitted; floor ACKs are shown explicitly.

```mermaid
sequenceDiagram
    participant A as Originating client A
    participant S as MCPTT server
    participant B as Group member B
    A->>S: INVITE group and SDP
    S-->>A: 180 Ringing
    S->>B: INVITE target B, calling group, Answer-Mode, focus Contact
    B-->>S: 200 OK and SDP
    S->>B: ACK
    S-->>A: 200 OK, session URI, timer, SDP
    A->>S: ACK
    S->>A: Floor Idle
    A->>S: Floor ACK
    S->>B: Floor Idle
    B->>S: Floor ACK
    A->>S: SUBSCRIBE conference for session
    S-->>A: 200 OK
    S->>A: NOTIFY conference roster and MCPTT info
    A-->>S: 200 OK
    B->>S: SUBSCRIBE conference for session
    S-->>B: 200 OK
    S->>B: NOTIFY conference roster and MCPTT info
    B-->>S: 200 OK
    A->>S: Floor Request
    S->>A: Floor Granted
    A->>S: Floor ACK
    S->>B: Floor Taken
    B->>S: Floor ACK
    A->>S: AMR-WB RTP
    S->>B: AMR-WB RTP
    A->>S: Floor Release
    S->>A: Floor ACK
    S->>A: Floor Idle
    A->>S: Floor ACK
    S->>B: Floor Idle
    B->>S: Floor ACK
    A->>S: BYE
    S-->>A: 200 OK
    S->>B: BYE per configured initiator-leave policy
    B-->>S: 200 OK
    S->>A: NOTIFY conference terminated
    A-->>S: 200 OK
    S->>B: NOTIFY conference terminated
    B-->>S: 200 OK
```

Membership changes produce further conference notifications. The queue scenario adds Floor Queue Position Info, Floor Queue Position Request and queued Floor Granted; a client must confirm a queued grant before sending speech. The refresh scenario includes in-dialog UPDATE/200 transactions. Scheduling can interleave independent notifications and floor packets differently from this diagram.
