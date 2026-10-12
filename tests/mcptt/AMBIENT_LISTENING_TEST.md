# Ambient listening call tests

These tests cover **ambient listening calls** (TS 24.379 §11.1.6, TS 23.379 §10.14): one user hears the surroundings of another user's device without that device's user being made aware of it. The tests cover the implemented on-demand subset below, not complete conformance. Pre-established sessions are not implemented; private call key (PCK) protection is covered elsewhere, see [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md). Related: [private calls](PRIVATE_CALL_TEST.md), [remotely initiated calls](REMOTE_INITIATED_TEST.md).

## How ambient listening calls work

- **Two types.** In a **remotely initiated** call (`remote-init`), the listening user calls the user to be listened to. In a **locally initiated** call (`local-init`), the listened-to user calls the user who will listen. Either way, the listened-to user's microphone is the only source of speech.
- **Setup.** The originator sends an INVITE with `session-type` `ambient-listening`, an `<ambient-listening-type>`, one listed user in `resource-lists`, `Priv-Answer-Mode: Auto` and `mc_implicit_request`. Speech is offered `recvonly` by a listening originator and `sendonly` by a listened-to originator (§6.2.1 step c). Both invitees answer automatically.
- **Authorization.** The server checks the originator's ruleset: `allow-request-remote-initiated-ambient-listening` or `allow-request-locally-initiated-ambient-listening` (403/154), `allow-private-call` (107) and the `<PrivateCall>` list (144). The callee must be callable in private calls (127).
- **No indication at the listened-to device.** A listened-to invitee gets a null `Alert-Info` (`<file:///dev/null>`) and shows no call at all. A listened-to originator gets no indication that its call was set up or ended (§11.1.6.2.0).
- **Floor.** Once both parties are connected, the server grants the floor to the listened-to user, who keeps it for the whole call. The listening user gets Floor Taken with no permission to request the floor; a request is denied with cause 5 (receive only).
- **Release by a user.** Only a party that received the D.3 `g.3gpp.mcptt.ambient-listening-call-release` feature capability may release: the originator of either type (in the 200 OK), and the listening invitee of a local-init call (in the INVITE). A listened-to invitee cannot release a call it does not know about.
- **Release by the server** (§11.1.6.4.3). The server sends BYE to the listened-to user first, then to the listening user with a `<release-reason>`: `administrator-action`, `private-call-expiry`, `call-request-for-listened-to-client` or `call-request-initiated-by-listened-to-client` (TS 23.379 §10.14.3.3).

## Implemented profile

| Step | Behavior | Reference |
|---|---|---|
| Originating INVITE | `session-type` ambient-listening, `<ambient-listening-type>` remote-init or local-init, one `resource-lists` entry, `Priv-Answer-Mode: Auto`, `mc_implicit_request`, `recvonly` (remote-init) or `sendonly` (local-init) | 24.379 §11.1.6.2.1.1 steps 7–14 |
| Participating checks | Ruleset element for the requested type (403/154), `allow-private-call` (107), `<PrivateCall>` list (144), SDP direction matching the type (488) | §11.1.6.3.1.1 steps 4–9 |
| Terminating checks | Callee unknown or not registered (480), not callable in private calls (403/127) | §11.1.6.3.2.1 steps 4–5 |
| Busy users | An originator already in a call gets 486; a target already in a call, including an ambient call, gets 480 | TS 23.379 §10.14.3.1–2 preconditions; §11.1.6.4.2 |
| Invitation | Listened-to invitee: `Priv-Answer-Mode: Auto`, null `Alert-Info`, `recvonly` offer. Listening invitee: `Priv-Answer-Mode: Auto`, `Feature-Caps` D.3, `sendonly` offer | §11.1.6.4.1 steps 6–7 |
| Answer to the originator | 183 without ringing (null `Alert-Info` for remote-init), then 200 OK with `Feature-Caps` D.3 and the complementary SDP direction | §11.1.6.4.2 |
| Floor | Granted to the listened-to user when both legs are connected; the listening user gets Floor Taken with Permission to Request 0, and Floor Deny cause 5 on request. No T1/T2 revocation during the call | TS 23.379 §10.14.3.1–2 steps 6–7; 24.380 |
| Private call timer | Runs from the invitation (30 s in the test fixture); expiry releases with `private-call-expiry` | §11.1.6.4.1 step 9 |
| Server release | BYE to the listened-to user, then BYE with `<release-reason>` to the listening user | §11.1.6.4.3 |
| BYE from a participant | Releases the other participant | §11.1.6.4.4 |
| Client role cache | Each client caches its role and the ambient listening type and clears them on release | §11.1.6.2.1.1–4 |

The ruleset is served by the CMS as `ambient_remote` / `ambient_local` in the `private_call` policy of the internal user resource, and as the two ruleset actions in the user profile document.

### Listened-to client behaviour

The lab client simulates the device of a listened-to user:

- It shows no call: `call_state` stays `idle`, and `call_type`, `private_peer` and `talking` are empty. The `ambient` status entry is test instrumentation, not a user indication.
- It transmits a looped source instead of a microphone: the WAV set by `ambient-source`, else `mcptt.ambient_source`, else silence.
- `hangup` and `release` do nothing in a remotely initiated call, because the user does not know about it.
- A call request of its own (`call`, `chat`, `private`, `first-to-answer`, `adhoc`, `ambient`, `callback-fulfil`, or a remote/transfer/forward request it has to place) takes over. The client drops the ambient call once the new INVITE is sent, and the server then releases the ambient call. If the command fails before an INVITE is sent, the client stays in the ambient call (AL-09a).

### Client and server commands

```bash
mcx-client --config FILE --command 'ambient remote sip:bob.mcptt@mcx.test'   # listen to bob
mcx-client --config FILE --command 'ambient local sip:alice.mcptt@mcx.test'  # be listened to by alice
mcx-client --config FILE --command 'ambient-source /artifacts/speech/bravo.wav'
openmcx-mcptt-server --config FILE --command 'ambient-release sip:bob.mcptt@mcx.test' # or: ambient-release all
```

A client's status shows `ambient` (type, role, peer, release permission, null alert, attached, transmitting) during the call and `last_ambient` (including `release_reason`) after it. The server status lists the session with `call_type` `ambient`, `ambient_listening_type`, `listening`, `listened_to` and `release_reason`.

## Running the tests

The ambient listening scenario runs in the `call-types` lab (one server) and the `call-types-split` lab (separate
participating and controlling servers) of the regression:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =call-types
```

The lab's `--private-call` option grants client-a both ambient listening types (targets limited to client-b and
client-c by its `<PrivateCall>` list), client-b the locally initiated type only, client-c neither, and makes client-d
uncallable. The private call timer is 30 s. Over debug TCP SIP the run also captures at the MCPTT server and checks the
capture with `tests/integration/verify_ambient_listening.py`.

## Checks

| ID | What is checked |
|---|---|
| AL-01 | Remote-init: client-a listens to client-b. The server session records the type, the listening and listened-to users and the floor owner. Client-a caches its role, may release and saw a null alert in the 183. Client-b shows no call but is transmitting, with no release permission. Client-a gets Floor Taken naming client-b with no permission to request |
| AL-02 | Client-b's speech reaches client-a; no other client receives it |
| AL-03 | Client-a's floor request is denied with cause 5; the floor stays with client-b |
| AL-04 | `hangup` by the listened-to user of a remote-init call changes nothing |
| AL-05 | The listening user's release ends the call for both, with no release reason; both role caches are cleared |
| AL-06 | Local-init: client-b asks client-a to listen. Client-a is told and may release (Feature-Caps in the INVITE); client-b gets no indication but may release (Feature-Caps in the 200 OK); speech reaches client-a |
| AL-07 | The listened-to originator of a local-init call releases it |
| AL-08 | `ambient-release` on the server ends the call; the listening user gets `administrator-action`, the listened-to user's BYE has no reason |
| AL-09a | A call command by the listened-to user that fails before any INVITE (`private` to itself) is no call request: client-b stays attached and keeps transmitting, and the server and client-a keep the call |
| AL-09 | A group call by the listened-to user releases the ambient call with `call-request-initiated-by-listened-to-client`, and the group call proceeds |
| AL-10 | A private call to the listened-to user (from client-c) releases the ambient call with `call-request-for-listened-to-client`, and the private call is established |
| AL-11 | Private call timer expiry releases the call with `private-call-expiry`, not before the timer |
| AL-12 | Rejections with no ambient session created: requester without the remote-init ruleset (154); a local-only user asking for remote-init (154); target outside `<PrivateCall>` (144); uncallable target (127) |
| AL-13 | An ambient request to a user already in a private call gets 480 and does not disturb that call |
| AL-14 | SIP wire checks: originating INVITE content; `recvonly`/`sendonly` by type; listened-to invitee headers and offer; listening invitee Feature-Caps and offer; 200 OK Feature-Caps and direction; 183 with null Alert-Info; 403/154, 403/144 and 403/127; 480 for a busy user; each release reason on the listening user's BYE; release reasons only in ambient dialogs |

## High-level call flow (remote-init, then server release)

Kamailio and floor retransmission detail are omitted. The listening user L and the listened-to user T are both served by the one combined MCPTT server.

```mermaid
sequenceDiagram
    participant L as Listening user L
    participant S as MCPTT server
    participant T as Listened-to user T
    L->>S: INVITE session-type ambient-listening, remote-init, resource-lists T, recvonly, mc_implicit_request, Priv-Answer-Mode Auto
    Note over S: Authorise L (154, 107, 144), check T callable (127) and idle (480)
    S-->>L: 183 Session Progress, Alert-Info null
    S->>T: INVITE ambient-listening remote-init, Priv-Answer-Mode Auto, Alert-Info null, recvonly
    Note over T: Answers silently, shows no call
    T-->>S: 200 OK sendonly
    S-->>L: 200 OK sendonly, Feature-Caps ambient-listening-call-release
    S->>T: Floor Granted
    S->>L: Floor Taken (T), no permission to request
    T->>S: Speech (looped source)
    S->>L: Speech
    Note over S: Release trigger: administrator, timer, or a call by or to T
    S->>T: BYE
    T-->>S: 200 OK
    S->>L: BYE with release-reason
    L-->>S: 200 OK
```

## Coverage gaps

| Area | Gap |
|---|---|
| Pre-established sessions | Ambient listening over a pre-established session (§11.1.6.2.2, §11.1.6.3.1.4), including the SIP INFO release reason: not in present edition. |
| End-to-end protection | PCK protection (§11.1.6.2.1.1 step 10) is covered in the [protected private-call tests](PROTECTED_PRIVATE_CALL_TEST.md) (PP-06, and this scenario run on the protected fixture). |
| Implicit request | The server grants the floor to the listened-to user whether or not the offer carries `mc_implicit_request` (§6.4 makes it the trigger). |
| Location | The location-info bodies of §11.1.6.3.1.1 step 15 are not relayed. |
| Multiple servers | Covered: the ambient listening scenario also runs with separate participating and controlling servers. |
| Microphone | The lab client transmits a looped WAV or silence; a real microphone is not covered by these tests. |
| Wire qualification | In-repository decoders only; no independent-peer run. |
