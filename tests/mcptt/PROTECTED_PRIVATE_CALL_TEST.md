# Protected private call tests

These tests cover **end-to-end protection of on-network private calls with a private call key (PCK)** (TS 33.180 V19.4.0 §5.6, §7.2, §7.4.1, Annex E.3; TS 24.379 V19.7.0 §11.1.1.2.1.1 step 11, §11.1.1.2.1.2 steps 4–5). They include private calls, first-to-answer calls, ambient listening calls and emergency private calls. The results cover one MCPTT server; the same calls across separate servers are in the [split protected tests](PROTECTED_SPLIT_TEST.md). They do not certify interoperability with an independent MIKEY-SAKKE implementation. See [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented profile

The PCK is end to end. The caller generates it, the callee's KMS-provisioned SAKKE key decrypts it, and the server never holds it. The server passes the I_MESSAGE and the SRTP through unchanged. Floor control is protected hop by hop, as in group calls, with each user's client-server key (CSK).

| Step | Behavior | Reference |
|---|---|---|
| PCK and PCK-ID | 16 random octets; a PCK-ID whose four most significant bits are `0001` and whose other 28 bits are random | 24.379 §11.1.1.2.1.1 step 11b–c; 33.180 §5.6 |
| I_MESSAGE | MIKEY-SAKKE (HDR data type 26, CSB-ID = PCK-ID, CS# 0 with an empty map, so the default profile of E.3.2 applies), TS, RAND, IDRi = caller, IDRr = callee, IDRkmsi, IDRkmsr, SAKKE to the callee's UID (ID scheme 2) and an ECCSI signature by the caller. It has **no key parameters payload**: E.3 does not use E.6, so the unassigned Key Parameters IEI does not affect a PCK. | 33.180 E.1.2, E.3.1 |
| Offer | `a=key-mgmt:mikey <base64>` (IETF RFC 4567) in the SDP offer with `RTP/SAVP`; a re-INVITE or session refresh does not repeat it | 24.379 §11.1.1.2.1.1 step 11 |
| Server | Refuses a protected offer without an I_MESSAGE, and a first-to-answer request carrying one. Requires the caller and every callee to hold a CSK. Passes the I_MESSAGE unchanged in its own offer to the callee. | 24.379 §6.3.2.2.3 |
| Callee | Takes the initiator from IDRi, checks it is the calling user, verifies the signature and decrypts the PCK. On failure it answers 488 with warning `136 authentication of the MIKEY-SAKKE I_MESSAGE failed` (the text of table 4.4.2-2). A replayed I_MESSAGE is refused within the 300 s freshness window. | 24.379 §11.1.1.2.1.2 step 4 |
| First-to-answer | The request carries no key. The invitee that answers generates the PCK, encapsulates it to the caller and puts it in its SDP answer. The server sends the caller no SDP before the 200, then includes that answer unchanged. The caller verifies it, requiring the sender to be one of the invitees. On failure it releases with `<release-reason>` "authentication of the MIKEY-SAKE I_MESSAGE failed" (the schema value of annex F.1, spelled SAKE) and resets MEPC/MEPP/MPEA. Keys from invitees that are not selected are discarded. | 33.180 §7.2.4; 24.379 §11.1.1.2.1.1 SIP 200 step 2 |
| Ambient listening | Protected as a private call; the authorised (calling) user generates the PCK | 33.180 §7.2.5 |
| SRTP | PRF-HMAC-SHA-256 with TGK = PCK, CSB-ID = PCK-ID and the RAND of the I_MESSAGE. CS-ID 0 applies to the streams of the user who initiated the call and CS-ID 1 to the other party's streams. AES-128-GCM with a 16-octet tag, a KDR of 0 and a 4-octet MKI = PCK-ID. There is no ROC field: E.3.2 has no RCCm3. | 33.180 §7.4.1, §7.5, E.1.3, E.3.2 |
| Key lifetime | One PCK per call. It is removed when that call's dialog ends. It is suspended while a listened-to client's ambient listening call is set aside, and resumed if that call returns. | 33.180 §5.6 |

In a first-to-answer call, TS 33.180 E.1.3 assigns CS-ID 0 to "the initiator of the private call", while the answering invitee is the MIKEY initiator (§7.2.4.2). This implementation reads E.1.3 literally: the caller's streams use CS-ID 0. Interoperability with a peer that reads it the other way would fail at SRTP authentication, not silently.

## Running the tests

The protected private-call scenario runs in the `protected-private` lab of the regression, and again with XML
protection in the `xml-protection` and `xml-integrity` labs:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =protected-private
```

The lab uses `--private-call --protected --key-parameters-iei 0x79`. `--key-parameters-iei` only affects the group keys (GMK/CSK). The PCK does not use it. Over debug TCP SIP the run
also captures at the MCPTT server and checks the capture with `tests/integration/verify_protected_private.py`.

A protected client provisions from the KMS when it starts. After a client restart, wait for the lab to be healthy before running the next scenario. Otherwise a scenario can read the previous process's status file and send its first command too early.

## Checks

| ID | What is checked |
|---|---|
| PP-01 | Automatic commencement: the server reports a protected session, and both parties select the same PCK-ID with purpose tag 1 |
| PP-02 | Speech both ways, each decrypted and decoded by the other party (CS-ID 0 and 1); floor control over SRTCP under each CSK; no speech at non-participants; release removes the PCK |
| PP-03 | Manual commencement answered later shares the PCK; each call has its own PCK |
| PP-04 | An altered I_MESSAGE (`tamper-key` test aid) → 488 with warning 136; the callee never joins |
| PP-05 | First-to-answer: both invitees ring without key material; the answering invitee's PCK reaches the caller; the other invitee is cancelled without a key; speech is decrypted |
| PP-06 | Ambient listening (remote-init): protected session, shared PCK, the listening user decrypts the listened-to user's speech |
| PP-07 | Emergency private call: protected and keyed; speech decrypted |

The [wire verifier](../integration/verify_protected_private.py) decodes the capture independently:

| ID | Wire check |
|---|---|
| W-01 | Every protected private offer carries `a=key-mgmt:mikey`. The I_MESSAGE decodes as MIKEY-SAKKE with the default map, CSB-ID purpose tag `0001`, the four IDR roles, IDRi = the calling user, a 16-octet RAND, SAKKE ID scheme 2, an ECCSI SIGN and no general-extension payload |
| W-02 | The server's INVITE to the callee carries the caller's I_MESSAGE byte for byte |
| W-03 | A first-to-answer request carries no key. The invitee's 200 and the server's 200 to the caller carry the same I_MESSAGE, whose IDRi is the answering invitee |
| W-04 | The altered I_MESSAGE is answered 488 with warning 136 |
| W-05 | SRTP ends in the call's PCK-ID as the MKI, with no ROC. Every packet is relayed byte-identically, on the private calls with speech and on the ambient listening call |
| W-06 | Floor control is SRTCP whose MKI carries the CSK purpose tag 2 |

The other private-call scenarios also run on a protected lab: every private, first-to-answer and ambient listening
call in them is then protected by a PCK ([private calls](PRIVATE_CALL_TEST.md), [ambient listening](AMBIENT_LISTENING_TEST.md),
[emergency first-to-answer](FIRST_TO_ANSWER_TEST.md)).

Unit tests: PCK SRTP key and salt known answers for CS-ID 0 and 1, calculated independently from RFC 3830 §4.1.3 and RFC 6043 §6.1. They also cover the MKI position and the absence of a ROC; rejection of the wrong direction, replay and the wrong purpose tag; the PCK I_MESSAGE round trip and initiator extraction; and the SDP `key-mgmt` round trip with its malformed forms. The private context tests cover direction separation, suspension and resumption without restarting the packet index, and removal.

## Coverage gaps

| Area | Gap |
|---|---|
| Interoperability | Lab to lab only. The ECCSI SIGN length field is 129 (the full RFC 6507 signature), where E.1.2 says 32. No independent MIKEY-SAKKE peer has been tested. |
| Multiple servers | Within one system, protected private calls across participating and controlling servers work, with the floor control between servers under an SPK; see the [split protected tests](PROTECTED_SPLIT_TEST.md). |
| Optional MIKEY features | SAKKE-to-self (E.5), identity hiding (E.7), a security profile supplied in a GENERIC-ID map (E.3.3) and the MC Security Gateway warning are not implemented. The parser rejects them. |
| Ad hoc group calls | End-to-end security for ad hoc group calls uses a GMK, not a PCK, and is refused |
| Pre-established and off-network | Not in present edition |
| TLS captures | Wire checks use the debug-SIP fixture; with TLS the same flows run but the SDP cannot be inspected from the capture |
