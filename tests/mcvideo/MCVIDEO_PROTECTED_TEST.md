# MCVideo protected call tests

The keying of MCVideo identities, the MCVideo crypto sessions, protected MCVideo group calls, and PCK-protected private and ambient viewing calls (TS 24.281 4.7.1; TS 33.180).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SEC-01).

## How it works

- **Crypto sessions.** TS 33.180 Table E.1.3-1 gives MCVideo its own CS-IDs:
  - 5 for a group call (MCPTT 4)
  - 2 and 3 for the initiator's and receiver's streams of a private call (MCPTT 0 and 1)
  - 8 for CSK SRTCP (MCPTT 6).

  The MIKEY key derivation and each MCVideo user's key context use them. The unit tests carry known answers for the MCVideo CS-IDs, calculated independently, beside the MCPTT answers.
- **Key management services.**
  - The KMS provisions the MCVideo server's identity (`mcvideo_service.service_uri` in the site configuration).
  - It provisions a token user's own MCVideo ID only under `3gpp:mc:video_key_management_service`, which the IdMS lists and the client requests.
  - The GMS delivers a group's GMK to an MCVideo ID only if that ID is one of the group's MCVideo members.
- **Client.** The MCVideo client has its own key client, CSK and key contexts, as its MCVideo ID, apart from the MCPTT ones.
  - Its CSK goes to the MCVideo server in `application/mikey` with the MCVideo service authorisation (TS 24.281 7.2.5).
  - It subscribes to the group's GMK at the MCVideo server (GKTP, `xcap-diff`) and refreshes the subscription.
  - A group call is offered as RTP/SAVP.
  - Transmission control is SRTCP under the CSK. Video is SRTP under the GMK, keyed per sender: the receiver takes the sender from the transmission control.
- **Private and ambient viewing calls.** The caller generates a PCK for the called MCVideo ID (TS 33.180 7.4) and offers it in `a=key-mgmt`. This covers a private call with or without transmission control, and a remotely or locally initiated ambient viewing call.
  - The called client authenticates the I_MESSAGE as from the calling MCVideo ID. It refuses the call with 488 and warning 136 if that fails, or if a protected offer has no PCK.
  - Both select the PCK, with the initiator's streams on CS-ID 2 and the receiver's on CS-ID 3. It is ended with the call.
  - A protected call to a functional alias is not offered, because the user called is known only from the 300.
- **Server.**
  - It sends and receives transmission control as SRTCP under each user's CSK. A leg whose key is missing or fails is ended.
  - It relays protected video unchanged: it holds no GMK or PCK, so it neither rewrites nor records it. It refuses a receiver whose protected profile differs.
  - Its size check allows a PCK-protected packet with only a 4-byte MKI.
  - Pull and push to and from the server stay clear.
- **XML protection** of MCVideo signalling is tested separately, in the [XML protection tests](MCVIDEO_XML_PROTECTION_TEST.md); the client protects MCVideo requests under its MCVideo CSK only. In this lab `mcvideo-server` has XML protection off.

## Running the tests

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-protected
```

The lab is `--mcvideo --protected --key-parameters-iei 0x79`. The groups protect media and transmission control, and `mcvideo-server` has the same security section as the MCPTT server. The `mcvideo-protected-split` lab runs the same scenario on separate participating and controlling servers ([split tests](MCVIDEO_SPLIT_TEST.md)).

The scenario makes 34 checks over debug TCP and 32 over TLS, where the SDP checks are skipped. The unit tests cover the MCVideo CS-ID known answers, the KMS's MCVideo server identity and MCVideo ID under its scope only, and the GMK delivery to MCVideo members only, encapsulated for the MCVideo ID.

## Tests

| ID | What is checked |
|---|---|
| MV-SE-01 | The four clients are MCVideo authorised and affiliated. Each has its own MCVideo CSK (purpose tag 2, different from its MCPTT CSK), and all hold the same group GMK (purpose tag 0) |
| MV-SE-02 | client-a's protected group call reaches all four, and client-a is granted over protected transmission control. client-b and client-c learn it transmits and decode its protected video, all pictures equal to client-a's |
| MV-SE-03 | client-b then transmits under the same GMK, keyed by its own identity, and client-c's pictures of it equal client-b's |
| MV-SE-04 | The server ended no leg for a missing or failed key, and it sent transmission control |
| MV-SE-05 | Captured at `mcvideo-server`. Transmission control packets, none with a readable `MCV0`/`MCV1`/`MCV2` name, each long enough for the SRTCP index, the 16-byte tag and the MKI. Over debug TCP, the offers carry video and audio as RTP/SAVP |
| MV-SE-06 | Protected private call with transmission control. client-a's PCK for client-b, purpose tag 1, is held by both; client-a is granted, and client-b's pictures equal client-a's |
| MV-SE-07 | Protected private call without transmission control, under a new PCK. Both send at once, and each decodes the other with every compared picture equal |
| MV-SE-08 | Protected remotely initiated ambient viewing call. client-a's new PCK reaches client-b through the server, and client-a's pictures of client-b are equal |
| MV-SE-09 | Over debug TCP, the private and ambient offers carry the PCK in `a=key-mgmt:mikey` |

## Coverage gaps

| Area | Gap |
|---|---|
| Private calls | A protected call to a functional alias is not offered; a tampered I_MESSAGE (warning 136) is not exercised for MCVideo; first-to-answer does not exist in MCVideo |
| Negative key cases | A replayed or tampered packet and a leg without a CSK are covered by the shared code's MCPTT tests, not by an MCVideo scenario |
| Audio | The MCVideo client sends no audio, so protected audio is offered but not exercised |
| Server calls | Push to and pull from the server stay unprotected; the server holds no GMK or PCK |
| Other groups | The client keys only its selected group; a protected call on another group needs that group's GMK |
