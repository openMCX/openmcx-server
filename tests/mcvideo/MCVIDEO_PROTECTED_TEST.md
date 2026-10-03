# MCVideo protected call tests

These tests cover **steps V9a to V9f of increment V9 of the MCVideo plan**: the keying of MCVideo identities, the MCVideo crypto sessions, protected MCVideo group calls, and PCK-protected private and ambient viewing calls (TS 24.281 V19.6.0 4.7.1; TS 33.180 V19.4.0).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SEC-01).

## How it works

- **Crypto sessions (V9b).** TS 33.180 Table E.1.3-1 gives MCVideo its own CS-IDs:
  - 5 for a group call (MCPTT 4)
  - 2 and 3 for the initiator's and receiver's streams of a private call (MCPTT 0 and 1)
  - 8 for CSK SRTCP (MCPTT 6).

  The MIKEY key derivation and each MCVideo user's key context use them. The unit tests carry known answers for the MCVideo CS-IDs, calculated independently, and the MCPTT answers are unchanged.
- **Key management services (V9a).**
  - The KMS provisions the MCVideo server's identity (`mcvideo_service.service_uri` in the site configuration).
  - It provisions a token user's own MCVideo ID only under `3gpp:mc:video_key_management_service`, which the IdMS lists and the client requests.
  - The GMS delivers a group's GMK to an MCVideo ID only if that ID is one of the group's MCVideo members.
- **Client (V9d, V9e).** The MCVideo client has its own key client, CSK and key contexts, as its MCVideo ID, apart from the MCPTT ones.
  - Its CSK goes to the MCVideo server in `application/mikey` with the MCVideo service authorisation (TS 24.281 7.2.5).
  - It subscribes to the group's GMK at the MCVideo server (GKTP, `xcap-diff`) and refreshes the subscription.
  - A group call is offered as RTP/SAVP.
  - Transmission control is SRTCP under the CSK. Video is SRTP under the GMK, keyed per sender: the receiver takes the sender from the transmission control.
- **Private and ambient viewing calls (V9f).** The caller generates a PCK for the called MCVideo ID (TS 33.180 7.4) and offers it in `a=key-mgmt`. This covers a private call with or without transmission control, and a remotely or locally initiated ambient viewing call.
  - The called client authenticates the I_MESSAGE as from the calling MCVideo ID. It refuses the call with 488 and warning 136 if that fails, or if a protected offer has no PCK.
  - Both select the PCK, with the initiator's streams on CS-ID 2 and the receiver's on CS-ID 3. It is ended with the call.
  - A protected call to a functional alias is not offered, because the user called is known only from the 300.
- **Server (V9d, V9e).**
  - It sends and receives transmission control as SRTCP under each user's CSK. A leg whose key is missing or fails is ended.
  - It relays protected video unchanged: it holds no GMK or PCK, so it neither rewrites nor records it. It refuses a receiver whose protected profile differs.
  - Its size check allows a PCK-protected packet with only a 4-byte MKI.
  - Pull and push to and from the server stay clear.
- **XML protection** of MCVideo signalling is not part of these steps.
  - The client no longer protects MCVideo requests under its MCPTT CSK when MCPTT XML protection is on: the MCVideo server could not open them. This was a latent defect.
  - The lab's `mcvideo-server` has XML protection off.

## Running the tests

```bash
tools/regress.py --image openmcx:v9 --client-image openmcx-client:v9 --select mcvideo-protected
```

The lab is `--mcvideo --protected --key-parameters-iei 0x79`. The groups protect media and transmission control, and `mcvideo-server` has the same security section as the MCPTT server.

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| MV-SE-01 | 2026-09-27 | `openmcx:v9` (`97dda509740f`), `openmcx-client:v9` (`0d72fa31a61f`) | The four clients are MCVideo authorised and affiliated. Each has its own MCVideo CSK (purpose tag 2, different from its MCPTT CSK), and all hold the same group GMK (purpose tag 0) | Passed |
| MV-SE-02 | 2026-09-27 | same | client-a's protected group call reaches all four, and client-a is granted over protected transmission control. client-b and client-c learn it transmits and decode its protected video: 18 and 17 pictures, all equal to client-a's | Passed |
| MV-SE-03 | 2026-09-27 | same | client-b then transmits under the same GMK, keyed by its own identity, and client-c's pictures of it equal client-b's | Passed |
| MV-SE-04 | 2026-09-27 | same | The server ended no leg for a missing or failed key, and it sent transmission control | Passed |
| MV-SE-06 | 2026-09-27 | `openmcx:v9f` (`195cb41776ad`), `openmcx-client:v9f` (`12e82d6486b6`) | Protected private call with transmission control. client-a's PCK for client-b, purpose tag 1, is held by both; client-a is granted, and client-b's 16 pictures equal client-a's | Passed |
| MV-SE-07 | 2026-09-27 | same | Protected private call without transmission control, under a new PCK. Both send at once, and each decodes the other with every compared picture equal (15 each way) | Passed |
| MV-SE-08 | 2026-09-27 | same | Protected remotely initiated ambient viewing call. client-a's new PCK reaches client-b through the server, and client-a's pictures of client-b are equal (15) | Passed |
| MV-SE-09 | 2026-09-27 | same | Over debug TCP, the private and ambient offers carry the PCK in `a=key-mgmt:mikey` | Passed |
| MV-SE-05 | 2026-09-27 | same | Captured at `mcvideo-server`. 38 transmission control packets, none with a readable `MCV0`/`MCV1`/`MCV2` name, each long enough for the SRTCP index, the 16-byte tag and the MKI. Over debug TCP, the offers carry video and audio as RTP/SAVP | Passed |

Run results:
- **With V9f (`openmcx:v9f`):**
  - debug TCP: 34 checks (`artifacts/regress-v9f-tcp/`)
  - TLS: 32 checks (`artifacts/regress-v9f-tls/`)
  - on the same images, the MCVideo, ambient, pull and push labs and the MCPTT `protected-private` lab passed (`artifacts/regress-v9f-related/`).
- **Debug TCP (V9e):** 19 checks (`artifacts/regress-v9e-tcp/`).
- **TLS:** 18 checks, with the SDP check skipped (`artifacts/regress-v9e-tls/`).
- **Other labs**, on the same images: every MCVideo lab and every protected lab passed (40 scenarios, `artifacts/regress-v9e-mcvideo-protected/`). The protected labs are the MCPTT protected and XML protection labs, the MCData protected and XML labs.
- **Unit tests:**
  - the MCVideo CS-ID known answers
  - the KMS's MCVideo server identity and MCVideo ID under its scope only
  - the GMK delivery to MCVideo members only, encapsulated for the MCVideo ID.

Defects found by the runs and fixed:
- **V9f:** the server dropped PCK-protected video packets under 40 bytes as truncated. The limit fitted the GMK trailer (MKI with ROC and GUK-ID), not the PCK's 4-byte MKI. The H.264 parameter sets never reached the receiver, which could not start decoding.
- The first run's check for the CSK upload looked for the authorisation PUBLISH in a capture started after it. The check was removed; the granted protected transmission control shows the server holds each CSK.

## Coverage gaps

| Area | Gap |
|---|---|
| Private calls | A protected call to a functional alias is not offered; a tampered I_MESSAGE (warning 136) is not exercised for MCVideo; first-to-answer does not exist in MCVideo |
| XML protection | MCVideo signalling protection with the CSK and XML confidentiality and integrity (TS 24.281 4.8, 6.6) are V9g |
| Negative key cases | A replayed or tampered packet and a leg without a CSK are covered by the shared code's MCPTT tests, not by an MCVideo scenario |
| Audio | The MCVideo client sends no audio, so protected audio is offered but not exercised |
| Server calls | Push to and pull from the server stay unprotected; the server holds no GMK or PCK |
| Other groups | The client keys only its selected group; a protected call on another group needs that group's GMK |
