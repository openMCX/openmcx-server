# MCVideo XML protection tests

These tests cover **step V9g of increment V9 of the MCVideo plan**: the confidentiality and integrity protection of MCVideo signalling (TS 24.281 V19.6.0 4.8, 6.6; TS 33.180 9.3).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Architecture: MCVideo design, [standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SEC-02).

## How it works

- **Sensitive data (4.8).** The categories are those of MCPTT: MCVideo IDs, group IDs, location, the emergency, alert and imminent peril indicators, the access token, the client ID and functional aliases.
  - The shared library's `signalling_profile` gives the protected elements in each service's names: `<mcvideo-request-uri>`, `<mcvideo-access-token>` and so on, plus the location elements of F.3.
  - It also gives the URI attributes of the resource-lists, affiliation, conference and functional alias bodies.
  - The MCPTT server and the MCVideo server each use their own names.
- **Keys (6.6.2.2).** The XPK between an MCVideo client and the MCVideo server is the MCVideo CSK uploaded at MCVideo service authorisation. That request is the first protected one: its access token is encrypted under the CSK it carries (7.2.5).
- **Integrity (6.6.3).** Each XML body is signed with the XPK's integrity key, in the `application/vnd.3gpp.mcptt-signed+xml` body that TS 24.281 takes from TS 24.379, with the `urn:3gpp:ns:mcpttSignedDoc:1.0` namespace.
- **Client.**
  - An MCVideo request, one asking for the MCVideo ICSI, is protected under the MCVideo CSK and in the MCVideo names.
  - An MCPTT request stays under the MCPTT CSK.
  - Incoming content is opened, and signatures verified, under whichever of the two CSKs its key ID names.
- **Configuration.** Protection follows the same `confidentiality_protection` and `integrity_protection` settings as MCPTT. In the lab, `mcvideo-server` takes them from `--xml-protection` and `--integrity-protection`.

## Running the tests

```bash
tools/regress.py --image openmcx:v9g --client-image openmcx-client:v9g --select mcvideo-xml,mcvideo-integrity
```

The labs are `--mcvideo --protected --key-parameters-iei 0x79 --xml-protection`, the second with `--integrity-protection` as well.

## Performed tests

| ID | Date | Build | Test | Result |
|---|---|---|---|---|
| MV-XP-01 | 2026-09-27 | `openmcx:v9g` (`9008230eb0c8`), `openmcx-client:v9g` (`a65c6c0f424a`) | The four clients are MCVideo authorised and affiliated with XML protection on, and `mcvideo-server` opened the protected authorisations and affiliations | Passed |
| MV-XP-02 | 2026-09-27 | same | A group call is set up and released with protected MCVideo signalling | Passed |
| MV-XP-03 | 2026-09-27 | same | A private call is set up and released with the called MCVideo ID protected | Passed |
| MV-XP-04 | 2026-09-27 | same | `mcvideo-server` encrypted 72 and decrypted 27 items. `mcptt-server` still decrypted the MCPTT signalling of the same clients under their MCPTT CSKs (32) | Passed |
| MV-XP-05 | 2026-09-27 | same | No protected content was refused by any client or server | Passed |
| MV-XP-06 | 2026-09-27 | same | With integrity protection, `mcvideo-server` signed 47 bodies and verified 18, and `mcptt-server` verified the MCPTT ones (20) | Passed |
| MV-XP-07 | 2026-09-27 | same | Captured at `mcvideo-server` over debug TCP. The `<mcvideo-request-uri>` and `<mcvideo-client-id>` elements are `type="Encrypted"`. No MCVideo ID appears in clear in an mcvideo-info or resource-lists body, and no access token in clear. With integrity, the messages carry `application/vnd.3gpp.mcptt-signed+xml` | Passed |

Run results:
- **Debug TCP:** 12 checks without integrity and 14 with it (`artifacts/regress-v9g-tcp/`).
- **TLS:** 9 and 10 checks, with the wire checks skipped (`artifacts/regress-v9g-tls/`).
- **Other labs:** every MCVideo lab and every protected lab passed on the same images: 42 scenarios, the MCPTT and MCData protected and XML labs among them (`artifacts/regress-v9g-mcvideo-protected/`).

Defects found by the runs and fixed:
- The client took any request whose headers mentioned the MCVideo ICSI for an MCVideo one. The Contact of every request lists the MCVideo feature tag, so the MCPTT requests were caught too.
  - With integrity, the MCPTT service authorisation was signed under the MCVideo CSK and left unencrypted, and `mcptt-server` refused it with 403.
  - With confidentiality only, the MCPTT signalling went out in clear, unnoticed, because the server accepts clear content.

  An MCVideo request is now one whose P-Preferred-Service (or P-Asserted-Service) names the MCVideo ICSI. The scenario also checks that `mcptt-server` keeps decrypting the MCPTT signalling.

## Coverage gaps

| Area | Gap |
|---|---|
| Negative cases | A body that cannot be decrypted (403, warning 140) or whose signature fails (403, warning 139) is not exercised for MCVideo; the shared code's refusal is exercised for MCPTT |
| Between servers | Protection with an SPK between MCVideo servers comes with separate servers and systems (V10 to V12) |
| Service configuration | The switch is the lab configuration, not the `<confidentiality-protection>` element of the TS 24.484 service configuration document |
