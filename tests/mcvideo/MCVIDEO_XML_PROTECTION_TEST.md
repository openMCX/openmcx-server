# MCVideo XML protection tests

The confidentiality and integrity protection of MCVideo signalling (TS 24.281 4.8, 6.6; TS 33.180 9.3).

Back to the [MCVideo test index](../MCVIDEO_TEST.md). Acceptance: [MCVideo standards and acceptance](../../docs/architecture/mcvideo-standards-and-acceptance.md) (row MV-SEC-02).

## How it works

- **Sensitive data (4.8).** The categories are those of MCPTT: MCVideo IDs, group IDs, location, the emergency, alert and imminent peril indicators, the access token, the client ID and functional aliases.
  - The shared library's `signalling_profile` gives the protected elements in each service's names: `<mcvideo-request-uri>`, `<mcvideo-access-token>` and so on, plus the location elements of F.3.
  - It also gives the URI attributes of the resource-lists, affiliation, conference and functional alias bodies.
  - The MCPTT server and the MCVideo server each use their own names.
- **Keys (6.6.2.2).** The XPK between an MCVideo client and the MCVideo server is the MCVideo CSK uploaded at MCVideo service authorisation. That request is the first protected one: its access token is encrypted under the CSK it carries (7.2.5).
- **Integrity (6.6.3).** Each XML body is signed with the XPK's integrity key, in the `application/vnd.3gpp.mcptt-signed+xml` body that TS 24.281 takes from TS 24.379, with the `urn:3gpp:ns:mcpttSignedDoc:1.0` namespace.
- **Client.**
  - An MCVideo request is one whose P-Preferred-Service (or P-Asserted-Service) names the MCVideo ICSI. It is protected under the MCVideo CSK and in the MCVideo names.
  - An MCPTT request stays under the MCPTT CSK, even though the Contact of every request lists the MCVideo feature tag.
  - Incoming content is opened, and signatures verified, under whichever of the two CSKs its key ID names.
- **Configuration.** Protection follows the same `confidentiality_protection` and `integrity_protection` settings as MCPTT. In the lab, `mcvideo-server` takes them from `--xml-protection` and `--integrity-protection`.

## Running the tests

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-xml
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =mcvideo-integrity
```

The labs are `--mcvideo --protected --key-parameters-iei 0x79 --xml-protection`, the second with `--integrity-protection` as well. The scenario makes 12 checks without integrity and 14 with it over debug TCP; over TLS the wire checks (MV-XP-07) are skipped.

## Tests

| ID | What is checked |
|---|---|
| MV-XP-01 | The four clients are MCVideo authorised and affiliated with XML protection on, and `mcvideo-server` opened the protected authorisations and affiliations |
| MV-XP-02 | A group call is set up and released with protected MCVideo signalling |
| MV-XP-03 | A private call is set up and released with the called MCVideo ID protected |
| MV-XP-04 | `mcvideo-server` encrypted and decrypted items, and `mcptt-server` still decrypted the MCPTT signalling of the same clients under their MCPTT CSKs |
| MV-XP-05 | No protected content was refused by any client or server |
| MV-XP-06 | With integrity protection, `mcvideo-server` signed and verified bodies, and `mcptt-server` verified the MCPTT ones |
| MV-XP-07 | Captured at `mcvideo-server` over debug TCP. The `<mcvideo-request-uri>` and `<mcvideo-client-id>` elements are `type="Encrypted"`. No MCVideo ID appears in clear in an mcvideo-info or resource-lists body, and no access token in clear. With integrity, the messages carry `application/vnd.3gpp.mcptt-signed+xml` |

## Coverage gaps

| Area | Gap |
|---|---|
| Negative cases | A body that cannot be decrypted (403, warning 140) or whose signature fails (403, warning 139) is not exercised for MCVideo; the shared code's refusal is exercised for MCPTT |
| Between servers | XML protection with an SPK between separate MCVideo servers is not exercised for MCVideo; between MC systems it is not in present edition |
| Service configuration | The switch is the lab configuration, not the `<confidentiality-protection>` element of the TS 24.484 service configuration document |
