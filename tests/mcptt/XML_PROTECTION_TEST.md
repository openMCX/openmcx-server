# MCPTT XML protection tests

These tests cover **confidentiality and integrity protection of the XML content of MCPTT signalling** (TS 24.379 V19.7.0 §4.8, §6.6.2 and §6.6.3, with TS 33.180 V19.4.0 §9.3 and §9.3.5). The MCData equivalent is in the [MCData protected tests](../mcdata/MCDATA_PROTECTED_TEST.md). What the tests do not cover is listed under [coverage gaps](#coverage-gaps).

Back to the [test index by call type](../MCPTT_TEST.md).

## Implemented profile

| Step | Behavior | Reference |
|---|---|---|
| Protected data | In the `application/vnd.3gpp.mcptt-info+xml`, resource-lists, PIDF, location and conference-info bodies: the access token, the request, calling, called and group identities, the client ID, originated-by, the associated group, the location functional alias, the emergency, alert and imminent peril indicators, and the reported location. In attributes: resource-list entries, the PIDF entity and affiliated groups, functional alias IDs and conference user entities. | §4.8 |
| Encryption | Each element becomes `<EncryptedData>` (XML Encryption 1.1, AES-128-GCM, KeyName the XPK-ID), and each URI attribute `sip:<ciphertext>;iv=...;key-id=...;alg=128-aes-gcm@mc1-encryption.3gppnetwork.org`. The key derives from the XPK and the client's MCPTT ID, or between servers the sending server's PSI (TS 33.180 Annex F.1.4). | §6.6.2.3.3, §6.6.2.3.4 |
| Keys | Between a client and its server, the XPK is the CSK the client uploads at service authorisation; between two servers, the SPK provisioned for the pair. | §6.6.2.2 |
| Service authorisation | The access token and client ID of the PUBLISH that uploads the CSK are encrypted with that CSK; the server accepts the CSK from the request first and then decrypts them. | §7.3.3 with §6.6.2 |
| Every message | The SIP engine protects the bodies of every request and response, once the destination is known, and opens them on receipt before any procedure runs. A server decrypts content from a peer and re-encrypts it for the next hop, which is the copying of §6.6.2.5. | §6.6.1.2, §6.6.1.4, §6.6.2.5 |
| Refusal | Content that cannot be decrypted is refused with 403 and warning 140. | §6.6.2.4.2 |
| Integrity | Every XML body of a message (mcptt-info, poc-settings, resource-lists, location, affiliation command, conference-info, PIDF, xcap-diff, simple-filter, regroup) gets a Content-ID and an xmldsig `<Signature>` in an `application/vnd.3gpp.mcptt-signed+xml` body (`<signatures>`, namespace `urn:3gpp:ns:mcpttSignedDoc:1.0`): a SHA-256 digest of the body referenced as `cid:`, and HMAC-SHA256 over the exclusive canonical SignedInfo under the integrity key of the hop's XPK (TS 33.180 Annex F.1.4, FC 0x52), KeyName the XPK-ID. Integrity is applied after encryption, and verified before decryption; a failed check is refused with 403 and warning 139. | §6.6.3.1, §6.6.3.3.3, §6.6.3.4, Annex F.6 |

### Local choices

| Choice | Reason |
|---|---|
| Protection is enabled by the service configuration documents' `<confidentiality-protection>` and `<integrity-protection>` (absent: enabled), which the lab generator writes "false" where the lab's flags leave a protection off. | `--protection-documents-only` (lab xml-key-documents) removes the local switches from every configuration to show that nothing else decides. |
| The signed digest covers the octets of each body as sent (no transform), and the signature covers the exclusive canonical form of SignedInfo. | TS 33.180 §9.3.5 leaves the canonicalisation to "an appropriate algorithm". |
| The MCData service protects its own messages under the MCData CSK; the MCPTT filter leaves messages to and from the MCData server alone. | One client process runs both services. |

## Call flow

```mermaid
sequenceDiagram
    participant A as client-a
    participant S as mcptt-server
    participant B as client-b
    A->>S: PUBLISH poc-settings, MIKEY CSK and mcptt-info with the access token encrypted under that CSK
    Note over S: accepts the CSK, decrypts the token, authorises
    S-->>A: 200 OK
    A->>S: INVITE, mcptt-info and resource-lists encrypted under alice's CSK
    Note over S: decrypts by the XPK-ID before handling
    S->>B: INVITE, the same content encrypted under bob's CSK
    B-->>S: 200 OK, SDP only: no MCPTT XML to protect
    S-->>A: 200 OK, encrypted under alice's CSK
    Note over A,B: with integrity on, each message also carries an mcptt-signed+xml body signing its XML bodies under the same XPK
    Note over S: with separate participating and controlling servers, the hop between them uses their SPK
```

## Running the tests

The XML protection scenario runs in the `xml-protection` (confidentiality), `xml-integrity` (confidentiality and
integrity) and `xml-protection-split` / `xml-integrity-split` (separate participating and controlling servers) labs of
the regression:

```bash
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =xml-protection,=xml-integrity,=xml-integrity-split
```

The clients and servers report `xml_protection` in their status: whether each protection is enabled, and how many bodies they encrypted, decrypted, signed, verified and refused.

## Checks

| ID | What is checked |
|---|---|
| XP-00 | The clients are authorised with protection enabled |
| XP-01 | The service authorisation is protected: the servers decrypt every client's access token |
| XP-02 | A group call with protected mcptt-info |
| XP-03 | A private call with the called party protected (one server) |
| XP-04 | Every client and server encrypts and decrypts MCPTT XML |
| XP-05 | Nothing is refused |
| XP-06 | With integrity protection, every client and server signs its XML bodies and verifies those it receives |

### Required protection without keys (`xml_key_scenario`)

The `xml-key-confidentiality`, `xml-key-integrity` and `xml-key-mixed` labs run XML protection without media and
floor protection (`--xml-only`), confidentiality and integrity apart, with one client whose KMS cannot be reached
(`--kms-unreachable client-c`), and MCPTT XML protection with MCData signalling protection off
(`--mcdata-clear-signalling`). The requirement is the configuration alone; without the service's CSK, or past its
Expiry time, a message it applies to is not sent (TS 24.379 clauses 6.6.2.3.1 and 6.6.3.3.1, TS 24.282 clauses
6.5.2.3.1 and 6.5.3.3.1, TS 33.180 annex E.6.10).

| ID | What is checked |
|---|---|
| XK-01 | Every client with a reachable KMS is authorised and holds its MCPTT CSK without media or floor protection |
| XK-02 | The client without keys is not authorised; nothing of it goes out in the clear |
| XK-03 | A group call with its signalling protected as required |
| XK-04 | With MCData (mixed configuration), a one-to-one SDS is delivered |
| wire | `verify_xml_keys.py`: every service authorisation carries the CSK; no clear sensitive mcptt-info element with confidentiality protection; every authorisation signed with integrity protection; integrity alone encrypts nothing, confidentiality alone signs nothing (`verify_xml_signatures.py` checks every later XML body in the integrity labs) |

The missing, expired and revoked key cases of the gate itself are unit tests (openmcx-client `linux/tests/test_xml_gate.cpp`).

In the same labs the protected private call scenario (automatic, manual, tampered key, first-to-answer, ambient
listening, emergency) and the prearranged scenario run with the protection on.

## Coverage gaps

| Area | Gap |
|---|---|
| MCData integrity | The MCData XML signatures of TS 24.282 §6.5.3 are not implemented. |
| Service configuration | The servers read the document from the CMS's internal view, not by a subscription (LIMITATIONS). |
| Pre-established sessions | The REFER case of §6.6.2.1 does not arise (pre-established sessions are not in present edition). |
| Negative lab test | No scenario sends a tampered or undecryptable body; the xmlsec unit tests cover tampered bodies and signatures, keys of another XPK and decryption failures. |
