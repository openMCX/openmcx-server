# Protected MCData payload tests

These tests cover **end-to-end protection of MCData payloads** (TS 33.180 V19.4.0 clause 8; TS 24.282 V19.7.0 §6.6):

- standalone SDS over the signalling control plane (§9.2.2)
- standalone SDS and SDS sessions over the media plane (§9.2.3, §9.2.4)
- files over the media plane (§10.2.5)
- one-to-one files over HTTP (§10.2.2.1 steps 7 and 8)

One-to-one payloads use a private call key (PCK) and group payloads use the group's GMK. They also cover two kinds of protection between each client and the MCData server under the client's CSK:

- **signalling protection** (TS 33.180 §9.5; TS 24.282 §6.6.3, §7.2.1A), on SIP and inside MSRP
- **confidentiality of the sensitive XML content** (TS 33.180 §9.3; TS 24.282 §4.6, §6.5.2)

They also cover **signed payloads**, where each DATA PAYLOAD carries its sender's ECCSI signature (TS 33.180 §8.5.5; TS 24.282 §6.6.3.2). The results cover one MCData server. They do not certify interoperability with an independent implementation. See [coverage gaps](#coverage-gaps).

Back to the [MCData test index](../MCDATA_TEST.md).

## Implemented profile

| Step | Behavior | Reference |
|---|---|---|
| Key material | The MCData client provisions KMS keys for its **MCData ID**, which signs and receives PCKs. The KMS provisions an MCData ID only for the token's own user, and only under the scope `3gpp:mc:data_key_management_service`. The `init` response stays bound to the token's user. Group payloads use the GMK the UE already holds for the group: E.6.3 lets one GMK serve MCPTT, MCData and MCVideo group IDs. | 33.180 §5.3, §8.2, §8.4; 24.282 §6.6.1 |
| One-to-one security context | The first message to a peer carries a new PCK in an `application/mikey` body. The PCK-ID's purpose tag is `0001`. IDRi and IDRr are the two MCData IDs. There is no key parameters payload (E.3). Later messages in either direction reuse the PCK and carry only its PCK-ID. The context lasts `mcdata.pck_lifetime_s`, 3600 s by default. | 24.282 §9.2.2.2.1 step 2c; 33.180 §8.3 |
| Recipient | Authenticates the I_MESSAGE from IDRi, checks that it is the calling MCData user, and keeps the PCK. An authentication failure is answered 606 with warning `136 authentication of the MIKEY-SAKKE I_MESSAGE failed`. A redelivered or retransmitted I_MESSAGE that is already accepted is not treated as a replay. | 24.282 §9.2.2.2.2 step 3 |
| Payload protection | The whole DATA PAYLOAD message is protected. The MCData Protected Payload message inherits its type with bit 7 set (0x43). It carries the date and time, Payload ID 0, sequence 0, the algorithm, a random 16-octet IV and the DPPK-ID, then the AES-128-GCM ciphertext and 16-octet tag. The associated data is every field before the ciphertext. The DPCK is derived from the DPPK with FC 0x53 and the DPPK-ID. | 24.282 §6.6.3.1; 33.180 §8.5.1, §8.5.3, §8.5.4, F.1.5 |
| Key selection | The recipient reads the DPPK-ID. A PCK-ID selects the context shared with the sender, and is refused on a group message. A GMK-ID selects the GMK, which must be active and list the group the message was sent to. A payload that cannot be decrypted is answered 606 and never rendered. | 24.282 §6.6.3.2 |
| MCData server | Cannot read a protected payload. It applies the size limits to the Protected Payload message and passes it and the `application/mikey` body to the recipient unchanged, including in a redelivery. | 24.282 §9.2.2.3, §9.2.2.4 |
| Media plane | A one-to-one offer with no security context carries the new PCK in `a=key-mgmt:mikey` (RFC 4567). The MCData server puts the same value in its own offer to the recipient and refuses one in a group offer. The recipient answers 488 with warning 136 when it fails authentication. DATA PAYLOADs in MSRP SEND requests are protected as on the signalling plane, by the sender and, in a session, by every participant. Ad hoc groups stay clear. | 24.282 §9.2.3.2.1 step 2, §9.2.3.2.4, §9.2.4.2.1 step 2, §10.2.5.2.1 step 2 |
| Files | A protected file is a series of Protected Payload messages: one random Payload ID, sequence numbers from 0, at most 60000 octets each (Table 8.5.4.1-1 NOTE 2). The first message's plaintext starts with the 8-octet length of the file, so a series missing its last messages is refused. Over the media plane, the one-to-one and group file is protected. Over HTTP, a one-to-one file is protected before upload and the FD request carries the I_MESSAGE when there is no context; a group file is uploaded in clear. The RFC 5547 size and hash describe the transferred object, which the recipient checks before decrypting. | 24.282 §10.2.2.1 steps 7-8, §10.2.3.1; 33.180 §8.1, §8.3 |

### Signalling protection

| Step | Behavior | Reference |
|---|---|---|
| CSK | With `mcdata.protect_signalling`, the client creates a CSK (purpose tag `0010`) under its MCData ID, encapsulated to the MCData server's identity. It uploads the CSK in an `application/mikey` body of its first service authorisation PUBLISH. The MCData server provisions its own KMS identity, its public service identity, which the KMS issues when the site configuration names it. It authenticates the upload, or answers 488 with warning 136. | 24.282 §7.2.1A step 3; 33.180 §9.2.1.3 |
| Protected signalling | Every `application/vnd.3gpp.mcdata-signalling` body between that client and the server, in SIP and in MSRP SEND requests, is an MCData Protected Payload message under the CSK. The message type is inherited with bit 7 set. The server opens what arrives before any procedure reads it, and seals what it sends separately for each client. This covers SDS and FD signalling payloads, notifications, FD HTTP TERMINATION, COMMUNICATION RELEASE and the FD signalling of a media plane offer. A clear body, a body under another key, or one that fails authentication is answered 403, and counted. | 33.180 §8.5, §9.5.3; 24.282 §6.6.3.1-6.6.3.2 |

### XML confidentiality protection

| Step | Behavior | Reference |
|---|---|---|
| Keys | The XPK is the client's CSK and the XPK-ID its CSK-ID. The confidentiality key is derived from them with FC 0x51, P0 = the client's MCData ID and P1 = the CSK-ID, taking the 128 least significant bits of HMAC-SHA-256. | 33.180 §9.3.3, F.1.4 |
| Elements | In mcdata-info, the access token, request URI, calling user, called party, calling group, alert indicator, originated-by, client ID, functional alias and called functional alias. Each becomes `type="Encrypted"` with an `<EncryptedData>` (xmlenc 1.1, `aes128-gcm`: IV, ciphertext and tag in the CipherValue; `ds:KeyName` = base64 CSK-ID). Other elements stay clear. | 24.282 §4.6, §6.5.2.3.3, Annex F.1 |
| URI attributes | The `uri` of a resource-lists `entry`; the `entity` and affiliation `group` of a PIDF; the `functionalAliasID` of a functional alias PIDF. Each becomes `sip:<base64 ciphertext>;iv=<base64>;key-id=<base64 CSK-ID>;alg=128-aes-gcm@mc1-encryption.3gppnetwork.org`. | 24.282 §6.5.2.3.4; 33.180 §9.3.4.3 |
| Service authorisation | The first PUBLISH carries the access token and client ID encrypted with the CSK it uploads. The server authenticates the upload first, decrypts with it, and requires the CSK's initiator to be the MCData ID the token names. | 24.282 §7.2.1A step 4 |
| Everything else | Requests and responses in both directions, including SUBSCRIBE, NOTIFY, re-INVITEs and INFO, are decrypted on arrival before any procedure reads them, and encrypted per recipient when sent. So the server decrypts and re-encrypts what it copies from one client to another. A body that cannot be decrypted is answered 403 with warning `140 unable to decrypt XML content`. | 24.282 §6.5.1.4, §6.5.2.4, §6.5.2.5 |

### Signed payloads

With `mcdata.authenticate_payload`, set by `--sign-payloads`, each DATA PAYLOAD is signed on both planes. The payload is signed after it is protected, so a protected and signed payload has bits 7 and 8 set (0xc3). The signed payload is an Authenticated Payload message:

- the Original Payload
- the algorithm (ECCSI)
- the Signing Data: the signer's UID (Annex F.2.1) and KMS URI
- the RFC 6507 signature over everything up to and including the Signature element's type and length

The key is the one the KMS provisioned for the sender's MCData ID. The recipient checks that the Signing UID is the sender's UID for the current or the previous key period, then verifies the signature, before opening the payload. A payload whose signature fails is answered 606 on the signalling plane and discarded on the media plane. It is never rendered.

Values not assigned by the specifications:

- **Payload algorithm and ciphertext IEI.** TS 33.180 V19.4.0 gives DP_AES_128_GCM and the Payload element no numeric values. The client uses the same local wire profile as E.6: algorithm 1 and IEI 0x78 (the Payload IEI of TS 24.282 Table 15.1.4.1-1). Only these two values are local.
- **Message type of a protected file.** TS 24.282 Table 15.2.2-1 has no message type for file data. The file series uses FD SIGNALLING PAYLOAD with bit 7 (0x42), and the length prefix above is also local.
- **Group files over HTTP.** TS 33.180 §8.2 protects group files with the GMK, but TS 24.282 §10.2.2.1 step 8b uploads them in clear. This implementation follows the stage 3 text.
- **Authenticated Payload coding.** TS 33.180 Table 8.5.5-1 gives the elements but no IEIs, no algorithm number and no message type octet. The implementation uses a message type octet (the inner type with bit 8), Original Payload 0x71 (TLV-E), algorithm 1 = ECCSI, Signing Data 0x72 (TLV-E) holding the Signing UID 0x73 and the Signing KMS 0x74 (TLV), and Signature 0x75 (TLV-E, 129 octets).
- **Confidentiality protection domain.** TS 23.003 is not supplied. The domain of an encrypted URI is `mc1-encryption.3gppnetwork.org`, as in the TS 33.180 §9.3.4.3 example.
- **L0 in F.1.5.** F.1.5 prints L0 for the 4-octet DPPK-ID as "0x00 0x17". The implementation uses the length of the parameter, 0x00 0x04, as TS 33.220 Annex B defines it, and as the existing E.6 code already did.

## Run a separate lab

```bash
docker build -t openmcx-dev:0.3 -f docker/Dockerfile.dev .   # pjsip with PJSIP_MAX_PKT_LEN 16000
docker build -t openmcx:<tag> -f docker/Dockerfile .
python3 tools/prepare-prearranged-test.py --directory artifacts/dpp-lab --project openmcx-dpp \
  --debug-sip --private-call --mcdata --protected --key-parameters-iei 0x79 --image openmcx:<tag>
C=".cache/deps/docker-compose-linux-x86_64 -p openmcx-dpp -f artifacts/dpp-lab/compose.json"
$C up -d --wait mcdata-server
docker run -d --rm --name openmcx-dpp-capture --network "container:$($C ps -q mcdata-server)" \
  --cap-drop ALL --cap-add NET_RAW openmcx-dev:0.3 tcpdump -Z root -i eth0 -U --immediate-mode -s 0 -w /tmp/c.pcap tcp   # SIP and MSRP
$C up -d --wait
python3 tests/integration/mcdata_protected_scenario.py \
  --compose artifacts/dpp-lab/compose.json --artifacts artifacts/dpp-lab/artifacts --project openmcx-dpp
docker cp openmcx-dpp-capture:/tmp/c.pcap artifacts/dpp-lab/artifacts/integration/mcdata-protected.pcap
docker stop openmcx-dpp-capture
python3 tests/integration/verify_mcdata_protected.py artifacts/dpp-lab/artifacts/integration/mcdata-protected.pcap \
  --results artifacts/dpp-lab/artifacts/integration/mcdata-protected-results.json \
  --output artifacts/dpp-lab/artifacts/integration/mcdata-protected-wire.json
$C down -v
```

`--mcdata --protected` sets `mcdata.protect_payload` on every client (and `mcdata.authenticate_payload` with `--sign-payloads`), and `mcdata.protect_signalling` and `mcdata.confidentiality_protection` on every client and the MCData server. The MCData server also gets a `security` block. The `tamper-key` word in `sds tamper-key <MCData ID> <text>` is a test aid. It sends an altered I_MESSAGE with a new PCK, which the sender then forgets.

The client status has `mcdata_authentication` (`enabled`, `signed`, `verified`, `failures`), `mcdata_xml_protection` (`enabled`, `encrypted`, `decrypted`) and `mcdata_signalling_protection` (`enabled`, `csk_id`, `sealed`, `opened`, `refused`). The server status has `xml_protection` and `signalling_protection` with the same counters, and `csk_id` for each user. The client status also has `mcdata_protection` with `enabled`, `pck_contexts`, `group_keys`, `sent`, `received` and `failures`. Each `mcdata_sent`, `mcdata_inbox`, `mcdata_media_received`, `mcdata_media_result` and `mcdata_files_sent` entry records `dppk_id` (and, for received items, `protected`). A received file records `plain_bytes` and `plain_sha256` of the decrypted file.

## Performed tests

The protection unit tests and the Go tests pass. The regression runs the scenario in the `mcdata-protected` lab.

| ID | Scenario | Checks |
|---|---|---|
| DS-01 | Every client holds a CSK that the MCData server accepted at service authorisation | 1 |
| DP-01 | The first one-to-one message carries a new PCK; the recipient authenticates it, decrypts and renders the text; both hold one context | 4 |
| DP-02 | A second message reuses the PCK and carries only its PCK-ID | 3 |
| DP-03 | The recipient's reply uses the same PCK in the other direction | 3 |
| DP-04 | A group message is protected with the group's GMK-ID; the three other members decrypt it | 5 |
| DP-05 | An altered I_MESSAGE: the recipient rejects it (606, warning 136) and never renders the message | 3 |
| DP-06 | A new context with that recipient then works, with a PCK distinct from the other pair's | 3 |
| DP-07 | A delivery notification still reaches the sender; no other decryption failure anywhere | 3 |
| DP-08 | A media plane SDS between users with no context: the PCK travels in the SDP offer; the recipient decrypts the MSRP payload | 3 |
| DP-09 | A group media plane SDS is protected with the GMK; the three other members decrypt it | 6 |
| DP-10 | An SDS session reuses the pair's PCK; both parties' messages are decrypted | 6 |
| DP-11 | A file over the media plane: protected with the pair's PCK; the recipient stores a file whose SHA-256 matches the original | 4 |
| DP-12 | Files over HTTP: a one-to-one file names the PCK and is decrypted to the original; a group file travels in clear | 4 |
| DS-02 | The server opened and sealed signalling bodies and refused none; the senders sealed, every client opened, none refused | 2 |
| DX-01 | Every client and the server encrypted and decrypted XML content; the server refused none | 1 |
| DA-01 | With `--sign-payloads`: every received message carried a verified signature; the senders signed, the recipients verified, nothing failed | 2 |
| DA-02 | A message whose signature was altered (`tamper-sig` test aid) is refused by the recipient and never rendered | 3 |

The scenario makes 52 checks, including readiness, and 57 with `--sign-payloads`, where the verifier makes 145 checks over the signed SIP payloads and checks that every MSRP payload is signed. The [wire verifier](../integration/verify_mcdata_protected.py) decodes the capture of SIP and MSRP at the MCData server independently. It passed 118 checks over:

- 7 protected SIP payloads and 32 protected SIP signalling bodies
- 83 XML bodies
- 26 protected MSRP payloads, 42 protected MSRP signalling bodies and 2 protected files

The capture contains no MCData ID and no access token anywhere. The capture of the signalling-only run held the access token 4 times.

| ID | Wire check |
|---|---|
| W-01 | Every DATA PAYLOAD body is a Protected Payload message of type 0x43, Payload ID 0, sequence 0, whose TLV-E length matches the message |
| W-02 / W-03 | One-to-one payloads use a PCK-ID (purpose 1); group payloads use a GMK-ID (purpose 0) |
| W-04 | The `application/mikey` body appears only with a one-to-one SDS or FD request. It decodes as MIKEY-SAKKE with the payload's PCK-ID as CSB-ID, MCData IDs in IDRi and IDRr, and no key parameters |
| W-05 | The MCData server relays each protected payload byte for byte |
| W-06 | The altered I_MESSAGE is answered 606 with warning 136 |
| W-07 | None of the texts the scenario sent, nor the marker at the start of each protected file, appears anywhere in the capture |
| W-08 | Media plane offers with `a=key-mgmt` carry a PCK between MCData IDs, and the server's offer to the recipient carries the same value |
| W-09 | Every DATA PAYLOAD in an MSRP SEND is a Protected Payload message (0x43) |
| W-10 | Every file in an MSRP SEND is a series of Protected Payload messages (0x42) |
| W-11 | Every signalling body in SIP is a Protected Payload message with bit 7 set, under a CSK-ID (purpose 2), with one CSK per client |
| W-12 | No mcdata-info, resource-lists or PIDF body holds an MCData ID or an element still marked `type="Normal"`; `EncryptedData` with `aes128-gcm` and encrypted URIs are present |
| W-13 | No access token (the JWT prefix `eyJhbGci`) anywhere in the capture |
| W-14 | Every signalling body inside an MSRP SEND is protected (bit 7) |
| W-15 | With signing: every DATA PAYLOAD, in SIP and in MSRP, is an Authenticated Payload (0xc3) with an ECCSI Signature element of 129 octets |

The [standalone SDS scenario](MCDATA_SDS_TEST.md) was run again on the protected fixture: 163 checks, every one-to-one and group payload protected, and 69 signalling bodies opened and 60 sealed by the server, none refused. The six SD-10 checks that send to groups other than the protected group check that the client refuses to send without a GMK for them. On a clear fixture they check the server's rejections as before.

On a fixture with signalling protection only (`protect_payload` turned off after preparation), all six MCData scenarios passed:

| Scenario | Signalling bodies opened / sealed by the server |
|---|---|
| SDS | 75 / 60 |
| FD over HTTP | 36 / 47 |
| Communication release | 11 / 13 |
| Enhanced status | 4 / 9 |
| Media plane | 11 / 11 |
| IP connectivity | 0 / 0 (it carries no signalling bodies) |

None was refused.

The media plane and FD scenarios were not run with payload protection. Many of their checks test the lab's size limits (auto-receive at 64 octets, 300 octets per one-to-one request), which the 59 octets of a Protected Payload message cross.

The same scenarios run clear in the `mcdata` and `mcdata-ipconn` labs.

The image build also raises pjsip's `PJSIP_MAX_PKT_LEN` from 4000 to 16000. A service authorisation PUBLISH carrying the access token, the CSK I_MESSAGE and the XML bodies exceeded 4000 octets once the token carried the MCData key management scope. The long identities of client-c and client-d crossed the limit first, and the send failed with `PJSIP_EMSGTOOLONG`.

## Coverage gaps

| Area | Gap |
|---|---|
| Other MCData messages | Ad hoc group SDS, sessions and files (clause 24) stay clear: they need the GMK of a preconfigured group. Group files over HTTP are clear (see above). A multi-message file series is covered by unit tests only, because the lab's FD limit is 4000 octets. |
| Signalling protection | The CSK is uploaded once, not renewed by key download (24.282 §7.2.5), and has no MuSiK. |
| Signed payloads | Files are not signed; TS 33.180 §8.5 lists only the Authenticated Data Payload. Signatures are checked against the sender's MCData ID from its own KMS, and there is no cross-KMS verification. |
| XML protection | XML integrity protection (xmlsig HMAC, `application/vnd.3gpp.mcptt-signed+xml`, warning 139) is not implemented. Confidentiality covers mcdata-info, resource-lists and the affiliation and functional-alias PIDF bodies. The location-info, conference-info and regroup bodies are not covered. MCPTT XML confidentiality and integrity are in the [MCPTT XML protection tests](../mcptt/XML_PROTECTION_TEST.md). |
| Context recovery | The MCData server answers the sender before delivery and does not relay a recipient's 606. A sender whose recipient lost the PCK context is not told. It sends a new I_MESSAGE only when its own context expires. |
| Multiple servers | The MCData server is one combined participating and controlling function: there are no separate servers. |
| Interoperability | Lab to lab only. The algorithm and ciphertext IEI values are local, and the ECCSI SIGN length field is 129 (see the security audit). |
| Off-network | The I_MESSAGE inside the Protected Payload message (NOTE 4 of Table 8.5.4.1-1) is for off-network use: not in present edition. |
