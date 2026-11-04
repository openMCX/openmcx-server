# Tutorial 9: call flow of TS 37.579-2 test 5.1 over IP, step by step

This page follows the [walk-through of test 5.1](README.md#3-walk-through-of-ts-37579-2-test-51) message by message:
- for each step of TS 37.579-2 V18.1.0 table 5.1.3.2-1, the procedure of TS 37.579-1 V18.1.0 it refers to;
- the messages the MC client sends and receives, with the frame numbers of the
  [reference capture](captures/09-test-5-1-over-ip-full.pcap.gz) (ESP decrypted, see
  [Look at the capture](README.md#4-look-at-the-capture));
- where OpenMCX or this tutorial **differs from the test's procedure**, marked **⚠ G*n*** and listed in
  [Gaps](#gaps) at the end.

The MC client is OpenMCX's Linux client `client-d` on an IP network, without 3GPP access. The OpenMCX system takes
the system simulator's place: this is a walk-through, not a conformance test.

## Actors

| Name in the diagrams | What it is | Address in the capture |
|---|---|---|
| UE | the MC client `client-d@mcx.test` | `172.31.109.104` |
| P-CSCF | Kamailio with `docker/pcscf.cfg` | `172.31.109.60` |
| SIP core | the S-CSCF and registrar (Kamailio) | `172.31.109.10` |
| IdMS | OpenMCX IdMS | `172.31.109.40:8443` |
| KMS | OpenMCX KMS | `172.31.109.43:8443` |
| Proxy | home HTTP proxy, forward mode | `172.31.109.45:8443` |
| CMS, GMS | configuration and group management servers, behind the proxy | `cms:8443`, `gms:8443` |
| MCPTT | MCPTT server (also the CMS and GMS subscription target, see G4) | `172.31.109.20` |
| MCData | MCData server | `172.31.109.21` |

## Overview

| 5.1 step | TS 37.579-1 procedure | Frames | Gaps |
|---|---|---|---|
| 1 | 5.4.1B MCX PDU session | - | G1 |
| in parallel to 3-16 | table 5.3.2.4.1-1 SIP registration | 198-309 | G2 |
| 3-12 | table 5.3.2.3.1-1 steps 1-10 (initial configuration, user authentication) | 203-295 | - |
| 13-16 | table 5.3.2.3.1-1 steps 11-14 (key material) | 327-350 | G3, G5, G6 |
| 18 | table 5.3.2.6.1-1 configuration management subscription | 883-1067 | G4 |
| 17 | table 5.3.2.5.1-1 publication of MCX service settings | 1676-1823 | - |
| 19 | table 5.3.2.7.1-1 group management subscription | 1703-2954 | G4 |
| (main procedure 6-7) | table 5.3.2.2.1-1 location reporting configuration | 1760-1892 | - |
| (after 5.1) | affiliation, location reports, MC log-off, SIP de-REGISTER | 1900-4504 | G7 |

Order in the reference run: the SIP registration and the sign-in run in parallel; then the key material (steps
13-16), the configuration subscription (step 18), the service authorisation (step 17) and the group subscription
(step 19). Table 5.1.3.2-1 has steps 17-19 in parallel; the PUBLISH follows the user profile (table 5.3.2.5.1-1 NOTE 1).

```mermaid
sequenceDiagram
    autonumber
    participant UE
    participant PC as P-CSCF
    participant SC as SIP core
    participant IdMS
    participant KMS
    participant PX as Proxy
    participant AS as MCPTT
    Note over UE: step 1: no 5GS or EPS, plain IP (⚠ G1)
    par SIP registration
        UE->>PC: REGISTER (198), 401 (251), protected REGISTER in ESP (258), 200 (274)
        PC->>SC: REGISTER, 401, REGISTER, 200 (217-273)
    and sign-in
        UE->>IdMS: steps 3-12: authorize, form, userauth, code, token (203-295)
    end
    UE->>KMS: steps 13-16: KMS Initialize, KeyProvision, signed, TrK-wrapped (327, 350)
    UE->>AS: step 18: SUBSCRIBE configuration (883), NOTIFY (1012)
    UE->>PX: GETs of the three documents, absolute-form (1023-1067)
    UE->>AS: step 17: PUBLISH poc-settings with the access token (1676), 200 (1691)
    UE->>AS: step 19: SUBSCRIBE group document (1703), GKTP document (2020)
    AS->>UE: NOTIFYs (2598, 2830)
    UE->>PX: GET of the group document (2608)
    Note over UE: MC log-off, SIP de-REGISTER (4416-4504)
```

## Step 1: switch-on and the access

TS 37.579-1 clause 5.4.1B sets up the MCX PDU session (5GS) or PDN connection (EPS) for the MC client's signalling.
Here the client's container is on an IP network (`172.31.109.0/24`) and reaches the P-CSCF and the HTTP services
directly: the IPCAN model of a test system reached over a VPN. **⚠ G1**

## In parallel to steps 3-16: SIP registration with IMS AKA

TS 37.579-1 table 5.3.2.4.1-1. The client takes path 3b1: its REGISTER carries no access token, which goes in the
PUBLISH of step 17 (table 5.3.2.4.1-1 NOTE 1; TS 33.180 clause 5.1.3.2.1: the REGISTER is not delayed for the token).

```mermaid
sequenceDiagram
    participant UE
    participant PC as P-CSCF
    participant SC as SIP core
    UE->>PC: (1) REGISTER, unprotected, to port 5060 (frame 198)<br/>Security-Client: ipsec-3gpp, the client's alg/ealg pairs, spi-c/spi-s, port-c 44614, port-s 5064<br/>Require, Proxy-Require: sec-agree, Expires 600000
    PC->>SC: REGISTER (217)
    SC->>PC: 401 (245): AKAv2-SHA-256 and AKAv1-MD5 challenges, ck and ik
    PC->>UE: (2) 401 (251): both challenges (ck, ik removed)<br/>Security-Server: spi-c 4096, spi-s 4097, port-c 5100, port-s 6100
    Note over UE: checks AUTN (MAC, SQN), computes RES, CK, IK<br/>sets up the temporary SAs (ESP, transport mode)
    Note over UE,PC: ⚠ G2: the client answers the first challenge, AKAv2-SHA-256
    UE->>PC: (3b1) REGISTER inside ESP, port_uc to port_ps 6100 (258)<br/>Security-Verify (the P-CSCF's list), Authorization with RES, AKAv2-SHA-256
    PC->>SC: REGISTER (272)
    SC->>PC: 200 (273)
    PC->>UE: (4) 200 inside ESP (274)<br/>P-Associated-URI sip:client-d@mcx.test, Service-Route, expires=3600
    UE->>PC: SUBSCRIBE reg event inside ESP (277), Expires 600000
    PC->>UE: 200 (298), Expires 3761; NOTIFY (307); the client's 200 (309)
```

- The P-CSCF chose `alg=null`, `ealg=aes-gcm-us` (AES-GCM, TS 33.203 annex I), the client's first pair.
- Every later request of the client carries Security-Verify and the sec-agree option tag in Require (RFC 3329
  section 2.3.1, TS 24.229 annex A), Proxy-Require in INVITE and OPTIONS only ([Known
  limitations](../../../docs/LIMITATIONS.md), "sec-agree option-tag in Proxy-Require"). Its Via names its protected
  server port 5064 (TS 24.229 clause 5.1.2A.1.1). The P-CSCF removes both before passing a request on.
- The reg event subscription (TS 24.229 clause 5.1.1.3) is not part of table 5.3.2.4.1-1.
- What to check: in the capture, `sip && ip.addr == 172.31.109.104 && tcp.port == 5060` (frames 198, 251) and
  `esp && sip` (258, 274); `sip_security` in the client's status (README step 3, check 1).
- Normative: TS 24.229 clauses 5.1.1.2, 5.1.1.5, 5.2.2; TS 33.203 clauses 6.1, 7; TS 33.180 clause 6.2.1.

## Steps 3-12: initial configuration and user authentication

TS 37.579-1 table 5.3.2.3.1-1 steps 1-10. Step 1a, the initial UE configuration, is preconfigured
(`config/client-d.json`). TLS to the IdMS directly, as the table's exceptions ask (TS 24.482 annex A.2.1.2).

```mermaid
sequenceDiagram
    participant UE
    participant IdMS
    Note over UE: 1a: preconfigured initial UE configuration (no GET, allowed by the table's NOTE)
    UE->>IdMS: TLS, server name idms (frame 203)
    UE->>IdMS: (3a1) HTTP GET authorization endpoint (OIDC authentication request, PKCE)
    IdMS->>UE: (4) 200: HTML form, fields user and password
    Note over UE: (5) user name and password stored on the UE (table NOTE 1)
    UE->>IdMS: TLS (228)
    UE->>IdMS: (6) HTTP POST /userauth with the credentials
    IdMS->>UE: (7) 302 (Found) with the authorization code
    UE->>IdMS: TLS (249, 295)
    UE->>IdMS: (9) HTTP POST token endpoint with the code
    IdMS->>UE: (10) 200: id_token, access_token, refresh_token
    Note over UE: checks the ID token signature with the key of the configured jwks_uri
```

- What to check: `signed_in` in the client's status; with `MCX_LOG=debug`,
  `docker compose logs idms | grep -E 'HTTP (GET|POST) /(authorize|userauth|token)'`.
- Normative: TS 24.482 clause 6.2.1; TS 33.180 clause 5.1.2, annex B.

## Steps 13-16: key material from the KMS

TS 37.579-1 table 5.3.2.3.1-1 steps 11-14, right after the token. The KMS holds a TrK and an InK for the client's
MCPTT user (TS 33.180 clause 5.3.2, annex D.2.2, D.3.1).

```mermaid
sequenceDiagram
    participant UE
    participant PX as Proxy
    participant KMS
    Note over UE,PX: ⚠ G3: the table sends steps 11-14 through the TLS tunnel to the HTTP proxy,<br/>OpenMCX sends them to the KMS directly
    UE->>KMS: TLS, server name kms (frame 327)
    UE->>KMS: (11) HTTP POST KMS Initialize with the access token, signed with the InK
    KMS->>UE: (12) 200, signed: KMS certificate (KPAK, Z_T, key period)
    UE->>KMS: TLS (350)
    UE->>KMS: (13) HTTP POST KeyProvision with the access token, signed with the InK
    KMS->>UE: (14) 200, signed: key set (UserID, SSK, PVT, RSK) wrapped under the TrK
    Note over UE: verifies the signatures, unwraps with the TrK,<br/>validates SSK/PVT (RFC 6507 5.1.2) and RSK (RFC 6508)<br/>⚠ G5: UID form; ⚠ G6: TrK/InK details the texts leave open
```

- What to check: `transport_keys` and `key_management` in the client's status (README step 3, check 2); with
  `MCX_LOG=debug`, `docker compose logs kms | grep kms_signed_request`.
- Normative: TS 33.180 clauses 5.3.2, 5.3.3, 5.3.5, 5.3.6, annexes D and F.

## Step 18: configuration management subscription

TS 37.579-1 table 5.3.2.6.1-1.

```mermaid
sequenceDiagram
    participant UE
    participant PC as P-CSCF
    participant AS as MCPTT
    participant PX as Proxy
    participant CMS
    UE->>PC: (1) SUBSCRIBE inside ESP (frame 883), Event xcap-diff, Expires 3600<br/>Request-URI sip:mcptt@mcx.test (⚠ G4), multipart: MCPTT-Info with the access token,<br/>resource list: UE configuration, user profile, service configuration
    PC->>AS: via the SIP core
    AS->>UE: (2) 200 (940)
    AS->>UE: (3) NOTIFY xcap-diff with the three XCAP URIs (1012)
    UE->>AS: (4) 200 (1014)
    UE->>PX: TLS tunnels (1023, 1042, 1067)
    PX->>CMS: (5) GET absolute-form, https://cms:8443/..., with the access token
    CMS->>UE: (6) 200 with each document
```

- The GETs come after the NOTIFY (`mcptt.documents_on_notify`), and ':' and '@' stand unencoded in the XCAP path
  segments (RFC 3986 section 3.3).
- What to check: `configuration` and `ue_configuration` in the client's status (README step 3, check 4); with
  `MCX_LOG=debug`, `docker compose logs http-proxy` (the requests by authority, `cms:8443`).
- Normative: TS 24.484 clauses 6.3.13.3.2.2, 8.2; TS 24.482 annex A.2.1.2; RFC 4825.

## Step 17: publication of MCX service settings (service authorisation)

TS 37.579-1 table 5.3.2.5.1-1, path 1b1: the access token goes in the PUBLISH, after the user profile was read
(table NOTE 1).

```mermaid
sequenceDiagram
    participant UE
    participant PC as P-CSCF
    participant AS as MCPTT
    participant MD as MCData
    UE->>PC: (1b1) PUBLISH inside ESP (frame 1676), Event poc-settings<br/>Request-URI sip:mcptt@mcx.test, multipart: MCPTT-Info with the access token,<br/>poc-settings with the user profile index
    AS->>UE: (2) 200 (1691)
    UE->>MD: PUBLISH poc-settings, sip:mcdata@mcx.test (1698)
    MD->>UE: 200 (1823)
```

- What to check: `authorized` and `mcdata_authorized` in the client's status (README step 3, check 3).
- Normative: TS 24.379 clause 7.2.1; TS 24.282 clause 7.2.1; TS 33.180 clause 5.1.3.2.3.

## Step 19: group management subscription

TS 37.579-1 table 5.3.2.7.1-1: path 1b1 (the group document) and path 1a1 (the group's GKTP document, table
5.3.2.7.1-2, for the GMK).

```mermaid
sequenceDiagram
    participant UE
    participant PC as P-CSCF
    participant AS as MCPTT
    participant PX as Proxy
    participant GMS
    UE->>PC: (1b1) SUBSCRIBE inside ESP (frame 1703), Event xcap-diff, Expires 600<br/>Request-URI = the configured GMS-URI (here sip:mcptt@mcx.test, ⚠ G4)<br/>resource list: org.openmobilealliance.groups/global/byGroupID/sip:operations@mcx.test
    AS->>UE: (1b2) 200 (2004)
    UE->>PC: (1a1) SUBSCRIBE inside ESP (2020), Event xcap-diff, Expires 3600<br/>resource list: the GKTP document of operations
    AS->>UE: 200 (2360)
    AS->>UE: (3) NOTIFY with the group document's XCAP URI (2598)
    UE->>AS: (4) 200 (2599)
    UE->>PX: TLS tunnel (2608)
    PX->>GMS: (5) GET absolute-form with the access token: group document
    GMS->>UE: (6) 200 with the document
    AS->>UE: NOTIFY with the GKTP document (2830): the GMK in a MIKEY-SAKKE I_MESSAGE
    UE->>AS: 200 (2954)
```

- What to check: `group_documents`, `group_subscription_result`, `group_key_id` and `protected_ready` in the
  client's status (README step 3, check 5).
- Normative: TS 24.481 clauses 6.3.13.2.1, 6.3.13.2.2.

## Main procedure steps 6-7: location reporting configuration

TS 37.579-1 table 5.3.2.2.1-1 steps 6-7.

```mermaid
sequenceDiagram
    participant UE
    participant AS as MCPTT
    participant MD as MCData
    AS->>UE: MESSAGE: location reporting configuration (frame 1760)<br/>triggers t1 InitialLogOn, t2 GroupCallNonEmergency, distance, areas, cell change
    UE->>AS: 200 (1762)
    MD->>UE: MESSAGE (1889)
    UE->>MD: 200 (1892)
```

- What to check: `location.configured` and `mcdata_location.configured` in the client's status (README step 3, check 6).
- Normative: TS 24.379 clause 13.2.2; TS 24.282 clause 17.

## After test 5.1: affiliation, location reports, log-off

Not checked by test 5.1, shown for completeness.

```mermaid
sequenceDiagram
    participant UE
    participant PC as P-CSCF
    participant AS as MCPTT
    participant MD as MCData
    UE->>MD: PUBLISH presence (affiliation, 1900), 200 (1934)
    UE->>AS: PUBLISH presence (affiliation, 2961), 200 (3108)
    UE->>AS: MESSAGE: location report, trigger t1 (3338)
    AS->>UE: 403, warning 100 "location reporting not authorised" (3369) ⚠ G7
    UE->>MD: MESSAGE: location report (3372)
    MD->>UE: 403 (3400)
    Note over UE: log-off command
    UE->>AS: SUBSCRIBE Expires 0 (end of the subscriptions, 4416-4420)
    UE->>AS: PUBLISH poc-settings Expires 0 per service (MC log-off: MCData 4422, MCPTT 4424)
    AS->>UE: final NOTIFYs, the client's 200s (4450-4492)
    AS->>UE: 200 to the PUBLISHes (4482, 4484)
    UE->>PC: REGISTER Expires 0 (SIP de-REGISTER, 4488)
    PC->>UE: 200 (4497); final reg NOTIFY (4504)
```

- Normative: TS 24.379 clauses 9.2.1.2 and 9.2.1.3 (affiliation), 13.2.4 (location report), 7.2.1A NOTE 3 (MC
  log-off); TS 24.229 clause 5.1.1.6 (SIP de-REGISTER).

## Gaps

Each gap is one of:
- **spec gap**: the specifications leave the detail open or contradict each other; OpenMCX keeps its behaviour and
  reports it ([Known limitations](../../../docs/LIMITATIONS.md));
- **tutorial**: a choice of this tutorial or its test bed, not of the MC client.

| Gap | Kind | Step | What | Where described |
|---|---|---|---|---|
| G1 | tutorial | 1 | No 5GS or EPS: the client is on an IP network (the IPCAN model of a test system over a VPN), without a radio, a system simulator or a TTCN-3 test suite. | README, step 3 |
| G2 | tutorial | SIP registration | The SIP core offers AKAv2-SHA-256 before AKAv1-MD5 (TS 33.203 clause 6.1.1) and the client answers the first; table 5.3.2.4.1-1 step 2 sends AKAv1-MD5 only, which the client also answers. | README, step 3 |
| G3 | spec gap | 13-16 | The KMS requests go to the KMS directly. Table 5.3.2.3.1-1 steps 11-14 send them through the TLS tunnel to the HTTP proxy; TS 24.482 annex A.2.1.2 sends every request but the IdMS's through the proxy, TS 33.180 clause 5.3.2 lets the KMS be used without it, and no configuration item tells the UE which applies. The Linux client's `security.kms_via_proxy` (off by default) sends them through the proxy. | Known limitations, "Home HTTP proxy" |
| G4 | spec gap | 18, 19 | The configuration SUBSCRIBE goes to the MCPTT server's PSI: TS 24.484 clause 6.3.13.2.2 b) 2) names "the configured public service identity for performing subscription proxy function of the CMS", but no configuration item for it exists (the Linux client's `cms.subscription_psi` sets one). The group SUBSCRIBEs go to the configured GMS-URI, in this tutorial the same PSI. | Known limitations, "CMS subscription proxy PSI" |
| G5 | spec gap | 13-16, and every MIKEY-SAKKE use | TS 33.180 annex F.2.1.1 does not say whether ECCSI and SAKKE take the UID's 32 octets or its base64 text. OpenMCX's KMS uses the text; the Linux client finds the form that validates the key set (`key_management.uid_form`, `text` here). | Known limitations, "MIKEY-SAKKE UID form" |
| G6 | spec gap | 13-16 | The TrK and InK exchange follows the texts where they are clear; the details they leave open (Signature-ID and TrK-ID, the key-wrap padding, the schema Id, AES-128-GCM, a Time without a zone) are listed there. | Known limitations, "KMS request security (TrK/InK)" |
| G7 | tutorial | after 5.1 | `client-d` is the generator's user without the right to report its location (the regression's refusal case), so its reports are refused with 403. | README, step 3 |
