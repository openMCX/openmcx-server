# Tutorial 9: Test 5.1 over IP

The OpenMCX system on one computer, with OpenMCX's Linux client as the MC client under test. The client has no 3GPP
access, no 5G core and no radio: it reaches the P-CSCF over plain IP, as it would over a VPN to a test system. From
switch-on to service, it goes through test 5.1 of TS 37.579-2 by itself:
- the user signs in to the IdMS;
- the client registers with **IMS AKA** through a **P-CSCF**, with its SIP inside **IPsec ESP**;
- it gets its key material from the KMS, with the exchange **signed and the keys wrapped under a transport key
  (TrK)**;
- the MCPTT and MCData servers authorise the service;
- the client subscribes to its configuration and group documents, and to the group's key (GMK).

Its HTTP requests go through the **home HTTP proxy** in absolute-form, except the IdMS's and the KMS's. At the end it
logs off (the MC log-off) and de-registers.

[Tutorial 7](../07-ims-aka-over-oai-5g/README.md) runs the same test with the client inside a 5G UE. Here the client's
container is a terminal without 3GPP access, so its software IMS AKA credentials are the IM credentials that TS 33.180
clause 6.2.1 allows for "non-3GPP-only MC UEs not equipped with UICC" (TS 33.203 clause 9, TS 24.229 clause
5.1.1.1B.1).

## What you need

- **A Linux computer** with Docker and Docker Compose v2 (2.24 or later) and about 4 CPU cores free.
- **IPsec in the kernel**: the modules `xfrm_user`, `esp4`, `authenc` and `gcm`, as in the kernels of the common Linux
  distributions. The client and the P-CSCF set up their security associations in their own containers (with
  `NET_ADMIN`); if a module is not loaded yet: `sudo modprobe -a xfrm_user esp4 authenc gcm`.
- Nothing to compile, no phones, no `sudo` otherwise. The tutorial uses OpenMCX's **`develop` images** from Docker Hub
  (IMS AKA, the TrK and the documents on notify need a version after 1.0.0).
- Nothing is published on the computer: every service is on the tutorial's own network, `172.31.109.0/24`
  (bridge `openmcx-t09`).

## 1. Make the configuration

```bash
cd tutorials/end-to-end/09-test-5-1-over-ip
docker compose run --rm setup
```

The setup runs OpenMCX's lab generator (`tools/prepare-prearranged-test.py`, the generator of the regression labs)
with the flags at the top of `docker-compose.yaml`, and copies the configuration to `./config`. Among them:

| Flag | What it gives the MC client `client-d` |
|---|---|
| `--aka-role client-d` | An IMS AKA subscription (private user identity `client-d@mcx.test`, K and OPc of its own) in the SIP database, and the P-CSCF (`pcscf`, `docker/pcscf.cfg`) as its first hop. |
| `--http-proxy-mode forward` | The home HTTP proxy in forward mode (TS 24.482 annex A.2.1.2): the clients name each server by its own URI and send their requests to the proxy in absolute-form, over a TLS tunnel. |
| `--protected --key-parameters-iei 0x79` | MIKEY-SAKKE keys: a client signature key (CSK) for the service, the group's GMK. |
| `--transport-keys --transport-key-role client-d=trk+ink` | A TrK and an InK for `client-d`'s MCPTT user (TS 33.180 clause 5.3.2, annex D): the KMS exchange is signed and the key set wrapped. |
| `--documents-on-notify` | The client GETs its documents only after the NOTIFY that names them (TS 37.579-1 tables 5.3.2.6.1-1 and 5.3.2.7.1-1). |
| `--group-management --location` | The group `operations` from the GMS, and the servers' location reporting configuration. |

The other three clients (`client-a` to `client-c`) are users of the same system with SIP digest, as on a control
room's network. They take no part in the test.

The certificates last 30 days. If `./config` exists, the setup stops: to start over, see step 5.

## 2. Start the system

```bash
MCX_LOG=debug docker compose up -d --wait
```

After about a minute all services are `(healthy)`. `client-d` is healthy once it has signed in, registered with IMS AKA
and been authorised.

`MCX_LOG=debug` is optional. With it, the logs hold the SIP messages and the HTTP requests, the HTTP proxy logs each
request line (step 3 checks their form), and `client-d`'s log holds the keys of its IPsec security associations (lines
`ESP SA`), so Wireshark can decrypt its SIP (step 4). **Treat that log as secret.**

## 3. Walk-through of TS 37.579-2 test 5.1

```bash
./run.sh
```

Test 5.1 of TS 37.579-2 V18.1.0 is "Configuration / Authentication / User Authorisation / UE Configuration / User
Profile / Key Generation" (table 5.1.3.2-1). It checks what an MC client does from switch-on to service, with the
procedures of TS 37.579-1 V18.1.0. Here it is a walk-through, not a conformance test: there is no TTCN-3 test suite
(TS 37.579-5) and no validated system simulator. The OpenMCX system takes the system simulator's place; the
implementation under test is `client-d`.

The test runs by itself at every start of the system (step 2). The client is preconfigured with the initial UE
configuration (TS 37.579-1 table 5.3.2.3.1-1 step 1a, the data of table 5.5.8.1-1: the IdMS, the HTTP proxy, the
P-CSCF and the identities) and with the user name and password (NOTE 1 of that table: stored on the UE).

`run.sh` checks each step in `client-d`'s status file, in this order:

1. the SIP registration with IMS AKA through the P-CSCF, and the security associations in use (TS 33.203 clause 7.1):
   `AKAv2-SHA-256`, `ipsec-3gpp`, `alg` `null` and `ealg` `aes-gcm-us` (AES-GCM, which protects integrity itself),
   the UE's protected server port `port_us` 5064 and the P-CSCF's `port_ps` 6100; then the subscription to its reg
   event (TS 24.229 clause 5.1.1.3);
2. the sign-in, then the KMS: `transport_keys` shows `signed, TrK-wrapped keys`;
3. the service authorisation of MCPTT and MCData;
4. the configuration subscription with the three documents, its NOTIFY and the GETs;
5. the group document subscription, its NOTIFY and the GET; the CSK and the GMK;
6. the location reporting configuration from the MCPTT and MCData servers;
7. with `MCX_LOG=debug`: every request through the HTTP proxy in absolute-form, none in origin-form;
8. the MC log-off (a PUBLISH with Expires 0 per service, TS 24.379 clause 7.2.1A NOTE 3), then the SIP de-REGISTER
   (TS 24.229 clause 5.1.1.6);
9. the capture, copied to `captures/09-test-5-1-over-ip-run.pcap.gz`, and with `MCX_LOG=debug` the keys of the
   client's security associations, as `captures/09-test-5-1-over-ip-run.esp_sa`. Before the log-off (check 8) it saves
   `client-d`'s status as the test left it, as `captures/09-test-5-1-over-ip-run.status.json`.

To run the test again, start over (step 5): the client has logged off.

Step by step (the messages of each step, with the frame numbers of the reference capture and where OpenMCX or this
tutorial differs from the test's procedure: [call flow](CALL_FLOW.md)):

| 5.1 step | TS 37.579-1 | What the client does | Normative clauses |
|---|---|---|---|
| 1 | 5.4.1B (IPCAN) | No 5GS or EPS: the client's container is on an IP network, which takes the place of the MCX PDU session. | |
| in parallel to 3-16 | table 5.3.2.4.1-1, path 3b1 | Initial REGISTER, unprotected, to the P-CSCF's port 5060, with Security-Client (`ipsec-3gpp`, the client's algorithms, its SPIs and ports) and sec-agree in Require and Proxy-Require. The SIP core answers 401 (Unauthorized) with an AKAv2-SHA-256 and an AKAv1-MD5 challenge; the P-CSCF adds Security-Server and removes the ck and ik meant for it. The client checks AUTN, computes RES, CK and IK, sets up the temporary security associations and sends the protected REGISTER from port_uc to port_ps, with Security-Verify and the AKA response; 200 (OK). The REGISTER does not wait for the access token, which goes in the PUBLISH (step 17). Every later request carries Security-Verify and sec-agree in Require. | TS 24.229 clauses 5.1.1.2, 5.1.1.5, 5.2.2; TS 33.203 clauses 6.1, 7; RFC 3329 section 2.3.1; TS 33.180 clauses 5.1.3.2.1, 6.2.1 |
| 3-12 | table 5.3.2.3.1-1 steps 1-10 | The OIDC authentication request to the IdMS; the HTML form; the form posted to the IdMS's `/userauth`; the 302 (Found) with the code; the token request; the ID, access and refresh tokens. The IdMS is reached directly, not through the HTTP proxy (TS 24.482 annex A.2.1.2). | TS 24.482 clause 6.2.1; TS 33.180 clause 5.1.2, annex B |
| 13-16 | table 5.3.2.3.1-1 steps 11-14 | KMS Initialize and KeyProvision with the access token, each request signed with the InK, each answer verified, the key set unwrapped with the TrK. The requests go to the KMS directly ([Known limitations](../../../docs/LIMITATIONS.md), "Home HTTP proxy"). | TS 33.180 clauses 5.3.2, 5.3.3, annex D |
| 17 | table 5.3.2.5.1-1, path 1b1 | PUBLISH to the MCPTT and MCData servers with the access token (service authorisation) and the PoC settings; 200 (OK). | TS 24.379 clause 7.2.1; TS 24.282 clause 7.2.1; TS 33.180 clause 5.1.3.2.3 |
| 18 | table 5.3.2.6.1-1 | One SUBSCRIBE with the access token and a resource list of the MCPTT UE configuration, user profile and service configuration documents; the NOTIFY with their XCAP URIs; the GETs after the NOTIFY, through the HTTP proxy. | TS 24.484 clauses 6.3.13.3.2.2, 8.2; TS 24.482 annex A.2.1.2 |
| 19 | table 5.3.2.7.1-1, paths 1b1 and 1a1 | SUBSCRIBE to the group document of `operations`; NOTIFY; the GET. SUBSCRIBE to the group's GKTP document (table 5.3.2.7.1-2); NOTIFY; the GMK. | TS 24.481 clauses 6.3.13.2.1, 6.3.13.2.2 |
| (main procedure 6-7) | table 5.3.2.2.1-1 | The MCPTT and MCData servers' MESSAGE configuring location reporting; the client's 200 (OK). | TS 24.379 clause 13.2.2; TS 24.282 clause 17 |

Where the walk-through departs from the test, in short (the full list: [call flow, Gaps](CALL_FLOW.md#gaps)):

- **The access**: no 5GS or EPS, no radio (step 1).
- **The challenge**: the SIP core offers AKAv2-SHA-256 before AKAv1-MD5 (TS 33.203 clause 6.1.1), and the client
  answers the first. The 401 of TS 37.579-1 table 5.3.2.4.1-1 carries AKAv1-MD5, which the client also supports.
- **The KMS** is reached directly, not through the HTTP proxy.
- **After the test**: `client-d` is the generator's user without the right to report its location, so its first
  report (trigger `InitialLogOn`) is refused, 403 (Forbidden) with warning 100 from the MCPTT server. Location
  reporting is not part of test 5.1.

## 4. Look at the capture

The reference capture is [`captures/09-test-5-1-over-ip-full.pcap.gz`](captures/09-test-5-1-over-ip-full.pcap.gz)
(1.0 MB, 4 541 frames). It records a run of steps 2 and 3: the system starting, `client-d` signing in, registering
with IMS AKA, getting its keys and being authorised and configured, then its MC log-off and SIP de-REGISTER.
Wireshark opens the compressed file directly. The frame numbers below are those of the reference.

It was captured on the tutorial's network (`172.31.109.0/24`) and keeps:
- SIP on 5060 in clear: between the servers, the SIP core and the P-CSCF, and of the digest clients `client-a` to
  `client-c`;
- `client-d`'s SIP, unprotected on 5060 until the 401, then inside **IPsec ESP** between the client and the P-CSCF;
- HTTPS on 8443, encrypted: the clients' requests to the IdMS and the KMS, and the TLS tunnels to the HTTP proxy;
- UDP, for media and floor control (none in this run: no call is made).

It leaves out DNS, the databases and the computer's own traffic on the bridge.

To read the SIP inside ESP, give Wireshark the run's security associations:
1. copy [`captures/09-test-5-1-over-ip-full.esp_sa`](captures/09-test-5-1-over-ip-full.esp_sa) to
   `~/.config/wireshark/esp_sa`, or import it in **Edit → Preferences → Protocols → ESP → ESP SAs**;
2. tick **Attempt to detect/decode encrypted ESP payloads** there.

They are the keys of this throwaway run (CK and IK of one AKA challenge). A run of your own has others, in
`captures/09-test-5-1-over-ip-run.esp_sa` (with `MCX_LOG=debug`).

Addresses: the SIP core `.10`, the MCPTT server `.20`, the MCData server `.21`, the IdMS `.40`, the KMS `.43`, the HTTP
proxy `.45`, the P-CSCF `.60`, `client-d` `.104`.

Useful display filters:

| Filter | Shows |
|---|---|
| `sip && ip.addr == 172.31.109.104 && tcp.port == 5060` | IMS AKA: the unprotected REGISTER with Security-Client, and the 401 with the AKA challenges and Security-Server. |
| `esp && sip` | `client-d`'s SIP inside ESP (with the ESP SAs above): the protected REGISTER, PUBLISH, SUBSCRIBE, NOTIFY, MESSAGE. |
| `sip && ip.addr == 172.31.109.60 && ip.addr == 172.31.109.10` | The same requests between the P-CSCF and the SIP core. |
| `ip.src == 172.31.109.104 && tls.handshake.type == 1` | `client-d`'s TLS connections: the IdMS, the KMS and the HTTP proxy (the server name in each Client Hello). |

What to look for, in the reference run:

- **IMS AKA** (frames 198 to 309): the unprotected REGISTER to the P-CSCF's port 5060 with Security-Client (198);
  the P-CSCF passes it to the SIP core (217), which answers 401 (245). The P-CSCF's 401 to the client (251) carries
  the AKAv2-SHA-256 and AKAv1-MD5 challenges and Security-Server. Then come the first ESP packets (253), the
  protected REGISTER inside ESP with Security-Verify and the AKA response (258), and its 200 (274). The client's
  SUBSCRIBE to its reg event follows (277), with its 200 (298) and the first NOTIFY (307).
- **Sign-in** (frames 203 to 295, in parallel): TLS connections to the IdMS (Client Hellos 203, 228, 249, 295, server
  name `idms`): the authentication request, the HTML form, the code and the tokens.
- **The KMS** (frames 327 and 350, server name `kms`): KMS Initialize and KeyProvision, signed, the key set wrapped.
- **Through the HTTP proxy** (frames 827 to 2608, server name `http-proxy`): inside each tunnel, a second TLS session
  with the CMS or the GMS.
- **Configuration** (inside ESP): the SUBSCRIBE for the three configuration documents (883), its 200 (940) and NOTIFY
  (1012); the service authorisation PUBLISHes with the access token to the MCPTT server (1676, 200 at 1691) and the
  MCData server (1698, 200 at 1823); the SUBSCRIBE to the group document of `operations` (1703, 200 at 2004, NOTIFY
  at 2598) and to its GKTP document (2020, 200 at 2360, NOTIFY at 2830). The location reporting configuration
  MESSAGEs of the MCPTT and MCData servers come at 1760 and 1889.
- **After the test**: the affiliation (PUBLISH presence, 1900 and 2961), the refused location reports (3338 and 3372,
  403 at 3369 and 3400).
- **MC log-off and SIP de-REGISTER** (frames 4416 to 4504): the SUBSCRIBEs with Expires 0 (4416 to 4420), the
  PUBLISHes with Expires 0 for MCData (4422) and MCPTT (4424), answered 200 (4482, 4484); then the REGISTER with
  Expires 0 (4488) and its 200 (4497).

The `.esp_sa` file holds the IPsec keys of the MC client. The access tokens of the IdMS travel in SIP for service
authorisation. They all belong to a throwaway system: its signing keys and users no longer exist, and the tokens
expired after an hour. Treat a capture of your own system and its ESP keys as secret.

## 5. Stop or start over

```bash
docker compose down -v      # stop and delete the data
rm -rf config               # then start over at step 1
```

`docker compose down` (without `-v`) keeps the data: `MCX_LOG=debug docker compose up -d --wait` starts the same
system again, and `client-d` signs in and registers again.

## How it is put together

- **One compose file**, `docker-compose.yaml`, made by `tools/tutorial-compose.py` from a lab of the generator, like the
  [unit-test tutorials](../../README.md#unit-test-tutorials): published image names, `./config` from the setup, a
  fixed address per service, and a capture service (`tcpdump` on the bridge).
- **IMS AKA** (TS 33.203; TS 33.180 clause 6.2.1):
  - The SIP core chooses the scheme by the private user identity, as an HSS stores it (TS 29.228 clause 6.3.1 step 4):
    `client-d@mcx.test` has an IMS AKA subscription (K, OPc, AMF) in the SIP database; every other identity has a
    digest password.
  - The SIP core makes the authentication vectors itself (Kamailio `ims_auth`, MILENAGE, no HSS).
  - The P-CSCF (`pcscf`, at `.60`) is the SIP core's Kamailio image with `docker/pcscf.cfg`, with `NET_ADMIN` for its
    security associations. Before passing a request on to the SIP core, it removes the sec-agree option tag, and
    Security-Verify from the requests after the registration (TS 24.229 annex A, RFC 3329 section 2.3.1: they are for
    the first hop).
  - `client-d` reaches the P-CSCF at a configured address (TS 24.229 clause 9.2.1 allows that instead of discovery),
    with `NET_ADMIN` for its security associations. SIP runs over TCP inside them.
  - Its IMS AKA credentials are held in software: on a terminal without 3GPP access these are the IM credentials of
    TS 33.203 clause 9 ([Known limitations](../../../docs/LIMITATIONS.md), "SIP core access").
- **Keys** (TS 33.180 clause 5.3): the KMS has a TrK and an InK for `client-d`'s MCPTT user; the client signs its KMS
  requests with the InK, verifies the KMS's signed answers and unwraps the key set with the TrK
  (`security.transport_keys` in `config/client-d.json`). Its MCData user has no TrK or InK. The
  details the texts leave open are listed in [Known limitations](../../../docs/LIMITATIONS.md), "KMS request security
  (TrK/InK)" and "MIKEY-SAKKE UID form".
- **The home HTTP proxy** (TS 24.482 annex A): the CMS, the GMS and the MCData content server, message store and
  notification server are named by their own URIs (`https://cms:8443/xcap-root`, ...); the requests go through a TLS
  tunnel to the proxy in absolute-form, and the proxy passes each on by its authority. The tunnel is authenticated one
  way. Mutual tunnel authentication is not implemented, and the KMS requests go directly (the Linux client's
  `security.kms_via_proxy`, off by default, sends them through the proxy; [Known
  limitations](../../../docs/LIMITATIONS.md), "Home HTTP proxy").
