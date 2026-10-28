# Tutorial 3: MCX over the OAI 5G core and RAN (rfsim), with MCPTT QoS over N5

Tutorial 1's system and phones, plus a 5G network: the OAI 5G core, the OAI gNB and one nr-UE connected by the
rfsimulator (a simulated radio, no radio hardware). The dispatcher position runs inside the nr-UE, so all its traffic
crosses the 5G radio and core. When it calls, the MCPTT server asks the 5G core, over **N5**, for the QoS of
mission-critical voice: the core sets up a dedicated QoS flow (**5QI 65**) for the dispatcher's speech. A second MC
client in the nr-UE, the Linux client of the test user `client-d`, registers with **IMS AKA** through a P-CSCF, over
IPsec, and walks through test 5.1 of TS 37.579-2 at each start ([Walk-through of TS 37.579-2 test
5.1](#walk-through-of-ts-37579-2-test-51)).

<p align="center"><img src="images/architecture.svg" width="900" alt="Tutorial 3: the phones reach the OpenMCX system over the Wi-Fi; the dispatcher runs inside the nr-UE and reaches it over the rfsim radio, the gNB, the UPF (N3, N6) of the OAI 5G core; the MCPTT server asks the PCF for MCPTT QoS over N5"></p>

The phones reach the system on the Wi-Fi as in tutorial 1; their calls get no 5G QoS (they are not on 5G). The MCPTT
server asks for QoS only for call legs of UEs in the 5G pool (12.1.1.0/24).

The 5G addresses: the 5G core's functions (AMF, SMF, PCF, ...) and the gNB run on `192.168.71.128/26`; the data
network (N6) is `192.168.72.128/26`, with the UPF's N6 address `192.168.72.134` and the OpenMCX servers; the UE gets
its address from the pool `12.1.1.0/24` (the dispatcher's UE: `12.1.1.2`).

## What you need

- **Tutorial 1 done once**: the phones have the app, and you know the steps in MCX Admin. Tutorial 1's system must be
  **stopped**: tutorial 3 runs its own system with the same ports.
- **A Linux computer** with Docker and Docker Compose v2 (2.24 or later), about 8 CPU cores free (the rfsimulator's gNB
  and UE keep several cores busy) and **sudo** (step 3).
- **The OAI 5G core and RAN images**, from Docker Hub: OAI's own, and its AMF, PCF, SMF and UPF v2.2.1 with changes
  for N5 (`openmcx/oai-{amf,pcf,smf,upf}:mcx-n5`): the PCF turns an AF's media components into a PCC rule with 5QI 65,
  the SMF modifies the PDU session for it (a new QoS flow), and the UPF keeps the flow's packet rules. When the RAN
  cannot set the flow up, the AMF passes its answer on, the SMF removes the flow and reports the rule to the PCF, and
  the PCF tells the MCPTT server; the call goes on without the dedicated flow. The patches and the script that builds
  these images yourself are in [`oai/cn5g/`](oai/cn5g/README.md).

  The OAI 5G core is under the Collaborative Standards Software License v1.0: its patent license covers study,
  testing and research only ([`oai/cn5g/NOTICE`](oai/cn5g/NOTICE)).
- **Two Android phones** on the same Wi-Fi as in tutorial 1, with the OpenMCX app from the `develop` build
  ([`android/apk/openmcx-client-develop.apk`](https://github.com/openMCX/openmcx-client/tree/main/android/apk)): the
  servers of the `develop` images check the scopes of the access token, which the app of release 1.0.0 does not ask for.
- **IPsec in the kernel** for IMS AKA: the modules `xfrm_user`, `esp4`, `authenc` and `gcm` (step 3 loads them; `gcm` for AES-GCM and AES-GMAC), with the
  HMAC-SHA-1 and AES-CBC algorithms, as in the kernels of the common Linux distributions.
- Nothing to compile: the tutorial uses **prebuilt images from Docker Hub**, OpenMCX's `develop` images
  (`openmcx/openmcx-*:develop`, the main branch: IMS AKA needs a version after 1.0.0) and OAI's. To build the OpenMCX
  images yourself, see [tutorial 1's Images](../01-mcx-over-wlan-android/README.md#images) and [Building
  OpenMCX](../../../docs/BUILD.md); for the three OAI images, [`oai/cn5g/`](oai/cn5g/README.md).

## 1. Set the computer's address

```bash
cd tutorials/end-to-end/03-mcx-over-oai-5g
cp .env.example .env
```

Set `HOST_IP` in `.env` to this computer's address on the Wi-Fi, as in tutorial 1.

## 2. Make the configuration

```bash
docker compose -f docker-compose-5g-mcx.yaml run --rm setup
```

As in tutorial 1 (a new system in `./config`), plus the MCPTT server's N5 settings: the PCF's address on the 5G core
network and the UE pool 12.1.1.0/24, and a location reporting configuration in the MCPTT, MCVideo and MCData servers,
which they send each client in a SIP MESSAGE once it is authorised. The test user `client-d` is provisioned for IMS
AKA: a software ISIM with keys of its own (K, OPc) and the private user identity `client-d@mcx.test`, in its MC
client's configuration (`config/ue-client.json`) and in the SIP database, and the P-CSCF's configuration
(`config/pcscf.cfg`); the SIP core is then the S-CSCF of that identity. Every other user keeps SIP digest over TLS.

## 3. Connect this computer to the UE pool

```bash
sudo ./host-network.sh add
```

The dispatcher reaches the system at `HOST_IP`, as the phones do. Two settings of this computer complete the path:

- **A route** to the UE pool `12.1.1.0/24` through the UPF's N6 address `192.168.72.134`: replies to the UE go back
  through the UPF.
- **SNAT** for packets from the N6 network `192.168.72.128/26` to the UE pool: they leave from `HOST_IP`, so the UE
  sees one address both ways and the 5G core's packet filters (`permit out 17 from HOST_IP ...`) match the speech.

The P-CSCF (`192.168.72.140`, on the N6 network) is left out of the SNAT: it reaches the UE through the UPF itself,
with its own address, which its IPsec security associations with the UE are bound to. The script also loads the
kernel's IPsec modules (`xfrm_user`, `esp4`, `authenc`, `gcm`) if they are not loaded yet.

The addresses are fixed in `host-network.sh` and match the 5G core's configuration (`oai/mcx_core_config.yaml`,
the networks in `docker-compose-5g-core.yaml`): change them only together. `sudo ./host-network.sh remove` undoes the
route and the NAT rules (step 9).

## 4. Start the system

```bash
docker compose -f docker-compose-5g-mcx.yaml up -d
docker compose -f docker-compose-5g-mcx.yaml ps --format 'table {{.Name}}\t{{.Status}}'
```

After about two minutes all 33 services are `(healthy)`: the OpenMCX system, the P-CSCF (`pcscf` and `pcscf-route`),
the 5G core, the gNB, the nr-UE, `ue-route`, the dispatcher and the MC client of `client-d` (`ue-client`), which is
healthy once it has signed in, registered with IMS AKA and been authorised. `openmcx-ue-route` shows the UE's address:

```bash
docker logs openmcx-ue-route        # UE address 12.1.1.2, HOST_IP and the P-CSCF 192.168.72.140 through oaitun_ue1
```

## 5. Users and phones

As in tutorial 1, steps 4 to 6: in MCX Admin (`https://HOST_IP:8446/`; sign in as `admin` with the password from
`config/ADMIN.txt`) create `alice` and `bob` with the template
`phone-user` and the group `operations`, set their passwords and activate the phones. Also create `dispatcher` the same
way, and set its password.

- **Passwords**: use **Password link** on that user's own row; the box that opens says *Password link for alice*. The
  page that sets the password does not name the user.
- **Phones activated on another system** (tutorial 1, for example) keep that account: remove it in the app first, then
  scan the new user's QR code, and check that the code is for that user.

## 6. Activate the dispatcher (over 5G)

Open **http://localhost:8080/** on this computer: the dispatcher position, inside the nr-UE. In MCX Admin, issue an
activation link for `dispatcher` (Activation → Issue link → Copy link), and on the position choose **Activate an
account on this position**, paste the link and enter the password. The activation, the sign-in, the SIP registration
and every call of the position go through the 5G user plane.

## 7. Call, and see the QoS

1. On the position, choose **Group call**: Alice's and Bob's phones join.
2. Hold **PTT** on the position: it has the floor, and the phones show `Dispatcher is talking` with **Floor busy** on
   their PTT button.

<p align="center"><img src="images/call-floor-5g.png" width="100%" alt="Left, the dispatcher position over 5G: registered and affiliated, group call to operations active, floor HasPermission, PTT button Talking, release to stop. Middle and right, Alice's and Bob's phones in the group call operations: Dispatcher is talking, wait for the floor to be free, PTT Floor busy"></p>

3. While the call is up, the MCPTT server has an app session with the PCF for the dispatcher's leg, and the SMF has
   added a QoS flow to its PDU session:

   ```bash
   docker logs openmcx-mcptt-server 2>&1 | grep pcf_app_session
   docker logs openmcx-oai-pcf 2>&1 | grep -o '"flowDescription":"[^"]*"' | sort -u
   docker logs openmcx-oai-pcf 2>&1 | grep -o '"5qi":65'
   docker logs openmcx-oai-smf 2>&1 | grep -E 'PCF-initiated PDU|Add QoS flow|QoS Flow to Release'
   ```

   ```
   {"app_session_id":"1",...,"event":"pcf_app_session_created","status":201,"user_id":"sip:dispatcher.mcptt@mcx.test"}
   "flowDescription":"permit out 17 from HOST_IP 4000 to 12.1.1.2 4400"              speech (RTP)
   "flowDescription":"permit out 17 from HOST_IP 4001 to 12.1.1.2 4401"              RTCP
   "flowDescription":"permit out 17 from HOST_IP 5000 to 12.1.1.2 5400"              floor control
   "5qi":65                                                                          GBR 41 kbit/s, may pre-empt
   [smf_app] [info] PCF-initiated PDU Session Modification: 1 QoS flow(s) to add     the new QoS flow
   [smf_app] [info] Add QoS flow QFI 2 (PCC rule mcx-1-1, precedence 10): permit out 17 from HOST_IP 4000 to 12.1.1.2 4400 ...
   ```

   The QFI (QoS Flow Identifier) numbers a QoS flow within the UE's PDU session; the 5QI describes the flow's QoS
   (TS 23.501 clause 5.7.1). QFI 1 is the session's default flow, with 5QI 69 (MC signalling) for the DNN `mcptt`.
   The speech flow the PCF asks for is a second flow, so the SMF gives it the next QFI, 2, with 5QI 65. When the call
   ends, the MCPTT server deletes the app session (`pcf_app_session_deleted`, 204) and the SMF releases the flow; the
   next call's flow may get another free QFI (3, ...).

## 8. Look at the capture

The reference capture [`captures/03-mcx-over-oai-5g-full.pcapng.gz`](captures/03-mcx-over-oai-5g-full.pcapng.gz)
(1.4 MB, 8 234 frames) records a run of steps 4 to 7: the system starting, the UE registering over the 5G core, the
MC client of `client-d` registering with IMS AKA through the P-CSCF, the phones and the dispatcher signing in, a group
call from the dispatcher with PTT, Bob talking back, the hang-up, and the phones' MC log-off. Wireshark opens the
compressed file directly. The frame numbers below are those of the reference.

It was captured on the two Docker networks, the 5G core's (`192.168.71.128/26`: N2, N3, N4, SBI and N5) and N6 with
the OpenMCX system (`192.168.72.128/26`), and reduced by port so that every TCP segment of a kept stream stays:

- NGAP and NAS-5GS (SCTP), PFCP, GTP-U (with IP fragments), the SBI of the core functions and N5 (HTTP/2 on 8080; the
  NRF's registrations and heartbeats are left out);
- SIP over TLS on 5061, **decrypted**: the file carries the TLS secrets of the SIP core (a pcapng decryption secrets
  block), so Wireshark shows the SIP messages without further setup;
- the IMS AKA client's SIP: unprotected on 5060 until the 401, then inside **IPsec ESP** between the UE and the P-CSCF;
- every UDP flow (speech and floor control) and ICMP.

The databases, DNS, the encrypted HTTPS between the OpenMCX services and the simulated radio between the gNB and the
UE (rfsimulator, TCP 4043) are left out.

To read the SIP inside ESP, give Wireshark the run's security associations: copy
[`captures/03-mcx-over-oai-5g-full.esp_sa`](captures/03-mcx-over-oai-5g-full.esp_sa) to `~/.config/wireshark/esp_sa`
(or import it in **Edit → Preferences → Protocols → ESP → ESP SAs**) and tick **Attempt to detect/decode encrypted ESP
payloads** there. They are the keys of this throwaway run (CK and IK of one AKA challenge); a run of your own has
others, in the client's debug log (lines `ESP SA`).

The UE's packets appear more than once: inside GTP-U on N3 between the gNB (`192.168.71.140`) and the UPF
(`192.168.71.134`), and on N6 after the UPF, once with `HOST_IP` (`192.168.179.39` in the reference) and once with
the address of the SIP core or the MCPTT server behind it; the P-CSCF (`192.168.72.140`) reaches the UE without NAT.
The UE's address is `12.1.1.2`; the phones are on the Wi-Fi (`192.168.179.40` Alice, `192.168.179.42` Bob). With
**Edit → Preferences → Protocols → GTP** off (`--disable-protocol gtp`), only the N6 copies are read as TCP.

Useful display filters:

| Filter | Shows |
|---|---|
| `ngap` | N2 between the gNB and the AMF: NG Setup, the UE's registration and PDU session, and the PDU Session Resource Modify for the call's QoS flow. |
| `nas-5gs` | The UE's NAS: registration, authentication, security mode, PDU session establishment and modification. |
| `pfcp && !(pfcp.msg_type == 1 \|\| pfcp.msg_type == 2)` | N4 between the SMF and the UPF, without the heartbeats. |
| `http2.headers.path contains "policyauthorization"` | N5: the MCPTT server's app session at the PCF (TS 29.514), and its deletion. |
| `http2.headers.path contains "sm-policy" \|\| http2.headers.path contains "smpolicycontrol"` | N7: the PCF's policy for the PDU session and its update for the call. |
| `sip && ip.addr == 192.168.72.140 && tcp.port == 5060` | IMS AKA: the unprotected REGISTER with Security-Client and the 401 with the AKA challenge and Security-Server. |
| `esp && sip` | The IMS AKA client's SIP inside ESP (with the ESP SAs above): the protected REGISTER, PUBLISH, SUBSCRIBE, NOTIFY, MESSAGE. |
| `sip && !gtp` | Every SIP message (once; without the GTP-U copies). **Telephony → SIP Flows** draws them. |
| `rtcp.app.name == "MCPT" && !gtp` | Floor control (TS 24.380 clause 8.2). |
| `rtp && !gtp` | Speech: AMR-WB. |

What to look for, in the reference run (frame numbers with GTP off):

- **The 5G core and the UE** (frames 3 to 323): PFCP Association between the SMF and the UPF (3), NG Setup (9), the
  UE's Registration request (13) with 5G-AKA through the AUSF, UDM and UDR, Security mode command (170), and the PDU
  session establishment accept for the DNN `mcptt` (323). The session's default QoS flow is QFI 1, 5QI 69 (MC
  signalling).
- **IMS AKA of `client-d`** (frames 523 to 937): the unprotected REGISTER to the P-CSCF's port 5060 with
  Security-Client (523); the 401 with an AKAv2-SHA-256 and an AKAv1-MD5 challenge and Security-Server (604); the first
  ESP packets (611); the protected REGISTER inside ESP with Security-Verify and the AKA response (623) and its 200
  (631); then the service authorisation PUBLISH (937) and the subscriptions, all inside ESP.
- **Sign-in and registration with SIP digest** (frames 1751 to 3194): Alice's phone (1751), the dispatcher over 5G
  (2267) and Bob's phone (3194) register with the SIP core: REGISTER, the challenge, REGISTER again.
- **The group call** (frames 3360 to 3449): the dispatcher's INVITE (3360) and the `407` challenge (3365); the MCPTT
  server invites the members, among them `client-d` through the P-CSCF, inside ESP (3405, answered `200` at 3415),
  and answers the dispatcher with `200` (3449).
- **QoS over N5** (frames 3439 to 3507): the MCPTT server, as application function, asks the PCF for the dispatcher's
  media (3439: `POST /npcf-policyauthorization/v1/app-sessions` with the media components, speech, RTCP and floor
  control, TS 29.514). The PCF turns them into a PCC rule with 5QI 65 and updates the SMF; the SMF adds a QoS flow to
  the PDU session (3507: PDU Session Resource Modify Request with 5QI 65 and a guaranteed bit rate).
- **Floor control and speech** (frames 3859 to 7806): the dispatcher's Floor Request (3859), its speech, then Bob's
  turn, up to the last Floor Release (7806). Downlink, the speech and floor control the UPF sends the gNB for the
  dispatcher carry the call's QFI in their GTP-U header (filter `gtp.ext_hdr.pdu_ses_con.qos_flow_id`).
- **Hang-up** (from frame 7875): the dispatcher's BYE (7875); the MCPTT server deletes the app session (7889: `POST
  .../app-sessions/2/delete`), and the SMF releases the QoS flow (7983: PDU Session Resource Modify Request, cause
  normal release; the gNB's response 7996).
- **MC log-off of the phones** (frames 8114 to 8207): Alice's phone logs off from MCVideo, MCData and MCPTT with a
  PUBLISH with Expires 0 each (8114, 8121, 8127; TS 24.379 clause 7.2.1A NOTE 3, TS 24.281 and TS 24.282 alike), and
  Bob's phone does the same (8197 to 8207). After the MC log-off, each phone sends a SIP de-REGISTER, a REGISTER with
  Expires 0 (TS 24.229 clause 5.1.1.6): Alice's 8133, passed on to the three servers 8135 to 8142, and Bob's 8213.

The access tokens of the IdMS travel in SIP for service authorisation, and the file holds the SIP core's TLS secrets
(and the `.esp_sa` file the IPsec keys of `client-d`). They belong to a throwaway system: its signing key and users no
longer exist and the tokens expired after an hour. Treat a capture of your own system, its TLS secrets and its ESP
keys, as secret.

## 9. Stop or start over

```bash
docker compose -f docker-compose-5g-mcx.yaml down        # stop; ./config is kept
docker compose -f docker-compose-5g-mcx.yaml down -v     # stop and delete the data
sudo ./host-network.sh remove
rm -rf config                                            # with down -v: start over at step 2
```

After `down`, `docker compose -f docker-compose-5g-mcx.yaml up -d` starts the same system again, users and phones
included; then run `sudo ./host-network.sh add` again (step 3): its route goes with the network `down` removes.

## Walk-through of TS 37.579-2 test 5.1

Test 5.1 of TS 37.579-2 V18.1.0 ("Configuration / Authentication / User Authorisation / UE Configuration / User
Profile / Key Generation", table 5.1.3.2-1) checks what an MC client does from switch-on to service: the 5GS
registration of the UE, the MC user's sign-in, the SIP registration with IMS AKA, the service authorisation and the
configuration and group management subscriptions, with the procedures of TS 37.579-1 V18.1.0. Here it is a
walk-through, not a conformance test: there is no TTCN-3 test suite (TS 37.579-5), no validated system simulator and
no radio. The OAI 5G core and RAN and the OpenMCX system take the system simulator's place; the implementation under
test is the MC client of `client-d` in the nr-UE (`openmcx-ue-client`).

It runs by itself at every start of the system (step 4): the client is preconfigured with the initial UE
configuration (table 5.3.2.3.1-1 step 1a, the data of table 5.5.8.1-1: the IdMS's endpoints, the HTTP proxy, the
P-CSCF, the identities) and with the user name and password (NOTE 1 of that table: stored on the UE). Nothing to do
in MCX Admin. To see every step, switch the debug log on before the start (`MCX_LOG=debug` in `.env`, then
`docker compose -f docker-compose-5g-mcx.yaml up -d`): the SIP messages and the HTTP requests are then in the logs. The
debug log of `openmcx-ue-client` also holds the keys of its IPsec security associations (lines `ESP SA`), so that
Wireshark can decrypt its SIP: treat it as secret. To run the test again, stop the system and start it again (step 9,
`down` without `-v`, `sudo ./host-network.sh add`, `up -d`).

The client is healthy when it is authorised:

```bash
docker compose -f docker-compose-5g-mcx.yaml ps ue-client     # (healthy)
docker logs openmcx-ue-client 2>&1 | grep -E '"event":"(sip_registered|oidc_authenticated|signed_in|service_authorized|configuration_subscribed|group_documents_subscribed|group_document_notified|location_configuration_received)"'
python3 -c 'import json; print(json.dumps(json.load(open("config/artifacts/client-d/status.json"))["sip_security"], indent=1))'
```

The last command shows the security associations in use (TS 33.203 clause 7.1, the SA_table): `ims-aka`,
`ipsec-3gpp`, `hmac-sha-1-96` and `aes-cbc`, the SPIs and protected ports of the UE (`spi_uc`, `spi_us`, `port_uc`,
`port_us` 5064) and of the P-CSCF (`port_pc` and `port_ps`, from 5100 and 6100), and the public user identity of the
200 (OK)'s P-Associated-URI. Step by step:

| 5.1 step | TS 37.579-1 | What the client does | Where to see it | Normative clauses |
|---|---|---|---|---|
| 1 | 5.4.2.3, 5.4.1B | The nr-UE registers with the 5GS (5G AKA, NAS security) and sets up the MCX PDU session on the DNN `mcptt`, whose default QoS flow has 5QI 69. | `docker logs openmcx-ue-route` (the UE's address); in a capture `nas-5gs` and `ngap.fiveQI == 69` (step 8, frames 13 to 323 of the reference). | TS 24.501, TS 23.501 table 5.7.4-1 |
| in parallel to 3-16 | table 5.3.2.4.1-1, path 3b1 | Initial REGISTER, unprotected, to the P-CSCF's port 5060 with Security-Client (`ipsec-3gpp`, `hmac-sha-1-96`, `aes-cbc`, its SPIs and ports) and sec-agree in Require and Proxy-Require; the 401 (Unauthorized) of the SIP core with an AKAv2-SHA-256 and an AKAv1-MD5 challenge, through the P-CSCF, which adds Security-Server and removes the ck and ik meant for it; the client checks AUTN (MAC, SQN), computes RES, CK and IK and sets up the temporary security associations; the protected REGISTER from port_uc to port_ps, with Security-Verify and the AKA response; the 200 (OK). The REGISTER does not wait for the access token, which goes in the PUBLISH (step 17). | `docker logs openmcx-ue-client 2>&1 \| grep -E 'SIP (->\|<-) .*REGISTER\|ESP SA'`; in a capture the first REGISTER and the 401 are readable on N6 (`tcp.port == 5060`), the rest is ESP (`esp`): Wireshark decrypts it with the keys of the `ESP SA` lines (Protocols, ESP, ESP SAs). | TS 24.229 clauses 5.1.1.2, 5.1.1.5, 5.2.2; TS 33.203 clauses 6.1, 7; TS 33.180 clauses 5.1.3.2.1, 6.2.1 |
| 3-12 | table 5.3.2.3.1-1 steps 1-10 | Preconfigured initial UE configuration (step 1a); the OIDC authentication request to the IdMS; the HTML form with the fields `user` and `password` (table 5.3.2.3.2-5); the form posted to the IdMS's `/userauth`; the 302 (Found) with the authorization code; the token request; the ID, access and refresh tokens. | `docker logs openmcx-idms 2>&1 \| grep -E 'HTTP (GET\|POST) /(authorize\|userauth\|token)'`; the client's `oidc_authenticated` | TS 24.482 clause 6.2.1; TS 33.180 clause 5.1.2, annex B |
| 13-16 | table 5.3.2.3.1-1 steps 11-14 | The KMS Initialize and KeyProvision requests with the access token, through the HTTP proxy, and the KMS's answers with the key material. The client provisions its keys at sign-in although the group `operations` is not protected (`security.kms_uri`, set by `setup/ue-client.py`); it makes no CSK then. | `docker logs openmcx-kms 2>&1 \| grep -E 'init\|keyprov'`; `key_management` in `config/artifacts/client-d/status.json` | TS 33.180 clause 5.3.3, annex D |
| 17 | table 5.3.2.5.1-1, path 1b1 | PUBLISH to the MCPTT server with the access token (service authorisation) and the PoC settings with the user profile index; 200 (OK). | `docker logs openmcx-ue-client 2>&1 \| grep -E 'SIP (->\|<-) .*PUBLISH'`; `service_authorized` | TS 24.379 clause 7.2.1; TS 33.180 clause 5.1.3.2.3 |
| 18 | table 5.3.2.6.1-1 | One SUBSCRIBE with the access token and a resource list of the MCPTT UE configuration, user profile and service configuration documents; the NOTIFY with their XCAP URIs; the GETs of the documents, only after the NOTIFY (`mcptt.documents_on_notify`, set by `setup/ue-client.py`). | `configuration_subscribed` (the three documents), `document_retrieved` | TS 24.484 clauses 6.3.13.3.2.2, 8.2 |
| 19 | table 5.3.2.7.1-1, path 1b1 | SUBSCRIBE to the group document of `operations`; NOTIFY; the GET of the document after the NOTIFY. The GKTP subscription for the GMK (optional, table 5.3.2.7.1-2) is not made: the group is not protected. | `group_documents_subscribed`, `group_document_notified`, `document_retrieved` | TS 24.481 clause 6.3.13.2.1 |
| (main procedure 6-7) | table 5.3.2.2.1-1 | The MCPTT, MCVideo and MCData servers' MESSAGE configuring location reporting (configured in step 2); the client's 200 (OK). | `location_configuration_received` | TS 24.379 clause 13.2.2 |

Where the walk-through departs from the test:

- **The challenge**: the SIP core offers AKAv2-SHA-256 before AKAv1-MD5 (TS 33.203 clause 6.1.1) and the client
  answers the first; the 401 of TS 37.579-1 table 5.3.2.4.1-1 carries AKAv1-MD5, which the client also supports.
- **The radio**: the rfsimulator carries the 5QI of the QoS flows in NGAP and NAS but does not enforce it.

## How it is put together

- **Three compose files**: `docker-compose-5g-core.yaml` has tutorial 1's OpenMCX services, unchanged, on the 5G core's
  **N6 network** (`openmcx-5g-n6`, 192.168.72.128/26) and the OAI 5G core on the **core network** (`openmcx-5g-core`,
  192.168.71.128/26); [tutorial 4](../04-mcx-over-srsran-5g/README.md) uses it too. `docker-compose-5g-mcx.yaml`
  includes it, with tutorial 3's change to its setup (`docker-compose-5g-core-aka.yaml`: the IMS AKA user), and adds the
  gNB and the nr-UE (IMSI 208990100001100, DNN `mcptt`), the dispatcher and the MC client of `client-d` in the nr-UE's
  network namespace, `ue-route`, which routes `HOST_IP` and the P-CSCF through the UE's tunnel (`oaitun_ue1`) once its
  PDU session is up, and the P-CSCF. The OAI configuration is in `oai/`, the N5 patches of the AMF, PCF, SMF and UPF in
  `oai/cn5g/`.
- **N5**: the MCPTT server is also on the core network (192.168.71.141). With the `pcf` block that the setup adds
  (`setup/pcf.py`), it creates an `Npcf_PolicyAuthorization` app session (TS 29.514) for each call leg of a UE in
  12.1.1.0/24: the leg's speech, RTCP and floor control flows, its bandwidth and priority. The PCF makes a PCC rule
  (5QI 65), the SMF a QoS flow on the UE's PDU session (TS 23.502 4.3.3.2), the UPF its packet rules. Without the
  `pcf` block, as in tutorials 1 and 2, the server never contacts a PCF.
- **The MCX PDU session**: the nr-UE sets up one PDU session, on the DNN `mcptt`, right after its registration; all
  the dispatcher's traffic (SIP, HTTP, speech and floor control) uses it. Its default QoS flow has 5QI 69 (MC
  signalling, TS 23.501 table 5.7.4-1), the MCX PDU session of TS 37.579-1 clause 5.4.1B: from the subscription
  in the UDR (`oai/oai_db.sql`) and the PCF's policy for the DNN (`oai/policies/`), whose match-all PCC rule becomes
  the default QoS rule with precedence 255 (TS 24.501 clause 6.2.5.1.1.2). The calls' QoS flows (5QI 65) are added
  to this session. There is no internet or IMS PDU session: the dispatcher and the MC client of `client-d` need
  neither.
- **Location**: the setup adds (`setup/location.py`) the location reporting configuration of TS 37.579-1 tables
  5.5.3.4.2-1 to 5.5.3.4.2-3 to the MCPTT, MCVideo and MCData servers: upon service authorisation each sends the
  client a SIP MESSAGE (TS 24.379 clause 13.2.2) asking for the serving and neighbouring cells, the MBMS and MBSFN
  areas and the coordinates, at most every 10 s (5 s in an emergency), with no triggering criteria. The phones and
  the dispatcher answer `200` and send no report on their own.
- **IMS AKA** (TS 33.203; TS 33.180 clause 6.2.1 for 3GPP access): the SIP core chooses the scheme by the private
  user identity, as an HSS stores it (TS 29.228 clause 6.3.1 step 4): `client-d@mcx.test` has an IMS AKA
  subscription (K, OPc, AMF) in the SIP database, every other identity a digest password. The SIP core makes the
  authentication vectors itself (Kamailio `ims_auth`, MILENAGE, no HSS). The P-CSCF (`pcscf`, the SIP core's Kamailio
  image with `docker/pcscf.cfg`) is on the N6 network at 192.168.72.140, where the UE reaches it through the UPF without
  NAT: ESP cannot cross Docker's port publishing. It has `NET_ADMIN` for its security associations, and `pcscf-route`
  gives it the route to the UE pool through the UPF. The MC client (`ue-client`, `setup/ue-client.py`) is the Linux
  client in the nr-UE's network namespace, with `NET_ADMIN` for its security associations there; it reaches the
  P-CSCF at a configured address (TS 24.229 clause 9.2.1 allows that instead of discovery) and the IdMS, HTTP proxy
  and KMS at `HOST_IP`. SIP runs over TCP inside the security associations; the P-CSCF reaches the SIP core over TLS
  with its own certificate, and checks the SDP addresses of its UEs as the SIP core does those of the other clients.
- **The dispatcher** is the image and settings of tutorial 2, with its address the UE's. The UE's address can change
  when the UE or the core restarts; the dispatcher then updates its activated accounts at start.
- **Routing**: the UPF sends a UE's packets for `HOST_IP` out of the core network (its default route), so they reach
  this computer from another Docker network than the OpenMCX system's and Docker's NAT keeps the UE's address (the
  SIP core checks that the SDP address is the sender's). The replies come back through `host-network.sh`'s route and
  leave from `HOST_IP`.
- **The phones** are not on 5G: their legs are outside the UE pool and get no app session.
