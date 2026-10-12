# Tutorial 5: MCX over a 4G core (Open5GS EPC) and the OAI LTE RAN (rfsim), with MCPTT QoS over Rx

Tutorial 3, on 4G instead of 5G: tutorial 1's system and phones, plus an LTE network made of the Open5GS 4G core
(EPC) and the OAI eNB and one LTE UE connected by the rfsimulator (a simulated radio, no radio hardware). The
dispatcher position runs inside the LTE UE, so all its traffic crosses the LTE radio and the EPC. When it calls, the
MCPTT server asks the EPC's PCRF, over **Rx** (TS 29.214, the MCPTT-5 reference point of TS 23.379), for the QoS of
mission-critical voice: the EPC sets up a **dedicated bearer with QCI 65** for the dispatcher's speech, down to the
radio.

<p align="center"><img src="images/architecture.svg" width="900" alt="Tutorial 5: the phones reach the OpenMCX system over the Wi-Fi; the dispatcher runs inside the OAI LTE UE and reaches it over the rfsim radio, the OAI eNB, the S-GW and P-GW (S1-U, SGi) of the Open5GS EPC; the MCPTT server asks the PCRF for MCPTT QoS over Rx, and the PCRF installs a QCI 65 rule over Gx"></p>

The phones reach the system on the Wi-Fi as in tutorial 1; their calls get no 4G QoS (they are not on 4G). The MCPTT
server asks for QoS only for call legs of UEs in the LTE pool (10.45.0.0/16): a UE on another access, such as the
phones on WLAN, gets no request and its calls work as before (TS 24.379 clause 4.13).

## What you need

- **Tutorial 1 done once**: the phones have the app, and you know the steps in MCX Admin. Tutorial 1's system (and
  tutorials 3 and 4) must be **stopped**: tutorial 5 runs its own system with the same ports.
- **A Linux computer** with Docker and Docker Compose v2, about 8 CPU cores free (the rfsimulator's eNB and UE keep
  several cores busy) and **sudo** (step 3).
- **The images**, from Docker Hub: OpenMCX's (`openmcx/openmcx-*:1.0.0`, as in tutorial 1, with Rx) and three patched
  images:
  - `openmcx/open5gs:2.8.0-mcx`: Open5GS v2.8.0 for every EPC function, with a PCRF change: an MCPTT AF session's
    audio gets QCI 65 (and an MCVideo session's video QCI 67), as TS 23.379 clause 5.7.3 asks, instead of the QCI 1
    of IMS voice. The patch and the build are in [`open5gs/`](open5gs/NOTICE). Open5GS is under the GNU AGPL v3.
  - `openmcx/oai-enb:2026.w39-mcx` and `openmcx/oai-lte-ue:2026.w39-mcx`: OAI's eNB and LTE UE with fixes for
    dedicated bearers: the UE accepts every type of tracking area identity list, accepts a dedicated bearer that the
    network sets up with a new connection and one that the network releases (TS 24.301), and the eNB and the UE
    release the bearer's radio bearer (TS 36.331). The patches and the build are in [`oai/ran/`](oai/ran/NOTICE).
    OAI is under the Collaborative Standards Software License v1.0: its patent license covers study, testing and
    research only.

  To build the patched images yourself: `open5gs/build-images.sh` (about 10 minutes) and `oai/ran/build-images.sh`
  (about 40 minutes); then set `OPEN5GS_IMG=open5gs:2.8.0-mcx`, `ENB_IMG=oai-enb:2026.w39-mcx` and
  `UE_IMG=oai-lte-ue:2026.w39-mcx` in `.env`.

## 1. Set the computer's address

```bash
cd tutorials/end-to-end/05-mcx-over-4g-open5gs-oai
cp .env.example .env
```

Set `HOST_IP` in `.env` to this computer's address on the Wi-Fi, as in tutorial 1.

## 2. Make the configuration

```bash
docker compose -f docker-compose-4g-mcx.yaml run --rm setup
```

As in tutorial 1 (a new system in `./config`), plus the MCPTT server's Rx settings (the PCRF as a Diameter peer and
the LTE pool 10.45.0.0/16) and the EPC's Diameter certificates (`config/epc-tls`).

## 3. Connect this computer to the UE pool

```bash
sudo ./host-network.sh add
```

As in tutorial 3: replies to the UE pool go back through the P-GW's user plane (the UPF, at its SGi address), and
they leave from `HOST_IP`, so the UE sees one address both ways and the EPC's packet filters match the speech.
`sudo ./host-network.sh remove` undoes both (step 9).

## 4. Start the system

```bash
docker compose -f docker-compose-4g-mcx.yaml up -d
docker compose -f docker-compose-4g-mcx.yaml ps --format 'table {{.Name}}\t{{.Status}}'
```

After about two minutes every service is `(healthy)`: the OpenMCX system, the EPC (`epc-mme`, `epc-hss`,
`epc-sgwc`, `epc-sgwu`, `epc-smf`, `epc-upf`, `epc-pcrf`, `epc-mongo`; `epc-subscriber` loads the UE's subscription
and exits), the eNB, the LTE UE, `ue-route` and the dispatcher. `openmcx-ue-route` shows the UE's address:

```bash
docker logs openmcx-ue-route        # UE address 10.45.0.3, 192.168.179.39 through oaitun_ue1
```

If the UE has no address after two minutes (the rfsimulator's first random access sometimes fails), restart it:
`docker restart openmcx-oai-lte-ue`, then `docker compose -f docker-compose-4g-mcx.yaml up -d --force-recreate
ue-route dispatcher`.

## 5. Users and phones, 6. Activate the dispatcher (over 4G)

As in tutorial 3, steps 5 and 6: in MCX Admin (`https://HOST_IP:8446/`; sign in as `admin` with the password from
`config/ADMIN.txt`) create `alice`, `bob` and `dispatcher`,
activate the phones, and activate the dispatcher position at **http://localhost:8080/**. The position's activation,
sign-in, SIP registration and calls go through the LTE user plane.

## 7. Call, and see the QoS

1. On the position, choose **Group call**: Alice's and Bob's phones join.
2. Hold **PTT** on the position: it has the floor, and the phones show `Dispatcher is talking`.
3. While the call is up, the MCPTT server has an Rx session with the PCRF for the dispatcher's leg, and the EPC has
   set up a dedicated bearer for it:

   ```bash
   docker logs openmcx-mcptt-server 2>&1 | grep rx_session
   docker logs openmcx-epc-mme 2>&1 | grep 'Bearer added'
   docker logs openmcx-oai-enb 2>&1 | grep 'QCI 65'
   docker logs openmcx-oai-lte-ue 2>&1 | grep -i 'dedicated EPS bearer'
   ```

   ```
   {"dialog":"f9b98939-…","event":"rx_session_created",…,"status":2001,"user_id":"sip:dispatcher.mcptt@mcx.test"}
   10/05 19:06:30.706: [mme] INFO: Bearer added (EBI=6 IMSI=208960100000001) (../src/mme/mme-context.c:4683)
   1152522.369879 [RRC]    I EPS ID 6, DRB ID 2 (index 1), QCI 65, priority 4, LCID 4 LCGID 1
   … ESM-PROC  - Dedicated EPS bearer context activation requested by the network (ebi=6)
   … ESM-PROC  - Dedicated EPS bearer context activation accepted by the UE (ebi=6)
   ```

   The default bearer (EPS bearer 5, QCI 9) carries everything else of the UE, including SIP. The MCPTT server's
   AA-Request names the leg's speech, RTCP and floor control flows and the MCPTT service (its ICSI): the PCRF makes a
   PCC rule with QCI 65 and installs it at the P-GW over Gx; the P-GW and S-GW create the dedicated bearer (EPS bearer
   6), and the MME and the eNB set it up on the radio as a data radio bearer.
4. End the call on the position. The MCPTT server ends the Rx session, and the EPC releases the dedicated bearer, on
   the radio too; the next call sets it up again:

   ```bash
   docker logs openmcx-mcptt-server 2>&1 | grep rx_session_terminated     # "status":2001
   docker logs openmcx-epc-mme 2>&1 | grep 'Bearer removed'               # Bearer removed (EBI=6 ...)
   docker logs openmcx-oai-lte-ue 2>&1 | grep 'DRB 2 released'            # [RRC] I [UE 0] DRB 2 released
   ```

## 8. Look at the capture

The reference capture [`captures/05-mcx-over-4g-open5gs-oai-full.pcapng.gz`](captures/05-mcx-over-4g-open5gs-oai-full.pcapng.gz) (0.7 MB, 5 749
frames) records a run of steps 4 to 7: the
EPC and the eNB starting, the UE attaching, the phones and the dispatcher signing in, a group call from the
dispatcher with PTT, Bob talking back, and the hang-up. Wireshark opens the compressed file directly. The frame
numbers below are those of the reference.

It was captured on the two Docker networks, the EPC's (`192.168.73.128/26`: S1, S11, S5, Gx, Rx and S6a) and SGi
with the OpenMCX system (`192.168.74.128/26`), and reduced by port so that every TCP segment of a kept stream stays:

- S1AP and NAS-EPS (SCTP), GTPv2-C, PFCP (Open5GS splits the SGW and the PGW into control and user plane), GTP-U
  (with IP fragments) and Diameter (Rx, Gx and S6a);
- SIP over TLS on 5061, **decrypted**: the file carries the TLS secrets of the SIP core (a pcapng decryption secrets
  block), so Wireshark shows the SIP messages without further setup;
- every UDP flow (speech and floor control) and ICMP.

The databases, DNS, the encrypted HTTPS between the OpenMCX services and the simulated radio between the eNB and the
UE (rfsimulator, TCP 4043) are left out.

The dispatcher's packets appear more than once: inside GTP-U between the eNB (`192.168.73.140`), the SGW-U
(`192.168.73.132`) and the UPF (`192.168.73.134`), and on SGi after the UPF, once with `HOST_IP` (`192.168.90.88` in
the reference) and once with the address of the SIP core or the MCPTT server behind it. The UE's address is
`10.45.0.2`; the phones are on the Wi-Fi (`192.168.91.76` Alice, `192.168.88.177` Bob).

Useful display filters:

| Filter | Shows |
|---|---|
| `s1ap` | S1 between the eNB and the MME: S1 Setup, the attach, and the E-RAB Setup and Release of the call's dedicated bearer. |
| `nas-eps` | The UE's NAS: attach, authentication, security mode, and the dedicated EPS bearer context activation and deactivation. |
| `diameter.applicationId == 16777236` | Rx: the MCPTT server's AA-Request and Session-Termination-Request at the PCRF (TS 29.214). |
| `diameter.applicationId == 16777238` | Gx: the PCRF's Credit-Control and Re-Auth exchanges with the SMF (the PGW-C). |
| `gtpv2` | S11 and S5-C: Create Session, Modify Bearer, Create Bearer and Delete Bearer. |
| `sip && !gtp` | Every SIP message (once; without the GTP-U copies). **Telephony → SIP Flows** draws them. |
| `rtcp.app.name == "MCPT" && !gtp` | Floor control (TS 24.380 clause 8.2). |
| `rtp && !gtp` | Speech: AMR-WB. |

What to look for, in the reference run:

- **The EPC and the UE** (frames 11 to 201): PFCP Associations (11, 22), the Diameter Capabilities-Exchange with the
  PCRF (from the SMF, 23, and the MCPTT server, 94) and the HSS (from the MME, 73), S1 Setup (142), the UE's Attach
  request with its PDN connectivity request (167), authentication through the HSS (168), Security mode command (173),
  the default bearer for the subscription's APN `oai.ipv4`: Create Session through the SGW-C and the SMF (177, 180),
  the PCRF's Gx Credit-Control (181), and the Initial Context Setup with Attach accept (190).
- **Sign-in and registration** (frames 257 to 1797): Alice's and Bob's phones (257, 755) and the dispatcher over 4G
  (1797) register with the SIP core.
- **The group call** (frames 2427 to 2472): the dispatcher's INVITE (2427; after the `407` challenge 2455), forwarded
  to the MCPTT server (2460), which invites Alice (2468) and Bob (2472).
- **QoS over Rx** (frames 2521 to 2549): the MCPTT server, as application function, sends the dispatcher's media to
  the PCRF (2521: AA-Request with the media components and their flow descriptions, for example `permit out 17 from
  192.168.90.88 4000 to 10.45.0.2 4400`, TS 29.214). The PCRF installs a rule at the SMF over Gx (2526: Re-Auth
  Request), which creates a dedicated bearer: Create Bearer Request (2532, 2535), E-RAB Setup Request with Activate
  dedicated EPS bearer context request (2536: E-RAB 6, QCI 65, guaranteed bit rate 84 kbit/s each way), and the UE's
  accept (2540).
- **Floor control and speech** (frames 2664 to 5565): the dispatcher's Floor Request (2664) and Floor Granted (2665),
  Floor Taken to the phones (2667, 2669), the dispatcher's speech, Floor Release (4321); then Bob's turn (4365 to
  5565). Downlink, the speech and floor control for the dispatcher reach the eNB in the dedicated bearer's GTP-U
  tunnel (filter `gtp.teid == 0xa3ca1406`); the UE's uplink packets stay on the default bearer in the reference run.
- **Hang-up** (from frame 5628): the dispatcher's BYE (5628, again after the challenge 5640), the server's BYEs to
  Alice and Bob (5648, 5661). The MCPTT server ends the Rx session (5644: Session-Termination-Request), the PCRF removes
  the rule over Gx (5645), and the bearer goes: Delete Bearer Request (5657, 5658), E-RAB Release Command with
  Deactivate EPS bearer context request (5660), and its responses (5673, 5677).

The access tokens of the IdMS travel in SIP for service authorisation, and the file holds the SIP core's TLS secrets.
They belong to a throwaway system: its signing key and users no longer exist and the tokens expired after an hour.
Treat a capture of your own system, and its TLS secrets, as secret.

## 9. Stop or start over

```bash
docker compose -f docker-compose-4g-mcx.yaml down        # stop; ./config is kept
docker compose -f docker-compose-4g-mcx.yaml down -v     # stop and delete the data
sudo ./host-network.sh remove
rm -rf config                                            # with down -v: start over at step 2
```

## How it is put together

- **Two compose files**: `docker-compose-4g-core.yaml` has tutorial 1's OpenMCX services, unchanged, on the EPC's
  **SGi network** (`openmcx-4g-sgi`, 192.168.74.128/26) and the Open5GS EPC on the **EPC network** (`openmcx-4g-core`,
  192.168.73.128/26). `docker-compose-4g-mcx.yaml` includes it and adds the eNB and the LTE UE (OAI's CI USIM:
  IMSI 208960100000001, APN `oai.ipv4`), the dispatcher in the UE's network namespace and `ue-route`, which routes
  `HOST_IP` through the UE's tunnel (`oaitun_ue1`) once it is attached.
- **The EPC is Open5GS**, one container per function: HSS, MME, S-GW (SGW-C and SGW-U), P-GW (Open5GS's SMF as
  PGW-C and its UPF as PGW-U) and the **PCRF**, with MongoDB for the subscriber; the configuration is in
  `open5gs/config/` and `open5gs/freeDiameter/`, the subscription in `open5gs/subscriber.js`. OAI's own 4G EPC has no
  PCRF, and so no Rx. Open5GS names its P-GW parts after their 5G counterparts; here they play only their 4G roles
  (S5, Gx, SGi), and the SMF runs without a 5G service interface.
- **Rx**: the MCPTT server is also on the EPC network (192.168.73.141), a Diameter peer of the PCRF over TCP. With
  the `rx` block that the setup adds (`setup/rx.py`), it opens an Rx session (TS 29.214) for each call leg of a UE in
  10.45.0.0/16: the AF-Application-Identifier (the MCPTT ICSI), the leg's speech, RTCP and floor control flows, the
  bandwidth, and the call's priority (MCPTT-Identifier and Reservation-Priority from its Resource-Priority). Without
  the `rx` block, as in tutorials 1 to 4, the server never contacts a PCRF. See
  [QoS for call media](../../../docs/POLICY.md).
- **Packet filters**: the P-GW's packet filters for the UE leave out the UE's own address (`smf.yaml`,
  `no_ipv4v6_local_addr_in_packet_filter`): the "local address" components of TS 24.008 table 10.5.162 are used only
  when the UE supports them, and the OAI LTE UE does not.
- **The RAN** is OAI's eNB and LTE UE over the rfsimulator (band 7, 5 MHz), as in OAI's own `4g_rfsimulator_fdd_05MHz`
  test; their configuration is in `oai/ran/`.
- **The dispatcher** is the image and settings of tutorial 2, with its address the UE's, as in tutorial 3.
- **The phones** are not on 4G: their legs are outside the UE pool and get no Rx session.
