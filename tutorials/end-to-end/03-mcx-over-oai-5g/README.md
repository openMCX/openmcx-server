# Tutorial 3: MCX over the OAI 5G core and RAN (rfsim), with MCPTT QoS over N5

Tutorial 1's system and phones, plus a 5G network: the OAI 5G core, the OAI gNB and one nr-UE connected by the
rfsimulator (a simulated radio, no radio hardware). The dispatcher position runs inside the nr-UE, so all its traffic
crosses the 5G radio and core. When it calls, the MCPTT server asks the 5G core, over **N5**, for the QoS of
mission-critical voice: the core sets up a dedicated QoS flow (**5QI 65**) for the dispatcher's speech.

<p align="center"><img src="images/architecture.svg" width="900" alt="Tutorial 3: the phones reach the openMCX system over the Wi-Fi; the dispatcher runs inside the nr-UE and reaches it over the rfsim radio, the gNB, the UPF (N3, N6) of the OAI 5G core; the MCPTT server asks the PCF for MCPTT QoS over N5"></p>

The phones reach the system on the Wi-Fi as in tutorial 1; their calls get no 5G QoS (they are not on 5G). The MCPTT
server asks for QoS only for call legs of UEs in the 5G pool (12.1.1.0/24).

## What you need

- **Tutorial 1 done once**: the phones have the app, and you know the steps in MCX Admin. Tutorial 1's system must be
  **stopped**: tutorial 3 runs its own system with the same ports.
- **A Linux computer** with Docker and Docker Compose v2, about 8 CPU cores free (the rfsimulator's gNB and UE keep
  several cores busy) and **sudo** (step 3).
- **The OAI 5G core and RAN images**, from Docker Hub: OAI's own, and its AMF, PCF, SMF and UPF v2.2.1 with changes
  for N5 (`openmcx/oai-{amf,pcf,smf,upf}:mcx-n5`): the PCF turns an AF's media components into a PCC rule with 5QI 65,
  the SMF modifies the PDU session for it (a new QoS flow), and the UPF keeps the flow's packet rules. When the RAN
  cannot set the flow up, the AMF passes its answer on, the SMF removes the flow and reports the rule to the PCF, and
  the PCF tells the MCPTT server; the call goes on without the dedicated flow. The patches and the script that builds
  these images yourself are in [`oai/cn5g/`](oai/cn5g/README.md).

  The OAI 5G core is under the Collaborative Standards Software License v1.0: its patent license covers study,
  testing and research only ([`oai/cn5g/NOTICE`](oai/cn5g/NOTICE)).
- Nothing to compile: the tutorial uses **prebuilt images from Docker Hub**, openMCX's (`openmcx/openmcx-*:v1`, as
  in tutorial 1) and OAI's. To build the openMCX images yourself, see
  [tutorial 1's Images](../01-mcx-over-wlan-android/README.md#images) and [Building openMCX](../../../docs/BUILD.md);
  for the three OAI images, [`oai/cn5g/`](oai/cn5g/README.md).

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
network and the UE pool 12.1.1.0/24.

## 3. Connect this computer to the UE pool

```bash
sudo ./host-network.sh add
```

The dispatcher reaches the system at `HOST_IP`, as the phones do. Two settings of this computer complete the path:
replies to the UE pool go back through the UPF, and they leave from `HOST_IP`, so the UE sees one address both ways and
the 5G core's packet filters match the speech. `sudo ./host-network.sh remove` undoes both (step 8).

## 4. Start the system

```bash
docker compose -f docker-compose-5g-mcx.yaml up -d
docker compose -f docker-compose-5g-mcx.yaml ps --format 'table {{.Name}}\t{{.Status}}'
```

After about two minutes every service is `(healthy)`: the 30 of the openMCX system, the 5G core, the gNB, the nr-UE,
`ue-route` and the dispatcher. `openmcx-ue-route` shows the UE's address:

```bash
docker logs openmcx-ue-route        # UE address 12.1.1.2, 192.168.179.39 through oaitun_ue1
```

## 5. Users and phones

As in tutorial 1, steps 4 to 6: in MCX Admin (`https://HOST_IP:8446/`) create `alice` and `bob` with the template
`phone-user` and the group `operations`, set their passwords and activate the phones. Also create `dispatcher` the same
way, and set its password.

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
   docker logs openmcx-oai-smf 2>&1 | grep -E 'PDU Session Modification|QoS Flow'
   ```

   ```
   {"app_session_id":"1",...,"event":"pcf_app_session_created","status":201,"user_id":"sip:dispatcher.mcptt@mcx.test"}
   "flowDescription":"permit out 17 from 192.168.179.39 4000 to 12.1.1.3 4400"      speech (RTP)
   "flowDescription":"permit out 17 from 192.168.179.39 4001 to 12.1.1.3 4401"      RTCP
   "flowDescription":"permit out 17 from 192.168.179.39 5000 to 12.1.1.3 5400"      floor control
   "5qi":65                                                                          GBR 41 kbit/s, may pre-empt
   [smf_app] [info] PDU Session Modification PCF-initiated                          the new QoS flow (QFI 2)
   ```

   The QFI (QoS Flow Identifier) numbers a QoS flow within the UE's PDU session; the 5QI describes the flow's QoS
   (TS 23.501 clause 5.7.1). QFI 1 is the session's default flow, with 5QI 69 (MC signalling) for the DNN `mcptt`.
   The speech flow the PCF asks for is a second flow, so the SMF gives it the next QFI, 2, with 5QI 65. When the call
   ends, the MCPTT server deletes the app session (`pcf_app_session_deleted`, 204) and the SMF releases the flow; the
   next call's flow may get another free QFI (3, ...).

## 8. Stop or start over

```bash
docker compose -f docker-compose-5g-mcx.yaml down        # stop; ./config is kept
docker compose -f docker-compose-5g-mcx.yaml down -v     # stop and delete the data
sudo ./host-network.sh remove
rm -rf config                                            # with down -v: start over at step 2
```

## How it is put together

- **Two compose files**: `docker-compose-5g-core.yaml` has tutorial 1's openMCX services, unchanged, on the 5G core's
  **N6 network** (`openmcx-5g-n6`, 192.168.72.128/26) and the OAI 5G core on the **core network** (`openmcx-5g-core`,
  192.168.71.128/26); [tutorial 4](../04-mcx-over-srsran-5g/README.md) uses it too. `docker-compose-5g-mcx.yaml`
  includes it and adds the gNB and the nr-UE (IMSI 208990100001100, DNN `mcptt`), the dispatcher in the nr-UE's
  network namespace and `ue-route`, which routes `HOST_IP` through the UE's tunnel (`oaitun_ue1`) once its PDU
  session is up. The OAI configuration is in `oai/`, the N5 patches of the AMF, PCF, SMF and UPF in `oai/cn5g/`.
- **N5**: the MCPTT server is also on the core network (192.168.71.141). With the `pcf` block that the setup adds
  (`setup/pcf.py`), it creates an `Npcf_PolicyAuthorization` app session (TS 29.514) for each call leg of a UE in
  12.1.1.0/24: the leg's speech, RTCP and floor control flows, its bandwidth and priority. The PCF makes a PCC rule
  (5QI 65), the SMF a QoS flow on the UE's PDU session (TS 23.502 4.3.3.2), the UPF its packet rules. Without the
  `pcf` block, as in tutorials 1 and 2, the server never contacts a PCF.
- **The dispatcher** is the image and settings of tutorial 2, with its address the UE's. The UE's address can change
  when the UE or the core restarts; the dispatcher then updates its activated accounts at start.
- **Routing**: the UPF sends a UE's packets for `HOST_IP` out of the core network (its default route), so they reach
  this computer from another Docker network than the openMCX system's and Docker's NAT keeps the UE's address (the
  SIP core checks that the SDP address is the sender's). The replies come back through `host-network.sh`'s route and
  leave from `HOST_IP`.
- **The phones** are not on 5G: their legs are outside the UE pool and get no app session.
