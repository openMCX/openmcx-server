# Tutorial 3a: MCX QoS over the OAI 5G core and RAN (rfsim)

[Tutorial 3](../03-mcx-over-oai-5g/README.md)'s system, with the OAI RAN and core replaced by openMCX's QoS versions
([github.com/openMCX/oai](https://github.com/openMCX/oai)). In tutorial 3 the core sets up a QoS flow for an MC call,
5QI 65 for speech or 67 for video, but the gNB's scheduler does not look at it. Here the gNB schedules by the flow's
5QI, guaranteed bit rate (GFBR), delay budget (PDB) and priority (ARP):

- **The gNB schedules by QoS**: GBR flows get their guaranteed bit rate before any best effort, in both directions,
  and MC signalling before best effort. Optionally, a GBR flow the cell cannot carry is refused, or a flow with a
  lower ARP pre-empted to make room for it.
- **The core**: the SMF releases the flows the gNB refused or pre-empted and reports them to the PCF, which tells the
  MC server (`FAILED_RESOURCES_ALLOCATION`); the UPF serves the MC downlink before best effort when it is
  overloaded.
- **Four emulated UEs**: two MC clients (`client-d` in UE 1, `client-b` in UE 2, both with IMS AKA) that call each
  other, and two load UEs (3, 4) that send best effort (5QI 9) to and from an iperf server on N6. No phones.

The walk-through: an MCVideo call at 4 Mbit/s in a small cell, which best effort overloads (step 6).

## What you need

- **Tutorial 3's step 1 done** (`.env` with `HOST_IP`), and tutorial 3's system **stopped**: this tutorial runs the
  same services, in tutorial 3's directory and `./config` (step 3).
- **A Linux computer** with Docker and Docker Compose v2 (2.24 or later), **sudo** and about **16 CPU cores**: the
  rfsimulator's gNB and four nr-UEs keep many cores busy, and with too few the simulation itself loses packets. The
  walk-through was measured on 16 cores.
- **On the computer**: `git`, `python3`, Wireshark's `dumpcap` and `tshark`, `tcpdump`, `nsenter` (util-linux) and
  `iptables`, for the measurements of step 6.
- **openmcx-server** checked out (this repository); **openMCX/oai** and **openmcx-client** side by side with it only
  to build the images yourself (step 1):

  ```
  openmcx/
    oai/              github.com/openMCX/oai
    openmcx-server/   this repository
    openmcx-client/
  ```

- No phones: the MC clients are emulated. The OpenMCX servers are the `develop` images from Docker Hub, as in
  tutorial 3.

The OAI RAN and core are under the Collaborative Standards Software License v1.0: its patent license covers study,
testing and research only.

## 1. The images

The QoS RAN and core, and an MC client recent enough for the video at a set rate (`mcvideo.live`, in openmcx-client
since 2026-10-28; the client's `develop` image predates it), are on Docker Hub; `./qos.sh up` (step 4) pulls them:

| Image | What |
|---|---|
| `openmcx/oai-gnb:mcx-qos`, `openmcx/oai-nr-ue:mcx-qos` | OAI RAN `2026.w39` with openMCX's QoS scheduler and bearers |
| `openmcx/oai-amf:mcx-qos`, `openmcx/oai-smf:mcx-qos`, `openmcx/oai-upf:mcx-qos` | OAI CN5G `v2.2.1` with tutorial 3's N5 patches and openMCX's QoS changes |
| `openmcx/openmcx-client:mcx-qos` | openmcx-client's main branch |

The PCF and the other core functions stay tutorial 3's.

To build them yourself instead (then set the image names in `.env`, step 2):

```bash
cd oai
tools/build.sh gnb nr-ue upf smf amf
cd ../openmcx-client
linux/tools/build-image -t openmcx-client:mcx-qos --server ../openmcx-server
```

`tools/build.sh` clones the pinned OAI trees once: the RAN at `2026.w39` from OAI's GitLab, the core functions at
`v2.2.1` from GitHub with tutorial 3's N5 patches (`oai/cn5g/patches/` there). It copies openMCX's changed files on top,
compiles in OAI's build container, and layers the new programs onto the stock images: `oai-gnb:mcx-qos`,
`oai-nr-ue:mcx-qos`, `oai-upf:mcx-qos`, `oai-smf:mcx-qos`, `oai-amf:mcx-qos`. The first RAN build takes the longest;
the trees and the compiler cache stay in `~/.cache/openmcx-oai`, so later builds are incremental. The same changes
as patch series, for review: `patches/` in openMCX/oai.

## 2. Settings

```bash
cd openmcx-server/tutorials/end-to-end/03a-mcx-qos-over-oai-5g
cp .env.example .env
```

`qos.sh` reads tutorial 3's `.env` (`HOST_IP`, the OpenMCX images), then this one. A variable set in the shell wins
over both: `GNB_OPTS= ./qos.sh up` starts the system with the full cell without editing a file.

| Setting | Default | |
|---|---|---|
| `GNB_IMG`, `NRUE_IMG`, `AMF_IMG`, `SMF_IMG`, `UPF_IMG` | the `openmcx/…:mcx-qos` images of step 1 | your own builds' names (step 1) |
| `CLIENT_IMG` | `openmcx/openmcx-client:mcx-qos` | the MC clients in UE 1 and UE 2 |
| `GNB_OPTS` | `--MACRLCs.[0].dl_max_mcs 4 --MACRLCs.[0].ul_max_mcs 4` | the small cell of the walk-through: MCS at most 4 both ways (about 7 Mbit/s uplink); empty: the full cell |
| `OAI_MCX_GBR_ADMISSION` | empty (off) | admission: the share of the cell that GBR flows may take, e.g. `0.9` (step 7) |
| `OAI_MCX_RLC_UM` | empty | `1`: voice in RLC UM with a discard timer; otherwise RLC AM, as in stock OAI |
| `OAI_MCX_UPF_PRIORITY_SUBNETS` | `12.1.1.0/24` | the UE pools (DNN `mcptt`) whose N6 downlink the UPF serves before best effort |
| `VIDEO_KBPS` | `4096` | the MC video's rate; the GFBR asked for is 10 % above |

## 3. Make the configuration

```bash
./qos.sh setup
```

The configuration of tutorial 3's step 2, written to tutorial 3's `./config`, plus:

- `client-b` as the second UE's MC client, also with IMS AKA (`setup/ue2-client.py`);
- MCVideo over N5: the MCVideo server asks the PCF for 5QI 67 with a GFBR of 4.5 Mbit/s for each video leg of a 5G
  UE, and the clients send a test video at `VIDEO_KBPS` (`setup/mcvideo.py`);
- a best-effort PDU session for every UE, DNN `internet` with 5QI 9 and the pool `12.1.2.0/24`
  (`setup/internet.py`, into `generated/`): the load UEs have only that one, so their load is best effort, not MC
  signalling on the `mcptt` DNN's default flow (5QI 69), which the QoS scheduler rightly serves first.

The setup ends with tutorial 3's next step, `docker compose ... up -d`: use `./qos.sh up` instead. If tutorial 3's
`./config` exists, the setup stops: start over first (tutorial 3's step 9).

## 4. Start the system

```bash
./qos.sh up
./qos.sh ps
```

`qos.sh up` adds tutorial 3's host route and NAT (`host-network.sh`, with sudo) and an exception for the iperf
server, which reaches the UEs with its own address. After about three minutes the 38 services are up and healthy;
`./qos.sh ps` shows each one's image. The gNB and the UPF say what they run:

```bash
docker logs openmcx-oai-gnb 2>&1 | grep 'RB allocation policy'    # qos, the QoS scheduler
docker logs openmcx-oai-upf 2>&1 | grep 'N6 downlink'              # ip route replace 12.1.1.0/24 dev tun1
```

## 5. A call and its QoS flow

```bash
./qos.sh call 5
docker logs openmcx-oai-gnb 2>&1 | grep -E 'DRB 3|logical channel priority'
```

`client-d` calls the group `operations`, takes the floor, talks for 5 s and hangs up; `client-b` is called.
For each UE's speech the gNB sets up a DRB of its own, and tells the MAC the flow's QoS:

```
[NR_RRC] I UE 3: created new DRB 3 for QFI 2 (5QI 65), RLC AM, PDCP discard timer -1 ms
[NR_MAC] I DRB 3: UL logical channel priority 5, prioritisedBitRate 1, LCG 2 (5QI priority level 7, GBR, GFBR UL 41984 bit/s)
```

The UE numbers are the gNB's, in the order the UEs attached. The uplink logical channel's priority comes from the
5QI's priority level and its prioritised bit rate from the GFBR, and the logical channel groups follow the QoS class
(GBR 2, delay-sensitive signalling such as 5QI 69 1, best effort 4), so the UE's buffer status reports tell the gNB
how much GBR data it has. The calls' QoS flows themselves are set up as in tutorial 3 (its step 7).

## 6. Walk-through: an MC video in a small cell under load

`client-d` sends a 4 Mbit/s video to `client-b`, through the MCVideo server, in the small cell (`GNB_OPTS`). The load
UEs 3 and 4 each send and receive 50 Mbit/s of best effort, far more than the cell carries:

```bash
./qos.sh measure video 3
```

Each run starts the load, makes a video call of 15 s and captures it at every hop: the UE's TUN in each nr-UE, N3
(GTP-U between the gNB and the UPF) and N6. `hops.py` matches each RTP packet of the video at the hops and prints
the loss and one-way delay per hop into `results/`, then the end-to-end lines (about 4 minutes for 3 runs):

```
run 1 UL lost 0/6459 (0.0 %)  delay median   30.8  p95   55.8  p99   73.1  max   90.4 ms
run 1 DL lost 0/6438 (0.0 %)  delay median    2.2  p95    3.3  p99    4.0  max    9.7 ms
...
```

UL is UE 1 to the MCVideo server, DL the MCVideo server to UE 2. The video's share of the uplink is more than UE 1's
fair share with the two load UEs. The QoS scheduler grants a UE with an active GBR flow its GFBR's share at every
uplink occasion, and the backlog of its GBR channels before any best effort; the load UEs share what is left.

The per-hop lines in the results file show where a packet was lost or delayed: `UE 1 TUN (sent) -> N3 gNB -> UPF` is
the radio (the UE's and the gNB's protocol stack and the rfsimulator), `N3 -> N6` the UPF.

## 7. GBR admission (optional)

The gNB can refuse a GBR flow that the cell cannot carry, instead of letting every flow degrade:

```bash
./qos.sh down
OAI_MCX_GBR_ADMISSION=0.9 ./qos.sh up
./qos.sh vcall 8
docker logs openmcx-oai-gnb 2>&1 | grep 'GBR QFI'
docker logs openmcx-oai-pcf 2>&1 | grep FAILED_RESOURCES_ALLOCATION
```

```
[NR_RRC] I UE 4: GBR QFI 3 (GFBR DL 4614144 UL 4614144 bit/s) admitted: cell GBR load DL 0.003 UL 0.008, the flow DL 0.341 UL 0.834, threshold 0.900
[NR_RRC] I UE 3: GBR QFI 3 (ARP priority 3, may pre-empt): 0 pre-emptable flow(s), not enough to make room
[NR_RRC] I UE 3: GBR QFI 3 (GFBR DL 4614144 UL 4614144 bit/s) refused: cell GBR load DL 0.347 UL 0.849, the flow DL 0.341 UL 0.834, threshold 0.900
[pcf_app] [info] Npcf_PolicyAuthorization_Notify to http://192.168.71.142:8099/npcf-af/.../notify: app session 2, FAILED_RESOURCES_ALLOCATION (RES_ALLO_FAIL)
```

The gNB counts a flow's GFBR as a share of the cell's PRBs at the MCS its UE's link sustains. The PCF asks for the
video's GFBR in both directions for both legs, so the first leg's video flow takes 83 % of the uplink and the
second's does not fit under 90 %. The gNB refuses it in its PDU Session Resource Modify Response (cause: radio
resources not available); the SMF releases the flow at the UPF and reports the PCC rule to the PCF, which notifies
the MCVideo server; the call goes on without that leg's dedicated flow.

A flow that may pre-empt (an emergency call: the PCF gives it ARP 1 from the priority the MCPTT server asks for)
releases flows that are pre-emptable
and have a lower priority, in other UEs or its own, to make room; the gNB then reports them in a PDU Session
Resource Notify. It needs a user with emergency call rights in MCX Admin, and is not walked through here.

## 8. The UPF under overload (optional)

In the full cell (`GNB_OPTS` empty), 400 Mbit/s of best effort each way for each load UE overloads the UPF's
downlink (800 Mbit/s offered) before the radio:

```bash
./qos.sh down
GNB_OPTS= ./qos.sh up
./qos.sh measure voice 2 400M 10
```

```
run 1 UL lost 0/507 (0.0 %)  delay median    4.1  p95    6.2  p99   12.9  max   16.1 ms
run 1 DL lost 0/507 (0.0 %)  delay median    1.7  p95    2.3  p99    2.6  max    3.6 ms
```

The UPF routes the MC pools (`OAI_MCX_UPF_PRIORITY_SUBNETS`) to a TUN and a reader of their own and serves GBR flows,
then the MC pools, then best effort, from separate queues: under overload only best effort is dropped.

## 9. Stop or start over

```bash
./qos.sh down                                                  # stop; ./config is kept
./qos.sh compose --profile load --profile dispatcher down -v   # stop and delete the data
rm -rf ../03-mcx-over-oai-5g/config generated                  # with down -v: start over at step 3
```

After `down`, `./qos.sh up` starts the same system again; a setting changed in the shell or in `.env` applies then.

## How it is put together

- **One compose file on top of tutorial 3's**: `qos.sh` runs `docker compose` with tutorial 3 as the project
  directory, `../03-mcx-over-oai-5g/docker-compose-5g-mcx.yaml` with its profile `ims-aka` (the P-CSCF and UE 1's MC
  client) and `docker-compose-qos.yaml`, which changes the
  images and the gNB's and UPF's settings, mounts `generated/` over tutorial 3's subscription data and core and nr-UE
  configuration, and adds UE 2 with `ue2-route` and `ue2-client`, the load UEs 3 and 4 and the iperf server
  (`192.168.72.150` on N6). Tutorial 3's dispatcher position is left out (profile `dispatcher`).
- **The gNB** (openMCX/oai `gnb/`): the 5QI, PDB, GFBR, MFBR and ARP of each flow reach the MAC; uplink logical
  channel priorities, prioritised bit rates and groups follow the QoS class; the `qos` policies schedule
  retransmissions first, then GBR flows up to their rates and urgent MC signalling, in order of urgency, then the
  rest by proportional fair weighted by the 5QI's priority level. The admission and pre-emption run at PDU Session Resource Modify
  (`OAI_MCX_GBR_ADMISSION`). It also fixes the stock gNB's abort when an MC video call's flow is released.
- **The core**: the SMF installs the QERs of the N5 flows, and releases the flows the gNB refused or pre-empted and
  reports them to the PCF; the AMF passes the gNB's PDU Session Resource Notify to the SMF; the UPF serves the N6
  downlink by class (GBR QER, MC pool, best effort).
- **`qos.sh measure`**: the load from `LOAD_UES` (default `3 4`; 1 and 2 load over their own best-effort session),
  the capture with `dumpcap` on the core and N6 bridges and `tcpdump` on the UEs' TUNs (without the rfsimulator's
  samples and the load), `hops.py` on one clock: the delays are one-way.
- **Limits**: a simulated radio, one cell; the UPF knows the MC traffic by its UE pool, not by its 5QI; a pre-empted
  flow is released in the RAN and the UPF but not removed from the UE's QoS rules; the gNB does not notify the core
  when a GBR flow falls below its GFBR. The open points are in openMCX/oai's `PLAN.md`.
