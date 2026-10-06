# Unit Test Tutorial 10: MCPTT regroups: group, user and GMS-formed temporary groups

One computer runs the openMCX system from the published images, with four headless clients in place of phones.
client-a and client-b are in the group `operations-north`, client-c and client-d in `operations-south`. A script
combines them for a while in three ways, and makes a call each time:

- a **group regroup** (TS 24.379 clause 16.2): both groups become one temporary group that takes its configuration from
  a preconfigured group;
- a **user regroup** (clause 16.3): a temporary group of two named users;
- a **temporary group formed by the GMS** (TS 24.481 clauses 6.3.14 and 6.3.15).

While a group is combined, a call on it is refused; once the combination is removed, the groups carry their own calls
again. A capture of the lab network records every SIP message and every speech and floor control packet, so you can
follow each step in Wireshark.

The tutorial is built on two scenarios of the openMCX regression tests, `tests/integration/regroup_scenario.py` and
`tests/integration/temporary_group_scenario.py`, and uses the same images. [Unit Test Tutorial 1](../01-group-call-basics/README.md)
explains a prearranged group call, which is what a call on a regroup is.

> **SIP in clear, for learning.** The system runs in its debug mode: SIP goes over TCP without TLS (port 5060), so
> Wireshark shows every message, its SDP and its MCPTT XML. A real system uses TLS (tutorials 1 to 5). Speech and
> floor control are not encrypted in this tutorial in either mode. The HTTPS traffic to the common services
> (sign-in, configuration, keys, and here the XCAP requests to the GMS that form a temporary group) stays encrypted and
> is not captured.

<p align="center"><img src="images/architecture.svg" width="900" alt="Unit Test Tutorial 10: client-a and client-b in operations-north, client-c and client-d in operations-south, combined by a group regroup, a user regroup and a temporary group; the openMCX system (SIP core, MCPTT server, MCData server, common services with the GMS) on one computer, on the lab network 172.31.10.0/24"></p>

## Three ways to combine

| | Group regroup | User regroup | Temporary group formed by the GMS |
|---|---|---|---|
| Asked for with | a SIP MESSAGE to the MCPTT service, `<regroup-action>create</regroup-action>` and `<groups-for-regroup>` (TS 24.379 clause 16.2.1.1) | the same with `<users-for-regroup>` (clause 16.3.1.1) | an XCAP `POST` to the GMS (TS 24.481 clause 6.3.14), over HTTPS |
| Configuration | the preconfigured group named in the request | the preconfigured group named in the request | the temporary group's own document |
| Members | everyone in the constituent groups | the named users only | everyone in the constituent groups |
| Told by | a SIP MESSAGE from the server to each affiliated member | a SIP MESSAGE to each named user | the same regroup MESSAGE (an openMCX choice, see step 7) |
| The constituent groups | regrouped: no call of their own | not regrouped | regrouped: no call of their own |
| Removed by | a SIP MESSAGE, `<regroup-action>remove</regroup-action>` (clause 16.2.1.2) | the same | an XCAP `DELETE` (TS 24.481 clause 6.3.15) |

## What you need

- A computer with Docker and Docker Compose v2 (Linux, or Docker Desktop on macOS or Windows) and a bash shell for
  `run.sh` (on Windows: WSL or Git Bash).
- No phones, no network set-up, nothing to compile: the tutorial uses the **prebuilt openMCX images from Docker Hub**
  (`openmcx/openmcx-*:v1`) and publishes no port; everything stays on the computer.
- [Wireshark](https://www.wireshark.org/) to look at the capture (optional: `run.sh` prints a summary).

## 1. Make the configuration

```bash
cd tutorials/unit-tests/10-dynamic-groups
docker compose run --rm setup
```

The setup container runs the generator of the regression lab (`tools/prepare-prearranged-test.py --debug-sip
--regroup`). It writes `./config` with these parts:

- a new certificate authority with the servers' and clients' certificates;
- the users `alice` (client-a), `bob` (client-b), `client-c` and `client-d`; alice and bob in `operations-north`,
  client-c and client-d in `operations-south`;
- the preconfigured group `operations-preconf`, marked `<preconfigured-group-use-only>`: it cannot be called itself, it
  only lends its configuration to a regroup (TS 24.379 clause 16.1);
- the rights (TS 24.484 `<allow-regroup>` and the GMS's own setting): only alice may regroup and form temporary groups.

It runs once. To start over, see step 5. The certificates last 30 days.

## 2. Start the system

```bash
docker compose up -d --wait
```

After about half a minute `--wait` returns and every service is healthy, with the capture already running.

| Address | Container |
|---|---|
| 172.31.10.10 | SIP core (Kamailio) |
| 172.31.10.20 | MCPTT server |
| 172.31.10.21 | MCData server (running, not used here) |
| 172.31.10.101 | client-a, user `alice`, in `operations-north` |
| 172.31.10.102 | client-b, user `bob`, in `operations-north` |
| 172.31.10.103 | client-c, user `client-c`, in `operations-south` |
| 172.31.10.104 | client-d, user `client-d`, in `operations-south` |

## 3. Run the steps

```bash
./run.sh
```

The script sends each command to a client and waits until the clients and the server show its result before going
on. It takes about a minute:

```
2. A group regroup: client-b may not create one, client-a may
  $ client-b: regroup create sip:operations-regroup-1@mcx.test sip:operations-preconf@mcx.test sip:operations-north@mcx.test,sip:operations-south@mcx.test
  ok: client-b refused: 403, warning 160
  $ client-a: regroup create sip:operations-regroup-1@mcx.test sip:operations-preconf@mcx.test sip:operations-north@mcx.test,sip:operations-south@mcx.test
  ok: client-a answered 200
  ok: every member of both groups told of the regroup
...
8. The capture: captures/10-dynamic-groups-run.pcap.gz
```

Each command is the same program the clients run, with `--command`. To type one yourself:

```bash
docker compose exec client-a mcx-client --config /config/client-a.json --command "group sip:operations-regroup-1@mcx.test"
```

| Step | Command | What happens (TS 24.379 unless noted) |
|---|---|---|
| 2 | `client-b: regroup create …`, `client-a: regroup create …` | bob has no `<allow-regroup>`: 403 with warning 160 (clause 16.2.2.2 step 3), nothing is created. alice's request is accepted (clause 16.2.3.1): the server marks both groups regrouped, answers 200 and tells every affiliated member of both groups (clauses 16.2.4.1 and 16.2.2.4). |
| 3 | `client-a: call` | client-a calls its own group, which is regrouped: 403 with warning 148, and the server sends client-a a copy of the regroup notice (clause 10.1.1.4.1 step 5 b)). |
| 4 | every client `group <regroup>`, `client-a: call`, `client-a: ptt` | The clients use the regroup at once, with the preconfigured group's configuration (clause 16.1). The call on it invites the members of both groups, and client-a's speech reaches client-c and client-d. |
| 5 | `client-a: regroup remove …`, every client back to its group | Removal (clause 16.2.3.2): 200, the call on the regroup is released, every member is told, and the groups are free again. |
| 6 | `client-a: regroup users …`, `client-a: group <user regroup>`, `client-a: call`, `client-a: regroup remove …` | A user regroup of alice and client-c (clause 16.3): only they are told; client-c is invited to the call without having selected the regroup, and bob and client-d are not. The removal tells both, without the list of users (clause 16.2.2.5). |
| 7 | `client-b: temporary-create …`, `client-a: temporary-create …`, calls, `client-a: temporary-delete …` | A temporary group formed by the GMS (TS 24.481 clauses 6.3.14 and 6.3.15): bob is refused 403, alice's request forms it. The MCPTT server applies it as a group regroup: the members are told, a call on `operations-north` is refused with 148, a call on the temporary group joins both groups, and alice's teardown ends the call and frees the groups. |

## 4. Look at the capture

`run.sh` copies the capture to `captures/10-dynamic-groups-run.pcap.gz`. The folder also holds a reference run,
`captures/10-dynamic-groups-full.pcap.gz` (171 KB, 2 877 frames): the frame numbers below and in the call flow are
those of the reference. Wireshark opens the compressed file directly (or `gunzip` it first).

The capture filter is `ip and not host 172.31.10.1 and (tcp port 5060 or (udp and not port 53) or icmp)`:

- SIP on 5060/tcp, with every TCP segment, so Wireshark rebuilds a message split over two segments;
- every UDP flow, since the speech and floor control ports come from the SDP and are not fixed;
- ICMP, which shows media sent to a closed port.

DNS, the encrypted HTTPS (including the XCAP requests of step 7) and the host's own traffic on the bridge
(172.31.10.1) are left out.

Useful display filters:

| Filter | Shows |
|---|---|
| `sip.Method == "MESSAGE"` | The regroup requests and the notices; open the `application/vnd.3gpp.mcptt-regroup+xml` part of each. |
| `sip.Warning` | The refusals: 160 (not allowed to regroup) and 148 (group is regrouped). |
| `sip.Method == "INVITE" \|\| sip.Method == "BYE"` | The calls on the combined groups and their release. |
| `rtp` | Speech: AMR-WB. |

Each client request appears twice in a row: the SIP core challenges it with `407 Proxy Authentication Required`, and
the client sends it again with its credentials. The frame numbers below are those of the second one.

What to look for, in the reference run:

- **A refused regroup** (frames 405 to 411): bob's MESSAGE (405) with `<regroup-action>create</regroup-action>`, the
  server's 403 (409) with `Warning: 399 mcx "160 user not authorised to request creation of a regroup"`. No notice
  follows.
- **The group regroup** (frames 417 to 440): alice's MESSAGE (417) names `sip:operations-regroup-1@mcx.test` in
  `<mcptt-regroup-uri>`, the preconfigured group and both groups in `<groups-for-regroup>`. The server answers 200
  (421, to alice 423) and tells alice (425), bob (430), client-c (435) and client-d (440), each with the same three
  items.
- **A call on a regrouped group** (frames 453 to 467): alice's INVITE on `operations-north` (453) gets 403 (457, to
  alice 467) with `Warning: 399 mcx "148 group is regrouped"`, and the server sends her a copy of the regroup notice
  (461). Nobody is invited.
- **The call on the regroup** (frames 550 to 731): alice's INVITE (550) and the server's INVITEs to bob (563),
  client-c (572) and client-d (582), members of both groups. alice's Floor Request (721) and Floor Granted (722), her
  speech from 729, reaching client-c from 731.
- **Removal** (frames 2092 to 2138): alice's MESSAGE with `<regroup-action>remove</regroup-action>` (2092), the 200
  (2096), the call released with BYEs to client-d (2111), bob (2117), alice (2106) and client-c (2101), then the
  removal notices to alice (2120), bob (2124), client-c (2132) and client-d (2138).

  Like every removal notice, they carry neither `<groups-for-regroup>` nor `<users-for-regroup>`: TS 24.379 clause
  16.2.2.5 step 3 e) leaves both out.
- **The user regroup** (frames 2274 to 2422): alice's MESSAGE (2274) with `<users-for-regroup>` naming alice and
  client-c, the 200 (2278), the notices to alice (2282) and client-c (2287) only. alice's call on the user regroup
  (2318) invites client-c (2331) and nobody else. The removal (2400) ends the call (BYE to client-c 2414) and the
  notices to alice (2417) and client-c (2422) name neither users nor groups.
- **The temporary group** (frames 2468 to 2816): its formation and teardown are XCAP requests over HTTPS, so the
  capture shows only their effect. The regroup notices for `sip:operations-temp-1@mcx.test` to alice (2468), bob
  (2473), client-c (2479) and client-d (2483). alice's call on `operations-north` (2496) is refused 403 with warning
  148 (2500), followed by a copy of the notice (2504). The call on the temporary group (2593) invites bob (2606),
  client-c (2615) and client-d (2624). After alice's teardown the server releases the call (BYE 2776) and sends the
  removal notices (2801 to 2816).

  > **Note.** Telling the members of a temporary group with the regroup notice is an openMCX choice: TS 24.481 lets a
  > client learn of it from its group documents, and does not define a SIP notice. Following that choice, the server
  > also sends the copy of the notice after a refused call (2504), which TS 24.379 clause 10.1.1.4.1 step 5 b) iii)
  > asks for only when the group is regrouped "based on a preconfigured group".

## 5. Stop or start over

```bash
docker compose down -v        # remove the containers and their data (status files, capture)
rm -rf config                 # with down -v: start over at step 1
```

To run the steps again on the same system, run `./run.sh` again: the capture keeps everything since `up`. For a new
capture, `docker compose down -v` and `docker compose up -d --wait` first (the configuration stays).

## Images

The compose file names every image in full, all from Docker Hub:

| Image | What it is |
|---|---|
| `docker.io/openmcx/openmcx-setup:v1` | The setup: the lab's generator |
| `docker.io/openmcx/openmcx-mcptt-server:v1`, `docker.io/openmcx/openmcx-mcdata-server:v1` | The MCPTT and MCData servers |
| `docker.io/openmcx/openmcx-common:v1`, `docker.io/openmcx/openmcx-http-proxy:v1`, `docker.io/openmcx/openmcx-user-db:v1` | The common services, among them the GMS |
| `docker.io/openmcx/openmcx-client:v1` | The headless client (`openMCX/openmcx-client` repository) |
| `docker.io/openmcx/openmcx-kamailio:6.1.4-2` | The SIP core |
| `docker.io/library/mysql@sha256:…` | The SIP core's database |
| `docker.io/nicolaka/netshoot@sha256:…` | tcpdump, for the capture |

To use images you built yourself, change the `image:` lines in `docker-compose.yaml` (building them:
[docs/BUILD.md](../../../docs/BUILD.md)).

## When something does not work

- **A service stays unhealthy**: `docker compose logs <service>`.
- **A step of run.sh fails**: it prints the step that did not complete. `docker compose exec client-a cat
  /artifacts/client-a/status.json` shows a client's regroups (`regroups`), its last regroup answer (`regroup_result`)
  and its last XCAP answer (`xcap_last`); `/artifacts/mcptt-server/status.json` shows the server's `regroups` and
  `regrouped_groups`. Start over from a clean state with `docker compose down -v` and `docker compose up -d --wait`.
- **No capture, or `capture` exited**: `docker compose logs capture`. The capture container uses the host's network
  to reach the lab's bridge (`openmcx-ut10`), and the address range 172.31.10.0/24 must be free on the computer.
- **Certificates expired** (after 30 days): start over (step 5).

## How it is put together

- `docker-compose.yaml`: the regression lab of `prepare-prearranged-test.py --debug-sip --regroup`, written for the
  published images by `tools/tutorial-compose.py`. Each container has a fixed address, so the capture reads by role. The
  status files are in a volume, and the capture runs on the lab's bridge.
- `run.sh`: the steps RG-01, RG-02, RG-04, RG-05, RG-07, RU-02, RU-04 and RU-05 of
  `tests/integration/regroup_scenario.py` and TG-01, TG-02, TG-04, TG-05 and TG-06 of
  `tests/integration/temporary_group_scenario.py`. Left out: removal by an unauthorised user and of an unknown regroup
  (warnings 161, 163), a reused identity (165), the late notice to a member affiliating later, removal decided by the
  server, chat calls on a regroup or temporary group, and the GMS's own refusals (409).
- `speech/`: the two spoken test messages the clients transmit (16 kHz WAV, made with espeak-ng).
- `captures/10-dynamic-groups-full.pcap.gz`: the reference run.

## Call flow

The group regroup of steps 2 to 5, drawn from the reference capture (the regression's test reports have no diagram
for it). A = client-a, B = client-b, C/D = client-c and client-d, S = MCPTT server. Each SIP arrow passes through the
SIP core; the 407 challenges, the 200 OKs to the notices and the floor Acks are left out.

```mermaid
sequenceDiagram
    participant A as client-a (north)
    participant B as client-b (north)
    participant S as MCPTT server
    participant CD as client-c, client-d (south)
    Note over A,CD: Step 2: create
    B->>S: MESSAGE regroup create (north, south)
    S-->>B: 403, warning 160
    A->>S: MESSAGE regroup create (north, south)
    S-->>A: 200 OK
    S->>A: MESSAGE regroup notice
    S->>B: MESSAGE regroup notice
    S->>CD: MESSAGE regroup notice
    Note over A,CD: Step 3: a call on a regrouped group
    A->>S: INVITE operations-north
    S-->>A: 403, warning 148
    S->>A: MESSAGE copy of the regroup notice
    Note over A,CD: Step 4: a call on the regroup
    A->>S: INVITE operations-regroup-1
    S->>B: INVITE
    S->>CD: INVITE
    A->>S: Floor Request
    S->>A: Floor Granted
    A->>S: AMR-WB RTP
    S->>CD: AMR-WB RTP
    Note over A,CD: Step 5: remove
    A->>S: MESSAGE regroup remove
    S-->>A: 200 OK
    S->>A: BYE
    S->>B: BYE
    S->>CD: BYE
    S->>A: MESSAGE removal notice
    S->>B: MESSAGE removal notice
    S->>CD: MESSAGE removal notice
```

| Message | Frames |
|---|---|
| B's regroup request; 403 with warning 160 | 405; 409, 411 |
| A's regroup request; 200 OK | 417; 421, 423 |
| Notices to A, B, C, D | 425, 430, 435, 440 |
| A's INVITE on `operations-north`; 403 with warning 148; copy of the notice | 453; 457, 467; 461 |
| A's INVITE on the regroup; INVITEs to B, C, D | 550; 563, 572, 582 |
| Floor Request; Floor Granted; A's speech; to C | 721; 722; 729; 731 |
| A's removal request; 200 OK | 2092; 2096 |
| BYEs to D, B, A, C | 2111, 2117, 2106, 2101 |
| Removal notices to A, B, C, D | 2120, 2124, 2132, 2138 |
