# Tutorial: a basic MCX system with two phones

One computer runs a complete openMCX system from the published images: the MCPTT, MCData and MCVideo servers, the
common services, the SIP core and MCX Admin. In MCX Admin's web console you create two users, and two Android phones
on the same Wi-Fi as the computer activate with them. Then they call, chat and make video calls.

```
   phone A ──┐                    ┌── MCPTT server ─┐
             │   Wi-Fi            ├── MCData server ├── common services (IdMS, GMS, CMS, KMS, LMS,
   phone B ──┼──────── computer ──┼── MCVideo server┘    Credential Service, content, message store, ...)
             │      (HOST_IP)     ├── SIP core (Kamailio + MySQL)
   browser ──┘                    └── MCX Admin (console, activation codes)
```

This page covers the system on the computer; the console and the phones follow in the next part.

## What you need

- A computer with Docker and Docker Compose v2 (Linux, or Docker Desktop on macOS or Windows), on the same Wi-Fi as
  the phones. Its firewall must let the phones reach the ports below.
- Two Android phones (Android 11 or later) with the openMCX app. Phones and computer on the same network, with no
  client isolation between devices (guest networks often have it).

| Port on the computer | Service |
|---|---|
| 5061/tcp | SIP core (TLS) |
| 8443/tcp | IdMS: sign-in and passwords |
| 8444/tcp | HTTP proxy: CMS, GMS, KMS, LMS, files |
| 8445/tcp | KMS |
| 8446/tcp | MCX Admin: web console and activation |
| 8447/tcp | Credential Service |
| 4000-4199/udp, 5000-5199/udp | MCPTT speech and floor control |
| 7000-7599/udp | MCVideo audio, transmission control and video |

## 1. Set the computer's address

```bash
cd tutorial
cp .env.example .env
```

Set `HOST_IP` in `.env` to the computer's IPv4 address on the Wi-Fi:

- Linux: `ip -4 route get 1.1.1.1` (the address after `src`)
- macOS: `ipconfig getifaddr en0`
- Windows: `ipconfig` (IPv4 address of the Wi-Fi adapter)

The phones reach every service through this address. If it changes (another network, a new DHCP lease), make a new
configuration (step 2) and activate the phones again.

## 2. Make the configuration

```bash
docker compose -f docker-compose-basic-mcx.yaml run --rm setup
```

The setup container writes `./config`: a new certificate authority and the servers' certificates, the system's
users and groups, the configuration of every server and of MCX Admin, all set up for `HOST_IP`. It prints the console
address and the administrator's password, which it also keeps in `config/ADMIN.txt`.

It runs once. To start over with a new system, stop it with `down -v` and remove `./config` (step 6). The
certificates last 30 days.

## 3. Start the system

```bash
docker compose -f docker-compose-basic-mcx.yaml up -d
docker compose -f docker-compose-basic-mcx.yaml ps
```

After a minute or two every service shows `(healthy)`: `sip-db`, `sip-core`, `idms`, `gms`, `cms`, `kms`, `lms`,
`credentials`, `content-server`, `message-store`, `notification-server`, `http-proxy`, `mcx-user-db`, `mcptt-server`,
`mcdata-server`, `mcvideo-server` and `mcxadmin`.

## 4. Open MCX Admin

Open `https://HOST_IP:8446/` in a browser on the computer (with your `HOST_IP`). The system has its own certificate
authority, which the browser does not know: accept the warning, here and at `https://HOST_IP:8443` where you sign in.
Sign in as `admin` with the password from `config/ADMIN.txt`. The console shows the system's users, groups and the
live status of its services.

The system starts with the administrator and three test users (bob, client-c, client-d) in the group `operations`.

## 5. Next: users and phones

In the console you create two users with MCPTT, MCData and MCVideo in the group `operations`, give each a
set-password link and an activation code (a QR code). On each phone the openMCX app scans the code, the user signs in,
and the phone registers through `HOST_IP`. The two phones then make private and group calls, send messages and make
video calls. The step-by-step guide for the console and the app follows.

## 6. Stop or start over

```bash
docker compose -f docker-compose-basic-mcx.yaml stop          # stop, keep everything
docker compose -f docker-compose-basic-mcx.yaml down          # remove the containers, keep the data
docker compose -f docker-compose-basic-mcx.yaml down -v       # also remove the data (users, groups, messages)
rm -rf config                                                 # with down -v: start over at step 2
```

## Images

The compose file takes the images from `${OPENMCX_IMAGE_PREFIX}openmcx-<program>:${OPENMCX_TAG}` (`.env`):
`openmcx-setup`, `openmcx-mcptt-server`, `openmcx-mcvideo-server`, `openmcx-mcdata-server`, `openmcx-common`,
`openmcx-http-proxy` and `openmcx-user-db`, with `openmcx-kamailio` (`KAMAILIO_TAG`) and MCX Admin's `openmcx-admin`
(`ADMIN_TAG`, from the `openMCX/openmcx-admin` repository). MySQL comes from Docker Hub.

To use images built on this computer instead, set `OPENMCX_IMAGE_PREFIX=` (empty) and the tags you built:

```bash
tools/build-images u2404                                                  # the server images (docs/BUILD.md)
docker build -f tutorial/setup/Dockerfile -t openmcx-setup:u2404 .        # the setup image
```

## When something does not work

- **A service stays unhealthy**: `docker compose -f docker-compose-basic-mcx.yaml logs <service>`.
- **The phones cannot connect**: check that the computer's firewall lets the ports above through, that `HOST_IP` is the
  Wi-Fi address, and that the phones are on the same network without client isolation.
- **Calls connect but there is no sound or video**: the UDP ports (4000-5199, 7000-7599) are blocked between the
  phones and the computer.
- **Certificates expired** (after 30 days): start over (step 6), then activate the phones again.

## How it is put together

- `docker-compose-basic-mcx.yaml`: the services, their configuration files from `./config`, their data in Docker
  volumes, and the published ports.
- `setup/`: the setup image. `configure.py` runs the lab's generator (`tools/prepare-prearranged-test.py` with MCData,
  MCVideo, ad hoc calls and MCX Admin) and then sets it up for phones on the network: the MCPTT and MCVideo servers
  advertise `HOST_IP` for media and accept the phones' addresses as the SIP core checks them; MCX Admin's activation
  codes and console, and IdMS's password links, point to `HOST_IP` and the published ports; activation codes carry
  MCVideo as well as MCPTT and MCData.
