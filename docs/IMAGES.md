# The openMCX images and containers

Which image runs which program, and which lab container runs it. How to build them: `docs/BUILD.md`.

## Images

| Image | Program | Base | Size (2026-10-01) |
|---|---|---|---|
| `openmcx-mcptt-server` | `openmcx-mcptt-server`: MCPTT server (TS 24.379, TS 24.380) | Ubuntu 24.04 slim | 182 MB |
| `openmcx-mcvideo-server` | `openmcx-mcvideo-server`: MCVideo server (TS 24.281, TS 24.581) | Ubuntu 24.04 slim | 182 MB |
| `openmcx-mcdata-server` | `openmcx-mcdata-server`: MCData server (TS 24.282, TS 24.582) | Ubuntu 24.04 slim | 180 MB |
| `openmcx-common` | `mcx-common` (IdMS, GMS, CMS, KMS, LMS, message store, content and notification servers, Credential Service) and `mcx-keytool` | Ubuntu 24.04 slim | 190 MB |
| `openmcx-http-proxy` | `mcx-http-proxy` (TS 24.482 annex A.2.2.2) | Ubuntu 24.04 slim | 180 MB |
| `openmcx-user-db` | `mcx-user-db`: user profiles over Diameter (TS 29.283) | Ubuntu 24.04 slim | 133 MB |
| `openmcx-client` (openmcx-client) | `mcx-client`: the MC client for all three services | Ubuntu 24.04 slim | 181 MB |
| `openmcx-all` | every server program (the former single image) | development image | 1.68 GB |
| `openmcx-kamailio` | Kamailio 6.1.4: SIP core | development image | |
| `openmcx-sipdb` | MySQL 8.0 for the SIP core | MySQL | |
| `openmcx-dev` | build and development tools, also the capture container (tcpdump) | Ubuntu 24.04 | |
| `openmcx-dev:0.1-ubuntu26.04` | the same on Ubuntu 26.04, for `tools/build-images --ubuntu 26.04` (docs/BUILD.md) | Ubuntu 26.04 | |
| `openmcx-lint` | formatting and lint tools | development image | |

Before the split every container ran the 1.6 GB `openmcx` image with all programs and their debug information.

Every long-running openMCX program prints the openMCX banner naming itself when it starts.

## Lab containers

System A; system B's containers carry a `-b` suffix (servers) or a `b-` prefix (common services).

| Container | Image | Started as |
|---|---|---|
| `mcptt-server`, `mcptt-part-1`, `mcptt-part-2` | `openmcx-mcptt-server` | controlling and participating MCPTT functions |
| `mcvideo-server`, `mcvideo-part-1`, `mcvideo-part-2` | `openmcx-mcvideo-server` | controlling and participating MCVideo functions |
| `mcdata-server` | `openmcx-mcdata-server` | MCData server |
| `idms`, `gms`, `cms`, `kms`, `lms`, `message-store`, `content-server`, `notification-server` | `openmcx-common` | `mcx-common --role <role>` |
| `http-proxy` | `openmcx-http-proxy` | HTTP proxy |
| `mcx-user-db` | `openmcx-user-db` | user database |
| `sip-core` | `openmcx-kamailio` | SIP core (P-/S-CSCF role) |
| `sip-db` | `openmcx-sipdb` | SIP core database |
| `client-a` ... `client-f` | `openmcx-client` | MC clients |
| `mcxadmin` (admin labs) | `openmcx-admin` (openmcx-admin) | MCX Admin |
