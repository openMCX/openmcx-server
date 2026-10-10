# openMCX 1.0.0 — release notes

Release 1.0.0, 2026-10-15: the first release of the **standalone edition** of openMCX, 3GPP Release 19 mission-critical
services (MCX) for an IP network. It covers one MC system, on-network, with the three services MCPTT, MCVideo and
MCData, their common services, a SIP core, the clients and MCX Admin.

It is not an interoperability-certified implementation: it has not yet been tested against independent
implementations, and the scope and known limitations below say what it does not do.

## What is in the release

| Part | Repository | What it is | Images (Docker Hub `openmcx/`) |
|---|---|---|---|
| Servers and common services | [openmcx-server](https://github.com/openMCX/openmcx-server) | MCPTT, MCVideo and MCData servers (participating and controlling functions); IdMS, GMS, CMS, KMS, LMS, Credential Service, content server, message store, notification server; HTTP proxy; user database; the tutorials and the lab tools | `openmcx-mcptt-server`, `openmcx-mcvideo-server`, `openmcx-mcdata-server`, `openmcx-common`, `openmcx-http-proxy`, `openmcx-user-db`, `openmcx-setup`, `openmcx-kamailio` |
| Clients | [openmcx-client](https://github.com/openMCX/openmcx-client) | The Android app (`android/apk/openmcx-client-v1.apk`), the dispatcher position in the browser, and `mcx-client`, the headless Linux client | `openmcx-client`, `openmcx-dispatcher` |
| MCX Admin | [openmcx-admin](https://github.com/openMCX/openmcx-admin) | MC user profiles, groups and rights, client activation | `openmcx-admin` |
| Helm chart (experimental) | [openmcx-server `helm/openmcx`](helm/openmcx/README.md) | The tutorial 1 system on Kubernetes or OpenShift; validated with `helm lint`, `helm template` and kubeconform, **not yet installed on a cluster** | (the images above) |

Every openMCX image, `openmcx-kamailio` (Kamailio 6.1.4) and `openmcx-admin` included, is published with the one tag
`1.0.0`, the tag the tutorials and the Helm chart use.

| Repository | Release commit |
|---|---|
| openmcx-server | tag `v1.0.0` |
| openmcx-client | `314298c` |
| openmcx-admin | `39e17e3` |

<!-- TO FILL AT PUBLISHING: the digest of each image. -->

The services and what each supports are listed in the [feature list](docs/FEATURES.md); the 3GPP specifications and
versions the code follows are in [docs/SPECS.md](docs/SPECS.md).

## Try it

The [tutorials](tutorials/README.md) run the whole system on one computer from the Docker Hub images:

- End to end: [1, MCX over Wi-Fi with two Android phones](tutorials/end-to-end/01-mcx-over-wlan-android/README.md);
  [2, the dispatcher](tutorials/end-to-end/02-dispatcher-with-android/README.md);
  [3, over an OAI 5G core with QoS over N5](tutorials/end-to-end/03-mcx-over-oai-5g/README.md);
  [4, over srsRAN 5G](tutorials/end-to-end/04-mcx-over-srsran-5g/README.md);
  [5, over a 4G core with QoS over Rx](tutorials/end-to-end/05-mcx-over-4g-open5gs-oai/README.md). The RAN of
  tutorials 3 to 5 is simulated.
- [Unit test tutorials](tutorials/unit-tests): one feature each, with its SIP and media flow captured and explained
  against the specification.

## Scope: not in this release

| Area | Why |
|---|---|
| Off-network operation (ProSe), relays, isolated operation (IOPS) | No radio side in this edition |
| Interconnection between MC systems, MC gateway servers, migration | The standalone edition is one MC system |
| Interworking with LMR and other non-3GPP systems | Not part of the standalone edition |
| MBMS/eMBMS broadcast bearers | Unicast bearers only |
| Pre-established sessions (TS 24.379 clause 8) | They require resource sharing in the PCRF/PCF, which the cores of the tutorials do not support; a setup request is refused with 403 and warning 100 |
| N33 through the NEF, and the SIP core as the QoS application function | The MCPTT server is the application function, over Rx (4G) and N5 (5G) |
| Several devices of one user at the same time | Not implemented |
| Audio cut-in, multi-talker groups, override with simultaneous talkers | Not implemented |
| Acknowledged group call options (TNG1: proceed or convert on timeout, list of members who did not acknowledge) | Not implemented; a call missing required members is abandoned |
| MCVideo: several transmitters at a time, video conferencing, video modes, remote camera control | Not implemented |
| MCData data streaming | Not implemented (TS 24.282 has no procedure for it) |
| Discreet listening, MC logging and recording, lawful interception, charging | Not implemented |
| Measured performance (access time, mouth-to-ear latency, MOS) | Not measured yet |

## Known limitations

- **Registration.** The service authorisation by third-party REGISTER (TS 24.379 clause 7.3.2) is not supported; the
  clients authorise by PUBLISH (clause 7.3.3).
- **Keys.** The servers and the GMS fetch keys from the KMS over an internal interface, not with the access-token
  request of TS 33.180 annex D.2; a KMS of another vendor would not serve them.
- **Media.** The servers accept media only from the address and port in a client's SDP, and send to them; they do not
  learn the address from the received media. A client behind NAT is reachable only if the address it advertises is.
- **Message store.** Answers are JSON only, and the `listFilter` query is not supported.
- **Android app.** It is a debug build. Not supported: MCPTT chat calls and the conference subscription, first-to-answer
  calls, ambient listening, call-back, transfer and forwarding, functional aliases, floor queueing, MCPTT media and XML
  protection, MCData over MSRP, IP connectivity, enhanced status and the message store, and the SIP subscriptions to
  the CMS and GMS documents (it reads them with XCAP). It has not been run over a 4G or 5G bearer.
- **Other limits** of each service are in the feature list, [current limits](docs/FEATURES.md#current-limits).

## Verification of this release

The release commits passed, on images built from them:

| Check | Result |
|---|---|
| Lab regression (`tools/regress.py --all`), debug TCP SIP | 122 of 122 scenarios and wire checks |
| Lab regression, TLS SIP | 93 of 93 |
| Unit test tutorials, each new capture checked against its documented flow | 21 of 21 |
| Tutorial 1 start-up | 17 of 17 services healthy |

The Helm chart was checked with `helm lint`, `helm template` and kubeconform (Kubernetes 1.30, strict): 50 of 50
manifests valid.

## Licence

openMCX is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).
Third-party software and its licences: [NOTICE](NOTICE).
