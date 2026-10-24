# OpenMCX 1.0.0 — release notes

Release 1.0.0, 2026-10-15: the first release of the **standalone edition** of OpenMCX, 3GPP Release 19 mission-critical
services (MCX) for an IP network. One MC system, on-network, with the three services MCPTT, MCData and MCVideo, their
common services, a SIP core, the clients and MCX Admin, as containers that start on one computer.

## Since 1.0.0 (main and the `develop` images)

- **Access token scopes.** The CMS, GMS, LMS, KMS and the MCData content server, message store and notification server
  check the scope of the access token (TS 33.180 clause 5.1.3.1 and table B.4.2.2-1). The clients of release 1.0.0
  (the Linux client, the dispatcher and the Android app `openmcx-client-v1.apk`) do not ask for the configuration and
  group management scopes, so they are refused by these servers: use the clients of the same images (`develop`) or
  `openmcx-client-develop.apk`. The 1.0.0 images keep working together.

## What 1.0.0 provides

- **MCPTT**: prearranged, chat, broadcast and ad hoc group calls with floor control and queueing; private calls in every
  commencement mode, with or without floor control; first-to-answer, remotely initiated and ambient listening calls;
  emergency and imminent peril with pre-emption and alerts; call-back, transfer and forwarding; functional aliases,
  regroups and location.
- **MCData**: short data over the signalling and media planes, one-to-one, group and ad hoc; file distribution over HTTP
  and over the media plane; emergency and imminent-peril communications and alerts; IP connectivity, enhanced status,
  communication release, functional aliases, the message store and location.
- **MCVideo**: group, chat and ad hoc calls with transmission and reception control; private calls; emergency and
  imminent peril; video pull and push, ambient viewing, regroups, functional aliases, remote group selection and
  location.
- **Security** (TS 33.180): OIDC identity, KMS key distribution, end-to-end protected media (GMK, PCK), protected floor
  and transmission control, and protected and signed XML signalling.
- **Common services**: identity, group, configuration, location and key management, the message store and the content
  server; separate participating and controlling servers within one system.
- **QoS on 4G and 5G**: the MCPTT and MCVideo servers request MCPTT QoS from the core as application function, over Rx
  (4G) and N5 (5G), shown in tutorials 3 to 5.
- **Clients and administration**: the Android app, the dispatcher position in the browser, the headless Linux client,
  and MCX Admin for users, groups, rights and device activation.

The full list, per service and with the clauses, is the [feature list](docs/FEATURES.md); the specifications and
versions the code follows are in [docs/SPECS.md](docs/SPECS.md).

## Components and images

| Part | Repository | What it is | Images (Docker Hub `openmcx/`) |
|---|---|---|---|
| Servers and common services | [openmcx-server](https://github.com/openMCX/openmcx-server) | MCPTT, MCVideo and MCData servers (participating and controlling functions); IdMS, GMS, CMS, KMS, LMS, Credential Service, content server, message store, notification server; HTTP proxy; user database; the tutorials and the lab tools | `openmcx-mcptt-server`, `openmcx-mcvideo-server`, `openmcx-mcdata-server`, `openmcx-common`, `openmcx-http-proxy`, `openmcx-user-db`, `openmcx-setup`, `openmcx-kamailio` |
| Clients | [openmcx-client](https://github.com/openMCX/openmcx-client) | The Android app (`android/apk/openmcx-client-v1.apk`), the dispatcher position in the browser, and `mcx-client`, the headless Linux client | `openmcx-client`, `openmcx-dispatcher` |
| MCX Admin | [openmcx-admin](https://github.com/openMCX/openmcx-admin) | MC user profiles, groups and rights, client activation | `openmcx-admin` |
| Helm chart (experimental) | [openmcx-server `helm/openmcx`](helm/openmcx/README.md) | The tutorial 1 system on Kubernetes or OpenShift; validated with `helm lint`, `helm template` and kubeconform, **not yet installed on a cluster** | (the images above) |

Every OpenMCX image, `openmcx-kamailio` (Kamailio 6.1.4) and `openmcx-admin` included, is published with the one tag
`1.0.0`, the tag the tutorials and the Helm chart use.

| Repository | Release commit |
|---|---|
| openmcx-server | tag `v1.0.0` |
| openmcx-client | tag `v1.0.0` (`9fcea43`) |
| openmcx-admin | tag `v1.0.0` (`e8a3587`) |

The digests of the published images; `docker pull openmcx/<image>@sha256:<digest>` gets exactly the release
image, whatever happens to the tag later.

| Image (tag `1.0.0`) | Digest |
|---|---|
| `openmcx-mcptt-server` | `sha256:6befb2a07b940a8b62c4fc258f79f64c449c67ff83d643b4705291a4a1b2fcc9` |
| `openmcx-mcvideo-server` | `sha256:abd46f73d437fb313d48ffebe5d4ca1528340c8d74d522eac3c22267df9ff0c6` |
| `openmcx-mcdata-server` | `sha256:3fe6a11134072562d35e584af680b02131b2fb033f362361a0c4d862e1ddf51c` |
| `openmcx-common` | `sha256:01741977c080a9708944f35ed315028deef09f84429143e4cd70bfe82055276c` |
| `openmcx-http-proxy` | `sha256:4d66d3ff28fd119bc50977819362b5ee1d491c68c1fe4a5af55faa3e5c805840` |
| `openmcx-user-db` | `sha256:086326ac7565c7bfcfc8f865eb37a024df2758a652964443787c1a3eb4d2e98b` |
| `openmcx-setup` | `sha256:a63f4764bbb64c64bab735d3c261fcf1450425d285c9d005022061569e62f936` |
| `openmcx-kamailio` | `sha256:f53a3e47bb5e52ffe208935fd96c9b0eb626ce5fc1a1713a84f01caf22091af0` |
| `openmcx-client` | `sha256:a2a7518c8134ca1be46e2e584c363bd18a00f04c5e11433e73ce8bf12f57df61` |
| `openmcx-dispatcher` | `sha256:9f25d7c3fd0df8aeac636e94d08fbf3545b8f70991da43986d0a9dc05d9fb87d` |
| `openmcx-admin` | `sha256:4580fd66441814930e46288b27685e7cd9338f44f86add0caedf08a1f61989ac` |

The third-party images of the 5G and 4G tutorials, built by OpenMCX, all modified except srsUE (their patches, notices
and build scripts are in the tutorial folders):

| Image | Tutorials | Digest |
|---|---|---|
| `oai-amf:mcx-n5` | 3, 4 | `sha256:df1e48f8d0244f0e8912217e8cf3ef25308d5960e67d8a4014480a6bddf3f60d` |
| `oai-pcf:mcx-n5` | 3, 4 | `sha256:08ebaccbdf355aaf880066950eeaf933ce0eb119853e12d2d97ee12c8cd199d3` |
| `oai-smf:mcx-n5` | 3, 4 | `sha256:7f4007e1c5b18c3c8513959271aefdfe557dd5f3dbfdae724d927670bda7691b` |
| `oai-upf:mcx-n5` | 3, 4 | `sha256:ff91b3a581e4f463e9c3a9272e52a9e919495f8487cb375d677a45c25509f5bf` |
| `openmcx-srsran-gnb:25.10-mcx` | 4 | `sha256:51064b621c83c5ccbc391125b7c613f740e37a78f219d807ed3fe16e22ecd33f` |
| `openmcx-srsue:25.10` | 4 | `sha256:ab4bae2520414fb3199ba26e393b3efc88109ad49a9c3a0750d929cb83aa0618` |
| `open5gs:2.8.0-mcx` | 5 | `sha256:74fd9d3e6e56890e99ef3c9dbc5973506a6992916c1e7a2d70df08de8477afa4` |
| `oai-enb:2026.w39-mcx` | 5 | `sha256:df44fbe08940eaa864d5e964a9ef55c5e5c3dcf12e8c3fa957f1e3960f9a2ee4` |
| `oai-lte-ue:2026.w39-mcx` | 5 | `sha256:8f28d3e282d63c4cdf6ce819641e2f1da8bc08d1536c32d91ddc91f15ee8a231` |

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

## Limitations

What the present edition does not include (off-network, interconnection, MBMS, pre-established sessions, several devices per
user and others) and the known limits of what it implements are listed, checked against the code of this release, in
[LIMITATIONS.md](docs/LIMITATIONS.md). OpenMCX is not an interoperability-certified implementation: it has not yet been
tested against independent implementations.

## Verification of this release

The release images and the commits they are built from passed:

| Check | Result |
|---|---|
| Lab regression (`tools/regress.py --all`), debug TCP SIP and TLS SIP | 123 of 123 and 94 of 94 on the candidate before the last functional changes; on the candidate with them (MCVideo reception control, functional aliases on split servers and in MCData), every failure was a client fault since fixed or a timing miss of an overloaded test host, and passed when run again alone |
| On the release images | smoke and admin labs 4 of 4; the functional alias labs 16 of 16 (TCP) and 9 of 9 (TLS) |
| Unit test tutorials, each new capture checked against its documented flow | 21 of 21 |
| Android app on two phones (Xiaomi, moto g67) | functional aliases and floor queueing 44 of 45, video 127 of 128 (the misses are speech and picture counts over Wi-Fi) |

The Helm chart was checked with `helm lint`, `helm template` and kubeconform (Kubernetes 1.30, strict): 50 of 50
manifests valid.

## Licence

OpenMCX is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).
Third-party software and its licences: [NOTICE](NOTICE).
