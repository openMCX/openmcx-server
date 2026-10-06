# OAI CN5G with N5 QoS for tutorial 3

Tutorial 3's 5G core is OAI CN5G v2.2.1. Four of its network functions need changes so that the MCPTT server can
ask for MCPTT QoS over N5 (TS 29.514): the PCF turns the AF's media components into a PCC rule with 5QI 65, the SMF
modifies the PDU session for it (a new QoS flow, TS 23.502 clause 4.3.3.2), and the UPF keeps all the flow's packet
rules. When the RAN cannot set the flow up (tutorial 4's srsUE has one QoS flow only), the AMF passes its PDU Session
Resource Modify Response on (TS 38.413 9.2.1.6), the SMF removes the flow at the UPF and reports the PCC rule as
inactive (RES_ALLO_FAIL, TS 29.512), and the PCF notifies the AF (FAILED_RESOURCES_ALLOCATION, TS 29.514 4.2.5): the
traffic stays on the session's default flow. The other network functions and the RAN are OAI's unmodified images.

| Path | What |
|---|---|
| `patches/oai-cn5g-{amf,pcf,smf,upf}/` | The changes against v2.2.1 (`git format-patch`): `0001` the feature, `0002` the notices of modification, `0003` QoS flows the RAN refuses (PCF, SMF), `0004` a flow missing from the RAN's list of added flows counts as refused (SMF) |
| `build-images.sh` | Clones v2.2.1 into `src/` at the pinned commit, applies the patches and builds `oai-{amf,pcf,smf,upf}:mcx-n5` (about 30 minutes each) |
| `package-images.sh` | Adds the license, the notices, the patches and `SOURCE` (commits, patch hashes): `openmcx/oai-{amf,pcf,smf,upf}:mcx-n5`; `--push` publishes them |
| `LICENSE`, `NOTICE` | The Collaborative Standards Software License v1.0 that this directory is under, and what the images contain |

```bash
oai/cn5g/build-images.sh                  # all four; or e.g.: oai/cn5g/build-images.sh pcf
```

The tutorial uses `openmcx/oai-{amf,pcf,smf,upf}:mcx-n5` from Docker Hub; set `AMF_IMG`, `PCF_IMG`, `SMF_IMG` and
`UPF_IMG` in `.env` to `oai-amf:mcx-n5` and so on to use images built here.

**Pinned sources:** the patches apply to these commits of the v2.2.1 tag. `build-images.sh` checks out the commit and
stops if the tag points elsewhere; the submodules come at the commits the release records. Each image has the commit
(`org.opencontainers.image.revision`) and the SHA-256 of its patches (`org.openmcx.patches.sha256`) as labels, and the
published images list both, with the submodule commits, in `/usr/share/doc/openmcx-oai/SOURCE`.

| Network function | Tag | Commit |
|---|---|---|
| [oai-cn5g-amf](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-amf) | v2.2.1 | `513c0f2dc4175e7d8f099a41d4a797913d3cf40e` |
| [oai-cn5g-pcf](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-pcf) | v2.2.1 | `e4780235d0115e58b18b33cef17903f224b69a2c` |
| [oai-cn5g-smf](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-smf) | v2.2.1 | `53af440450d2ece3a3908ba9f87febc4187d232c` |
| [oai-cn5g-upf](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf) | v2.2.1 | `451c27daa4b38bd03a5cb5b92412743364ff8ae0` |

**License:** this directory is under the Collaborative Standards Software License v1.0 (CSSL), not the license of the
rest of openmcx-server. The patent license granted with OAI covers study, testing and research only; see `NOTICE`.

**PCF details:** AppSessionContext media components become the PCC rule `mcx-<appSessionId>-<n>` and a QoS decision.
Audio maps to 5QI 65 GBR, with GBR = MBR = marBw. Reservation priority PRIO_16 maps to ARP 1, PRIO_12 to PRIO_15 to
ARP 2, and no priority to ARP 3. The PCF also supports PATCH (merge-patch) and delete, and sends an
SmPolicyUpdateNotify with only the changed rules. Its Dockerfile installs libodb 2.5 with build2 0.18.1.
