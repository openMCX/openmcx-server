# srsRAN 4G for the eMBMS labs

The `srsran` and `srsran-mcvideo` labs (`tools/regress.py`; `tools/prepare-prearranged-test.py --multicast --srsran`)
carry the MBMS bearers of the MCPTT and MCVideo servers over srsRAN 4G eMBMS instead of the lab network. The eNodeB and
the UE exchange baseband samples over ZeroMQ, so no SDR is needed. This document records what srsRAN needed for that:
one source patch, and the build, configuration and host settings around it.

```
docker build -t openmcx-srsran:23.11 docker/srsran
tools/regress.py --images <tag> --client-image openmcx-client:<tag> --select =srsran,=srsran-mcvideo
```

## Baseline

- srsRAN 4G `release_23_11`, commit `eea87b1d893ae58e0b08bc381730c502024ae71f` (pinned in the Dockerfile).
- eMBMS as in the srsRAN app note (docs.srsran.com, 4G, app notes, eMBMS): `srsmbms` (MBMS gateway, SGi-mb TUN
  `sgi_mb`, M1-U to an IP multicast group), `srsenb` with `sib.conf.mbsfn` (SIB2 MBSFN subframes, SIB13) and
  `[embms] enable`, 2 control symbols, `srsue` with `rrc.mbms_service_id=0`, `phy.interpolate_subframe_enabled`,
  `phy.snr_estim_alg=empty`.
- Unpatched, over ZeroMQ, one eNodeB and one UE delivered every datagram (500 of 500 at 20 ms intervals) with the
  group address and port intact, but delayed by 10 to 676 ms (median 339 ms): unusable for speech.

## Source patch: `mch-period-80ms.patch`

**Cause.** srsENB builds the MTCH schedule (`mac::build_mch_sched`) and sends the MCH scheduling information only in
the MCCH subframe, so MTCH data waits for the next MCCH. The MCCH repetition period comes from `sib.conf`
(`mcch_repetition_period`, rf32 at the least), and the MCCH it sends hardcodes a common subframe allocation period and
an MCH scheduling period of rf64 (640 ms). Changing the MCH scheduling period alone has no effect: the delay stays at
640 ms because the schedule is still rebuilt only with the MCCH.

**Change.** Everything at 80 ms (rf8), the shortest MCH scheduling period, in the eNodeB and the UE alike:

| File | Change |
| --- | --- |
| `srsenb/src/stack/rrc/rrc.cc` `configure_mbsfn_sibs()` | `common_sf_alloc_period` rf64 → rf8; `mch_sched_period` rf64 → rf8; `sf_alloc_end` 64 × 6 → 8 × 6 (6 MBSFN subframes per frame) |
| `srsenb/src/stack/rrc/rrc.cc` `pack_mcch()` (the MCCH sent) | `common_sf_alloc_period_r9` rf64 → rf8; `mch_sched_period_r9` rf64 → rf8; `sf_alloc_end_r9` 64 × 6 → 8 × 6 |
| `srsenb/src/phy/phy_common.cc` `is_mcch_subframe()` | MCCH (with the MCH scheduling information) every 8 frames instead of `mcch_repeat_period` |
| `srsue/src/phy/phy_common.cc` `is_mcch_subframe()` | the same in the UE, which otherwise looks for the MCCH every `mcch_repeat_period` |

The PHY change departs from TS 36.331: the MCCH repetition period in SIB13 still says rf64, and the UE does not follow
it. That is acceptable only because both ends are this patched srsRAN; a commercial UE would not decode this cell's
MCCH and MCH as intended.

**Result.** 500 of 500 datagrams at 20 ms intervals, delay 9 to 92 ms (median 52 ms). In the four-UE lab the
subchannel speech arrived within 90 ms.

## Build (`Dockerfile`)

- ZeroMQ RF driver only: `ENABLE_ZEROMQ=ON`, UHD, bladeRF, SoapySDR, GUI, RF plugins and tests off; built targets
  `srsenb srsue srsepc srsmbms`.
- `sib.conf.mbsfn.example` is not installed by `make install`; the Dockerfile copies it to `/usr/local/share/srsran/`.
- Run-time packages beyond srsRAN's libraries: `iproute2`, `nftables`, `smcroute`, `procps`. The `iptables` TTL target
  did not work in this image (`unknown option "--ttl-inc"`, nft and legacy back ends), so nftables is used.

## Configuration and host settings (`tests/integration/srsran/`)

All on the command line over the installed `*.example` files; nothing else in srsRAN is changed.

`ran-core.sh` (one container: EPC and MBMS gateway):

- `srsepc` bound to the container's lab address (`mme.mme_bind_addr`, `spgw.gtpu_bind_addr`); an HSS file with one
  Milenage subscriber per UE (PLMN 001/01, `00101000000000N`, the srsRAN example K and OPc).
- `srsmbms` with `sgi_mb_if_addr=10.99.0.254` (the example's 172.16.0.254 is in the SP-GW's 172.16.0.0/24) and
  `m1u_multi_if` on the lab address, so M1-U reaches the eNodeBs of the other containers over the lab bridge.
- The MCx servers send their host groups to the lab network as without the radio. smcroute joins those groups on
  `eth0` and forwards them into `sgi_mb` (`mgroup` and `mroute` lines, one per group of the bearers).
- The servers send with TTL 1 (RFC 1112: not forwarded, as an MBMS bearer starts at the BM-SC); nftables sets TTL 2 on
  `eth0` for 239.10.0.0/16 before forwarding. The servers' configuration and the wire checks' TTL 1 stay as they are.
- `rp_filter` 0.

`ran-ue.sh` (one container per client: an eNodeB of its own and a UE; the client shares the network namespace):

- One eNodeB per UE: a ZeroMQ eNodeB serves one UE without a broker. Each has its own `enb_id`, S1 to the MME in
  ran-core, `m1u_if_addr` on its lab address, 25 PRB, `base_srate=23.04e6`.
- `expert.rrc_inactivity_timer=86400000`: with the default 30 s the eNodeB releases the RRC connection; the next uplink
  packet starts a service request, and in one run srsUE's MBMS reception stopped after it.
- Nothing goes up over the radio: an nftables output rule drops everything to `tun_srsue` (the joins' IGMP reports
  would otherwise wake the UE). SIP and unicast media use the lab network.
- `ip route add 239.10.0.0/16 dev tun_srsue`, so the client's joins (interface 0.0.0.0) are on the UE's interface.
- `rp_filter` 0: the servers' addresses are on the lab network, not behind `tun_srsue`, so the reverse path filter
  drops the MTCH datagrams (seen: tcpdump showed them on `tun_srsue`, the socket received none).
- The lab bridge floods the servers' host groups to `eth0` too; an nftables rule drops 239.10.0.0/16 arriving there,
  so the radio is the only multicast path.

`tools/prepare-prearranged-test.py` (`add_srsran`): the clients get `network_mode: service:ran-<x>`, and the ran
container carries the client's name as a network alias. `multicast_scenario.py` reads a client's address from the
container whose namespace it shares.

## Limits

- One MBSFN area, one PMCH, one MTCH (LCID 1) and a fixed service: every host group shares the one MTCH, and the UE's
  kernel sorts the datagrams by group. The TMGIs and announcements of the MCx servers are end-to-end signalling; srsUE
  does not activate or deactivate per TMGI (the clients' emulated MBMS interface, `mbms area|quality`, still decides).
- eMBMS only: the 5G MBS labs (`--mbs`) have no srsRAN equivalent here.
- Four eNodeB/UE pairs take about 65 % of a core each, so the labs run alone (`alone=True`).

## What the radio found in OpenMCX

The radio's delay (up to an MCH scheduling period) exposed three client faults the emulated lab could not
(openmcx-client `MBMS: radio delay at path changes`; finding M25 in `docs/3GPP_CORRECTION_CANDIDATES.md`):

1. A Floor Idle repeated on T7 over the subchannel arrived after the unicast Floor Granted that followed it, and the
   talker released the floor 47 ms after the grant.
2. At the change from the subchannel to unicast, the first unicast packets overtook the radio's last ones, which the
   duplicate check dropped as old.
3. After joining a subchannel the radio still delivered packets sent just before, which the client had had by unicast:
   one packet was decoded twice.
