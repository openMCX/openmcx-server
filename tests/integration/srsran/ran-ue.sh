#!/bin/bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# One UE of the --srsran lab (docker/srsran): an eNodeB of its own with eMBMS (SIB13, MCCH, MTCH from the MBMS
# gateway in ran-core) and a UE (srsue) attached to it over ZeroMQ instead of an SDR. The client runs in this
# container's network namespace: the host groups are routed to the UE's tun_srsue, so the client's joins and the
# subchannels' datagrams go over the radio; SIP and unicast media stay on the lab network.
#
# Usage: ran-ue.sh NAME INDEX
set -euo pipefail

name=$1
index=$2
out=/artifacts/$name
mkdir -p "$out"
share=/usr/local/share/srsran
address=$(ip -4 -o addr show eth0 | awk '{split($4, a, "/"); print a[1]}')
core=$(getent hosts ran-core | awk '{print $1}')

srsenb "$share/enb.conf.example" --enb.enb_id="0x$((410 + index))" --enb.mme_addr="$core" \
  --enb.gtp_bind_addr="$address" --enb.s1c_bind_addr="$address" --enb.n_prb=25 \
  --enb_files.sib_config="$share/sib.conf.mbsfn.example" --enb_files.rr_config="$share/rr.conf.example" \
  --enb_files.rb_config="$share/rb.conf.example" \
  --rf.device_name=zmq \
  --rf.device_args='fail_on_disconnect=true,tx_port=tcp://*:2000,rx_port=tcp://localhost:2001,id=enb,base_srate=23.04e6' \
  --embms.enable=true --embms.m1u_if_addr="$address" --embms.m1u_multiaddr=239.255.0.1 \
  --scheduler.min_nof_ctrl_symbols=2 --scheduler.max_nof_ctrl_symbols=2 --expert.nof_phy_threads=2 \
  --expert.rrc_inactivity_timer=86400000 \
  --log.filename="$out/enb.log" --log.all_level=warning > "$out/enb.out" 2>&1 &
sleep 2
srsue "$share/ue.conf.example" --usim.imsi="00101000000000$index" --usim.k=00112233445566778899aabbccddeeff \
  --usim.opc=63bfa50ee6523365ff14c1f45f88737d --usim.algo=milenage --rf.device_name=zmq \
  --rf.device_args='tx_port=tcp://*:2001,rx_port=tcp://localhost:2000,id=ue,base_srate=23.04e6' \
  --rrc.mbms_service_id=0 --phy.interpolate_subframe_enabled=true --phy.snr_estim_alg=empty \
  --phy.nof_phy_threads=2 --log.filename="$out/ue.log" --log.all_level=warning > "$out/ue.out" 2>&1 &

for _ in $(seq 1 150); do
  grep -q 'MBMS service started' "$out/ue.out" 2> /dev/null && ip -4 addr show tun_srsue 2> /dev/null | grep -q inet && break
  sleep 0.2
done
# The host groups over the radio only: the lab bridge floods the servers' datagrams to eth0 too, which are dropped.
# The servers' addresses are on the lab network, not behind tun_srsue, so the reverse path filter would drop the
# subchannels' datagrams.
ip route add 239.10.0.0/16 dev tun_srsue
nft add table ip lab
nft 'add chain ip lab radio { type filter hook prerouting priority raw; }'
nft add rule ip lab radio iifname eth0 ip daddr 239.10.0.0/16 counter drop
# Nothing goes up over the radio: the joins' IGMP reports would wake the UE from RRC idle for nothing (srsUE's MBMS
# reception does not always survive the service request).
nft 'add chain ip lab uplink { type filter hook output priority filter; }'
nft add rule ip lab uplink oifname tun_srsue counter drop
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.tun_srsue.rp_filter=0
touch /tmp/ready
wait -n
