#!/bin/bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# The core of the --srsran lab (docker/srsran): the EPC (srsepc: MME, HSS and SP-GW) the eNodeBs attach to, and the
# MBMS gateway (srsmbms) that sends what reaches its SGi-mb interface to every eNodeB over M1-U (GTP-U to an IP
# multicast group on the lab network). The MCx servers send their host groups to the lab network as without the
# radio; smcroute forwards them from eth0 into SGi-mb, so they reach the clients only over the eNodeBs' MBSFN.
#
# Usage: ran-core.sh UE-COUNT HOST-GROUP...
set -euo pipefail

ues=$1
shift
out=/artifacts/ran-core
mkdir -p "$out"
share=/usr/local/share/srsran
address=$(ip -4 -o addr show eth0 | awk '{split($4, a, "/"); print a[1]}')

# The HSS: one subscriber per UE (test PLMN 001/01, Milenage with the srsRAN example K and OPc).
: > "$out/user_db.csv"
for index in $(seq 1 "$ues"); do
  printf 'ue%d,mil,00101000000000%d,00112233445566778899aabbccddeeff,opc,63bfa50ee6523365ff14c1f45f88737d,8000,000000001234,7,dynamic\n' \
    "$index" "$index" >> "$out/user_db.csv"
done

srsepc "$share/epc.conf.example" --hss.db_file="$out/user_db.csv" --mme.mme_bind_addr="$address" \
  --spgw.gtpu_bind_addr="$address" --log.filename="$out/epc.log" > "$out/epc.out" 2>&1 &
srsmbms "$share/mbms.conf.example" --mbms_gw.sgi_mb_if_addr=10.99.0.254 --mbms_gw.m1u_multi_if="$address" \
  --mbms_gw.m1u_multi_ttl=1 --log.filename="$out/mbms.log" --log.all_level=info > "$out/mbms.out" 2>&1 &
for _ in $(seq 1 50); do
  ip link show sgi_mb > /dev/null 2>&1 && break
  sleep 0.2
done

# Host groups from the lab network to SGi-mb. The servers send with time-to-live 1 (RFC 1112: not forwarded), as an
# MBMS bearer starts at the BM-SC; the radio is one hop that the lab adds, so the TTL is raised to 2 before forwarding.
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.eth0.rp_filter=0
nft add table ip lab
nft 'add chain ip lab radio { type filter hook prerouting priority mangle; }'
nft add rule ip lab radio iifname eth0 ip daddr 239.10.0.0/16 ip ttl set 2
{
  echo 'phyint eth0 enable'
  echo 'phyint sgi_mb enable'
  for group in "$@"; do echo "mgroup from eth0 group ${group%:*}"; done
  for group in "$@"; do echo "mroute from eth0 group ${group%:*} to sgi_mb"; done
} > "$out/smcroute.conf"
smcrouted -n -N -f "$out/smcroute.conf" -l info > "$out/smcroute.out" 2>&1 &

touch /tmp/ready
wait -n
