#!/bin/sh
# Tutorial 3: this computer's part of the path between the openMCX system and the 5G UEs (run with sudo).
#
#   sudo ./host-network.sh add       before `up`
#   sudo ./host-network.sh remove    after `down`
#
# - The UE pool 12.1.1.0/24 is reached through the UPF (its N6 address): replies of the openMCX system to a UE go back
#   through the 5G user plane.
# - Packets of the openMCX containers to the UE pool leave from HOST_IP, the address the UE reaches the system at:
#   the UE sees the same address both ways, and the PCF's packet filters (the server's address in the SDP, HOST_IP)
#   match the speech the UPF carries.
set -eu
cd "$(dirname "$0")"
HOST_IP=$(sed -n 's/^HOST_IP=//p' .env 2>/dev/null)
[ -n "$HOST_IP" ] || { echo "set HOST_IP in .env first" >&2; exit 1; }
POOL=12.1.1.0/24 UPF=192.168.72.134 N6=192.168.72.128/26
case "${1:-}" in
  add)
    ip route replace "$POOL" via "$UPF"
    iptables -t nat -C POSTROUTING -s "$N6" -d "$POOL" -j SNAT --to-source "$HOST_IP" 2>/dev/null ||
      iptables -t nat -I POSTROUTING 1 -s "$N6" -d "$POOL" -j SNAT --to-source "$HOST_IP"
    echo "added: route $POOL via $UPF; SNAT $N6 -> $POOL to $HOST_IP" ;;
  remove)
    ip route del "$POOL" via "$UPF" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$N6" -d "$POOL" -j SNAT --to-source "$HOST_IP" 2>/dev/null || true
    echo "removed" ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
