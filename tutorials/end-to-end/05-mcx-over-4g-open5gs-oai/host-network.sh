#!/bin/sh
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# Tutorial 5: this computer's part of the path between the OpenMCX system and the LTE UEs (run with sudo).
#
#   sudo ./host-network.sh add       before `up`
#   sudo ./host-network.sh remove    after `down`
#
# - The UE pool 10.45.0.0/16 is reached through the UPF, the P-GW's user plane (its SGi address): replies of the
#   OpenMCX system to a UE go back through the LTE user plane.
# - Packets of the OpenMCX containers to the UE pool leave from HOST_IP, the address the UE reaches the system at:
#   the UE sees the same address both ways, and the PCRF's packet filters (the server's address in the SDP, HOST_IP)
#   match the speech the P-GW carries. Not those of the P-CSCF (192.168.74.140), which reaches the UE through the UPF
#   itself: its IPsec security associations with the UE are bound to its own address (TS 33.203 clause 7.1).
# - The kernel's IPsec (XFRM netlink and ESP) for those security associations, loaded if it is a module.
set -eu
cd "$(dirname "$0")"
HOST_IP=$(sed -n 's/^HOST_IP=//p' .env 2>/dev/null)
[ -n "$HOST_IP" ] || { echo "set HOST_IP in .env first" >&2; exit 1; }
POOL=10.45.0.0/16 UPF=192.168.74.134 N6=192.168.74.128/26 PCSCF=192.168.74.140
case "${1:-}" in
  add)
    ip route replace "$POOL" via "$UPF"
    iptables -t nat -C POSTROUTING -s "$N6" -d "$POOL" -j SNAT --to-source "$HOST_IP" 2>/dev/null ||
      iptables -t nat -I POSTROUTING 1 -s "$N6" -d "$POOL" -j SNAT --to-source "$HOST_IP"
    # First, before the SNAT rule (Docker's bridge may pass the P-CSCF's packets to the UPF through the host's nat
    # table).
    iptables -t nat -D POSTROUTING -s "$PCSCF" -d "$POOL" -j RETURN 2>/dev/null || true
    iptables -t nat -I POSTROUTING 1 -s "$PCSCF" -d "$POOL" -j RETURN
    modprobe -a xfrm_user esp4 authenc 2>/dev/null ||
      echo "the kernel modules xfrm_user, esp4 and authenc could not be loaded: IMS AKA needs them" >&2
    echo "added: route $POOL via $UPF; SNAT $N6 -> $POOL to $HOST_IP, except the P-CSCF $PCSCF" ;;
  remove)
    ip route del "$POOL" via "$UPF" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$N6" -d "$POOL" -j SNAT --to-source "$HOST_IP" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$PCSCF" -d "$POOL" -j RETURN 2>/dev/null || true
    echo "removed" ;;
  *) sed -n '2,15p' "$0"; exit 1 ;;
esac
