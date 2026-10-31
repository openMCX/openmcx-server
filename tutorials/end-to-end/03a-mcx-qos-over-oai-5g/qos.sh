#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# Tutorial 3a: tutorial 3 with the openMCX QoS RAN and core (docker-compose-qos.yaml), two MC UEs and two load UEs.
#
#   ./qos.sh setup                   make tutorial 3's configuration, with client-b as the second UE's MC client and
#                                    MCVideo over N5
#   ./qos.sh up                      start (adds the host route and NAT), the load UEs and the iperf server included
#   ./qos.sh down | ps               stop (removes the route and NAT) / status
#   ./qos.sh call [seconds]          client-d (UE 1) calls the group operations, holds the floor and talks for the
#                                    given time (default 10), releases, hangs up; client-b (UE 2) is a member
#   ./qos.sh vcall [seconds]         the same as an MCVideo group call: client-d sends video (noise pictures at
#                                    VIDEO_KBPS) for the given time (default 10); client-b receives
#   ./qos.sh video-config            apply VIDEO_KBPS, VIDEO_SIZE again (setup/mcvideo.py), restart the MCVideo
#                                    server, the P-CSCF and the clients
#   ./qos.sh load start <dl|ul|both> [rate] [seconds]
#                                    UDP best effort from/to the load UEs (default 200M for 600 s); load stop ends it
#   ./qos.sh measure <voice|video> [runs] [rate] [seconds]
#                                    per run: start the load (both ways, default 50M per load UE), capture one call
#                                    of the given length (default 15 s), print the MC flow's loss and one-way delay
#                                    per hop (hops.py) into results/; then delete the capture
#   ./qos.sh compose <args...>       docker compose on the system
#
# LOAD_UES: the UEs that load (default "3 4"; 1 and 2 load on their best-effort PDU session).
# Settings (images, cell, admission): .env, after tutorial 3's .env; a variable set in the shell wins.
set -euo pipefail
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TUT=${TUTORIAL3:-$DIR/../03-mcx-over-oai-5g}
IPERF=192.168.72.150
export TUTORIAL3A_DIR=$DIR
[ -f "$TUT/.env" ] || { echo "set up $TUT/.env first (tutorial 3 step 1: HOST_IP)" >&2; exit 1; }
[ -f "$DIR/.env" ] || { echo "cp .env.example .env first (step 2)" >&2; exit 1; }
[ -f "$DIR/generated/oai_db.sql" ] || python3 "$DIR/setup/internet.py" "$TUT" >&2
[ -f "$DIR/media/tone.wav" ] || python3 "$DIR/media/make-tone.py" "$DIR/media/tone.wav"
# Tutorial 3's profile ims-aka: the P-CSCF and the MC client in UE 1.
compose() {
  docker compose --project-directory "$TUT" --env-file "$TUT/.env" --env-file "$DIR/.env" \
    -f "$TUT/docker-compose-5g-mcx.yaml" -f "$DIR/docker-compose-qos.yaml" --profile ims-aka "$@"
}
mc() { docker exec "$1" mcx-client --config /run/mcx/ue-client.json --command "$2"; }  # <container> <command>
event() { docker logs --since "$2" "$1" 2>&1 | grep -c "\"event\":\"$3\"" || true; }    # <container> <since> <event>
# The iperf server reaches the UEs through the UPF with its own address, as the P-CSCF does: no SNAT to HOST_IP.
iperf_nat() { sudo iptables -t nat -D POSTROUTING -s "$IPERF" -d 12.1.0.0/16 -j RETURN 2>/dev/null || true
  [ "$1" = add ] && sudo iptables -t nat -I POSTROUTING 1 -s "$IPERF" -d 12.1.0.0/16 -j RETURN; true; }

load_ue() {  # <n>: ue, tun, dl_port, ul_port
  case $1 in
    1) ue=openmcx-oai-nr-ue tun=oaitun_ue1p2 dl_port=5205 ;;
    2) ue=openmcx-oai-nr-ue2 tun=oaitun_ue1p2 dl_port=5207 ;;
    3|4) ue=openmcx-oai-nr-ue$1 tun=oaitun_ue1 dl_port=$((5201 + 2 * ($1 - 3))) ;;
    *) echo "no load UE $1" >&2; exit 2 ;;
  esac
  ul_port=$((dl_port + 1))
}

case ${1:-} in
  setup)
    if [ -e "$TUT/config" ]; then
      echo "$TUT/config exists: ./qos.sh down, then './qos.sh compose down -v' and rm -rf it to start over" >&2; exit 1
    fi
    compose run --rm setup ;;
  up)
    # The host route and NAT before the clients sign in (compose up waits for them to be healthy).
    compose --profile load up -d --no-start
    sudo "$TUT/host-network.sh" add
    iperf_nat add
    compose --profile load up -d || echo "compose up: not every service came up" >&2
    compose --profile load ps --format 'table {{.Name}}\t{{.Status}}' | grep -v '(healthy)' || echo "all services healthy" ;;
  down)
    compose --profile load --profile dispatcher down
    iperf_nat remove
    sudo "$TUT/host-network.sh" remove || true ;;
  ps) compose --profile load ps --format 'table {{.Name}}\t{{.Image}}\t{{.Status}}' ;;
  call)
    seconds=${2:-10}; since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    mc openmcx-ue-client call
    for _ in $(seq 1 20); do [ "$(event openmcx-ue-client "$since" call_active)" -gt 0 ] && break; sleep 0.5; done
    [ "$(event openmcx-ue-client "$since" call_active)" -gt 0 ] || {
      echo "call not connected:" >&2; docker logs --since "$since" openmcx-ue-client 2>&1 | tail -5 >&2; exit 1; }
    echo "call connected; talking ${seconds} s"
    mc openmcx-ue-client "ptt /media/tone.wav"
    sleep "$seconds"
    mc openmcx-ue-client release; sleep 1
    mc openmcx-ue-client hangup; sleep 2
    echo "client-b joined: $(event openmcx-ue2-client "$since" call_active) call(s)" ;;
  vcall)
    seconds=${2:-10}; since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    live=$(docker exec openmcx-ue-client python3 -c "import json;l=json.load(open('/run/mcx/ue-client.json'))['mcvideo']['live'];print(l['fifo'],l['width'],l['height'],l['frame_rate'])")
    # MCVideo affiliation (TS 24.281 clause 9.2.2): explicit, unlike MCPTT's from the user profile
    mc openmcx-ue-client mcvideo-affiliate; mc openmcx-ue2-client mcvideo-affiliate; sleep 2
    mc openmcx-ue-client mcvideo-call
    for _ in $(seq 1 20); do [ "$(event openmcx-ue-client "$since" mcvideo_call_active)" -gt 0 ] && break; sleep 0.5; done
    [ "$(event openmcx-ue-client "$since" mcvideo_call_active)" -gt 0 ] || {
      echo "video call not connected:" >&2; docker logs --since "$since" openmcx-ue-client 2>&1 | grep -i mcvideo | tail -5 >&2; exit 1; }
    # shellcheck disable=SC2086 # the FIFO, width, height and frame rate, as words
    docker exec -d openmcx-ue-client python3 /media/video-feeder.py $live $((seconds + 5))
    mc openmcx-ue-client mcvideo-transmit
    echo "video call connected; sending ${seconds} s ($live)"
    sleep "$seconds"
    mc openmcx-ue-client mcvideo-release; sleep 1
    mc openmcx-ue-client mcvideo-hangup; sleep 2
    docker exec openmcx-ue-client pkill -f video-feeder.py || true
    echo "client-b joined: $(event openmcx-ue2-client "$since" mcvideo_call_active) video call(s)" ;;
  video-config)
    compose run --rm --entrypoint python3 setup /tutorial3a/mcvideo.py
    # The P-CSCF too: it keeps the clients' registrations and IPsec SAs in memory, and would send to a recreated
    # client on its old SAs (the affiliation NOTIFY never arrives). pcscf-route shares its network namespace.
    # --no-deps: not the nr-UEs (a re-attached UE gets a new address); in order, each healthy before the next.
    for services in "mcvideo-server pcscf pcscf-route" ue-client ue2-client; do
      # shellcheck disable=SC2086 # the services, as words
      compose up -d --no-deps --force-recreate --wait $services
    done ;;
  load)
    ues=${LOAD_UES:-3 4}
    case ${2:-} in
      start)
        dir=${3:?dl, ul or both} rate=${4:-200M} seconds=${5:-600}
        for n in $ues; do
          load_ue "$n"
          docker exec "$ue" ip route replace "$IPERF/32" dev "$tun"
          src=$(docker exec "$ue" ip -4 -o addr show "$tun" | awk '{print $4}' | cut -d/ -f1)
          [ -n "$src" ] || { echo "UE $n: no $tun yet" >&2; exit 1; }
          # -R: the server sends (downlink); the default: the UE sends (uplink).
          case $dir in dl|both) docker exec -d "$ue" iperf3 -c "$IPERF" -B "$src" -p $dl_port -u -b "$rate" -t "$seconds" -R --logfile /tmp/dl.log ;; esac
          case $dir in ul|both) docker exec -d "$ue" iperf3 -c "$IPERF" -B "$src" -p $ul_port -u -b "$rate" -t "$seconds" --logfile /tmp/ul.log ;; esac
        done
        sleep 3; echo "load $dir at $rate per UE ($ues) for $seconds s" ;;
      stop)
        for n in $ues; do
          load_ue "$n"
          docker exec "$ue" pkill iperf3 || true
          for f in dl ul; do docker exec "$ue" sh -c "[ -f /tmp/$f.log ] && tail -4 /tmp/$f.log && rm /tmp/$f.log" || true; done
        done ;;
      *) echo "load start <dl|ul|both> [rate] [seconds] | load stop  (LOAD_UES=\"3 4\")" >&2; exit 2 ;;
    esac ;;
  measure)
    what=${2:?voice or video} runs=${3:-1} rate=${4:-50M} talk=${5:-15}
    case $what in voice) call=call port=4500 ;; video) call=vcall port=6700 ;; *) echo "voice or video" >&2; exit 2 ;; esac
    name=$what-$(date +%H%M%S)
    mkdir -p "$DIR/captures" "$DIR/results"; out=$DIR/results/$name.txt
    {
      echo "# $name: $runs run(s), $call (UE port $port), load both ways $rate on UE(s) ${LOAD_UES:-3 4}, $talk s"
      echo "# images: $(docker ps --format '{{.Names}}={{.Image}}' | grep -E 'oai-(gnb|nr-ue|smf|upf|amf)=|ue-client=' | sort | tr '\n' ' ')"
      echo "# gNB options: $(docker inspect openmcx-oai-gnb -f '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^USE_ADDITIONAL_OPTIONS=//p')"
    } > "$out"
    br() { echo "br-$(docker network inspect -f '{{.Id}}' "$1" | cut -c1-12)"; }
    # Not the rfsimulator's samples (TCP 4043), nor the load: on N6 the iperf server's packets; on the core network
    # the GTP-U packets of iperf (inner UDP ports 5201-5208) and the fragments of the inner packets after the first.
    load_gtp='udp port 2152 and (ether[78:2] >= 5201 and ether[78:2] <= 5208 or ether[80:2] >= 5201 and ether[80:2] <= 5208 or ether[64:2] & 0x1fff != 0)'
    n3_fragment='host 192.168.71.140 and ip[6:2] & 0x1fff != 0'
    for i in $(seq 1 "$runs"); do
      "$0" load start both "$rate" $((talk + 30)) >/dev/null
      sleep 3
      cap=$DIR/captures/$name-$i.pcapng
      sudo dumpcap -q -i "$(br openmcx-5g-core)" -f "not tcp port 4043 and not ($n3_fragment) and not ($load_gtp)" -B 64 \
        -i "$(br openmcx-5g-n6)" -f "not host $IPERF" -B 64 -w - 2>/dev/null > "$cap" & pid=$!
      # The MC UEs' own side: their TUN in each nr-UE's network namespace, MC media only (UDP 4000-6999)
      ue_pids=()
      for ue in 1 2; do
        c=openmcx-oai-nr-ue; [ "$ue" = 1 ] || c=$c$ue
        sudo nsenter -t "$(docker inspect -f '{{.State.Pid}}' "$c")" -n tcpdump -q -i oaitun_ue1 -s 128 \
          -w - 'udp portrange 4000-6999 and not portrange 5201-5208' 2>/dev/null > "${cap%.pcapng}-ue$ue.pcap" & ue_pids+=($!)
      done
      sleep 2
      "$0" "$call" "$talk" >/dev/null 2>&1 || echo "run $i: call failed" >> "$out"
      sleep 2; sudo pkill -INT -P "$pid" 2>/dev/null; sudo kill -INT "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
      for p in "${ue_pids[@]}"; do sudo pkill -INT -P "$p" 2>/dev/null; done; wait "${ue_pids[@]}" 2>/dev/null || true
      "$0" load stop >/dev/null 2>&1 || true
      { echo "## run $i"; python3 "$DIR/hops.py" "$cap" --port "$port" 2>&1; } >> "$out"
      rm -f "$cap" "${cap%.pcapng}"-ue[12].pcap
      sleep 5
    done
    echo "$out"
    awk '/^## run/{r=$3} /^Uplink/{d="UL"} /^Downlink/{d="DL"} /end to end:/{sub(/^ +end to end: /,""); printf "run %s %s %s\n", r, d, $0}' "$out" ;;
  compose) shift; compose "$@" ;;
  *) sed -n '6,27p' "$0"; exit 2 ;;
esac
