#!/usr/bin/env bash
# openMCX Unit Test Tutorial 15: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/15-mcdata-ip-connectivity-run.pcap.gz (captures/15-mcdata-ip-connectivity-full.pcap.gz is the
# reference run of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=15-mcdata-ip-connectivity-full.pcap   # in the capture container
OUT=captures/15-mcdata-ip-connectivity-run.pcap.gz
ALICE=sip:alice.mcdata@mcx.test
BOB=sip:bob.mcdata@mcx.test
CLIENT_C=sip:client-c.mcdata@mcx.test
CLIENT_D=sip:client-d.mcdata@mcx.test
DESK=sip:desk.fa@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of wait_for and value: st('client-a') is a role's status.json, ipcon(role) its IP connectivity
# session, counts(role) its IP application counters, pings(role) the echo replies it received, tunnels() the
# GRE-in-UDP tunnels the MCData server relays, counters() the server's counters, saved[...] values kept by remember.
HELPERS='
import json, sys, time
def st(role):
    try:
        return json.load(open(f"/artifacts/{role}/status.json")) or {}
    except (OSError, ValueError):
        return {}
def ipcon(role):
    return st(role).get("mcdata_ipconn") or {}
def counts(role):
    return st(role).get("mcdata_ipconn_counters") or {}
def pings(role):
    return st(role).get("mcdata_ipconn_pings") or []
def tunnels():
    return st("mcdata-server").get("ipconn_sessions") or []
def counters():
    return st("mcdata-server").get("counters") or {}
try:
    saved = json.load(open("/tmp/saved.json"))
except (OSError, ValueError):
    saved = {}
def ok(condition):
    try:
        return bool(eval(condition))
    except (KeyError, IndexError, TypeError, AttributeError):
        return False
'

# Wait until a Python condition on the clients' and the server's status holds.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
while time.monotonic() < deadline:
    if ok(condition):
        sys.exit(0)
    time.sleep(0.1)
sys.exit(1)" "$condition" "$timeout" || { echo "  FAILED: $label" >&2; exit 1; }
  echo "  ok: $label"
}

# Keep the value of a Python expression as saved[name], for later conditions.
remember() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
saved[sys.argv[1]] = eval(sys.argv[2])
json.dump(saved, open('/tmp/saved.json', 'w'))" "$1" "$2"
}

# Print the value of a Python expression.
value() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
print(eval(sys.argv[1]))" "$1"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in and authorised for MCData'
wait_for 'client-a to client-d MCData-authorised' "all(st(r).get('mcdata_authorized') for r in ('client-a','client-b','client-c','client-d'))" 90

step '2. client-a opens an IP connectivity session with client-b'
mcx client-a ipcon "$BOB"
wait_for 'the session is open at both clients' "ipcon('client-a').get('state') == 'open' and ipcon('client-b').get('state') == 'open'"
wait_for 'client-b learns the caller and the Referred-By identity' "ipcon('client-b').get('from') == '$ALICE' and 'sip:' in ipcon('client-b').get('referred_by', '')"
wait_for 'the MCData server holds one tunnel, a port facing each client' "len(tunnels()) == 1 and tunnels()[0]['established'] and tunnels()[0]['origin_port'] != tunnels()[0]['target_port'] and ipcon('client-a')['peer'].endswith(':' + str(tunnels()[0]['origin_port'])) and ipcon('client-b')['peer'].endswith(':' + str(tunnels()[0]['target_port']))"

step '3. IP packets both ways through the tunnel: ICMP echo between 10.77.0.1 and 10.77.0.2'
remember relayed "counters().get('ipconn_packets', 0)"
mcx client-a ipcon-ping 10.77.0.2 5 64
wait_for 'five 64-byte echoes from client-a are answered, data unchanged, TTL 64' "len([p for p in pings('client-a') if p['from'] == '10.77.0.2' and p['bytes'] == 64 and p['ttl'] == 64]) >= 5"
wait_for 'client-b answered five echoes' "counts('client-b').get('echo_answered') == 5"
mcx client-b ipcon-ping 10.77.0.1 3 1200
wait_for 'three 1200-byte echoes from client-b are answered' "len([p for p in pings('client-b') if p['from'] == '10.77.0.1' and p['bytes'] == 1200]) >= 3"
wait_for 'the server relayed all 16 datagrams' "counters().get('ipconn_packets', 0) >= saved['relayed'] + 16 and tunnels()[0]['to_target'] >= 8 and tunnels()[0]['to_origin'] >= 8"

step '4. A packet for an address that is not client-b'"'"'s: dropped by client-b, nothing answers'
remember dropped_b "counts('client-b').get('dropped', 0)"
mcx client-a ipcon-ping 10.77.0.99 2
wait_for 'client-b dropped the two packets' "counts('client-b').get('dropped', 0) >= saved['dropped_b'] + 2"
wait_for 'client-a has two unanswered echoes' "counts('client-a').get('outstanding') == 2"

step '5. Datagrams to the tunnel from a stranger (client-c): dropped by the server'
remember dropped_s "tunnels()[0]['dropped']"
remember received_b "counts('client-b').get('received', 0)"
PORT=$(value "tunnels()[0]['origin_port']")
echo "  \$ client-c: three GRE datagrams to mcdata-server:$PORT"
"${DC[@]}" exec -T client-c python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);[s.sendto(bytes.fromhex('00000800450000140000400040010000c0000201c0000202'),('mcdata-server',$PORT)) for _ in range(3)]"
wait_for 'the server dropped the three datagrams' "tunnels()[0]['dropped'] >= saved['dropped_s'] + 3"
wait_for 'nothing reached client-b' "counts('client-b').get('received', 0) == saved['received_b']"

step '6. client-a closes the session'
mcx client-a ipcon close
wait_for 'both clients and the tunnel released' "ipcon('client-a').get('state') == 'closed' and ipcon('client-b').get('state') == 'released' and not tunnels()"

step '7. A busy client: client-a talks to client-c, client-b'"'"'s request to client-c is refused 486'
mcx client-a ipcon "$CLIENT_C"
wait_for 'the session client-a to client-c is open' "ipcon('client-a').get('state') == 'open' and ipcon('client-c').get('state') == 'open'"
mcx client-b ipcon "$CLIENT_C"
wait_for 'client-b is refused 486, passed back by the server' "ipcon('client-b').get('state') == 'rejected' and ipcon('client-b').get('status') == 486"
wait_for 'the first session goes on' "ipcon('client-c').get('state') == 'open' and len(tunnels()) == 1"
mcx client-c ipcon close
wait_for 'the called party released it; client-a learns it' "ipcon('client-a').get('state') == 'released' and ipcon('client-c').get('state') == 'closed' and not tunnels()"

step '8. Refusals: transmission rights and the one-to-one lists (warnings 200, 229, 230), an alias nobody holds (145)'
mcx client-d ipcon "$ALICE"
wait_for 'client-d, without the right to transmit: 403, warning 200' "ipcon('client-d').get('status') == 403 and '\"200 ' in ipcon('client-d').get('warning', '')"
mcx client-a ipcon "$CLIENT_D"
wait_for 'client-a to client-d, outside its list: 403, warning 229' "ipcon('client-a').get('status') == 403 and '\"229 ' in ipcon('client-a').get('warning', '')"
mcx client-c ipcon "$BOB"
wait_for 'client-c to client-b, outside client-b'"'"'s incoming list: 403, warning 230' "ipcon('client-c').get('status') == 403 and '\"230 ' in ipcon('client-c').get('warning', '')"
mcx client-a ipcon fa=sip:nobody.fa@mcx.test
wait_for 'an alias nobody has activated: 403, warning 145' "ipcon('client-a').get('status') == 403 and '\"145 ' in ipcon('client-a').get('warning', '')"
wait_for 'no tunnel for a refused request' "not tunnels()"

step '9. A session to a functional alias: client-b takes desk.fa, client-a calls the alias'
mcx client-b mcdata-fa activate "$DESK"
wait_for 'client-b holds desk.fa' "(st('mcdata-server').get('functional_aliases') or {}).get('$DESK') == ['$BOB']"
mcx client-a ipcon fa="$DESK"
wait_for 'the session reaches client-b, which learns the alias' "ipcon('client-a').get('state') == 'open' and ipcon('client-a').get('selected') == '$BOB' and ipcon('client-b').get('state') == 'open' and ipcon('client-b').get('called_alias') == '$DESK'"
remember answered "counts('client-b').get('echo_answered', 0)"
mcx client-a ipcon-ping 10.77.0.2 2
wait_for 'IP traffic flows on it' "counts('client-b').get('echo_answered', 0) >= saved['answered'] + 2"
mcx client-b ipcon close
wait_for 'released' "ipcon('client-a').get('state') == 'released' and not tunnels()"
mcx client-b mcdata-fa deactivate "$DESK"

step "10. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z io,phs 2>/dev/null \
  | grep -E 'gre|icmp|sip ' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
