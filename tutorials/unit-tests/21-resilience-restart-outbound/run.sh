#!/usr/bin/env bash
# openMCX Unit Test Tutorial 21: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/21-resilience-run.pcap.gz (captures/21-resilience-full.pcap.gz is the reference run of README.md).
# Set COMPOSE to another command than "docker compose" if needed, and OVERRIDE to a second compose file (other
# images, for example) that every docker compose command of the script takes after docker-compose.yaml.
# It runs once per system (README.md, to start over).
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
if [ -n "${OVERRIDE:-}" ]; then DC+=(-f "$OVERRIDE"); fi
CAPTURE=21-resilience-full.pcap   # in the capture container
OUT=captures/21-resilience-run.pcap.gz
BOB=sip:bob.mcptt@mcx.test
# The MC UE without a SIP listener of step 7: a small SIP client in Python, a copy of the one of the openMCX regression
# tests (tests/integration/outbound_flow_client.py).
FLOW_CLIENT=$PWD/outbound_flow_client.py

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of wait_for and value: st('client-a') is a role's status.json (the MCPTT server's too),
# flow() the status of the client without a listener, signed_in(role) the role is registered, authorised and
# affiliated, sessions() the MCPTT server's group sessions, active(...) exactly these clients in calls.
HELPERS='
import json, sys, time
CLIENTS = ("client-a", "client-b", "client-c", "client-d")
def st(role):
    try:
        return json.load(open(f"/artifacts/{role}/status.json"))
    except (OSError, ValueError):
        return {}
def flow():
    return st("outbound-flow")
def signed_in(role):
    s = st(role)
    return bool(s.get("registered") and s.get("authorized") and s.get("affiliated"))
def sessions():
    value = st("mcptt-server").get("sessions") or []
    return list(value.values()) if isinstance(value, dict) else value
def active(*roles):
    count = sum(len(s.get("participants", [])) for s in sessions())
    return all(st(r).get("call_state") == "active" for r in roles) and count == len(roles)
def failure(role):
    s = st(role)
    return s.get("call_state") == "idle" and (s.get("last_call_failure") or {}).get("status")
'

# Wait until a Python condition on the status holds.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.1)
sys.exit(1)" "$condition" "$timeout" || { echo "  FAILED: $label" >&2; exit 1; }
  echo "  ok: $label"
}

# Print the value of a Python expression on the status.
value() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
print($1)"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in: registered, authorised for MCPTT and affiliated to the group operations'
wait_for 'client-a to client-d signed in' 'all(signed_in(r) for r in CLIENTS)' 90
SERVER=$(value 'st("mcptt-server")["instance_id"]')
OLD_A=$(value 'st("client-a")["instance_id"]')
echo "  the MCPTT server's instance: $SERVER"

step '2. client-a restarts (a new instance of the client): it registers, is authorised and affiliates again'
echo "  \$ docker compose restart client-a"
"${DC[@]}" restart client-a >/dev/null 2>&1
wait_for 'client-a signed in again, as a new instance' \
  "st('client-a').get('instance_id') not in ('', None, '$OLD_A') and signed_in('client-a')" 60
wait_for 'the same MCPTT server, still serving the other three' \
  "st('mcptt-server').get('instance_id') == '$SERVER' and all(signed_in(r) for r in CLIENTS[1:])"

step '3. client-a calls the group and talks: the restarted client is fully back'
mcx client-a call
wait_for 'client-a to client-d in the call' "active(*CLIENTS)"
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a has the floor' "sessions() and sessions()[0].get('floor_owner')"
wait_for 'floor idle again' "not st('client-a').get('talking') and not sessions()[0].get('floor_owner')"
mcx client-a hangup
wait_for 'every client idle, no session on the server' "all(st(r).get('call_state') == 'idle' for r in CLIENTS) and not sessions()"

step '4. The MCPTT server restarts: it starts again with no service authorisation and no affiliation'
echo "  \$ docker compose restart mcptt-server"
"${DC[@]}" restart mcptt-server >/dev/null 2>&1
wait_for 'a new MCPTT server instance, with nobody authorised or affiliated' \
  "st('mcptt-server').get('ready') and st('mcptt-server').get('instance_id') not in ('', None, '$SERVER') \
   and st('mcptt-server').get('authorized_users') == 0 and st('mcptt-server').get('affiliated_users') == 0" 60
wait_for 'the clients still count themselves signed in: nothing told them' 'all(signed_in(r) for r in CLIENTS)'

step "5. client-a calls the group: the server does not know client-a any more and refuses the call"
mcx client-a call
wait_for 'the call refused with 404 and warning 141' \
  "failure('client-a') == 404 and '141 ' in ((st('client-a').get('last_call_failure') or {}).get('warning') or '')" 15
echo "  client-a's call failed with SIP $(value "failure('client-a')"), $(value "st('client-a')['last_call_failure']['warning']")"

step "6. Each client renews its access token: 412 to its PUBLISH refresh, then a new PUBLISH, and it affiliates again"
RENEWALS=$(value '[st(r).get("token_renewals", 0) for r in CLIENTS]')
wait_for 'every client renewed its token once more (about one minute)' \
  "all(st(r).get('token_renewals', 0) > n for r, n in zip(CLIENTS, $RENEWALS))" 90
wait_for 'every client authorised and affiliated again, and the server knows all four, without a restart' \
  "all(signed_in(r) for r in CLIENTS) and st('mcptt-server').get('authorized_users') == 4 \
   and st('mcptt-server').get('affiliated_users') == 4" 30
mcx client-a call
wait_for 'client-a to client-d in the call' "active(*CLIENTS)"
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a has the floor' "sessions() and sessions()[0].get('floor_owner')"
wait_for 'floor idle again' "not st('client-a').get('talking') and not sessions()[0].get('floor_owner')"
mcx client-a hangup
wait_for 'every client idle, no session on the server' "all(st(r).get('call_state') == 'idle' for r in CLIENTS) and not sessions()"

step "7. bob without a SIP listener: client-b's mcx-client stops, a client that only uses its outbound flow takes over"
echo "  \$ docker compose stop client-b"
"${DC[@]}" stop client-b >/dev/null 2>&1
echo "  \$ docker compose run client-b python3 /outbound_flow_client.py ...   (in the background)"
"${DC[@]}" run --rm -T --no-deps --entrypoint python3 -v "$FLOW_CLIENT:/outbound_flow_client.py:ro" client-b \
  /outbound_flow_client.py --config /config/client-b.json --output /artifacts/outbound-flow --disable-tls \
  >/dev/null 2>&1 &
FLOW_PID=$!
wait_for 'registered over its flow (a Contact with alias refused first), authorised, NOTIFY over the flow' \
  "flow().get('phase') == 'waiting-invite'" 60
mcx client-a private "$BOB" manual
wait_for 'the INVITE reached bob over the flow; bob answered 486 and closed the flow' \
  "flow().get('phase') == 'closed' and failure('client-a') == 486"
mcx client-a private "$BOB" manual
wait_for 'the next call to bob fails at once: 430 (Flow Failed) from the core, which does not dial the binding' \
  "failure('client-a') and failure('client-a') != 486" 5
echo "  client-a's call failed with SIP $(value "failure('client-a')")"
"${DC[@]}" exec -T client-a touch /artifacts/outbound-flow/stop
wait "$FLOW_PID"
wait_for "the flow client's checks all passed" "flow().get('passed') is True"
value '"\n".join("  - " + c["name"] for c in flow()["checks"])'

step "8. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|BYE|ACK|REGISTER|SUBSCRIBE|NOTIFY|PUBLISH|MESSAGE|SIP [0-9]{3})' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
