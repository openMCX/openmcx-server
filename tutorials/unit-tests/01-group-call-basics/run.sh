#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Unit Test Tutorial 1: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/01-group-call-run.pcap.gz (captures/01-group-call-full.pcap.gz is the reference run of README.md).
# Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=01-group-call-full.pcap   # in the capture container
OUT=captures/01-group-call-run.pcap.gz

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# Wait until a Python condition on the clients' and the server's status holds; st('client-a') is a role's
# status.json, sessions() the MCPTT server's group sessions, active(...) exactly these clients in calls,
# roster(...) each of them sees that many participants in the call's conference roster (TS 24.379 6.3.3.4).
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def sessions():
    value = st('mcptt-server').get('sessions') or []
    return list(value.values()) if isinstance(value, dict) else value
def active(*roles):
    count = sum(len(s.get('participants', [])) for s in sessions())
    return all(st(r).get('call_state') == 'active' for r in roles) and count == len(roles)
def roster(*roles):
    return all(st(r).get('conference_active') and len(st(r).get('conference_participants', [])) == len(roles) for r in roles)
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.2)
sys.exit(1)
PY
  echo "  ok: $label"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in, registered and affiliated to the group operations'
wait_for 'client-a to client-d authorized and affiliated' \
  "all(st(r).get('authorized') and st(r).get('affiliated') for r in ('client-a','client-b','client-c','client-d'))" 90
step '   client-c and client-d leave the group (they come back later)'
mcx client-c deaffiliate
mcx client-d deaffiliate
wait_for 'client-c and client-d not affiliated' "not st('client-c').get('affiliated') and not st('client-d').get('affiliated')"

step '2. client-a calls the group: client-b, the only other affiliated member, joins'
mcx client-a call
wait_for 'client-a and client-b in the call' "active('client-a','client-b')"
wait_for 'both see both in the conference roster' "roster('client-a','client-b')"

step '3. client-a talks: Floor Request, Floor Granted, speech, Floor Release'
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a has the floor' "sessions() and sessions()[0].get('floor_owner')"
wait_for 'floor idle again' "not st('client-a').get('talking') and not sessions()[0].get('floor_owner')" 30

step '4. client-c affiliates: the server brings it into the running call (late entry)'
mcx client-c affiliate
wait_for 'client-a, client-b and client-c in the call' "active('client-a','client-b','client-c')"
wait_for 'the roster lists three' "roster('client-a','client-b','client-c')"

step '5. client-b leaves the call and rejoins it'
mcx client-b hangup
wait_for 'client-b idle, client-a and client-c still in the call' \
  "st('client-b').get('call_state') == 'idle' and active('client-a','client-c')"
mcx client-b rejoin
wait_for 'client-b back in the same call' "active('client-a','client-b','client-c')"

step '6. client-a, who started the call, hangs up: the server ends the call for everyone'
mcx client-a hangup
wait_for 'every client idle, no session on the server' \
  "all(st(r).get('call_state') == 'idle' for r in ('client-a','client-b','client-c','client-d')) and not sessions()"

step '7. Two groups at once: client-c and client-d select operations-parallel'
mcx client-c group sip:operations-parallel@mcx.test
mcx client-d group sip:operations-parallel@mcx.test
wait_for 'client-c and client-d affiliated to operations-parallel' \
  "all(st(r).get('affiliated') and st(r).get('group_id') == 'sip:operations-parallel@mcx.test' for r in ('client-c','client-d'))"
mcx client-a call
wait_for 'operations: client-a and client-b' "active('client-a','client-b')"
mcx client-c call
wait_for 'operations-parallel: client-c and client-d, two sessions' \
  "active('client-a','client-b','client-c','client-d') and len(sessions()) == 2"
step '   client-a and client-c talk at the same time, each in its own group'
mcx client-a ptt /speech/alpha.wav
mcx client-c ptt /speech/bravo.wav
wait_for 'two floors granted at once' "len(sessions()) == 2 and all(s.get('floor_owner') for s in sessions())"
wait_for 'both floors idle again' "all(not s.get('floor_owner') for s in sessions())"
mcx client-a hangup
mcx client-c hangup
wait_for 'every client idle, no session on the server' \
  "all(st(r).get('call_state') == 'idle' for r in ('client-a','client-b','client-c','client-d')) and not sessions()"

step "8. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat -z rtp,streams \
  2>/dev/null | grep -E '^ *(INVITE|BYE|ACK|REGISTER|SUBSCRIBE|NOTIFY|PUBLISH|MESSAGE|SIP 200)|RTP Streams|Src IP|AMR|^ *172\.' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
