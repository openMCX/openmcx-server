#!/usr/bin/env bash
# OpenMCX Unit Test Tutorial 2: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/02-floor-queue-priority-run.pcap.gz (captures/02-floor-queue-priority-full.pcap.gz is the
# reference run of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=02-floor-queue-priority-full.pcap   # in the capture container
OUT=captures/02-floor-queue-priority-run.pcap.gz

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# Wait until a Python condition on the clients' and the server's status holds; st('client-a') is a role's
# status.json, session() the MCPTT server's group session, owner() who holds its floor ('a', 'b', 'c' or ''),
# active(...) exactly these clients in the call.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
IDS = {'sip:alice.mcptt@mcx.test': 'a', 'sip:bob.mcptt@mcx.test': 'b', 'sip:client-c.mcptt@mcx.test': 'c'}
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def session():
    value = st('mcptt-server').get('sessions') or []
    value = list(value.values()) if isinstance(value, dict) else value
    return value[0] if value else {}
def owner():
    return IDS.get(session().get('floor_owner') or '', '')
def active(*roles):
    return all(st(r).get('call_state') == 'active' for r in roles) and len(session().get('participants', [])) == len(roles)
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
  echo "  ok: $label"
}

# A speech file long enough to hold the floor while the others act: the role's test message repeated for
# 20 s, written in the client's container (/tmp/hold.wav).
hold_file() {
  "${DC[@]}" exec -T "$1" python3 - "$2" <<'PY'
import sys, wave
with wave.open(sys.argv[1]) as source:
    params, pcm = source.getparams(), source.readframes(source.getnframes())
with wave.open('/tmp/hold.wav', 'wb') as target:
    target.setparams(params)
    size = 20 * params.framerate * params.sampwidth
    target.writeframes((pcm * (size // len(pcm) + 1))[:size])
PY
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in and affiliated; client-d leaves the group'
wait_for 'client-a to client-d authorized and affiliated' \
  "all(st(r).get('authorized') and st(r).get('affiliated') for r in ('client-a','client-b','client-c','client-d'))" 90
mcx client-d deaffiliate
wait_for 'client-d not affiliated' "not st('client-d').get('affiliated')"
hold_file client-a /speech/alpha.wav
hold_file client-b /speech/bravo.wav

step '2. client-a calls the group: client-b and client-c join, with floor queueing and priorities negotiated'
mcx client-a call
wait_for 'client-a, client-b and client-c in the call' "active('client-a','client-b','client-c')"
wait_for 'negotiated floor priorities: client-a up to 10, client-b up to 90' \
  "st('client-a').get('negotiated_floor_priority') == 10 and st('client-b').get('negotiated_floor_priority') == 90"

step '3. client-a talks; client-b asks for the floor too and is queued at position 1'
mcx client-a ptt /tmp/hold.wav
wait_for 'client-a has the floor' "owner() == 'a' and st('client-a').get('talking')"
mcx client-b ptt /tmp/hold.wav
wait_for 'client-b queued at position 1, not talking' \
  "st('client-b').get('floor_state') == 'Queued' and st('client-b').get('queue_position') == 1 and not st('client-b').get('talking')"
step '   client-b asks for its position in the queue'
mcx client-b queue-status
wait_for 'client-b told: still position 1' \
  "st('client-b').get('floor_queue_info_received', 0) >= 2 and st('client-b').get('queue_position') == 1"

step '4. client-b gives up: it leaves the queue, client-a keeps talking'
mcx client-b release
wait_for 'client-b out of the queue, client-a still has the floor' \
  "st('client-b').get('floor_state') == 'NoPermission' and not st('client-b').get('queued') and owner() == 'a'" 5

step '5. client-b queues again; when client-a stops, the floor goes to client-b, which confirms it'
mcx client-b ptt /tmp/hold.wav
wait_for 'client-b queued again' "st('client-b').get('floor_state') == 'Queued'"
mcx client-a release
wait_for 'client-b granted the floor, waiting for its user to accept' \
  "owner() == 'b' and st('client-b').get('pending_floor_confirmation') and not st('client-b').get('talking')"
mcx client-b floor-confirm
wait_for 'client-b talks, client-a hears it' "st('client-b').get('floor_state') == 'HasPermission' and st('client-b').get('talking')"
mcx client-b release
wait_for 'floor idle' "owner() == '' and not st('client-a').get('talking') and not st('client-b').get('talking')"

step '6. A grant nobody accepts: client-b queues behind client-a again and does not confirm'
mcx client-a ptt /tmp/hold.wav
wait_for 'client-a has the floor' "owner() == 'a' and st('client-a').get('talking')"
mcx client-b ptt /tmp/hold.wav
wait_for 'client-b queued' "st('client-b').get('floor_state') == 'Queued'"
mcx client-a release
wait_for 'client-b granted, waiting for its user' "owner() == 'b' and st('client-b').get('pending_floor_confirmation')"
wait_for 'no answer: the grant lapses and the floor is idle again, client-b sent no speech' \
  "owner() == '' and st('client-b').get('floor_state') == 'NoPermission' and not st('client-b').get('talking')" 15

step '7. Pre-emption: client-a talks, client-b requests the floor at priority 90 and takes it over'
mcx client-a ptt /tmp/hold.wav
wait_for 'client-a has the floor' "owner() == 'a' and st('client-a').get('talking')"
mcx client-b priority 90
mcx client-b ptt /tmp/hold.wav
wait_for 'the server revokes client-a and grants client-b' "owner() == 'b'"
if "${DC[@]}" exec -T client-a python3 -c \
  "import json,sys; sys.exit(0 if json.load(open('/artifacts/client-b/status.json')).get('pending_floor_confirmation') else 1)"; then
  mcx client-b floor-confirm
fi
wait_for 'client-b talks, client-a has stopped' "st('client-b').get('talking') and not st('client-a').get('talking')"
mcx client-b release
mcx client-b priority 10
wait_for 'floor idle' "owner() == '' and not st('client-b').get('talking')"

step '8. client-a ends the call'
mcx client-a hangup
wait_for 'every client idle, no session on the server' \
  "all(st(r).get('call_state') == 'idle' for r in ('client-a','client-b','client-c','client-d')) and not session()"

step "9. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z rtp,streams \
  2>/dev/null | grep -E 'RTP Streams|Src IP|AMR' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
