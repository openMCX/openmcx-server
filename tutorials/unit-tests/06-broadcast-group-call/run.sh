#!/usr/bin/env bash
# openMCX Unit Test Tutorial 6: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/06-broadcast-group-call-run.pcap.gz (captures/06-broadcast-group-call-full.pcap.gz is the
# reference run of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=06-broadcast-group-call-full.pcap   # in the capture container
OUT=captures/06-broadcast-group-call-run.pcap.gz

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of the checks: st('client-a') is a role's status.json, sessions() the MCPTT server's calls,
# call_active(type, roles) exactly these clients in one call of the type started by client-a, idle() no call
# anywhere, rejected(role, code, text) the role's last call attempt failed so, B and A the Floor Indicator bits
# broadcast and normal call (TS 24.380 clause 8.2.3.15).
HELPERS=$(cat <<'PY'
import json, sys, time
ROLES = ('client-a', 'client-b', 'client-c', 'client-d')
IDS = {'client-a': 'sip:alice.mcptt@mcx.test', 'client-b': 'sip:bob.mcptt@mcx.test',
       'client-c': 'sip:client-c.mcptt@mcx.test', 'client-d': 'sip:client-d.mcptt@mcx.test'}
B, A = 0x4000, 0x8000
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def sessions():
    value = st('mcptt-server').get('sessions') or []
    return list(value.values()) if isinstance(value, dict) else value
def call_active(kind, roles=ROLES):
    s = sessions()
    return (len(s) == 1 and s[0].get('call_type') == kind and s[0].get('initiator') == IDS['client-a']
            and set(s[0].get('participants', [])) == {IDS[r] for r in roles}
            and all(st(r).get('call_state') == 'active' and st(r).get('call_type') == kind for r in roles))
def idle():
    return all(st(r).get('call_state') == 'idle' for r in ROLES) and not sessions()
def rejected(role, code, text):
    failure = st(role).get('last_call_failure') or {}
    return st(role).get('call_state') == 'idle' and failure.get('status') == code and text in failure.get('warning', '')
PY
)

# Wait until a Python condition (one line, with the helpers above) holds.
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

# Print a number from a role's status (a counter read before a step).
value() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
print(st(sys.argv[1]).get(sys.argv[2]) or 0)" "$1" "$2"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in and affiliated to the group operations'
wait_for 'client-a to client-d authorized and affiliated' "all(st(r).get('authorized') and st(r).get('affiliated') for r in ROLES) and idle()" 90

step '2. client-a starts a broadcast group call: every affiliated member is invited, nobody subscribes to the roster'
mcx client-a call broadcast
wait_for 'one broadcast call with client-a to client-d' "call_active('broadcast')"
wait_for 'no conference subscription in a broadcast' "all(st(r).get('conference_wait_reason') == 'broadcast group call' and not st(r).get('conference_subscription') for r in ROLES)"

step '3. client-b, a receiver, asks for the idle floor: denied, receive only'
before=$(value client-b floor_denials)
mcx client-b ptt /speech/bravo.wav
wait_for 'client-b denied with cause #5 (Receive only)' "st('client-b').get('floor_denials', 0) > $before and st('client-b').get('last_floor_reject_cause') == 5 and not st('client-b').get('talking')"

step '4. client-a talks to everyone; receivers see Floor Taken with the broadcast bit and may not ask for the floor'
received=$(value client-d received_packets)
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a has the floor' "st('client-a').get('talking') and sessions() and sessions()[0].get('floor_owner') == IDS['client-a']"
wait_for 'client-b, client-c and client-d: Floor Indicator B, permission to request 0' "all(st(r).get('floor_indicator') == B and st(r).get('permission_to_request') is False for r in ('client-b', 'client-c', 'client-d'))"
before=$(value client-c floor_denials)
mcx client-c ptt /speech/bravo.wav
wait_for 'client-c denied with cause #5 while client-a talks' "st('client-c').get('floor_denials', 0) > $before and st('client-c').get('last_floor_reject_cause') == 5"
wait_for 'every receiver hears client-a' "st('client-d').get('received_packets', 0) >= $received + 100 and all(st(r).get('received_packets', 0) >= 100 for r in ('client-b', 'client-c'))"

step '5. client-a stops: the end of its transmission ends the call for everyone, with no hangup'
wait_for 'client-a stopped talking' "not st('client-a').get('talking')"
wait_for 'every client idle, no session on the server' "idle()" 15

step '6. A second broadcast: a forced conference subscription is refused, and client-a leaves before talking'
mcx client-a call broadcast
wait_for 'broadcast with client-a to client-d' "call_active('broadcast')"
mcx client-b conference-subscribe
wait_for 'client-b SUBSCRIBE refused with 480' "st('client-b').get('last_error') == 'conference subscription: 480'"
mcx client-a hangup
wait_for 'the initiator leaving ends the broadcast' "idle()"

step '7. client-c may not start a broadcast'
mcx client-c call broadcast
wait_for 'client-c refused with 403 (broadcast group call not authorised)' "rejected('client-c', 403, 'broadcast group call not authorised') and idle()"

step '8. A broadcast cannot take over a group call in progress; the normal call keeps normal floor control'
mcx client-a call
wait_for 'normal group call with client-a to client-d' "call_active('prearranged')"
mcx client-b hangup
wait_for 'client-b left the group call' "st('client-b').get('call_state') == 'idle' and call_active('prearranged', ('client-a', 'client-c', 'client-d'))"
mcx client-b call broadcast
wait_for 'client-b refused with 486 (group call in progress)' "rejected('client-b', 486, 'group call in progress') and call_active('prearranged', ('client-a', 'client-c', 'client-d'))"
mcx client-c ptt /speech/bravo.wav
wait_for 'in the normal call client-c may talk: Floor Indicator A, permission to request 1' "st('client-c').get('talking') and all(st(r).get('floor_indicator') == A and st(r).get('permission_to_request') is True for r in ('client-a', 'client-d'))"
wait_for 'client-c finished' "not st('client-c').get('talking') and not sessions()[0].get('floor_owner')" 20
mcx client-a hangup
wait_for 'every client idle' "idle()"

step '9. Late entry: client-d affiliates during a broadcast and joins it as a receiver'
mcx client-d deaffiliate
wait_for 'client-d not affiliated' "not st('client-d').get('affiliated')"
mcx client-a call broadcast
wait_for 'broadcast with client-a, client-b and client-c' "call_active('broadcast', ('client-a', 'client-b', 'client-c'))"
mcx client-d affiliate
wait_for 'client-d joined the broadcast' "call_active('broadcast')"
received=$(value client-d received_packets)
mcx client-a ptt /speech/alpha.wav
wait_for 'client-d hears client-a' "st('client-d').get('received_packets', 0) >= $received + 100"
wait_for 'released at the end of the transmission' "idle()" 25

step '10. Override: client-d may take over a broadcast transmission, client-c may not'
mcx client-a call broadcast
wait_for 'broadcast with client-a to client-d' "call_active('broadcast')"
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a talking' "st('client-a').get('talking')"
before=$(value client-c floor_denials)
mcx client-c ptt /speech/bravo.wav
wait_for 'client-c denied with cause #5' "st('client-c').get('floor_denials', 0) > $before and st('client-c').get('last_floor_reject_cause') == 5"
mcx client-d ptt /speech/bravo.wav
wait_for 'client-d took over, client-a stopped' "st('client-d').get('talking') and not st('client-a').get('talking') and sessions() and sessions()[0].get('floor_owner') == IDS['client-d']"
wait_for 'released when the overriding transmission ends' "idle()" 25

step "11. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z rtp,streams \
  2>/dev/null | grep -E 'RTP Streams|Src IP|AMR' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
