#!/usr/bin/env bash
# openMCX Unit Test Tutorial 9: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/09-remote-ambient-calls-run.pcap.gz (captures/09-remote-ambient-calls-full.pcap.gz is the
# reference run of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=09-remote-ambient-calls-full.pcap   # in the capture container
OUT=captures/09-remote-ambient-calls-run.pcap.gz
ALICE=sip:alice.mcptt@mcx.test
BOB=sip:bob.mcptt@mcx.test
CLIENT_D=sip:client-d.mcptt@mcx.test
GROUP=sip:operations@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The same, for a command that may find nothing to do (a hangup on a client already idle).
mcx_quiet() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null 2>&1 || true
}

# Send a command to the running MCPTT server (an administrator's action).
server() {
  echo "  \$ mcptt-server: $*"
  "${DC[@]}" exec -T mcptt-server openmcx-mcptt-server --config /config/mcptt-server.json --command "$*" >/dev/null
}

# Wait until a Python condition on the clients' and the server's status holds. st('client-a') is a role's
# status.json, sessions() the MCPTT server's sessions, amb()/last() a client's ambient listening call (during, after),
# svc() the answer to its last service request, fail() its last call failure, out() a service outcome.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
ROLES = ('client-a', 'client-b', 'client-c', 'client-d')
A, B, C, D = 'sip:alice.mcptt@mcx.test', 'sip:bob.mcptt@mcx.test', 'sip:client-c.mcptt@mcx.test', 'sip:client-d.mcptt@mcx.test'
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def sessions():
    value = st('mcptt-server').get('sessions') or []
    return list(value.values()) if isinstance(value, dict) else value
def ambient_sessions():
    return [s for s in sessions() if s.get('call_type') == 'ambient']
def idle():
    return all(st(r).get('call_state') == 'idle' and not st(r).get('ambient') for r in ROLES) and not sessions()
def amb(role):
    return st(role).get('ambient') or {}
def last(role):
    return st(role).get('last_ambient') or {}
def svc(role):
    return st(role).get('last_service_result') or {}
def fail(role):
    return st(role).get('last_call_failure') or {}
def out(role, key):
    return (st(role).get('service_outcomes') or {}).get(key)
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
  echo "  ok: $label"
}

# A number from a role's status (a counter to compare against later).
value() {
  "${DC[@]}" exec -T client-a python3 -c "import json; print(json.load(open('/artifacts/$1/status.json')).get('$2', 0))"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in and affiliated to operations; client-a and client-b get a speech source to be listened to'
wait_for 'client-a to client-d authorized and affiliated' "all(st(r).get('authorized') and st(r).get('affiliated') for r in ROLES)" 90
wait_for 'the MCPTT server knows every affiliation' "all('sip:operations@mcx.test' in (st('mcptt-server').get('affiliations') or {}).get(u, []) for u in (A, B, C, D))"
mcx client-a ambient-source /speech/alpha.wav
mcx client-b ambient-source /speech/bravo.wav

step '2. Remotely initiated group call: client-a asks client-b to call operations'
mcx client-a remote-group-call "$BOB" "$GROUP"
wait_for 'client-b placed the call, every member is in it, and client-b is its initiator' "all(st(r).get('call_state') == 'active' for r in ROLES) and any(s.get('initiator') == B and s.get('group_id') == 'sip:operations@mcx.test' for s in sessions())"
wait_for 'client-a is told: success; client-b recorded the same' "out('client-a', 'remotely-initiated-group-call-response') == 'success' and out('client-b', 'remote-group') == 'success'"
mcx client-b ptt /speech/bravo.wav
wait_for 'client-b has the floor and talks' "st('client-b').get('talking')"
wait_for 'floor released' "not st('client-b').get('talking')" 20
mcx client-b hangup
wait_for 'call released' "idle()"

step '3. The same request, silent: client-b places the call without telling its user'
mcx client-a remote-group-call "$BOB" "$GROUP" silent
wait_for 'the silent request also establishes the call' "all(st(r).get('call_state') == 'active' for r in ROLES)"
mcx client-b hangup
wait_for 'call released' "idle()"

step '4. Refused requests: client-c may not ask (157); a group client-b is not affiliated to (120)'
mcx client-c remote-group-call "$BOB" "$GROUP"
wait_for 'client-c refused with 403 and warning 157, no call' "svc('client-c').get('status') == 403 and '157' in svc('client-c').get('warning', '') and idle()"
mcx client-a remote-group-call "$BOB" sip:no-such-group@mcx.test
wait_for 'client-a refused with 403 and warning 120' "svc('client-a').get('status') == 403 and '120' in svc('client-a').get('warning', '')"

step '5. client-b is busy: it reports failure and its own call goes on'
mcx client-b call
wait_for 'client-b in its own group call' "st('client-b').get('call_state') == 'active'"
mcx client-a remote-group-call "$BOB" "$GROUP"
wait_for 'client-a is told: fail; client-b still in its call' "out('client-a', 'remotely-initiated-group-call-response') == 'fail' and st('client-b').get('call_state') == 'active'"
mcx client-b hangup
wait_for 'call released' "idle()"

step '6. A request with an application priority: client-b calls with Resource-Priority mcpttp.5'
mcx client-a remote-group-call "$BOB" "$GROUP" priority=mcpttp.5
wait_for 'the prioritised call is established and reported' "all(st(r).get('call_state') == 'active' for r in ROLES) and out('client-a', 'remotely-initiated-group-call-response') == 'success'"
mcx client-b hangup
wait_for 'call released' "idle()"

step '7. A preconfigured-use-only group: refused by the server (167)'
mcx client-a remote-group-call "$BOB" sip:operations-ric-preconf@mcx.test
wait_for 'client-a refused with 403 and warning 167, no call' "svc('client-a').get('status') == 403 and '167' in svc('client-a').get('warning', '') and idle()"

step '8. Ambient listening, remotely initiated: client-a listens to client-b, whose device shows nothing'
before=$(value client-a received_packets)
mcx client-a ambient remote "$BOB"
wait_for 'client-a listens; the floor is with client-b, which transmits' "st('client-a').get('call_state') == 'active' and any(s.get('listened_to') == B and s.get('floor_owner') == B and s.get('ambient_listening_type') == 'remote-init' for s in ambient_sessions()) and amb('client-b').get('transmitting')"
wait_for 'client-b shows no call: idle, no call type, not talking' "st('client-b').get('call_state') == 'idle' and st('client-b').get('call_type') == '' and not st('client-b').get('talking')"
wait_for 'client-b speech reaches client-a' "st('client-a').get('received_packets', 0) >= $before + 150" 20
denials=$(value client-a floor_denials)
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a may only listen: Floor Deny cause 5' "st('client-a').get('floor_denials', 0) > $denials and st('client-a').get('last_floor_reject_cause') == 5"
mcx client-b hangup
sleep 2
wait_for 'client-b cannot end a call it does not know about' "ambient_sessions() and st('client-a').get('call_state') == 'active' and amb('client-b').get('transmitting')" 5
mcx client-a hangup
wait_for 'client-a ends the call' "idle()"

step '9. Ambient listening, locally initiated: client-b asks client-a to listen to it, and ends it'
mcx client-b ambient local "$ALICE"
wait_for 'client-a listens to client-b (local-init)' "st('client-a').get('call_state') == 'active' and amb('client-b').get('transmitting') and any(s.get('ambient_listening_type') == 'local-init' and s.get('listened_to') == B for s in ambient_sessions())"
mcx client-b hangup
wait_for 'client-b ends its own local-init call' "idle()"

step '10. The server releases ambient listening calls: administrator, a call by or to client-b, the timer'
mcx client-a ambient remote "$BOB"
wait_for 'client-a listens to client-b' "any(s.get('listened_to') == B for s in ambient_sessions()) and amb('client-b').get('transmitting')"
server ambient-release "$BOB"
wait_for 'released, client-a told administrator-action' "idle() and last('client-a').get('release_reason') == 'administrator-action'"
mcx client-a ambient remote "$BOB"
wait_for 'client-a listens to client-b' "any(s.get('listened_to') == B for s in ambient_sessions()) and amb('client-b').get('transmitting')"
mcx client-b call
wait_for 'client-a told call-request-initiated-by-listened-to-client; client-b group call goes on' "last('client-a').get('release_reason') == 'call-request-initiated-by-listened-to-client' and st('client-b').get('call_state') == 'active' and not ambient_sessions()"
mcx client-b hangup
wait_for 'calls released' "idle()"
mcx client-a ambient remote "$BOB"
wait_for 'client-a listens to client-b' "any(s.get('listened_to') == B for s in ambient_sessions()) and amb('client-b').get('transmitting')"
mcx client-c private "$BOB" auto
wait_for 'client-a told call-request-for-listened-to-client; client-c reaches client-b' "last('client-a').get('release_reason') == 'call-request-for-listened-to-client' and st('client-b').get('private_peer') == C and st('client-c').get('call_state') == 'active'"
mcx client-c hangup
wait_for 'calls released' "idle()"
mcx client-a ambient remote "$BOB"
wait_for 'client-a listens to client-b' "any(s.get('listened_to') == B for s in ambient_sessions()) and amb('client-b').get('transmitting')"
wait_for 'after the 30 s private call timer: client-a told private-call-expiry' "idle() and last('client-a').get('release_reason') == 'private-call-expiry'" 45

step '11. Refused ambient listening calls: no ruleset (154), target not in the list (144), target not callable (127)'
mcx client-c ambient remote "$BOB"
wait_for 'client-c refused with 403 and warning 154' "fail('client-c').get('status') == 403 and '154' in fail('client-c').get('warning', '') and idle()"
mcx client-a ambient remote "$CLIENT_D"
wait_for 'client-a refused with 403 and warning 144' "fail('client-a').get('status') == 403 and '144' in fail('client-a').get('warning', '') and idle()"
mcx client-b ambient local "$CLIENT_D"
wait_for 'client-b refused with 403 and warning 127' "fail('client-b').get('status') == 403 and '127' in fail('client-b').get('warning', '') and idle()"

step '12. A busy target: client-b is in a private call, client-a cannot listen to it (480)'
mcx client-c private "$BOB" auto
wait_for 'client-b in a private call with client-c' "st('client-b').get('call_state') == 'active' and st('client-b').get('private_peer') == C"
mcx client-a ambient remote "$BOB"
wait_for 'client-a refused with 480; the private call goes on' "fail('client-a').get('status') == 480 and st('client-a').get('call_state') == 'idle' and st('client-b').get('private_peer') == C"
mcx client-c hangup
wait_for 'call released' "idle()"
mcx_quiet client-a hangup

step "13. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|BYE|MESSAGE|SIP 403|SIP 480|SIP 200)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
