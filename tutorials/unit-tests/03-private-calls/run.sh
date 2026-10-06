#!/usr/bin/env bash
# openMCX Unit Test Tutorial 3: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/03-private-calls-run.pcap.gz (captures/03-private-calls-full.pcap.gz is the reference run of
# README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=03-private-calls-full.pcap   # in the capture container
OUT=captures/03-private-calls-run.pcap.gz
ALICE=sip:alice.mcptt@mcx.test
BOB=sip:bob.mcptt@mcx.test
CLIENT_D=sip:client-d.mcptt@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# Wait until a Python condition on the clients' and the server's status holds; st('client-a') is a role's
# status.json, private() the MCPTT server's private call sessions, owner() who holds the floor ('a', 'b' or ''),
# in_call(caller, callee) exactly one private call between them, idle() no client in a call and no session,
# failed(role, code, warning) the role's last call ended with that SIP status (and Warning text).
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
IDS = {'sip:alice.mcptt@mcx.test': 'a', 'sip:bob.mcptt@mcx.test': 'b'}
ROLES = ('client-a', 'client-b', 'client-c', 'client-d')
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def sessions():
    value = st('mcptt-server').get('sessions') or []
    return list(value.values()) if isinstance(value, dict) else value
def private():
    return [s for s in sessions() if s.get('call_type') == 'private']
def owner():
    return IDS.get((private() or [{}])[0].get('floor_owner') or '', '')
def in_call(caller, callee):
    return len(private()) == 1 and all(
        st(r).get('call_state') == 'active' and st(r).get('call_type') == 'private' for r in (caller, callee))
def idle():
    return all(st(r).get('call_state') == 'idle' for r in ROLES) and not sessions()
def failed(role, code, warning=''):
    failure = st(role).get('last_call_failure') or {}
    return st(role).get('call_state') == 'idle' and failure.get('status') == code and warning in failure.get('warning', '')
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
  echo "  ok: $label"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in; every client answers private calls automatically unless told otherwise'
wait_for 'client-a to client-d authorized' "all(st(r).get('authorized') for r in ROLES) and idle()" 90
for role in client-a client-b client-c client-d; do mcx "$role" answer-mode auto; done

step '2. Automatic commencement: client-a calls client-b, which answers at once; they take turns to talk'
mcx client-a private "$BOB" auto
wait_for 'client-a and client-b in a private call, nobody else' \
  "in_call('client-a','client-b') and st('client-c').get('call_state') == 'idle'"
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a has the floor' "owner() == 'a' and st('client-a').get('talking')"
mcx client-b ptt /speech/bravo.wav
wait_for 'client-b asks too while client-a talks: denied' "st('client-b').get('floor_denials', 0) >= 1"
wait_for 'client-a finishes, the floor is idle' "owner() == '' and not st('client-a').get('talking')" 20
mcx client-b ptt /speech/bravo.wav
wait_for 'client-b has the floor' "owner() == 'b' and st('client-b').get('talking')"
wait_for 'client-b finishes' "owner() == '' and not st('client-b').get('talking')" 20
mcx client-b hangup
wait_for 'client-b hangs up: the call ends for both' "idle()"

step '3. Manual commencement: client-b rings and its user answers'
mcx client-a private "$BOB" manual
wait_for 'client-b rings, client-a waits' \
  "st('client-b').get('call_state') == 'ringing' and st('client-a').get('call_state') == 'calling'"
mcx client-b answer
wait_for 'client-a and client-b in a private call' "in_call('client-a','client-b')"
mcx client-a hangup
wait_for 'the call ends for both' "idle()"

step '4. Manual commencement, declined: client-b rejects the call'
mcx client-a private "$BOB" manual
wait_for 'client-b rings' "st('client-b').get('call_state') == 'ringing'"
mcx client-b reject
wait_for 'client-a gets 480 with Warning 110 (user declined)' "failed('client-a', 480, '110 user declined')"

step '5. client-b answers manually from now on; client-a forces an automatic answer, which client-a may do'
mcx client-b answer-mode manual
mcx client-a private "$BOB" force-auto
wait_for 'client-b answered without ringing' "in_call('client-a','client-b')"
mcx client-a hangup
wait_for 'the call ends for both' "idle()"

step '6. client-a asks for an automatic answer, but client-b answers manually: it rings, and client-a gives up'
mcx client-a private "$BOB" auto
wait_for 'client-b rings' "st('client-b').get('call_state') == 'ringing'"
mcx client-a hangup
wait_for 'client-a cancels: client-b stops ringing' "idle()"

step '7. Nobody answers: the server gives up after its setup timer (5 s)'
mcx client-a private "$BOB" manual
wait_for 'client-b rings' "st('client-b').get('call_state') == 'ringing'"
wait_for 'client-a gets 408 after the setup timer' "failed('client-a', 408)" 15
wait_for 'client-b stopped ringing' "idle()"
mcx client-b answer-mode auto

step '8. Calls the server refuses: client-d may not make private calls, client-a may not call client-d'
mcx client-d private "$ALICE" auto
wait_for 'client-d gets 403, Warning 107' "failed('client-d', 403, '107 ')"
mcx client-a private "$CLIENT_D" auto
wait_for 'client-a gets 403, Warning 144' "failed('client-a', 403, '144 ')"

step '9. Busy: client-c calls client-b while client-b is in a call'
mcx client-a private "$BOB" auto
wait_for 'client-a and client-b in a private call' "in_call('client-a','client-b')"
mcx client-c private "$BOB" auto
wait_for 'client-c gets 486 Busy Here' "failed('client-c', 486)"
mcx client-a hangup
wait_for 'the call ends for both' "idle()"

step '10. A private call without floor control: both talk at once'
mcx client-a private "$BOB" auto no-floor
wait_for 'client-a and client-b in a private call, neither with floor control' \
  "in_call('client-a','client-b') and st('client-a').get('floor_control') is False and st('client-b').get('floor_control') is False"
mcx client-a ptt /speech/alpha.wav
mcx client-b ptt /speech/bravo.wav
wait_for 'both talk at the same time' "st('client-a').get('talking') and st('client-b').get('talking')"
wait_for 'both have finished' "not st('client-a').get('talking') and not st('client-b').get('talking')" 20
mcx client-b hangup
wait_for 'the call ends for both' "idle()"

step "11. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat -z rtp,streams \
  2>/dev/null | grep -E '^ *(INVITE|CANCEL|BYE|ACK|SIP [0-9]{3})|RTP Streams|Src IP|AMR' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
