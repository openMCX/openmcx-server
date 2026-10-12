#!/usr/bin/env bash
# OpenMCX Unit Test Tutorial 11: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/11-functional-aliases-run.pcap.gz (captures/11-functional-aliases-full.pcap.gz is the reference run
# of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=11-functional-aliases-full.pcap   # in the capture container
OUT=captures/11-functional-aliases-run.pcap.gz

DISPATCHER=sip:dispatcher.alias@mcx.test   # alice or bob, one at a time; take-over allowed (bob may)
MEDIC=sip:medic.alias@mcx.test             # client-c and client-d, both at once
RESERVE=sip:reserve.alias@mcx.test         # alice; nobody activates it
ALICE=sip:alice.mcptt@mcx.test
BOB=sip:bob.mcptt@mcx.test
CLIENT_C=sip:client-c.mcptt@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# Wait until a Python condition on the clients' and the server's status holds; st('client-a') is a role's
# status.json, fa(role) its last functional alias request as (action, status code of the PUBLISH, outcome of the alias
# in the status NOTIFY), warn(role) the warning of that answer, held(role) the aliases the NOTIFYs give the role,
# sub(role) the status code of the role's status subscription, al() the server's activated aliases
# (alias to the users, in activation order), sessions() the server's calls, private(a, b) one private call between a
# and b, failed(role) the role's last refused call as (status, warning), idle() no call anywhere.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
ROLES = ('client-a', 'client-b', 'client-c', 'client-d')
ID = {'client-a': 'sip:alice.mcptt@mcx.test', 'client-b': 'sip:bob.mcptt@mcx.test',
      'client-c': 'sip:client-c.mcptt@mcx.test', 'client-d': 'sip:client-d.mcptt@mcx.test'}
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def fa(role):
    r = st(role).get('last_fa_result') or {}
    outcomes = r.get('outcomes') or {}
    return (r.get('action'), r.get('status'), next(iter(outcomes.values()), None))
def warn(role):
    return (st(role).get('last_fa_result') or {}).get('warning', '')
def held(role):
    return st(role).get('active_functional_aliases') or []
def sub(role):
    return st(role).get('functional_alias_subscription_result')
def al():
    return st('mcptt-server').get('functional_aliases') or {}
def sessions():
    value = st('mcptt-server').get('sessions') or []
    return list(value.values()) if isinstance(value, dict) else value
def private(a, b):
    calls = [s for s in sessions() if s.get('call_type') == 'private']
    return len(calls) == 1 and set(calls[0].get('participants', [])) == {ID[a], ID[b]} and all(st(r).get('call_state') == 'active' for r in (a, b))
def failed(role):
    f = st(role).get('last_call_failure') or {}
    return (f.get('status'), f.get('warning', ''))
def idle():
    return all(st(r).get('call_state') == 'idle' for r in ROLES) and not sessions()
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
  echo "  ok: $label"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in and affiliated; every client answers private calls automatically'
wait_for 'client-a to client-d authorized and affiliated' "all(st(r).get('authorized') and st(r).get('affiliated') for r in ROLES)" 90
for role in client-a client-b client-c client-d; do mcx "$role" answer-mode auto; done

step '2. Activation: client-c and client-d activate medic; client-c may not activate dispatcher'
mcx client-c fa activate "$MEDIC"
wait_for 'client-c subscribed to its alias status first: 200' "sub('client-c') == 200"
wait_for 'client-c activated medic: PUBLISH 200, then NOTIFY "activated"' "fa('client-c') == ('activate', 200, 'activated')"
mcx client-d fa activate "$MEDIC"
wait_for 'client-d too, within the limit of 2' "fa('client-d') == ('activate', 200, 'activated') and al().get('$MEDIC') == [ID['client-c'], ID['client-d']]"
mcx client-c fa activate "$DISPATCHER"
wait_for 'client-c may not change dispatcher: 403, warning 201' "fa('client-c')[:2] == ('activate', 403) and '201 user not authorized to change the functional alias status' in warn('client-c')"

step '3. The limit and take-over: dispatcher may be active for one user at a time'
mcx client-a fa activate "$DISPATCHER"
wait_for 'client-a activated dispatcher' "al().get('$DISPATCHER') == [ID['client-a']]"
mcx client-b fa activate "$DISPATCHER"
wait_for 'client-b over the limit: PUBLISH 200, then NOTIFY "take-over-possible" (bob may take it over)' "fa('client-b') == ('activate', 200, 'take-over-possible') and al().get('$DISPATCHER') == [ID['client-a']]"
mcx client-b fa takeover "$DISPATCHER"
wait_for 'client-b takes it over: NOTIFY "activated", now only client-b' "fa('client-b') == ('takeover', 200, 'activated') and al().get('$DISPATCHER') == [ID['client-b']]"
wait_for 'client-a is told by NOTIFY that it no longer holds dispatcher' "'$DISPATCHER' not in held('client-a')"
mcx client-a fa takeover "$DISPATCHER"
wait_for 'client-a may not take it back: no offer, so a plain activation, refused in the NOTIFY' "fa('client-a') == ('takeover', 200, 'refused') and al().get('$DISPATCHER') == [ID['client-b']]"

step '4. A private call to an alias: the server answers 300 with a user behind it, and client-a calls that user'
mcx client-a private-fa "$MEDIC" auto
wait_for 'client-a and client-c in a private call' "private('client-a', 'client-c')" 20
wait_for 'client-a followed the 300 naming client-c; client-c told medic was called' "(st('client-a').get('functional_alias_redirect') or {}).get('selected') == ID['client-c'] and st('client-c').get('called_functional_alias') == '$MEDIC'"
mcx client-a hangup
wait_for 'released' "idle()"

step '5. Presenting the caller'"'"'s alias: only while it is activated for the caller'
mcx client-b fa use "$DISPATCHER"
mcx client-b private "$ALICE" auto
wait_for 'client-a sees the call come from dispatcher' "private('client-b', 'client-a') and st('client-a').get('calling_functional_alias') == '$DISPATCHER'"
mcx client-b hangup
wait_for 'released' "idle()"
mcx client-a fa use "$DISPATCHER"
mcx client-a private "$CLIENT_C" auto
wait_for 'client-a asks for dispatcher, which client-b holds: not presented' "private('client-a', 'client-c') and st('client-c').get('calling_functional_alias') == ''"
mcx client-a hangup
wait_for 'released' "idle()"
mcx client-b call
wait_for 'a group call by client-b: every member sees dispatcher' "all(st(r).get('call_state') == 'active' for r in ROLES) and all(st(r).get('calling_functional_alias') == '$DISPATCHER' for r in ('client-a', 'client-c', 'client-d'))" 20
mcx client-b hangup
wait_for 'released' "idle()" 20
mcx client-a fa use none
mcx client-b fa use none

step '6. A first-to-answer call to an alias: every user behind it rings, the first answer wins'
mcx client-a first-to-answer-fa "$MEDIC"
wait_for 'client-c and client-d ring' "all(st(r).get('call_state') == 'ringing' for r in ('client-c', 'client-d'))"
mcx client-d answer
wait_for 'client-d answered first: in the call with client-a; client-c no longer rings' "private('client-a', 'client-d') and st('client-c').get('call_state') == 'idle'"
mcx client-a hangup
wait_for 'released' "idle()"

step '7. An ad hoc call to a list naming an alias: the users behind it are invited'
mcx client-a adhoc "$MEDIC"
wait_for 'client-a, client-c and client-d in an ad hoc call; client-c and client-d told medic was called' "all(st(r).get('call_state') == 'active' and st(r).get('call_type') == 'adhoc' for r in ('client-a', 'client-c', 'client-d')) and all(st(r).get('called_functional_alias') == '$MEDIC' for r in ('client-c', 'client-d'))" 20
mcx client-a hangup
wait_for 'released' "idle()" 20

step '8. A broadcast ad hoc call: client-b and client-c only listen; the call ends with client-a'"'"'s transmission'
mcx client-a adhoc broadcast "$BOB" "$CLIENT_C"
wait_for 'the broadcast ad hoc call is up; client-b knows it is a broadcast' "all(st(r).get('call_state') == 'active' and st(r).get('call_type') == 'adhoc' for r in ('client-a', 'client-b', 'client-c')) and st('client-b').get('adhoc_broadcast')"
mcx client-b ptt /speech/bravo.wav
wait_for 'client-b asks for the floor: Floor Deny, cause 5 (receive only)' "st('client-b').get('floor_denials', 0) >= 1 and st('client-b').get('last_floor_reject_cause') == 5"
mcx client-a ptt /speech/alpha.wav
wait_for 'client-c hears client-a' "st('client-c').get('received_packets', 0) >= 100" 20
wait_for 'the server ends the call when client-a stops talking' "idle()" 25

step '9. Deactivation, and an alias nobody holds'
mcx client-c fa deactivate "$MEDIC"
wait_for 'client-c deactivated medic: PUBLISH 200, then NOTIFY without it; only client-d behind it' "fa('client-c') == ('deactivate', 200, 'deactivated') and al().get('$MEDIC') == [ID['client-d']]"
mcx client-b private-fa "$MEDIC" auto
wait_for 'a call to medic now reaches client-d' "private('client-b', 'client-d')" 20
mcx client-b hangup
wait_for 'released' "idle()"
mcx client-b private-fa "$RESERVE" auto
wait_for 'a call to reserve, which nobody activated: 403, warning 145' "st('client-b').get('call_state') == 'idle' and failed('client-b')[0] == 403 and '145 unable to determine called party' in failed('client-b')[1]"

step "10. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|BYE|PUBLISH|SUBSCRIBE|NOTIFY|CANCEL|SIP 200|SIP 300|SIP 403)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
