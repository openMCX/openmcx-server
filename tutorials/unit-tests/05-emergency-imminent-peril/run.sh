#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Unit Test Tutorial 5: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/05-emergency-imminent-peril-run.pcap.gz (captures/05-emergency-imminent-peril-full.pcap.gz is the
# reference run of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=05-emergency-imminent-peril-full.pcap   # in the capture container
OUT=captures/05-emergency-imminent-peril-run.pcap.gz

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# Wait until a Python condition on the clients' and the server's status holds; st('client-a') is a role's
# status.json, session() the MCPTT server's group session, owner() who holds its floor ('a' to 'd' or ''),
# active(...) exactly these clients in the call, prio(value, ...) the session and these clients at priority value
# ('normal', 'imminent' or 'emergency'), group() the group's state on the server, alert(user, ...) these clients show
# user's emergency alert.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
IDS = {'a': 'sip:alice.mcptt@mcx.test', 'b': 'sip:bob.mcptt@mcx.test', 'c': 'sip:client-c.mcptt@mcx.test',
       'd': 'sip:client-d.mcptt@mcx.test'}
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
    return {v: k for k, v in IDS.items()}.get(session().get('floor_owner') or '', '')
def active(*roles):
    return all(st(r).get('call_state') == 'active' for r in roles) and len(session().get('participants', [])) == len(roles)
def prio(value, *roles):
    return session().get('priority') == value and all(st(r).get('priority') == value for r in roles)
def group():
    return st('mcptt-server').get('group_priority', {}).get('sip:operations@mcx.test', {})
def alert(user, *roles):
    return all(IDS[user] in st(r).get('alerts', []) for r in roles)
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

# The number in a client's status field, for "it went up" checks.
count() {
  "${DC[@]}" exec -T client-a python3 -c \
    "import json; print(json.load(open('/artifacts/$1/status.json')).get('$2', 0))"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in and affiliated; client-d leaves the group for now'
wait_for 'client-a to client-d authorized and affiliated' \
  "all(st(r).get('authorized') and st(r).get('affiliated') for r in ('client-a','client-b','client-c','client-d'))" 90
mcx client-d deaffiliate
wait_for 'client-d not affiliated' "not st('client-d').get('affiliated')"
hold_file client-a /speech/alpha.wav
hold_file client-b /speech/bravo.wav

step '2. client-a calls the group: a normal call with client-b and client-c'
mcx client-a call
wait_for 'client-a, client-b and client-c in a normal call' \
  "active('client-a','client-b','client-c') and prio('normal','client-a','client-b','client-c')"

step '3. client-a raises the call to imminent peril'
mcx client-a imminent on
wait_for 'the call and every participant at imminent peril' "prio('imminent','client-a','client-b','client-c')"
# The server repeats Floor Idle each time T7 (1 s) expires (TS 24.380 clause 6.3.4.3.4); wait for one at imminent peril.
sleep 1.5

step '4. client-a sends an emergency alert, with its location'
mcx client-a alert on
wait_for 'every participant shows client-a alert and location' \
  "alert('a','client-a','client-b','client-c') and all(st(r).get('alert_locations', {}).get(IDS['a']) for r in ('client-a','client-b','client-c'))"

step '5. client-a raises the call to emergency'
mcx client-a emergency on
wait_for 'the call and every participant at emergency, the alert kept' \
  "prio('emergency','client-a','client-b','client-c') and alert('a','client-a','client-b','client-c')"

step '6. client-b asks for imminent peril: the server keeps emergency and tells client-b so'
corrections=$(count client-b priority_corrections_received)
mcx client-b imminent on
wait_for 'client-b corrected by the server, the call still at emergency' \
  "st('client-b').get('priority_corrections_received', 0) > $corrections and prio('emergency','client-a','client-b','client-c')"

step '7. client-c, not allowed to, tries to cancel the emergency: refused'
completed=$(count client-c priority_updates_completed)
mcx client-c emergency off
wait_for 'client-c refused (403), the call still at emergency' \
  "st('client-c').get('priority_updates_completed', 0) > $completed and st('client-c').get('last_error') == 'priority update: 403' and prio('emergency','client-a','client-b','client-c')"

step '8. client-d affiliates: it joins the emergency call late, already at emergency'
mcx client-d affiliate
wait_for 'client-d in the call at emergency' \
  "active('client-a','client-b','client-c','client-d') and prio('emergency','client-a','client-b','client-c','client-d')"

step '9. client-b talks; client-a, who raised the emergency, asks for the floor and takes it over'
mcx client-b ptt /tmp/hold.wav
wait_for 'client-b has the floor' "owner() == 'b' and st('client-b').get('talking')"
mcx client-a ptt /tmp/hold.wav
wait_for 'the server revokes client-b and grants client-a' "owner() == 'a'"
if [ "$("${DC[@]}" exec -T client-a python3 -c \
  "import json; print(1 if json.load(open('/artifacts/client-a/status.json')).get('pending_floor_confirmation') else 0)")" = 1 ]; then
  mcx client-a floor-confirm
fi
wait_for 'client-a talks, client-b has stopped' "st('client-a').get('talking') and not st('client-b').get('talking')"
mcx client-a release
wait_for 'floor idle' "owner() == '' and not st('client-a').get('talking')"

step '10. client-a cancels the emergency: the call is normal again; then it cancels its alert'
mcx client-a emergency off
wait_for 'the call and every participant back to normal, the alert still on' \
  "prio('normal','client-a','client-b','client-c','client-d') and alert('a','client-a','client-b','client-c','client-d')"
mcx client-a alert off
wait_for 'the alert cancelled at every participant' \
  "not any(IDS['a'] in st(r).get('alerts', []) for r in ('client-a','client-b','client-c','client-d'))"

step '11. client-c, not allowed to, tries imminent peril and an emergency alert: both refused'
completed=$(count client-c priority_updates_completed)
mcx client-c imminent on
wait_for 'client-c imminent peril refused (403), the call still normal' \
  "st('client-c').get('priority_updates_completed', 0) > $completed and st('client-c').get('last_error') == 'priority update: 403' and prio('normal','client-a','client-b','client-c','client-d')"
mcx client-c alert on
wait_for 'client-c alert refused (403), sent to nobody' \
  "st('client-c').get('last_error') == 'emergency alert: 403' and not any(IDS['c'] in st(r).get('alerts', []) for r in ('client-a','client-b','client-d'))"
mcx client-a hangup
wait_for 'every client idle' "all(st(r).get('call_state') == 'idle' for r in ('client-a','client-b','client-c','client-d')) and not session()"

step '12. client-a starts a call at imminent peril from the outset, then lowers it to normal'
mcx client-a call imminent
wait_for 'every participant at imminent peril' "active('client-a','client-b','client-c','client-d') and prio('imminent','client-a','client-b','client-c','client-d')"
mcx client-a imminent off
wait_for 'the call back to normal' "prio('normal','client-a','client-b','client-c','client-d')"
mcx client-a hangup
wait_for 'every client idle' "all(st(r).get('call_state') == 'idle' for r in ('client-a','client-b','client-c','client-d')) and not session()"

step '13. client-a starts an emergency call, ends it; the group stays in emergency until client-a cancels it'
mcx client-a call emergency
wait_for 'every participant at emergency' "active('client-a','client-b','client-c','client-d') and prio('emergency','client-a','client-b','client-c','client-d')"
mcx client-a hangup
wait_for 'call ended, the group still in emergency on the server' \
  "not session() and all(st(r).get('call_state') == 'idle' for r in ('client-a','client-b','client-c','client-d')) and group().get('priority') == 'emergency'"
mcx client-a emergency off
wait_for 'the group back to normal on the server and at every client' \
  "group().get('priority') == 'normal' and all(st(r).get('priority') == 'normal' for r in ('client-a','client-b','client-c','client-d'))"

step "14. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|BYE|INFO|MESSAGE|SIP 200|SIP 403)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
