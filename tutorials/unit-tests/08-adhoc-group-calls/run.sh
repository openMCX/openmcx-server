#!/usr/bin/env bash
# openMCX Unit Test Tutorial 8: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/08-adhoc-group-calls-run.pcap.gz (captures/08-adhoc-group-calls-full.pcap.gz is the reference run
# of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=08-adhoc-group-calls-full.pcap   # in the capture container
OUT=captures/08-adhoc-group-calls-run.pcap.gz

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of the checks: st('client-a') is a role's status.json, sessions() the MCPTT server's calls,
# adhoc() its ad hoc calls, adhoc_active(roles) exactly these clients in one ad hoc call that client-a started for
# a generated ad hoc group (sip:adhoc-...), roster(roles) each of them sees exactly them in the conference roster,
# idle() no call anywhere, rejected(role, code, text) the role's last call attempt failed so.
HELPERS=$(cat <<'PY'
import json, sys, time
ROLES = ('client-a', 'client-b', 'client-c', 'client-d')
IDS = {'client-a': 'sip:alice.mcptt@mcx.test', 'client-b': 'sip:bob.mcptt@mcx.test',
       'client-c': 'sip:client-c.mcptt@mcx.test', 'client-d': 'sip:client-d.mcptt@mcx.test'}
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def sessions():
    value = st('mcptt-server').get('sessions') or []
    return list(value.values()) if isinstance(value, dict) else value
def adhoc():
    return [s for s in sessions() if s.get('call_type') == 'adhoc']
def adhoc_active(*roles):
    calls = adhoc()
    if len(calls) != 1 or not calls[0].get('group_id', '').startswith('sip:adhoc-'):
        return False
    group = calls[0]['group_id']
    return (calls[0].get('initiator') == IDS['client-a'] and set(calls[0].get('participants', [])) == {IDS[r] for r in roles}
            and all(st(r).get('call_state') == 'active' and st(r).get('call_type') == 'adhoc' and st(r).get('call_group') == group for r in roles))
def roster(*roles):
    return all(st(r).get('conference_active') and set(st(r).get('conference_participants', [])) == {IDS[x] for x in roles} for r in roles)
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

# Check that a Python condition holds for the whole of a few seconds.
holds() {
  local label=$1 condition=$2 seconds=$3
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
condition, end = sys.argv[1], time.monotonic() + float(sys.argv[2])
while time.monotonic() < end:
    if not eval(condition):
        sys.exit(1)
    time.sleep(0.1)" "$condition" "$seconds" || { echo "  FAILED: $label" >&2; exit 1; }
  echo "  ok: $label"
}

# Print the value of a Python expression (with the helpers above).
value() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
print(eval(sys.argv[1]))" "$1"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in and affiliated; each answers automatically; client-c leaves the group'
wait_for 'client-a to client-d authorized and affiliated' "all(st(r).get('authorized') and st(r).get('affiliated') for r in ROLES) and idle()" 90
for role in client-a client-b client-c client-d; do mcx "$role" answer-mode auto; done
mcx client-c deaffiliate
wait_for 'client-c not affiliated' "not st('client-c').get('affiliated')"

step '2. client-a calls bob and client-c by list: the server makes an ad hoc group for the call'
mcx client-a adhoc sip:bob.mcptt@mcx.test sip:client-c.mcptt@mcx.test
wait_for 'client-a, client-b and client-c in one ad hoc call (client-c without affiliation)' "adhoc_active('client-a', 'client-b', 'client-c')"
wait_for 'client-d, not on the list, is not invited' "st('client-d').get('call_state') == 'idle'"
wait_for 'the conference roster lists the three' "roster('client-a', 'client-b', 'client-c')"
GROUP=$(value "adhoc()[0]['group_id']")
SESSION=$(value "adhoc()[0]['session_uri']")
echo "  ad hoc group $GROUP"

step '3. Floor control as in a group call: client-a talks, client-b is denied meanwhile'
DENIALS=$(value "st('client-b').get('floor_denials', 0)")
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a has the floor' "st('client-a').get('talking')"
mcx client-b ptt /speech/bravo.wav
wait_for "client-b's request denied" "st('client-b').get('floor_denials', 0) > $DENIALS"
wait_for 'floor idle again' "not st('client-a').get('talking') and not adhoc()[0].get('floor_owner')"

step '4. client-b leaves and rejoins the same ad hoc call'
mcx client-b hangup
wait_for 'client-a and client-c go on' "st('client-b').get('call_state') == 'idle' and adhoc_active('client-a', 'client-c')"
mcx client-b rejoin
wait_for 'client-b back in the same session and ad hoc group' "adhoc_active('client-a', 'client-b', 'client-c') and adhoc()[0]['session_uri'] == '$SESSION' and adhoc()[0]['group_id'] == '$GROUP'"

step '5. client-b and client-c leave: the call goes on with client-a alone; client-a leaves: the call ends'
mcx client-b hangup
mcx client-c hangup
wait_for 'client-a alone in the ad hoc call' "adhoc_active('client-a')"
holds 'still running 3 s later (one participant does not end an ad hoc call)' "adhoc_active('client-a')" 3
mcx client-a hangup
wait_for 'call released and the ad hoc group gone' "idle()"
mcx client-c affiliate
wait_for 'client-c affiliated again' "st('client-c').get('affiliated')"

step '6. Refused requests'
mcx client-d adhoc sip:alice.mcptt@mcx.test
wait_for 'client-d may not start ad hoc calls: 403, warning 185' "rejected('client-d', 403, '185 ')"
mcx client-a adhoc sip:bob.mcptt@mcx.test sip:client-c.mcptt@mcx.test sip:client-d.mcptt@mcx.test sip:nobody.mcptt@mcx.test
wait_for 'four invitees, three allowed: 403, warning 189' "rejected('client-a', 403, '189 ')"
mcx client-a adhoc sip:alice.mcptt@mcx.test
wait_for 'only the initiator on the list: 403, warning 187' "rejected('client-a', 403, '187 ')"
mcx client-a adhoc sip:nobody.mcptt@mcx.test
wait_for 'nobody reachable: 480' "rejected('client-a', 480, '')"
wait_for 'no session left' "idle()"

step '7. Manual answer: client-b rings and accepts; then it rings and declines'
mcx client-b answer-mode manual
mcx client-a adhoc sip:bob.mcptt@mcx.test sip:client-c.mcptt@mcx.test
wait_for 'client-a and client-c connected, client-b ringing' "adhoc_active('client-a', 'client-c') and st('client-b').get('call_state') == 'ringing'"
mcx client-b answer
wait_for 'client-b joins' "adhoc_active('client-a', 'client-b', 'client-c')"
mcx client-a hangup
wait_for 'released' "idle()"
mcx client-a adhoc sip:bob.mcptt@mcx.test sip:client-c.mcptt@mcx.test
wait_for 'client-b ringing again' "adhoc_active('client-a', 'client-c') and st('client-b').get('call_state') == 'ringing'"
mcx client-b reject
wait_for 'the decline leaves the call with the others' "st('client-b').get('call_state') == 'idle' and adhoc_active('client-a', 'client-c')"
mcx client-a hangup
wait_for 'released' "idle()"
mcx client-b answer-mode auto

step '8. client-a changes the participants of a running ad hoc call'
mcx client-a adhoc sip:bob.mcptt@mcx.test
wait_for 'client-a and client-b in an ad hoc call' "adhoc_active('client-a', 'client-b')"
mcx client-a adhoc-modify add sip:client-c.mcptt@mcx.test
wait_for 'client-c added' "adhoc_active('client-a', 'client-b', 'client-c')"
mcx client-a adhoc-modify remove sip:bob.mcptt@mcx.test
wait_for 'client-b removed' "adhoc_active('client-a', 'client-c') and st('client-b').get('call_state') == 'idle'"
mcx client-c adhoc-modify add sip:client-d.mcptt@mcx.test
wait_for 'client-c may not modify: 403, warning 190' "(st('client-c').get('last_modify_result') or {}).get('status') == 403 and '190 ' in (st('client-c').get('last_modify_result') or {}).get('warning', '')"
wait_for 'the call is unchanged' "adhoc_active('client-a', 'client-c')"
mcx client-a hangup
wait_for 'released' "idle()"

step '9. An emergency ad hoc call: refused for client-b, set up by client-a, ended by its timer (TNG2, 12 s)'
mcx client-b adhoc emergency sip:alice.mcptt@mcx.test
wait_for 'client-b may not: 403' "rejected('client-b', 403, 'emergency adhoc group call not authorized')"
mcx client-a adhoc emergency sip:bob.mcptt@mcx.test sip:client-c.mcptt@mcx.test
wait_for 'emergency ad hoc call with client-b and client-c' "adhoc_active('client-a', 'client-b', 'client-c') and adhoc()[0].get('priority') == 'emergency'"
wait_for 'the invitees know it is an emergency' "all(st(r).get('adhoc_priority') == 'emergency' for r in ('client-b', 'client-c'))"
wait_for 'TNG2 ends the call' "idle()" 25

step '10. The call timer (TNG3, 30 s) ends an ordinary ad hoc call'
mcx client-a adhoc sip:bob.mcptt@mcx.test
wait_for 'client-a and client-b in an ad hoc call' "adhoc_active('client-a', 'client-b')"
mcx client-a ptt /speech/alpha.wav
wait_for 'TNG3 ends the call' "idle()" 45

step "11. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|BYE|SIP 4|SIP 2|NOTIFY|MESSAGE)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
