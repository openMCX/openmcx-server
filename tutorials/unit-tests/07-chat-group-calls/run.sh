#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Unit Test Tutorial 7: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/07-chat-group-calls-run.pcap.gz (captures/07-chat-group-calls-full.pcap.gz is the reference run of
# README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=07-chat-group-calls-full.pcap   # in the capture container
OUT=captures/07-chat-group-calls-run.pcap.gz
CHAT=sip:operations-chat@mcx.test
PREARRANGED=sip:operations@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of the checks: st('client-a') is a role's status.json, sessions() the MCPTT server's calls,
# chat_active(roles) exactly these clients in the one chat session, roster(roles) each of them sees exactly them in
# the conference roster, idle(roles) these clients idle and no call on the server, rejected(role, code, text) the
# role's last call attempt failed so, on(roles, group) these clients affiliated to and on the group.
HELPERS=$(cat <<'PY'
import json, sys, time
ROLES = ('client-a', 'client-b', 'client-c', 'client-d')
IDS = {'client-a': 'sip:alice.mcptt@mcx.test', 'client-b': 'sip:bob.mcptt@mcx.test',
       'client-c': 'sip:client-c.mcptt@mcx.test', 'client-d': 'sip:client-d.mcptt@mcx.test'}
CHAT = 'sip:operations-chat@mcx.test'
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def sessions():
    value = st('mcptt-server').get('sessions') or []
    return list(value.values()) if isinstance(value, dict) else value
def chat_active(roles):
    s = [c for c in sessions() if c.get('call_type') == 'chat']
    return (len(s) == 1 and s[0].get('group_id') == CHAT and set(s[0].get('participants', [])) == {IDS[r] for r in roles}
            and all(st(r).get('call_state') == 'active' and st(r).get('call_type') == 'chat' for r in roles))
def roster(roles):
    return all(st(r).get('conference_active') and set(st(r).get('conference_participants', [])) == {IDS[x] for x in roles} for r in roles)
def idle(roles=ROLES):
    return all(st(r).get('call_state') == 'idle' for r in roles) and not sessions()
def rejected(role, code, text):
    failure = st(role).get('last_call_failure') or {}
    return st(role).get('call_state') == 'idle' and failure.get('status') == code and text in failure.get('warning', '')
def on(roles, group):
    return all(st(r).get('affiliated') and st(r).get('group_id') == group for r in roles)
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

# Check that a Python condition holds for the whole time given (nothing happens that should not).
hold_for() {
  local label=$1 condition=$2 seconds=$3
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
while time.monotonic() < deadline:
    if not eval(condition):
        sys.exit(1)
    time.sleep(0.1)" "$condition" "$seconds" || { echo "  FAILED: $label" >&2; exit 1; }
  echo "  ok: $label"
}

# Print a number from a role's status (a counter read before a step).
value() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
print(st(sys.argv[1]).get(sys.argv[2]) or 0)" "$1" "$2"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in; each selects the chat group operations-chat'
wait_for 'client-a to client-d authorized and affiliated' "all(st(r).get('authorized') and st(r).get('affiliated') for r in ROLES) and idle()" 90
for role in client-a client-b client-c client-d; do mcx "$role" group "$CHAT"; done
wait_for 'all four affiliated to operations-chat' "on(ROLES, CHAT)"

step '2. client-a joins first: the server creates the chat session and invites nobody'
mcx client-a chat
wait_for 'a chat session with client-a alone' "chat_active(['client-a'])"
hold_for 'nobody else is invited' "all(st(r).get('call_state') == 'idle' for r in ('client-b', 'client-c', 'client-d'))" 2

step '3. client-b joins the same session; both rosters list both'
mcx client-b chat
wait_for 'client-a and client-b in the chat session' "chat_active(['client-a', 'client-b'])"
wait_for 'both rosters list both' "roster(['client-a', 'client-b'])"

step '4. Floor control as in any group call: client-a talks, client-b is denied meanwhile, then client-b talks'
before=$(value client-b floor_denials)
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a has the floor' "st('client-a').get('talking')"
mcx client-b ptt /speech/bravo.wav
wait_for 'client-b denied while client-a talks' "st('client-b').get('floor_denials', 0) > $before"
wait_for 'client-a done, floor idle' "not st('client-a').get('talking') and not sessions()[0].get('floor_owner')" 20
mcx client-b ptt /speech/bravo.wav
wait_for 'client-b has the floor' "st('client-b').get('talking')"
wait_for 'client-b done, floor idle' "not st('client-b').get('talking') and not sessions()[0].get('floor_owner')" 20

step '5. client-c joins; client-d is one too many (the group allows three participants)'
mcx client-c chat
wait_for 'client-a, client-b and client-c in the chat session' "chat_active(['client-a', 'client-b', 'client-c'])"
wait_for 'the rosters list three' "roster(['client-a', 'client-b', 'client-c'])"
mcx client-d chat
wait_for 'client-d refused with 486 and warning 122' "rejected('client-d', 486, '122 too many participants')"

step '6. client-a, who created the session, leaves: the session goes on; then client-a joins it again'
mcx client-a hangup
wait_for 'client-b and client-c still in the session' "st('client-a').get('call_state') == 'idle' and chat_active(['client-b', 'client-c'])"
wait_for 'the rosters drop client-a' "roster(['client-b', 'client-c'])"
mcx client-a chat
wait_for 'client-a back in the same session' "chat_active(['client-a', 'client-b', 'client-c'])"

step '7. client-b and client-c leave: with one participant left, the server ends the session'
mcx client-b hangup
wait_for 'client-a and client-c remain' "chat_active(['client-a', 'client-c'])"
mcx client-c hangup
wait_for 'the server released client-a, no session' "idle()"

step '8. client-d joins alone: nobody else joins, and the session ends after 20 s of inactivity'
mcx client-d chat
wait_for 'a chat session with client-d alone' "chat_active(['client-d'])"
wait_for 'released by the inactivity timer' "idle()" 35

step '9. The call type must match the group type'
mcx client-a call
wait_for 'a prearranged call on the chat group: 404 with warning 118' "rejected('client-a', 404, '118 the group identity indicated in the request is a chat group')"
mcx client-a group "$PREARRANGED"
wait_for 'client-a on the prearranged group operations' "on(['client-a'], '$PREARRANGED')"
mcx client-a chat
wait_for 'a chat call on the prearranged group: 404 with warning 117' "rejected('client-a', 404, '117 the group identity indicated in the request is a prearranged group')"

step '10. Implicit affiliation: client-d leaves the group, then joins the chat anyway'
mcx client-d deaffiliate
wait_for 'client-d not affiliated' "not st('client-d').get('affiliated')"
mcx client-d call force
wait_for 'a normal call while not affiliated: 403 with warning 120' "rejected('client-d', 403, '120 user is not affiliated to this group')"
mcx client-d chat
wait_for 'the chat join is accepted' "chat_active(['client-d'])"
wait_for 'and the server affiliated client-d' "st('client-d').get('affiliated')"
mcx client-d hangup
wait_for 'session ended' "idle()"

step '11. Chat groups that do not allow a chat call now'
mcx client-c group sip:operations-chat-preconfigured@mcx.test
wait_for 'client-c on operations-chat-preconfigured' "on(['client-c'], 'sip:operations-chat-preconfigured@mcx.test')"
mcx client-c chat
wait_for 'refused with 403 and warning 167' "rejected('client-c', 403, '167 call is not allowed on the preconfigured group')"
mcx client-c group sip:operations-chat-regrouped@mcx.test
wait_for 'client-c on operations-chat-regrouped' "on(['client-c'], 'sip:operations-chat-regrouped@mcx.test')"
mcx client-c chat
wait_for 'refused with 403 and warning 148' "rejected('client-c', 403, '148 group is regrouped')"
wait_for 'no call anywhere' "idle()"

step "12. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z rtp,streams \
  2>/dev/null | grep -E 'RTP Streams|Src IP|AMR' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
