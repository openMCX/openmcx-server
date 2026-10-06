#!/usr/bin/env bash
# openMCX Unit Test Tutorial 13: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/13-mcdata-sds-status-run.pcap.gz (captures/13-mcdata-sds-status-full.pcap.gz is the reference run
# of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=13-mcdata-sds-status-full.pcap   # in the capture container
OUT=captures/13-mcdata-sds-status-run.pcap.gz
ALICE=sip:alice.mcdata@mcx.test
BOB=sip:bob.mcdata@mcx.test
CLIENT_D=sip:client-d.mcdata@mcx.test
GROUP=sip:operations@mcx.test
NO_STATUS=sip:operations-noemergency@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of wait_for and remember: st('client-a') is a role's status.json, inbox(role, text) the SDS it
# received with that text, notes(role, id) the disposition notifications it received for a message (type 2 DELIVERED,
# 3 READ, 4 DELIVERED AND READ), last(role) the outcome of its last SDS, sent(role) the SDS it sent, statuses(role)
# the enhanced statuses it rendered, saved[...] values remembered by remember().
HELPERS='
import json, sys, time
def st(role):
    try:
        return json.load(open(f"/artifacts/{role}/status.json"))
    except (OSError, ValueError):
        return {}
def inbox(role, text):
    return [m for m in st(role).get("mcdata_inbox") or [] if any(p.get("text") == text for p in m.get("payloads", []))]
def notes(role, message_id):
    return [n for n in st(role).get("mcdata_notifications") or [] if n.get("message_id") == message_id]
def last(role):
    return st(role).get("mcdata_last_result") or {}
def sent(role):
    return st(role).get("mcdata_sent") or []
def statuses(role):
    return st(role).get("mcdata_enhanced_status") or []
try:
    saved = json.load(open("/tmp/saved.json"))
except (OSError, ValueError):
    saved = {}
'

# Wait until a Python condition on the clients' and the server's status holds.
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

# Check that a Python condition holds for the whole of a short time (something that must not happen).
hold_for() {
  local label=$1 condition=$2 seconds=${3:-1}
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
while time.monotonic() < deadline:
    if not eval(condition):
        sys.exit(1)
    time.sleep(0.1)" "$condition" "$seconds" || { echo "  FAILED: $label" >&2; exit 1; }
  echo "  ok: $label"
}

# Remember the value of a Python expression as saved[name], and print it.
remember() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
saved[sys.argv[1]] = eval(sys.argv[2])
json.dump(saved, open('/tmp/saved.json', 'w'))
print(saved[sys.argv[1]])" "$1" "$2"
}

# Send an SDS from a role and wait for its outcome (202 or a refusal with a warning); remember its Message ID as
# saved[name] and print it (the progress goes to stderr).
send_sds() {
  local name=$1 role=$2 expect=$3 warning=$4
  shift 4
  remember "${name}_before" "len(sent('$role'))" >/dev/null
  mcx "$role" "$@" >&2
  wait_for "$role's SDS answered $expect${warning:+ with warning $warning}" "len(sent('$role')) > saved['${name}_before'] and last('$role').get('message_id') == sent('$role')[-1]['message_id'] and last('$role').get('status') == $expect and '$warning' in last('$role').get('warning', '')" >&2
  remember "$name" "sent('$role')[-1]['message_id']"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in, MCData-authorised and affiliated to the group operations'
wait_for 'client-a to client-d MCData-authorised and affiliated' "all(st(r).get('mcdata_authorized') and st(r).get('mcdata_affiliated') for r in ('client-a','client-b','client-c','client-d'))" 90

step '2. A one-to-one SDS from alice to bob, and bob replies in the same conversation'
first=$(send_sds first client-a 202 '' sds "$BOB" hello-bob)
wait_for 'bob receives it from alice, rendered to the user' "inbox('client-b','hello-bob') and inbox('client-b','hello-bob')[0]['from'] == '$ALICE' and inbox('client-b','hello-bob')[0]['delivered_to'] == 'user'"
hold_for 'nobody else receives it' "not any(inbox(r,'hello-bob') for r in ('client-a','client-c','client-d'))"
mcx client-b sds-reply "$first" hello-alice
wait_for 'the reply reaches alice with InReplyTo and the same conversation' "inbox('client-a','hello-alice') and inbox('client-a','hello-alice')[0]['in_reply_to'] == '$first' and inbox('client-a','hello-alice')[0]['conversation_id'] == inbox('client-b','hello-bob')[0]['conversation_id']"

step '3. Disposition notifications: delivery, read after display, delivered and read'
delivery=$(send_sds delivery client-a 202 '' sds delivery "$BOB" please-confirm)
wait_for 'a DELIVERED notification from bob' "[n['type'] for n in notes('client-a','$delivery')] == [2] and notes('client-a','$delivery')[0]['from'] == '$BOB'"
read=$(send_sds read client-a 202 '' sds read "$BOB" please-read)
wait_for 'bob receives it' "inbox('client-b','please-read')"
hold_for 'no notification before bob displays it' "not notes('client-a','$read')"
mcx client-b sds-display "$read"
wait_for 'a READ notification after the display' "[n['type'] for n in notes('client-a','$read')] == [3]"
both=$(send_sds both client-a 202 '' sds both "$BOB" read-at-once)
wait_for 'bob receives it' "inbox('client-b','read-at-once')"
mcx client-b sds-display "$both"
wait_for 'one DELIVERED AND READ notification, displayed within TDU1' "[n['type'] for n in notes('client-a','$both')] == [4]"

step '4. Refused one-to-one SDS (transmission control)'
send_sds no_right client-d 403 200 sds "$ALICE" not-allowed >/dev/null
send_sds no_target client-a 403 229 sds "$CLIENT_D" not-a-target >/dev/null
send_sds no_sender client-c 403 230 sds "$BOB" not-from-you >/dev/null

step '5. A group SDS asking for delivery: every other affiliated member, one aggregated notification'
group=$(send_sds group client-a 202 '' sds-group delivery "$GROUP" to-everyone)
wait_for 'bob, client-c and client-d receive it with the group identity' "all(inbox(r,'to-everyone') and inbox(r,'to-everyone')[0]['group'] == '$GROUP' for r in ('client-b','client-c','client-d'))"
hold_for 'alice does not receive her own group message' "not inbox('client-a','to-everyone')"
wait_for 'three DELIVERED notifications, sent to alice together in one message' "len(notes('client-a','$group')) == 3 and all(n['type'] == 2 and n['group'] == '$GROUP' and n.get('aggregated') == 3 for n in notes('client-a','$group'))"

step '6. A group SDS asking for read: two read it, the third later'
group_read=$(send_sds group_read client-a 202 '' sds-group read "$GROUP" read-by-all)
wait_for 'every other member receives it' "all(inbox(r,'read-by-all') for r in ('client-b','client-c','client-d'))"
mcx client-b sds-display "$group_read"
mcx client-d sds-display "$group_read"
hold_for 'the READ notifications are held while TDC1 runs' "not notes('client-a','$group_read')"
wait_for 'TDC1 expiry sends both READ notifications in one aggregate' "sorted((n['from'], n['type'], n.get('aggregated')) for n in notes('client-a','$group_read')) == sorted([('$BOB', 3, 2), ('$CLIENT_D', 3, 2)])" 10
mcx client-c sds-display "$group_read"
wait_for 'the late READ from client-c is relayed on its own' "any(n['from'] == 'sip:client-c.mcdata@mcx.test' and n['type'] == 3 and n.get('aggregated') == 1 for n in notes('client-a','$group_read'))"

step '7. A member that is not affiliated receives no group SDS'
mcx client-d mcdata-deaffiliate
wait_for 'client-d is not affiliated' "not st('client-d').get('mcdata_affiliated')"
send_sds after client-a 202 '' sds-group "$GROUP" while-d-is-away >/dev/null
wait_for 'bob and client-c receive it' "inbox('client-b','while-d-is-away') and inbox('client-c','while-d-is-away')"
hold_for 'client-d does not' "not inbox('client-d','while-d-is-away')"
mcx client-d mcdata-affiliate
wait_for 'client-d affiliated again' "st('client-d').get('mcdata_affiliated')"

step '8. Enhanced status: a member shares one of the group operational values'
mcx client-a sds-status-values "$GROUP"
wait_for "the group document allows it and names 1 On scene, 2 En route, 3 Available" "(st('client-a').get('mcdata_enhanced_status_values') or {}).get('$GROUP') == {'allowed': True, 'values': [{'id': '1', 'value': 'On scene'}, {'id': '2', 'value': 'En route'}, {'id': '3', 'value': 'Available'}]}"
send_sds status_1 client-a 202 '' sds-status "$GROUP" 1 >/dev/null
wait_for 'bob, client-c and client-d render "On scene" from alice' "all(any(e['from'] == '$ALICE' and e['id'] == '1' and e['value'] == 'On scene' for e in statuses(r)) for r in ('client-b','client-c','client-d'))"
send_sds status_2 client-b 202 '' sds-status "$GROUP" 2 >/dev/null
wait_for 'alice, client-c and client-d render "En route" from bob' "all(any(e['from'] == '$BOB' and e['value'] == 'En route' for e in statuses(r)) for r in ('client-a','client-c','client-d'))"
mcx client-a sds-status "$NO_STATUS" 1
wait_for 'the client refuses a group without enhanced status' "'enhanced status is not allowed' in st('client-a').get('last_error', '')"
mcx client-a sds-status "$GROUP" 9
wait_for 'the client refuses an id the group does not know' "'no operational value' in st('client-a').get('last_error', '')"
remember discarded "{r: st(r).get('mcdata_discarded', 0) for r in ('client-b','client-c','client-d')}" >/dev/null
send_sds status_9 client-a 202 '' sds-status "$GROUP" 9 force >/dev/null
wait_for 'sent anyway (test aid): each member discards the unknown id' "all(st(r).get('mcdata_discarded', 0) == saved['discarded'][r] + 1 for r in ('client-b','client-c','client-d'))"
send_sds status_c client-c 403 201 sds-status "$GROUP" 3 >/dev/null

step "9. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(MESSAGE|PUBLISH|SUBSCRIBE|NOTIFY|SIP 202|SIP 403)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
