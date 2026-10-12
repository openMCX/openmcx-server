#!/usr/bin/env bash
# OpenMCX Unit Test Tutorial 19: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/19-mcvideo-emergency-adhoc-regroup-run.pcap.gz (captures/19-mcvideo-emergency-adhoc-regroup-full.pcap.gz
# is the reference run of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=19-mcvideo-emergency-adhoc-regroup-full.pcap   # in the capture container
OUT=captures/19-mcvideo-emergency-adhoc-regroup-run.pcap.gz
ALICE=sip:alice.mcvideo@mcx.test
BOB=sip:bob.mcvideo@mcx.test
CLIENT_C=sip:client-c.mcvideo@mcx.test
GROUP=sip:operations@mcx.test
CLOSED=sip:video-closed@mcx.test
PRECONF=sip:video-regroup@mcx.test
REGROUP=sip:video-rg1@mcx.test
USER_REGROUP=sip:video-rg2@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of wait_for and remember: st(role) is a role's status.json, video() the MCVideo server's,
# active(*roles) clients in an MCVideo call, idle(*roles) clients without one, prio(role) the priority state of its
# call (normal, emergency or imminent), result(role, action, on) the answer to its last change of that priority,
# same(sender, receiver) the pictures the receiver decoded compared with those the sender encoded (by RTP timestamp),
# last(role) the outcome of its last call, adhoc(*roles) clients in one ad hoc group call, regroups(role) the
# regroups it was told of, regrouped(role) the answer to its last regroup request, regroup_affiliated(group, *roles)
# the members the server counts affiliated with a regroup, on(group, *roles) clients in a call on that group,
# saved[...] values remembered by remember().
HELPERS='
import json, sys, time
ROLES = ("client-a", "client-b", "client-c", "client-d")
IDS = {"client-a": "sip:alice.mcvideo@mcx.test", "client-b": "sip:bob.mcvideo@mcx.test",
       "client-c": "sip:client-c.mcvideo@mcx.test", "client-d": "sip:client-d.mcvideo@mcx.test"}
def st(role):
    try:
        return json.load(open(f"/artifacts/{role}/status.json"))
    except (OSError, ValueError):
        return {}
def video():
    return st("mcvideo-server")
def active(*roles):
    return all(st(r).get("mcvideo_call_state") == "active" for r in roles or ROLES)
def idle(*roles):
    return all(st(r).get("mcvideo_call_state") == "idle" for r in roles or ROLES)
def tx(role):
    return st(role).get("mcvideo_transmitting") is True
def prio(role):
    return st(role).get("mcvideo_priority")
def all_prio(value, *roles):
    return all(prio(r) == value for r in roles or ROLES)
def result(role, action, on):
    r = st(role).get("mcvideo_priority_result") or {}
    return r if r.get("action") == action and r.get("enabled") == on else {}
def compare(sent, received):
    common = [k for k in received if k in sent]
    return len(common), sum(1 for k in common if sent[k] == received[k])
def same(sender, receiver, least=15):
    compared, equal = compare(st(sender).get("mcvideo_sent_frames") or {}, st(receiver).get("mcvideo_received_frames") or {})
    return compared >= least and equal == compared
def last(role):
    return st(role).get("mcvideo_last_call") or {}
def alerts(role):
    return st(role).get("mcvideo_alerts") or {}
def adhoc(*roles):
    groups = {st(r).get("mcvideo_group") for r in roles}
    return (all(st(r).get("mcvideo_call_state") == "active" and st(r).get("mcvideo_call_type") == "adhoc" for r in roles)
            and len(groups) == 1 and not groups & {None, ""})
def adhoc_alerts(role):
    return st(role).get("mcvideo_received_adhoc_alerts") or {}
def regroups(role):
    return st(role).get("mcvideo_regroups") or {}
def regrouped(role):
    return st(role).get("mcvideo_regroup_result") or {}
def regroup_affiliated(group, *roles):
    return all(IDS[r] in (((video().get("regroups") or {}).get(group) or {}).get("affiliated") or []) for r in roles)
def on(group, *roles):
    return all(st(r).get("mcvideo_call_state") == "active" and st(r).get("mcvideo_group") == group for r in roles)
try:
    saved = json.load(open("/tmp/saved.json"))
except (OSError, ValueError):
    saved = {}
'

# Wait until a Python condition on the clients' and the server's status holds.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-60}
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
  local label=$1 condition=$2 seconds=${3:-2}
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
while time.monotonic() < deadline:
    if not eval(condition):
        sys.exit(1)
    time.sleep(0.1)" "$condition" "$seconds" || { echo "  FAILED: $label" >&2; exit 1; }
  echo "  ok: $label"
}

# Remember the value of a Python expression as saved[name].
remember() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
saved[sys.argv[1]] = eval(sys.argv[2])
json.dump(saved, open('/tmp/saved.json', 'w'))" "$1" "$2"
}

# A regroup request: wait for a new answer to the role's last one, with this status code and, when given, this
# warning code.
regroup() {
  local label=$1 role=$2 code=$3 warning=$4
  shift 4
  remember before "json.dumps(regrouped('$role'))"
  mcx "$role" mcvideo-regroup "$@"
  wait_for "$label" "json.dumps(regrouped('$role')) != saved['before'] and regrouped('$role').get('status') == $code and '$warning' in regrouped('$role').get('warning', '')"
}

# A call the server refuses: wait for a new outcome of the role's last call, with this status code and warning code.
refused() {
  local label=$1 role=$2 code=$3 warning=$4
  shift 4
  remember before "json.dumps(last('$role'))"
  mcx "$role" "$@"
  wait_for "$label" "json.dumps(last('$role')) != saved['before'] and idle('$role') and last('$role').get('status') == $code and '$warning' in last('$role').get('warning', '')"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in to MCVideo and affiliated to operations'
wait_for 'client-a to client-d authorized and affiliated' "all(st(r).get('mcvideo_authorized') and st(r).get('mcvideo_affiliated') for r in ROLES)" 90

step '2. Emergency group call: alice calls operations as an emergency; she cancels the emergency'
mcx client-a mcvideo-call emergency
wait_for 'all four in the group call' "active()"
wait_for 'every member knows the call is an emergency' "all_prio('emergency')"
mcx client-a mcvideo-emergency off
wait_for 'alice'"'"'s cancellation is accepted (200)' "result('client-a', 'emergency', False).get('status') == 200"
wait_for 'every member back to normal' "all_prio('normal')"

step '3. Refused: client-c may not raise an emergency (403)'
mcx client-c mcvideo-emergency on
wait_for 'client-c refused with 403, not for a malformed request (warning 150)' "result('client-c', 'emergency', True).get('status') == 403 and '150' not in result('client-c', 'emergency', True).get('warning', '')"
hold_for 'the call stays normal' "all_prio('normal')"

step '4. Imminent peril: bob raises it, then ends it'
mcx client-b mcvideo-imminent on
wait_for 'every member in imminent peril' "all_prio('imminent')"
mcx client-b mcvideo-imminent off
wait_for 'every member back to normal' "all_prio('normal')"

step '5. An emergency pre-empts a normal transmission'
mcx client-a mcvideo-emergency on
wait_for 'the call is an emergency again' "all_prio('emergency')"
mcx client-c mcvideo-transmit
wait_for 'client-c transmits' "tx('client-c')"
remember revocations "st('client-c').get('mcvideo_revocations', 0)"
mcx client-a mcvideo-transmit
wait_for 'alice is granted; client-c is revoked with cause 4 (pre-empted)' "tx('client-a') and not tx('client-c') and st('client-c').get('mcvideo_revocations', 0) > saved['revocations'] and st('client-c').get('mcvideo_reject_cause') == 4"
wait_for 'bob decodes alice'"'"'s pictures' "same('client-a', 'client-b', 10)"
mcx client-a mcvideo-end
mcx client-a mcvideo-emergency off
wait_for 'back to normal' "all_prio('normal')"
mcx client-a mcvideo-hangup
wait_for 'alice, who started the call, leaves: the call ends for all' "idle()"

step '6. Emergency private call: alice calls bob'
mcx client-a mcvideo-private "$BOB" auto emergency
wait_for 'alice and bob in the call, both in the emergency state' "active('client-a', 'client-b') and all_prio('emergency', 'client-a', 'client-b')"
mcx client-a mcvideo-hangup
wait_for 'call released' "idle('client-a', 'client-b')"

step '7. Emergency alert: alice raises it, with her location, then cancels it'
mcx client-a mcvideo-alert on
wait_for 'alice'"'"'s alert is accepted' "st('client-a').get('mcvideo_alerting') is True"
wait_for 'bob, client-c and client-d receive it with her location' "all((alerts(r).get(IDS['client-a']) or {}).get('location') for r in ('client-b', 'client-c', 'client-d'))"
mcx client-a mcvideo-alert off
wait_for 'alice'"'"'s alert is cancelled' "st('client-a').get('mcvideo_alerting') is False"
wait_for 'the others see it withdrawn' "not any(IDS['client-a'] in alerts(r) for r in ('client-b', 'client-c', 'client-d'))"

step '8. Ad hoc group call: alice calls bob and client-c'
mcx client-a mcvideo-adhoc "$BOB" "$CLIENT_C"
wait_for 'alice, bob and client-c in one ad hoc group call' "adhoc('client-a', 'client-b', 'client-c')"
wait_for 'the ad hoc group identity is new, not operations; client-d is not invited' "st('client-a').get('mcvideo_group') != '$GROUP' and idle('client-d')"
mcx client-a mcvideo-transmit
wait_for 'alice transmits; bob and client-c decode her pictures' "tx('client-a') and same('client-a', 'client-b', 10) and same('client-a', 'client-c', 10)"
mcx client-a mcvideo-end
wait_for 'alice released the transmission' "not tx('client-a')"
mcx client-b mcvideo-transmit
wait_for 'bob transmits in turn; client-c decodes his pictures' "tx('client-b') and same('client-b', 'client-c', 5)"
mcx client-a mcvideo-hangup
wait_for 'alice, the originator, leaves: the call ends for all' "idle()"

step '9. Ad hoc group call by criteria: everyone affiliated to operations; client-d may not call'
mcx client-a mcvideo-adhoc criteria "affiliated:$GROUP"
wait_for 'all four in one ad hoc group call' "adhoc(*ROLES)"
mcx client-a mcvideo-hangup
wait_for 'the call ended' "idle()"
refused 'client-d'"'"'s ad hoc group call: 403 with warning 185' client-d 403 185 mcvideo-adhoc "$ALICE"

step '10. Ad hoc group emergency alert: alice raises it to everyone affiliated to operations, then cancels it'
mcx client-a mcvideo-adhoc-alert "affiliated:$GROUP"
wait_for 'alice'"'"'s alert is accepted (200) and confirmed' "st('client-a').get('mcvideo_adhoc_alert_state') == 3 and (st('client-a').get('mcvideo_adhoc_alert_result') or {}).get('status') == 200 and st('client-a').get('mcvideo_adhoc_alert_group')"
wait_for 'bob, client-c and client-d receive it from alice, with its ad hoc group' "all((adhoc_alerts(r).get(st('client-a')['mcvideo_adhoc_alert_group']) or {}).get('initiator') == IDS['client-a'] for r in ('client-b', 'client-c', 'client-d'))"
remember alert "st('client-a')['mcvideo_adhoc_alert_group']"
mcx client-a mcvideo-adhoc-alert cancel
wait_for 'the cancellation clears it everywhere' "st('client-a').get('mcvideo_adhoc_alert_state') == 1 and not any(saved['alert'] in adhoc_alerts(r) for r in ('client-b', 'client-c', 'client-d'))"
mcx client-b mcvideo-adhoc-alert "affiliated:$GROUP"
wait_for 'bob may not raise one: 403' "(st('client-b').get('mcvideo_adhoc_alert_result') or {}).get('status') == 403 and st('client-b').get('mcvideo_adhoc_alert_state') == 1"

step '11. Group regroup: bob may not create one; alice regroups operations with video-closed'
regroup 'bob refused: 403 with warning 160' client-b 403 160 create "$USER_REGROUP" "$PRECONF" users "$CLIENT_C"
regroup 'alice'"'"'s group regroup is accepted (200)' client-a 200 '' create "$REGROUP" "$PRECONF" groups "$GROUP,$CLOSED"
wait_for 'every affiliated member is told, with both groups and the preconfigured group' "all(set(regroups(r).get('$REGROUP', {}).get('groups', [])) == {'$GROUP', '$CLOSED'} and regroups(r)['$REGROUP'].get('preconfigured') == '$PRECONF' for r in ROLES)"

step '12. A call on the regroup reaches the members of both groups'
wait_for 'the server counts every member it told affiliated with the regroup, without a request' "regroup_affiliated('$REGROUP', *ROLES)"
mcx client-a mcvideo-call "group=$REGROUP"
wait_for 'all four in the call on the regroup' "on('$REGROUP', *ROLES)"
mcx client-a mcvideo-transmit
wait_for 'alice transmits; client-c decodes her pictures' "tx('client-a') and same('client-a', 'client-c', 10)"
mcx client-a mcvideo-hangup
wait_for 'alice, who started the call, leaves: the call ends for all' "idle()"

step '13. Refused while regrouped: a call on operations (148), bob'"'"'s removal (161); then alice removes the regroup'
refused 'bob'"'"'s call on operations: 403 with warning 148' client-b 403 148 mcvideo-call
regroup 'bob'"'"'s removal: 403 with warning 161' client-b 403 161 remove "$REGROUP"
regroup 'alice'"'"'s removal is accepted (200)' client-a 200 '' remove "$REGROUP"
wait_for 'every member is told of the removal' "not any('$REGROUP' in regroups(r) for r in ROLES)"

step '14. User regroup: alice regroups bob and client-c; bob calls it'
regroup 'alice'"'"'s user regroup is accepted (200)' client-a 200 '' create "$USER_REGROUP" "$PRECONF" users "$BOB,$CLIENT_C"
wait_for 'bob and client-c are told; alice and client-d are not' "all('$USER_REGROUP' in regroups(r) for r in ('client-b', 'client-c')) and not any('$USER_REGROUP' in regroups(r) for r in ('client-a', 'client-d'))"
wait_for 'the server counts bob and client-c affiliated with it, without a request' "regroup_affiliated('$USER_REGROUP', 'client-b', 'client-c')"
mcx client-b mcvideo-call "group=$USER_REGROUP"
wait_for 'bob and client-c in the call on the user regroup' "on('$USER_REGROUP', 'client-b', 'client-c')"
hold_for 'alice and client-d are not in it' "idle('client-a', 'client-d')"
mcx client-b mcvideo-hangup
wait_for 'bob leaves; client-c alone, the call ends' "idle()"
regroup 'alice removes the user regroup (200)' client-a 200 '' remove "$USER_REGROUP"
wait_for 'its members are told of the removal' "not any('$USER_REGROUP' in regroups(r) for r in ROLES)"

step "15. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|re-INVITE|MESSAGE|BYE|SIP 200|SIP 403)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
