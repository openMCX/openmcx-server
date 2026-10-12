#!/usr/bin/env bash
# OpenMCX Unit Test Tutorial 10: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/10-dynamic-groups-run.pcap.gz (captures/10-dynamic-groups-full.pcap.gz is the reference run of
# README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=10-dynamic-groups-full.pcap   # in the capture container
OUT=captures/10-dynamic-groups-run.pcap.gz

NORTH=sip:operations-north@mcx.test        # client-a and client-b
SOUTH=sip:operations-south@mcx.test        # client-c and client-d
PRECONF=sip:operations-preconf@mcx.test    # the preconfigured group the regroups take their configuration from
REGROUP=sip:operations-regroup-1@mcx.test  # the group regroup
USERS=sip:operations-regroup-2@mcx.test    # the user regroup
TEMP=sip:operations-temp-1@mcx.test        # the temporary group formed by the GMS
ALICE=sip:alice.mcptt@mcx.test
CLIENT_C=sip:client-c.mcptt@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# Keep a role's status value (key) in client-a's container, for prev() in wait_for: tells a new answer from an old one.
remember() {
  "${DC[@]}" exec -T client-a python3 -c \
    "import json; s = json.load(open('/artifacts/$1/status.json')); json.dump(s.get('$2'), open('/tmp/prev.json', 'w'))"
}

# Wait until a Python condition on the clients' and the server's status holds; st('client-a') is a role's
# status.json, rg(role) the regroups the role was told of, res(role) its last regroup answer, srv() the MCPTT server's
# status, prev() the value remember() kept, active(...) these clients in a call, idle() every client out of calls.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
ROLES = ('client-a', 'client-b', 'client-c', 'client-d')
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def rg(role):
    return st(role).get('regroups') or {}
def res(role):
    return st(role).get('regroup_result') or {}
def srv():
    return st('mcptt-server')
def prev():
    try:
        return json.load(open('/tmp/prev.json'))
    except (OSError, ValueError):
        return None
def active(*roles):
    return all(st(r).get('call_state') == 'active' for r in roles)
def idle():
    return all(st(r).get('call_state') != 'active' for r in ROLES)
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.2)
sys.exit(1)
PY
  echo "  ok: $label"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in: client-a and client-b in operations-north, client-c and client-d in operations-south'
wait_for 'client-a to client-d authorized and affiliated' "all(st(r).get('authorized') and st(r).get('affiliated') for r in ROLES)" 90

step '2. A group regroup: client-b may not create one, client-a may'
mcx client-b regroup create "$REGROUP" "$PRECONF" "$NORTH,$SOUTH"
wait_for 'client-b refused: 403, warning 160' "res('client-b').get('regroup') == '$REGROUP' and res('client-b').get('status') == 403 and '160' in res('client-b').get('warning', '')"
mcx client-a regroup create "$REGROUP" "$PRECONF" "$NORTH,$SOUTH"
wait_for 'client-a answered 200' "res('client-a').get('action') == 'create' and res('client-a').get('regroup') == '$REGROUP' and res('client-a').get('status') == 200"
wait_for 'every member of both groups told of the regroup' "all('$REGROUP' in rg(r) for r in ROLES)"
wait_for 'both constituent groups regrouped on the server' "(srv().get('regrouped_groups') or {}).get('$NORTH') == '$REGROUP' and (srv().get('regrouped_groups') or {}).get('$SOUTH') == '$REGROUP'"

step '3. A call on a regrouped constituent group is refused'
remember client-a last_call_failure
mcx client-a call
wait_for 'client-a refused: warning 148' "st('client-a').get('last_call_failure') != prev() and '148' in json.dumps(st('client-a').get('last_call_failure') or {})"

step '4. A call on the regroup reaches the members of both groups'
for role in client-a client-b client-c client-d; do mcx "$role" group "$REGROUP"; done
wait_for 'every client uses the regroup' "all(st(r).get('group_id') == '$REGROUP' and st(r).get('affiliated') for r in ROLES)"
mcx client-a call
wait_for 'client-a, client-b, client-c and client-d in the call' "active(*ROLES)" 40
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a talks to both groups' "st('client-c').get('received_packets', 0) > 20 and not st('client-a').get('talking')" 30

step '5. client-a removes the regroup: the call ends and the groups are free'
mcx client-a regroup remove "$REGROUP"
wait_for 'client-a answered 200' "res('client-a').get('action') == 'remove' and res('client-a').get('status') == 200"
wait_for 'every member told the regroup is gone, the call released' "all('$REGROUP' not in rg(r) for r in ROLES) and idle()" 40
wait_for 'the server holds no regroup' "not (srv().get('regroups') or {}) and not (srv().get('regrouped_groups') or {})"
for role in client-a client-b; do mcx "$role" group "$NORTH"; done
for role in client-c client-d; do mcx "$role" group "$SOUTH"; done
wait_for 'every client back on its own group' "all(st(r).get('affiliated') and st(r).get('group_id') in ('$NORTH', '$SOUTH') for r in ROLES)" 40

step '6. A user regroup of client-a and client-c'
mcx client-a regroup users "$USERS" "$PRECONF" "$ALICE,$CLIENT_C"
wait_for 'client-a answered 200' "res('client-a').get('regroup') == '$USERS' and res('client-a').get('status') == 200"
wait_for 'client-a and client-c told; client-b and client-d not' "'$USERS' in rg('client-a') and '$USERS' in rg('client-c') and '$USERS' not in rg('client-b') and '$USERS' not in rg('client-d')"
mcx client-a group "$USERS"
wait_for 'client-a uses the user regroup' "st('client-a').get('group_id') == '$USERS' and st('client-a').get('affiliated')"
mcx client-a call
wait_for 'client-c takes the call on the user regroup without selecting it' "active('client-a', 'client-c') and st('client-c').get('call_group') == '$USERS' and st('client-c').get('group_id') == '$SOUTH'" 40
wait_for 'client-b and client-d not invited' "st('client-b').get('call_state') != 'active' and st('client-d').get('call_state') != 'active'"
mcx client-a regroup remove "$USERS"
wait_for 'removed: both told, the call released' "res('client-a').get('action') == 'remove' and res('client-a').get('status') == 200 and '$USERS' not in rg('client-a') and '$USERS' not in rg('client-c') and idle()" 40
mcx client-a group "$NORTH"
wait_for 'client-a back on operations-north' "st('client-a').get('group_id') == '$NORTH' and st('client-a').get('affiliated')"

step '7. A temporary group formed by the GMS (XCAP over HTTPS, not in the capture)'
remember client-b xcap_last
mcx client-b temporary-create temp-1 "$TEMP" "$NORTH,$SOUTH"
wait_for 'client-b refused: 403' "(st('client-b').get('xcap_last') or {}) != prev() and (st('client-b').get('xcap_last') or {}).get('status') == 403"
remember client-a xcap_last
mcx client-a temporary-create temp-1 "$TEMP" "$NORTH,$SOUTH"
wait_for 'client-a forms it: 200' "(st('client-a').get('xcap_last') or {}) != prev() and (st('client-a').get('xcap_last') or {}).get('status') == 200"
wait_for 'the MCPTT server holds it and both groups are regrouped' "(srv().get('regroups') or {}).get('$TEMP', {}).get('temporary') and (srv().get('regrouped_groups') or {}).get('$NORTH') == '$TEMP'" 20
wait_for 'every member of both groups told' "all('$TEMP' in rg(r) for r in ROLES)" 20
remember client-a last_call_failure
mcx client-a call
wait_for 'a call on operations-north is refused: warning 148' "st('client-a').get('last_call_failure') != prev() and '148' in json.dumps(st('client-a').get('last_call_failure') or {})" 40
for role in client-a client-b client-c client-d; do mcx "$role" group "$TEMP"; done
wait_for 'every client uses the temporary group' "all(st(r).get('group_id') == '$TEMP' and st(r).get('affiliated') for r in ROLES)" 40
mcx client-a call
wait_for 'the call on the temporary group joins both groups' "active(*ROLES)" 40
remember client-a xcap_last
mcx client-a temporary-delete temp-1
wait_for 'client-a tears it down: 200' "(st('client-a').get('xcap_last') or {}) != prev() and (st('client-a').get('xcap_last') or {}).get('status') == 200"
wait_for 'the call released, every member told, the groups free' "idle() and all('$TEMP' not in rg(r) for r in ROLES) and not (srv().get('regrouped_groups') or {})" 40

step "8. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|BYE|MESSAGE|NOTIFY|SIP 200|SIP 403)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
