#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Unit Test Tutorial 16: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/16-location-run.pcap.gz (captures/16-location-full.pcap.gz is the reference run of README.md).
# Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=16-location-full.pcap   # in the capture container
OUT=captures/16-location-run.pcap.gz
ALICE=sip:alice.mcptt@mcx.test
BOB=sip:bob.mcptt@mcx.test
CLIENT_C=sip:client-c.mcptt@mcx.test
GROUP=sip:operations@mcx.test
# Two E-UTRAN cell global identities (PLMN 208 01, as text) for the cell change trigger.
ECGI_1=2080100000000000000000000000000001
ECGI_2=2080100000000000000000000000000010

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of wait_for and remember: st(role) is a role's status.json, loc(role) its location state,
# server() the MCPTT server's location state, stored(role) what the server stores for that role's user, sent(role)
# the reports it sent, with(role, trigger, after) those from index `after` on that name the trigger, answered(role,
# id) the reports it received for a request, last(role) the result of its last location request or configuration,
# near(coordinate, lat, lon) a coordinate close to a point, saved[...] values remembered by remember().
HELPERS='
import json, sys, time
IDS = {"client-a": "sip:alice.mcptt@mcx.test", "client-b": "sip:bob.mcptt@mcx.test",
       "client-c": "sip:client-c.mcptt@mcx.test", "client-d": "sip:client-d.mcptt@mcx.test"}
def st(role):
    try:
        return json.load(open(f"/artifacts/{role}/status.json"))
    except (OSError, ValueError):
        return {}
def loc(role):
    return st(role).get("location") or {}
def server():
    return st("mcptt-server").get("location") or {}
def counter(name):
    return server().get("counters", {}).get(name, 0)
def stored(role):
    return server().get("users", {}).get(IDS[role], {})
def sent(role):
    return loc(role).get("sent", [])
def with_(role, trigger, after=0):
    return [r for r in sent(role)[after:] if trigger in r.get("triggers", [])]
def answered(role, rid):
    return [r for r in loc(role).get("received", []) if r.get("id") == rid]
def last(role):
    return st(role).get("location_last_result") or {}
def near(c, lat, lon):
    return bool(c) and abs(c["latitude"] - lat) < 1e-4 and abs(c["longitude"] - lon) < 1e-4
def alerts():
    return st("mcptt-server").get("group_priority", {}).get("sip:operations@mcx.test", {}).get("alerts", [])
try:
    saved = json.load(open("/tmp/saved.json"))
except (OSError, ValueError):
    saved = {}
'

# Wait until a Python condition on the clients' and the server's status holds.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-20}
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
  local label=$1 condition=$2 seconds=${3:-3}
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

# A location request from a role (TS 24.379 clause 13.2.3.2); remember its RequestId as saved[name].
request() {
  local name=$1 role=$2
  shift 2
  remember "${name}_before" "st('$role').get('location_last_request')" >/dev/null
  mcx "$role" location request "$@"
  wait_for "$role's request is sent" "st('$role').get('location_last_request') not in (None, saved['${name}_before'])" 5
  remember "$name" "st('$role')['location_last_request']" >/dev/null
}

step() { printf '\n%s\n' "$*"; }

step '1. Log-on: every client gets its reporting configuration and reports where it is'
wait_for 'every client holds the configuration the server sent after its service authorisation' "all(loc(r).get('configured') for r in IDS) and counter('configured') >= 4" 60
wait_for 'the triggers are numbered t1 to t6, the emergency trigger t7' "stored('client-a').get('configuration', {}).get('triggers') == ['t1','t2','t3','t4','t5','t6'] and stored('client-a').get('configuration', {}).get('emergency_triggers') == ['t7']"
wait_for 'client-a, client-b and client-c report their log-on position (t1), and the server stores it' "all(with_(r, 't1') and near(stored(r).get('report', {}).get('coordinate'), 48.0, 2.0 + 0.01 * i) for i, r in enumerate(['client-a','client-b','client-c']))"
wait_for 'client-d may not report: refused 403, nothing stored' "sent('client-d') and not stored('client-d').get('report') and counter('refused') >= 1"

step '2. Triggers: distance, entering and leaving a zone, a cell change, a group call'
remember a0 "len(sent('client-a'))" >/dev/null
mcx client-a location position 48.0 2.004
wait_for 'moving 300 m fires the travelled-distance trigger t3' "with_('client-a', 't3', saved['a0']) and near(stored('client-a').get('report', {}).get('coordinate'), 48.0, 2.004)"
remember a1 "len(sent('client-a'))" >/dev/null
mcx client-a location position 48.01 2.0
wait_for 'entering the configured zone fires t4' "with_('client-a', 't4', saved['a1'])"
remember a2 "len(sent('client-a'))" >/dev/null
mcx client-a location position 48.0 2.004
wait_for 'leaving it fires t5' "with_('client-a', 't5', saved['a2'])"
mcx client-a location radio cell "$ECGI_1"
remember a3 "len(sent('client-a'))" >/dev/null
mcx client-a location radio cell "$ECGI_2"
wait_for 'a cell change fires t6, and the report carries the new cell' "any(r.get('serving_ecgi') == '$ECGI_2' for r in with_('client-a', 't6', saved['a3']))"
remember a4 "len(sent('client-a'))" >/dev/null
mcx client-a call
wait_for 'a group call fires t2' "with_('client-a', 't2', saved['a4'])"
mcx client-a hangup
wait_for 'the call ends' "st('client-a').get('call_state') == 'idle'"

step '3. Requests: alice asks where bob is, from what is stored, then fresh'
request r1 client-a "$BOB"
wait_for 'alice gets bob'"'"'s stored position, with her RequestId and bob as reporting user' "any(r.get('reporting_uri') == '$BOB' and near(r.get('coordinate'), 48.0, 2.01) for r in answered('client-a', saved['r1'])) and last('client-a').get('status') == 200"
remember b0 "len(sent('client-b'))" >/dev/null
request r2 client-a refresh "$BOB"
wait_for 'with refresh the server first asks bob, who answers at once' "any(r.get('id') and r.get('id') != saved['r2'] for r in sent('client-b')[saved['b0']:]) and answered('client-a', saved['r2'])"

step '4. Filters and sharing'
request r3 client-a filter t4 in "$BOB"
hold_for 'a filter for users inside the zone yields nothing: bob is outside' "not answered('client-a', saved['r3'])"
request r4 client-a filter t4 out "$BOB"
wait_for 'a filter for users outside it yields bob' "answered('client-a', saved['r4'])"
request r5 client-a "$CLIENT_C"
hold_for 'client-c shares its location only with another user: nothing for alice, though the request is accepted' "not answered('client-a', saved['r5']) and last('client-a').get('status') == 200"

step '5. Refusals'
request r6 client-b "$ALICE"
wait_for 'bob may not request locations: 403 with warning 193' "last('client-b').get('status') == 403 and '193' in last('client-b').get('warning', '')"
request r7 client-a no-list
wait_for 'a request naming nobody: 403 with warning 192' "last('client-a').get('status') == 403 and '192' in last('client-a').get('warning', '')"
mcx client-c location configure "$ALICE" '{"triggers": [{"periodic": 5}]}'
wait_for 'client-c may not configure others: 403 with warning 194' "last('client-c').get('status') == 403 and '194' in last('client-c').get('warning', '')"

step '6. Alice adds a periodic trigger to bob'"'"'s configuration'
mcx client-a location configure "$BOB" '{"scope": "update", "triggers": [{"periodic": 2, "id": "every-2s"}]}'
wait_for 'accepted, and bob and the server hold the new trigger' "last('client-a').get('status') == 200 and 'every-2s' in loc('client-b').get('configuration', {}).get('triggers', []) and 'every-2s' in stored('client-b').get('configuration', {}).get('triggers', [])"
remember b1 "len(sent('client-b'))" >/dev/null
wait_for 'bob now reports every 2 s' "len(with_('client-b', 'every-2s', saved['b1'])) >= 2" 10

step '7. Areas: the group'"'"'s geographic area, and an emergency alert area'
wait_for 'client-c starts affiliated' "st('client-c').get('affiliated') is True"
mcx client-c location position 48.02 2.02
wait_for 'client-c enters the group area: told so, recorded by the server' "any(n.get('kind') == 'group_geographic_area' and n.get('entered') is True for n in loc('client-c').get('area_notices', [])) and stored('client-c').get('areas', {}).get('group:$GROUP') is True"
mcx client-c location position 48.0 2.02
wait_for 'leaving it: told so, and client-c leaves the group' "stored('client-c').get('areas', {}).get('group:$GROUP') is False and st('client-c').get('affiliated') is False"
mcx client-c location position 48.02 2.02
wait_for 'back in it: client-c joins the group again' "st('client-c').get('affiliated') is True"
mcx client-b location position 48.05 2.05
wait_for 'bob enters the emergency alert area: told so, and his client raises an emergency alert' "stored('client-b').get('areas', {}).get('alert:hazard') is True and '$BOB' in alerts()"
remember b2 "len(sent('client-b'))" >/dev/null
wait_for 'in the emergency state bob reports Emergency on the emergency trigger t7' "any(r.get('emergency') is True for r in with_('client-b', 't7', saved['b2']))" 10
mcx client-a alert off "$BOB"
mcx client-b location position 48.0 2.01
wait_for 'alice clears bob'"'"'s alert; bob leaves the area and the server records it' "stored('client-b').get('areas', {}).get('alert:hazard') is False and '$BOB' not in alerts()"

step "8. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(MESSAGE|PUBLISH|INVITE|SIP 200|SIP 403)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
