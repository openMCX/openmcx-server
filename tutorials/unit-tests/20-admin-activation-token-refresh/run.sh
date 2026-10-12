#!/usr/bin/env bash
# OpenMCX Unit Test Tutorial 20: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/20-admin-activation-token-refresh-run.pcap.gz (captures/20-admin-activation-token-refresh-full.pcap.gz
# is the reference run of README.md). Set COMPOSE to another command than "docker compose" if needed. It runs once per
# system: erin's activation URL works only once (README.md, step 5, to start over).
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=20-admin-activation-token-refresh-full.pcap   # in the capture container
OUT=captures/20-admin-activation-token-refresh-run.pcap.gz
ALICE=sip:alice.mcptt@mcx.test
ERIN_PASSWORD=Erin-Tutorial-20

# Send a command to a client's running mcx-client (it is the same program with --command). client-e is erin's
# activated device: it runs in the compose profile "activation", with its configuration in config/activate-e.
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  if [ "$role" = client-e ]; then
    "${DC[@]}" --profile activation exec -T client-e mcx-client --config /config/activate/client-e.json --command "$*" >/dev/null
  else
    "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
  fi
}

# What alice does in MCX Admin, and what erin does with her links (admin.py), from alice's computer (client-a).
admin() {
  "${DC[@]}" exec -T client-a python3 - "$@" <admin.py
}

# The Python helpers of wait_for and hold_for: st('client-a') is a role's status.json, signed_in(role) the role is
# registered and authorised for MCPTT (and for MCData, if it has MCData), expiry(role) the expiry of its access token.
HELPERS='
import json, sys, time
def st(role):
    try:
        return json.load(open(f"/artifacts/{role}/status.json"))
    except (OSError, ValueError):
        return {}
def signed_in(role):
    s = st(role)
    return bool(s.get("registered") and s.get("authorized") and (role == "client-e" or s.get("mcdata_authorized")))
def expiry(role):
    return st(role).get("token_expires_at") or 0
def state(role):
    return st(role).get("call_state")
'

# Wait until a Python condition on the clients' status holds.
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

# Check that a Python condition holds for the whole of a time (here: no client ever loses its authorisation).
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

# Print the value of a Python expression on the clients' status.
value() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
print($1)"
}

step() { printf '\n%s\n' "$*"; }

if [ -s config/activate-e/url ]; then
  echo "erin was activated already on this system: start over (README.md, step 5)" >&2
  exit 1
fi

step '1. Four clients signed in with their passwords; each holds a short-lived access token'
wait_for 'client-a to client-d registered, authorised for MCPTT and MCData' \
  "all(signed_in(r) for r in ('client-a', 'client-b', 'client-c', 'client-d'))" 90
wait_for 'alice and bob signed in at IdMS with the password once, and their tokens last at most 120 s' \
  "all(st(r).get('password_logins') == 1 and 0 < expiry(r) - time.time() <= 125 for r in ('client-a', 'client-b'))"

step '2. alice, the administrator, creates the user erin in MCX Admin; erin sets her password'
echo "  \$ alice: create erin (MCX Admin REST API)"
echo "  $(admin create-erin)"
echo "  \$ alice: a one-time set-password link for erin"
LINK=$(admin password-link)
echo "  $LINK"
echo "  \$ erin: open the link, set the password"
[ "$(admin set-password "$LINK" "$ERIN_PASSWORD")" = 200 ] || { echo "  FAILED: erin sets her password" >&2; exit 1; }
echo "  ok: IdMS took erin's password"

step "3. alice issues erin's activation URL; erin's device (client-e) activates with it and signs in"
echo "  \$ alice: an activation URL (and its QR code) for erin"
URL=$(admin activation)
echo "  $URL"
printf '%s\n' "$URL" >config/activate-e/url
printf '%s\n' "$ERIN_PASSWORD" >config/activate-e/password
echo "  \$ docker compose --profile activation up -d client-e"
"${DC[@]}" --profile activation up -d client-e >/dev/null 2>&1
wait_for 'client-e activated: registered and authorised as erin' \
  "signed_in('client-e') and st('client-e').get('user_id') == 'sip:erin.mcptt@mcx.test'" 90
wait_for "client-e never used erin's password for the access token: it signed in with the refresh token" \
  "st('client-e').get('password_logins') == 0 and st('client-e').get('token_refreshes') == 1"
[ "$(admin fetch "$URL")" = 404 ] || { echo "  FAILED: the activation URL works only once" >&2; exit 1; }
echo "  ok: the activation URL works only once (404 the second time)"

step '4. The tokens expire: each client renews its own with the refresh token and publishes the new one'
RENEWALS=$(value "[st(r).get('token_renewals', 0) for r in ('client-a', 'client-b', 'client-e')]")
UNTIL=$(value "int(max(expiry(r) for r in ('client-a', 'client-b', 'client-e')) + 15 - time.time())")
echo "  (watching the three clients for ${UNTIL} s, until 15 s after the last of their current tokens expires)"
hold_for 'alice, bob and erin stay registered and authorised all along' \
  "all(signed_in(r) for r in ('client-a', 'client-b', 'client-e'))" "$UNTIL"
wait_for 'each renewed its token at least once, by the refresh token, never with the password again' \
  "all(st(r).get('token_renewals', 0) > n for r, n in zip(('client-a', 'client-b', 'client-e'), $RENEWALS)) and all(st(r).get('password_logins') == 1 for r in ('client-a', 'client-b')) and st('client-e').get('password_logins') == 0 and not any(st(r).get('token_refresh_refusals') for r in ('client-a', 'client-b', 'client-e'))"

step '5. With renewed tokens, erin calls alice and talks'
mcx client-e "private $ALICE auto"
wait_for 'client-e and client-a in a private call' \
  "state('client-e') == 'active' and state('client-a') == 'active'"
BEFORE=$(value "st('client-a').get('received_packets', 0)")
mcx client-e ptt /speech/alpha.wav
wait_for "alice hears erin's speech" "st('client-a').get('received_packets', 0) >= $BEFORE + 50"
wait_for 'erin released the floor' "not st('client-e').get('talking')"
mcx client-e hangup
wait_for 'the call ended for both' "state('client-e') == 'idle' and state('client-a') == 'idle'"

step '6. erin restarts her device: it signs in from its saved configuration with the refresh token alone'
echo "  \$ docker compose --profile activation restart client-e"
"${DC[@]}" --profile activation restart client-e >/dev/null 2>&1
wait_for 'client-e registered and authorised again, no password, no activation URL' \
  "signed_in('client-e') and st('client-e').get('password_logins') == 0 and st('client-e').get('token_refreshes') == 1" 60

step "7. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(REGISTER|PUBLISH|INVITE|BYE|ACK|SUBSCRIBE|NOTIFY|SIP [0-9]{3})' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
