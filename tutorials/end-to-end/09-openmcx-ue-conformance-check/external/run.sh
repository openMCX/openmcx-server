#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Tutorial 9, part B: follows the MC client through TS 37.579-2 test 5.1 against a conformance test system
# (README.md, part B), from its status file, each check before the next; the test system drives the test and gives the
# verdict. Usage: ./run.sh (the client must be up: docker compose up -d). Writes status-before-log-off.json.
# Set COMPOSE to another command than "docker compose" if needed, and OVERRIDE to a second compose file.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
if [ -n "${OVERRIDE:-}" ]; then DC+=(-f "$OVERRIDE"); fi
UE=client-d
STATUS=status-before-log-off.json

# Wait until a Python condition on the client's status holds; st() is its status.json.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-120}
  "${DC[@]}" exec -T "$UE" python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
def st():
    try:
        return json.load(open('/artifacts/client-d/status.json'))
    except (OSError, ValueError):
        return {}
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.2)
sys.exit(1)
PY
  echo "  ok: $label"
}

# Print part of the client's status (a Python expression on st()), as JSON.
show() {
  "${DC[@]}" exec -T "$UE" python3 - "$1" <<'PY'
import json, sys
st = lambda: json.load(open('/artifacts/client-d/status.json'))
print('   ', json.dumps(eval(sys.argv[1])))
PY
}

step() { printf '\n%s\n' "$*"; }

step '1. SIP registration with IMS AKA through the P-CSCF; the SIP signalling inside IPsec ESP (TS 33.203 clause 7)'
wait_for 'registered with ims-aka, ipsec-3gpp, security associations set up' "st().get('registered') and (st().get('sip_security') or {}).get('mechanism') == 'ims-aka' and (st().get('sip_security') or {}).get('sec_mechanism') == 'ipsec-3gpp' and (st().get('sip_security') or {}).get('security_associations')" 300
show "{k: st()['sip_security'].get(k) for k in ('algorithm', 'alg', 'ealg', 'port_us', 'port_ps', 'associated_uris')}"
show "st().get('reg_event')"

step '2. Sign-in at the IdMS, then the KMS: Initialize and KeyProvision, signed, key sets wrapped under the TrK'
wait_for 'signed in' "st().get('signed_in') and not st().get('sign_in_failures')" 300
wait_for 'key management done with the KMS' "(st().get('key_management') or {}).get('kms_uri')" 300
show "{'transport_keys': st().get('transport_keys'), 'uid_form': (st().get('key_management') or {}).get('uid_form')}"

step '3. Service authorisation: the PUBLISH with the access token'
wait_for 'MCPTT authorised' "st().get('authorized')" 300

step '4. Configuration: one SUBSCRIBE for the UE configuration, user profile and service configuration; NOTIFY; GETs'
wait_for 'configuration documents subscribed and notified' "len((st().get('configuration') or {}).get('subscribed_documents', [])) == 3 and (st().get('configuration') or {}).get('notifies', 0) >= 1" 300
show "{'subscribed': st()['configuration']['subscribed_documents'], 'ue_configuration': (st().get('ue_configuration') or {}).get('status')}"

step '5. Group management: SUBSCRIBE to the group document; NOTIFY; GET; the group key (GMK)'
wait_for 'group document subscribed, notified and fetched' "(st().get('group_subscription_result') or {}).get('status') == 200 and st().get('group_documents') and all(d.get('fetch_status') == 200 and d.get('notifications', 0) >= 1 for d in st()['group_documents'].values())" 300
wait_for 'client signature key (CSK) and group key (GMK) held' "st().get('csk_id') and st().get('group_key_id') and st().get('protected_ready')" 300

step '6. MC log-off (PUBLISH with Expires 0 per service), then SIP de-REGISTER, when the test system asks for them'

"${DC[@]}" exec -T "$UE" cat /artifacts/client-d/status.json >"$STATUS" </dev/null
echo "  the client's status before the log-off: $STATUS"
read -r -p "  Press Enter to log off (or Ctrl-C to leave the client registered) " _
"${DC[@]}" exec -T "$UE" mcx-client --config /config/client.json --command log-off >/dev/null </dev/null
wait_for 'every service answered 200, then the de-REGISTER 200' "st().get('logged_off') and st().get('log_off') and all(code == 200 for code in st()['log_off'].values()) and st().get('deregistered') == 200" 120
show "{'log_off': st()['log_off'], 'deregistered': st()['deregistered']}"
echo
echo "Done. Stop the client with: docker compose down -v"
