#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Tutorial 9: the walk-through of TS 37.579-2 test 5.1 (README.md, step 3), each check before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/09-openmcx-ue-conformance-check-run.pcap.gz and, when the system runs with MCX_LOG=debug, the keys of the MC
# client's IPsec security associations as captures/09-openmcx-ue-conformance-check-run.esp_sa (README.md, step 4), and client-d's
# status before the log-off as captures/09-openmcx-ue-conformance-check-run.status.json.
# captures/09-openmcx-ue-conformance-check-full.pcap.gz is the reference run of README.md. Set COMPOSE to another command than
# "docker compose" if needed, and OVERRIDE to a second compose file (other images).
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
if [ -n "${OVERRIDE:-}" ]; then DC+=(-f "$OVERRIDE"); fi
CAPTURE=09-openmcx-ue-conformance-check-full.pcap   # in the capture container
OUT=captures/09-openmcx-ue-conformance-check-run.pcap.gz
ESP_SA=captures/09-openmcx-ue-conformance-check-run.esp_sa
STATUS=captures/09-openmcx-ue-conformance-check-run.status.json
UE=client-d

# Wait until a Python condition on client-d's status holds; st() is its status.json.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-60}
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

# Print part of client-d's status (a Python expression on st()), as JSON.
show() {
  "${DC[@]}" exec -T "$UE" python3 - "$1" <<'PY'
import json, sys
st = lambda: json.load(open('/artifacts/client-d/status.json'))
print('   ', json.dumps(eval(sys.argv[1])))
PY
}

step() { printf '\n%s\n' "$*"; }

step '1. SIP registration with IMS AKA through the P-CSCF; the SIP signalling inside IPsec ESP (TS 33.203 clause 7)'
wait_for 'registered with ims-aka, ipsec-3gpp, security associations set up' "st().get('registered') and (st().get('sip_security') or {}).get('mechanism') == 'ims-aka' and (st().get('sip_security') or {}).get('sec_mechanism') == 'ipsec-3gpp' and (st().get('sip_security') or {}).get('security_associations')" 120
show "{k: st()['sip_security'].get(k) for k in ('algorithm', 'alg', 'ealg', 'port_us', 'port_ps', 'associated_uris')}"
wait_for 'subscribed to its reg event (TS 24.229 clause 5.1.1.3)' "(st().get('reg_event') or {}).get('subscription_status') == 200"

step '2. Sign-in at the IdMS, then the KMS: Initialize and KeyProvision, signed, key sets wrapped under the TrK'
wait_for 'signed in' "st().get('signed_in') and not st().get('sign_in_failures')" 120
wait_for 'key management done with the KMS' "(st().get('key_management') or {}).get('kms_uri')"
wait_for 'signed KMS exchange with TrK-wrapped keys' "(st().get('transport_keys') or {}).get('protected_kms_exchange') == 'signed, TrK-wrapped keys'"
show "st()['transport_keys']"

step '3. Service authorisation: the PUBLISH with the access token, MCPTT and MCData'
wait_for 'MCPTT and MCData authorised' "st().get('authorized') and st().get('mcdata_authorized')" 120

step '4. Configuration: one SUBSCRIBE for the UE configuration, user profile and service configuration; NOTIFY; GETs'
wait_for 'three documents subscribed, notified and fetched' "len((st().get('configuration') or {}).get('subscribed_documents', [])) == 3 and (st().get('configuration') or {}).get('notifies', 0) >= 1 and (st().get('ue_configuration') or {}).get('status') == 200"
show "st()['configuration']['subscribed_documents']"

step '5. Group management: SUBSCRIBE to the group document of operations; NOTIFY; GET; the group key (GMK)'
wait_for 'group document subscribed, notified and fetched' "(st().get('group_subscription_result') or {}).get('status') == 200 and all(d.get('fetch_status') == 200 and d.get('notifications', 0) >= 1 for d in (st().get('group_documents') or {}).values()) and st().get('group_documents')"
wait_for 'client signature key (CSK) and group key held' "st().get('csk_id') and st().get('group_key_id') and st().get('protected_ready')"

step '6. Location reporting: the MCPTT and MCData servers configure it in a MESSAGE (TS 24.379 clause 13.2.2)'
wait_for 'location reporting configured for MCPTT and MCData' "(st().get('location') or {}).get('configured') and (st().get('mcdata_location') or {}).get('configured')" 60

step '7. The home HTTP proxy (forward mode): requests in absolute-form only (with MCX_LOG=debug)'
lines=$("${DC[@]}" logs --no-color http-proxy 2>/dev/null | grep -E 'DEBUG \[http-proxy\] HTTP [A-Z]+ ' | grep -v ' /readyz ' || true)
if [ -z "$lines" ]; then
  echo "  not checked: no request lines (start the system with MCX_LOG=debug, README.md step 2)"
else
  absolute=$(grep -cE 'HTTP [A-Z]+ https://' <<<"$lines" || true)
  origin=$(grep -cE 'HTTP [A-Z]+ /' <<<"$lines" || true)
  echo "    absolute-form $absolute, origin-form $origin, by authority:"
  grep -oE 'HTTP [A-Z]+ https://[^/ ]+' <<<"$lines" | sort | uniq -c | sed 's/^/     /'
  [ "$origin" = 0 ] && [ "$absolute" -gt 0 ] || { echo "  FAILED: a request in origin-form" >&2; exit 1; }
  echo "  ok: every request through the proxy in absolute-form"
fi

step '8. MC log-off (PUBLISH with Expires 0 per service), then SIP de-REGISTER'
# client-d's status as the test left it, before the log-off ends the registration and the services.
mkdir -p captures
"${DC[@]}" exec -T "$UE" cat /artifacts/client-d/status.json >"$STATUS"
echo "  client-d's status before the log-off: $STATUS"
echo "  \$ $UE: log-off"
"${DC[@]}" exec -T "$UE" mcx-client --config "/config/$UE.json" --command log-off >/dev/null
wait_for 'every service answered 200, then the de-REGISTER 200' "st().get('logged_off') and st().get('log_off') and all(code == 200 for code in st()['log_off'].values()) and st().get('deregistered') == 200" 60
show "{'log_off': st()['log_off'], 'deregistered': st()['deregistered']}"

step "9. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
# The client's IPsec security associations in Wireshark's ESP SA table (README.md, step 4); only in a debug log.
"${DC[@]}" logs --no-color "$UE" 2>/dev/null | grep -oE 'ESP SA .*' | awk '
  {
    split($3, s, ":"); split($5, d, ":"); spi = $7; alg = $9; akey = $11; ealg = $13; ekey = $15; salt = ($16 == "salt") ? $17 : ""
    if (ealg == "aes-gcm" || ealg == "aes-gcm-us") { enc = "AES-GCM with 16 octet ICV [RFC4106]"; ek = "0x" ekey salt }
    else if (ealg == "aes-cbc") { enc = "AES-CBC [RFC3602]"; ek = "0x" ekey }
    else { enc = "NULL"; ek = "" }
    if (alg == "hmac-sha-1-96") { auth = "HMAC-SHA-1-96 [RFC2404]"; ak = "0x" akey }
    else if (alg == "hmac-sha2-256-128") { auth = "HMAC-SHA-256-128 [RFC4868]"; ak = "0x" akey }
    else { auth = "NULL"; ak = "" }
    printf "\"IPv4\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", s[1], d[1], spi, enc, ek, auth, ak
  }' > "$ESP_SA"
if [ -s "$ESP_SA" ]; then
  echo "  $(wc -l <"$ESP_SA") ESP security associations in $ESP_SA (secret: the keys of this run)"
else
  rm -f "$ESP_SA"
  echo "  no ESP keys (the system runs without MCX_LOG=debug): the SIP inside ESP stays encrypted"
fi
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z io,phs \
  2>/dev/null | grep -E 'esp|sip|tls|tcp|udp' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, step 4)."
