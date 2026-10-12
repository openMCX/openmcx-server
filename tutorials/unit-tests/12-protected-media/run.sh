#!/usr/bin/env bash
# OpenMCX Unit Test Tutorial 12: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/12-protected-media-run.pcap.gz (captures/12-protected-media-full.pcap.gz is the reference run of
# README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=12-protected-media-full.pcap   # in the capture container
OUT=captures/12-protected-media-run.pcap.gz

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# Wait until a Python condition on the clients' and the server's status holds; st('client-a') is a role's
# status.json, xml('client-a') its XML protection counters, sessions() the MCPTT server's sessions, key('client-a')
# the PCK-ID of its private call, rx('client-b') the speech packets it decrypted and decoded, saved[...] values
# remembered by remember().
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
CLIENTS = ('client-a', 'client-b', 'client-c', 'client-d')
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def xml(role):
    return st(role).get('xml_protection') or {}
def sessions():
    value = st('mcptt-server').get('sessions') or []
    return list(value.values()) if isinstance(value, dict) else value
def key(role):
    return st(role).get('private_key_id')
def rx(role):
    return st(role).get('received_packets', 0)
try:
    saved = json.load(open('/tmp/saved.json'))
except (OSError, ValueError):
    saved = {}
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
  echo "  ok: $label"
}

# Remember the value of a Python expression (same helpers as wait_for) as saved[name].
remember() {
  "${DC[@]}" exec -T client-a python3 - "$1" "$2" <<'PY'
import json, sys
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def key(role):
    return st(role).get('private_key_id')
def rx(role):
    return st(role).get('received_packets', 0)
try:
    saved = json.load(open('/tmp/saved.json'))
except (OSError, ValueError):
    saved = {}
saved[sys.argv[1]] = eval(sys.argv[2])
json.dump(saved, open('/tmp/saved.json', 'w'))
PY
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in with keys: a CSK each (uploaded to the server), the group key (GMK), XML protection on'
wait_for 'client-a to client-d authorized and affiliated, each with a CSK and XML protection' "all(st(r).get('authorized') and st(r).get('affiliated') and st(r).get('csk_id') and xml(r).get('enabled') for r in CLIENTS)" 120
wait_for 'every client holds the group key and is ready for protected calls' "all(st(r).get('protected_ready') for r in CLIENTS)" 60
wait_for 'all four hold the same GMK-ID, whose four first bits are 0000 (the purpose tag of a GMK)' "len({st(r).get('group_key_id') for r in CLIENTS}) == 1 and st('client-a').get('group_key_id') and st('client-a').get('group_key_id') >> 28 == 0"
wait_for 'each CSK-ID has the purpose tag 2 (TS 33.180 annex G)' "all(st(r).get('csk_id') >> 28 == 2 for r in CLIENTS)"
wait_for 'the server decrypted the access tokens of the service authorisation' "xml('mcptt-server').get('decrypted', 0) >= 4"
for role in client-a client-b client-c client-d; do mcx "$role" answer-mode auto; done

step '2. A protected group call: SRTP speech under the GMK, floor control in SRTCP under each CSK'
remember rx_b "rx('client-b')"
mcx client-a call
wait_for 'the group call is up, with protected media and floor control at every client' "len(sessions()) == 1 and all(st(r).get('call_state') == 'active' and st(r).get('protected_media') and st(r).get('protected_floor') for r in CLIENTS)"
mcx client-a ptt /speech/alpha.wav
wait_for 'client-a has the floor (protected floor control)' "st('client-a').get('talking')"
wait_for 'client-b decrypted and decoded client-a speech' "rx('client-b') >= saved['rx_b'] + 100"
wait_for 'floor released' "not st('client-a').get('talking')" 20
mcx client-a hangup
wait_for 'every client idle' "all(st(r).get('call_state') == 'idle' for r in CLIENTS) and not sessions()"

step '3. A protected private call: client-a sends a new PCK to client-b in the SDP offer (MIKEY-SAKKE)'
remember rx_c "rx('client-c')"
remember rx_d "rx('client-d')"
mcx client-a private sip:bob.mcptt@mcx.test auto
wait_for 'one PCK-ID at both parties, starting with the bits 0001' "key('client-a') is not None and key('client-a') == key('client-b') and key('client-a') >> 28 == 1 and st('client-a').get('call_state') == 'active'"
remember pck "key('client-a')"
remember rx_b "rx('client-b')"
mcx client-a ptt /speech/alpha.wav
wait_for 'client-b decrypted client-a speech with the PCK' "rx('client-b') >= saved['rx_b'] + 100" 20
wait_for 'floor released' "not st('client-a').get('talking')" 20
remember rx_a "rx('client-a')"
mcx client-b ptt /speech/bravo.wav
wait_for 'client-a decrypted client-b speech with the PCK' "rx('client-a') >= saved['rx_a'] + 100" 20
wait_for 'floor released' "not st('client-b').get('talking')" 20
wait_for 'client-c and client-d received none of it' "rx('client-c') == saved['rx_c'] and rx('client-d') == saved['rx_d']"
mcx client-b hangup
wait_for 'released, and the PCK is gone at both parties' "all(st(r).get('call_state') == 'idle' for r in CLIENTS) and not sessions() and key('client-a') is None and key('client-b') is None"

step '4. A second private call gets a new PCK'
mcx client-a private sip:bob.mcptt@mcx.test auto
wait_for 'a new PCK-ID, shared by both parties' "key('client-a') is not None and key('client-a') == key('client-b') and key('client-a') != saved['pck']"
mcx client-a hangup
wait_for 'released' "all(st(r).get('call_state') == 'idle' for r in CLIENTS) and not sessions()"

step '5. A tampered key: client-a alters its I_MESSAGE; client-b refuses it'
mcx client-a private sip:bob.mcptt@mcx.test auto tamper-key
wait_for 'refused with 488 and warning 136, and client-b never joined' "(st('client-a').get('last_call_failure') or {}).get('status') == 488 and '136 authentication of the MIKEY-SAKKE I_MESSAGE failed' in (st('client-a').get('last_call_failure') or {}).get('warning', '') and st('client-b').get('call_state') == 'idle' and key('client-b') is None"
wait_for 'nothing left over' "all(st(r).get('call_state') == 'idle' for r in CLIENTS) and not sessions()"

step '6. XML protection: every client and the server encrypted, decrypted, signed and verified, and refused nothing'
wait_for 'counters' "all(xml(r).get('encrypted', 0) > 0 and xml(r).get('decrypted', 0) > 0 and xml(r).get('signed', 0) > 0 and xml(r).get('verified', 0) > 0 and xml(r).get('refused', 0) == 0 for r in CLIENTS + ('mcptt-server',))"

step "7. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z io,phs \
  2>/dev/null | grep -E 'sip|srtp|srtcp|rtp|rtcp|udp' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
