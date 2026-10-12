#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Unit Test Tutorial 17: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/17-mcvideo-calls-run.pcap.gz (captures/17-mcvideo-calls-full.pcap.gz is the reference run of
# README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=17-mcvideo-calls-full.pcap   # in the capture container
OUT=captures/17-mcvideo-calls-run.pcap.gz
ALICE=sip:alice.mcvideo@mcx.test
BOB=sip:bob.mcvideo@mcx.test
CLIENT_C=sip:client-c.mcvideo@mcx.test
CLIENT_D=sip:client-d.mcvideo@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of wait_for and hold_for: st('client-a') is a role's status.json, state(role) its MCVideo call
# state, others(role) the three other clients, same(sender, receiver) the receiver decoded at least 15 pictures of the
# sender's video and each equals the sender's own picture of the same RTP timestamp, idle() no client in an MCVideo
# call, refused(role, code, warning) the role's last MCVideo call ended with that SIP status (and Warning text).
HELPERS='
import json, sys, time
ROLES = ("client-a", "client-b", "client-c", "client-d")
def st(role):
    try:
        return json.load(open(f"/artifacts/{role}/status.json"))
    except (OSError, ValueError):
        return {}
def state(role):
    return st(role).get("mcvideo_call_state")
def others(role):
    return [r for r in ROLES if r != role]
def same(sender, receiver):
    sent = st(sender).get("mcvideo_sent_frames") or {}
    received = st(receiver).get("mcvideo_received_frames") or {}
    common = [key for key in received if key in sent]
    return len(common) >= 15 and all(sent[key] == received[key] for key in common)
def idle():
    return all(state(r) == "idle" for r in ROLES)
def refused(role, code, warning=""):
    last = st(role).get("mcvideo_last_call") or {}
    return state(role) == "idle" and last.get("status") == code and warning in last.get("warning", "")
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

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in to MCVideo and affiliated to the group'
wait_for 'client-a to client-d MCVideo authorised and affiliated' \
  "all(st(r).get('mcvideo_affiliated') for r in ROLES) and idle()" 90

step '2. client-a calls the group: every affiliated member joins, and each sees the four participants'
mcx client-a mcvideo-call
wait_for 'all four in the MCVideo group call' "all(state(r) == 'active' for r in ROLES)"
wait_for 'each member sees the four participants connected' \
  "all(len(st(r).get('mcvideo_participants') or {}) == 4 and set((st(r).get('mcvideo_participants') or {}).values()) == {'connected'} for r in ROLES)"

step '3. client-a asks to transmit and is granted; client-d accepts the video by hand; client-b pauses its reception'
mcx client-a mcvideo-transmit
wait_for 'client-a transmits' "st('client-a').get('mcvideo_transmitting') is True"
wait_for 'the others know client-a transmits, and were offered the video' \
  "all(st(r).get('mcvideo_transmitter') == '$ALICE' and st(r).get('mcvideo_reception_notifications', 0) >= 1 for r in others('client-a'))"
hold_for 'client-d receives nothing before it accepts' \
  "st('client-d').get('mcvideo_receiving') is False and st('client-d').get('mcvideo_frames_received', 0) == 0" 1.5
mcx client-d mcvideo-receive
wait_for 'client-b, client-c and client-d decode the pictures client-a sends' \
  "all(same('client-a', r) for r in others('client-a'))"
mcx client-b mcvideo-stop-receiving
wait_for 'client-b stopped receiving' "st('client-b').get('mcvideo_receiving') is False"
mcx client-b mcvideo-receive
wait_for 'client-b receives again' "st('client-b').get('mcvideo_receiving') is True"

step '4. client-a ends; client-b transmits; client-c is queued, client-d (no queueing) rejected; client-b ends, client-c goes on'
mcx client-a mcvideo-end
wait_for 'client-a no longer transmits' "st('client-a').get('mcvideo_transmitting') is False"
mcx client-b mcvideo-transmit
wait_for 'client-b transmits' "st('client-b').get('mcvideo_transmitting') is True"
mcx client-c mcvideo-transmit
wait_for 'client-c queued at position 1' "st('client-c').get('mcvideo_queue_position') == 1"
mcx client-d mcvideo-transmit
wait_for 'client-d rejected with cause 1 (transmission limit reached)' "st('client-d').get('mcvideo_reject_cause') == 1"
mcx client-b mcvideo-end
wait_for 'client-b no longer transmits' "st('client-b').get('mcvideo_transmitting') is False"
wait_for 'client-c granted from the queue, without asking again' "st('client-c').get('mcvideo_transmitting') is True"
wait_for 'the others know client-c transmits' \
  "all(st(r).get('mcvideo_transmitter') == '$CLIENT_C' for r in others('client-c'))"

step '5. client-c transmits for too long: the server revokes its transmission after 15 s'
wait_for 'client-c revoked with cause 2 (transmitted too long)' \
  "st('client-c').get('mcvideo_revocations', 0) >= 1 and st('client-c').get('mcvideo_reject_cause') == 2" 30
wait_for 'client-c stopped transmitting' "st('client-c').get('mcvideo_transmitting') is False"

step '6. client-a, which started the call, leaves: the server ends the call for everyone'
mcx client-a mcvideo-hangup
wait_for 'the call ended for all four' "idle()"

step '7. client-d calls the group asking to transmit in the same request (implicit request)'
mcx client-d mcvideo-call implicit
wait_for 'client-d transmits as the call starts' \
  "state('client-d') == 'active' and st('client-d').get('mcvideo_transmitting') is True"
wait_for 'client-a, client-b and client-c decode the pictures client-d sends' \
  "all(same('client-d', r) for r in others('client-d'))"
mcx client-a mcvideo-hangup
mcx client-b mcvideo-hangup
wait_for 'client-a and client-b left; client-c and client-d go on' \
  "state('client-a') == 'idle' and state('client-b') == 'idle' and state('client-c') == 'active' and state('client-d') == 'active'"
mcx client-c mcvideo-hangup
wait_for 'client-c leaves: with client-d alone, the server ends the call' "idle()"

step '8. A private call with transmission control: client-a calls client-b, which answers at once'
mcx client-a mcvideo-private "$BOB" auto
wait_for 'client-a and client-b in a private call, nobody else' \
  "state('client-a') == 'active' and state('client-b') == 'active' and state('client-c') == 'idle' and state('client-d') == 'idle'"
mcx client-a mcvideo-transmit
wait_for 'client-b decodes the pictures client-a sends' "same('client-a', 'client-b')"
mcx client-a mcvideo-end
wait_for 'client-a no longer transmits' "st('client-a').get('mcvideo_transmitting') is False"
mcx client-b mcvideo-transmit
wait_for 'client-a decodes the pictures client-b sends' "same('client-b', 'client-a')"
mcx client-b mcvideo-hangup
wait_for 'client-b hangs up: the call ends for both' "idle()"

step '9. Manual commencement: client-b rings and its user answers; then a call client-b declines'
mcx client-a mcvideo-private "$BOB" manual
wait_for 'client-b rings, client-a waits' "state('client-b') == 'ringing' and state('client-a') == 'calling'"
mcx client-b mcvideo-answer
wait_for 'client-a and client-b in a private call' "state('client-a') == 'active' and state('client-b') == 'active'"
mcx client-a mcvideo-hangup
wait_for 'the call ends for both' "idle()"
mcx client-a mcvideo-private "$BOB" manual
wait_for 'client-b rings' "state('client-b') == 'ringing'"
mcx client-b mcvideo-reject
wait_for 'client-a gets 480 (user declined)' "refused('client-a', 480)"

step '10. Private calls the server refuses, by the private call rulesets of the MCVideo user profiles'
mcx client-d mcvideo-private "$ALICE" auto
wait_for 'client-d gets 403, Warning 107 (may not make private calls)' "refused('client-d', 403, '107 ')"
mcx client-a mcvideo-private "$CLIENT_D" auto
wait_for 'client-a gets 403, Warning 144 (may not call this user)' "refused('client-a', 403, '144 ')"
mcx client-b mcvideo-private "$CLIENT_D" auto
wait_for 'client-b gets 403, Warning 127 (client-d may not be called)' "refused('client-b', 403, '127 ')"
mcx client-b mcvideo-private "$CLIENT_C" auto
wait_for 'client-b gets 403, Warning 159 (client-c may not be called by client-b)' "refused('client-b', 403, '159 ')"

step '11. A private call without transmission control: both send at once'
mcx client-a mcvideo-private "$BOB" auto no-control
wait_for 'client-a and client-b in a private call, neither with transmission control' \
  "all(state(r) == 'active' and st(r).get('mcvideo_transmission_control') is False for r in ('client-a', 'client-b'))"
wait_for 'both send, and each decodes the other' \
  "same('client-a', 'client-b') and same('client-b', 'client-a')"
mcx client-a mcvideo-hangup
wait_for 'the call ends for both' "idle()"

step "12. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|CANCEL|BYE|ACK|SUBSCRIBE|NOTIFY|SIP [0-9]{3})' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
