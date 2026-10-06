#!/usr/bin/env bash
# openMCX Unit Test Tutorial 4: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/04-private-call-services-run.pcap.gz (captures/04-private-call-services-full.pcap.gz is the
# reference run of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=04-private-call-services-full.pcap   # in the capture container
OUT=captures/04-private-call-services-run.pcap.gz
A=sip:alice.mcptt@mcx.test
B=sip:bob.mcptt@mcx.test
C=sip:client-c.mcptt@mcx.test
D=sip:client-d.mcptt@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# Wait until a Python condition on the clients' and the server's status holds; st('client-a') is a role's
# status.json, private() the server's private calls, call('a', 'b') a private call started by client-a with
# client-b, active at both, idle() every client idle and no call on the server, result(role) the answer to the
# role's last service request, outcome(role, kind) a service's result.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 - "$condition" "$timeout" <<'PY' || { echo "  FAILED: $label" >&2; exit 1; }
import json, sys, time
condition, deadline = ' '.join(sys.argv[1].split()), time.monotonic() + float(sys.argv[2])
IDS = {r: f'sip:{u}.mcptt@mcx.test' for r, u in
       (('a', 'alice'), ('b', 'bob'), ('c', 'client-c'), ('d', 'client-d'))}
ROLES = ('client-a', 'client-b', 'client-c', 'client-d')
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def sessions():
    value = st('mcptt-server').get('sessions') or []
    return list(value.values()) if isinstance(value, dict) else value
def private():
    return [s for s in sessions() if s.get('call_type') == 'private']
def call(caller, callee):
    calls = private()
    return (len(calls) == 1 and set(calls[0].get('participants', [])) == {IDS[caller], IDS[callee]}
            and calls[0].get('calling_user') == IDS[caller]
            and all(st('client-' + r).get('call_state') == 'active' for r in (caller, callee)))
def idle():
    return all(st(r).get('call_state') == 'idle' for r in ROLES) and not sessions()
def result(role):
    return st(role).get('last_service_result') or {}
def outcome(role, kind):
    return (st(role).get('service_outcomes') or {}).get(kind) == 'success'
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
  echo "  ok: $label"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in; every client answers private calls automatically unless asked otherwise'
wait_for 'client-a to client-d authorized and affiliated' \
  "all(st(r).get('authorized') and st(r).get('affiliated') for r in ROLES) and idle()" 90
for role in client-a client-b client-c client-d; do mcx "$role" answer-mode auto; done

step '2. Call-back: client-a asks client-b to call back; client-b does, and client-a answers'
mcx client-a callback "$B" high
wait_for 'client-b stores the request (urgency high), client-a sees it confirmed' \
  "(st('client-b').get('callback_requests_received') or {}).get(IDS['a'], {}).get('urgency') == 'high'
   and (st('client-a').get('callback_requests_sent') or {}).get(IDS['b']) == 'PCCB-I3: confirmed'"
mcx client-b callback-fulfil "$A"
wait_for 'client-a rings (a call-back is answered by hand)' "st('client-a').get('call_state') == 'ringing'"
mcx client-a answer
wait_for 'client-b and client-a in a private call; both call-back entries gone' \
  "call('b', 'a') and not st('client-a').get('callback_requests_sent') and not st('client-b').get('callback_requests_received')"
mcx client-b hangup
wait_for 'released' "idle()"
step '   client-c may not ask for a call-back'
mcx client-c callback "$A"
wait_for 'refused: 403 with warning 151' "result('client-c').get('status') == 403 and '151' in result('client-c').get('warning', '')"

step '3. Remotely initiated call: client-a asks client-b'\''s device to call client-d'
mcx client-a remote-call "$B" "$D" auto
wait_for 'client-b calls client-d' "call('b', 'd')"
wait_for 'client-a told it worked' "outcome('client-a', 'remotely-initiated-private-call-response')"
mcx client-b hangup
wait_for 'released' "idle()"

step '4. Transfer: client-a calls client-b, then hands client-b over to client-d'
mcx client-a private "$B" auto
wait_for 'client-a and client-b in a private call' "call('a', 'b')"
mcx client-a transfer "$D"
wait_for 'client-b now with client-d; client-a told it worked and out of the call' \
  "call('b', 'd') and outcome('client-a', 'transfer-private-call-response') and st('client-a').get('call_state') == 'idle'"
mcx client-b hangup
wait_for 'released' "idle()"

step '5. Announced transfer: client-a holds client-b, talks to client-d first, then completes the transfer'
mcx client-a private "$B" auto
wait_for 'client-a and client-b in a private call' "call('a', 'b')"
mcx client-a transfer "$D" announced
wait_for 'client-b on hold, client-a talks to client-d: two private calls' \
  "(st('client-a').get('announced_transfer') or {}).get('state') == 'announcing'
   and st('client-d').get('call_state') == 'active' and len(private()) == 2"
mcx client-a transfer "$D" complete
wait_for 'client-b calls client-d and replaces client-a'\''s call; client-a out of both' \
  "call('b', 'd') and st('client-a').get('call_state') == 'idle'
   and (st('client-a').get('announced_transfer') or {}).get('state') == 'completed'"
mcx client-b hangup
wait_for 'released' "idle()"

step '6. Forwarding by hand: client-a calls client-b, who is asked to answer, and client-b forwards to client-d'
mcx client-a private "$B" manual
wait_for 'client-b rings' "st('client-b').get('call_state') == 'ringing'"
mcx client-b forward "$D"
wait_for 'client-a gets 480 (the call is forwarded), calls again and reaches client-d' \
  "call('a', 'd') and '480' in st('client-a').get('last_error', '')"
mcx client-a hangup
wait_for 'released' "idle()"

step '7. Immediate forwarding: client-c forwards every call to client-b'
mcx client-a private "$C" auto
wait_for 'client-a reaches client-b; client-c never rang' "call('a', 'b') and st('client-c').get('call_state') == 'idle'"
mcx client-a hangup
wait_for 'released' "idle()"

step '8. Forwarding on no answer: client-d forwards to client-a when it does not answer within 3 s'
mcx client-b private "$D" manual
wait_for 'client-d rings' "st('client-d').get('call_state') == 'ringing'"
wait_for 'after 3 s: client-d stops ringing and client-b reaches client-a' \
  "st('client-d').get('call_state') == 'idle' and call('b', 'a')" 20
mcx client-b hangup
wait_for 'released' "idle()"

step '9. First-to-answer: client-a calls client-b and client-d at once; the first to answer gets the call'
mcx client-a first-to-answer "$B" "$D"
wait_for 'client-b and client-d both ring' \
  "all(st(r).get('call_state') == 'ringing' and st(r).get('first_to_answer') for r in ('client-b', 'client-d'))"
mcx client-b answer
wait_for 'client-b gets the call, client-d stops ringing' "call('a', 'b') and st('client-d').get('call_state') == 'idle'"
mcx client-a ptt /speech/alpha.wav
wait_for 'client-b hears client-a' "st('client-b').get('received_packets', 0) >= 50" 20
mcx client-a hangup
wait_for 'released' "idle()"

step "10. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|BYE|CANCEL|MESSAGE|REFER|SIP [0-9])' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
