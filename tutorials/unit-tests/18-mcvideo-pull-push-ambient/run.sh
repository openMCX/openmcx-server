#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Unit Test Tutorial 18: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/18-mcvideo-pull-push-ambient-run.pcap.gz (captures/18-mcvideo-pull-push-ambient-full.pcap.gz is the
# reference run of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=18-mcvideo-pull-push-ambient-full.pcap   # in the capture container
OUT=captures/18-mcvideo-pull-push-ambient-run.pcap.gz
ALICE=sip:alice.mcvideo@mcx.test
BOB=sip:bob.mcvideo@mcx.test
CLIENT_D=sip:client-d.mcvideo@mcx.test

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# The Python helpers of wait_for and remember: st(role) is a role's status.json, video() the MCVideo server's,
# active(role, mode) a client in an MCVideo call of that video mode, idle(*roles) clients without an MCVideo call,
# same(sender, receiver) the pictures the receiver decoded compared with those the sender encoded (by RTP timestamp),
# last(role) the outcome of its last call, replayed() bob's pictures equal to those alice pushed to the server,
# remote(role) the answer to its last Remote Transmission request,
# ambient(viewing, viewed, kind) an ambient viewing call between the two, saved[...] values remembered by remember().
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
def active(role, mode=None):
    s = st(role)
    return s.get("mcvideo_call_state") == "active" and (mode is None or s.get("mcvideo_video_mode") == mode)
def idle(*roles):
    return all(st(r).get("mcvideo_call_state") == "idle" for r in roles or ROLES)
def tx(role):
    return st(role).get("mcvideo_transmitting") is True
def frames(role):
    return st(role).get("mcvideo_frames_received", 0)
def compare(sent, received):
    common = [k for k in received if k in sent]
    return len(common), sum(1 for k in common if sent[k] == received[k])
def same(sender, receiver, least=15):
    compared, equal = compare(st(sender).get("mcvideo_sent_frames") or {}, st(receiver).get("mcvideo_received_frames") or {})
    return compared >= least and equal == compared
def last(role):
    return st(role).get("mcvideo_last_call") or {}
def replayed(least=20):
    compared, equal = compare(last("client-a").get("sent_frames") or {}, st("client-b").get("mcvideo_received_frames") or {})
    return compared >= least and equal == compared
def remote(role):
    return st(role).get("mcvideo_remote_result") or {}
def answered(role, kind, target):
    r = remote(role)
    return r.get("answered") == kind and r.get("target") == IDS[target]
def ambient(viewing, viewed, kind):
    return (active(viewing) and active(viewed) and st(viewing).get("mcvideo_ambient_role") == "viewing"
            and st(viewed).get("mcvideo_ambient_role") == "viewed-to" and st(viewing).get("mcvideo_ambient_type") == kind
            and st(viewed).get("mcvideo_ambient_type") == kind)
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

# A call the server (or the called client) refuses: wait for a new outcome of the role's last call, with this status
# code and, when given, this warning code.
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

step '2. Video push: alice pushes her video to bob'
mcx client-a mcvideo-push "$BOB" auto
wait_for 'alice and bob in a one-to-one video push call' "active('client-a', 'one-to-one video push') and active('client-b', 'one-to-one video push')"
wait_for 'alice transmits without asking; bob does not transmit' "tx('client-a') and not tx('client-b')"
wait_for 'bob decodes alice'"'"'s pictures, each equal to the one she encoded' "frames('client-b') >= 20 and same('client-a', 'client-b')"
mcx client-a mcvideo-hangup
wait_for 'call released' "idle('client-a', 'client-b')"

step '3. Video pull: alice pulls bob'"'"'s video'
mcx client-a mcvideo-pull "$BOB" auto
wait_for 'alice and bob in a one-to-one video pull call' "active('client-a', 'one-to-one video pull') and active('client-b', 'one-to-one video pull')"
wait_for 'bob, the called user, transmits without asking; alice does not' "tx('client-b') and not tx('client-a')"
wait_for 'alice decodes bob'"'"'s pictures' "frames('client-a') >= 20 and same('client-b', 'client-a')"
mcx client-a mcvideo-hangup
wait_for 'call released' "idle('client-a', 'client-b')"

step '4. Video push to the server: alice'"'"'s video is recorded; the server sends her its URL in a SIP INFO'
remember recorded "video().get('video_recorded', 0)"
mcx client-a mcvideo-push-server
wait_for 'alice in a one-to-server video push call, transmitting' "active('client-a', 'one-to-server video push') and tx('client-a')"
wait_for 'alice has the recording'"'"'s URL (<video-push-url>)' "(st('client-a').get('mcvideo_push_url') or '').startswith('https://')"
wait_for 'the server records alice'"'"'s video' "video().get('video_recorded', 0) - saved['recorded'] >= 60"
mcx client-a mcvideo-hangup
wait_for 'call released; nobody else was in it' "idle()"
URL=$("${DC[@]}" exec -T client-a python3 -c "import json; print(json.load(open('/artifacts/client-a/status.json'))['mcvideo_push_url'])")
echo "  the recording: $URL"

step '5. Video pull from the server: bob pulls alice'"'"'s recording and sees the very pictures she pushed'
remember streamed "video().get('video_streamed', 0)"
mcx client-b mcvideo-pull-server "$URL"
wait_for 'bob in a one-from-server video pull call, not transmitting' "active('client-b', 'one-from-server video pull') and not tx('client-b')"
wait_for 'the server streams the whole recording' "video().get('video_streamed', 0) - saved['streamed'] >= 60"
wait_for 'bob decodes the pictures alice pushed' "replayed()"
mcx client-b mcvideo-hangup
wait_for 'call released' "idle()"

step '6. Refused: client-c may not pull from or push to the server (403, warning 100); an unknown recording (404); client-d may not push to alice (403)'
refused 'client-c pulling from the server: 403 with warning 100' client-c 403 100 mcvideo-pull-server "$URL"
refused 'client-c pushing to the server: 403 with warning 100' client-c 403 100 mcvideo-push-server
refused 'bob pulling an unknown recording: 404' client-b 404 '' mcvideo-pull-server "${URL%/*}/ffffffffffffffffffffffffffffffff"
refused 'client-d pushing to alice: 403' client-d 403 '' mcvideo-push "$ALICE" auto

step '7. Remote transmission in a group call: alice has bob transmit, then stops him; client-c may do neither'
mcx client-a mcvideo-call
wait_for 'all four in the MCVideo group call, nobody transmits' "all(active(r) for r in ROLES) and not any(tx(r) for r in ROLES)"
mcx client-a "mcvideo-remote-transmit $BOB"
wait_for 'alice'"'"'s Remote Transmission request is granted (Result 1)' "answered('client-a', 'transmit', 'client-b') and remote('client-a').get('result') is True"
wait_for 'bob transmits; client-c decodes his pictures' "tx('client-b') and frames('client-c') >= 15 and same('client-b', 'client-c', 10)"
mcx client-c "mcvideo-remote-cancel $BOB"
wait_for 'client-c'"'"'s Remote Transmission cancel request is refused (Result 0); bob goes on' "answered('client-c', 'cancel', 'client-b') and remote('client-c').get('result') is False and tx('client-b')"
remember revocations "st('client-b').get('mcvideo_revocations', 0)"
mcx client-a "mcvideo-remote-cancel $BOB"
wait_for 'alice'"'"'s cancel request succeeds (Result 1)' "answered('client-a', 'cancel', 'client-b') and remote('client-a').get('result') is True"
wait_for 'bob stops: his transmission is revoked with cause 5' "not tx('client-b') and st('client-b').get('mcvideo_revocations', 0) > saved['revocations'] and st('client-b').get('mcvideo_reject_cause') == 5"
mcx client-c "mcvideo-remote-transmit $CLIENT_D"
wait_for 'client-c'"'"'s Remote Transmission request is refused (Result 0)' "answered('client-c', 'transmit', 'client-d') and remote('client-c').get('result') is False"
hold_for 'client-d does not transmit' "not tx('client-d')"
mcx client-a "mcvideo-remote-cancel $CLIENT_D"
wait_for 'a cancel for a user who is not transmitting fails (Result 0)' "answered('client-a', 'cancel', 'client-d') and remote('client-a').get('result') is False"
mcx client-a mcvideo-hangup
wait_for 'the group call ends for all' "idle()"

step '8. Ambient viewing, remotely initiated: alice views bob, whose client may not end the call'
mcx client-a mcvideo-ambient "$BOB" remote
wait_for 'alice views bob (remote-init)' "ambient('client-a', 'client-b', 'remote-init')"
wait_for 'bob transmits without asking; alice decodes his pictures; she does not transmit' "tx('client-b') and not tx('client-a') and frames('client-a') >= 20 and same('client-b', 'client-a')"
wait_for 'alice may release the call, bob may not' "st('client-a').get('mcvideo_ambient_release') is True and st('client-b').get('mcvideo_ambient_release') is False"
mcx client-b mcvideo-hangup
wait_for 'bob'"'"'s client refuses to release it' "'ambient viewing call release not allowed' in (st('client-b').get('last_error') or '')" 10
hold_for 'the call goes on' "ambient('client-a', 'client-b', 'remote-init')"
mcx client-a mcvideo-hangup
wait_for 'alice releases it' "idle('client-a', 'client-b')"

step '9. Ambient viewing, locally initiated: alice asks bob to view her; bob ends it'
mcx client-a mcvideo-ambient "$BOB" local
wait_for 'bob views alice (local-init)' "ambient('client-b', 'client-a', 'local-init')"
wait_for 'alice transmits; bob decodes her pictures' "tx('client-a') and frames('client-b') >= 20 and same('client-a', 'client-b')"
wait_for 'both may release the call' "st('client-a').get('mcvideo_ambient_release') is True and st('client-b').get('mcvideo_ambient_release') is True"
mcx client-b mcvideo-hangup
wait_for 'bob releases it' "idle('client-a', 'client-b')"

step '10. Refused: bob may not make ambient viewing calls (403, warning 154)'
refused 'bob'"'"'s ambient viewing call: 403 with warning 154' client-b 403 154 mcvideo-ambient "$ALICE" remote

step '11. A call to the viewed-to user ends the ambient viewing call'
mcx client-a mcvideo-ambient "$BOB" remote
wait_for 'alice views bob again' "ambient('client-a', 'client-b', 'remote-init')"
remember before "json.dumps(last('client-a'))"
mcx client-c mcvideo-private "$BOB" auto
wait_for 'alice'"'"'s call is released: call-request-for-viewed-to-client' "json.dumps(last('client-a')) != saved['before'] and idle('client-a') and last('client-a').get('release_reason') == 'call-request-for-viewed-to-client'"
wait_for 'client-c'"'"'s private call to bob goes through' "all(active(r) and st(r).get('mcvideo_call_type') == 'private' and not st(r).get('mcvideo_ambient_type') for r in ('client-b', 'client-c'))"
mcx client-c mcvideo-hangup
wait_for 'call released' "idle()"

step "12. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|INFO|BYE|SIP 200|SIP 403|SIP 404)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
