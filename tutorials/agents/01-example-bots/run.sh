#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Agent Tutorial 1: the steps of README.md, one after the other, each checked before the next. client-c, a
# headless user, chats with the chat bot, talks to the voice bot and watches the video bot.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/01-example-bots-run.pcap.gz (captures/01-example-bots-full.pcap.gz is the reference run of
# README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=01-example-bots-full.pcap   # in the capture container
OUT=captures/01-example-bots-run.pcap.gz
AGENT_MCDATA=sip:alice.mcdata@mcx.test
AGENT_MCPTT=sip:alice.mcptt@mcx.test
AGENT_MCVIDEO=sip:alice.mcvideo@mcx.test

# Send a command to client-c's running mcx-client (it is the same program with --command).
mcx() {
  echo "  \$ client-c: $*"
  "${DC[@]}" exec -T client-c mcx-client --config /config/client-c.json --command "$*" >/dev/null
}

# The Python helpers of wait_for and remember: st() is client-c's status.json, sent() the SDS it sent, answer(id)
# the text of the SDS that answers one of them (InReplyTo), saved[...] values remembered by remember().
HELPERS='
import json, re, sys, time
def st():
    try:
        return json.load(open("/artifacts/client-c/status.json"))
    except (OSError, ValueError):
        return {}
def sent():
    return st().get("mcdata_sent") or []
def answer(message_id):
    for m in st().get("mcdata_inbox") or []:
        if m.get("in_reply_to") == message_id and m.get("payloads"):
            return m["payloads"][0].get("text")
    return None
try:
    saved = json.load(open("/tmp/saved.json"))
except (OSError, ValueError):
    saved = {}
'

# Wait until a Python condition on client-c's status holds.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-c python3 -c "$HELPERS
condition, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
while time.monotonic() < deadline:
    if eval(condition):
        sys.exit(0)
    time.sleep(0.1)
sys.exit(1)" "$condition" "$timeout" || { echo "  FAILED: $label" >&2; exit 1; }
  echo "  ok: $label"
}

# Remember the value of a Python expression as saved[name], and print it.
remember() {
  "${DC[@]}" exec -T client-c python3 -c "$HELPERS
saved[sys.argv[1]] = eval(sys.argv[2])
json.dump(saved, open('/tmp/saved.json', 'w'))
print(saved[sys.argv[1]])" "$1" "$2"
}

# Wait until a bot logs a line with this text, since the step began (step sets SINCE).
SINCE=1970-01-01T00:00:00Z
wait_log() {
  local label=$1 bot=$2 text=$3 timeout=${4:-30}
  local deadline=$((SECONDS + timeout))
  until "${DC[@]}" logs --no-log-prefix --since "$SINCE" "$bot" 2>/dev/null | grep -qF -- "$text"; do
    ((SECONDS < deadline)) || { echo "  FAILED: $label" >&2; exit 1; }
    sleep 0.5
  done
  echo "  ok: $label"
}

# Send an SDS to the agent and print the bot's answer.
ask() {
  remember before "len(sent())" >/dev/null
  mcx sds "$AGENT_MCDATA" "$1" >&2
  wait_for "the SDS is accepted (202)" "len(sent()) > saved['before'] and sent()[-1].get('status') == 202" >&2
  remember asked "sent()[-1]['message_id']" >/dev/null
  wait_for "the chat bot answers \"$1\"" "answer(saved['asked']) is not None" >&2
  remember answer "answer(saved['asked'])"
}

step() {
  printf '\n%s\n' "$*"
  SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
}

step '1. The agent and its bots are ready'
SINCE=1970-01-01T00:00:00Z   # their ready lines come at start-up
wait_for 'client-c signed in, MCPTT, MCData and MCVideo affiliated' "st().get('affiliated') and st().get('mcdata_affiliated') and st().get('mcvideo_affiliated')" 90
"${DC[@]}" exec -T client-a mcx-agent status | python3 -c '
import json, sys
services = json.load(sys.stdin)["services"]
for name in ("mcdata", "mcptt", "mcvideo"):
    service = services[name]
    print("  agent", name + ":", service["id"], "ready" if service["ready"] else "NOT READY")
    assert service["ready"], name'
wait_log 'the chat bot is ready' chat-bot "ready as $AGENT_MCDATA"
wait_log 'the voice bot is ready' voice-bot "voice bot ready as $AGENT_MCPTT"
wait_log 'the video bot is ready' video-bot 'video feed ready'

step '2. The chat bot (MCData): client-c writes ping, time and hello to alice'
pong=$(ask ping)
[ "$pong" = pong ] || { echo "  FAILED: ping answered $pong" >&2; exit 1; }
echo "  ok: ping -> $pong"
time=$(ask time)
[[ $time =~ ^It\ is\ [0-9]{2}:[0-9]{2}\ UTC\ on\ [0-9]{4}-[0-9]{2}-[0-9]{2}\.$ ]] || { echo "  FAILED: time answered $time" >&2; exit 1; }
echo "  ok: time -> $time"
help=$(ask hello)
echo "  ok: hello -> $help"

step '3. The voice bot (MCPTT): a private call from client-c to alice, client-c talks, the bot answers'
mcx private "$AGENT_MCPTT" auto
wait_for 'the agent answers the call at once' "st().get('call_state') == 'active'"
remember heard "st().get('received_packets', 0)" >/dev/null
mcx ptt /speech/alpha.wav
wait_log 'the voice bot hears client-c' voice-bot "heard sip:client-c.mcptt@mcx.test in a private call"
wait_log 'the voice bot speaks in the call' voice-bot "spoke to sip:client-c.mcptt@mcx.test" 40
wait_for 'client-c hears the answer (a tone, then its own words)' "st().get('received_packets', 0) > saved['heard'] + 100"
mcx hangup
wait_for 'the call ended' "st().get('call_state') == 'idle'"

step '4. The voice bot in a group call: client-c calls the group operations, the agent is in it'
mcx call
wait_for 'the group call is up' "st().get('call_state') == 'active'"
remember heard "st().get('received_packets', 0)" >/dev/null
mcx ptt /speech/alpha.wav
wait_log 'the voice bot hears client-c in the group call' voice-bot "in a prearranged call (sip:operations@mcx.test)"
wait_log 'the voice bot speaks in the group call' voice-bot "spoke to sip:operations@mcx.test" 40
wait_for 'client-c hears the answer' "st().get('received_packets', 0) > saved['heard'] + 100"
mcx hangup
wait_for 'the call ended' "st().get('call_state') == 'idle'"

step '5. The video bot (MCVideo): a private video call from client-c to alice'
mcx mcvideo-private "$AGENT_MCVIDEO"
wait_for 'the agent answers and transmits' "st().get('mcvideo_call_state') == 'active' and st().get('mcvideo_transmitter') == '$AGENT_MCVIDEO'" 30
wait_for 'client-c receives the test card (at least 30 pictures)' "len(st().get('mcvideo_received_frames') or {}) >= 30" 30
mcx mcvideo-hangup
wait_for 'the video call ended' "st().get('mcvideo_call_state') in (None, 'idle')"

step '6. The video bot in a group video call of operations'
mcx mcvideo-call
wait_for 'the agent joins and transmits' "st().get('mcvideo_call_state') == 'active' and st().get('mcvideo_transmitter') == '$AGENT_MCVIDEO'" 30
remember pictures "len(st().get('mcvideo_received_frames') or {})" >/dev/null
wait_for 'client-c receives the test card' "len(st().get('mcvideo_received_frames') or {}) >= saved['pictures'] + 30" 30
mcx mcvideo-hangup
wait_for 'the video call ended' "st().get('mcvideo_call_state') in (None, 'idle')"

step "7. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|BYE|MESSAGE|PUBLISH|SIP 200|SIP 202)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture'). The client page: http://127.0.0.1:8080/client/"
