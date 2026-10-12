#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# OpenMCX Unit Test Tutorial 14: the steps of README.md, one after the other, each checked before the next.
# Usage: ./run.sh            (the system must be up: docker compose up -d --wait)
# Writes captures/14-mcdata-files-msgstore-run.pcap.gz (captures/14-mcdata-files-msgstore-full.pcap.gz is the
# reference run of README.md). Set COMPOSE to another command than "docker compose" if needed.
set -euo pipefail
cd "$(dirname "$0")"
read -r -a DC <<<"${COMPOSE:-docker compose}"
DC+=(-f docker-compose.yaml)
CAPTURE=14-mcdata-files-msgstore-full.pcap   # in the capture container
OUT=captures/14-mcdata-files-msgstore-run.pcap.gz
ALICE=sip:alice.mcdata@mcx.test
BOB=sip:bob.mcdata@mcx.test
GROUP=sip:operations@mcx.test
RUN=$RANDOM   # a suffix for this run's file names and texts, so that the steps can run again on the same system

# Send a command to a client's running mcx-client (it is the same program with --command).
mcx() {
  local role=$1
  shift
  echo "  \$ $role: $*"
  "${DC[@]}" exec -T "$role" mcx-client --config "/config/$role.json" --command "$*" >/dev/null
}

# Run a shell command in a client's container and print its output.
in_client() {
  "${DC[@]}" exec -T "$1" sh -c "$2"
}

# The Python helpers of wait_for and value: st('client-a') is a role's status.json, files() the files it was
# offered over HTTP, sent() the file distributions it sent, notes(role, id) the FD notifications it received for a
# message, media_files() the files it sent or received over the media plane, store() its message store state,
# deposited() the objects the MCData server has deposited in the message store.
HELPERS=$(
  cat <<'PY'
import json
def st(role):
    try:
        return json.load(open(f'/artifacts/{role}/status.json'))
    except (OSError, ValueError):
        return {}
def files(role):
    return st(role).get('mcdata_files') or []
def sent(role):
    return st(role).get('mcdata_files_sent') or []
def notes(role, message):
    return [n for n in st(role).get('mcdata_file_notifications') or [] if n.get('message_id') == message]
def media_files(role):
    return st(role).get('mcdata_media_files') or []
def store(role):
    return st(role).get('msgstore') or {}
def deposited():
    return (st('mcdata-server').get('msgstore') or {}).get('counters', {}).get('deposited', 0)
PY
)

# Wait until a Python condition (with the helpers above) holds.
wait_for() {
  local label=$1 condition=$2 timeout=${3:-30}
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
import sys, time
deadline = time.monotonic() + float(sys.argv[2])
while time.monotonic() < deadline:
    try:
        if eval(sys.argv[1]):
            sys.exit(0)
    except (AttributeError, KeyError, IndexError, TypeError):
        pass  # a status not written yet
    time.sleep(0.2)
sys.exit(1)" "$condition" "$timeout" || { echo "  FAILED: $label" >&2; exit 1; }
  echo "  ok: $label"
}

# Print the value of a Python expression (with the helpers above).
value() {
  "${DC[@]}" exec -T client-a python3 -c "$HELPERS
import sys
print(eval(sys.argv[1]))" "$1"
}

# Make a file of random text of this size in a client's /tmp; print its SHA-256.
make_file() {
  in_client "$1" "head -c $3 /dev/urandom | base64 | head -c $3 > /tmp/$2 && sha256sum /tmp/$2 | cut -d' ' -f1"
}

step() { printf '\n%s\n' "$*"; }

step '1. Four clients signed in, registered and authorised for MCData, affiliated to the group operations'
wait_for 'client-a to client-d MCData-authorised and affiliated' \
  "all(st(r).get('mcdata_authorized') and st(r).get('mcdata_affiliated') for r in ('client-a','client-b','client-c','client-d'))" 90

step '2. File distribution over HTTP to one user: upload, offer, automatic download, notifications'
NOTE=note-$RUN.txt
sum=$(make_file client-a "$NOTE" 40)
mcx client-a fd-send completed "$BOB" "/tmp/$NOTE"
wait_for 'the FD request is accepted (202) and names the uploaded file by its URL' \
  "(st('client-a').get('mcdata_fd_last_result') or {}).get('status') == 202 and sent('client-a') and sent('client-a')[-1]['file_url'].endswith('/$NOTE')"
M1=$(value "sent('client-a')[-1]['message_id']")
wait_for 'client-b downloads the small file at once (mandatory), its hash verified' \
  "any(f.get('name') == '$NOTE' and f.get('state') == 'downloaded' and f.get('mandatory') and f.get('hash_verified') for f in files('client-b'))"
[ "$(in_client client-b "sha256sum /artifacts/client-b/downloads/$NOTE | cut -d' ' -f1")" = "$sum" ] ||
  { echo "  FAILED: the downloaded file differs" >&2; exit 1; }
echo '  ok: the downloaded file is identical to the file sent'
wait_for 'client-a is told: ACCEPTED, then COMPLETED' "{n.get('type') for n in notes('client-a', '$M1') if 'type' in n} == {1, 3}"

step '3. File distribution to the group: each member decides (accept, reject, defer)'
BIG=report-$RUN.txt
make_file client-a "$BIG" 600 >/dev/null
mcx client-a fd-send completed "group=$GROUP" "/tmp/$BIG"
wait_for 'the group FD request is accepted (202)' \
  "(st('client-a').get('mcdata_fd_last_result') or {}).get('status') == 202 and sent('client-a')[-1]['file_url'].endswith('/$BIG')"
M2=$(value "sent('client-a')[-1]['message_id']")
wait_for 'client-b, client-c and client-d are offered the file, without mandatory download' \
  "all(any(f.get('name') == '$BIG' and f.get('state') == 'offered' and not f.get('mandatory') for f in files(r)) for r in ('client-b','client-c','client-d'))"
mcx client-b fd-accept "$M2"
mcx client-c fd-reject "$M2"
mcx client-d fd-defer "$M2"
wait_for 'client-b downloads it' "any(f.get('name') == '$BIG' and f.get('state') == 'downloaded' for f in files('client-b'))"
wait_for 'client-a is told: accepted and completed (client-b), rejected (client-c), deferred (client-d)' \
  "{1, 2, 3, 4} <= {n.get('type') for n in notes('client-a', '$M2') if 'type' in n}"

step '4. File distribution over the media plane: the file travels in MSRP, not by URL'
MEDIA=photo-$RUN.bin
make_file client-a "$MEDIA" 200 >/dev/null
mcx client-a fd-media mandatory completed "$BOB" "/tmp/$MEDIA"
wait_for 'the file offer is accepted (200 OK to the INVITE)' "(st('client-a').get('mcdata_media_result') or {}).get('status') == 200"
wait_for 'client-b receives the 200 bytes over MSRP, its hash verified' \
  "any(f.get('name') == '$MEDIA' and f.get('state') == 'received' and f.get('hash_verified') and f.get('received_bytes') == 200 for f in media_files('client-b'))"
wait_for 'the session is released once the file has been relayed' "(st('client-a').get('mcdata_media_result') or {}).get('state') == 'delivered'" 40

step '5. The message store: storage switched on, communications deposited, found again'
mcx client-a mcdata-msgstore-ctrl enable all-private all-group
wait_for 'client-a stores all its communications: 200' "(store('client-a').get('control') or {}).get('status') == 200"
mcx client-b mcdata-msgstore-ctrl enable "private=$ALICE"
wait_for 'client-b stores its communications with client-a: 200' "(store('client-b').get('control') or {}).get('status') == 200"
mcx client-c mcdata-msgstore-ctrl enable all-private
wait_for 'client-c may not: 403, warning 234' \
  "(store('client-c').get('control') or {}).get('status') == 403 and '234' in (store('client-c').get('control') or {}).get('warning', '')"
before=$(value 'deposited()')
mcx client-a sds "$BOB" "stored-hello-$RUN"
wait_for 'the SDS is sent (202)' "(st('client-a').get('mcdata_last_result') or {}).get('status') == 202"
wait_for 'the MCData server deposits it for the sender and for the recipient' "deposited() >= $before + 2"
for _ in 1 2 3 4 5; do
  mcx client-b mcdata-msgstore sync
  if "${DC[@]}" exec -T client-a python3 -c "$HELPERS
import sys
sys.exit(0 if any(o.get('Text') == 'stored-hello-$RUN' for o in (store('client-b').get('objects') or {}).values()) else 1)"; then
    break
  fi
  sleep 1
done
wait_for 'client-b finds it in its message store, from client-a' \
  "any(o.get('Text') == 'stored-hello-$RUN' and o.get('From') == '$ALICE' for o in (store('client-b').get('objects') or {}).values())" 5
KEPT=kept-$RUN.bin
sum=$(make_file client-a "$KEPT" 300)
mcx client-a fd-send "$BOB" "/tmp/$KEPT"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  mcx client-b mcdata-msgstore sync
  OBJ=$(value "next((k for k, o in (store('client-b').get('objects') or {}).items() if o.get('Request-Type') == 'one-to-one-fd'), '')")
  [ -n "$OBJ" ] && break
  sleep 1
done
[ -n "$OBJ" ] || { echo "  FAILED: no file distribution in client-b's message store" >&2; exit 1; }
echo '  ok: the file distribution is deposited for client-b'
mcx client-b mcdata-msgstore payload "$OBJ"
wait_for 'the message store fetched the file itself from the content server: same SHA-256' \
  "(store('client-b').get('payload') or {}).get('sha256') == '$sum'"

step "6. The capture: $OUT"
sleep 1
mkdir -p captures
"${DC[@]}" cp "capture:/captures/$CAPTURE" "${OUT%.gz}" 2>/dev/null
gzip -9f "${OUT%.gz}"
"${DC[@]}" run --rm --no-deps -T --entrypoint tshark capture -r "/captures/$CAPTURE" -q -z sip,stat \
  2>/dev/null | grep -E '^ *(INVITE|BYE|MESSAGE|SIP 200|SIP 202)' || true
echo
echo "Done. Open $OUT in Wireshark (README.md, 'Look at the capture')."
