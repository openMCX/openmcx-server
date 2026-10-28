#!/bin/sh
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#

# Tutorial tooling: activate the agent's MC client from an MCX Admin activation link, once (Agent Tutorial 1). The
# activation itself is mcx-client's (--activate): it fetches the package, signs in with the password and keeps the
# activated configuration in the agent's volume. It implements no 3GPP procedure.
#   docker compose run --rm activate '<activation link>'
set -eu
link=${1:-}
[ -n "$link" ] || { echo "usage: docker compose run --rm activate '<activation link>'" >&2; exit 2; }
mkdir -p /data/engine
if [ -f /data/engine/client.json ] && grep -q '"activated": true' /data/engine/client.json; then
  echo "the agent is activated already: docker compose down -v to start over" >&2
  exit 1
fi
# The device settings: only local ones, ports and addresses. Everything else comes from the activation.
sed -e "s/AGENT_IP/$AGENT_IP/g" -e "s/HOST_IP/$HOST_IP/g" /tutorials/device.json.in > /data/engine/client.json
# The token the bots and the daemon share (MCP over HTTP on 127.0.0.1:8765).
[ -f /data/token ] || python3 -c 'import secrets; print(secrets.token_hex(32))' > /data/token
chmod 644 /data/token
printf 'Password of the user bots: '
stty -echo 2>/dev/null || true
read -r password
stty echo 2>/dev/null || true
echo
umask 077
printf '%s\n' "$password" > /tmp/password
# The engine activates, then is asked for its status: as it does not run here, it stops at once.
mcx-client --config /data/engine/client.json --activate "$link" --password-file /tmp/password --command status \
  >/tmp/out 2>&1 || true
rm -f /tmp/password
if grep -q '"activated": true' /data/engine/client.json; then
  echo "activated as $(python3 -c 'import json; print(json.load(open("/data/engine/client.json"))["sip"]["identity"])')"
else
  cat /tmp/out >&2
  echo "not activated" >&2
  exit 1
fi
