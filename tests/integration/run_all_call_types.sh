#!/usr/bin/env bash
# Regression of every call-type scenario against one server instance.
#
# Usage: tests/integration/run_all_call_types.sh LAB_DIRECTORY PROJECT [LAB_FLAGS]
# The lab must be prepared with
#   tools/prepare-prearranged-test.py --private-call --broadcast --chat --adhoc ...
# and its speech fixtures copied. Clients are restarted between scenarios so
# each starts from its configured affiliation; the server keeps running.
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
LAB=$(cd -- "$1" && pwd)
PROJECT=$2
COMPOSE=("$ROOT/.cache/deps/docker-compose-linux-x86_64" -p "$PROJECT" -f "$LAB/compose.json")
ARTIFACTS="$LAB/artifacts"
"${COMPOSE[@]}" up -d >/dev/null
failed=0
# Each scenario's wire check (wire_check.py) runs alongside it and is reported as NAME-wire.
WIRE=(python3 "$ROOT/tests/integration/wire_check.py" --compose "$LAB/compose.json" --project "$PROJECT"
  --artifacts "$ARTIFACTS" "--lab-flags=${3:-}")
run() {
  local name=$1 script=$2
  "${WIRE[@]}" start --scenario "${script%.py}" > "$LAB/$name.wire.log" 2>&1
  local wire=$?
  timeout 900 python3 "$ROOT/tests/integration/$script" --compose "$LAB/compose.json" \
    --artifacts "$ARTIFACTS" --project "$PROJECT" > "$LAB/$name.log" 2>&1
  local status=$?
  echo "$name: $([ $status -eq 0 ] && echo PASS || echo "FAIL ($status)")"
  [ $status -eq 0 ] || failed=1
  if [ $wire -eq 0 ]; then
    "${WIRE[@]}" finish --scenario "${script%.py}" >> "$LAB/$name.wire.log" 2>&1
    wire=$?
    if ! tail -1 "$LAB/$name.wire.log" | grep -q '"skipped"'; then
      echo "$name-wire: $([ $wire -eq 0 ] && echo PASS || echo "FAIL ($wire)")"
      [ $wire -eq 0 ] || failed=1
    fi
  fi
  "${COMPOSE[@]}" restart client-a client-b client-c client-d >/dev/null
}
run prearranged prearranged_scenario.py
run failure prearranged_failure_scenario.py
run broadcast broadcast_call_scenario.py
run private private_call_scenario.py
run chat chat_call_scenario.py
run adhoc adhoc_call_scenario.py
run remote-group remote_group_call_scenario.py
run ambient ambient_listening_scenario.py
echo "server instance: $(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['instance_id'])" "$ARTIFACTS/mcptt-server/status.json")"
exit $failed
