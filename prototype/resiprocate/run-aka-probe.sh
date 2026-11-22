#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#
# The reSIProcate prototype's IMS AKA registration against a lab (prototype/resiprocate/README.md): builds
# reSIProcate (dependencies/resiprocate/build.sh) and aka_probe in the development image, prepares an IMS AKA lab
# (tools/prepare-prearranged-test.py --aka, the regression's), starts it, runs aka_probe as the lab's aka-probe
# subscriber in a container on the lab network with CAP_NET_ADMIN (for the SAs), and always tears the lab down.
#
#   prototype/resiprocate/run-aka-probe.sh IMAGES_TAG CLIENT_IMAGE
#   e.g. prototype/resiprocate/run-aka-probe.sh sakke1 openmcx-client:sakke1
#
# Needs .cache/deps/docker-compose-linux-x86_64 (tools/fetch-dependencies.py). Work files in .cache/resip-prototype.
set -euo pipefail
cd "$(dirname "$0")/../.."
images=${1:?usage: run-aka-probe.sh IMAGES_TAG CLIENT_IMAGE}
client_image=${2:?usage: run-aka-probe.sh IMAGES_TAG CLIENT_IMAGE}
compose_tool=.cache/deps/docker-compose-linux-x86_64
work=.cache/resip-prototype
project="resip-aka-$$"
[ -x "$compose_tool" ] || { echo "run-aka-probe.sh: $compose_tool is missing: run tools/fetch-dependencies.py" >&2; exit 1; }
mkdir -p "$work"

echo "== build reSIProcate and aka_probe"
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace openmcx-dev:0.4 bash -lc "
  set -e
  [ -f $work/resiprocate/include/resip/dum/DialogUsageManager.hxx ] ||
    dependencies/resiprocate/build.sh /workspace/$work/resiprocate /workspace/$work/resiprocate-build > $work/resiprocate-build.log 2>&1
  cmake -S . -B $work/build -DCMAKE_PREFIX_PATH=/workspace/$work/resiprocate > /dev/null
  cmake --build $work/build -j8 --target aka_probe > $work/aka-probe-build.log 2>&1"

echo "== prepare and start the IMS AKA lab ($project)"
lab="$work/lab"
python3 tools/prepare-prearranged-test.py --directory "$lab" --project "$project" --images "$images" \
  --client-image "$client_image" --aka --debug-sip > "$work/lab-prepare.log"
compose=("$compose_tool" -p "$project" -f "$lab/compose.json")
trap '"${compose[@]}" down -v > /dev/null 2>&1 || true' EXIT
"${compose[@]}" up -d --wait > "$work/lab-up.log" 2>&1

echo "== aka_probe as the lab's aka-probe subscriber"
docker run --rm --network "${project}_mcx" --network-alias aka-probe --hostname aka-probe --cap-add NET_ADMIN \
  --user 0 -e HOME=/tmp -v "$PWD/$work/build/aka_probe:/usr/local/bin/aka_probe:ro" \
  -v "$PWD/$lab/generated/aka-probe-aka-probe.json:/config/aka-probe.json:ro" openmcx-dev:0.4 \
  aka_probe --config /config/aka-probe.json 2>&1 | grep -v -i sipCerts
