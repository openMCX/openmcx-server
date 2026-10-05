#!/usr/bin/env bash
# Builds tutorial 4's srsRAN images from the pinned sources (Dockerfile): the gNB with openMCX's patches
# (patches/srsran-project/, NOTICE) and srsUE unmodified. About 25 minutes each.
#   srsran/build-images.sh            both;  srsran/build-images.sh gnb  or  ue
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
GNB_TAG=${SRSRAN_GNB_TAG:-25.10-mcx}   # the patched gNB
UE_TAG=${SRSRAN_UE_TAG:-25.10}        # srsUE, unmodified
sum=$(cat "$HERE"/patches/srsran-project/*.patch | sha256sum | cut -d' ' -f1)
for target in "${@:-gnb ue}"; do
  for t in $target; do
    case "$t" in
      gnb) docker build --target gnb --build-arg SRSRAN_PROJECT_PATCHES_SHA256="$sum" -t "openmcx-srsran-gnb:$GNB_TAG" "$HERE" ;;
      ue)  docker build --target ue -t "openmcx-srsue:$UE_TAG" "$HERE" ;;
      *)   echo "unknown target: $t (gnb, ue)" >&2; exit 2 ;;
    esac
  done
done
