#!/usr/bin/env bash
# Builds tutorial 5's Open5GS image (Dockerfile): v2.8.0 with openMCX's PCRF patch, for every EPC function.
# About 10 minutes.   open5gs/build-images.sh   ->  open5gs:2.8.0-mcx
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TAG=${OPEN5GS_TAG:-2.8.0-mcx}
sum=$(cat "$HERE"/patches/open5gs/*.patch | sha256sum | cut -d' ' -f1)
docker build --build-arg OPEN5GS_PATCHES_SHA256="$sum" -t "open5gs:$TAG" "$HERE"
