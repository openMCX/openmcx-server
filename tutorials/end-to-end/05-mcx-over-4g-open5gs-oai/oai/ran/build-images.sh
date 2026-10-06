#!/usr/bin/env bash
# Builds tutorial 5's OAI eNB and LTE UE: OpenAirInterface at the pinned commit of tag 2026.w39 with openMCX's
# patches (patches/openairinterface5g/, NOTICE), built with OAI's own Dockerfiles (ran-base, ran-build, then the eNB
# and the LTE UE). About 40 minutes (ran-build compiles every OAI target).
#   oai/ran/build-images.sh                 ->  oai-enb:2026.w39-mcx, oai-lte-ue:2026.w39-mcx
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OAI_TAG=2026.w39
OAI_COMMIT=29d5fa7d38bb1ee8935ef7ae30a396d53772ea4f
UE_TAG=${OAI_LTE_UE_TAG:-2026.w39-mcx}
ENB_TAG=${OAI_ENB_TAG:-2026.w39-mcx}
SRC="$HERE/src"

rm -rf "$SRC"
git clone --depth 1 --branch "$OAI_TAG" https://gitlab.eurecom.fr/oai/openairinterface5g.git "$SRC"
test "$(git -C "$SRC" rev-parse HEAD)" = "$OAI_COMMIT" \
  || { echo "openairinterface5g $OAI_TAG is not $OAI_COMMIT" >&2; exit 1; }
sum=$(cat "$HERE"/patches/openairinterface5g/*.patch | sha256sum | cut -d' ' -f1)
for patch in "$HERE"/patches/openairinterface5g/*.patch; do
  git -C "$SRC" -c user.name=openMCX -c user.email=noreply@openmcx.invalid am --3way -q "$patch" \
    || { echo "patch $(basename "$patch") does not apply to openairinterface5g $OAI_COMMIT" >&2; exit 1; }
done
{
  echo "OpenAirInterface eNB and LTE UE built by openMCX (tutorials/end-to-end/05-mcx-over-4g-open5gs-oai/oai/ran)"
  echo "upstream: https://gitlab.eurecom.fr/oai/openairinterface5g.git"
  echo "tag: $OAI_TAG"; echo "commit: $OAI_COMMIT"
  echo "patches (sha256 of all: $sum):"
  for patch in "$HERE"/patches/openairinterface5g/*.patch; do
    echo "  $(sha256sum "$patch" | cut -d' ' -f1)  $(basename "$patch")"
  done
  echo "result: $(git -C "$SRC" rev-parse HEAD)"
} > "$HERE/SOURCE"
cat "$HERE/SOURCE"

# OAI's build chain names its intermediate images ran-base:latest and ran-build:latest.
cd "$SRC"
docker build --target ran-base -t ran-base:latest -f docker/Dockerfile.base.ubuntu .
docker build --target ran-build -t ran-build:latest -f docker/Dockerfile.build.ubuntu .
docker build --target oai-enb -t "oai-enb:$ENB_TAG-build" -f docker/Dockerfile.eNB.ubuntu .
docker build --target oai-lte-ue -t "oai-lte-ue:$UE_TAG-build" -f docker/Dockerfile.lteUE.ubuntu .
# The license, the notices, the patches and SOURCE go into each image, with the commit and the patches' SHA-256.
for image in "oai-enb:$ENB_TAG" "oai-lte-ue:$UE_TAG"; do
  cat > "$HERE/Dockerfile.package" <<EOF
FROM $image-build
COPY LICENSE NOTICE SOURCE /usr/share/doc/openmcx-oai/
COPY patches/openairinterface5g/ /usr/share/doc/openmcx-oai/patches/
LABEL org.opencontainers.image.source="https://gitlab.eurecom.fr/oai/openairinterface5g" \\
      org.opencontainers.image.version="$OAI_TAG" org.opencontainers.image.revision="$OAI_COMMIT" \\
      org.opencontainers.image.licenses="LicenseRef-CSSL-1.0" org.openmcx.patches.sha256="$sum"
EOF
  docker build -t "$image" -f "$HERE/Dockerfile.package" "$HERE"
  docker rmi "$image-build" >/dev/null
  echo "built $image"
done
rm -f "$HERE/Dockerfile.package"
