#!/usr/bin/env bash
# Package the patched OAI CN5G images for distribution: openmcx/oai-<nf>:mcx-n5 is oai-<nf>:mcx-n5 (from
# build-images.sh) with the license, the NOTICE files, the patches and the source location added, as the
# Collaborative Standards Software License v1.0 section 5 requires (NOTICE in this directory). SOURCE in the image
# names the exact upstream commit, its submodules' commits and the SHA-256 of each patch.
#
#   oai/cn5g/package-images.sh [--push] [amf|pcf|smf|upf ...]
#
# The network function repositories are read from src/ (build-images.sh). --push uploads the images to Docker Hub.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PUSH=0
if [ "${1:-}" = --push ]; then PUSH=1; shift; fi
NFS=("$@")
[ ${#NFS[@]} -gt 0 ] || NFS=(amf pcf smf upf)
CN5G=${CN5G:-$HERE/src}
SOURCE=https://github.com/openMCX/openmcx-server/tree/main/tutorials/end-to-end/03-mcx-over-oai-5g/oai/cn5g
for nf in "${NFS[@]}"; do
  repo="$CN5G/oai-cn5g-$nf"
  [ -f "$repo/LICENSE" ] || { echo "no $repo (build-images.sh)" >&2; exit 1; }
  docker image inspect "oai-$nf:mcx-n5" >/dev/null || { echo "no image oai-$nf:mcx-n5 (build-images.sh)" >&2; exit 1; }
  revision=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "oai-$nf:mcx-n5")
  patches_sha=$(docker image inspect -f '{{index .Config.Labels "org.openmcx.patches.sha256"}}' "oai-$nf:mcx-n5")
  [ -n "$revision" ] || { echo "oai-$nf:mcx-n5 has no revision label (build it with build-images.sh)" >&2; exit 1; }
  dir="$HERE/patches/oai-cn5g-$nf"
  all_patches=("$dir"/*.patch)
  while read -r sub; do all_patches+=("$dir/$sub"/*.patch); done < <(cd "$dir" && find . -mindepth 2 -name '*.patch' -printf '%h\n' | sed 's|^\./||' | sort -u)
  if [ "$(cat "${all_patches[@]}" | sha256sum | cut -d' ' -f1)" != "$patches_sha" ]; then
    echo "oai-$nf:mcx-n5 was built from other patches than patches/oai-cn5g-$nf/: build it again" >&2
    exit 1
  fi
  tmp=$(mktemp -d)
  mkdir -p "$tmp/doc"
  cp "$repo/LICENSE" "$tmp/doc/LICENSE"
  cp "$repo/NOTICE" "$tmp/doc/NOTICE.oai"
  cp -r "$repo/LICENSES" "$tmp/doc/LICENSES"
  cp "$HERE/NOTICE" "$tmp/doc/NOTICE"
  cp -r "$HERE/patches/oai-cn5g-$nf" "$tmp/doc/patches"
  {
    echo "upstream:   https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-$nf"
    echo "tag:        v2.2.1"
    echo "commit:     $revision"
    echo "submodules, at the commits the release records (patched ones: patches/<path>/ below):"
    git -C "$repo" ls-tree -r HEAD | awk '$2 == "commit" {print "  " $3 "  " $4}'
    echo "patches (applied in this order with git am; sha256):"
    for patch in "${all_patches[@]}"; do echo "  $(sha256sum "$patch" | cut -d' ' -f1)  ${patch#"$dir"/}"; done
    echo "modifications: $SOURCE"
  } > "$tmp/doc/SOURCE"
  cat > "$tmp/Dockerfile" <<EOF
FROM oai-$nf:mcx-n5
COPY doc /usr/share/doc/openmcx-oai
LABEL org.opencontainers.image.title="oai-$nf (openMCX MCX N5 QoS)" \\
      org.opencontainers.image.version="v2.2.1" \\
      org.opencontainers.image.revision="$revision" \\
      org.openmcx.patches.sha256="$patches_sha" \\
      org.opencontainers.image.source="$SOURCE" \\
      org.opencontainers.image.licenses="LicenseRef-CSSL-1.0" \\
      org.opencontainers.image.description="OAI CN5G $nf v2.2.1 modified by openMCX; see /usr/share/doc/openmcx-oai/NOTICE and SOURCE"
EOF
  docker build -q -t "openmcx/oai-$nf:mcx-n5" "$tmp" >/dev/null
  rm -rf "$tmp"
  echo "openmcx/oai-$nf:mcx-n5 ($revision)"
  if [ "$PUSH" = 1 ]; then docker push "openmcx/oai-$nf:mcx-n5"; fi
done
