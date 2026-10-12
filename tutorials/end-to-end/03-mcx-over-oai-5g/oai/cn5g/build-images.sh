#!/usr/bin/env bash
# Build the patched OAI CN5G network functions of tutorial 3: oai-amf:mcx-n5, oai-pcf:mcx-n5, oai-smf:mcx-n5 and
# oai-upf:mcx-n5.
#
#   oai/cn5g/build-images.sh [amf|pcf|smf|upf ...]
#
# For each network function: clone OAI CN5G v2.2.1 into oai/cn5g/src/, check out the pinned commit of the tag (the
# build stops if the tag no longer points to it), its submodules at the commits the release records, apply the patches
# of patches/oai-cn5g-<nf>/ as commits on the branch feature/mcx-n5-qos (and those of patches/oai-cn5g-<nf>/<path>/ in
# the submodule at <path>, e.g. the AMF's src/common-src), and build the image from the repository's
# docker/Dockerfile.<nf>.ubuntu. The image carries the upstream commit and a hash of the patches as labels. About 30
# minutes per network function; stop tutorial 3's RAN (gNB, nr-UE) while compiling, it keeps several cores busy. A
# tree that already exists is reused as it is, if it is based on the pinned commit.
#
# OAI CN5G and these patches are under the Collaborative Standards Software License v1.0 (LICENSE, NOTICE).
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TAG=v2.2.1
BRANCH=feature/mcx-n5-qos
# The commits of TAG (git rev-parse "$TAG^{commit}"), see README.md
declare -A PIN=(
  [amf]=513c0f2dc4175e7d8f099a41d4a797913d3cf40e
  [pcf]=e4780235d0115e58b18b33cef17903f224b69a2c
  [smf]=53af440450d2ece3a3908ba9f87febc4187d232c
  [upf]=451c27daa4b38bd03a5cb5b92412743364ff8ae0
)
if [ $# -gt 0 ]; then nfs=("$@"); else nfs=(amf pcf smf upf); fi
mkdir -p "$HERE/src"
for nf in "${nfs[@]}"; do
  [ -n "${PIN[$nf]:-}" ] || { echo "unknown network function: $nf" >&2; exit 2; }
  pin=${PIN[$nf]}
  repo="$HERE/src/oai-cn5g-$nf"
  dir="$HERE/patches/oai-cn5g-$nf"
  patches=("$dir"/*.patch)
  # patches of submodules: patches/oai-cn5g-<nf>/<submodule path>/*.patch
  mapfile -t submodule_dirs < <(cd "$dir" && find . -mindepth 2 -name '*.patch' -printf '%h\n' | sed 's|^\./||' | sort -u)
  all_patches=("${patches[@]}")
  for sub in "${submodule_dirs[@]}"; do all_patches+=("$dir/$sub"/*.patch); done
  if [ ! -e "$repo" ]; then
    git clone -q "https://github.com/OPENAIRINTERFACE/oai-cn5g-$nf.git" "$repo"
    tagged=$(git -C "$repo" rev-parse "$TAG^{commit}")
    if [ "$tagged" != "$pin" ]; then
      echo "oai-cn5g-$nf: $TAG is now $tagged, not the pinned $pin: the patches are for $pin" >&2
      exit 1
    fi
    git -C "$repo" switch -q -c "$BRANCH" "$pin"
    # The submodules name gitlab.eurecom.fr; OAI publishes the same repositories and commits on GitHub.
    git -C "$repo" -c url."https://github.com/OPENAIRINTERFACE/".insteadOf="https://gitlab.eurecom.fr/oai/cn5g/" \
      submodule update -q --init --recursive
    apply() {  # <git work tree> <patch>...
      local tree=$1; shift
      for patch in "$@"; do
        if ! git -C "$tree" -c user.name=openMCX -c user.email=noreply@openmcx.invalid am -q --3way "$patch"; then
          git -C "$tree" am --abort || true
          echo "oai-cn5g-$nf: patch ${patch#"$HERE"/patches/} does not apply to $tree" >&2
          exit 1
        fi
      done
    }
    apply "$repo" "${patches[@]}"
    for sub in "${submodule_dirs[@]}"; do
      git -C "$repo/$sub" switch -q -c "$BRANCH"
      apply "$repo/$sub" "$dir/$sub"/*.patch
    done
  elif ! git -C "$repo" merge-base --is-ancestor "$pin" HEAD; then
    echo "oai-cn5g-$nf: $repo is not based on the pinned $pin; remove it to clone again" >&2
    exit 1
  fi
  echo "oai-cn5g-$nf: $(git -C "$repo" log --oneline -1) (on $TAG = $pin)"
  patches_sha=$(cat "${all_patches[@]}" | sha256sum | cut -d' ' -f1)
  # A low open-files limit: with the daemon's default (about 10^9) the Python 2 tools the dependencies install close
  # every possible descriptor in each subprocess and the build takes hours
  (cd "$repo" && docker build --ulimit nofile=65536:65536 -t "oai-$nf:mcx-n5" -f "docker/Dockerfile.$nf.ubuntu" \
    --label org.opencontainers.image.revision="$pin" \
    --label org.opencontainers.image.version="$TAG" \
    --label org.openmcx.patches.sha256="$patches_sha" .)
done
