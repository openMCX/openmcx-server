#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#
# reSIProcate for the SIP stack prototype (prototype/resiprocate, dependencies/resiprocate/README.md): downloads the
# pinned release, checks its SHA-256, applies OpenMCX's patches in this directory, and builds the static rutil, resip
# and dum libraries with OpenSSL only (no repro, media, TURN, tests, popt, GeoIP, DTLS).
#
#   dependencies/resiprocate/build.sh INSTALL_PREFIX [WORK_DIRECTORY]
set -euo pipefail
prefix=${1:?usage: build.sh INSTALL_PREFIX [WORK_DIRECTORY]}
work=${2:-/tmp/openmcx-resiprocate-build}
here=$(cd -- "$(dirname -- "$0")" && pwd)
version=1.14.0
url="https://github.com/resiprocate/resiprocate/archive/refs/tags/resiprocate-$version.tar.gz"
sha256=f132e4d0fcae0c155f91e5dad608a9985e199e4e3c09b6029a70b1b3b6d0b156
archive="$work/resiprocate-$version.tar.gz"
source="$work/resiprocate-$version"

mkdir -p "$work"
if [ ! -f "$archive" ]; then
  curl --fail --silent --show-error --location --retry 3 "$url" --output "$archive"
fi
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --strict

# A fresh source tree each time, so that the patches apply to the pinned release only.
if [ -e "$source" ]; then
  echo "build.sh: $source exists; remove it or pass another WORK_DIRECTORY" >&2
  exit 1
fi
mkdir -p "$source"
tar -xzf "$archive" -C "$source" --strip-components=1
for patch_file in "$here"/*.patch; do
  patch -d "$source" -p1 --forward --quiet < "$patch_file"
done

cmake -S "$source" -B "$source/build" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX="$prefix" \
  -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DWITH_SSL=ON -DUSE_POPT=OFF -DUSE_DTLS=OFF \
  -DUSE_MAXMIND_GEOIP=OFF -DBUILD_REPRO=OFF -DBUILD_RETURN=OFF -DBUILD_REFLOW=OFF -DBUILD_MEDIA=OFF -DBUILD_REND=OFF \
  -DBUILD_TFM=OFF -DBUILD_RECON=OFF -DBUILD_TESTING=OFF -DBUILD_QPID_PROTON=OFF -DBUILD_DSO_PLUGINS=OFF \
  -DWITH_C_ARES=OFF -DENABLE_LOG_REPOSITORY_DETAILS=OFF -DRESIP_ASSERT_SYSLOG=OFF >/dev/null
cmake --build "$source/build" -j"${MCX_BUILD_JOBS:-8}"
cmake --install "$source/build" >/dev/null
