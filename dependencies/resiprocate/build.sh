#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#
# reSIProcate for the SIP engine (prototype/resiprocate, dependencies/resiprocate/README.md): downloads the pinned tag
# of OpenMCX's fork (github.com/openMCX/resiprocate: the 1.14.0 release with OpenMCX's patches as commits), checks its
# SHA-256, and builds the static rutil, resip and dum libraries with OpenSSL only (no repro, media, TURN, tests, popt,
# GeoIP, DTLS).
#
#   dependencies/resiprocate/build.sh INSTALL_PREFIX [WORK_DIRECTORY]
set -euo pipefail
prefix=${1:?usage: build.sh INSTALL_PREFIX [WORK_DIRECTORY]}
work=${2:-/tmp/openmcx-resiprocate-build}
version=openmcx-1.14.0-1
url="https://github.com/openMCX/resiprocate/archive/refs/tags/$version.tar.gz"
sha256=a04a018a1e6be6321f979b0aa9f3abb9c30daddf7936b5caa853db650a7dc1e8
archive="$work/resiprocate-$version.tar.gz"
source="$work/resiprocate-$version"

mkdir -p "$work"
if [ ! -f "$archive" ]; then
  curl --fail --silent --show-error --location --retry 3 "$url" --output "$archive"
fi
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --strict

# A fresh source tree each time, the pinned tag only.
if [ -e "$source" ]; then
  echo "build.sh: $source exists; remove it or pass another WORK_DIRECTORY" >&2
  exit 1
fi
mkdir -p "$source"
tar -xzf "$archive" -C "$source" --strip-components=1

cmake -S "$source" -B "$source/build" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX="$prefix" \
  -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DWITH_SSL=ON -DUSE_POPT=OFF -DUSE_DTLS=OFF \
  -DUSE_MAXMIND_GEOIP=OFF -DBUILD_REPRO=OFF -DBUILD_RETURN=OFF -DBUILD_REFLOW=OFF -DBUILD_MEDIA=OFF -DBUILD_REND=OFF \
  -DBUILD_TFM=OFF -DBUILD_RECON=OFF -DBUILD_TESTING=OFF -DBUILD_QPID_PROTON=OFF -DBUILD_DSO_PLUGINS=OFF \
  -DWITH_C_ARES=OFF -DENABLE_LOG_REPOSITORY_DETAILS=OFF -DRESIP_ASSERT_SYSLOG=OFF >/dev/null
cmake --build "$source/build" -j"${MCX_BUILD_JOBS:-8}"
cmake --install "$source/build" >/dev/null
# The licence, kept with the libraries for the images that carry them.
install -D -m 644 "$source/LICENSE.md" "$prefix/share/doc/resiprocate/LICENSE.md"
