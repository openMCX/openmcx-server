#!/usr/bin/env bash
set -euo pipefail
# wolfCrypt ECCSI/SAKKE backend; see README.md for license and provenance.
prefix=${1:?usage: build.sh INSTALL_PREFIX [WORK_DIRECTORY]}
work=${2:-/tmp/openmcx-wolfssl-build}
version=5.8.2-stable
archive="$work/wolfssl-$version.tar.gz"
mkdir -p "$work"
if [ ! -f "$archive" ]; then
  curl --fail --location --retry 3 "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v$version.tar.gz" --output "$archive"
fi
printf '%s  %s\n' '3ef126e3466e2f8f6ebb62b916a7f8fb26c6709dbdf2b63a167759f2fdb53068' "$archive" | sha256sum --check --strict
tar -xzf "$archive" -C "$work"
cd "$work/wolfssl-$version"
./autogen.sh
./configure --prefix="$prefix" --enable-eccsi --enable-sakke --enable-static --disable-shared --disable-examples --disable-crypttests
make -j"${MCX_BUILD_JOBS:-4}"
make install
