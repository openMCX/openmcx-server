# wolfSSL: the optional ECCSI and SAKKE cross-check

OpenMCX's ECCSI (RFC 6507) and SAKKE (RFC 6508) are its own, on OpenSSL (`src/security/eccsi.cpp`,
`src/security/sakke.cpp`). No OpenMCX program or image contains wolfSSL, the development image included.

It remains available, built by hand, for one test: `tests/test_ibe_wolfssl.cpp` checks that keys, signatures and
Encapsulated Data made by either implementation are accepted by the other, that the deterministic results (an RSK,
the Encapsulated Data of an SSV) are the same octets (so KMS secrets and key sets stored by OpenMCX versions that
used wolfSSL keep working), and that both give the same verdict on randomly mutated inputs. CMake builds the test
only when it finds wolfSSL. Run it after a change to the ECCSI or SAKKE code:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace openmcx-dev:0.4 bash -lc '
  dependencies/wolfssl/build.sh /tmp/wolfssl /tmp/wolfssl-build &&
  cmake -S . -B /tmp/build-wolfssl -DCMAKE_PREFIX_PATH=/tmp/wolfssl >/dev/null &&
  cmake --build /tmp/build-wolfssl -j8 --target test_ibe_wolfssl && /tmp/build-wolfssl/test_ibe_wolfssl'
```

`build.sh` downloads the pinned source, checks its SHA-256, and builds a static wolfCrypt with ECCSI and SAKKE only
(it needs a C compiler, make, autoconf, automake, libtool and curl, which the development image has). The test
includes `<wolfssl/options.h>` before the wolfCrypt headers to use the same configuration.

Pinned source: [wolfSSL v5.8.2-stable](https://github.com/wolfSSL/wolfssl/tree/v5.8.2-stable).
Archive SHA-256: `3ef126e3466e2f8f6ebb62b916a7f8fb26c6709dbdf2b63a167759f2fdb53068` (also in `dependencies/lock.json`,
marked optional).

The ECCSI/SAKKE source headers license this release under **GPL-3.0-or-later**; the release's complete license is
retained in [COPYING](COPYING). Building and running the test locally does not distribute wolfSSL; do not ship the
test binary or a wolfSSL build.
