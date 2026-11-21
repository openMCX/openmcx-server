# wolfSSL: the ECCSI and SAKKE cross-check

OpenMCX's ECCSI (RFC 6507) and SAKKE (RFC 6508) are its own, on OpenSSL (`src/security/eccsi.cpp`,
`src/security/sakke.cpp`); no OpenMCX program links wolfSSL. The development image keeps it for one test,
`tests/test_ibe_wolfssl.cpp`, which checks that keys, signatures and Encapsulated Data made by either implementation
are accepted by the other (and that KMS secrets and key sets stored by earlier OpenMCX versions, made with wolfSSL,
keep working). CMake builds that test only when it finds wolfSSL.

Pinned source: [wolfSSL v5.8.2-stable](https://github.com/wolfSSL/wolfssl/tree/v5.8.2-stable).
Archive SHA-256: `3ef126e3466e2f8f6ebb62b916a7f8fb26c6709dbdf2b63a167759f2fdb53068`.

The ECCSI/SAKKE source headers license this release under **GPL-3.0-or-later**;
the release's complete license is retained in [COPYING](COPYING). Upstream also
offers commercial licensing. This dependency's license does not grant a new
license to open-mcx. Packaging and redistribution must preserve the applicable
license and source obligations. It was used for cryptographic primitives, not TLS.

Build (requires C compiler, make, autoconf, automake, libtool, curl):

```sh
dependencies/wolfssl/build.sh /opt/wolfssl
```

The test uses `/opt/wolfssl/include` and links `/opt/wolfssl/lib/libwolfssl.a`; it includes `<wolfssl/options.h>`
before the wolfCrypt headers to use the same configuration.

This is an explicit reproducible pin, not a claim that the release is the latest
or that the resulting product has undergone a cryptographic security review.
