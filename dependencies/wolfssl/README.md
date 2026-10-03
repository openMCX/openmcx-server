# ECCSI and SAKKE backend

Pinned source: [wolfSSL v5.8.2-stable](https://github.com/wolfSSL/wolfssl/tree/v5.8.2-stable).
Archive SHA-256: `3ef126e3466e2f8f6ebb62b916a7f8fb26c6709dbdf2b63a167759f2fdb53068`.

The ECCSI/SAKKE source headers license this release under **GPL-3.0-or-later**;
the release's complete license is retained in [COPYING](COPYING). Upstream also
offers commercial licensing. This dependency's license does not grant a new
license to open-mcx. Packaging and redistribution must preserve the applicable
license and source obligations. It is used for cryptographic primitives, not TLS.

Build (requires C compiler, make, autoconf, automake, libtool, curl):

```sh
dependencies/wolfssl/build.sh /opt/wolfssl
```

Use `/opt/wolfssl/include`, link `/opt/wolfssl/lib/libwolfssl.a` and pthread.
Include `<wolfssl/options.h>` before wolfCrypt headers to use the same configuration.
The backend separately uses OpenSSL libcrypto for UID SHA-256 and protected payload
AES-GCM/HMAC. No pairing or ECCSI arithmetic is reimplemented by open-mcx.

This is an explicit reproducible pin, not a claim that the release is the latest
or that the resulting product has undergone a cryptographic security review.
