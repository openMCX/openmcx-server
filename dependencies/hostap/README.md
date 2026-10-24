# MILENAGE (TS 35.206) from hostap

Pinned source: [hostap](https://w1.fi/cgit/hostap/) tag `hostap_2_11`, commit
`e313f6c0a8e8a95ece631644e8356c6b4c7ca3c5`, files `src/crypto/milenage.c` and `src/crypto/milenage.h`, and the
project's `README`, which carries its licence (BSD, the one with the advertisement clause removed). The three files
are kept here unmodified:

| File | SHA-256 |
|---|---|
| `milenage.c` | `67065ba6346dffe80fe50929f44ac15f81e49f2e02044b12249b0743e725ef4c` |
| `milenage.h` | `2bf1176fcd1d82f292f53a802df5af48e86c194c8d7ee586c596f8f2324b8e50` |
| `README` | `f1b5992bbdd015c3ccb7faaadd62ef58ed821e15b9329bf2ceb27511ccc3f562` |

Fetched with:

```sh
for f in milenage.c milenage.h; do
  curl -fsSL -o $f "https://w1.fi/cgit/hostap/plain/src/crypto/$f?id=e313f6c0a8e8a95ece631644e8356c6b4c7ca3c5"
done
curl -fsSL -o README "https://w1.fi/cgit/hostap/plain/README?id=e313f6c0a8e8a95ece631644e8356c6b4c7ca3c5"
```

CMakeLists.txt checks the SHA-256 of `milenage.c` and `milenage.h` at configure time and stops on a difference.
The headers `milenage.c` includes (`includes.h`, `common.h`, `crypto/aes_wrap.h`) are not hostap's: OpenMCX
supplies them in `src/security/hostap/`, with the AES-128 block function on OpenSSL (`aes_128_encrypt_block`),
the `os_mem*` functions and the debug print functions as no-ops. OpenMCX's own code (`src/security/ims_aka.cpp`:
the ISIM's sequence numbers of TS 33.102 annex C.2, AUTS, the HTTP Digest AKA passwords, sec-agree, the ESP keys)
calls `milenage_f1` and `milenage_f2345` only.
