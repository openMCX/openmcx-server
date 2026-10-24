//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The AES-128 block function the vendored MILENAGE of hostap (dependencies/hostap/milenage.c) calls, on OpenSSL's AES.
//
// Specifications: TS 35.206 V19.0.0 (Rel-19) clause 4.1 (the kernel function E is AES-128, FIPS 197).

#include "hostap/crypto/aes_wrap.h"

#include <openssl/evp.h>

#include <memory>

//------------------------------------------------------------------------------
// TS 35.206 clause 4.1: E[in]key, one 16-byte block of AES-128 in ECB mode without padding; 0 on success, -1 on any
// OpenSSL failure.
extern "C" int aes_128_encrypt_block(const u8 *key, const u8 *in, u8 *out) {
  const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(),
                                                                                &EVP_CIPHER_CTX_free);
  int length = 0, final_length = 0;
  if (!context || EVP_EncryptInit_ex(context.get(), EVP_aes_128_ecb(), nullptr, key, nullptr) != 1 ||
      EVP_CIPHER_CTX_set_padding(context.get(), 0) != 1 ||
      EVP_EncryptUpdate(context.get(), out, &length, in, 16) != 1 ||
      EVP_EncryptFinal_ex(context.get(), out + length, &final_length) != 1 || length + final_length != 16)
    return -1;
  return 0;
}
