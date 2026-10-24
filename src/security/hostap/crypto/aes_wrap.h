/*
 * OpenMCX Licence Information : AGPL-3.0-or-later
 */

/* OpenMCX's stand-in for hostap's crypto/aes_wrap.h, for the vendored dependencies/hostap/milenage.c: the one AES
 * function it calls, implemented on OpenSSL in src/security/hostap_aes.cpp. OpenMCX build glue, no 3GPP behaviour. */
#ifndef OPENMCX_HOSTAP_AES_WRAP_H
#define OPENMCX_HOSTAP_AES_WRAP_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TS 35.206 clause 4.1, the kernel function E[x]K of MILENAGE: one AES-128 block (16 bytes) encrypted with a 128-bit
 * key; 0 on success, -1 on failure. */
int aes_128_encrypt_block(const u8 *key, const u8 *in, u8 *out);

#ifdef __cplusplus
}
#endif

#endif
