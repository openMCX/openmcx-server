/*
 * OpenMCX Licence Information : AGPL-3.0-or-later
 */

/* OpenMCX's stand-in for hostap's common.h, for the vendored dependencies/hostap/milenage.c: its byte type, the os_mem*
 * functions and the debug print functions, which print nothing (the keys and results never reach a log from here).
 * OpenMCX build glue, no 3GPP behaviour. */
#ifndef OPENMCX_HOSTAP_COMMON_H
#define OPENMCX_HOSTAP_COMMON_H

#include "includes.h"

typedef uint8_t u8;

#define os_memcpy(d, s, n) memcpy((d), (s), (n))
#define os_memcmp(a, b, n) memcmp((a), (b), (n))

/* hostap's os_memcmp_const: a comparison whose time does not depend on where the inputs differ; zero when equal. */
static inline int os_memcmp_const(const void *a, const void *b, size_t len) {
  const u8 *left = (const u8 *)a, *right = (const u8 *)b;
  u8 difference = 0;
  for (size_t i = 0; i < len; i++) difference |= (u8)(left[i] ^ right[i]);
  return difference;
}

enum { MSG_DEBUG = 2 };

#define wpa_printf(level, ...) ((void)(level))
#define wpa_hexdump(level, title, buf, len) ((void)(level), (void)(title), (void)(buf), (void)(len))
#define wpa_hexdump_key(level, title, buf, len) ((void)(level), (void)(title), (void)(buf), (void)(len))

#endif
