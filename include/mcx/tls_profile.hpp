//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The 3GPP TLS profile of every TLS client and server here (HTTP, SIP, MSRP): TS 33.210 clause 6.2, which TS 33.180
// clause 6.1 refers to through TS 33.310 annex E. TLS 1.2 and TLS 1.3 (clause 6.2.1); for TLS 1.3 the cipher suites of
// the TLS library (RFC 8446 section 9.1, clause 6.2.2); for TLS 1.2 only ECDHE with AEAD (clause 6.2.3); no finite
// field Diffie-Hellman groups (clauses 6.2.1 and 6.2.2). The library's signature algorithms carry no MD5 or SHA-1 at
// its security level 2, its other defaults (SNI, RFC 5746, extended master secret, no compression) follow clause
// 6.2.1.
//
// Specifications: TS 33.210 V19.3.0, TS 33.180 V19.5.0, TS 33.310 V19.5.0 (Rel-19); RFC 5246, RFC 8446.

#pragma once

namespace mcx::tls_profile {

// TS 33.210 clause 6.2.3: the two mandatory suites first, then the recommended AES-256 ones and ChaCha20-Poly1305
// ("Only cipher suites with AEAD (e.g. GCM) and PFS (i.e., ECDHE) shall be supported"). OpenSSL cipher names.
inline constexpr const char *tls12_ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                                             "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                                             "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";

// TS 33.210 clauses 6.2.1 to 6.2.3: P-256 (shall), P-384 (should), x25519; no ffdhe group, no curve below 256 bits.
inline constexpr const char *groups = "X25519:P-256:P-384:P-521";

} // namespace mcx::tls_profile
