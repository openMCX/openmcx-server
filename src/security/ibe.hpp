//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The identity-based primitives of MIKEY-SAKKE on OpenSSL: ECCSI signatures (RFC 6507) over NIST P-256 with SHA-256
// and SAKKE key encapsulation (RFC 6508) with parameter set 1 of RFC 6509, the two TS 33.180 clause 5 uses. The
// values are octet strings in the canonical forms of RFC 6507 section 3.2 and RFC 6508 section 4; the KMS secrets and
// the signing pair have the layouts below, which are the stored forms of OpenMCX's KMS keys and key sets.
//
// Private to src/security/: mcx/keying.hpp is the interface the rest of OpenMCX uses.
//
// Specifications: RFC 6507, RFC 6508, RFC 6509, TS 33.180 V19.4.0 (Rel-19).
#pragma once

#include "bignum.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace mcx::ibe {

using ByteView = std::span<const std::uint8_t>;

// RFC 6507 section 4.1 with NIST P-256: N = 32 octets for integers and F_p elements, 65 for a point.
constexpr std::size_t eccsi_scalar_bytes = 32;
constexpr std::size_t eccsi_point_bytes = 2 * eccsi_scalar_bytes + 1;
// RFC 6507 section 3.3: Signature = r || s || PVT, 4N + 1 octets.
constexpr std::size_t eccsi_signature_bytes = 2 * eccsi_scalar_bytes + eccsi_point_bytes;
// The KMS secret KSAK || KPAK_x || KPAK_y and the signing pair SSK || PVT_x || PVT_y: 3N octets each.
constexpr std::size_t eccsi_secret_bytes = 3 * eccsi_scalar_bytes;
constexpr std::size_t eccsi_pair_bytes = 3 * eccsi_scalar_bytes;

// RFC 6509 appendix A parameter set 1: L = 128 octets for F_p elements, 2L + 1 for a point; n = 128 bits.
constexpr std::size_t sakke_field_bytes = 128;
constexpr std::size_t sakke_point_bytes = 2 * sakke_field_bytes + 1;
constexpr std::size_t sakke_ssv_bytes = 16;
// RFC 6508 section 4: Encapsulated Data = R || H, 2L + n/8 + 1 octets.
constexpr std::size_t sakke_encapsulated_bytes = sakke_point_bytes + sakke_ssv_bytes;
// The KMS secret z_T || Z_T_x || Z_T_y: 3L octets.
constexpr std::size_t sakke_secret_bytes = 3 * sakke_field_bytes;

// A KMS key pair: the stored secret and the public key of its certificate (RFC 6507 KPAK, RFC 6508 Z_T).
struct AuthorityKeys {
  Bytes secret;
  Bytes public_key;
};

// RFC 6507 section 4.2: a new KMS secret KSAK and its KPAK = [KSAK]G.
AuthorityKeys eccsi_create_authority();
// RFC 6507 section 5.1.1: the (SSK, PVT) pair of an identifier.
Bytes eccsi_issue(ByteView secret, ByteView identifier);
// RFC 6507 section 5.1.2: whether a received (SSK, PVT) pair is valid for the identifier under the KPAK.
bool eccsi_validate(ByteView kpak, ByteView identifier, ByteView pair);
// RFC 6507 section 5.2.1: the signature of a message.
Bytes eccsi_sign(ByteView kpak, ByteView identifier, ByteView pair, ByteView message);
// RFC 6507 section 5.2.2: whether a signature of a message is valid for the identifier under the KPAK.
bool eccsi_verify(ByteView kpak, ByteView identifier, ByteView message, ByteView signature);

// RFC 6508 section 6.1: a new KMS Master Secret z_T and its KMS Public Key Z_T = [z_T]P.
AuthorityKeys sakke_create_authority();
// RFC 6508 section 6.1.1: the Receiver Secret Key of an identifier.
Bytes sakke_issue(ByteView secret, ByteView identifier);
// RFC 6508 section 6.1.2: whether a Receiver Secret Key is valid for the identifier under Z_T.
bool sakke_validate(ByteView public_key, ByteView identifier, ByteView receiver_key);
// RFC 6508 section 6.2.1: the Encapsulated Data of an SSV for the identifier under Z_T.
Bytes sakke_encapsulate(ByteView public_key, ByteView identifier, std::span<const std::uint8_t, sakke_ssv_bytes> ssv);
// RFC 6508 section 6.2.2: the SSV of Encapsulated Data; throws when the check of step 5 fails.
std::array<std::uint8_t, sakke_ssv_bytes> sakke_decapsulate(ByteView public_key, ByteView identifier,
                                                            ByteView receiver_key, ByteView encapsulated);

// The deterministic steps under the random choices, for the known-answer tests of RFC 6507 and RFC 6508 appendix A.
// They take the ephemeral and secret values from the caller, which a program must never do, so they exist only in the
// test build (MCX_IBE_KNOWN_ANSWER, set for tests/test_ibe.cpp alone): the library of the programs has none.
#ifdef MCX_IBE_KNOWN_ANSWER
namespace known_answer {
// RFC 6507 section 4.2 with the given KSAK.
AuthorityKeys eccsi_authority(const BIGNUM *ksak);
// RFC 6507 section 5.1.1 with the given ephemeral v.
Bytes eccsi_issue(ByteView secret, ByteView identifier, const BIGNUM *ephemeral);
// RFC 6507 section 5.2.1 with the given ephemeral j.
Bytes eccsi_sign(ByteView kpak, ByteView identifier, ByteView pair, ByteView message, const BIGNUM *ephemeral);
// RFC 6508 section 6.1 with the given z_T.
AuthorityKeys sakke_authority(const BIGNUM *master_secret);
// RFC 6508 section 5.1: HashToIntegerRange(s, n, SHA-256).
Bignum hash_to_integer_range(ByteView data, const BIGNUM *limit);
// RFC 6508 section 3.2: the pairing <R, Q>, as its representative in F_p (L octets).
Bytes pairing(ByteView first, ByteView second);
} // namespace known_answer
#endif

} // namespace mcx::ibe
