//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// ECCSI, the Elliptic Curve-Based Certificateless Signatures for Identity-Based Encryption of RFC 6507, over NIST P-256
// with SHA-256 (the ECCSI of TS 33.180 clause 5.3 and annex E): KMS key creation, (SSK, PVT) issue and validation,
// signing and verification.
//
// Specifications: RFC 6507, TS 33.180 V19.4.0 (Rel-19).
#include "ibe.hpp"

#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <algorithm>

namespace mcx::ibe {
namespace {

// RFC 6507 section 4.1: Hash is SHA-256, N = 32 octets of output.
constexpr std::size_t hash_bytes = 32;

// The P-256 curve with its generator G and order q (RFC 6507 appendix A).
struct Curve {
  Group group{EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)};
  Context ctx = context();
  Bytes generator;

  Curve() {
    require(group != nullptr, "ECCSI: P-256 curve");
    generator = encode_point(group.get(), EC_GROUP_get0_generator(group.get()), ctx.get());
  }

  const BIGNUM *order() const { return EC_GROUP_get0_order(group.get()); }
};

//------------------------------------------------------------------------------
// Helper: SHA-256 of the concatenation of the given octet strings.
std::array<std::uint8_t, hash_bytes> hash(std::initializer_list<ByteView> parts) {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  require(digest != nullptr && EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) == 1, "ECCSI: hash");
  for (const auto part : parts) require(EVP_DigestUpdate(digest.get(), part.data(), part.size()) == 1, "ECCSI: hash");
  std::array<std::uint8_t, hash_bytes> out{};
  unsigned length = 0;
  require(EVP_DigestFinal_ex(digest.get(), out.data(), &length) == 1 && length == out.size(), "ECCSI: hash");
  return out;
}

//------------------------------------------------------------------------------
// RFC 6507 sections 5.1.1 step 3, 5.1.2 step 2 and 5.2.2 step 2: HS = hash( G || KPAK || ID || PVT ).
std::array<std::uint8_t, hash_bytes> identity_hash(const Curve &curve, ByteView kpak, ByteView identifier,
                                                   ByteView pvt) {
  return hash({curve.generator, kpak, identifier, pvt});
}

//------------------------------------------------------------------------------
// Helper: [scalar]G.
Point base_multiple(const Curve &curve, const BIGNUM *scalar) {
  auto result = point(curve.group.get());
  require(EC_POINT_mul(curve.group.get(), result.get(), scalar, nullptr, nullptr, curve.ctx.get()) == 1,
          "ECCSI: scalar multiplication");
  return result;
}

//------------------------------------------------------------------------------
// Helper: the PVT of a signing pair SSK || PVT_x || PVT_y in its canonical form 0x04 || PVT_x || PVT_y.
Bytes pvt_of_pair(ByteView pair) {
  Bytes pvt{POINT_CONVERSION_UNCOMPRESSED};
  pvt.insert(pvt.end(), pair.begin() + eccsi_scalar_bytes, pair.end());
  return pvt;
}

//------------------------------------------------------------------------------
// RFC 6507 section 4.2: KPAK = [KSAK]G, and the KMS secret KSAK || KPAK_x || KPAK_y.
AuthorityKeys authority_from(const Curve &curve, const BIGNUM *ksak) {
  const auto kpak = base_multiple(curve, ksak);
  AuthorityKeys keys;
  keys.public_key = encode_point(curve.group.get(), kpak.get(), curve.ctx.get());
  keys.secret = to_bytes(ksak, eccsi_scalar_bytes);
  keys.secret.insert(keys.secret.end(), keys.public_key.begin() + 1, keys.public_key.end());
  return keys;
}

//------------------------------------------------------------------------------
// RFC 6507 section 5.1.1 steps 2 to 6: PVT = [v]G, HS, SSK = ( KSAK + HS * v ) modulo q; empty when SSK or HS is zero
// modulo q (step 5: the caller restarts with a fresh v).
Bytes issue_with(const Curve &curve, ByteView secret, ByteView identifier, const BIGNUM *ephemeral) {
  require(secret.size() == eccsi_secret_bytes, "ECCSI: invalid KMS secret length");
  const auto ksak = from_bytes(secret.first(eccsi_scalar_bytes));
  BN_set_flags(ksak.get(), BN_FLG_CONSTTIME);
  Bytes kpak{POINT_CONVERSION_UNCOMPRESSED};
  kpak.insert(kpak.end(), secret.begin() + eccsi_scalar_bytes, secret.end());

  const auto pvt = encode_point(curve.group.get(), base_multiple(curve, ephemeral).get(), curve.ctx.get());
  const auto hs = identity_hash(curve, kpak, identifier, pvt);
  const auto hs_value = from_bytes(hs);
  auto ssk = secret_bignum();
  require(BN_mod_mul(ssk.get(), hs_value.get(), ephemeral, curve.order(), curve.ctx.get()) == 1 &&
              BN_mod_add(ssk.get(), ssk.get(), ksak.get(), curve.order(), curve.ctx.get()) == 1,
          "ECCSI: SSK");
  auto hs_reduced = bignum();
  require(BN_nnmod(hs_reduced.get(), hs_value.get(), curve.order(), curve.ctx.get()) == 1, "ECCSI: HS modulo q");
  if (BN_is_zero(ssk.get()) == 1 || BN_is_zero(hs_reduced.get()) == 1) return {};

  auto pair = to_bytes(ssk.get(), eccsi_scalar_bytes);
  pair.insert(pair.end(), pvt.begin() + 1, pvt.end());
  return pair;
}

//------------------------------------------------------------------------------
// RFC 6507 section 5.2.1 steps 2 to 7 with the ephemeral j; empty when HE + r * SSK is zero modulo q (step 4: the
// caller restarts with a fresh j).
Bytes sign_with(const Curve &curve, ByteView kpak, ByteView identifier, ByteView pair, ByteView message,
                const BIGNUM *ephemeral) {
  require(pair.size() == eccsi_pair_bytes, "ECCSI: invalid signing pair length");
  const auto pvt = pvt_of_pair(pair);
  const auto ssk = from_bytes(pair.first(eccsi_scalar_bytes));
  BN_set_flags(ssk.get(), BN_FLG_CONSTTIME);

  // Step 2: J = [j]G, r = J_x.
  auto j_x = bignum();
  affine(curve.group.get(), base_multiple(curve, ephemeral).get(), j_x.get(), nullptr, curve.ctx.get());
  const auto r_bytes = to_bytes(j_x.get(), eccsi_scalar_bytes);

  // Step 3: HE = hash( HS || r || M ).
  const auto hs = identity_hash(curve, kpak, identifier, pvt);
  const auto he = from_bytes(hash({hs, r_bytes, message}));

  // Steps 4 and 5: s' = ( ( HE + r * SSK )^-1 * j ) modulo q.
  auto sum = secret_bignum();
  require(BN_mod_mul(sum.get(), j_x.get(), ssk.get(), curve.order(), curve.ctx.get()) == 1 &&
              BN_mod_add(sum.get(), sum.get(), he.get(), curve.order(), curve.ctx.get()) == 1,
          "ECCSI: HE + r * SSK");
  if (BN_is_zero(sum.get()) == 1) return {};
  const auto inverse = inverse_mod_prime(sum.get(), curve.order(), curve.ctx.get());
  auto s_value = secret_bignum();
  require(BN_mod_mul(s_value.get(), inverse.get(), ephemeral, curve.order(), curve.ctx.get()) == 1, "ECCSI: s");

  // Step 6: q is below 2^256 for P-256, so s' always fits in N octets and s = s'. Step 7: r || s || PVT.
  auto signature = r_bytes;
  const auto s_bytes = to_bytes(s_value.get(), eccsi_scalar_bytes);
  signature.insert(signature.end(), s_bytes.begin(), s_bytes.end());
  signature.insert(signature.end(), pvt.begin(), pvt.end());
  return signature;
}

} // namespace

//------------------------------------------------------------------------------
// RFC 6507 section 4.2: the KSAK is "a random secret non-zero integer modulo q".
AuthorityKeys eccsi_create_authority() {
  const Curve curve;
  const auto ksak = random_below(curve.order(), 1);
  return authority_from(curve, ksak.get());
}

//------------------------------------------------------------------------------
// RFC 6507 section 5.1.1: v is "a random (ephemeral) non-zero element of F_q", chosen afresh when step 5 fails.
Bytes eccsi_issue(ByteView secret, ByteView identifier) {
  const Curve curve;
  for (;;) {
    const auto ephemeral = random_below(curve.order(), 1);
    auto pair = issue_with(curve, secret, identifier, ephemeral.get());
    if (!pair.empty()) return pair;
  }
}

//------------------------------------------------------------------------------
// RFC 6507 section 5.1.2: the PVT lies on E, and KPAK = [SSK]G - [HS]PVT, checked as [SSK]G = KPAK + [HS]PVT.
bool eccsi_validate(ByteView kpak, ByteView identifier, ByteView pair) {
  if (pair.size() != eccsi_pair_bytes) return false;
  try {
    const Curve curve;
    const auto kpak_point = decode_point(curve.group.get(), kpak, curve.ctx.get());
    const auto pvt = pvt_of_pair(pair);
    const auto pvt_point = decode_point(curve.group.get(), pvt, curve.ctx.get());
    const auto hs = from_bytes(identity_hash(curve, kpak, identifier, pvt));
    const auto ssk = from_bytes(pair.first(eccsi_scalar_bytes));
    BN_set_flags(ssk.get(), BN_FLG_CONSTTIME);

    const auto expected = base_multiple(curve, ssk.get());
    auto computed = point(curve.group.get());
    require(EC_POINT_mul(curve.group.get(), computed.get(), nullptr, pvt_point.get(), hs.get(), curve.ctx.get()) == 1 &&
                EC_POINT_add(curve.group.get(), computed.get(), computed.get(), kpak_point.get(), curve.ctx.get()) == 1,
            "ECCSI: KPAK + [HS]PVT");
    return EC_POINT_cmp(curve.group.get(), expected.get(), computed.get(), curve.ctx.get()) == 0;
  } catch (const std::exception &) {
    // A malformed point or an OpenSSL failure: the pair is not valid.
    return false;
  }
}

//------------------------------------------------------------------------------
// RFC 6507 section 5.2.1: j is "a random (ephemeral) non-zero value in F_q", chosen afresh when step 4 fails.
Bytes eccsi_sign(ByteView kpak, ByteView identifier, ByteView pair, ByteView message) {
  const Curve curve;
  for (;;) {
    const auto ephemeral = random_below(curve.order(), 1);
    auto signature = sign_with(curve, kpak, identifier, pair, message, ephemeral.get());
    if (!signature.empty()) return signature;
  }
}

//------------------------------------------------------------------------------
// RFC 6507 section 5.2.2: PVT on E (step 1), HS and HE (steps 2 and 3), Y = [HS]PVT + KPAK (step 4),
// J = [s]( [HE]G + [r]Y ) (step 5), and J_x = r modulo p with J_x non-zero (step 6).
bool eccsi_verify(ByteView kpak, ByteView identifier, ByteView message, ByteView signature) {
  if (signature.size() != eccsi_signature_bytes) return false;
  try {
    const Curve curve;
    const auto r_bytes = signature.first(eccsi_scalar_bytes);
    const auto s_value = from_bytes(signature.subspan(eccsi_scalar_bytes, eccsi_scalar_bytes));
    const auto pvt = signature.subspan(2 * eccsi_scalar_bytes);
    const auto kpak_point = decode_point(curve.group.get(), kpak, curve.ctx.get());
    const auto pvt_point = decode_point(curve.group.get(), pvt, curve.ctx.get());
    if (BN_is_zero(s_value.get()) == 1) return false;

    const auto hs = identity_hash(curve, kpak, identifier, pvt);
    const auto hs_value = from_bytes(hs);
    const auto he = from_bytes(hash({hs, r_bytes, message}));
    const auto r_value = from_bytes(r_bytes);
    auto y_point = point(curve.group.get());
    require(EC_POINT_mul(curve.group.get(), y_point.get(), nullptr, pvt_point.get(), hs_value.get(), curve.ctx.get()) ==
                    1 &&
                EC_POINT_add(curve.group.get(), y_point.get(), y_point.get(), kpak_point.get(), curve.ctx.get()) == 1,
            "ECCSI: Y");

    auto j_point = point(curve.group.get());
    require(
        EC_POINT_mul(curve.group.get(), j_point.get(), he.get(), y_point.get(), r_value.get(), curve.ctx.get()) == 1 &&
            EC_POINT_mul(curve.group.get(), j_point.get(), nullptr, j_point.get(), s_value.get(), curve.ctx.get()) == 1,
        "ECCSI: J");
    if (EC_POINT_is_at_infinity(curve.group.get(), j_point.get()) == 1) return false;
    auto j_x = bignum();
    auto prime = bignum();
    require(EC_GROUP_get_curve(curve.group.get(), prime.get(), nullptr, nullptr, curve.ctx.get()) == 1, "ECCSI: p");
    affine(curve.group.get(), j_point.get(), j_x.get(), nullptr, curve.ctx.get());
    auto r_reduced = bignum();
    require(BN_nnmod(r_reduced.get(), r_value.get(), prime.get(), curve.ctx.get()) == 1, "ECCSI: r modulo p");
    return BN_is_zero(j_x.get()) == 0 && BN_cmp(j_x.get(), r_reduced.get()) == 0;
  } catch (const std::exception &) {
    // A malformed point or an OpenSSL failure: the signature is not valid.
    return false;
  }
}

//------------------------------------------------------------------------------
// RFC 6507 appendix A: the KMS keys of a given KSAK.
AuthorityKeys known_answer::eccsi_authority(const BIGNUM *ksak) {
  const Curve curve;
  return authority_from(curve, ksak);
}

//------------------------------------------------------------------------------
// RFC 6507 appendix A: the (SSK, PVT) pair of a given v.
Bytes known_answer::eccsi_issue(ByteView secret, ByteView identifier, const BIGNUM *ephemeral) {
  const Curve curve;
  return issue_with(curve, secret, identifier, ephemeral);
}

//------------------------------------------------------------------------------
// RFC 6507 appendix A: the signature of a given j.
Bytes known_answer::eccsi_sign(ByteView kpak, ByteView identifier, ByteView pair, ByteView message,
                               const BIGNUM *ephemeral) {
  const Curve curve;
  return sign_with(curve, kpak, identifier, pair, message, ephemeral);
}

} // namespace mcx::ibe
