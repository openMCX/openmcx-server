//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Owned OpenSSL big numbers and elliptic curve objects for the identity-based cryptography of MIKEY-SAKKE (ECCSI and
// SAKKE): RAII handles, the octet string conversions and the point encoding of RFC 6507 section 3.2 and RFC 6508
// section 4.
//
// Private to src/security/.
//
// Specifications: RFC 6507, RFC 6508, RFC 5480.
#pragma once

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>

#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

namespace mcx::ibe {

using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// Helper: throws the given error when a condition fails.
inline void require(bool is_ok, const char *what) {
  if (!is_ok) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Helper: wipes octets that held a secret or a value derived from one (OPENSSL_cleanse, which the compiler does not
// remove).
inline void wipe(std::span<std::uint8_t> data) { OPENSSL_cleanse(data.data(), data.size()); }

// Octets of a secret or of a value derived from one, wiped when destroyed. The capacity is reserved up front where it
// is known, so that growing does not leave an unwiped copy behind.
class SecretBytes {
public:
  SecretBytes() = default;

  explicit SecretBytes(Bytes value) : data_(std::move(value)) {}

  SecretBytes(const SecretBytes &) = delete;
  SecretBytes &operator=(const SecretBytes &) = delete;

  ~SecretBytes() { wipe(data_); }

  Bytes &data() { return data_; }

  const Bytes &data() const { return data_; }

private:
  Bytes data_;
};

struct BignumFree {
  void operator()(BIGNUM *value) const { BN_clear_free(value); }
};

struct ContextFree {
  void operator()(BN_CTX *value) const { BN_CTX_free(value); }
};

struct MontgomeryFree {
  void operator()(BN_MONT_CTX *value) const { BN_MONT_CTX_free(value); }
};

struct GroupFree {
  void operator()(EC_GROUP *value) const { EC_GROUP_free(value); }
};

struct PointFree {
  void operator()(EC_POINT *value) const { EC_POINT_clear_free(value); }
};

// Every BIGNUM is wiped when freed (BN_clear_free): secrets and public values alike.
using Bignum = std::unique_ptr<BIGNUM, BignumFree>;
using Context = std::unique_ptr<BN_CTX, ContextFree>;
using Montgomery = std::unique_ptr<BN_MONT_CTX, MontgomeryFree>;
using Group = std::unique_ptr<EC_GROUP, GroupFree>;
using Point = std::unique_ptr<EC_POINT, PointFree>;

//------------------------------------------------------------------------------
// Helper: a new zero big number.
inline Bignum bignum() {
  Bignum value(BN_new());
  require(value != nullptr, "allocate big number");
  return value;
}

//------------------------------------------------------------------------------
// Helper: a new big number for a secret: OpenSSL takes its constant-time paths for it (BN_FLG_CONSTTIME).
inline Bignum secret_bignum() {
  auto value = bignum();
  BN_set_flags(value.get(), BN_FLG_CONSTTIME);
  return value;
}

//------------------------------------------------------------------------------
// Helper: a new big number context.
inline Context context() {
  Context value(BN_CTX_secure_new());
  require(value != nullptr, "allocate big number context");
  return value;
}

//------------------------------------------------------------------------------
// Helper: a copy of a big number.
inline Bignum copy(const BIGNUM *value) {
  Bignum result(BN_dup(value));
  require(result != nullptr, "copy big number");
  return result;
}

//------------------------------------------------------------------------------
// RFC 6507 section 3.2, RFC 6508 section 4: an integer from its big-endian octet string.
inline Bignum from_bytes(std::span<const std::uint8_t> data) {
  auto value = bignum();
  require(BN_bin2bn(data.data(), static_cast<int>(data.size()), value.get()) != nullptr, "decode integer");
  return value;
}

//------------------------------------------------------------------------------
// RFC 6507 section 3.2, RFC 6508 section 4: an integer as a big-endian octet string of the given length, zero padded
// on the left.
inline void to_bytes(const BIGNUM *value, std::span<std::uint8_t> out) {
  require(BN_bn2binpad(value, out.data(), static_cast<int>(out.size())) == static_cast<int>(out.size()),
          "encode integer");
}

//------------------------------------------------------------------------------
// RFC 6507 section 3.2, RFC 6508 section 4: an integer as a big-endian octet string of the given length.
inline Bytes to_bytes(const BIGNUM *value, std::size_t length) {
  Bytes out(length);
  to_bytes(value, out);
  return out;
}

//------------------------------------------------------------------------------
// Helper: a new point of a curve (the point at infinity).
inline Point point(const EC_GROUP *group) {
  Point value(EC_POINT_new(group));
  require(value != nullptr, "allocate EC point");
  return value;
}

//------------------------------------------------------------------------------
// RFC 6507 section 3.2, RFC 6508 section 4 (RFC 5480 section 2.2): a point from its uncompressed form
// 0x04 || x || y, refused unless it is a finite point on the curve (RFC 6507 section 4.2 and 5.2.2 step 1).
inline Point decode_point(const EC_GROUP *group, std::span<const std::uint8_t> data, BN_CTX *ctx) {
  const auto field_length = static_cast<std::size_t>((EC_GROUP_get_degree(group) + 7) / 8);
  require(data.size() == 2 * field_length + 1 && data[0] == POINT_CONVERSION_UNCOMPRESSED, "invalid point encoding");
  auto result = point(group);
  // EC_POINT_oct2point sets the affine coordinates, which OpenSSL refuses for a point that is not on the curve.
  require(EC_POINT_oct2point(group, result.get(), data.data(), data.size(), ctx) == 1, "point not on the curve");
  require(EC_POINT_is_at_infinity(group, result.get()) == 0, "point at infinity");
  return result;
}

//------------------------------------------------------------------------------
// RFC 6507 section 3.2, RFC 6508 section 4: a finite point in its uncompressed form 0x04 || x || y.
inline Bytes encode_point(const EC_GROUP *group, const EC_POINT *value, BN_CTX *ctx) {
  require(EC_POINT_is_at_infinity(group, value) == 0, "point at infinity");
  const auto field_length = static_cast<std::size_t>((EC_GROUP_get_degree(group) + 7) / 8);
  Bytes out(2 * field_length + 1);
  require(EC_POINT_point2oct(group, value, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), ctx) == out.size(),
          "encode point");
  return out;
}

//------------------------------------------------------------------------------
// Helper: the affine coordinates of a finite point.
inline void affine(const EC_GROUP *group, const EC_POINT *value, BIGNUM *x_coordinate, BIGNUM *y_coordinate,
                   BN_CTX *ctx) {
  require(EC_POINT_is_at_infinity(group, value) == 0, "point at infinity");
  require(EC_POINT_get_affine_coordinates(group, value, x_coordinate, y_coordinate, ctx) == 1, "affine coordinates");
}

//------------------------------------------------------------------------------
// Helper: a uniformly random secret integer in the range [minimum, limit - 1].
inline Bignum random_below(const BIGNUM *limit, unsigned minimum) {
  auto value = secret_bignum();
  do {
    require(BN_priv_rand_range(value.get(), limit) == 1, "random integer");
  } while (BN_cmp(value.get(), BN_value_one()) < 0 || (minimum > 1 && BN_is_one(value.get())));
  return value;
}

//------------------------------------------------------------------------------
// Helper: the inverse of a secret non-zero value modulo a prime by Fermat's little theorem, value^(prime - 2), with
// OpenSSL's constant-time modular exponentiation (no secret-dependent branches, unlike BN_mod_inverse).
inline Bignum inverse_mod_prime(const BIGNUM *value, const BIGNUM *prime, BN_CTX *ctx) {
  require(BN_is_zero(value) == 0, "inverse of zero");
  auto exponent = copy(prime);
  require(BN_sub_word(exponent.get(), 2) == 1, "inverse exponent");
  auto result = secret_bignum();
  auto base = secret_bignum();
  require(BN_nnmod(base.get(), value, prime, ctx) == 1, "reduce before inverse");
  require(BN_mod_exp_mont_consttime(result.get(), base.get(), exponent.get(), prime, ctx, nullptr) == 1,
          "modular inverse");
  return result;
}

} // namespace mcx::ibe
