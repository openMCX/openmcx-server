//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SAKKE, the Sakai-Kasahara Key Encryption of RFC 6508, with parameter set 1 of RFC 6509 (the SAKKE of TS 33.180
// clause 5.3 and annex E): KMS key creation, Receiver Secret Key issue and validation, and the encapsulation and
// decapsulation of an SSV, on the Tate-Lichtenbaum pairing of RFC 6508 section 3.2.
//
// The pairing follows the routine of RFC 6508 section 3.2 with the curve point C in Jacobian coordinates and every
// line value scaled by a non-zero element of F_p, which the pairing's values in PF_p = (F_p^2)* / (F_p)* do not see
// (RFC 6508 section 2.1): no inversion is needed in the loop. F_p arithmetic is in Montgomery form.
//
// Specifications: RFC 6508, RFC 6509, TS 33.180 V19.4.0 (Rel-19).
#include "ibe.hpp"

#include <openssl/evp.h>

#include <algorithm>

namespace mcx::ibe {
namespace {

// RFC 6509 appendix A, parameter set 1: p, q, P = (Px, Py) and g = <P, P>, as hexadecimal.
constexpr const char *prime_hex =
    "997ABB1F0A563FDA65C61198DAD0657A416C0CE19CB48261BE9AE358B3E01A2EF40AAB27E2FC0F1B228730D531A59CB0"
    "E791B39FF7C88A19356D27F4A666A6D0E26C6487326B4CD4512AC5CD65681CE1B6AFF4A831852A82A7CF3C521C3C09AA"
    "9F94D6AF56971F1FFCE3E82389857DB080C5DF10AC7ACE87666D807AFEA85FEB";
constexpr const char *order_hex =
    "265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068BBD02AAC9F8BF03C6C8A1CC354C69672C"
    "39E46CE7FDF222864D5B49FD2999A9B4389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026A"
    "A7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB";
constexpr const char *base_x_hex =
    "53FC09EE332C29AD0A7990053ED9B52A2B1A2FD60AEC69C698B2F204B6FF7CBFB5EDB6C0F6CE2308AB10DB9030B09E10"
    "43D5F22CDB9DFA55718BD9E7406CE8909760AF765DD5BCCB337C86548B72F2E1A702C3397A60DE74A7C1514DBA66910D"
    "D5CFB4CC80728D87EE9163A5B63F73EC80EC46C4967E0979880DC8ABEAE63895";
constexpr const char *base_y_hex =
    "0A8249063F6009F1F9F1F0533634A135D3E82016029906963D778D821E141178F5EA69F4654EC2B9E7F7F5E5F0DE55F6"
    "6B598CCF9A140B2E416CFF0CA9E032B970DAE117AD547C6CCAD696B5B7652FE0AC6F1E80164AA989492D979FC5A4D5F2"
    "13515AD7E9CB99A980BDAD5AD5BB4636ADB9B5706A67DCDE75573FD71BEF16D7";
constexpr const char *pairing_base_hex =
    "66FC2A432B6EA392148F15867D623068C6A87BD1FB94C41E27FABE658E015A87371E94744C96FEDA449AE9563F8BC446"
    "CBFDA85D5D00EF577072DA8F541721BEEE0FAED1828EAB90B99DFB0138C7843355DF0460B4A9FD74B4F1A32BCAFA1FFA"
    "D682C033A7942BCCE3720F20B9B7B0403C8CAE87B7A0042ACDE0FAB36461EA46";

// The coefficients of the Jacobian doubling formulas on y^2 = x^3 - 3x (double_step).
constexpr unsigned doubling_slope_factor = 3, doubling_x_factor = 8, doubling_beta_factor = 4, doubling_y_factor = 8;
constexpr int bits_per_octet = 8;

// RFC 6509 appendix A: Hash is SHA-256 (hashlen 256 bits, 32 octets).
constexpr std::size_t hash_bytes = 32;
constexpr int hash_bits = 256;

//------------------------------------------------------------------------------
// Helper: a big number from its hexadecimal text.
Bignum from_hex(const char *text) {
  BIGNUM *value = nullptr;
  require(BN_hex2bn(&value, text) > 0, "SAKKE: parameter");
  return Bignum(value);
}

// RFC 6508 section 2.1 and RFC 6509 appendix A: the curve E: y^2 = x^3 - 3x over F_p with the generator P of its
// subgroup of order q, the cofactor c = (p + 1) / q, g, and the Montgomery form of F_p.
struct Parameters {
  Context ctx = context();
  Bignum prime = from_hex(prime_hex);
  Bignum order = from_hex(order_hex);
  Bignum pairing_base = from_hex(pairing_base_hex);
  Bignum cofactor = bignum();
  Group group;
  Montgomery montgomery{BN_MONT_CTX_new()};

  Parameters() {
    auto curve_a = copy(prime.get());
    require(BN_sub_word(curve_a.get(), 3) == 1, "SAKKE: curve coefficient");
    const auto curve_b = bignum();
    group.reset(EC_GROUP_new_curve_GFp(prime.get(), curve_a.get(), curve_b.get(), ctx.get()));
    require(group != nullptr, "SAKKE: curve");

    auto cofactor_sum = copy(prime.get());
    require(BN_add_word(cofactor_sum.get(), 1) == 1 &&
                BN_div(cofactor.get(), nullptr, cofactor_sum.get(), order.get(), ctx.get()) == 1,
            "SAKKE: cofactor");
    auto base = point(group.get());
    const auto base_x = from_hex(base_x_hex);
    const auto base_y = from_hex(base_y_hex);
    require(EC_POINT_set_affine_coordinates(group.get(), base.get(), base_x.get(), base_y.get(), ctx.get()) == 1 &&
                EC_GROUP_set_generator(group.get(), base.get(), order.get(), cofactor.get()) == 1,
            "SAKKE: generator");
    require(montgomery != nullptr && BN_MONT_CTX_set(montgomery.get(), prime.get(), ctx.get()) == 1,
            "SAKKE: Montgomery form");
  }
};

// An element real + i * imaginary of F_p^2 = F_p[i], i^2 + 1 = 0 (RFC 6508 section 2.1), both parts in Montgomery
// form.
struct Extension {
  Bignum real = secret_bignum();
  Bignum imaginary = secret_bignum();
};

// F_p arithmetic in Montgomery form, and F_p^2 arithmetic on it.
class Field {
public:
  explicit Field(const Parameters &parameters) : parameters_(parameters) {}

  //------------------------------------------------------------------------------
  // Helper: an element of F_p (reduced modulo p) into Montgomery form.
  Bignum enter(const BIGNUM *value) const {
    auto reduced = secret_bignum();
    auto result = secret_bignum();
    require(BN_nnmod(reduced.get(), value, prime(), ctx()) == 1 &&
                BN_to_montgomery(result.get(), reduced.get(), parameters_.montgomery.get(), ctx()) == 1,
            "SAKKE: Montgomery form");
    return result;
  }

  //------------------------------------------------------------------------------
  // Helper: an element of F_p out of Montgomery form.
  Bignum leave(const BIGNUM *value) const {
    auto result = secret_bignum();
    require(BN_from_montgomery(result.get(), value, parameters_.montgomery.get(), ctx()) == 1,
            "SAKKE: Montgomery form");
    return result;
  }

  Bignum one() const { return enter(BN_value_one()); }

  //------------------------------------------------------------------------------
  // Helper: left * right in F_p.
  Bignum mul(const BIGNUM *left, const BIGNUM *right) const {
    auto result = secret_bignum();
    require(BN_mod_mul_montgomery(result.get(), left, right, parameters_.montgomery.get(), ctx()) == 1,
            "SAKKE: F_p multiplication");
    return result;
  }

  //------------------------------------------------------------------------------
  // Helper: left + right in F_p.
  Bignum add(const BIGNUM *left, const BIGNUM *right) const {
    auto result = secret_bignum();
    require(BN_mod_add_quick(result.get(), left, right, prime()) == 1, "SAKKE: F_p addition");
    return result;
  }

  //------------------------------------------------------------------------------
  // Helper: left - right in F_p.
  Bignum sub(const BIGNUM *left, const BIGNUM *right) const {
    auto result = secret_bignum();
    require(BN_mod_sub_quick(result.get(), left, right, prime()) == 1, "SAKKE: F_p subtraction");
    return result;
  }

  //------------------------------------------------------------------------------
  // Helper: value + value + ... (count times) in F_p, for the small constants of the point formulas.
  Bignum times(const BIGNUM *value, unsigned count) const {
    auto result = copy(value);
    for (unsigned added = 1; added < count; ++added) result = add(result.get(), value);
    return result;
  }

  //------------------------------------------------------------------------------
  // RFC 6508 section 2.1: (a + ib)(c + id) = (ac - bd) + i(ad + bc), with three F_p multiplications.
  Extension mul(const Extension &left, const Extension &right) const {
    const auto real_product = mul(left.real.get(), right.real.get());
    const auto imaginary_product = mul(left.imaginary.get(), right.imaginary.get());
    const auto cross =
        mul(add(left.real.get(), left.imaginary.get()).get(), add(right.real.get(), right.imaginary.get()).get());
    Extension result;
    result.real = sub(real_product.get(), imaginary_product.get());
    result.imaginary = sub(sub(cross.get(), real_product.get()).get(), imaginary_product.get());
    return result;
  }

  //------------------------------------------------------------------------------
  // RFC 6508 section 2.1: (a + ib)^2 = (a + b)(a - b) + i(2ab).
  Extension square(const Extension &value) const {
    Extension result;
    result.real =
        mul(add(value.real.get(), value.imaginary.get()).get(), sub(value.real.get(), value.imaginary.get()).get());
    const auto product = mul(value.real.get(), value.imaginary.get());
    result.imaginary = add(product.get(), product.get());
    return result;
  }

  //------------------------------------------------------------------------------
  // RFC 6508 section 3.2, "Routine for computing representative in F_p of elements of PF_p": b / a for a + ib, with
  // a constant-time inversion; out of Montgomery form.
  Bignum representative(const Extension &value) const {
    const auto real = leave(value.real.get());
    require(BN_is_zero(real.get()) == 0, "SAKKE: pairing value without a representative");
    const auto inverse = inverse_mod_prime(real.get(), prime(), ctx());
    const auto imaginary = leave(value.imaginary.get());
    auto result = secret_bignum();
    require(BN_mod_mul(result.get(), imaginary.get(), inverse.get(), prime(), ctx()) == 1, "SAKKE: representative");
    return result;
  }

  const BIGNUM *prime() const { return parameters_.prime.get(); }

  BN_CTX *ctx() const { return parameters_.ctx.get(); }

private:
  const Parameters &parameters_;
};

// A point (X, Y, Z) of E(F_p) in Jacobian coordinates, x = X / Z^2 and y = Y / Z^3, in Montgomery form.
struct Jacobian {
  Bignum x_coordinate;
  Bignum y_coordinate;
  Bignum z_coordinate;
};

// An affine point of E(F_p)[q] in Montgomery form.
struct Affine {
  Bignum x_coordinate;
  Bignum y_coordinate;
};

//------------------------------------------------------------------------------
// Helper: the affine coordinates of a point in Montgomery form.
Affine enter_point(const Parameters &parameters, const Field &field, const EC_POINT *value) {
  auto x_coordinate = bignum();
  auto y_coordinate = bignum();
  affine(parameters.group.get(), value, x_coordinate.get(), y_coordinate.get(), parameters.ctx.get());
  return {field.enter(x_coordinate.get()), field.enter(y_coordinate.get())};
}

//------------------------------------------------------------------------------
// RFC 6508 section 3.2, the doubling step: the line through C, C, [-2]C evaluated at [i]Q, accumulated as
// v = v^2 * line, then C = [2]C. With C = (X, Y, Z), delta = Z^2, gamma = Y^2 and alpha = 3(X - delta)(X + delta)
// (3 * (C_x^2 - 1) scaled by Z^4), the line l * (Q_x + C_x) + (i * Q_y - C_y) scaled by 2 * C_y * Z^6 is
// alpha * (X + Q_x * delta) - 2 * gamma + i * (2YZ) * delta * Q_y.
void double_step(const Field &field, Jacobian &current, const Affine &evaluation, Extension &accumulator) {
  const auto delta = field.mul(current.z_coordinate.get(), current.z_coordinate.get());
  const auto gamma = field.mul(current.y_coordinate.get(), current.y_coordinate.get());
  const auto beta = field.mul(current.x_coordinate.get(), gamma.get());
  const auto alpha = field.times(field
                                     .mul(field.sub(current.x_coordinate.get(), delta.get()).get(),
                                          field.add(current.x_coordinate.get(), delta.get()).get())
                                     .get(),
                                 doubling_slope_factor);

  // Z3 = (Y + Z)^2 - gamma - delta = 2YZ.
  const auto sum = field.add(current.y_coordinate.get(), current.z_coordinate.get());
  auto z_next = field.sub(field.sub(field.mul(sum.get(), sum.get()).get(), gamma.get()).get(), delta.get());

  Extension line;
  line.real = field.sub(
      field
          .mul(alpha.get(),
               field.add(current.x_coordinate.get(), field.mul(evaluation.x_coordinate.get(), delta.get()).get()).get())
          .get(),
      field.add(gamma.get(), gamma.get()).get());
  line.imaginary = field.mul(field.mul(z_next.get(), delta.get()).get(), evaluation.y_coordinate.get());
  accumulator = field.mul(field.square(accumulator), line);

  // X3 = alpha^2 - 8 * beta, Y3 = alpha * (4 * beta - X3) - 8 * gamma^2.
  auto x_next = field.sub(field.mul(alpha.get(), alpha.get()).get(), field.times(beta.get(), doubling_x_factor).get());
  auto y_next = field.sub(
      field.mul(alpha.get(), field.sub(field.times(beta.get(), doubling_beta_factor).get(), x_next.get()).get()).get(),
      field.times(field.mul(gamma.get(), gamma.get()).get(), doubling_y_factor).get());
  current = {std::move(x_next), std::move(y_next), std::move(z_next)};
}

//------------------------------------------------------------------------------
// RFC 6508 section 3.2, the addition step: the line through C, R, -C-R evaluated at [i]Q, accumulated as
// v = v * line, then C = C + R. With H = R_x * Z^2 - X and rise = R_y * Z^3 - Y, the new Z is Z * H =
// Z^3 * (R_x - C_x), and the line l * (Q_x + R_x) + (i * Q_y - R_y) (the same line, through R) scaled by it is
// rise * (Q_x + R_x) - R_y * Z3 + i * Q_y * Z3.
void add_step(const Field &field, Jacobian &current, const Affine &base, const Affine &evaluation,
              Extension &accumulator) {
  const auto z_squared = field.mul(current.z_coordinate.get(), current.z_coordinate.get());
  const auto h_value = field.sub(field.mul(base.x_coordinate.get(), z_squared.get()).get(), current.x_coordinate.get());
  const auto rise =
      field.sub(field.mul(field.mul(base.y_coordinate.get(), current.z_coordinate.get()).get(), z_squared.get()).get(),
                current.y_coordinate.get());
  const auto h_squared = field.mul(h_value.get(), h_value.get());
  const auto h_cubed = field.mul(h_value.get(), h_squared.get());
  const auto scaled_x = field.mul(current.x_coordinate.get(), h_squared.get());
  auto z_next = field.mul(current.z_coordinate.get(), h_value.get());

  Extension line;
  line.real =
      field.sub(field.mul(rise.get(), field.add(evaluation.x_coordinate.get(), base.x_coordinate.get()).get()).get(),
                field.mul(base.y_coordinate.get(), z_next.get()).get());
  line.imaginary = field.mul(evaluation.y_coordinate.get(), z_next.get());
  accumulator = field.mul(accumulator, line);

  // X3 = rise^2 - H^3 - 2 * X * H^2, Y3 = rise * (X * H^2 - X3) - Y * H^3.
  auto x_next = field.sub(field.sub(field.mul(rise.get(), rise.get()).get(), h_cubed.get()).get(),
                          field.add(scaled_x.get(), scaled_x.get()).get());
  auto y_next = field.sub(field.mul(rise.get(), field.sub(scaled_x.get(), x_next.get()).get()).get(),
                          field.mul(current.y_coordinate.get(), h_cubed.get()).get());
  current = {std::move(x_next), std::move(y_next), std::move(z_next)};
}

//------------------------------------------------------------------------------
// Helper: value^exponent in F_p^2 for a public exponent (square and multiply).
Extension public_power(const Field &field, const Extension &value, const BIGNUM *exponent) {
  Extension result;
  result.real = field.one();
  result.imaginary = field.enter(bignum().get());
  for (int bit = BN_num_bits(exponent) - 1; bit >= 0; --bit) {
    result = field.square(result);
    if (BN_is_bit_set(exponent, bit) == 1) result = field.mul(result, value);
  }
  return result;
}

//------------------------------------------------------------------------------
// RFC 6508 section 3.2: the pairing <R, Q> = f_R([i]Q)^c in PF_p[q], as its representative in F_p. Miller's loop
// runs over the bits of q - 1 from the second most significant; the secret operand (an RSK) is only the evaluation
// point Q, and the steps depend on the public q alone.
Bignum pairing(const Parameters &parameters, const EC_POINT *first, const EC_POINT *second) {
  const Field field(parameters);
  const auto base = enter_point(parameters, field, first);
  const auto evaluation = enter_point(parameters, field, second);
  Jacobian current{copy(base.x_coordinate.get()), copy(base.y_coordinate.get()), field.one()};
  Extension accumulator;
  accumulator.real = field.one();
  accumulator.imaginary = field.enter(bignum().get());

  auto loop_bound = copy(parameters.order.get());
  require(BN_sub_word(loop_bound.get(), 1) == 1, "SAKKE: q - 1");
  for (int bit = BN_num_bits(loop_bound.get()) - 2; bit >= 0; --bit) {
    double_step(field, current, evaluation, accumulator);
    if (BN_is_bit_set(loop_bound.get(), bit) == 1) add_step(field, current, base, evaluation, accumulator);
  }
  return field.representative(public_power(field, accumulator, parameters.cofactor.get()));
}

//------------------------------------------------------------------------------
// Helper: makes a big number hold at least the given number of words, so that BN_consttime_swap may swap them.
void reserve_words(BIGNUM *value, int words) {
  const auto saved = copy(value);
  require(BN_set_bit(value, words * BN_BITS2 - 1) == 1 && BN_copy(value, saved.get()) != nullptr,
          "SAKKE: reserve words");
}

//------------------------------------------------------------------------------
// Helper: swaps two elements of F_p^2 when the condition is 1, in constant time.
void conditional_swap(Extension &left, Extension &right, BN_ULONG condition, int words) {
  for (auto *value : {left.real.get(), left.imaginary.get(), right.real.get(), right.imaginary.get()})
    reserve_words(value, words);
  BN_consttime_swap(condition, left.real.get(), right.real.get(), words);
  BN_consttime_swap(condition, left.imaginary.get(), right.imaginary.get(), words);
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.2.1 step 4 a): g^r in PF_p[q], as its representative in F_p. g is the representative of
// 1 + i * g, so g^r is the representative of (1 + i * g)^r in F_p^2; the secret r is taken through a Montgomery
// ladder over as many bits as q, with constant-time swaps.
Bignum pairing_base_power(const Parameters &parameters, const BIGNUM *exponent) {
  const Field field(parameters);
  const int words = (BN_num_bits(parameters.prime.get()) + BN_BITS2 - 1) / BN_BITS2;
  Extension low;
  low.real = field.one();
  low.imaginary = field.enter(bignum().get());
  Extension high;
  high.real = field.one();
  high.imaginary = field.enter(parameters.pairing_base.get());
  for (int bit = BN_num_bits(parameters.order.get()) - 1; bit >= 0; --bit) {
    const auto condition = static_cast<BN_ULONG>(BN_is_bit_set(exponent, bit));
    conditional_swap(low, high, condition, words);
    high = field.mul(low, high);
    low = field.square(low);
    conditional_swap(low, high, condition, words);
  }
  return field.representative(low);
}

//------------------------------------------------------------------------------
// Helper: SHA-256 of the concatenation of the given octet strings.
std::array<std::uint8_t, hash_bytes> hash(std::initializer_list<ByteView> parts) {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  require(digest != nullptr && EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) == 1, "SAKKE: hash");
  for (const auto part : parts) require(EVP_DigestUpdate(digest.get(), part.data(), part.size()) == 1, "SAKKE: hash");
  std::array<std::uint8_t, hash_bytes> out{};
  unsigned length = 0;
  require(EVP_DigestFinal_ex(digest.get(), out.data(), &length) == 1 && length == out.size(), "SAKKE: hash");
  return out;
}

//------------------------------------------------------------------------------
// RFC 6508 section 5.1: HashToIntegerRange(s, n, SHA-256): A = hash(s), h_0 = 0, l = Ceiling(lg(n) / hashlen),
// h_i = hash(h_(i - 1)), v_i = hash(h_i || A), v = (v_1 || ... || v_l) mod n.
Bignum hash_to_integer_range(ByteView data, const BIGNUM *limit, BN_CTX *ctx) {
  // lg(n) is bits - 1 for a power of two, and strictly between bits - 1 and bits otherwise.
  const int bits = BN_num_bits(limit);
  auto below = copy(limit);
  require(BN_sub_word(below.get(), 1) == 1, "SAKKE: hash range");
  const bool is_power_of_two = BN_num_bits(below.get()) < bits;
  const int blocks = is_power_of_two ? (bits - 1 + hash_bits - 1) / hash_bits : (bits - 1) / hash_bits + 1;

  // The input is an SSV or g^r, so every value below is derived from a secret and wiped.
  auto digest = hash({data});
  std::array<std::uint8_t, hash_bytes> chain{};
  SecretBytes concatenated;
  concatenated.data().reserve(static_cast<std::size_t>(blocks) * hash_bytes);
  for (int block = 0; block < blocks; ++block) {
    chain = hash({chain});
    auto part = hash({chain, digest});
    concatenated.data().insert(concatenated.data().end(), part.begin(), part.end());
    wipe(part);
  }
  wipe(chain);
  wipe(digest);
  auto result = secret_bignum();
  const auto value = from_bytes(concatenated.data());
  require(BN_nnmod(result.get(), value.get(), limit, ctx) == 1, "SAKKE: hash modulo n");
  return result;
}

//------------------------------------------------------------------------------
// Helper: 2^n for the n = 128 of RFC 6509 appendix A.
Bignum ssv_range() {
  auto value = bignum();
  require(BN_set_bit(value.get(), bits_per_octet * sakke_ssv_bytes) == 1, "SAKKE: 2^n");
  return value;
}

//------------------------------------------------------------------------------
// RFC 6508 sections 6.2.1 step 4 b) and 6.2.2 step 3: SSV XOR HashToIntegerRange( g^r, 2^n, Hash ), with g^r
// represented in L octets (RFC 6508 section 4).
std::array<std::uint8_t, sakke_ssv_bytes> mask(const Parameters &parameters, const BIGNUM *power,
                                               std::span<const std::uint8_t> value) {
  // g^r (or w) and the mask give away the SSV: wiped.
  const SecretBytes encoded(to_bytes(power, sakke_field_bytes));
  const SecretBytes masking(
      to_bytes(hash_to_integer_range(encoded.data(), ssv_range().get(), parameters.ctx.get()).get(), sakke_ssv_bytes));
  std::array<std::uint8_t, sakke_ssv_bytes> result{};
  std::transform(value.begin(), value.end(), masking.data().begin(), result.begin(),
                 [](std::uint8_t left, std::uint8_t right) { return static_cast<std::uint8_t>(left ^ right); });
  return result;
}

//------------------------------------------------------------------------------
// RFC 6508 section 2.2: Z_T and an RSK are "a point of order q in E(F_p)". A point of E(F_p) that is not in
// E(F_p)[q] (the curve has order 4q, RFC 6509 appendix A) is refused: it lies on E (decode_point) and [q]X = 0.
Point decode_subgroup_point(const Parameters &parameters, ByteView data) {
  auto result = decode_point(parameters.group.get(), data, parameters.ctx.get());
  auto multiple = point(parameters.group.get());
  require(EC_POINT_mul(parameters.group.get(), multiple.get(), nullptr, result.get(), parameters.order.get(),
                       parameters.ctx.get()) == 1,
          "SAKKE: [q]X");
  require(EC_POINT_is_at_infinity(parameters.group.get(), multiple.get()) == 1,
          "SAKKE: RFC 6508 section 2.2, the point is not of order q");
  return result;
}

//------------------------------------------------------------------------------
// RFC 6508 section 2.2: "An Identifier is an integer in the range 2 to q-1"; others are refused.
Bignum identifier_value(const Parameters &parameters, ByteView identifier) {
  require(!identifier.empty(), "SAKKE: empty Identifier");
  auto value = from_bytes(identifier);
  require(BN_cmp(value.get(), BN_value_one()) > 0 && BN_cmp(value.get(), parameters.order.get()) < 0,
          "SAKKE: RFC 6508 section 2.2, the Identifier is not in the range 2 to q-1");
  return value;
}

//------------------------------------------------------------------------------
// RFC 6508 sections 6.1.2, 6.2.1 step 3 and 6.2.2 step 5: [b]P + Z_S, with the Identifier b as an integer.
Point identity_point(const Parameters &parameters, ByteView public_key, ByteView identifier) {
  const auto kms_point = decode_subgroup_point(parameters, public_key);
  const auto identity = identifier_value(parameters, identifier);
  auto result = point(parameters.group.get());
  require(
      EC_POINT_mul(parameters.group.get(), result.get(), identity.get(), nullptr, nullptr, parameters.ctx.get()) == 1 &&
          EC_POINT_add(parameters.group.get(), result.get(), result.get(), kms_point.get(), parameters.ctx.get()) == 1,
      "SAKKE: [b]P + Z");
  require(EC_POINT_is_at_infinity(parameters.group.get(), result.get()) == 0, "SAKKE: [b]P + Z at infinity");
  return result;
}

//------------------------------------------------------------------------------
// RFC 6508 sections 6.2.1 steps 2 and 3 and 6.2.2 steps 4 and 5: r = HashToIntegerRange( SSV || b, q, Hash ) and
// R_(b,S) = [r]([b]P + Z_S); r is returned through the given big number.
Point encapsulation_point(const Parameters &parameters, ByteView public_key, ByteView identifier, ByteView ssv,
                          Bignum &exponent) {
  // SSV || b gives away the SSV: wiped.
  SecretBytes input;
  input.data().reserve(ssv.size() + identifier.size());
  input.data().insert(input.data().end(), ssv.begin(), ssv.end());
  input.data().insert(input.data().end(), identifier.begin(), identifier.end());
  exponent = hash_to_integer_range(input.data(), parameters.order.get(), parameters.ctx.get());
  const auto identity = identity_point(parameters, public_key, identifier);
  auto result = point(parameters.group.get());
  require(EC_POINT_mul(parameters.group.get(), result.get(), nullptr, identity.get(), exponent.get(),
                       parameters.ctx.get()) == 1,
          "SAKKE: R");
  return result;
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.1: Z_T = [z_T]P, and the KMS secret z_T || Z_T_x || Z_T_y.
AuthorityKeys authority_from(const Parameters &parameters, const BIGNUM *master_secret) {
  auto public_point = point(parameters.group.get());
  require(EC_POINT_mul(parameters.group.get(), public_point.get(), master_secret, nullptr, nullptr,
                       parameters.ctx.get()) == 1,
          "SAKKE: Z_T");
  AuthorityKeys keys;
  keys.public_key = encode_point(parameters.group.get(), public_point.get(), parameters.ctx.get());
  keys.secret = to_bytes(master_secret, sakke_field_bytes);
  keys.secret.insert(keys.secret.end(), keys.public_key.begin() + 1, keys.public_key.end());
  return keys;
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.1: a stored KMS secret z_T || Z_T_x || Z_T_y: z_T is in the range 2 to q - 1 and Z_T = [z_T]P;
// a secret that does not hold together (corrupted, truncated, of another KMS) is refused before it issues keys.
Bignum import_master_secret(const Parameters &parameters, ByteView secret) {
  require(secret.size() == sakke_secret_bytes, "SAKKE: invalid KMS secret length");
  auto master_secret = from_bytes(secret.first(sakke_field_bytes));
  BN_set_flags(master_secret.get(), BN_FLG_CONSTTIME);
  require(BN_cmp(master_secret.get(), BN_value_one()) > 0 && BN_cmp(master_secret.get(), parameters.order.get()) < 0,
          "SAKKE: KMS secret z_T not in the range 2 to q-1");
  auto expected = authority_from(parameters, master_secret.get());
  const bool is_consistent = CRYPTO_memcmp(expected.secret.data(), secret.data(), secret.size()) == 0;
  wipe(expected.secret);
  require(is_consistent, "SAKKE: KMS secret does not match its Z_T");
  return master_secret;
}

} // namespace

//------------------------------------------------------------------------------
// RFC 6508 section 6.1: z_T is chosen at random in the range 2 to q - 1.
AuthorityKeys sakke_create_authority() {
  const Parameters parameters;
  const auto master_secret = random_below(parameters.order.get(), 2);
  return authority_from(parameters, master_secret.get());
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.1.1: K_(a,T) = [(a + z_T)^-1]P, the inversion modulo q.
Bytes sakke_issue(ByteView secret, ByteView identifier) {
  const Parameters parameters;
  const auto master_secret = import_master_secret(parameters, secret);
  auto sum = secret_bignum();
  require(BN_mod_add(sum.get(), identifier_value(parameters, identifier).get(), master_secret.get(),
                     parameters.order.get(), parameters.ctx.get()) == 1,
          "SAKKE: a + z_T");
  // RFC 6508 section 2.2: an Identifier is in the range 2 to q - 1, so a + z_T is zero modulo q only for a KMS secret
  // that is the negation of the Identifier; such an RSK does not exist.
  require(BN_is_zero(sum.get()) == 0, "SAKKE: no RSK for this Identifier");
  const auto inverse = inverse_mod_prime(sum.get(), parameters.order.get(), parameters.ctx.get());
  auto receiver_key = point(parameters.group.get());
  require(EC_POINT_mul(parameters.group.get(), receiver_key.get(), inverse.get(), nullptr, nullptr,
                       parameters.ctx.get()) == 1,
          "SAKKE: RSK");
  return encode_point(parameters.group.get(), receiver_key.get(), parameters.ctx.get());
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.1.2: < [a]P + Z, K_(a,T) > = g.
bool sakke_validate(ByteView public_key, ByteView identifier, ByteView receiver_key) {
  try {
    const Parameters parameters;
    const auto receiver_point = decode_subgroup_point(parameters, receiver_key);
    const auto identity = identity_point(parameters, public_key, identifier);
    const auto value = pairing(parameters, identity.get(), receiver_point.get());
    return BN_cmp(value.get(), parameters.pairing_base.get()) == 0;
  } catch (const std::exception &) {
    // A malformed point or an OpenSSL failure: the RSK is not valid.
    return false;
  }
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.2.1 steps 2 to 5 for a given SSV (step 1 is the caller's): r, R_(b,S), g^r and the Hint H, and
// the Encapsulated Data R_(b,S) || H.
Bytes sakke_encapsulate(ByteView public_key, ByteView identifier, std::span<const std::uint8_t, sakke_ssv_bytes> ssv) {
  const Parameters parameters;
  auto exponent = secret_bignum();
  const auto encapsulated = encapsulation_point(parameters, public_key, identifier, ssv, exponent);
  const auto power = pairing_base_power(parameters, exponent.get());
  const auto hint = mask(parameters, power.get(), ssv);
  auto result = encode_point(parameters.group.get(), encapsulated.get(), parameters.ctx.get());
  result.insert(result.end(), hint.begin(), hint.end());
  return result;
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.2.2: parse R_(b,S) and H (step 1), w = < R_(b,S), K_(b,S) > (step 2), the SSV (step 3), and
// the check TEST = R_(b,S) (steps 4 and 5): "If TEST does not equal R_(b,S), then B MUST NOT use the SSV".
std::array<std::uint8_t, sakke_ssv_bytes> sakke_decapsulate(ByteView public_key, ByteView identifier,
                                                            ByteView receiver_key, ByteView encapsulated) {
  require(encapsulated.size() == sakke_encapsulated_bytes, "SAKKE: invalid Encapsulated Data length");
  const Parameters parameters;
  const auto received =
      decode_point(parameters.group.get(), encapsulated.first(sakke_point_bytes), parameters.ctx.get());
  const auto receiver_point = decode_subgroup_point(parameters, receiver_key);
  const auto power = pairing(parameters, received.get(), receiver_point.get());
  const auto ssv = mask(parameters, power.get(), encapsulated.subspan(sakke_point_bytes));

  auto exponent = secret_bignum();
  const auto test = encapsulation_point(parameters, public_key, identifier, ssv, exponent);
  require(EC_POINT_cmp(parameters.group.get(), test.get(), received.get(), parameters.ctx.get()) == 0,
          "SAKKE: RFC 6508 section 6.2.2 step 5, TEST does not equal R_(b,S)");
  return ssv;
}

#ifdef MCX_IBE_KNOWN_ANSWER
//------------------------------------------------------------------------------
// RFC 6508 appendix A: the KMS keys of a given z_T.
AuthorityKeys known_answer::sakke_authority(const BIGNUM *master_secret) {
  const Parameters parameters;
  return authority_from(parameters, master_secret);
}

//------------------------------------------------------------------------------
// RFC 6508 appendix A: HashToIntegerRange.
Bignum known_answer::hash_to_integer_range(ByteView data, const BIGNUM *limit) {
  const auto ctx = context();
  return mcx::ibe::hash_to_integer_range(data, limit, ctx.get());
}

//------------------------------------------------------------------------------
// RFC 6508 appendix A: the pairing of two encoded points.
Bytes known_answer::pairing(ByteView first, ByteView second) {
  const Parameters parameters;
  const auto first_point = decode_point(parameters.group.get(), first, parameters.ctx.get());
  const auto second_point = decode_point(parameters.group.get(), second, parameters.ctx.get());
  return to_bytes(mcx::ibe::pairing(parameters, first_point.get(), second_point.get()).get(), sakke_field_bytes);
}

#endif // MCX_IBE_KNOWN_ANSWER

} // namespace mcx::ibe
