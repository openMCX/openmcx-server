//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Hostile inputs to the ECCSI and SAKKE primitives (src/security/ibe.hpp): every one is refused, none crashes.
// ECCSI: signatures with r = 0, s = 0 or s = q, PVTs and KPAKs that are not finite points on P-256, wrong lengths,
// pairs of another KMS or identifier, inconsistent KMS secrets, and randomly mutated signatures, messages and
// identifiers. SAKKE: Encapsulated Data whose R is not on E, of order 2, outside E(F_p)[q] or another known point;
// a Z_T or an RSK outside E(F_p)[q]; Identifiers outside the range 2 to q - 1; inconsistent KMS secrets; and randomly
// mutated Encapsulated Data. The mutations come from a fixed-seed generator, so a failure reproduces.
//
// Specifications: RFC 6507, RFC 6508, RFC 6509.

#include "ibe.hpp"

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using mcx::ibe::Bytes;
using mcx::ibe::ByteView;
using Ssv = std::array<std::uint8_t, mcx::ibe::sakke_ssv_bytes>;

// The rounds of the random mutation checks: ECCSI verification is fast, SAKKE decapsulation takes milliseconds.
constexpr int eccsi_mutation_rounds = 2000;
constexpr int sakke_mutation_rounds = 40;
// The fixed seed of the mutation source (any non-zero value).
constexpr std::uint64_t mutation_seed = 0x9e3779b97f4a7c15ULL;
// The offsets of r, s and the PVT in a signature r || s || PVT (RFC 6507 section 3.3).
constexpr std::size_t signature_s_offset = mcx::ibe::eccsi_scalar_bytes;
constexpr std::size_t signature_pvt_offset = 2 * mcx::ibe::eccsi_scalar_bytes;
// The offsets of the x and y coordinates in a SAKKE point 0x04 || x || y (RFC 6508 section 4).
constexpr std::size_t sakke_x_offset = 1;
constexpr std::size_t sakke_y_offset = 1 + mcx::ibe::sakke_field_bytes;

// RFC 6509 appendix A: p, as hexadecimal.
constexpr const char *sakke_prime_hex =
    "997ABB1F0A563FDA65C61198DAD0657A416C0CE19CB48261BE9AE358B3E01A2EF40AAB27E2FC0F1B228730D531A59CB0"
    "E791B39FF7C88A19356D27F4A666A6D0E26C6487326B4CD4512AC5CD65681CE1B6AFF4A831852A82A7CF3C521C3C09AA"
    "9F94D6AF56971F1FFCE3E82389857DB080C5DF10AC7ACE87666D807AFEA85FEB";
// RFC 6509 appendix A: q, as hexadecimal.
constexpr const char *sakke_order_hex =
    "265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068BBD02AAC9F8BF03C6C8A1CC354C69672C"
    "39E46CE7FDF222864D5B49FD2999A9B4389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026A"
    "A7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB";
// RFC 6507 appendix A: the order q of P-256, as hexadecimal.
constexpr const char *eccsi_order_hex = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

int failures = 0;

//------------------------------------------------------------------------------
// Records a failure when the condition does not hold.
void expect(bool condition, const std::string &text) {
  if (condition) return;
  ++failures;
  std::cerr << "FAIL: " << text << '\n';
}

//------------------------------------------------------------------------------
// Whether an action throws (a refusal).
template <class Action> bool throws(Action &&action) {
  try {
    action();
  } catch (const std::exception &) {
    return true;
  }
  return false;
}

// A fixed-seed xorshift generator: reproducible mutations, not for keys.
class MutationSource {
public:
  std::uint64_t next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }

  std::uint8_t octet() { return static_cast<std::uint8_t>(next()); }

  std::size_t below(std::size_t limit) { return static_cast<std::size_t>(next() % limit); }

private:
  std::uint64_t state_ = mutation_seed;
};

//------------------------------------------------------------------------------
// Helper: a big number from hexadecimal text.
mcx::ibe::Bignum number(const char *text) {
  BIGNUM *value = nullptr;
  if (BN_hex2bn(&value, text) <= 0) throw std::runtime_error("test number");
  return mcx::ibe::Bignum(value);
}

//------------------------------------------------------------------------------
// Helper: a SAKKE point 0x04 || x || y of the given coordinates.
Bytes sakke_point(const BIGNUM *x_coordinate, const BIGNUM *y_coordinate) {
  Bytes out{POINT_CONVERSION_UNCOMPRESSED};
  const auto x_octets = mcx::ibe::to_bytes(x_coordinate, mcx::ibe::sakke_field_bytes);
  const auto y_octets = mcx::ibe::to_bytes(y_coordinate, mcx::ibe::sakke_field_bytes);
  out.insert(out.end(), x_octets.begin(), x_octets.end());
  out.insert(out.end(), y_octets.begin(), y_octets.end());
  return out;
}

//------------------------------------------------------------------------------
// Helper: a random point of E: y^2 = x^3 - 3x over F_p, found by trying x until x^3 - 3x is a square (y is its square
// root (x^3 - 3x)^((p + 1) / 4), p being 3 modulo 4). E(F_p) has order 4q, so such a point is outside E(F_p)[q] with
// probability 3/4; the caller checks.
Bytes random_curve_point(MutationSource &source) {
  const auto ctx = mcx::ibe::context();
  const auto prime = number(sakke_prime_hex);
  auto root_exponent = mcx::ibe::copy(prime.get());
  if (BN_add_word(root_exponent.get(), 1) != 1 || BN_rshift(root_exponent.get(), root_exponent.get(), 2) != 1)
    throw std::runtime_error("square root exponent");
  for (;;) {
    Bytes x_octets(mcx::ibe::sakke_field_bytes);
    for (auto &octet : x_octets) octet = source.octet();
    auto x_coordinate = mcx::ibe::from_bytes(x_octets);
    auto right_side = mcx::ibe::bignum();
    auto term = mcx::ibe::bignum();
    auto y_coordinate = mcx::ibe::bignum();
    auto squared = mcx::ibe::bignum();
    const bool is_ok =
        BN_nnmod(x_coordinate.get(), x_coordinate.get(), prime.get(), ctx.get()) == 1 &&
        BN_mod_sqr(term.get(), x_coordinate.get(), prime.get(), ctx.get()) == 1 &&
        BN_mod_mul(right_side.get(), term.get(), x_coordinate.get(), prime.get(), ctx.get()) == 1 &&
        BN_mod_lshift1(term.get(), x_coordinate.get(), prime.get(), ctx.get()) == 1 &&
        BN_mod_add(term.get(), term.get(), x_coordinate.get(), prime.get(), ctx.get()) == 1 &&
        BN_mod_sub(right_side.get(), right_side.get(), term.get(), prime.get(), ctx.get()) == 1 &&
        BN_mod_exp(y_coordinate.get(), right_side.get(), root_exponent.get(), prime.get(), ctx.get()) == 1 &&
        BN_mod_sqr(squared.get(), y_coordinate.get(), prime.get(), ctx.get()) == 1;
    if (!is_ok) throw std::runtime_error("random curve point");
    if (BN_cmp(squared.get(), right_side.get()) == 0) return sakke_point(x_coordinate.get(), y_coordinate.get());
  }
}

//------------------------------------------------------------------------------
// Helper: whether a SAKKE point is in E(F_p)[q] ([q]X = 0), computed independently of the code under test.
bool in_sakke_subgroup(ByteView encoded) {
  const auto ctx = mcx::ibe::context();
  const auto prime = number(sakke_prime_hex);
  auto curve_a = mcx::ibe::copy(prime.get());
  BN_sub_word(curve_a.get(), 3);
  const auto curve_b = mcx::ibe::bignum();
  const mcx::ibe::Group group(EC_GROUP_new_curve_GFp(prime.get(), curve_a.get(), curve_b.get(), ctx.get()));
  const auto value = mcx::ibe::decode_point(group.get(), encoded, ctx.get());
  auto multiple = mcx::ibe::point(group.get());
  const auto order = number(sakke_order_hex);
  EC_POINT_mul(group.get(), multiple.get(), nullptr, value.get(), order.get(), ctx.get());
  return EC_POINT_is_at_infinity(group.get(), multiple.get()) == 1;
}

//------------------------------------------------------------------------------
// Helper: a random point of E outside E(F_p)[q].
Bytes point_outside_subgroup(MutationSource &source) {
  for (;;) {
    auto candidate = random_curve_point(source);
    if (!in_sakke_subgroup(candidate)) return candidate;
  }
}

//------------------------------------------------------------------------------
// Helper: whether a signature verifies.
bool verifies(const mcx::ibe::AuthorityKeys &authority, ByteView identifier, ByteView message, ByteView signature) {
  return mcx::ibe::eccsi_verify(authority.public_key, identifier, message, signature);
}

//------------------------------------------------------------------------------
// RFC 6507 section 5.2.2: signatures that are not valid are refused: r = 0, s = 0, s = q, PVTs that are not finite
// points on the curve, a KPAK off the curve, wrong lengths.
void eccsi_malformed_signatures(const mcx::ibe::AuthorityKeys &authority, ByteView identifier, ByteView message,
                                const Bytes &signature) {
  expect(verifies(authority, identifier, message, signature), "ECCSI: the unmodified signature verifies");
  auto altered = signature;
  std::fill(altered.begin(), altered.begin() + signature_s_offset, 0);
  expect(!verifies(authority, identifier, message, altered), "ECCSI: r = 0 refused");
  altered = signature;
  std::fill(altered.begin() + signature_s_offset, altered.begin() + signature_pvt_offset, 0);
  expect(!verifies(authority, identifier, message, altered), "ECCSI: s = 0 refused");
  altered = signature;
  const auto order = mcx::ibe::to_bytes(number(eccsi_order_hex).get(), mcx::ibe::eccsi_scalar_bytes);
  std::copy(order.begin(), order.end(), altered.begin() + signature_s_offset);
  expect(!verifies(authority, identifier, message, altered), "ECCSI: s = q refused");

  for (const std::uint8_t prefix : {std::uint8_t{0x00}, std::uint8_t{0x02}, std::uint8_t{0x03}, std::uint8_t{0x06}}) {
    altered = signature;
    altered[signature_pvt_offset] = prefix;
    expect(!verifies(authority, identifier, message, altered), "ECCSI: PVT prefix " + std::to_string(prefix));
  }
  for (const std::uint8_t fill : {std::uint8_t{0x00}, std::uint8_t{0xff}}) {
    altered = signature;
    std::fill(altered.begin() + signature_pvt_offset + 1, altered.end(), fill);
    expect(!verifies(authority, identifier, message, altered), "ECCSI: PVT coordinates all " + std::to_string(fill));
  }
  auto off_curve = authority.public_key;
  off_curve.back() ^= 1;
  expect(!mcx::ibe::eccsi_verify(off_curve, identifier, message, signature), "ECCSI: KPAK off the curve refused");
  expect(!mcx::ibe::eccsi_verify(Bytes(mcx::ibe::eccsi_point_bytes, 0), identifier, message, signature),
         "ECCSI: zero KPAK refused");
  expect(!verifies(authority, identifier, message, Bytes(signature.begin(), signature.end() - 1)),
         "ECCSI: short signature refused");
  auto longer = signature;
  longer.push_back(0);
  expect(!verifies(authority, identifier, message, longer), "ECCSI: long signature refused");
}

//------------------------------------------------------------------------------
// RFC 6507 sections 4.2, 5.1.1 and 5.1.2: pairs of another KMS, identifier or length do not validate; KMS secrets that
// do not hold together and an empty identifier issue nothing.
void eccsi_keys(const mcx::ibe::AuthorityKeys &authority, ByteView identifier, const Bytes &pair) {
  const auto other = mcx::ibe::eccsi_create_authority();
  expect(!mcx::ibe::eccsi_validate(other.public_key, identifier, pair), "ECCSI: pair of another KMS refused");
  expect(!mcx::ibe::eccsi_validate(authority.public_key, Bytes{'x'}, pair), "ECCSI: pair of another ID refused");
  expect(!mcx::ibe::eccsi_validate(authority.public_key, identifier, Bytes(mcx::ibe::eccsi_pair_bytes, 0)),
         "ECCSI: zero pair refused");
  expect(!mcx::ibe::eccsi_validate(authority.public_key, identifier, Bytes(pair.begin(), pair.end() - 1)),
         "ECCSI: short pair refused");
  expect(throws([&] { mcx::ibe::eccsi_issue(authority.secret, Bytes{}); }), "ECCSI: empty identifier issues nothing");

  auto wrong_kpak = authority.secret;
  wrong_kpak.back() ^= 1;
  expect(throws([&] { mcx::ibe::eccsi_issue(wrong_kpak, identifier); }), "ECCSI: KMS secret with another KPAK");
  auto zero_ksak = authority.secret;
  std::fill(zero_ksak.begin(), zero_ksak.begin() + mcx::ibe::eccsi_scalar_bytes, 0);
  expect(throws([&] { mcx::ibe::eccsi_issue(zero_ksak, identifier); }), "ECCSI: KMS secret with KSAK 0");
  auto order_ksak = authority.secret;
  const auto order = mcx::ibe::to_bytes(number(eccsi_order_hex).get(), mcx::ibe::eccsi_scalar_bytes);
  std::copy(order.begin(), order.end(), order_ksak.begin());
  expect(throws([&] { mcx::ibe::eccsi_issue(order_ksak, identifier); }), "ECCSI: KMS secret with KSAK q");
  expect(
      throws([&] { mcx::ibe::eccsi_issue(Bytes(authority.secret.begin(), authority.secret.end() - 1), identifier); }),
      "ECCSI: short KMS secret");
}

//------------------------------------------------------------------------------
// RFC 6507 section 5.2.2: random mutations of the signature, the message or the identifier never verify.
void eccsi_mutations(MutationSource &source, const mcx::ibe::AuthorityKeys &authority, const Bytes &identifier,
                     const Bytes &message, const Bytes &signature) {
  int accepted = 0;
  for (int round = 0; round < eccsi_mutation_rounds; ++round) {
    auto altered_signature = signature;
    auto altered_message = message;
    auto altered_identifier = identifier;
    switch (source.below(5)) {
    case 0:
      altered_signature[source.below(signature.size())] ^= static_cast<std::uint8_t>(1U << source.below(8));
      break;
    case 1:
      for (auto &octet : altered_signature) octet = source.octet();
      break;
    case 2:
      for (int count = 0; count < 3; ++count) altered_signature[source.below(signature_pvt_offset)] = source.octet();
      break;
    case 3: altered_message[source.below(message.size())] ^= 1; break;
    default: altered_identifier[source.below(identifier.size())] ^= 1; break;
    }
    if (verifies(authority, altered_identifier, altered_message, altered_signature)) ++accepted;
  }
  expect(accepted == 0, "ECCSI: " + std::to_string(accepted) + " mutated inputs verified");
}

//------------------------------------------------------------------------------
// Helper: Encapsulated Data with the given R and the H of other Encapsulated Data.
Bytes with_point(const Bytes &point_octets, const Bytes &encapsulated) {
  Bytes out = point_octets;
  out.insert(out.end(), encapsulated.begin() + mcx::ibe::sakke_point_bytes, encapsulated.end());
  return out;
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.2.2: Encapsulated Data whose R is not the sender's R_(b,S) are refused: not on E, of order 2,
// at infinity, -R, the receiver's RSK, Z_T, points outside E(F_p)[q], wrong lengths.
void sakke_malformed_data(MutationSource &source, const mcx::ibe::AuthorityKeys &authority, ByteView identifier,
                          const Bytes &receiver_key, const Bytes &encapsulated) {
  const auto refused = [&](const Bytes &data, const std::string &name) {
    expect(throws([&] { mcx::ibe::sakke_decapsulate(authority.public_key, identifier, receiver_key, data); }),
           "SAKKE: Encapsulated Data with R = " + name + " refused");
  };
  const auto zero = mcx::ibe::bignum();
  refused(with_point(sakke_point(zero.get(), zero.get()), encapsulated), "(0, 0), of order 2");
  Bytes all_ones(mcx::ibe::sakke_point_bytes, 0xff);
  all_ones[0] = POINT_CONVERSION_UNCOMPRESSED;
  refused(with_point(all_ones, encapsulated), "coordinates of all ones (not below p)");
  refused(with_point(Bytes(mcx::ibe::sakke_point_bytes, 0), encapsulated), "all zero octets");

  auto negated = Bytes(encapsulated.begin(), encapsulated.begin() + mcx::ibe::sakke_point_bytes);
  auto y_coordinate = mcx::ibe::from_bytes(ByteView(negated).subspan(sakke_y_offset, mcx::ibe::sakke_field_bytes));
  BN_sub(y_coordinate.get(), number(sakke_prime_hex).get(), y_coordinate.get());
  const auto y_octets = mcx::ibe::to_bytes(y_coordinate.get(), mcx::ibe::sakke_field_bytes);
  std::copy(y_octets.begin(), y_octets.end(), negated.begin() + sakke_y_offset);
  refused(with_point(negated, encapsulated), "-R");
  refused(with_point(receiver_key, encapsulated), "the receiver's RSK");
  refused(with_point(authority.public_key, encapsulated), "Z_T");
  for (int count = 0; count < 3; ++count)
    refused(with_point(point_outside_subgroup(source), encapsulated), "outside E[q]");
  refused(Bytes(encapsulated.begin(), encapsulated.end() - 1), "a short H");
  auto longer = encapsulated;
  longer.push_back(0);
  refused(longer, "a trailing octet");
}

//------------------------------------------------------------------------------
// RFC 6508 section 2.2: a Z_T or an RSK outside E(F_p)[q] and Identifiers outside the range 2 to q - 1 are refused
// in every operation.
void sakke_keys_and_identifiers(MutationSource &source, const mcx::ibe::AuthorityKeys &authority,
                                const Bytes &identifier, const Bytes &receiver_key, const Bytes &encapsulated) {
  Ssv ssv{};
  const auto zero = mcx::ibe::bignum();
  const auto order_two = sakke_point(zero.get(), zero.get());
  const auto outside = point_outside_subgroup(source);
  for (const auto &[kms_key, name] : {std::pair<Bytes, std::string>{order_two, "(0, 0)"}, {outside, "outside E[q]"}}) {
    expect(throws([&] { mcx::ibe::sakke_encapsulate(kms_key, identifier, ssv); }),
           "SAKKE: encapsulation under a Z_T " + name + " refused");
    expect(throws([&] { mcx::ibe::sakke_decapsulate(kms_key, identifier, receiver_key, encapsulated); }),
           "SAKKE: decapsulation under a Z_T " + name + " refused");
    expect(!mcx::ibe::sakke_validate(kms_key, identifier, receiver_key), "SAKKE: RSK under a Z_T " + name);
    expect(throws([&] { mcx::ibe::sakke_decapsulate(authority.public_key, identifier, kms_key, encapsulated); }),
           "SAKKE: decapsulation with an RSK " + name + " refused");
    expect(!mcx::ibe::sakke_validate(authority.public_key, identifier, kms_key), "SAKKE: RSK " + name + " validated");
  }

  const Bytes too_large(mcx::ibe::sakke_field_bytes, 0xff);
  for (const auto &[bad, name] : {std::pair<Bytes, std::string>{Bytes{}, "empty"},
                                  {Bytes{0}, "0"},
                                  {Bytes{1}, "1"},
                                  {Bytes{0, 0, 1}, "1 with leading zeros"},
                                  {too_large, "above q"}}) {
    expect(throws([&] { mcx::ibe::sakke_issue(authority.secret, bad); }), "SAKKE: RSK for Identifier " + name);
    expect(throws([&] { mcx::ibe::sakke_encapsulate(authority.public_key, bad, ssv); }),
           "SAKKE: encapsulation to Identifier " + name);
    expect(!mcx::ibe::sakke_validate(authority.public_key, bad, receiver_key), "SAKKE: validation for " + name);
  }
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.1: KMS secrets that do not hold together issue nothing: z_T of 0, 1 or q, another Z_T, wrong
// length.
void sakke_kms_secrets(const mcx::ibe::AuthorityKeys &authority, ByteView identifier) {
  const auto with_master_secret = [&](const BIGNUM *value) {
    auto secret = authority.secret;
    const auto octets = mcx::ibe::to_bytes(value, mcx::ibe::sakke_field_bytes);
    std::copy(octets.begin(), octets.end(), secret.begin());
    return secret;
  };
  const auto zero = mcx::ibe::bignum();
  expect(throws([&] { mcx::ibe::sakke_issue(with_master_secret(zero.get()), identifier); }), "SAKKE: z_T = 0");
  expect(throws([&] { mcx::ibe::sakke_issue(with_master_secret(BN_value_one()), identifier); }), "SAKKE: z_T = 1");
  expect(throws([&] { mcx::ibe::sakke_issue(with_master_secret(number(sakke_order_hex).get()), identifier); }),
         "SAKKE: z_T = q");
  auto wrong_public = authority.secret;
  wrong_public.back() ^= 1;
  expect(throws([&] { mcx::ibe::sakke_issue(wrong_public, identifier); }), "SAKKE: KMS secret with another Z_T");
  expect(
      throws([&] { mcx::ibe::sakke_issue(Bytes(authority.secret.begin(), authority.secret.end() - 1), identifier); }),
      "SAKKE: short KMS secret");
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.2.2 step 5: random mutations of the Encapsulated Data (a flipped bit, a new H, a random point of
// E for R) never decapsulate.
void sakke_mutations(MutationSource &source, const mcx::ibe::AuthorityKeys &authority, ByteView identifier,
                     const Bytes &receiver_key, const Bytes &encapsulated) {
  int accepted = 0;
  for (int round = 0; round < sakke_mutation_rounds; ++round) {
    auto altered = encapsulated;
    switch (source.below(3)) {
    case 0: altered[source.below(altered.size())] ^= static_cast<std::uint8_t>(1U << source.below(8)); break;
    case 1:
      for (std::size_t index = mcx::ibe::sakke_point_bytes; index < altered.size(); ++index)
        altered[index] = source.octet();
      break;
    default: {
      const auto replacement = random_curve_point(source);
      std::copy(replacement.begin(), replacement.end(), altered.begin());
    }
    }
    if (!throws([&] { mcx::ibe::sakke_decapsulate(authority.public_key, identifier, receiver_key, altered); }))
      ++accepted;
  }
  expect(accepted == 0, "SAKKE: " + std::to_string(accepted) + " mutated Encapsulated Data decapsulated");
}

} // namespace

int main() {
  try {
    MutationSource source;
    const Bytes identifier{'s', 'i', 'p', ':', 'u', 's', 'e', 'r'};
    const Bytes message{'M', 'I', 'K', 'E', 'Y', '-', 'S', 'A', 'K', 'K', 'E'};

    const auto eccsi = mcx::ibe::eccsi_create_authority();
    const auto pair = mcx::ibe::eccsi_issue(eccsi.secret, identifier);
    const auto signature = mcx::ibe::eccsi_sign(eccsi.public_key, identifier, pair, message);
    eccsi_malformed_signatures(eccsi, identifier, message, signature);
    eccsi_keys(eccsi, identifier, pair);
    eccsi_mutations(source, eccsi, identifier, message, signature);

    const auto sakke = mcx::ibe::sakke_create_authority();
    const auto receiver_key = mcx::ibe::sakke_issue(sakke.secret, identifier);
    Ssv ssv{};
    for (auto &octet : ssv) octet = source.octet();
    const auto encapsulated = mcx::ibe::sakke_encapsulate(sakke.public_key, identifier, ssv);
    expect(mcx::ibe::sakke_decapsulate(sakke.public_key, identifier, receiver_key, encapsulated) == ssv,
           "SAKKE: the unmodified Encapsulated Data decapsulate");
    expect(in_sakke_subgroup(sakke.public_key) && in_sakke_subgroup(receiver_key), "SAKKE: own keys are in E[q]");
    sakke_malformed_data(source, sakke, identifier, receiver_key, encapsulated);
    sakke_keys_and_identifiers(source, sakke, identifier, receiver_key, encapsulated);
    sakke_kms_secrets(sakke, identifier);
    sakke_mutations(source, sakke, identifier, receiver_key, encapsulated);
  } catch (const std::exception &error) {
    std::cerr << "FAIL: unexpected exception: " << error.what() << '\n';
    return 1;
  }
  if (failures != 0) {
    std::cerr << failures << " hostile inputs were not refused\n";
    return 1;
  }
  std::cout << "PASS: every hostile ECCSI and SAKKE input refused\n";
  return 0;
}
