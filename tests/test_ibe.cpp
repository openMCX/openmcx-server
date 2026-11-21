//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The identity-based primitives of MIKEY-SAKKE on OpenSSL (src/security/ibe.hpp): the known-answer tests of
// RFC 6507 appendix A (KMS keys, (SSK, PVT) issue, signature, verification) and RFC 6508 appendix A (KMS keys,
// HashToIntegerRange, RSK issue and validation, the pairing, encapsulation and decapsulation), then round trips with
// random keys and the refusal of altered keys, signatures and Encapsulated Data.
//
// Specifications: RFC 6507, RFC 6508, RFC 6509.

#include "ibe.hpp"
#include "ibe_vectors.hpp"

#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {

using mcx::ibe::Bytes;

//------------------------------------------------------------------------------
// Throws the text when the condition does not hold.
void check(bool condition, const char *text) {
  if (!condition) throw std::runtime_error(text);
}

//------------------------------------------------------------------------------
// Throws the text unless the action throws.
template <class Action> void rejected(Action &&action, const char *text) {
  try {
    action();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(text);
}

//------------------------------------------------------------------------------
// Helper: the octets of hexadecimal text.
Bytes hex(std::string_view text) {
  Bytes out;
  for (std::size_t index = 0; index + 1 < text.size(); index += 2)
    out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(text.substr(index, 2)), nullptr, 16)));
  return out;
}

//------------------------------------------------------------------------------
// Helper: a big number from hexadecimal text.
mcx::ibe::Bignum number(const char *text) {
  BIGNUM *value = nullptr;
  check(BN_hex2bn(&value, text) > 0, "test number");
  return mcx::ibe::Bignum(value);
}

//------------------------------------------------------------------------------
// Helper: the concatenation of octet strings.
Bytes join(std::initializer_list<Bytes> parts) {
  Bytes out;
  for (const auto &part : parts) out.insert(out.end(), part.begin(), part.end());
  return out;
}

// RFC 6507 and RFC 6508 appendix A: the Identifier "2011-02\0tel:+447700900123\0".
const Bytes test_identifier = hex("323031312D30320074656C3A2B34343737303039303031323300");

//------------------------------------------------------------------------------
// RFC 6507 appendix A: KPAK = [KSAK]G, the (SSK, PVT) pair of v, the signature of "message\0" with j, its
// verification, and the validation of the pair.
void rfc6507_appendix_a() {
  using namespace ibe_vectors;
  const auto authority = mcx::ibe::known_answer::eccsi_authority(number("12345").get());
  check(authority.public_key == hex(eccsi_kpak), "RFC 6507 appendix A: KPAK");
  check(authority.secret.size() == mcx::ibe::eccsi_secret_bytes, "RFC 6507: KMS secret length");

  const auto pair = mcx::ibe::known_answer::eccsi_issue(authority.secret, test_identifier, number("23456").get());
  const auto pvt = hex(eccsi_pvt);
  check(pair == join({hex(eccsi_ssk), Bytes(pvt.begin() + 1, pvt.end())}), "RFC 6507 appendix A: SSK and PVT");
  check(mcx::ibe::eccsi_validate(authority.public_key, test_identifier, pair), "RFC 6507 section 5.1.2: valid pair");

  const Bytes message = hex("6D65737361676500");
  const auto signature =
      mcx::ibe::known_answer::eccsi_sign(authority.public_key, test_identifier, pair, message, number("34567").get());
  check(signature == hex(eccsi_signature), "RFC 6507 appendix A: signature");
  check(mcx::ibe::eccsi_verify(authority.public_key, test_identifier, message, signature),
        "RFC 6507 appendix A: verification");
}

//------------------------------------------------------------------------------
// RFC 6508 appendix A: the HashToIntegerRange example, Z = [z]P, K_b, the pairing w = g^r, the Encapsulated Data of
// the SSV, its decapsulation, and the RSK validation of section 6.1.2.
void rfc6508_appendix_a() {
  using namespace ibe_vectors;
  const auto prime_order =
      number("265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068BBD02AAC9F8BF03C6C8A1CC354C69672C"
             "39E46CE7FDF222864D5B49FD2999A9B4389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026A"
             "A7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB");
  const auto hashed = mcx::ibe::known_answer::hash_to_integer_range(hex(sakke_hash_input), prime_order.get());
  check(mcx::ibe::to_bytes(hashed.get(), 128) == hex(sakke_r), "RFC 6508 appendix A: HashToIntegerRange");

  const auto authority = mcx::ibe::known_answer::sakke_authority(number(sakke_z).get());
  const Bytes uncompressed{0x04};
  check(authority.public_key == join({uncompressed, hex(sakke_zx), hex(sakke_zy)}), "RFC 6508 appendix A: Z");

  const auto receiver_key = mcx::ibe::sakke_issue(authority.secret, test_identifier);
  check(receiver_key == join({uncompressed, hex(sakke_kbx), hex(sakke_kby)}), "RFC 6508 appendix A: K_b");
  check(mcx::ibe::sakke_validate(authority.public_key, test_identifier, receiver_key),
        "RFC 6508 section 6.1.2: valid RSK");

  const auto encapsulated_point = join({uncompressed, hex(sakke_rbx), hex(sakke_rby)});
  check(mcx::ibe::known_answer::pairing(encapsulated_point, receiver_key) == hex(sakke_g_r),
        "RFC 6508 appendix A: w = <R_b, K_b> = g^r");

  const auto ssv_bytes = hex("123456789ABCDEF0123456789ABCDEF0");
  std::array<std::uint8_t, mcx::ibe::sakke_ssv_bytes> ssv{};
  std::copy(ssv_bytes.begin(), ssv_bytes.end(), ssv.begin());
  const auto encapsulated = mcx::ibe::sakke_encapsulate(authority.public_key, test_identifier, ssv);
  check(encapsulated == join({encapsulated_point, hex(sakke_h)}), "RFC 6508 appendix A: Encapsulated Data");
  check(mcx::ibe::sakke_decapsulate(authority.public_key, test_identifier, receiver_key, encapsulated) == ssv,
        "RFC 6508 appendix A: receiver SSV");
}

//------------------------------------------------------------------------------
// RFC 6507 sections 5.1 and 5.2 with random keys: a signature verifies, and fails for another identifier, another
// message, an altered signature or another KMS; an altered pair does not validate.
void rfc6507_random_keys() {
  const auto authority = mcx::ibe::eccsi_create_authority();
  const auto other = mcx::ibe::eccsi_create_authority();
  const Bytes identifier{'a', 'l', 'i', 'c', 'e'};
  const Bytes message{1, 2, 3};
  const auto pair = mcx::ibe::eccsi_issue(authority.secret, identifier);
  check(mcx::ibe::eccsi_validate(authority.public_key, identifier, pair), "RFC 6507: random pair valid");
  check(!mcx::ibe::eccsi_validate(other.public_key, identifier, pair), "RFC 6507: pair of another KMS");
  check(!mcx::ibe::eccsi_validate(authority.public_key, Bytes{'b', 'o', 'b'}, pair), "RFC 6507: pair of another ID");
  auto altered_pair = pair;
  altered_pair[5] ^= 1;
  check(!mcx::ibe::eccsi_validate(authority.public_key, identifier, altered_pair), "RFC 6507: altered SSK");

  const auto signature = mcx::ibe::eccsi_sign(authority.public_key, identifier, pair, message);
  check(mcx::ibe::eccsi_verify(authority.public_key, identifier, message, signature), "RFC 6507: random signature");
  check(!mcx::ibe::eccsi_verify(authority.public_key, Bytes{'b', 'o', 'b'}, message, signature),
        "RFC 6507: signature of another ID");
  check(!mcx::ibe::eccsi_verify(authority.public_key, identifier, Bytes{1, 2, 4}, signature),
        "RFC 6507: signature of another message");
  check(!mcx::ibe::eccsi_verify(other.public_key, identifier, message, signature), "RFC 6507: another KMS");
  for (const std::size_t position : {std::size_t{0}, std::size_t{40}, std::size_t{100}}) {
    auto altered = signature;
    altered[position] ^= 1;
    check(!mcx::ibe::eccsi_verify(authority.public_key, identifier, message, altered), "RFC 6507: altered signature");
  }
  check(!mcx::ibe::eccsi_verify(authority.public_key, identifier, message, Bytes(129, 0)), "RFC 6507: zero signature");
}

//------------------------------------------------------------------------------
// RFC 6508 sections 6.1 and 6.2 with random keys: the SSV round-trips; another identifier's RSK, an altered R or H, and
// another KMS are refused (section 6.2.2 step 5).
void rfc6508_random_keys() {
  const auto authority = mcx::ibe::sakke_create_authority();
  const auto other = mcx::ibe::sakke_create_authority();
  const Bytes identifier{'b', 'o', 'b'};
  const auto receiver_key = mcx::ibe::sakke_issue(authority.secret, identifier);
  check(mcx::ibe::sakke_validate(authority.public_key, identifier, receiver_key), "RFC 6508: random RSK valid");
  check(!mcx::ibe::sakke_validate(other.public_key, identifier, receiver_key), "RFC 6508: RSK of another KMS");
  const auto stranger = mcx::ibe::sakke_issue(authority.secret, Bytes{'e', 'v', 'e'});
  check(!mcx::ibe::sakke_validate(authority.public_key, identifier, stranger), "RFC 6508: RSK of another ID");

  std::array<std::uint8_t, mcx::ibe::sakke_ssv_bytes> ssv{};
  ssv.fill(0x5a);
  const auto encapsulated = mcx::ibe::sakke_encapsulate(authority.public_key, identifier, ssv);
  check(mcx::ibe::sakke_decapsulate(authority.public_key, identifier, receiver_key, encapsulated) == ssv,
        "RFC 6508: random SSV round trip");
  rejected([&] { mcx::ibe::sakke_decapsulate(authority.public_key, Bytes{'e', 'v', 'e'}, stranger, encapsulated); },
           "RFC 6508: another identifier decapsulated");
  auto altered_hint = encapsulated;
  altered_hint.back() ^= 1;
  rejected([&] { mcx::ibe::sakke_decapsulate(authority.public_key, identifier, receiver_key, altered_hint); },
           "RFC 6508: altered H accepted");
  auto altered_point = encapsulated;
  altered_point[100] ^= 1;
  rejected([&] { mcx::ibe::sakke_decapsulate(authority.public_key, identifier, receiver_key, altered_point); },
           "RFC 6508: altered R accepted");
  rejected([&] { mcx::ibe::sakke_decapsulate(other.public_key, identifier, receiver_key, encapsulated); },
           "RFC 6508: another KMS accepted");
}

//------------------------------------------------------------------------------
// Helper: the mean time of an operation in milliseconds over the given number of runs.
template <class Operation> double milliseconds(Operation &&operation, int runs) {
  const auto start = std::chrono::steady_clock::now();
  for (int run = 0; run < runs; ++run) operation();
  const std::chrono::duration<double, std::milli> elapsed = std::chrono::steady_clock::now() - start;
  return elapsed.count() / runs;
}

//------------------------------------------------------------------------------
// The cost of each primitive (informational).
void timings() {
  const auto eccsi = mcx::ibe::eccsi_create_authority();
  const auto sakke = mcx::ibe::sakke_create_authority();
  const Bytes identifier{'u', 's', 'e', 'r'};
  const auto pair = mcx::ibe::eccsi_issue(eccsi.secret, identifier);
  const auto receiver_key = mcx::ibe::sakke_issue(sakke.secret, identifier);
  std::array<std::uint8_t, mcx::ibe::sakke_ssv_bytes> ssv{};
  const auto encapsulated = mcx::ibe::sakke_encapsulate(sakke.public_key, identifier, ssv);
  const Bytes message(200, 7);
  const auto signature = mcx::ibe::eccsi_sign(eccsi.public_key, identifier, pair, message);
  std::cout << "ECCSI sign "
            << milliseconds([&] { mcx::ibe::eccsi_sign(eccsi.public_key, identifier, pair, message); }, 20)
            << " ms, verify "
            << milliseconds([&] { mcx::ibe::eccsi_verify(eccsi.public_key, identifier, message, signature); }, 20)
            << " ms; SAKKE issue " << milliseconds([&] { mcx::ibe::sakke_issue(sakke.secret, identifier); }, 5)
            << " ms, validate "
            << milliseconds([&] { mcx::ibe::sakke_validate(sakke.public_key, identifier, receiver_key); }, 5)
            << " ms, encapsulate "
            << milliseconds([&] { mcx::ibe::sakke_encapsulate(sakke.public_key, identifier, ssv); }, 5)
            << " ms, decapsulate "
            << milliseconds(
                   [&] { mcx::ibe::sakke_decapsulate(sakke.public_key, identifier, receiver_key, encapsulated); }, 5)
            << " ms\n";
}

} // namespace

int main() {
  try {
    rfc6507_appendix_a();
    rfc6508_appendix_a();
    rfc6507_random_keys();
    rfc6508_random_keys();
    timings();
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    return 1;
  }
  std::cout << "PASS: ECCSI and SAKKE on OpenSSL\n";
  return 0;
}
