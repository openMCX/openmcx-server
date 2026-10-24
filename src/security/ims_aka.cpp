//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IMS AKA in the UE (include/mcx/ims_aka.hpp): the software ISIM around hostap's MILENAGE, its sequence numbers
// (TS 33.102 annex C.2), the HTTP Digest AKA passwords and responses, sec-agree and the ESP keys of annex I.
//
// Specifications: TS 35.206 V19.0.0 (Rel-19), TS 33.102 V19.1.0 (Rel-19), TS 33.203 V19.1.0 (Rel-19),
// TS 24.229 V19.7.0 (Rel-19), RFC 2617, RFC 3310, RFC 3329, RFC 4169, RFC 7616.

#include "mcx/ims_aka.hpp"

extern "C" {
#include "hostap/common.h"
#include "milenage.h"
}

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace mcx::aka {
namespace {
//------------------------------------------------------------------------------
// Helper: the 48-bit number of 6 bytes, most significant first (TS 33.102 clause 6.3.2: SQN is 48 bits).
std::uint64_t sqn_value(const Sqn &sqn) {
  std::uint64_t value = 0;
  for (const auto byte : sqn) value = (value << 8U) | byte;
  return value;
}

//------------------------------------------------------------------------------
// Helper: the 6 bytes of a 48-bit number, most significant first.
Sqn sqn_bytes(std::uint64_t value) {
  Sqn sqn{};
  for (std::size_t index = sqn.size(); index-- > 0;) {
    sqn[index] = static_cast<std::uint8_t>(value & 0xffU);
    value >>= 8U;
  }
  return sqn;
}

//------------------------------------------------------------------------------
// Helper: ASCII lower-case copy.
std::string lower(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return char(std::tolower(c)); });
  return out;
}

//------------------------------------------------------------------------------
// Helper: the text without leading and trailing blanks (RFC 3261 section 25.1, LWS).
std::string_view trim(std::string_view text) {
  const auto first = text.find_first_not_of(" \t\r\n");
  if (first == std::string_view::npos) return {};
  return text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}

//------------------------------------------------------------------------------
// Helper: an unsigned decimal parameter value no greater than the maximum; throws on other text.
std::uint64_t number(std::string_view text, std::uint64_t maximum, const char *what) {
  std::uint64_t value = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (text.empty() || error != std::errc{} || end != text.data() + text.size() || value > maximum)
    throw std::invalid_argument(std::string("invalid sec-mechanism ") + what);
  return value;
}

//------------------------------------------------------------------------------
// Helper: the message digest of text with an OpenSSL digest, as lower-case hexadecimal text.
std::string hash_hex(const EVP_MD *md, std::string_view text) {
  unsigned char out[EVP_MAX_MD_SIZE];
  unsigned length = 0;
  if (EVP_Digest(text.data(), text.size(), out, &length, md, nullptr) != 1)
    throw std::runtime_error("digest computation failed");
  return hex(std::span<const std::uint8_t>(out, length));
}

//------------------------------------------------------------------------------
// Helper: bytes of hexadecimal text of the given length; throws on other text.
template <std::size_t N> std::array<std::uint8_t, N> from_hex(std::string_view text) {
  if (text.size() != 2 * N) throw std::invalid_argument("hexadecimal value of the wrong length");
  std::array<std::uint8_t, N> out{};
  for (std::size_t index = 0; index < N; ++index) {
    unsigned value = 0;
    const auto *begin = text.data() + 2 * index;
    const auto [end, error] = std::from_chars(begin, begin + 2, value, 16);
    if (error != std::errc{} || end != begin + 2) throw std::invalid_argument("invalid hexadecimal value");
    out[index] = static_cast<std::uint8_t>(value);
  }
  return out;
}
} // namespace

//------------------------------------------------------------------------------
// TS 35.206 clause 4.1: f1 = MAC-A of SQN || RAND || AMF (hostap milenage_f1).
Mac Milenage::f1(const Rand &rand, const Sqn &sqn, const Amf &amf) const {
  Mac mac{};
  if (milenage_f1(opc_.data(), k_.data(), rand.data(), sqn.data(), amf.data(), mac.data(), nullptr) != 0)
    throw std::runtime_error("MILENAGE f1 failed");
  return mac;
}

//------------------------------------------------------------------------------
// TS 35.206 clause 4.1: f1* = MAC-S of SQN || RAND || AMF (hostap milenage_f1).
Mac Milenage::f1_star(const Rand &rand, const Sqn &sqn, const Amf &amf) const {
  Mac mac{};
  if (milenage_f1(opc_.data(), k_.data(), rand.data(), sqn.data(), amf.data(), nullptr, mac.data()) != 0)
    throw std::runtime_error("MILENAGE f1* failed");
  return mac;
}

//------------------------------------------------------------------------------
// TS 35.206 clause 4.1: f2 (RES), f3 (CK), f4 (IK), f5 (AK) and f5* (AK for resynchronisation) of RAND (hostap
// milenage_f2345).
Milenage2345 Milenage::f2345(const Rand &rand) const {
  Milenage2345 out;
  if (milenage_f2345(opc_.data(), k_.data(), rand.data(), out.res.data(), out.ck.data(), out.ik.data(), out.ak.data(),
                     out.ak_star.data()) != 0)
    throw std::runtime_error("MILENAGE f2-f5* failed");
  return out;
}

//------------------------------------------------------------------------------
// TS 33.102 annex C.2.1: SEQ - SEQ_MS <= delta, then annex C.2.2: SEQ > SEQ_MS(IND).
bool SequenceNumbers::fresh(std::uint64_t sqn) const noexcept {
  const std::uint64_t seq = sqn >> ind_bits;
  const std::uint64_t seq_ms = sqn_ms_ >> ind_bits;
  if (seq > seq_ms && seq - seq_ms > delta) return false;
  return seq > seq_ms_[sqn & (array_size - 1U)];
}

//------------------------------------------------------------------------------
// TS 33.102 annex C.2.2 (a): SEQ_MS(IND) = SEQ; SQN_MS stays the highest accepted sequence number.
void SequenceNumbers::accept(std::uint64_t sqn) noexcept {
  seq_ms_[sqn & (array_size - 1U)] = sqn >> ind_bits;
  sqn_ms_ = std::max(sqn_ms_, sqn);
}

//------------------------------------------------------------------------------
// Helper: the state as JSON text (the ISIM file of SoftIsim).
std::string SequenceNumbers::serialize() const {
  return nlohmann::json{{"format", "openmcx-isim-sqn-1"}, {"sqn_ms", sqn_ms_}, {"seq_ms", seq_ms_}}.dump() + "\n";
}

//------------------------------------------------------------------------------
// Helper: the state from its JSON text; throws on other text.
SequenceNumbers SequenceNumbers::parse(std::string_view text) {
  const auto json = nlohmann::json::parse(text);
  if (json.value("format", "") != "openmcx-isim-sqn-1") throw std::invalid_argument("unknown ISIM SQN file format");
  SequenceNumbers out;
  out.sqn_ms_ = json.at("sqn_ms").get<std::uint64_t>();
  const auto values = json.at("seq_ms").get<std::vector<std::uint64_t>>();
  if (values.size() != array_size) throw std::invalid_argument("ISIM SQN file: wrong array size");
  std::copy(values.begin(), values.end(), out.seq_ms_.begin());
  return out;
}

//------------------------------------------------------------------------------
// Helper: the ISIM with its keys; the sequence numbers come from the file, or start at zero (TS 33.102 annex C.2.2)
// when it does not exist.
SoftIsim::SoftIsim(const Key &k, const Key &opc, std::filesystem::path sqn_file)
    : milenage_(k, opc), sqn_file_(std::move(sqn_file)) {
  std::ifstream in(sqn_file_);
  if (!in) return;
  std::stringstream text;
  text << in.rdbuf();
  sqn_ = SequenceNumbers::parse(text.str());
}

//------------------------------------------------------------------------------
// Helper: writes the sequence numbers atomically (a new file, then rename), readable by the owner only.
void SoftIsim::save() const {
  if (sqn_file_.empty()) return;
  auto temporary = sqn_file_;
  temporary += ".tmp";
  {
    std::ofstream out(temporary, std::ios::trunc);
    out << sqn_.serialize();
    out.flush();
    if (!out) throw std::runtime_error("cannot write the ISIM SQN file " + temporary.string());
  }
  std::filesystem::permissions(temporary, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
  std::filesystem::rename(temporary, sqn_file_);
}

//------------------------------------------------------------------------------
// TS 33.102 clause 6.3.3: verifies AUTN = (SQN XOR AK) || AMF || MAC and computes RES, CK and IK, or AUTS on a
// synchronisation failure. The new sequence number is saved before the result is returned.
AuthResult SoftIsim::authenticate(const Rand &rand, const Autn &autn) {
  AuthResult result;
  const auto outputs = milenage_.f2345(rand);
  Sqn sqn{};
  for (std::size_t index = 0; index < sqn.size(); ++index) sqn[index] = autn[index] ^ outputs.ak[index];
  const Amf amf{autn[6], autn[7]};
  const auto xmac = milenage_.f1(rand, sqn, amf);
  if (os_memcmp_const(xmac.data(), autn.data() + 8, xmac.size()) != 0) {
    result.status = AuthStatus::mac_failure;
    return result;
  }
  const auto received = sqn_value(sqn);
  if (!sqn_.fresh(received)) {
    // AUTS = Conc(SQN_MS) || MAC-S, with the dummy AMF* of all zeros.
    const auto sqn_ms = sqn_bytes(sqn_.highest());
    for (std::size_t index = 0; index < sqn_ms.size(); ++index)
      result.auts[index] = sqn_ms[index] ^ outputs.ak_star[index];
    const auto mac_s = milenage_.f1_star(rand, sqn_ms, Amf{0, 0});
    std::copy(mac_s.begin(), mac_s.end(), result.auts.begin() + 6);
    result.status = AuthStatus::sync_failure;
    return result;
  }
  sqn_.accept(received);
  save();
  result.status = AuthStatus::success;
  result.res = outputs.res;
  result.ck = outputs.ck;
  result.ik = outputs.ik;
  return result;
}

//------------------------------------------------------------------------------
// RFC 3310 section 3.1 and RFC 4169 section 3: the algorithm of a challenge, case-insensitive.
std::optional<AkaAlgorithm> aka_algorithm(std::string_view name) {
  const auto value = lower(trim(name));
  if (value == "akav1-md5") return AkaAlgorithm::akav1_md5;
  if (value == "akav2-sha-256") return AkaAlgorithm::akav2_sha256;
  return std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: the algorithm's name as TS 24.229 clause 5.1.1.5.1 spells it.
std::string_view algorithm_name(AkaAlgorithm algorithm) {
  return algorithm == AkaAlgorithm::akav1_md5 ? "AKAv1-MD5" : "AKAv2-SHA-256";
}

//------------------------------------------------------------------------------
// RFC 3310 section 3.3: AKAv1 uses RES as the password; RFC 4169 section 3: AKAv2 uses
// base64(PRF(RES || IK || CK, "http-digest-akav2-password")), the PRF of AKAv2-SHA-256 being HMAC-SHA-256.
std::string digest_password(AkaAlgorithm algorithm, const AuthResult &result) {
  if (algorithm == AkaAlgorithm::akav1_md5) return std::string(result.res.begin(), result.res.end());
  std::vector<std::uint8_t> key(result.res.begin(), result.res.end());
  key.insert(key.end(), result.ik.begin(), result.ik.end());
  key.insert(key.end(), result.ck.begin(), result.ck.end());
  static constexpr std::string_view label = "http-digest-akav2-password";
  unsigned char out[EVP_MAX_MD_SIZE];
  unsigned length = 0;
  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
           reinterpret_cast<const unsigned char *>(label.data()), label.size(), out, &length) == nullptr)
    throw std::runtime_error("AKAv2 password derivation failed");
  return base64(std::span<const std::uint8_t>(out, length));
}

//------------------------------------------------------------------------------
// RFC 2617 section 3.2.2.1 and RFC 7616 section 3.4.1: KD(H(A1), nonce:nc:cnonce:qop:H(A2)) with qop, or
// KD(H(A1), nonce:H(A2)) without; A1 = username:realm:password, A2 = method:uri.
std::string digest_response(AkaAlgorithm algorithm, std::string_view username, std::string_view realm,
                            std::string_view password, std::string_view method, std::string_view uri,
                            std::string_view nonce, std::string_view nc, std::string_view cnonce,
                            std::string_view qop) {
  const EVP_MD *md = algorithm == AkaAlgorithm::akav1_md5 ? EVP_md5() : EVP_sha256();
  const auto ha1 = hash_hex(md, std::string(username) + ":" + std::string(realm) + ":" + std::string(password));
  const auto ha2 = hash_hex(md, std::string(method) + ":" + std::string(uri));
  if (qop.empty()) return hash_hex(md, ha1 + ":" + std::string(nonce) + ":" + ha2);
  return hash_hex(md, ha1 + ":" + std::string(nonce) + ":" + std::string(nc) + ":" + std::string(cnonce) + ":" +
                          std::string(qop) + ":" + ha2);
}

//------------------------------------------------------------------------------
// RFC 3310 section 3.2: RAND (16 octets) and AUTN (16 octets) are the first 32 octets of the decoded nonce.
std::optional<AkaNonce> parse_nonce(std::string_view nonce) {
  if (nonce.empty() || nonce.size() % 4 != 0 || nonce.size() > 1024) return std::nullopt;
  std::vector<unsigned char> decoded(nonce.size() / 4 * 3);
  const int length = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char *>(nonce.data()),
                                     static_cast<int>(nonce.size()));
  if (length < 0) return std::nullopt;
  // EVP_DecodeBlock keeps the bytes of the padding: they are not data.
  const auto padding = static_cast<std::size_t>(std::count(nonce.end() - 2, nonce.end(), '='));
  if (static_cast<std::size_t>(length) - padding < 32) return std::nullopt;
  AkaNonce out;
  std::copy_n(decoded.begin(), 16, out.rand.begin());
  std::copy_n(decoded.begin() + 16, 16, out.autn.begin());
  return out;
}

//------------------------------------------------------------------------------
// RFC 4648 section 4: base64 with padding.
std::string base64(std::span<const std::uint8_t> bytes) {
  std::string out(4 * ((bytes.size() + 2) / 3) + 1, '\0');
  const int length =
      EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), bytes.data(), static_cast<int>(bytes.size()));
  out.resize(static_cast<std::size_t>(length));
  return out;
}

//------------------------------------------------------------------------------
// RFC 3329 section 2.2 and TS 33.203 annex H: sec-mechanism = mechanism-name *(SEMI mech-parameters), mechanisms
// separated by commas; unknown parameters (such as those of RFC 3329's generic-param) are skipped.
std::vector<SecMechanism> parse_sec_mechanisms(std::string_view value) {
  std::vector<SecMechanism> out;
  while (!value.empty()) {
    const auto comma = value.find(',');
    const auto item = trim(value.substr(0, comma));
    value = comma == std::string_view::npos ? std::string_view{} : value.substr(comma + 1);
    if (item.empty()) continue;
    SecMechanism mechanism;
    const auto semi = item.find(';');
    mechanism.name = std::string(trim(item.substr(0, semi)));
    auto rest = semi == std::string_view::npos ? std::string_view{} : item.substr(semi + 1);
    while (!rest.empty()) {
      const auto next = rest.find(';');
      const auto part = trim(rest.substr(0, next));
      rest = next == std::string_view::npos ? std::string_view{} : rest.substr(next + 1);
      const auto equal = part.find('=');
      const auto name = lower(trim(part.substr(0, equal)));
      const auto parameter = equal == std::string_view::npos ? std::string_view{} : trim(part.substr(equal + 1));
      if (name == "q") {
        double q = 0;
        const auto [end, error] = std::from_chars(parameter.data(), parameter.data() + parameter.size(), q);
        if (parameter.empty() || error != std::errc{} || end != parameter.data() + parameter.size() || q < 0 || q > 1)
          throw std::invalid_argument("invalid sec-mechanism q");
        mechanism.q = q;
      } else if (name == "alg") {
        mechanism.alg = std::string(parameter);
      } else if (name == "ealg") {
        mechanism.ealg = std::string(parameter);
      } else if (name == "prot") {
        mechanism.prot = std::string(parameter);
      } else if (name == "mod") {
        mechanism.mod = std::string(parameter);
      } else if (name == "spi-c") {
        mechanism.spi_c = static_cast<std::uint32_t>(number(parameter, 0xffffffffU, "spi-c"));
      } else if (name == "spi-s") {
        mechanism.spi_s = static_cast<std::uint32_t>(number(parameter, 0xffffffffU, "spi-s"));
      } else if (name == "port-c") {
        mechanism.port_c = static_cast<std::uint16_t>(number(parameter, 65535, "port-c"));
      } else if (name == "port-s") {
        mechanism.port_s = static_cast<std::uint16_t>(number(parameter, 65535, "port-s"));
      }
    }
    if (mechanism.name.empty()) throw std::invalid_argument("sec-mechanism without a name");
    out.push_back(std::move(mechanism));
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 33.203 annex H in the parameter order of TS 37.579-1 table 5.5.2.13-1.
std::string format_sec_mechanism(const SecMechanism &mechanism) {
  std::ostringstream out;
  out << mechanism.name;
  if (mechanism.q) out << ";q=" << *mechanism.q;
  if (!mechanism.alg.empty()) out << ";alg=" << mechanism.alg;
  if (mechanism.ealg) out << ";ealg=" << *mechanism.ealg;
  if (mechanism.prot) out << ";prot=" << *mechanism.prot;
  if (mechanism.mod) out << ";mod=" << *mechanism.mod;
  if (mechanism.spi_c) out << ";spi-c=" << *mechanism.spi_c;
  if (mechanism.spi_s) out << ";spi-s=" << *mechanism.spi_s;
  if (mechanism.port_c) out << ";port-c=" << *mechanism.port_c;
  if (mechanism.port_s) out << ";port-s=" << *mechanism.port_s;
  return out.str();
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.2: "the UE selects the first integrity and encryption algorithm combination on the list received
// from the P-CSCF ... which is also supported by the UE. If the P-CSCF did not include any confidentiality algorithm
// ... the UE shall select the NULL encryption algorithm"; the list is ordered by q (RFC 3329 section 2.2).
std::optional<SecMechanism> select_mechanism(const std::vector<SecMechanism> &server) {
  std::vector<const SecMechanism *> ordered;
  for (const auto &mechanism : server) ordered.push_back(&mechanism);
  std::stable_sort(ordered.begin(), ordered.end(), [](const SecMechanism *left, const SecMechanism *right) {
    return left->q.value_or(0.001) > right->q.value_or(0.001);
  });
  for (const auto *mechanism : ordered) {
    if (lower(mechanism->name) != "ipsec-3gpp" || lower(mechanism->alg) != "hmac-sha-1-96") continue;
    if (mechanism->prot && lower(*mechanism->prot) != "esp") continue;
    if (mechanism->mod && lower(*mechanism->mod) != "trans") continue;
    const auto ealg = lower(mechanism->ealg.value_or("null"));
    if (ealg != "aes-cbc" && ealg != "null") continue;
    if (!mechanism->spi_c || !mechanism->spi_s || !mechanism->port_c || !mechanism->port_s) continue;
    auto chosen = *mechanism;
    chosen.alg = "hmac-sha-1-96";
    chosen.ealg = ealg;
    return chosen;
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 33.203 annex I: "If the selected authentication algorithm is HMAC-SHA-1-96 then IK_ESP is obtained from IK_IM by
// appending 32 zero bits to the end of IK_IM to create a 160-bit string."
std::vector<std::uint8_t> integrity_key_esp(std::string_view alg, const Key &ik) {
  if (lower(alg) != "hmac-sha-1-96") throw std::invalid_argument("unsupported IPsec integrity algorithm");
  std::vector<std::uint8_t> key(ik.begin(), ik.end());
  key.resize(20, 0);
  return key;
}

//------------------------------------------------------------------------------
// TS 33.203 annex I: "If selected encryption algorithm is AES-CBC ... with 128 bit key then CK_ESP = CK_IM"; the
// NULL algorithm (clause 7.2) has no key.
std::vector<std::uint8_t> encryption_key_esp(std::string_view ealg, const Key &ck) {
  const auto name = lower(ealg);
  if (name == "null") return {};
  if (name != "aes-cbc") throw std::invalid_argument("unsupported IPsec encryption algorithm");
  return {ck.begin(), ck.end()};
}

//------------------------------------------------------------------------------
// Helper: K or OPc (32 hexadecimal digits).
Key key_from_hex(std::string_view text) { return from_hex<16>(text); }

//------------------------------------------------------------------------------
// Helper: the AMF (4 hexadecimal digits).
Amf amf_from_hex(std::string_view text) { return from_hex<2>(text); }

//------------------------------------------------------------------------------
// Helper: lower-case hexadecimal text.
std::string hex(std::span<const std::uint8_t> bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    out.push_back(digits[byte >> 4U]);
    out.push_back(digits[byte & 0xfU]);
  }
  return out;
}
} // namespace mcx::aka
