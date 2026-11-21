//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Cross-check of OpenMCX's ECCSI and SAKKE (src/security/ibe.hpp, on OpenSSL) against wolfCrypt's, the
// implementation OpenMCX used before: keys, signatures and Encapsulated Data made by either are accepted by the other,
// and the deterministic results (an RSK, the Encapsulated Data of an SSV) are the same octets, so KMS secrets and key
// sets stored by earlier OpenMCX versions keep working. Then a differential test: on randomly mutated signatures and
// Encapsulated Data the two give the same verdict, a refusal.
//
// Built only when the development image provides wolfSSL (CMakeLists.txt); wolfSSL is not linked into any program.
//
// Specifications: RFC 6507, RFC 6508, RFC 6509.

#include "ibe.hpp"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/eccsi.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sakke.h>

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using mcx::ibe::Bytes;
using mcx::ibe::ByteView;
using Ssv = std::array<std::uint8_t, mcx::ibe::sakke_ssv_bytes>;

//------------------------------------------------------------------------------
// Throws the text when the condition does not hold.
void check(bool condition, const std::string &text) {
  if (!condition) throw std::runtime_error(text);
}

//------------------------------------------------------------------------------
// Throws on a non-zero wolfCrypt result.
void wolf(int result, const char *what) { check(result == 0, std::string("wolfCrypt ") + what); }

// Owned wolfCrypt objects.
struct Random {
  WC_RNG value{};

  Random() { wolf(wc_InitRng(&value), "RNG"); }

  ~Random() { wc_FreeRng(&value); }
};

struct Eccsi {
  EccsiKey value{};

  Eccsi() { wolf(wc_InitEccsiKey(&value, nullptr, INVALID_DEVID), "ECCSI key"); }

  ~Eccsi() { wc_FreeEccsiKey(&value); }
};

struct Sakke {
  SakkeKey value{};

  Sakke() { wolf(wc_InitSakkeKey(&value, nullptr, INVALID_DEVID), "SAKKE key"); }

  ~Sakke() { wc_FreeSakkeKey(&value); }
};

struct Scalar {
  mp_int value{};

  Scalar() { wolf(mp_init(&value), "scalar"); }

  ~Scalar() { mp_clear(&value); }
};

struct Point {
  ecc_point *value = wc_ecc_new_point();

  ~Point() { wc_ecc_del_point(value); }
};

//------------------------------------------------------------------------------
// wolfCrypt: a new KMS (ECCSI secret and KPAK, SAKKE secret and Z_T), in the stored forms.
std::pair<mcx::ibe::AuthorityKeys, mcx::ibe::AuthorityKeys> wolf_authority() {
  Random rng;
  Eccsi eccsi;
  Sakke sakke;
  wolf(wc_MakeEccsiKey(&eccsi.value, &rng.value), "make ECCSI key");
  wolf(wc_MakeSakkeKey(&sakke.value, &rng.value), "make SAKKE key");
  mcx::ibe::AuthorityKeys authentication{Bytes(mcx::ibe::eccsi_secret_bytes), Bytes(mcx::ibe::eccsi_point_bytes)};
  mcx::ibe::AuthorityKeys encryption{Bytes(mcx::ibe::sakke_secret_bytes), Bytes(mcx::ibe::sakke_point_bytes)};
  word32 size = authentication.secret.size();
  wolf(wc_ExportEccsiKey(&eccsi.value, authentication.secret.data(), &size), "export ECCSI key");
  size = authentication.public_key.size();
  wolf(wc_ExportEccsiPublicKey(&eccsi.value, authentication.public_key.data(), &size, 0), "export KPAK");
  size = encryption.secret.size();
  wolf(wc_ExportSakkeKey(&sakke.value, encryption.secret.data(), &size), "export SAKKE key");
  size = encryption.public_key.size();
  wolf(wc_ExportSakkePublicKey(&sakke.value, encryption.public_key.data(), &size, 0), "export Z_T");
  return {authentication, encryption};
}

//------------------------------------------------------------------------------
// wolfCrypt: the (SSK, PVT) pair of an identifier.
Bytes wolf_eccsi_issue(ByteView secret, ByteView identifier) {
  Random rng;
  Eccsi eccsi;
  Scalar ssk;
  Point pvt;
  wolf(wc_ImportEccsiKey(&eccsi.value, secret.data(), secret.size()), "import ECCSI key");
  wolf(wc_MakeEccsiPair(&eccsi.value, &rng.value, WC_HASH_TYPE_SHA256, identifier.data(), identifier.size(), &ssk.value,
                        pvt.value),
       "make ECCSI pair");
  Bytes pair(mcx::ibe::eccsi_pair_bytes);
  word32 size = pair.size();
  wolf(wc_EncodeEccsiPair(&eccsi.value, &ssk.value, pvt.value, pair.data(), &size), "encode ECCSI pair");
  return pair;
}

//------------------------------------------------------------------------------
// wolfCrypt: whether an (SSK, PVT) pair is valid.
bool wolf_eccsi_validate(ByteView kpak, ByteView identifier, ByteView pair) {
  Eccsi eccsi;
  Scalar ssk;
  Point pvt;
  wolf(wc_ImportEccsiPublicKey(&eccsi.value, kpak.data(), kpak.size(), 0), "import KPAK");
  wolf(wc_DecodeEccsiPair(&eccsi.value, pair.data(), pair.size(), &ssk.value, pvt.value), "decode ECCSI pair");
  int valid = 0;
  wolf(wc_ValidateEccsiPair(&eccsi.value, WC_HASH_TYPE_SHA256, identifier.data(), identifier.size(), &ssk.value,
                            pvt.value, &valid),
       "validate ECCSI pair");
  return valid == 1;
}

//------------------------------------------------------------------------------
// wolfCrypt: the HS of a PVT set on a key.
void wolf_identity_hash(Eccsi &eccsi, ByteView identifier, ecc_point *pvt) {
  std::array<std::uint8_t, 32> hash{};
  byte length = hash.size();
  wolf(wc_HashEccsiId(&eccsi.value, WC_HASH_TYPE_SHA256, identifier.data(), identifier.size(), pvt, hash.data(),
                      &length),
       "ECCSI HS");
  wolf(wc_SetEccsiHash(&eccsi.value, hash.data(), length), "set ECCSI HS");
}

//------------------------------------------------------------------------------
// wolfCrypt: an ECCSI signature.
Bytes wolf_eccsi_sign(ByteView kpak, ByteView identifier, ByteView pair, ByteView message) {
  Random rng;
  Eccsi eccsi;
  Scalar ssk;
  Point pvt;
  wolf(wc_ImportEccsiPublicKey(&eccsi.value, kpak.data(), kpak.size(), 0), "import KPAK");
  wolf(wc_DecodeEccsiPair(&eccsi.value, pair.data(), pair.size(), &ssk.value, pvt.value), "decode ECCSI pair");
  wolf_identity_hash(eccsi, identifier, pvt.value);
  wolf(wc_SetEccsiPair(&eccsi.value, &ssk.value, pvt.value), "set ECCSI pair");
  Bytes signature(mcx::ibe::eccsi_signature_bytes);
  word32 size = signature.size();
  wolf(wc_SignEccsiHash(&eccsi.value, &rng.value, WC_HASH_TYPE_SHA256, message.data(), message.size(), signature.data(),
                        &size),
       "ECCSI sign");
  return signature;
}

//------------------------------------------------------------------------------
// wolfCrypt: whether an ECCSI signature is valid.
bool wolf_eccsi_verify(ByteView kpak, ByteView identifier, ByteView message, ByteView signature) {
  Eccsi eccsi;
  Point pvt;
  wolf(wc_ImportEccsiPublicKey(&eccsi.value, kpak.data(), kpak.size(), 0), "import KPAK");
  wolf(wc_DecodeEccsiPvtFromSig(&eccsi.value, signature.data(), signature.size(), pvt.value), "signature PVT");
  wolf_identity_hash(eccsi, identifier, pvt.value);
  int valid = 0;
  wolf(wc_VerifyEccsiHash(&eccsi.value, WC_HASH_TYPE_SHA256, message.data(), message.size(), signature.data(),
                          signature.size(), &valid),
       "ECCSI verify");
  return valid == 1;
}

//------------------------------------------------------------------------------
// wolfCrypt: the RSK of an identifier.
Bytes wolf_sakke_issue(ByteView secret, ByteView identifier) {
  Sakke sakke;
  Point rsk;
  wolf(wc_ImportSakkeKey(&sakke.value, secret.data(), secret.size()), "import SAKKE key");
  wolf(wc_MakeSakkeRsk(&sakke.value, identifier.data(), identifier.size(), rsk.value), "make RSK");
  Bytes out(mcx::ibe::sakke_point_bytes);
  word32 size = out.size();
  wolf(wc_EncodeSakkeRsk(&sakke.value, rsk.value, out.data(), &size, 0), "encode RSK");
  return out;
}

//------------------------------------------------------------------------------
// wolfCrypt: whether an RSK is valid.
bool wolf_sakke_validate(ByteView public_key, ByteView identifier, ByteView receiver_key) {
  Sakke sakke;
  Point rsk;
  wolf(wc_ImportSakkePublicKey(&sakke.value, public_key.data(), public_key.size(), 0), "import Z_T");
  wolf(wc_DecodeSakkeRsk(&sakke.value, receiver_key.data(), receiver_key.size(), rsk.value), "decode RSK");
  int valid = 0;
  wolf(wc_ValidateSakkeRsk(&sakke.value, identifier.data(), identifier.size(), rsk.value, &valid), "validate RSK");
  return valid == 1;
}

//------------------------------------------------------------------------------
// wolfCrypt: the Encapsulated Data of an SSV.
Bytes wolf_sakke_encapsulate(ByteView public_key, ByteView identifier, const Ssv &ssv) {
  Sakke sakke;
  wolf(wc_ImportSakkePublicKey(&sakke.value, public_key.data(), public_key.size(), 0), "import Z_T");
  wolf(wc_SetSakkeIdentity(&sakke.value, identifier.data(), identifier.size()), "SAKKE identity");
  Bytes out(mcx::ibe::sakke_encapsulated_bytes);
  std::copy(ssv.begin(), ssv.end(), out.begin() + mcx::ibe::sakke_point_bytes);
  word16 size = mcx::ibe::sakke_point_bytes;
  wolf(wc_MakeSakkeEncapsulatedSSV(&sakke.value, WC_HASH_TYPE_SHA256, out.data() + mcx::ibe::sakke_point_bytes,
                                   ssv.size(), out.data(), &size),
       "SAKKE encapsulate");
  return out;
}

//------------------------------------------------------------------------------
// wolfCrypt: the SSV of Encapsulated Data.
Ssv wolf_sakke_decapsulate(ByteView public_key, ByteView identifier, ByteView receiver_key, ByteView encapsulated) {
  Sakke sakke;
  Point rsk;
  wolf(wc_ImportSakkePublicKey(&sakke.value, public_key.data(), public_key.size(), 0), "import Z_T");
  wolf(wc_SetSakkeIdentity(&sakke.value, identifier.data(), identifier.size()), "SAKKE identity");
  wolf(wc_DecodeSakkeRsk(&sakke.value, receiver_key.data(), receiver_key.size(), rsk.value), "decode RSK");
  wolf(wc_SetSakkeRsk(&sakke.value, rsk.value, nullptr, 0), "set RSK");
  Ssv ssv{};
  std::copy(encapsulated.begin() + mcx::ibe::sakke_point_bytes, encapsulated.end(), ssv.begin());
  wolf(wc_DeriveSakkeSSV(&sakke.value, WC_HASH_TYPE_SHA256, ssv.data(), ssv.size(), encapsulated.data(),
                         mcx::ibe::sakke_point_bytes),
       "SAKKE decapsulate");
  return ssv;
}

//------------------------------------------------------------------------------
// ECCSI both ways under one KMS: pairs issued by either validate in both, signatures by either verify in both.
void eccsi_cross(const mcx::ibe::AuthorityKeys &authority, ByteView identifier, const std::string &label) {
  const Bytes message{'M', 'I', 'K', 'E', 'Y'};
  const auto own_pair = mcx::ibe::eccsi_issue(authority.secret, identifier);
  const auto wolf_pair = wolf_eccsi_issue(authority.secret, identifier);
  check(wolf_eccsi_validate(authority.public_key, identifier, own_pair),
        label + ": wolfCrypt validates OpenMCX's pair");
  check(mcx::ibe::eccsi_validate(authority.public_key, identifier, wolf_pair),
        label + ": OpenMCX validates wolfCrypt's pair");
  for (const auto *pair : {&own_pair, &wolf_pair}) {
    const auto own_signature = mcx::ibe::eccsi_sign(authority.public_key, identifier, *pair, message);
    const auto wolf_signature = wolf_eccsi_sign(authority.public_key, identifier, *pair, message);
    check(wolf_eccsi_verify(authority.public_key, identifier, message, own_signature),
          label + ": wolfCrypt verifies OpenMCX's signature");
    check(mcx::ibe::eccsi_verify(authority.public_key, identifier, message, wolf_signature),
          label + ": OpenMCX verifies wolfCrypt's signature");
  }
}

//------------------------------------------------------------------------------
// SAKKE both ways under one KMS: the RSKs are the same octets and validate in both; the Encapsulated Data of an SSV
// are the same octets and decapsulate in both.
void sakke_cross(const mcx::ibe::AuthorityKeys &authority, ByteView identifier, const std::string &label) {
  const auto own_key = mcx::ibe::sakke_issue(authority.secret, identifier);
  check(own_key == wolf_sakke_issue(authority.secret, identifier), label + ": the same RSK");
  check(wolf_sakke_validate(authority.public_key, identifier, own_key), label + ": wolfCrypt validates the RSK");
  check(mcx::ibe::sakke_validate(authority.public_key, identifier, own_key), label + ": OpenMCX validates the RSK");

  Ssv ssv{};
  for (std::size_t index = 0; index < ssv.size(); ++index) ssv[index] = static_cast<std::uint8_t>(17 * index + 3);
  const auto own_data = mcx::ibe::sakke_encapsulate(authority.public_key, identifier, ssv);
  check(own_data == wolf_sakke_encapsulate(authority.public_key, identifier, ssv),
        label + ": the same Encapsulated Data");
  check(wolf_sakke_decapsulate(authority.public_key, identifier, own_key, own_data) == ssv,
        label + ": wolfCrypt decapsulates");
  check(mcx::ibe::sakke_decapsulate(authority.public_key, identifier, own_key, own_data) == ssv,
        label + ": OpenMCX decapsulates");
}

//------------------------------------------------------------------------------
// Helper: whether wolfCrypt verifies a signature (a wolfCrypt error is a refusal).
bool wolf_accepts_signature(ByteView kpak, ByteView identifier, ByteView message, ByteView signature) {
  try {
    return wolf_eccsi_verify(kpak, identifier, message, signature);
  } catch (const std::exception &) {
    // wolfCrypt refused to decode the input: not verified.
    return false;
  }
}

//------------------------------------------------------------------------------
// Helper: whether an implementation's decapsulation returns an SSV (an exception is a refusal).
template <class Decapsulate> bool decapsulates(Decapsulate &&decapsulate) {
  try {
    decapsulate();
    return true;
  } catch (const std::exception &) {
    // refused
    return false;
  }
}

// A fixed-seed xorshift generator for the differential mutations: reproducible, not for keys.
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
  std::uint64_t state_ = 0x2545f4914f6cdd1dULL;
};

// The rounds of the differential mutations: ECCSI is fast, SAKKE decapsulation takes milliseconds in each.
constexpr int eccsi_differential_rounds = 3000;
constexpr int sakke_differential_rounds = 60;

//------------------------------------------------------------------------------
// RFC 6507 section 5.2.2: on mutated signatures, messages and identifiers OpenMCX and wolfCrypt give the same verdict,
// and neither verifies a mutated input.
void eccsi_differential(MutationSource &source) {
  const auto authority = mcx::ibe::eccsi_create_authority();
  const Bytes identifier{'s', 'i', 'p', ':', 'a'};
  const Bytes message{'m', 'e', 's', 's', 'a', 'g', 'e'};
  const auto pair = mcx::ibe::eccsi_issue(authority.secret, identifier);
  const auto signature = mcx::ibe::eccsi_sign(authority.public_key, identifier, pair, message);
  for (int round = 0; round < eccsi_differential_rounds; ++round) {
    auto altered_signature = signature;
    auto altered_message = message;
    auto altered_identifier = identifier;
    switch (source.below(4)) {
    case 0:
      altered_signature[source.below(signature.size())] ^= static_cast<std::uint8_t>(1U << source.below(8));
      break;
    case 1:
      for (auto &octet : altered_signature) octet = source.octet();
      break;
    case 2: altered_message[source.below(message.size())] ^= 1; break;
    default: altered_identifier[source.below(identifier.size())] ^= 1; break;
    }
    const bool own =
        mcx::ibe::eccsi_verify(authority.public_key, altered_identifier, altered_message, altered_signature);
    const bool reference =
        wolf_accepts_signature(authority.public_key, altered_identifier, altered_message, altered_signature);
    check(own == reference, "ECCSI differential: OpenMCX and wolfCrypt disagree in round " + std::to_string(round));
    check(!own, "ECCSI differential: a mutated input verified in round " + std::to_string(round));
  }
}

//------------------------------------------------------------------------------
// RFC 6508 section 6.2.2: on mutated Encapsulated Data OpenMCX and wolfCrypt give the same verdict, and neither
// decapsulates a mutated input.
void sakke_differential(MutationSource &source) {
  const auto authority = mcx::ibe::sakke_create_authority();
  const Bytes identifier{'s', 'i', 'p', ':', 'b'};
  const auto receiver_key = mcx::ibe::sakke_issue(authority.secret, identifier);
  Ssv ssv{};
  for (auto &octet : ssv) octet = source.octet();
  const auto encapsulated = mcx::ibe::sakke_encapsulate(authority.public_key, identifier, ssv);
  for (int round = 0; round < sakke_differential_rounds; ++round) {
    auto altered = encapsulated;
    if (source.below(2) == 0)
      altered[source.below(altered.size())] ^= static_cast<std::uint8_t>(1U << source.below(8));
    else
      for (std::size_t index = mcx::ibe::sakke_point_bytes; index < altered.size(); ++index)
        altered[index] = source.octet();
    const bool own =
        decapsulates([&] { mcx::ibe::sakke_decapsulate(authority.public_key, identifier, receiver_key, altered); });
    const bool reference =
        decapsulates([&] { wolf_sakke_decapsulate(authority.public_key, identifier, receiver_key, altered); });
    check(own == reference, "SAKKE differential: OpenMCX and wolfCrypt disagree in round " + std::to_string(round));
    check(!own, "SAKKE differential: mutated Encapsulated Data decapsulated in round " + std::to_string(round));
  }
}

} // namespace

int main() {
  try {
    // TS 33.180 annex F.2.1.1: OpenMCX's UID text form (44 base64 characters) and the raw 32 octets.
    const std::string text_uid = "OoH7FMOx0P5DycV3EE1VptgXiL/S8JdDxFV3RqWgNTs=";
    const ByteView text_identifier{reinterpret_cast<const std::uint8_t *>(text_uid.data()), text_uid.size()};
    Bytes raw_identifier(32);
    for (std::size_t index = 0; index < raw_identifier.size(); ++index)
      raw_identifier[index] = static_cast<std::uint8_t>(0xff - 7 * index);

    const auto [wolf_eccsi, wolf_sakke] = wolf_authority();
    const auto own_eccsi = mcx::ibe::eccsi_create_authority();
    const auto own_sakke = mcx::ibe::sakke_create_authority();
    for (const auto &[identifier, name] : {std::pair<ByteView, std::string>{text_identifier, "text UID"},
                                           std::pair<ByteView, std::string>{raw_identifier, "raw UID"}}) {
      eccsi_cross(wolf_eccsi, identifier, name + ", wolfCrypt KMS");
      eccsi_cross(own_eccsi, identifier, name + ", OpenMCX KMS");
      sakke_cross(wolf_sakke, identifier, name + ", wolfCrypt KMS");
      sakke_cross(own_sakke, identifier, name + ", OpenMCX KMS");
    }
    MutationSource source;
    eccsi_differential(source);
    sakke_differential(source);
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    return 1;
  }
  std::cout << "PASS: OpenMCX and wolfCrypt ECCSI and SAKKE agree\n";
  return 0;
}
