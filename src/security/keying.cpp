//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MIKEY-SAKKE keying: the MC key periods and UIDs, KMS authority and user key issue, ECCSI signatures, SAKKE key
// encapsulation, MIKEY-SAKKE I_MESSAGEs with the key parameters extension, and the MCData protected and
// authenticated payloads.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 3830, RFC 6043, RFC 6509, RFC 6507,
// RFC 6508, RFC 5116.
#include "mcx/keying.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/eccsi.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sakke.h>

#include <algorithm>
#include <ctime>
#include <limits>
#include <memory>
#include <stdexcept>

namespace mcx::keying {
namespace {
//------------------------------------------------------------------------------
// Helper: throws the given error when a condition fails.
void require(bool ok, const char *what) {
  if (!ok) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Helper: throws on a non-zero wolfCrypt result.
void checked(int result, const char *what) {
  if (result != 0) throw std::runtime_error(std::string(what) + ": " + std::to_string(result));
}

//------------------------------------------------------------------------------
// Helper: an owned wolfCrypt random number generator.
struct Random {
  WC_RNG value{};

  Random() { checked(wc_InitRng(&value), "initialize crypto RNG"); }

  ~Random() { wc_FreeRng(&value); }
};

//------------------------------------------------------------------------------
// Helper: an owned wolfCrypt ECCSI key (RFC 6507).
struct Eccsi {
  EccsiKey value{};

  Eccsi() { checked(wc_InitEccsiKey(&value, nullptr, INVALID_DEVID), "initialize ECCSI"); }

  ~Eccsi() { wc_FreeEccsiKey(&value); }
};

//------------------------------------------------------------------------------
// Helper: an owned wolfCrypt SAKKE key (RFC 6508).
struct Sakke {
  SakkeKey value{};

  Sakke() { checked(wc_InitSakkeKey(&value, nullptr, INVALID_DEVID), "initialize SAKKE"); }

  ~Sakke() { wc_FreeSakkeKey(&value); }
};

//------------------------------------------------------------------------------
// Helper: an owned multi-precision integer, wiped when freed.
struct Scalar {
  mp_int value{};

  Scalar() { checked(mp_init(&value), "initialize scalar"); }

  ~Scalar() {
    mp_forcezero(&value);
    mp_clear(&value);
  }
};

//------------------------------------------------------------------------------
// Helper: an owned elliptic curve point.
struct Point {
  ecc_point *value = wc_ecc_new_point();

  Point() { require(value != nullptr, "allocate EC point"); }

  ~Point() { wc_ecc_del_point(value); }
};

//------------------------------------------------------------------------------
// Helper: the bytes of a string.
const byte *bytes(std::string_view text) { return reinterpret_cast<const byte *>(text.data()); }

//------------------------------------------------------------------------------
// Helper: appends a value as a big-endian integer of the given width in octets.
void integer(Bytes &out, std::uint64_t value, unsigned width) {
  for (unsigned remaining = width; remaining != 0; --remaining)
    out.push_back(static_cast<byte>(value >> ((remaining - 1) * 8)));
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.2.1.1: an integer parameter Pn in the fewest octets, then its 2-octet length Ln (the encoding of
// TS 33.220 annex B).
void minimal_integer(Bytes &out, std::uint64_t value) {
  unsigned width = 1;
  for (auto rest = value >> 8; rest != 0; rest >>= 8) ++width;
  integer(out, value, width);
  integer(out, width, 2);
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.2.1.1: a string parameter Pn, then its 2-octet length Ln (TS 33.220 annex B).
void string_parameter(Bytes &out, std::string_view text) {
  require(!text.empty() && text.size() <= 65535 && text.find('\0') == text.npos,
          "invalid identity length or embedded NUL");
  out.insert(out.end(), text.begin(), text.end());
  integer(out, text.size(), 2);
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.2.1.1: the current key period number P5 = Floor((TIME - P4) / P3).
std::uint64_t period_number(const Period &period, std::uint64_t time) {
  require(period.seconds != 0 && period.offset < period.seconds && time >= period.offset && !period.kms_uri.empty(),
          "invalid KMS period");
  return (time - period.offset) / period.seconds;
}

//------------------------------------------------------------------------------
// Helper: the identity keys must be those of the key period of the given time.
void check_identity_period(const PublicParameters &parameters, const IdentityKeys &id, std::uint64_t time) {
  require(id.period_number == period_number(parameters.period, time), "identity key period mismatch");
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.5: imports the KMS Public Authentication Key (KPAK of RFC 6507) of the KMS certificate.
void public_auth(Eccsi &key, const PublicParameters &parameters) {
  require(parameters.authentication_key.size() == 65, "invalid KMS authentication key length");
  checked(wc_ImportEccsiPublicKey(&key.value, parameters.authentication_key.data(),
                                  static_cast<word32>(parameters.authentication_key.size()), 0),
          "import KMS authentication key");
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.5: imports the KMS Public Confidentiality Key (Z_T of RFC 6508) of the KMS certificate.
void public_enc(Sakke &key, const PublicParameters &parameters) {
  require(parameters.encryption_key.size() == 257, "invalid KMS encryption key length");
  checked(wc_ImportSakkePublicKey(&key.value, parameters.encryption_key.data(),
                                  static_cast<word32>(parameters.encryption_key.size()), 0),
          "import KMS encryption key");
}

//------------------------------------------------------------------------------
// RFC 6507: sets the hash HS of the KPAK, the identity (UID) and the PVT for signing and verification.
void identity_hash(Eccsi &key, std::string_view id, ecc_point *pvt) {
  std::array<byte, 32> hash{};
  byte length = hash.size();
  checked(wc_HashEccsiId(&key.value, WC_HASH_TYPE_SHA256, bytes(id), id.size(), pvt, hash.data(), &length),
          "ECCSI identity hash");
  checked(wc_SetEccsiHash(&key.value, hash.data(), length), "set ECCSI identity hash");
}

//------------------------------------------------------------------------------
// Helper: decodes the SSK and PVT (RFC 6507) of the identity keys.
void import_pair(Eccsi &key, const IdentityKeys &id, Scalar &scalar, Point &point) {
  require(id.signing_pair.size() == 96, "invalid ECCSI signing pair length");
  checked(wc_DecodeEccsiPair(&key.value, id.signing_pair.data(), id.signing_pair.size(), &scalar.value, point.value),
          "decode ECCSI signing pair");
}

//------------------------------------------------------------------------------
// Helper: serialises key material through a wolfCrypt export function into a buffer of the given capacity.
template <class Serialize> Bytes export_key(std::size_t capacity, Serialize &&serialize) {
  Bytes result(capacity);
  word32 length = result.size();
  checked(serialize(result.data(), &length), "serialize key material");
  require(length <= result.size(), "invalid exported key size");
  result.resize(length);
  return result;
}

//------------------------------------------------------------------------------
// Helper: a bounds-checked reader of big-endian MIKEY and payload fields.
struct Reader {
  std::span<const byte> data;
  std::size_t position = 0;

  std::uint64_t number(unsigned count) {
    require(count <= 8 && count <= data.size() - position, "truncated MIKEY");
    std::uint64_t value = 0;
    while (count--) value = (value << 8) | data[position++];
    return value;
  }

  std::span<const byte> take(std::size_t count) {
    require(count <= data.size() - position, "truncated MIKEY");
    auto value = data.subspan(position, count);
    position += count;
    return value;
  }

  // RFC 3830 section 6.1, RFC 6509 section 4.1 and TS 33.180 annex E.1.2: the HDR of a MIKEY-SAKKE I_MESSAGE
  // (version 1, data type 26, next payload T) with CS# 0 and CS ID map type 1; returns the CSB-ID. The V bit "MUST
  // be set to '0' and ignored by the Responder" (RFC 6509 section 4.1). PRF func 1 (PRF-HMAC-SHA-256, the one
  // TS 33.180 annex E.1.2 makes mandatory) is the only one implemented.
  // Not implemented: CS# > 0 with GENERIC-ID (TS 33.180 annex E.1.2, RFC 6043 section 6.1.2) and a Security
  // Properties payload; they are refused.
  std::uint32_t mikey_header() {
    require(number(1) == 1 && number(1) == 26 && number(1) == 5, "unsupported MIKEY header");
    require((number(1) & 0x7f) == 1, "unsupported MIKEY PRF function");
    const auto csb_id = static_cast<std::uint32_t>(number(4));
    require(number(1) == 0 && number(1) == 1, "unsupported MIKEY session map");
    return csb_id;
  }

  // RFC 3830 section 6.6 and TS 33.180 annex E.1.2: the T payload (next payload RAND), TS type NTP-UTC (0), 64 bits;
  // returns its 32-bit seconds field (ntp_from_wire gives the era), the fraction is not used.
  std::uint32_t timestamp() {
    require(number(1) == 11 && number(1) == 0, "unsupported MIKEY timestamp");
    const auto seconds = static_cast<std::uint32_t>(number(4));
    (void)number(4);
    return seconds;
  }

  // RFC 3830 section 6.11: the RAND payload (next payload IDR), of variable length: "RAND len ... SHOULD be at least
  // 16" (a SHOULD, not a MUST): a shorter RAND of at least one octet is read, and KeyClient logs a warning for it.
  std::span<const byte> random() {
    require(number(1) == 14, "unsupported MIKEY RAND");
    const auto length = number(1);
    require(length >= 1, "empty MIKEY RAND");
    return take(length);
  }

  // RFC 6043 section 6.6: an IDR payload with the expected next payload and role and ID type URI (1).
  std::string identity(byte expected_role, byte expected_next) {
    require(number(1) == expected_next && number(1) == expected_role && number(1) == 1,
            "unsupported MIKEY identity payload");
    auto value = take(number(2));
    return {reinterpret_cast<const char *>(value.data()), value.size()};
  }
};

//------------------------------------------------------------------------------
// RFC 6043 section 6.6 and TS 33.180 annex E.1.2: an IDR payload with the next payload, the ID role (IDRi, IDRr,
// IDRkmsi or IDRkmsr) and ID type URI (1).
void id_payload(Bytes &out, byte next, byte role, std::string_view identity) {
  require(!identity.empty() && identity.size() <= 65535 && identity.find('\0') == identity.npos,
          "invalid MIKEY identity");
  out.insert(out.end(), {next, role, 1});
  integer(out, identity.size(), 2);
  out.insert(out.end(), identity.begin(), identity.end());
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.1: an LV-E element (2-octet length, then the value).
void length_string(Bytes &out, std::string_view text) {
  require(text.size() <= 65535, "oversized key property");
  integer(out, text.size(), 2);
  out.insert(out.end(), text.begin(), text.end());
}

//------------------------------------------------------------------------------
// TS 33.180 table E.6.11-1: the key types whose Key Parameters are written and read: GMK (0), CSK (2), MSCCK (5) and
// MuSiK (6); and annex E.6.1 NOTE: the MC Group IDs are present for a GMK, an MKFC (4) or a MuSiK.
bool supported_type(unsigned type) { return type == 0 || type == 2 || type == 5 || type == 6; }
bool carries_groups(unsigned type) { return type == 0 || type == 4 || type == 6; }

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.1 (table E.6.1-1): the Key Parameters payload: Key Type (annex E.6.11), Status (annex E.6.9),
// Activation Time (annex E.6.4), Expiry Time (annex E.6.10), Text (annex E.6.5) and, for a GMK, the MC Group IDs
// (annex E.6.3, each an MCData group ID IE of TS 24.282 clause 15.2.14).
Bytes encode_properties(const KeyProperties &properties, const KeyParameterWireProfile &profile) {
  require(supported_type(properties.type) && properties.activation_unix_seconds <= 0xffffffffffULL &&
              properties.expiry_unix_seconds <= 0xffffffffffULL,
          "unsupported key properties");
  require(carries_groups(properties.type) || properties.groups.empty(), "key type must not carry group IDs");
  require(properties.groups.size() <= 255, "too many group IDs");

  Bytes content{properties.type};
  integer(content, properties.status, 4);
  integer(content, properties.activation_unix_seconds, 5);
  integer(content, properties.expiry_unix_seconds, 5);
  length_string(content, properties.text);
  if (carries_groups(properties.type)) {
    Bytes groups{static_cast<byte>(properties.groups.size())};
    for (const auto &group : properties.groups) {
      require(!group.empty(), "empty group ID");
      groups.push_back(0x7b);
      length_string(groups, group);
    }
    require(groups.size() <= 65535, "oversized group IDs");
    integer(content, groups.size(), 2);
    content.insert(content.end(), groups.begin(), groups.end());
  }

  require(content.size() <= 65535, "oversized key properties");
  Bytes output{profile.key_parameters_iei};
  integer(output, content.size(), 2);
  output.insert(output.end(), content.begin(), content.end());
  return output;
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.1 (table E.6.1-1): reads a Key Parameters payload: every Key Type of table E.6.11-1, the MC
// Group IDs for a GMK, MKFC or MuSiK only (annex E.6.3), and any Reserved IEs (TLV-E, annex E.6.6, "outside of scope
// of the present document") skipped.
KeyProperties decode_properties(std::span<const byte> data, const KeyParameterWireProfile &profile) {
  Reader reader{data};
  require(reader.number(1) == profile.key_parameters_iei, "unexpected Key Parameters IEI");
  auto length = reader.number(2);
  require(length == data.size() - reader.position, "invalid Key Parameters length");

  KeyProperties properties;
  properties.type = reader.number(1);
  // TS 33.180 table E.6.11-1: GMK 0, PCK 1, CSK 2, SPK 3, MKFC 4, MSCCK 5, MuSiK 6; "All other values are reserved".
  require(properties.type <= 6, "reserved key type");
  properties.status = reader.number(4);
  properties.activation_unix_seconds = reader.number(5);
  properties.expiry_unix_seconds = reader.number(5);
  auto text = reader.take(reader.number(2));
  properties.text.assign(reinterpret_cast<const char *>(text.data()), text.size());

  if (carries_groups(properties.type)) {
    Reader groups{reader.take(reader.number(2))};
    const auto count = groups.number(1);
    for (std::size_t index = 0; index < count; ++index) {
      require(groups.number(1) == 0x7b, "unexpected MC group ID IEI");
      auto group = groups.take(groups.number(2));
      require(!group.empty(), "empty group ID");
      properties.groups.emplace_back(reinterpret_cast<const char *>(group.data()), group.size());
    }
    require(groups.position == groups.data.size(), "trailing MC group IDs");
  }
  while (reader.position < data.size()) {
    (void)reader.number(1);
    (void)reader.take(reader.number(2));
  }
  return properties;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.3 and annex F.1.5: the KDF of TS 33.220 annex B keyed with the DPPK, FC = 0x53,
// P0 = DPPK-ID: its full 256-bit output.
std::array<byte, 32> payload_kdf(std::span<const byte, 16> dppk, std::uint32_t dppk_id) {
  Bytes input{0x53};
  integer(input, dppk_id, 4);
  integer(input, 4, 2);
  std::array<byte, 32> hash{};
  unsigned size = hash.size();
  require(HMAC(EVP_sha256(), dppk.data(), dppk.size(), input.data(), input.size(), hash.data(), &size) != nullptr &&
              size == 32,
          "key parameter KDF failed");
  return hash;
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.5: the DPCK of a DPPK and DPPK-ID: "Where the DPPK is 128-bits, the DPCK shall be 128-bits and
// hence the 128 least significant bits of the 256 bits of the KDF output shall be used"; for the CSK protecting
// MCData signalling with DP_AES_256_GCM, "the output DPCK shall be 256-bits and hence the entire output of the KDF
// shall be used" (last paragraph).
Bytes payload_key(std::span<const byte, 16> dppk, std::uint32_t dppk_id, PayloadAlgorithm algorithm) {
  auto hash = payload_kdf(dppk, dppk_id);
  Bytes result = algorithm == PayloadAlgorithm::aes_256_gcm ? Bytes(hash.begin(), hash.end())
                                                            : Bytes(hash.begin() + 16, hash.end());
  OPENSSL_cleanse(hash.data(), hash.size());
  return result;
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.5 and annex G: DP_AES_256_GCM has a key only for the CSK (purpose tag 2) protecting MCData
// signalling; every other DPPK is 16 octets (annex E.1.1) and gives a 128-bit DPCK.
void require_256_key(std::uint32_t dppk_id) {
  require((dppk_id >> 28) == 2, "DP_AES_256_GCM is for MCData signalling under the CSK only (TS 33.180 annex F.1.5)");
}

//------------------------------------------------------------------------------
// TS 33.180 tables 8.5.4.2-1 and 8.5.4.2-2: AEAD_AES_128_GCM or AEAD_AES_256_GCM (RFC 5116).
const EVP_CIPHER *payload_cipher(PayloadAlgorithm algorithm) {
  return algorithm == PayloadAlgorithm::aes_256_gcm ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.1: the Key Parameters in a Protected Payload message (clause 8.5.4) under the encapsulated key,
// with Payload ID and Payload sequence number 0 and the DPPK-ID equal to the CSB-ID.
Bytes encrypt_properties(const KeyMessage &key, const KeyParameterWireProfile &profile) {
  require(key.ntp_seconds >= 2208988800ULL, "invalid key properties creation time");
  require(key.properties.has_value(), "missing key properties");
  require(key.properties->type == (key.csb_id >> 28), "key type disagrees with CSB-ID purpose");
  ProtectedPayload message{profile.message_type,
                           key.ntp_seconds - 2208988800ULL,
                           0,
                           0,
                           key.csb_id,
                           encode_properties(*key.properties, profile)};
  auto output = seal_payload(message, key.key, profile);
  OPENSSL_cleanse(message.plain.data(), message.plain.size());
  return output;
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.1: opens the Protected Payload of the key parameters; the DPPK-ID must be the CSB-ID and the
// key type must agree with the purpose tag of the CSB-ID (annex G). Its Date and Time is not compared with the MIKEY
// timestamp: annex E.6.1 does not ask for it.
KeyProperties decrypt_properties(const KeyMessage &key, std::span<const byte> data,
                                 const KeyParameterWireProfile &profile) {
  require(!data.empty() && data[0] == profile.message_type, "unexpected protected payload type");
  require(payload_key_id(data) == key.csb_id, "key properties CSB-ID mismatch");
  auto message = open_payload(data, key.key, profile);
  auto properties = decode_properties(message.plain, profile);
  OPENSSL_cleanse(message.plain.data(), message.plain.size());
  require(properties.type == (key.csb_id >> 28), "key type disagrees with CSB-ID purpose");
  return properties;
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.180 clauses 8.5.4.1 (table 8.5.4.1-1) and 8.5.4.2 (DP_AES_128_GCM, table 8.5.4.2-1): Message Type, Date and
// Time (5), Payload ID (4), Payload sequence number (1), Payload algorithm (1), IV (16), DPPK-ID (4), then the
// ciphertext and GCM tag in a TLV-E. The associated data is every field before it.
Bytes seal_payload(const ProtectedPayload &message, std::span<const byte, 16> dppk,
                   const KeyParameterWireProfile &profile) {
  require(message.unix_seconds <= 0xffffffffffULL, "protected payload time out of range");
  // DP_AES_128_GCM is the profile's algorithm 1; DP_AES_256_GCM needs the profile's code for it and a CSK. Both use
  // the 16-octet IV field of table 8.5.4.1-1 (table 8.5.4.2-2 gives DP_AES_256_GCM a 256-bit IV, which that field
  // cannot hold; reported as a spec defect).
  require(profile.algorithm == 1, "only DP_AES_128_GCM is supported as the profile's algorithm 1");
  const bool aes_256 = message.algorithm == PayloadAlgorithm::aes_256_gcm;
  if (aes_256) {
    require(profile.algorithm_256 && *profile.algorithm_256 != profile.algorithm,
            "the wire profile names no code for DP_AES_256_GCM");
    require_256_key(message.dppk_id);
  }

  auto dpck = payload_key(dppk, message.dppk_id, message.algorithm);
  Bytes output{message.message_type};
  integer(output, message.unix_seconds, 5);
  integer(output, message.payload_id, 4);
  output.push_back(message.sequence);
  output.push_back(aes_256 ? *profile.algorithm_256 : profile.algorithm);
  std::array<byte, 16> iv{};
  require(RAND_bytes(iv.data(), iv.size()) == 1, "IV generation failed");
  output.insert(output.end(), iv.begin(), iv.end());
  integer(output, message.dppk_id, 4);

  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  require(bool(ctx), "allocate AES-GCM context");
  int length = 0;
  require(EVP_EncryptInit_ex(ctx.get(), payload_cipher(message.algorithm), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, dpck.data(), iv.data()) == 1 &&
              EVP_EncryptUpdate(ctx.get(), nullptr, &length, output.data(), output.size()) == 1,
          "initialize payload encryption");

  Bytes cipher(message.plain.size() + 16);
  int written = 0;
  require(EVP_EncryptUpdate(ctx.get(), cipher.data(), &written, message.plain.data(), message.plain.size()) == 1 &&
              EVP_EncryptFinal_ex(ctx.get(), cipher.data() + written, &length) == 1,
          "encrypt payload");
  written += length;
  require(static_cast<std::size_t>(written) == message.plain.size(), "invalid AES-GCM output");
  require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, cipher.data() + written) == 1, "get payload tag");

  OPENSSL_cleanse(dpck.data(), dpck.size());
  require(cipher.size() <= 65535, "oversized protected payload");
  output.push_back(profile.encrypted_payload_iei);
  integer(output, cipher.size(), 2);
  output.insert(output.end(), cipher.begin(), cipher.end());
  return output;
}

//------------------------------------------------------------------------------
// TS 33.180 table 8.5.4.1-1 NOTE 2: data longer than one Protected Payload message holds, as a series of messages
// with one random Payload ID and consecutive Payload sequence numbers; at most 256 messages.
Bytes seal_series(std::span<const byte> plain, std::uint8_t type, std::span<const byte, 16> dppk, std::uint32_t dppk_id,
                  const KeyParameterWireProfile &profile, std::size_t chunk) {
  require(chunk > 8 && chunk <= 65535 - 16 && plain.size() + 8 <= chunk * 256,
          "data too large for 256 protected payloads");
  std::array<byte, 4> id{};
  require(RAND_bytes(id.data(), id.size()) == 1, "payload ID generation failed");

  // The series starts with the length of the data, so that a series missing its
  // last messages is refused (the format has no last-message indication).
  Bytes framed;
  integer(framed, plain.size(), 8);
  framed.insert(framed.end(), plain.begin(), plain.end());

  Bytes out;
  std::size_t offset = 0;
  unsigned sequence = 0;
  do {
    const auto length = std::min(chunk, framed.size() - offset);
    ProtectedPayload message{type,
                             static_cast<std::uint64_t>(std::time(nullptr)),
                             (std::uint32_t(id[0]) << 24) | (std::uint32_t(id[1]) << 16) | (std::uint32_t(id[2]) << 8) |
                                 id[3],
                             static_cast<std::uint8_t>(sequence++),
                             dppk_id,
                             Bytes(framed.begin() + offset, framed.begin() + offset + length)};
    const auto sealed = seal_payload(message, dppk, profile);
    OPENSSL_cleanse(message.plain.data(), message.plain.size());
    out.insert(out.end(), sealed.begin(), sealed.end());
    offset += length;
  } while (offset < framed.size());

  OPENSSL_cleanse(framed.data(), framed.size());
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 table 8.5.4.1-1 NOTE 2: opens a series sealed under one DPPK: every message must carry that DPPK-ID, the
// message type, one Payload ID and the next sequence number.
Bytes open_series(std::span<const byte> data, std::uint8_t type, std::span<const byte, 16> dppk,
                  const KeyParameterWireProfile &profile) {
  require(!data.empty(), "empty protected series");
  Bytes plain;
  std::size_t offset = 0;
  unsigned sequence = 0;
  const auto dppk_id = payload_key_id(data);
  std::optional<std::uint32_t> payload_id;

  while (offset < data.size()) {
    require(data.size() - offset >= 35, "truncated protected series");
    const std::size_t length = 35 + ((std::size_t(data[offset + 33]) << 8) | data[offset + 34]);
    require(length <= data.size() - offset, "truncated protected series");
    const auto message = data.subspan(offset, length);
    require(payload_key_id(message) == dppk_id, "protected series uses several keys");
    auto opened = open_payload(message, dppk, profile);
    require(opened.message_type == type && opened.sequence == sequence++ && sequence <= 256 &&
                (!payload_id || *payload_id == opened.payload_id),
            "protected series out of order");
    payload_id = opened.payload_id;
    plain.insert(plain.end(), opened.plain.begin(), opened.plain.end());
    OPENSSL_cleanse(opened.plain.data(), opened.plain.size());
    offset += length;
  }

  require(plain.size() >= 8, "protected series without its length");
  std::uint64_t declared = 0;
  for (int index = 0; index < 8; ++index) declared = (declared << 8) | plain[index];
  require(declared == plain.size() - 8, "protected series is incomplete");
  plain.erase(plain.begin(), plain.begin() + 8);
  return plain;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.4.1: the DPPK-ID, readable before decryption so that the receiver can select the key.
std::uint32_t payload_key_id(std::span<const byte> data) {
  Reader reader{data};
  (void)reader.take(1 + 5 + 4 + 1 + 1 + 16);
  return static_cast<std::uint32_t>(reader.number(4));
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 8.5.4.1 and 8.5.4.2: decrypts and authenticates a Protected Payload message under the DPCK of
// its DPPK-ID.
ProtectedPayload open_payload(std::span<const byte> data, std::span<const byte, 16> dppk,
                              const KeyParameterWireProfile &profile, bool csk_signalling) {
  require(profile.algorithm == 1, "only DP_AES_128_GCM is supported as the profile's algorithm 1");
  ProtectedPayload message;
  Reader reader{data};
  message.message_type = reader.number(1);
  message.unix_seconds = reader.number(5);
  message.payload_id = reader.number(4);
  message.sequence = reader.number(1);
  const auto algorithm = reader.number(1);
  if (algorithm != profile.algorithm) {
    require(csk_signalling && profile.algorithm_256 && algorithm == *profile.algorithm_256 &&
                *profile.algorithm_256 != profile.algorithm,
            "unsupported payload algorithm");
    message.algorithm = PayloadAlgorithm::aes_256_gcm;
  }
  auto iv = reader.take(16); // both algorithms: the 16-octet IV field of table 8.5.4.1-1
  message.dppk_id = reader.number(4);
  if (message.algorithm == PayloadAlgorithm::aes_256_gcm) require_256_key(message.dppk_id);
  const auto associated = data.first(reader.position);
  require(reader.number(1) == profile.encrypted_payload_iei, "unexpected protected payload IEI");
  auto cipher = reader.take(reader.number(2));
  require(reader.position == data.size() && cipher.size() >= 16, "invalid protected payload");

  auto dpck = payload_key(dppk, message.dppk_id, message.algorithm);
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  require(bool(ctx), "allocate AES-GCM context");
  int length = 0;
  require(EVP_DecryptInit_ex(ctx.get(), payload_cipher(message.algorithm), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, dpck.data(), iv.data()) == 1 &&
              EVP_DecryptUpdate(ctx.get(), nullptr, &length, associated.data(), associated.size()) == 1,
          "initialize payload decryption");

  message.plain.resize(cipher.size() - 16);
  int written = 0;
  require(EVP_DecryptUpdate(ctx.get(), message.plain.data(), &written, cipher.data(), message.plain.size()) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                                  const_cast<byte *>(cipher.data() + message.plain.size())) == 1,
          "decrypt payload");

  const int authenticated = EVP_DecryptFinal_ex(ctx.get(), message.plain.data() + written, &length);
  OPENSSL_cleanse(dpck.data(), dpck.size());
  if (authenticated != 1) {
    OPENSSL_cleanse(message.plain.data(), message.plain.size());
    throw std::runtime_error("protected payload authentication failed");
  }
  return message;
}

//------------------------------------------------------------------------------
// RFC 5905 section 6: "the seconds field is divided into a 32-bit Era Number field and a 32-bit Era Offset field";
// eras "can be derived from external means", and "correct values are obtained even if the client and server are in
// adjacent eras" (within 68 years). The 32-bit seconds of the timestamp (the era offset) is placed in the era
// nearest to the local clock: the previous, the current or the next one.
std::uint64_t ntp_from_wire(std::uint32_t seconds, std::uint64_t now) {
  const auto era = now >> 32;
  const auto distance = [now](std::uint64_t value) { return value > now ? value - now : now - value; };
  auto best = (era << 32) | seconds;
  if (era > 0 && distance(((era - 1) << 32) | seconds) < distance(best)) best = ((era - 1) << 32) | seconds;
  if (era < 0xffffffffULL && distance(((era + 1) << 32) | seconds) < distance(best)) best = ((era + 1) << 32) | seconds;
  return best;
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.2.1.1: the MIKEY-SAKKE UID, SHA-256 of FC 0x00, "MIKEY-SAKKE-UID", the identifier, the KMS URI,
// the key period length and offset and the current key period number, base64 encoded.
std::string uid(std::string_view identity, const Period &period, std::uint64_t time) {
  const auto number = period_number(period, time);
  Bytes input{0};
  string_parameter(input, "MIKEY-SAKKE-UID");
  string_parameter(input, identity);
  string_parameter(input, period.kms_uri);
  minimal_integer(input, period.seconds);
  minimal_integer(input, period.offset);
  minimal_integer(input, number);
  std::array<byte, 32> hash{};
  unsigned length = 0;
  require(EVP_Digest(input.data(), input.size(), hash.data(), &length, EVP_sha256(), nullptr) == 1,
          "UID SHA256 failed");
  std::string encoded(45, '\0');
  const int count = EVP_EncodeBlock(reinterpret_cast<byte *>(encoded.data()), hash.data(), hash.size());
  require(count == 44, "UID base64 failed");
  encoded.resize(count);
  return encoded;
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.3.1.1 and 5.3.5: creates the KMS master secrets and the public keys of its certificate
// (KPAK of RFC 6507, Z_T of RFC 6508) for a key period.
Authority create_authority(const Period &period) {
  (void)period_number(period, period.offset);
  Random rng;
  Eccsi auth;
  Sakke enc;
  checked(wc_MakeEccsiKey(&auth.value, &rng.value), "generate ECCSI authority");
  checked(wc_MakeSakkeKey(&enc.value, &rng.value), "generate SAKKE authority");
  Authority authority;
  authority.public_parameters.period = period;
  authority.authentication_secret =
      export_key(256, [&](auto *buffer, auto *size) { return wc_ExportEccsiKey(&auth.value, buffer, size); });
  authority.encryption_secret =
      export_key(512, [&](auto *buffer, auto *size) { return wc_ExportSakkeKey(&enc.value, buffer, size); });
  authority.public_parameters.authentication_key =
      export_key(65, [&](auto *buffer, auto *size) { return wc_ExportEccsiPublicKey(&auth.value, buffer, size, 0); });
  authority.public_parameters.encryption_key =
      export_key(257, [&](auto *buffer, auto *size) { return wc_ExportSakkePublicKey(&enc.value, buffer, size, 0); });
  return authority;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.6: the KMS provisioned key set of a user for the key period of the given time: SSK and PVT
// (RFC 6507) and RSK (RFC 6508) for the UID of the user's URI.
IdentityKeys issue(const Authority &authority, std::string_view uri, std::uint64_t time) {
  const auto identity = uid(uri, authority.public_parameters.period, time);
  Random rng;
  Eccsi auth;
  Sakke enc;
  Scalar ssk;
  Point pvt;
  Point rsk;

  checked(
      wc_ImportEccsiKey(&auth.value, authority.authentication_secret.data(), authority.authentication_secret.size()),
      "import ECCSI authority");
  checked(wc_ImportSakkeKey(&enc.value, authority.encryption_secret.data(), authority.encryption_secret.size()),
          "import SAKKE authority");
  checked(wc_MakeEccsiPair(&auth.value, &rng.value, WC_HASH_TYPE_SHA256, bytes(identity), identity.size(), &ssk.value,
                           pvt.value),
          "issue ECCSI identity");
  checked(wc_MakeSakkeRsk(&enc.value, bytes(identity), identity.size(), rsk.value), "issue SAKKE identity");

  IdentityKeys result;
  result.uri = uri;
  result.period_number = period_number(authority.public_parameters.period, time);
  result.signing_pair = export_key(96, [&](auto *buffer, auto *size) {
    return wc_EncodeEccsiPair(&auth.value, &ssk.value, pvt.value, buffer, size);
  });
  result.receiver_secret = export_key(
      257, [&](auto *buffer, auto *size) { return wc_EncodeSakkeRsk(&enc.value, rsk.value, buffer, size, 0); });
  return result;
}

//------------------------------------------------------------------------------
// RFC 6507 and RFC 6508: validates provisioned identity keys (the SSK/PVT pair against the KPAK and the RSK against
// Z_T) for the UID of the key period of the given time.
void validate_identity(const PublicParameters &parameters, const IdentityKeys &id, std::uint64_t time) {
  check_identity_period(parameters, id, time);
  const auto identity = uid(id.uri, parameters.period, time);
  Eccsi auth;
  Sakke enc;
  Scalar ssk;
  Point pvt;
  Point rsk;
  public_auth(auth, parameters);
  public_enc(enc, parameters);
  import_pair(auth, id, ssk, pvt);
  int valid = 0;
  checked(wc_ValidateEccsiPair(&auth.value, WC_HASH_TYPE_SHA256, bytes(identity), identity.size(), &ssk.value,
                               pvt.value, &valid),
          "validate ECCSI pair");
  require(valid == 1, "invalid ECCSI identity key");
  require(id.receiver_secret.size() == 257, "invalid SAKKE receiver key size");
  checked(wc_DecodeSakkeRsk(&enc.value, id.receiver_secret.data(), id.receiver_secret.size(), rsk.value),
          "decode SAKKE receiver key");
  checked(wc_ValidateSakkeRsk(&enc.value, bytes(identity), identity.size(), rsk.value, &valid),
          "validate SAKKE receiver key");
  require(valid == 1, "invalid SAKKE identity key");
}

//------------------------------------------------------------------------------
// RFC 6507: an ECCSI signature (r || s || PVT, 129 octets) of a message by the identity for its key period.
Bytes sign(const PublicParameters &parameters, const IdentityKeys &id, std::uint64_t time,
           std::span<const byte> message) {
  check_identity_period(parameters, id, time);
  Eccsi auth;
  Random rng;
  Scalar ssk;
  Point pvt;
  public_auth(auth, parameters);
  import_pair(auth, id, ssk, pvt);
  identity_hash(auth, uid(id.uri, parameters.period, time), pvt.value);
  checked(wc_SetEccsiPair(&auth.value, &ssk.value, pvt.value), "set ECCSI signing pair");
  return export_key(129, [&](auto *buffer, auto *size) {
    return wc_SignEccsiHash(&auth.value, &rng.value, WC_HASH_TYPE_SHA256, message.data(), message.size(), buffer, size);
  });
}

//------------------------------------------------------------------------------
// RFC 6507: verifies an ECCSI signature of a message by the UID of a URI for the key period of the given time.
bool verify(const PublicParameters &parameters, std::string_view uri, std::uint64_t time, std::span<const byte> message,
            std::span<const byte> signature) {
  if (signature.size() != 129 || message.size() > 65535) return false;
  try {
    Eccsi auth;
    Point pvt;
    public_auth(auth, parameters);
    checked(wc_DecodeEccsiPvtFromSig(&auth.value, signature.data(), signature.size(), pvt.value),
            "decode signature PVT");
    identity_hash(auth, uid(uri, parameters.period, time), pvt.value);
    int valid = 0;
    checked(wc_VerifyEccsiHash(&auth.value, WC_HASH_TYPE_SHA256, message.data(), message.size(), signature.data(),
                               signature.size(), &valid),
            "verify ECCSI");
    return valid == 1;
  } catch (const std::exception &) {
    return false;
  }
}

//------------------------------------------------------------------------------
// RFC 6508: SAKKE encapsulation of a 128-bit key (the SSV) to the UID of the recipient: the Encapsulated Data
// R (257 octets) || H (16 octets).
Bytes encapsulate(const PublicParameters &parameters, std::string_view recipient, std::uint64_t time,
                  std::span<const byte, 16> key) {
  Sakke enc;
  public_enc(enc, parameters);
  const auto identity = uid(recipient, parameters.period, time);
  checked(wc_SetSakkeIdentity(&enc.value, bytes(identity), identity.size()), "set SAKKE recipient");
  Bytes result(273);
  std::copy(key.begin(), key.end(), result.begin() + 257);
  word16 length = 257;
  checked(wc_MakeSakkeEncapsulatedSSV(&enc.value, WC_HASH_TYPE_SHA256, result.data() + 257, 16, result.data(), &length),
          "encapsulate SAKKE key");
  require(length == 257, "unexpected SAKKE parameter set");
  return result;
}

//------------------------------------------------------------------------------
// RFC 6508: recovers the 128-bit key of SAKKE Encapsulated Data with the RSK of the identity for its key period.
std::array<byte, 16> decapsulate(const PublicParameters &parameters, const IdentityKeys &id, std::uint64_t time,
                                 std::span<const byte> data) {
  check_identity_period(parameters, id, time);
  require(data.size() == 273, "invalid SAKKE encapsulation size");
  Sakke enc;
  public_enc(enc, parameters);
  const auto identity = uid(id.uri, parameters.period, time);
  checked(wc_SetSakkeIdentity(&enc.value, bytes(identity), identity.size()), "set SAKKE recipient");
  require(id.receiver_secret.size() == 257, "invalid SAKKE receiver key size");
  Point rsk;
  checked(wc_DecodeSakkeRsk(&enc.value, id.receiver_secret.data(), id.receiver_secret.size(), rsk.value),
          "decode SAKKE receiver key");
  checked(wc_SetSakkeRsk(&enc.value, rsk.value, nullptr, 0), "set SAKKE receiver key");
  std::array<byte, 16> key{};
  std::copy(data.begin() + 257, data.end(), key.begin());
  checked(wc_DeriveSakkeSSV(&enc.value, WC_HASH_TYPE_SHA256, key.data(), key.size(), data.data(), 257),
          "decapsulate SAKKE key");
  return key;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2: a MIKEY-SAKKE I_MESSAGE from an initiator and to a receiver keyed by the same KMS.
Bytes create_mikey(const PublicParameters &parameters, const IdentityKeys &sender, std::string_view recipient,
                   const KeyMessage &key, const KeyParameterWireProfile *profile) {
  return create_mikey(parameters, parameters, sender, recipient, key, profile);
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.2.2 and 5.2.7.3 and annex E.1.2, RFC 6509: a MIKEY-SAKKE I_MESSAGE: HDR (data type 26, CS# 0,
// CS ID map type 1), T (NTP-UTC), RAND, IDRi, IDRr, IDRkmsi, IDRkmsr, the SAKKE payload (ID scheme 2, encapsulated
// under the receiver's KMS), the optional general extension with the key parameters (annex E.6) and the ECCSI SIGN
// payload (signed under the initiator's KMS) over everything before the signature (RFC 3830 section 5.2).
Bytes create_mikey(const PublicParameters &parameters, const PublicParameters &rp, const IdentityKeys &sender,
                   std::string_view recipient, const KeyMessage &key, const KeyParameterWireProfile *profile) {
  require(key.random.size() >= 16 && key.random.size() <= 255, "invalid MIKEY RAND length");
  auto encrypted = encapsulate(rp, recipient, key.ntp_seconds, key.key);

  Bytes out{1, 26, 5, 1};
  integer(out, key.csb_id, 4);
  out.insert(out.end(), {0, 1});
  out.insert(out.end(), {11, 0});
  // RFC 5905 section 6: the 32-bit seconds field carries the era offset; the receiver infers the era (ntp_from_wire).
  integer(out, key.ntp_seconds & 0xffffffffULL, 4);
  integer(out, 0, 4);
  out.insert(out.end(), {14, static_cast<byte>(key.random.size())});
  out.insert(out.end(), key.random.begin(), key.random.end());

  id_payload(out, 14, 1, sender.uri);
  id_payload(out, 14, 2, recipient);
  id_payload(out, 14, 6, parameters.period.kms_uri);
  id_payload(out, 26, 7, rp.period.kms_uri);

  require(!key.properties || profile != nullptr, "key properties require an explicit wire profile");
  out.insert(out.end(), {static_cast<byte>(key.properties ? 21 : 4), 1, 2});
  integer(out, encrypted.size(), 2);
  out.insert(out.end(), encrypted.begin(), encrypted.end());
  if (key.properties) {
    auto parameters = encrypt_properties(key, *profile);
    require(parameters.size() <= 65535, "oversized MIKEY extension");
    out.insert(out.end(), {4, 7});
    integer(out, parameters.size(), 2);
    out.insert(out.end(), parameters.begin(), parameters.end());
  }

  // Deviation from TS 33.180 annex E.1.2 ("Signature length ... 32"): S type 2 (ECCSI) with the length of RFC 6509
  // section 4.2, 129 octets (r32 || s32 || uncompressed PVT65). An RFC 6507 ECCSI signature cannot fit in 32 octets;
  // the annex is inconsistent with the RFCs it names, and implementations follow RFC 6509.
  integer(out, 0x2081, 2);
  auto signature = sign(parameters, sender, key.ntp_seconds, out);
  out.insert(out.end(), signature.begin(), signature.end());
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2: opens a MIKEY-SAKKE I_MESSAGE signed under the receiver's own KMS.
KeyMessage open_mikey(const PublicParameters &parameters, const IdentityKeys &recipient, std::string_view sender,
                      std::span<const byte> message, std::uint64_t now, std::uint32_t skew,
                      const KeyParameterWireProfile *profile) {
  return open_mikey(
      parameters,
      [&parameters](std::string_view uri) { return uri == parameters.period.kms_uri ? &parameters : nullptr; },
      recipient, sender, message, now, skew, profile);
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.2.2 and 5.2.7.3 and annex E.1.2: checks the header, the timestamp (its era from now, RFC 5905
// section 6) against the allowed skew, the key period, the IDRi, IDRr and IDRkmsr, resolves the signing KMS
// (IDRkmsi), reads the general extension payloads after the SAKKE payload, verifies the ECCSI signature by the
// sender's UID, then decapsulates the key and opens the key parameters (annex E.6).
KeyMessage open_mikey(const PublicParameters &parameters, const KmsLookup &lookup, const IdentityKeys &recipient,
                      std::string_view sender, std::span<const byte> message, std::uint64_t now, std::uint32_t skew,
                      const KeyParameterWireProfile *profile) {
  require(message.size() <= 65535, "oversized MIKEY message");
  Reader reader{message};
  KeyMessage key;
  key.csb_id = reader.mikey_header();
  key.ntp_seconds = ntp_from_wire(reader.timestamp(), now);
  const auto delta = now >= key.ntp_seconds ? now - key.ntp_seconds : key.ntp_seconds - now;
  require(delta <= skew, "stale or future MIKEY timestamp");
  check_identity_period(parameters, recipient, key.ntp_seconds);

  auto random = reader.random();
  key.random.assign(random.begin(), random.end());

  require(reader.identity(1, 14) == sender, "unexpected MIKEY sender");
  require(reader.identity(2, 14) == recipient.uri, "unexpected MIKEY recipient");
  const auto signing_kms = reader.identity(6, 14);
  const PublicParameters *sp =
      signing_kms == parameters.period.kms_uri ? &parameters : (lookup ? lookup(signing_kms) : nullptr);
  require(sp != nullptr, "unexpected signing KMS");
  require(reader.identity(7, 26) == parameters.period.kms_uri, "unexpected recipient KMS");

  auto next = reader.number(1);
  require((next == 4 || next == 21) && reader.number(1) == 1 && reader.number(1) == 2, "unsupported SAKKE profile");
  auto ciphertext = reader.take(reader.number(2));
  // RFC 3830 section 6.15 and TS 33.180 annex E.1.2: general extension payloads (21) up to the SIGN payload (4): the
  // key parameters (type 7, annex E.6, at most one), SAKKE-to-self (type 6, annex E.5: "may be included"; not used
  // here, its content is ignored) and the RFC 3830 table 6.15 types Vendor ID (0) and SDP IDs (1), skipped. Any other
  // type is an unsupported parameter, refused: RFC 3830 section 5.3, "If any unsupported parameters or errors occur
  // during the processing ... The processing is then aborted."
  std::span<const byte> properties;
  bool have_properties = false;
  while (next == 21) {
    next = reader.number(1);
    const auto type = reader.number(1);
    auto data = reader.take(reader.number(2));
    if (type == 7) {
      require(!have_properties, "duplicate MIKEY key parameters");
      require(profile != nullptr, "key properties require an explicit wire profile");
      properties = data;
      have_properties = true;
    } else
      require(type == 6 || type == 0 || type == 1, "unsupported MIKEY general extension");
  }
  require(next == 4, "unsupported MIKEY payload before SIGN");

  require(reader.number(2) == 0x2081, "unsupported ECCSI SIGN");
  const auto signed_length = reader.position;
  auto signature = reader.take(129);
  require(reader.position == message.size(), "trailing MIKEY data");
  require(verify(*sp, sender, key.ntp_seconds, message.first(signed_length), signature), "MIKEY signature invalid");

  key.key = decapsulate(parameters, recipient, key.ntp_seconds, ciphertext);
  if (have_properties) key.properties = decrypt_properties(key, properties, *profile);
  return key;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5 (tables 8.5.5-1 and 8.5.5-2): an Authenticated Payload: the original payload, the algorithm,
// the Signing Data (the signer's UID and KMS URI) and an ECCSI signature over everything before the signature value.
Bytes authenticate_payload(const PublicParameters &parameters, const IdentityKeys &signer, std::uint64_t now,
                           std::uint8_t type, std::span<const byte> original) {
  require(original.size() <= 65535, "oversized payload to authenticate");
  const auto signer_uid = uid(signer.uri, parameters.period, now);
  require(signer_uid.size() <= 255 && parameters.period.kms_uri.size() <= 255, "signing data too long");
  Bytes out{static_cast<byte>(type | 0x80), original_payload_iei};
  integer(out, original.size(), 2);
  out.insert(out.end(), original.begin(), original.end());
  out.push_back(eccsi_algorithm);

  Bytes signing{signing_uid_iei, static_cast<byte>(signer_uid.size())};
  signing.insert(signing.end(), signer_uid.begin(), signer_uid.end());
  signing.push_back(signing_kms_iei);
  signing.push_back(static_cast<byte>(parameters.period.kms_uri.size()));
  signing.insert(signing.end(), parameters.period.kms_uri.begin(), parameters.period.kms_uri.end());
  out.push_back(signing_data_iei);
  integer(out, signing.size(), 2);
  out.insert(out.end(), signing.begin(), signing.end());

  // TS 33.180 clause 8.5.5: the type and length of the Signature element are signed; its value is not.
  out.push_back(signature_iei);
  integer(out, 129, 2);
  const auto signature = sign(parameters, signer, now, out);
  require(signature.size() == 129, "unexpected ECCSI signature length");
  out.insert(out.end(), signature.begin(), signature.end());
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5: verifies an Authenticated Payload signed under the receiver's own KMS.
AuthenticatedPayload open_authenticated(const PublicParameters &own, std::string_view sender,
                                        std::span<const byte> message, std::uint64_t now) {
  return open_authenticated([&own](std::string_view uri) { return uri == own.period.kms_uri ? &own : nullptr; }, sender,
                            message, now);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5: verifies an Authenticated Payload; the Signing KMS URI selects the KMS parameters, the
// Signing UID must be the sender's UID for the current or the previous key period, and the signature must verify.
AuthenticatedPayload open_authenticated(const KmsLookup &lookup, std::string_view sender, std::span<const byte> message,
                                        std::uint64_t now) {
  Reader reader{message};
  AuthenticatedPayload result;
  result.message_type = static_cast<std::uint8_t>(reader.number(1));
  require(result.message_type & 0x80, "payload is not authenticated");
  require(reader.number(1) == original_payload_iei, "unexpected Original Payload IEI");
  auto original = reader.take(reader.number(2));
  result.original.assign(original.begin(), original.end());
  require(reader.number(1) == eccsi_algorithm, "unsupported payload signature algorithm");
  require(reader.number(1) == signing_data_iei, "unexpected Signing Data IEI");

  Reader signing{reader.take(reader.number(2))};
  require(signing.number(1) == signing_uid_iei, "unexpected Signing UID IEI");
  auto signer_uid = signing.take(signing.number(1));
  result.signer_uid.assign(signer_uid.begin(), signer_uid.end());
  require(signing.number(1) == signing_kms_iei, "unexpected Signing KMS IEI");
  auto kms = signing.take(signing.number(1));
  result.signer_kms.assign(kms.begin(), kms.end());
  require(signing.position == signing.data.size(), "trailing signing data");

  const PublicParameters *found = lookup ? lookup(result.signer_kms) : nullptr;
  require(found != nullptr, "payload signed under another KMS");
  const PublicParameters &parameters = *found;

  require(reader.number(1) == signature_iei && reader.number(2) == 129, "unexpected Signature element");
  const auto signed_length = reader.position;
  auto signature = reader.take(129);
  require(reader.position == message.size(), "trailing authenticated payload data");

  // After verification the sender's URI must produce the Signing UID (TS 33.180 clause 8.5.5).
  std::optional<std::uint64_t> time;
  for (const auto candidate : {now, now >= parameters.period.seconds ? now - parameters.period.seconds : now})
    if (uid(sender, parameters.period, candidate) == result.signer_uid) {
      time = candidate;
      break;
    }
  require(time.has_value(), "Signing UID is not the sender's");
  require(verify(parameters, sender, *time, message.first(signed_length), signature), "payload signature invalid");
  return result;
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the initiator's KMS URI (IDRkmsi) of an I_MESSAGE, read without authenticating it.
std::string mikey_initiator_kms(std::span<const byte> message) {
  require(message.size() <= 65535, "oversized MIKEY message");
  Reader reader{message};
  (void)reader.mikey_header();
  (void)reader.timestamp();
  (void)reader.random();
  (void)reader.identity(1, 14);
  (void)reader.identity(2, 14);
  return reader.identity(6, 14);
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the receiver (IDRr) and its KMS (IDRkmsr) of an I_MESSAGE, not authenticated.
std::pair<std::string, std::string> mikey_receiver(std::span<const byte> message) {
  require(message.size() <= 65535, "oversized MIKEY message");
  Reader reader{message};
  (void)reader.mikey_header();
  (void)reader.timestamp();
  (void)reader.random();
  (void)reader.identity(1, 14);
  auto receiver = reader.identity(2, 14);
  (void)reader.identity(6, 14);
  return {receiver, reader.identity(7, 26)};
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2: the CSB-ID of an I_MESSAGE (the key identifier K-ID), read without authenticating it.
std::uint32_t mikey_csb_id(std::span<const byte> message) {
  Reader reader{message};
  require(reader.number(1) == 1 && reader.number(1) == 26 && reader.number(1) == 5 && (reader.number(1) & 0x7f) == 1,
          "unsupported MIKEY header");
  return static_cast<std::uint32_t>(reader.number(4));
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the initiator (IDRi) of an I_MESSAGE, read without authenticating it.
std::string mikey_initiator(std::span<const byte> message) {
  require(message.size() <= 65535, "oversized MIKEY message");
  Reader reader{message};
  (void)reader.mikey_header();
  (void)reader.timestamp();
  (void)reader.random();
  return reader.identity(1, 14);
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6: a key may be used only if its Status (annex E.6.9) is not revoked, between its Activation Time
// (annex E.6.4; 0 is the I_MESSAGE timestamp) and its Expiry Time (annex E.6.10; 0 never expires), and, for a GMK,
// for one of its MC Group IDs (annex E.6.3).
void require_active(const KeyMessage &key, std::string_view group, std::uint64_t now) {
  require_unexpired(key, group, now);
  const auto &properties = *key.properties;
  const auto activation =
      properties.activation_unix_seconds ? properties.activation_unix_seconds : key.ntp_seconds - 2208988800ULL;
  require(now >= activation, "key inactive or expired");
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.9, E.6.10 and E.6.3: not revoked, not expired, and for a GMK one of its groups; the Activation
// Time (annex E.6.4) is left to the user of the key.
void require_unexpired(const KeyMessage &key, std::string_view group, std::uint64_t now) {
  require(key.properties.has_value(), "missing protected key properties");
  const auto &properties = *key.properties;
  require((properties.status & 1) != 0, "key revoked");
  require(!properties.expiry_unix_seconds || now < properties.expiry_unix_seconds, "key inactive or expired");
  if (properties.type == 0)
    require(!group.empty() &&
                std::find(properties.groups.begin(), properties.groups.end(), group) != properties.groups.end(),
            "key not authorized for group");
  else
    require(group.empty(), "non-group key used for group media");
}
} // namespace mcx::keying
