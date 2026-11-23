//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The STUN messages of ICE connectivity checks (src/media/stun.hpp).
//
// Specifications: RFC 5389, RFC 8445.

#include "stun.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <cstring>

namespace mcx::stun {
namespace {

// RFC 5389 section 6: the 20-octet header and the magic cookie.
constexpr std::size_t kHeader = 20;
constexpr std::uint32_t kMagicCookie = 0x2112a442;
// RFC 5389 section 15.4: HMAC-SHA1, 20 octets.
constexpr std::size_t kIntegrityLength = 20;
// RFC 5389 section 15.5: the CRC-32 is XORed with 0x5354554e.
constexpr std::uint32_t kFingerprintXor = 0x5354554e;
// RFC 5389 section 15.6: the reason phrase is at most 128 characters.
constexpr std::size_t kReasonMaximum = 128;

std::uint16_t read16(std::span<const std::uint8_t> bytes, std::size_t at) {
  return static_cast<std::uint16_t>(bytes[at] << 8 | bytes[at + 1]);
}

std::uint32_t read32(std::span<const std::uint8_t> bytes, std::size_t at) {
  return static_cast<std::uint32_t>(bytes[at]) << 24 | static_cast<std::uint32_t>(bytes[at + 1]) << 16 |
         static_cast<std::uint32_t>(bytes[at + 2]) << 8 | bytes[at + 3];
}

void write16(std::vector<std::uint8_t> &bytes, std::uint16_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 8));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

void write32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
  write16(bytes, static_cast<std::uint16_t>(value >> 16));
  write16(bytes, static_cast<std::uint16_t>(value));
}

void set_length(std::vector<std::uint8_t> &bytes, std::size_t length) {
  bytes[2] = static_cast<std::uint8_t>(length >> 8);
  bytes[3] = static_cast<std::uint8_t>(length);
}

//------------------------------------------------------------------------------
// RFC 5389 section 15.5 (ISO/IEC 13239, as in RFC 1952 section 8): the reflected CRC-32 of polynomial 0xedb88320.
std::uint32_t crc32(std::span<const std::uint8_t> bytes) {
  static const auto table = [] {
    std::array<std::uint32_t, 256> out{};
    for (std::uint32_t index = 0; index < out.size(); ++index) {
      std::uint32_t value = index;
      for (int bit = 0; bit < 8; ++bit) value = value & 1 ? 0xedb88320 ^ (value >> 1) : value >> 1;
      out[index] = value;
    }
    return out;
  }();
  std::uint32_t crc = 0xffffffff;
  for (const auto byte : bytes) crc = table[(crc ^ byte) & 0xff] ^ (crc >> 8);
  return crc ^ 0xffffffff;
}

std::array<std::uint8_t, kIntegrityLength> hmac_sha1(std::span<const std::uint8_t> bytes, std::string_view key) {
  std::array<std::uint8_t, kIntegrityLength> out{};
  unsigned length = 0;
  HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), bytes.data(), bytes.size(), out.data(), &length);
  return out;
}

std::uint64_t read64(std::span<const std::uint8_t> bytes, std::size_t at) {
  return static_cast<std::uint64_t>(read32(bytes, at)) << 32 | read32(bytes, at + 4);
}

} // namespace

//------------------------------------------------------------------------------
// RFC 5389 sections 6, 7.3, 15 and 15.5.
std::optional<Message> decode(std::span<const std::uint8_t> datagram) {
  if (datagram.size() < kHeader || (datagram[0] & 0xc0) != 0 || read32(datagram, 4) != kMagicCookie) return {};
  const std::size_t length = read16(datagram, 2);
  if (length % 4 != 0 || kHeader + length != datagram.size()) return {};
  const auto type = read16(datagram, 0);
  Message message;
  switch (type) {
  case static_cast<std::uint16_t>(Class::Request):
  case static_cast<std::uint16_t>(Class::Indication):
  case static_cast<std::uint16_t>(Class::Success):
  case static_cast<std::uint16_t>(Class::Error): message.type = static_cast<Class>(type); break;
  default: return {}; // another method than Binding
  }
  std::copy_n(datagram.begin() + 8, message.transaction.size(), message.transaction.begin());
  std::size_t at = kHeader;
  while (at < datagram.size()) {
    if (at + 4 > datagram.size()) return {};
    const auto attribute = read16(datagram, at);
    const std::size_t size = read16(datagram, at + 2);
    const std::size_t value = at + 4;
    if (value + size > datagram.size()) return {};
    const auto bytes = datagram.subspan(value, size);
    // RFC 5389 section 15.4: attributes after MESSAGE-INTEGRITY are ignored, but FINGERPRINT.
    if (message.has_integrity && attribute != attribute::Fingerprint) {
      at = value + (size + 3) / 4 * 4;
      continue;
    }
    switch (attribute) {
    case attribute::Username: message.username.emplace(bytes.begin(), bytes.end()); break;
    case attribute::MessageIntegrity:
      if (size != kIntegrityLength) return {};
      message.has_integrity = true;
      message.integrity_offset = at;
      break;
    case attribute::ErrorCode:
      if (size < 4) return {};
      message.error_code = (bytes[2] & 0x07) * 100u + bytes[3];
      break;
    case attribute::XorMappedAddress:
      if (size < 8) return {};
      if (bytes[1] == 0x01 && size == 8)
        message.xor_mapped = Address{read32(bytes, 4) ^ kMagicCookie,
                                     static_cast<std::uint16_t>(read16(bytes, 2) ^ (kMagicCookie >> 16))};
      break;
    case attribute::Priority:
      if (size != 4) return {};
      message.priority = read32(bytes, 0);
      break;
    case attribute::UseCandidate: message.use_candidate = true; break;
    case attribute::IceControlling:
      if (size != 8) return {};
      message.ice_controlling = read64(bytes, 0);
      break;
    case attribute::IceControlled:
      if (size != 8) return {};
      message.ice_controlled = read64(bytes, 0);
      break;
    case attribute::Fingerprint: {
      // RFC 5389 section 15.5: the last attribute; the CRC over everything before it, with the length covering it.
      if (size != 4 || value + size != datagram.size()) return {};
      std::vector<std::uint8_t> covered(datagram.begin(), datagram.begin() + static_cast<std::ptrdiff_t>(at));
      if ((crc32(covered) ^ kFingerprintXor) != read32(bytes, 0)) return {};
      message.has_fingerprint = true;
      break;
    }
    case attribute::UnknownAttributes:
    case attribute::Software: break;
    default:
      if (attribute < 0x8000) message.unknown_required.push_back(attribute);
    }
    at = value + (size + 3) / 4 * 4;
  }
  return message;
}

//------------------------------------------------------------------------------
// RFC 5389 section 15.4: the HMAC over the message up to MESSAGE-INTEGRITY, the length field adjusted to end with it.
bool check_integrity(std::span<const std::uint8_t> datagram, const Message &message, std::string_view key) {
  if (!message.has_integrity) return false;
  std::vector<std::uint8_t> covered(datagram.begin(),
                                    datagram.begin() + static_cast<std::ptrdiff_t>(message.integrity_offset));
  set_length(covered, message.integrity_offset + 4 + kIntegrityLength - kHeader);
  const auto expected = hmac_sha1(covered, key);
  const auto *received = datagram.data() + message.integrity_offset + 4;
  return CRYPTO_memcmp(expected.data(), received, expected.size()) == 0;
}

//------------------------------------------------------------------------------
Builder::Builder(Class type, const TransactionId &transaction) {
  write16(bytes_, static_cast<std::uint16_t>(type));
  write16(bytes_, 0);
  write32(bytes_, kMagicCookie);
  bytes_.insert(bytes_.end(), transaction.begin(), transaction.end());
}

void Builder::add(std::uint16_t type, std::span<const std::uint8_t> value) {
  write16(bytes_, type);
  write16(bytes_, static_cast<std::uint16_t>(value.size()));
  bytes_.insert(bytes_.end(), value.begin(), value.end());
  bytes_.resize((bytes_.size() + 3) / 4 * 4, 0); // RFC 5389 section 15: padded to 32 bits
  set_length(bytes_, bytes_.size() - kHeader);
}

Builder &Builder::username(std::string_view value) {
  add(attribute::Username, {reinterpret_cast<const std::uint8_t *>(value.data()), value.size()});
  return *this;
}

Builder &Builder::priority(std::uint32_t value) {
  std::vector<std::uint8_t> bytes;
  write32(bytes, value);
  add(attribute::Priority, bytes);
  return *this;
}

Builder &Builder::use_candidate() {
  add(attribute::UseCandidate, {});
  return *this;
}

Builder &Builder::ice_controlling(std::uint64_t tie_breaker) {
  std::vector<std::uint8_t> bytes;
  write32(bytes, static_cast<std::uint32_t>(tie_breaker >> 32));
  write32(bytes, static_cast<std::uint32_t>(tie_breaker));
  add(attribute::IceControlling, bytes);
  return *this;
}

Builder &Builder::ice_controlled(std::uint64_t tie_breaker) {
  std::vector<std::uint8_t> bytes;
  write32(bytes, static_cast<std::uint32_t>(tie_breaker >> 32));
  write32(bytes, static_cast<std::uint32_t>(tie_breaker));
  add(attribute::IceControlled, bytes);
  return *this;
}

// RFC 5389 section 15.2: the family, the port XORed with the cookie's high 16 bits, the address with the cookie.
Builder &Builder::xor_mapped(const Address &address) {
  std::vector<std::uint8_t> bytes{0x00, 0x01};
  write16(bytes, static_cast<std::uint16_t>(address.port ^ (kMagicCookie >> 16)));
  write32(bytes, address.ip ^ kMagicCookie);
  add(attribute::XorMappedAddress, bytes);
  return *this;
}

// RFC 5389 section 15.6: the class (hundreds) and number, then the reason phrase.
Builder &Builder::error(unsigned code, std::string_view reason) {
  std::vector<std::uint8_t> bytes{0, 0, static_cast<std::uint8_t>(code / 100), static_cast<std::uint8_t>(code % 100)};
  const auto phrase = reason.substr(0, kReasonMaximum);
  bytes.insert(bytes.end(), phrase.begin(), phrase.end());
  add(attribute::ErrorCode, bytes);
  return *this;
}

Builder &Builder::unknown_attributes(std::span<const std::uint16_t> types) {
  std::vector<std::uint8_t> bytes;
  for (const auto type : types) write16(bytes, type);
  add(attribute::UnknownAttributes, bytes);
  return *this;
}

std::vector<std::uint8_t> Builder::finish(std::optional<std::string_view> key) {
  if (key) append_integrity(bytes_, *key);
  append_fingerprint(bytes_);
  return std::move(bytes_);
}

void append_integrity(std::vector<std::uint8_t> &message, std::string_view key) {
  set_length(message, message.size() + 4 + kIntegrityLength - kHeader);
  const auto mac = hmac_sha1(message, key);
  write16(message, attribute::MessageIntegrity);
  write16(message, kIntegrityLength);
  message.insert(message.end(), mac.begin(), mac.end());
}

void append_fingerprint(std::vector<std::uint8_t> &message) {
  set_length(message, message.size() + 8 - kHeader);
  const auto crc = crc32(message) ^ kFingerprintXor;
  write16(message, attribute::Fingerprint);
  write16(message, 4);
  write32(message, crc);
}

} // namespace mcx::stun
