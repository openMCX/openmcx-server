//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The STUN messages of ICE connectivity checks (RFC 5389 with the ICE attributes of RFC 8445 section 16.1): Binding
// requests, success and error responses, and indications; short-term credentials (MESSAGE-INTEGRITY, HMAC-SHA1 keyed
// with the ICE password) and FINGERPRINT. Only what ICE uses: no long-term credentials, no IPv6 address attributes,
// no SOFTWARE written (it is read and ignored).
//
// Specifications: RFC 5389, RFC 8445, RFC 5769 (test vectors).

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcx::stun {

// RFC 5389 section 6: the message classes of the Binding method.
enum class Class : std::uint16_t { Request = 0x0001, Indication = 0x0011, Success = 0x0101, Error = 0x0111 };

// RFC 5389 section 15 and RFC 8445 section 16.1: the attributes ICE reads or writes.
namespace attribute {
constexpr std::uint16_t Username = 0x0006, MessageIntegrity = 0x0008, ErrorCode = 0x0009, UnknownAttributes = 0x000a,
                        XorMappedAddress = 0x0020, Priority = 0x0024, UseCandidate = 0x0025, Software = 0x8022,
                        Fingerprint = 0x8028, IceControlled = 0x8029, IceControlling = 0x802a;
} // namespace attribute

using TransactionId = std::array<std::uint8_t, 12>;

// An IPv4 transport address in host byte order.
struct Address {
  std::uint32_t ip = 0;
  std::uint16_t port = 0;
  bool operator==(const Address &) const = default;
};

//------------------------------------------------------------------------------
// A decoded message: the fields ICE uses, and where its integrity attribute lies for check_integrity.
struct Message {
  Class type = Class::Request;
  TransactionId transaction{};
  std::optional<std::string> username;
  std::optional<std::uint32_t> priority;
  bool use_candidate = false;
  std::optional<std::uint64_t> ice_controlling, ice_controlled;
  std::optional<Address> xor_mapped;
  std::optional<unsigned> error_code; // class * 100 + number
  // Comprehension-required attributes (0x0000 to 0x7fff) this decoder does not know (RFC 5389 section 7.3).
  std::vector<std::uint16_t> unknown_required;
  bool has_integrity = false, has_fingerprint = false;
  std::size_t integrity_offset = 0; // the octet where the MESSAGE-INTEGRITY attribute starts
};

//------------------------------------------------------------------------------
// RFC 5389 sections 6 and 15: decodes a datagram; nullopt when it is not a well-formed STUN Binding message or its
// FINGERPRINT (when present) does not match (RFC 5389 section 7.3).
std::optional<Message> decode(std::span<const std::uint8_t> datagram);

//------------------------------------------------------------------------------
// RFC 5389 section 15.4: whether the MESSAGE-INTEGRITY of a decoded datagram is the HMAC-SHA1 under the key (the ICE
// password, RFC 8445 section 7.2.2); false when it has none.
bool check_integrity(std::span<const std::uint8_t> datagram, const Message &message, std::string_view key);

//------------------------------------------------------------------------------
// Builds a message attribute by attribute; finish appends MESSAGE-INTEGRITY (when a key is given) and FINGERPRINT.
class Builder {
public:
  Builder(Class type, const TransactionId &transaction);
  Builder &username(std::string_view value);
  Builder &priority(std::uint32_t value);
  Builder &use_candidate();
  Builder &ice_controlling(std::uint64_t tie_breaker);
  Builder &ice_controlled(std::uint64_t tie_breaker);
  Builder &xor_mapped(const Address &address);
  Builder &error(unsigned code, std::string_view reason);
  Builder &unknown_attributes(std::span<const std::uint16_t> types);
  std::vector<std::uint8_t> finish(std::optional<std::string_view> key);

private:
  void add(std::uint16_t type, std::span<const std::uint8_t> value);
  std::vector<std::uint8_t> bytes_;
};

//------------------------------------------------------------------------------
// RFC 5389 sections 15.4 and 15.5: appends MESSAGE-INTEGRITY and FINGERPRINT to an encoded message whose length field
// covers what precedes them (exposed for the RFC 5769 test vectors).
void append_integrity(std::vector<std::uint8_t> &message, std::string_view key);
void append_fingerprint(std::vector<std::uint8_t> &message);

} // namespace mcx::stun
