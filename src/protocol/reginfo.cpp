//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The registration information document of the reg event package (RFC 3680 section 5, application/reginfo+xml),
// which a UE reads from the NOTIFYs of its subscription to its own registration state (TS 24.229 clauses 5.1.1.3,
// 5.1.1.5A and 5.1.1.7).
//
// Specifications: RFC 3680; TS 24.229 V19.7.0 (Rel-19).

#include "protocol_internal.hpp"

#include <algorithm>
#include <charconv>

namespace mcx {
namespace {
constexpr const char *reginfo_ns = "urn:ietf:params:xml:ns:reginfo";

//------------------------------------------------------------------------------
// Helper: the canonical decimal digits of an XML Schema integer of the xs:nonNegativeInteger family (XML Schema Part 2
// section 3.3.20: an optional sign, "+" or, for zero only, "-", then decimal digits; whiteSpace collapse), without
// leading zeros; invalid for anything else (a negative value among them).
std::string non_negative_integer(std::string_view lexical) {
  auto value = trim(lexical);
  std::string_view digits = value;
  const bool minus = !digits.empty() && digits.front() == '-';
  if (!digits.empty() && (digits.front() == '+' || minus)) digits.remove_prefix(1);
  if (digits.empty() || digits.find_first_not_of("0123456789") != std::string_view::npos) invalid("reginfo number");
  digits.remove_prefix(std::min(digits.find_first_not_of('0'), digits.size()));
  if (digits.empty()) return "0";
  if (minus) invalid("reginfo number below zero");
  return std::string(digits);
}

//------------------------------------------------------------------------------
// Helper: an xs:unsignedLong (XML Schema Part 2 section 3.3.21, at most 18446744073709551615).
std::uint64_t unsigned_long(std::string_view lexical) {
  const auto digits = non_negative_integer(lexical);
  std::uint64_t value = 0;
  const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
  if (error != std::errc{} || end != digits.data() + digits.size()) invalid("reginfo number above xs:unsignedLong");
  return value;
}

//------------------------------------------------------------------------------
// Helper: canonical decimal digits plus one.
std::string plus_one(std::string digits) {
  for (auto at = digits.size(); at-- > 0;) {
    if (digits[at] != '9') {
      ++digits[at];
      return digits;
    }
    digits[at] = '0';
  }
  return "1" + digits;
}
} // namespace

//------------------------------------------------------------------------------
// RFC 3680 section 5.1: the <reginfo> root with its version and state ("full" or "partial"), its <registration>
// elements (aor, state "init", "active" or "terminated") and their <contact> elements (state "active" or
// "terminated", the event of RFC 3680 section 4.7.1, the optional expires, and the <uri>). Elements and attributes of
// other namespaces are ignored (section 5.1).
RegInfo parse_reginfo(std::string_view xml) {
  auto doc = document(xml);
  auto *root = xmlDocGetRootElement(doc.get());
  if (!is(root, "reginfo", reginfo_ns)) invalid("not a reginfo document");
  RegInfo info;
  const auto version = attr(root, "version");
  const auto state = attr(root, "state");
  if (version.empty() || (state != "full" && state != "partial")) invalid("reginfo version or state missing");
  info.version = non_negative_integer(version);
  info.full = state == "full";
  for (auto *node = root->children; node != nullptr; node = node->next) {
    if (!is(node, "registration", reginfo_ns)) continue;
    RegInfo::Registration registration;
    registration.aor = attr(node, "aor");
    registration.state = attr(node, "state");
    if (registration.aor.empty() ||
        (registration.state != "init" && registration.state != "active" && registration.state != "terminated"))
      invalid("reginfo registration without aor or state");
    for (auto *child = node->children; child != nullptr; child = child->next) {
      if (!is(child, "contact", reginfo_ns)) continue;
      RegInfo::Contact contact;
      contact.state = attr(child, "state");
      contact.event = attr(child, "event");
      if ((contact.state != "active" && contact.state != "terminated") || contact.event.empty())
        invalid("reginfo contact without state or event");
      if (const auto expires = attr(child, "expires"); !expires.empty())
        contact.expires = unsigned_long(expires);
      auto *uri = unique_child(child, "uri", reginfo_ns);
      contact.uri = trim(text(uri));
      registration.contacts.push_back(std::move(contact));
    }
    info.registrations.push_back(std::move(registration));
  }
  return info;
}

//------------------------------------------------------------------------------
// RFC 3680 section 5.2: canonical decimal digits compare by their length first, then digit by digit.
int compare_reginfo_version(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
  return a.compare(b) < 0 ? -1 : (a == b ? 0 : 1);
}

//------------------------------------------------------------------------------
// RFC 3680 section 5.2: "If the version is more than one higher than the local version".
bool reginfo_version_gap(std::string_view local, std::string_view received) {
  return compare_reginfo_version(received, plus_one(std::string(local))) > 0;
}

} // namespace mcx
