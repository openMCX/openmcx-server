//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The registration information document of the reg event package (RFC 3680 section 5, application/reginfo+xml),
// which a UE reads from the NOTIFYs of its subscription to its own registration state (TS 24.229 clauses 5.1.1.3,
// 5.1.1.5A and 5.1.1.7).
//
// Specifications: RFC 3680; TS 24.229 V19.7.0 (Rel-19).

#include "protocol_internal.hpp"

#include <limits>

namespace mcx {
namespace {
constexpr const char *reginfo_ns = "urn:ietf:params:xml:ns:reginfo";
}

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
  info.version = number(version, std::numeric_limits<std::uint32_t>::max());
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
        contact.expires = number(expires, std::numeric_limits<std::uint32_t>::max());
      auto *uri = unique_child(child, "uri", reginfo_ns);
      contact.uri = trim(text(uri));
      registration.contacts.push_back(std::move(contact));
    }
    info.registrations.push_back(std::move(registration));
  }
  return info;
}

} // namespace mcx
