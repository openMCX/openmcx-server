// Helpers on received SIP requests shared by the MC servers (message_parts.hpp).
//
// Specifications: RFC 2046, RFC 3261.

#include "parts/message_parts.hpp"

#include <algorithm>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the body parts of a request, parsed from its body when the SIP engine did not split it.
std::vector<BodyPart> parts_of(const SipMessage &message) {
  return message.parts.empty() && !message.body.empty() ? parse_body_parts(message.content_type, message.body)
                                                        : message.parts;
}

//------------------------------------------------------------------------------
// Helper: the first body part of the given content type, or nullptr.
const BodyPart *part_of(const std::vector<BodyPart> &parts, std::string_view type) {
  const auto found =
      std::find_if(parts.begin(), parts.end(), [&](const BodyPart &part) { return part.content_type == type; });
  return found == parts.end() ? nullptr : &*found;
}

//------------------------------------------------------------------------------
// Helper: the domain of a URI, the part after its last '@'; empty without one.
std::string domain_of(const std::string &uri) {
  const auto at = uri.rfind('@');
  return at == std::string::npos ? std::string{} : uri.substr(at + 1);
}

} // namespace mcx
