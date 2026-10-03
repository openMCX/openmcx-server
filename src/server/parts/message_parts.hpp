// Helpers on received SIP requests shared by the MC servers: their MIME body parts (RFC 2046 section 5.1) and the
// domain of an identity.
//
// Specifications: RFC 2046, RFC 3261.
#pragma once

#include "mcx/protocol.hpp"
#include "mcx/sip.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// Helper: the body parts of a request, parsed from its body when the SIP engine did not split it (RFC 2046 section
// 5.1).
std::vector<BodyPart> parts_of(const SipMessage &message);

//------------------------------------------------------------------------------
// Helper: the first body part of the given content type, or nullptr.
const BodyPart *part_of(const std::vector<BodyPart> &parts, std::string_view type);

//------------------------------------------------------------------------------
// Helper: the domain of a URI, the part after its last '@'; empty without one.
std::string domain_of(const std::string &uri);
} // namespace mcx
