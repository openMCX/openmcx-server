//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MC service profiles (include/mcx/service.hpp) and the places that tell the services apart: MCData has its own
// profile and never falls into the MCPTT branch; the shared request helpers (src/server/parts/message_parts.hpp).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 2046.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "mcx/protocol.hpp"
#include "mcx/service.hpp"
#include "mcx/warning.hpp"
#include "parts/location_service.hpp"
#include "parts/message_parts.hpp"

#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>
using namespace mcx;

//------------------------------------------------------------------------------
// Helper: whether the call throws an exception of the given type.
template <typename Exception, typename Call> static bool throws(Call call) {
  try {
    call();
  } catch (const Exception &) {
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// TS 24.282 annexes C.2, D.1 and D.4: the MCData profile carries the MCData ICSI, media feature tag, mcdata-info and
// location-info types, the mcdata_id claim and the "mcdata_" event prefix; MCPTT and MCVideo keep no prefix.
static void AnnexC2_D1_D4_McdataProfile() {
  static_assert(&service_profile(Service::mcdata) == &mcdata_service);
  static_assert(&service_profile(Service::mcptt) == &mcptt_service);
  static_assert(&service_profile(Service::mcvideo) == &mcvideo_service);
  assert(std::string(mcdata_service.name) == "mcdata");
  assert(std::string(mcdata_service.icsi) == "urn:urn-7:3gpp-service.ims.icsi.mcdata");
  assert(std::string(mcdata_service.info_mime) == "application/vnd.3gpp.mcdata-info+xml");
  assert(std::string(mcdata_service.info_ns) == "urn:3gpp:ns:mcdataInfo:1.0");
  assert(std::string(mcdata_service.location_mime) == "application/vnd.3gpp.mcdata-location-info+xml");
  assert(std::string(mcdata_service.id_claim) == "mcdata_id");
  assert(std::string(mcdata_service.event_prefix) == "mcdata_");
  assert(std::string(mcptt_service.event_prefix).empty() && std::string(mcvideo_service.event_prefix).empty());
  // The Accept-Contact values the MCData server has always sent.
  assert(feature_accept(mcdata_service) == "*;+g.3gpp.mcdata;require;explicit");
  assert(icsi_accept(mcdata_service) ==
         "*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata\";require;explicit");
  assert(feature_accept(mcptt_service) == "*;+g.3gpp.mcptt;require;explicit");
  assert(icsi_accept(mcvideo_service) ==
         "*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcvideo\";require;explicit");
  assert(location_namespace(mcdata_service) == location::Service::Mcdata);
  assert(location_namespace(mcvideo_service) == location::Service::Mcvideo);
  assert(location_namespace(mcptt_service) == location::Service::Mcptt);
}

//------------------------------------------------------------------------------
// The call-handling core serves MCPTT or MCVideo only: a configuration naming "mcdata" is refused.
static void CallServiceNames() {
  static_assert(call_service_named("mcptt") == &mcptt_service);
  static_assert(call_service_named("mcvideo") == &mcvideo_service);
  static_assert(call_service_named("mcdata") == nullptr);
  static_assert(call_service_named("") == nullptr);
}

//------------------------------------------------------------------------------
// TS 24.282 table 4.9.2-2: the MCData warnings of the shared location procedures are MCData's own codes, and a
// warning MCData does not define is refused rather than taken from the MCPTT table.
static void Table_4_9_2_2_McdataWarnings() {
  assert(warning_text(mcdata_service, Warning::unknown_user) == "141 user unknown to the participating function");
  assert(warning_text(mcdata_service, Warning::location_target_invalid) ==
         "244 invalid location request target client list");
  assert(warning_text(mcdata_service, Warning::location_request_not_authorised) ==
         "245 user not authorized to request location information");
  assert(warning_text(mcdata_service, Warning::location_configuration_not_authorised) ==
         "246 user not authorized to request location configuration changes");
  assert(warning_text(mcptt_service, Warning::location_target_invalid) ==
         "192 invalid location request target client list");
  assert(warning_entry(mcdata_service, Warning::service_authorisation_failed).code == 0);
  assert(throws<std::logic_error>([] { (void)warning_text(mcdata_service, Warning::too_many_affiliations); }));
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.4: the MCData emergency location document is in the MCData namespace, not MCPTT's; TS 24.282
// annex D.1: the mcdata-info is not written as an mcptt-info.
static void AnnexD4_D1_McdataDocuments() {
  const EmergencyLocation location{0x123456, 0x654321};
  assert(service_location_xml(location, mcdata_service) == emergency_location_xml(location, true));
  assert(service_location_xml(location, mcptt_service) == emergency_location_xml(location));
  assert(service_location_xml(location, mcvideo_service) != emergency_location_xml(location));
  assert(throws<std::invalid_argument>([] { (void)service_info_xml(McpttInfo{}, mcdata_service); }));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.3, TS 24.282 clause 22.2.2.3.3 step 4a: each service reads its own list of the users
// allowed to activate a functional alias.
static void Clause_9A_2_2_3_3_AliasUserLists() {
  static_assert(std::string_view(alias_user_list(Service::mcptt)) == "users");
  static_assert(std::string_view(alias_user_list(Service::mcvideo)) == "mcvideo_users");
  static_assert(std::string_view(alias_user_list(Service::mcdata)) == "mcdata_users");
}

//------------------------------------------------------------------------------
// RFC 2046 section 5.1: the body parts of a request, split from its multipart body when the SIP engine did not; the
// domain of an identity.
static void Section_5_1_MessageParts() {
  SipMessage message;
  message.content_type = "multipart/mixed; boundary=b";
  message.body = multipart_body({{"text/plain", "one"}, {"application/xml", "<two/>"}}, "b");
  const auto parts = parts_of(message);
  assert(parts.size() == 2);
  assert(part_of(parts, "application/xml") && part_of(parts, "application/xml")->body == "<two/>");
  assert(part_of(parts, "image/png") == nullptr);
  message.parts = {{"text/plain", "kept"}};
  assert(parts_of(message).size() == 1 && parts_of(message).front().body == "kept");
  assert(parts_of(SipMessage{}).empty());
  assert(domain_of("sip:alice@example.com") == "example.com");
  assert(domain_of("a@b@c.org") == "c.org");
  assert(domain_of("no-domain").empty());
}

//------------------------------------------------------------------------------
int main() {
  AnnexC2_D1_D4_McdataProfile();
  CallServiceNames();
  Table_4_9_2_2_McdataWarnings();
  AnnexD4_D1_McdataDocuments();
  Clause_9A_2_2_3_3_AliasUserLists();
  Section_5_1_MessageParts();
  std::cout << "service: all checks passed\n";
}
