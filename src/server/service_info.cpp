//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Service information of the MCPTT and MCVideo servers: the program's service checked against the configuration,
// its media feature tag, ICSI, Warning header field texts, media plane controller and affiliation namespace
// (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19),
// TS 24.581 V19.2.0 (Rel-19), RFC 6809.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the service profile (MCPTT or MCVideo) of the program, which the configuration's "service" entry
// ("mcptt" by default) must name: a configuration of the other service is refused.
const ServiceProfile &McServer::configured_service(const ServiceProfile &served, const Json &cfg) {
  const auto name = cfg.value("service", std::string("mcptt"));
  // "mcdata" is refused as well: the MCData server (DataServer) is not built on this core.
  if (!call_service_named(name)) throw std::runtime_error("service must be mcptt or mcvideo");
  if (name != served.name)
    throw std::runtime_error("the configuration is for the " + name + " service; this program is the " + served.label +
                             " server");
  return served;
}

//------------------------------------------------------------------------------
// TS 24.379 annex D.2, TS 24.281 annex D.2: an Accept-Contact value requiring the service's media feature tag
// (g.3gpp.mcptt or g.3gpp.mcvideo).
[[nodiscard]] std::string McServer::feature_accept() const { return mcx::feature_accept(svc_); }

//------------------------------------------------------------------------------
// TS 24.379 annex E.2, TS 24.281 annex E.2: an Accept-Contact value requiring the service's ICSI.
[[nodiscard]] std::string McServer::icsi_accept() const { return mcx::icsi_accept(svc_); }

//------------------------------------------------------------------------------
// TS 24.379 annexes D.2 and E.2, TS 24.281 annexes D.2 and E.2: the media feature tag and ICSI parameters of
// the service, appended to a Contact header field.
[[nodiscard]] std::string McServer::service_tags() const {
  return std::string(";+") + svc_.feature_tag + ";+g.3gpp.icsi-ref=\"" + svc_.icsi_encoded + "\"";
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4, TS 24.581 clause 6.3.4: the media plane control server of a call: floor control for
// MCPTT, transmission control for MCVideo. Both arbitrate one transmitting participant with queueing, priority
// and revocation (TS 24.581 clause 6.3.4 follows TS 24.380 clause 6.3.4), so the same arbitrator serves; the
// server encodes its notices as floor or transmission control messages (send_notice).
std::unique_ptr<MediaPlaneController> McServer::make_media_control(std::vector<std::string> members,
                                                                   const FloorArbitratorOptions &options) const {
  return std::make_unique<FloorArbitrator>(std::move(members), options);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.4.2, TS 24.281 clause 4.4.2: the Warning header field text of the service for a warning code.
[[nodiscard]] std::string McServer::warn(Warning warning, std::string_view detail) const {
  return warning_text(svc_, warning, detail);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1, TS 24.281 clause 8.3.1: whether an affiliation document belongs to this service's
// presence namespace (MCData exactly when this server serves MCData, which a McServer never does, and MCVideo exactly
// when this server is the MCVideo server).
[[nodiscard]] bool McServer::own_affiliation(const Affiliation &affiliation) const {
  return affiliation.mcdata == (svc_.service == Service::mcdata) &&
         affiliation.mcvideo == (svc_.service == Service::mcvideo);
}

} // namespace mcx
