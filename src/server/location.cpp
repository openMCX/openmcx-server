//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Location procedures of the participating function (TS 24.379 clause 13, for MCVideo TS 24.281 clause 18): the host
// of the shared LocationService (parts/location_service.hpp) in the MCPTT and MCVideo core, and the removal of
// location requests from a relayed request (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the configuration's <service>.location section.
Json McServer::PartsGlue::location_settings() const {
  return server_.cfg_.at(server_.svc_.name).value("location", Json::object());
}

//------------------------------------------------------------------------------
// Helper: the user profile, whose "location" object holds the user's location rights.
Json McServer::PartsGlue::location_profile(const std::string &id) { return server_.user_profile(id); }

//------------------------------------------------------------------------------
// Helper: the user with the MCPTT ID (or MCVideo ID), or none.
std::optional<LocationUser> McServer::PartsGlue::location_user_by_id(const std::string &id) {
  const auto *user = server_.by_id(id);
  return user ? std::optional(location_user_of(*user)) : std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: the user with the public user identity, or none.
std::optional<LocationUser> McServer::PartsGlue::location_user_by_sip(const std::string &sip) {
  const auto found = server_.users_.find(sip);
  return found == server_.users_.end() ? std::nullopt : std::optional(location_user_of(found->second));
}

//------------------------------------------------------------------------------
// Helper: every user known here, served here or through a peer.
void McServer::PartsGlue::each_location_user(
    const std::function<void(const std::string &id, const std::string &peer)> &visit) {
  for (const auto &[sip, user] : server_.users_) visit(user.id, user.peer);
}

//------------------------------------------------------------------------------
// Helper: group membership from the group profile; a group that cannot be read has no members.
bool McServer::PartsGlue::location_group_member(const std::string &group, const std::string &id) {
  try {
    return server_.member(server_.group_profile(group), id);
  } catch (const std::exception &) {
    return false;
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7b: the users that activated a functional alias.
std::vector<std::string> McServer::PartsGlue::location_alias_users(const std::string &alias) {
  return server_.functional_alias_users(alias);
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1: the request's one mcptt-info (or mcvideo-info), as the location procedures read it.
LocationInfo McServer::PartsGlue::location_info(const SipMessage &message, const BodyPart & /*info_part*/) {
  const auto info = message_info(message, server_.svc_);
  LocationInfo read;
  read.calling_user = info.calling_user;
  read.location_of_functional_alias = info.location_of_functional_alias;
  return read;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1: the mcptt-info (or mcvideo-info) body of a location procedure.
std::vector<BodyPart> McServer::PartsGlue::location_info_parts(const LocationInfo &info) {
  McpttInfo written;
  written.request_uri = info.request_uri;
  written.calling_user = info.calling_user;
  written.associated_group = info.associated_group;
  written.emergency_alert_area = info.emergency_alert_area;
  written.group_geo_area = info.group_geo_area;
  return server_.service_parts(written);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.5: a location request or configuration never reaches a client inside a request
// relayed to it.
std::pair<std::string, std::string> McServer::without_location_requests(const std::string &type,
                                                                        const std::string &body) {
  std::vector<BodyPart> parts;
  try {
    parts = parse_body_parts(type, body);
  } catch (const std::exception &) {
    return {type, body};
  }
  const auto before = parts.size();
  parts = location_.without_requests(std::move(parts));
  if (parts.size() == before) return {type, body};
  if (parts.empty()) return {"", ""};
  if (parts.size() == 1) return {parts.front().content_type, parts.front().body};
  const auto boundary = "mcx-" + random_id();
  return {"multipart/mixed; boundary=" + boundary, multipart_body(parts, boundary)};
}

} // namespace mcx
