// Location procedures of the participating MCData function (TS 24.282 clause 17.2): the host of the shared
// LocationService (parts/location_service.hpp) in the MCData server (member functions of DataServer, declared in
// data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the configuration's mcdata.location section.
Json DataServer::PartsGlue::location_settings() const {
  return server_.cfg_.at("mcdata").value("location", Json::object());
}

//------------------------------------------------------------------------------
// Helper: the MCData user profile, whose "location" object holds the user's location rights.
Json DataServer::PartsGlue::location_profile(const std::string &id) { return server_.profile(id); }

//------------------------------------------------------------------------------
// Helper: the user with the MCData ID, or none.
std::optional<LocationUser> DataServer::PartsGlue::location_user_by_id(const std::string &id) {
  const auto *user = server_.by_id(id);
  return user ? std::optional(location_user_of(*user)) : std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: the user with the public user identity, or none.
std::optional<LocationUser> DataServer::PartsGlue::location_user_by_sip(const std::string &sip) {
  const auto found = server_.users_.find(sip);
  return found == server_.users_.end() ? std::nullopt : std::optional(location_user_of(found->second));
}

//------------------------------------------------------------------------------
// Helper: every user known here.
void DataServer::PartsGlue::each_location_user(
    const std::function<void(const std::string &id, const std::string &peer)> &visit) {
  for (const auto &[sip, user] : server_.users_) visit(user.id, user.peer);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.3: membership from the MCData members of the GMS group document; a group whose document
// cannot be fetched has no members (a malformed document throws, refusing every area).
bool DataServer::PartsGlue::location_group_member(const std::string &group, const std::string &id) {
  std::optional<Json> document;
  try {
    document = server_.group_document(group);
  } catch (const std::exception &) {
    return false;
  }
  return document && document->contains("mcdata") && listed(document->at("mcdata").value("members", Json::array()), id);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 17.2.3.2 step 7b: the users that activated a functional alias.
std::vector<std::string> DataServer::PartsGlue::location_alias_users(const std::string &alias) {
  return server_.alias_users(alias, {});
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.1: the mcdata-info body part, as the location procedures read it.
LocationInfo DataServer::PartsGlue::location_info(const SipMessage & /*message*/, const BodyPart &info_part) {
  const auto info = mcdata::parse_info(info_part.body);
  LocationInfo read;
  read.calling_user = info.calling_user;
  read.location_of_functional_alias = info.location_of_functional_alias;
  return read;
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.1: the mcdata-info body of a location procedure.
std::vector<BodyPart> DataServer::PartsGlue::location_info_parts(const LocationInfo &info) {
  mcdata::Info written;
  written.request_uri = info.request_uri;
  written.calling_user = info.calling_user;
  written.associated_group = info.associated_group;
  written.emergency_alert_area = info.emergency_alert_area;
  written.group_geo_area = info.group_geo_area;
  return {{std::string(mcdata::info_mime), mcdata::info_xml(written)}};
}

} // namespace mcx
