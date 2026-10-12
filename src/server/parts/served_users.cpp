//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The users an MC server serves (served_users.hpp).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).

#include "parts/served_users.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1, TS 24.281 clause 8.3.1, TS 24.282 clause 8.4.1: the namespace is MCPTT's unless the
// MCVideo or MCData flag is set.
Affiliation service_affiliation(const ServiceProfile &service, const std::string &user, const std::string &client,
                                std::string publication_id) {
  Affiliation affiliation{user, client, std::move(publication_id), {}, {}};
  affiliation.mcvideo = service.service == Service::mcvideo;
  affiliation.mcdata = service.service == Service::mcdata;
  return affiliation;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.5, TS 24.282 clause 8.3.2.5: every affiliated group, with status "affiliated".
Affiliation affiliation_status(const ServiceProfile &service, const ServedUser &user, std::string publication_id) {
  auto affiliation = service_affiliation(service, user.id, user.client, std::move(publication_id));
  for (const auto &group : user.groups) {
    affiliation.groups.push_back(group);
    affiliation.statuses.push_back("affiliated");
  }
  return affiliation;
}

//------------------------------------------------------------------------------
// Helper: whether a JSON list names the ID.
bool listed(const Json &list, const std::string &id) {
  if (!list.is_array()) return false;
  for (const auto &entry : list)
    if (entry.is_string() && entry.get<std::string>() == id) return true;
  return false;
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: the group's <mcdata-allow-transmit-data-in-this-group> for a member.
bool transmit_allowed(const Json &settings, const std::string &id) {
  if (settings.value("transmit_all", false)) return true;
  return settings.contains("transmit_members") && listed(settings.at("transmit_members"), id);
}

} // namespace mcx
