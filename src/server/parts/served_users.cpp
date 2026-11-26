//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The users an MC server serves (served_users.hpp).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).

#include "parts/served_users.hpp"

#include "request_values.hpp"

#include <algorithm>

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
// TS 24.379 clauses 7.3.3 and 7.3.4 condition 3: the request URI and client ID without an access token make a PUBLISH
// for the service settings only; one service information body, readable, is needed for it.
PocSettingsPublish poc_settings_publish_kind(const std::vector<BodyPart> &parts, const ServiceProfile &service) {
  const BodyPart *info = nullptr;
  for (const auto &part : parts)
    if (part.content_type == service.info_mime) {
      if (info) return PocSettingsPublish::service_authorisation;
      info = &part;
    }
  if (!info) return PocSettingsPublish::service_authorisation;
  std::set<std::string> params;
  try {
    params = service_info_params(info->body, service);
  } catch (const std::exception &) {
    return PocSettingsPublish::service_authorisation;
  }
  const std::string prefix = std::string(service.info_prefix) + "-";
  if (params.contains(prefix + "access-token")) return PocSettingsPublish::service_authorisation;
  if (params.contains(prefix + "request-uri") && params.contains(prefix + "client-id"))
    return PocSettingsPublish::settings_only;
  return PocSettingsPublish::service_authorisation;
}

//------------------------------------------------------------------------------
// RFC 3903 section 6 steps 2 to 5 for the settings publication: Expires, then the entity tag (a single one, of the
// user's publication), then a body for an initial publication.
SettingsPublication settings_publication(std::string_view if_match, std::string_view expires, std::string_view etag,
                                         bool has_body) {
  SettingsPublication out;
  out.expires = max_expires_s;
  if (!expires.empty()) {
    const auto value = parse_expires(expires);
    if (!value) {
      out.status = 400;
      return out;
    }
    out.expires = *value;
  }
  if (if_match.find(',') != std::string_view::npos || (if_match.empty() && !has_body))
    out.status = 400;
  else if (!if_match.empty() && (etag.empty() || if_match != etag))
    out.status = 412;
  return out;
}

//------------------------------------------------------------------------------
// RFC 4354 <answer-mode> ("automatic", "manual"; TS 24.379 writes "auto-answer" and "manual-answer" in its text) as an
// RFC 5373 value; <multiplex-support> absent is false (TS 24.379 clause 7.3.4 step 10a).
ServiceSettings read_service_settings(std::string_view xml, std::string_view client_id, std::int64_t expires) {
  const auto entities = parse_poc_settings(xml);
  const auto entity = std::find_if(entities.begin(), entities.end(),
                                   [&](const PocSettingsEntity &candidate) { return candidate.id == client_id; });
  if (entity == entities.end()) throw std::runtime_error("poc-settings without the client's entity");
  ServiceSettings settings;
  if (entity->answer_mode == "automatic" || entity->answer_mode == "auto-answer")
    settings.answer_mode = "Auto";
  else if (entity->answer_mode == "manual" || entity->answer_mode == "manual-answer")
    settings.answer_mode = "Manual";
  settings.profile_index = entity->profile_index;
  settings.multiplex_support = entity->multiplex_support.value_or(false);
  settings.expires = expires;
  return settings;
}

//------------------------------------------------------------------------------
// Helper: the cached Answer-Mode Indication while the settings last.
std::string cached_answer_mode(const ServedUser &user, std::int64_t now) {
  return user.settings && user.settings->expires > now ? user.settings->answer_mode : std::string{};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.3.2 (clause 17.3.2.1.2 for an ad hoc group call): the terminating participating function
// performs automatic (step 7) or manual (step 8) commencement when the INVITE "does not contain an Answer-Mode header
// field and the Answer-Mode Indication received in the application/poc-settings+xml MIME body received from the
// invited MCPTT client as per clause 7.3.3 or clause 7.3.4 is set to" auto-answer or manual-answer. The controlling
// function adds no Answer-Mode (clause 10.1.1.4.1.1 with clause 6.3.3.1.2 step 10; a group call's originating INVITE
// has none), so the member's own setting decides (clauses 6.3.2.2.5.2 step 8 and 6.3.2.2.6.2 step 5).
std::string group_answer_mode(const ServedUser &user, std::int64_t now, const std::string &fallback) {
  if (auto mode = cached_answer_mode(user, now); !mode.empty()) return mode;
  if (!user.peer.empty()) return {};
  return fallback;
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
