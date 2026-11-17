//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The users an MC server serves, shared by the MCPTT and MCVideo servers (McServer, whose user adds the call keys and
// the affiliation subscription's expiry) and the MCData server (DataServer): the binding of MC service ID, client ID
// and public user identity made by service authorisation (TS 24.379 clause 7.3.3 step 5a, TS 24.282 clause 7.3.3
// step 5a), the user's affiliations (TS 24.379 clause 9.2.2, TS 24.282 clause 8.3) and the affiliation document of
// its status (TS 24.379 clause 9.3.1, TS 24.282 clause 8.4.1).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 33.180
// V19.4.0 (Rel-19).
#pragma once

#include "mcx/keying.hpp"
#include "mcx/protocol.hpp"
#include "mcx/runtime.hpp"
#include "mcx/service.hpp"

#include <cstdint>
#include <ctime>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// TS 24.379 clauses 7.3.3 and 7.3.4 steps 8 to 12 (TS 24.281 clause 7.3.4, TS 24.282 clause 7.3.4 steps 8 to 11): the
// service settings of a client from its application/poc-settings+xml (RFC 4354 with TS 24.379 clause 7.4.1.2.2):
// answer_mode, the current Answer-Mode Indication (step 10) as an RFC 5373 value, "Auto" or "Manual" ("" when the
// document has none or one this server does not know); profile_index, the <selected-user-profile-index> (step 11);
// multiplex_support, <multiplex-support> (step 10a: absent is false); expires, the end of the publication (step 8).
struct ServiceSettings {
  std::string answer_mode;
  std::optional<unsigned> profile_index;
  bool multiplex_support = false;
  std::int64_t expires = 0;
};

//------------------------------------------------------------------------------
// A service authorised user (TS 24.379 clause 7.3.3 step 5a). peer: the server of a user served elsewhere (MCPTT-3),
// learned from its registration; empty for a user served here. subscription: the dialog of its affiliation status
// subscription (TS 24.379 clause 9.2.2.2.5, TS 24.282 clause 8.3.2.4); the entity tags of its service
// authorisation and affiliation publications (RFC 3903); groups: its affiliated groups; csk: the CSK its client
// uploaded at service authorisation (TS 33.180 clause 5.1.5, TS 24.379 clause 6.6.2.2); expires: the end of its
// service authorisation.
struct ServedUser {
  std::string id, client, sip, subscription, auth_etag, affiliation_etag, peer;
  std::set<std::string> groups;
  std::optional<keying::KeyMessage> csk;
  std::int64_t expires = 0;
  // TS 24.379 clauses 7.3.3 and 7.3.4 step 8 (TS 24.281, TS 24.282 likewise): the service settings the client
  // published, cached until they expire; none before the client published any (an authorisation by REGISTER).
  std::optional<ServiceSettings> settings;
};

//------------------------------------------------------------------------------
// Helper: the served user with the MC service ID, or nullptr; with `live_only`, only while its service authorisation
// lasts (MCData).
template <typename User> User *served_by_id(std::map<std::string, User> &users, const std::string &id, bool live_only) {
  for (auto &[sip, user] : users)
    if (user.id == id && (!live_only || user.expires > std::time(nullptr))) return &user;
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 7.3.3 and 7.3.4 (TS 24.281 and TS 24.282 clauses 7.3.3 and 7.3.4): the procedure a SIP PUBLISH
// for poc-settings (Expires other than 0, clause 7.3.5) starts. Its service information names, in <prefix>-Params,
// the access token and client ID for a service authorisation (clause 7.3.3, condition 3), the request URI and client
// ID without access token for the service settings only (clause 7.3.4, condition 3). Whether an element is there does
// not depend on its content being encrypted (clause 7.3.1A: a service authorisation's CSK, which may key the access
// token, is only known once the request is handled). Anything else is handled as a service authorisation, which
// refuses it.
enum class PocSettingsPublish { service_authorisation, settings_only };
PocSettingsPublish poc_settings_publish_kind(const std::vector<BodyPart> &parts, const ServiceProfile &service);

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.4 step 7 (TS 24.281 and TS 24.282 likewise): RFC 3903 section 6 for a PUBLISH of the service
// settings, against the entity tag of the user's publication (`etag`, the one its service authorisation or last
// settings publication was given; empty for none): status 0 to go on, else the answer: 400 for an Expires that is not
// delta-seconds (RFC 3261 section 20.19), more than one entity tag in SIP-If-Match, or neither entity tag nor body
// (section 6 step 5); 412 for an entity tag naming no publication of the user (section 6 step 3). expires is the
// publication's lifetime: the requested one, else (no Expires) the longest (as a service authorisation's).
struct SettingsPublication {
  int status = 0;
  std::uint64_t expires = 0;
};
SettingsPublication settings_publication(std::string_view if_match, std::string_view expires, std::string_view etag,
                                         bool has_body);

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.4 steps 8, 10, 10a and 11 (TS 24.281 likewise; TS 24.282 steps 8 and 10): the service settings
// of the client in an application/poc-settings+xml document: those of the <entity> whose "id" is its client ID
// (RFC 4354 section 5.1). Throws when the document cannot be read or has no entity for the client.
ServiceSettings read_service_settings(std::string_view xml, std::string_view client_id, std::int64_t expires);

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.2.2.5.2 and 6.3.2.2.6.2 step 5 (TS 24.281 likewise): the current Answer-Mode Indication of the
// client from its cached service settings ("Auto" or "Manual"), "" when none is cached or they have expired.
std::string cached_answer_mode(const ServedUser &user, std::int64_t now);

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.4 steps 4 and 6 (TS 24.281 and TS 24.282 likewise): the binding between the IMS public user
// identity and the MC service ID named in the request, with the client ID of the request (the binding of clause 7.3.3
// step 5a is of the three), served here and whose validity has not expired; nullptr for none.
template <typename User>
User *settings_binding(std::map<std::string, User> &users, const std::string &identity, const std::string &id,
                       const std::string &client, std::int64_t now) {
  const auto found = users.find(identity);
  if (found == users.end() || id.empty() || found->second.id != id || found->second.client != client ||
      !found->second.peer.empty() || found->second.expires <= now)
    return nullptr;
  return &found->second;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1, TS 24.281 clause 8.3.1, TS 24.282 clause 8.4.1: an affiliation document of the user's client
// in the service's presence namespace, with the publication's p-id.
Affiliation service_affiliation(const ServiceProfile &service, const std::string &user, const std::string &client,
                                std::string publication_id);

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.5, TS 24.282 clause 8.3.2.5: the affiliation status of a user: every affiliated group.
Affiliation affiliation_status(const ServiceProfile &service, const ServedUser &user, std::string publication_id);

//------------------------------------------------------------------------------
// Helper: whether a JSON list (of a group or policy document) names the ID; anything but a list names nobody.
bool listed(const Json &list, const std::string &id);

//------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2 and TS 24.282 clause 11.1 step 2: whether an MCData group's document lets a member
// transmit data in the group (<mcdata-allow-transmit-data-in-this-group>): for every member ("transmit_all"), or for
// those listed ("transmit_members"); with neither, no member may.
bool transmit_allowed(const Json &settings, const std::string &id);
} // namespace mcx
