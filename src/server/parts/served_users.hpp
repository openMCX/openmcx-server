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

namespace mcx {
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
