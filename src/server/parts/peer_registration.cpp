//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Peer registration, both sides (peer_registration.hpp). The clauses are those of TS 24.379 clause 9.2.2.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 3261, RFC 3903.

#include "parts/peer_registration.hpp"

#include "mcx/http.hpp"
#include "parts/served_users.hpp"

#include <ctime>

namespace mcx {

//------------------------------------------------------------------------------
PeerRegistration::PeerRegistration(PeerRegistrationHost &host, const ServiceProfile &service)
    : host_(host), service_(service) {}

//------------------------------------------------------------------------------
// Helper: an event name with the service's prefix.
std::string PeerRegistration::event_name(std::string_view suffix) const {
  return std::string(service_.event_prefix) + std::string(suffix);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.6: the PUBLISH of one served user to one peer: an affiliation document in the service's
// namespace (TS 24.379 clause 9.3.1) with the affiliations to the groups that peer controls,
// protected as any body to that peer.
void PeerRegistration::publish_to(const PeerUser &user, const std::string &name, const ServicePeer &peer, bool active,
                                  bool refresh) {
  auto affiliation = service_affiliation(service_, user.id, user.client, random_id());
  if (active && user.affiliations_current)
    for (const auto &group : user.groups)
      if (host_.registration_group_controller(group) == name) {
        affiliation.groups.push_back(group);
        affiliation.statuses.push_back("affiliated");
      }
  const auto remaining = active ? user.expires - std::time(nullptr) : 0;
  std::vector<SipHeader> headers{
      {"Event", "presence"}, {"Expires", std::to_string(remaining)}, {"P-Asserted-Identity", "<" + user.sip + ">"}};
  try {
    const auto body =
        host_.seal_for_peer(name, {{"application/pidf+xml", affiliation_xml(affiliation, false)}}).front().body;
    host_.publish(peer.service_uri, "application/pidf+xml", body, host_.route_to(name, std::move(headers)),
                  [kind = event_name("peer_registration"), id = user.id, name, groups = affiliation.groups,
                   refresh](const SipResponse &response) {
                    if (response.status_code >= 300 || (response.status_code >= 200 && !refresh))
                      event(kind,
                            {{"user_id", id}, {"server", name}, {"status", response.status_code}, {"groups", groups}});
                  });
  } catch (const std::exception &error) {
    event(event_name("peer_registration_failed"), {{"user_id", user.id}, {"server", name}, {"reason", error.what()}});
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.6: the participating function reports each served user's service authorization and group
// affiliations to the controlling servers (an affiliation to a group controlled elsewhere goes to the server owning
// that group); Expires 0 withdraws the user.
void PeerRegistration::publish(const PeerUser &user, bool withdraw, bool refresh) {
  if (!user.peer.empty()) return;
  const bool active = !withdraw && user.expires > std::time(nullptr);
  for (const auto &[name, peer] : host_.peer_table()) {
    if (!peer.controlling) continue;
    publish_to(user, name, peer, active, refresh);
  }
}

//------------------------------------------------------------------------------
// Helper: the registrations repeated every <service>.registration_refresh_ms, so that a restarted peer learns the
// users again.
void PeerRegistration::refresh(std::uint64_t now) {
  const auto period = host_.registration_refresh_ms();
  if (!period || host_.peer_table().empty() || now - last_refresh_ < period) return;
  last_refresh_ = now;
  host_.each_registration_user([&](const PeerUser &user) {
    if (user.peer.empty() && user.expires > std::time(nullptr)) publish(user, false, true);
  });
}

//------------------------------------------------------------------------------
// Helper: whether a registration changes the user's entry (a periodic refresh with unchanged affiliations only
// extends it).
bool PeerRegistration::changes(const std::optional<PeerUser> &previous, const Affiliation &affiliation,
                               const std::string &peer, const std::set<std::string> &groups) {
  return !previous || previous->id != affiliation.user_id || previous->client != affiliation.client_id ||
         previous->peer != peer || previous->expires <= std::time(nullptr) || previous->groups != groups;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3: the server owning the groups receives a peer registration: the user, its client and its
// affiliations to groups controlled here. A user served here, or one whose ID another identity holds, is refused.
SipResponse PeerRegistration::receive(const SipMessage &message, const std::string &peer) {
  SipResponse response;
  response.status_code = 200;
  Affiliation affiliation;
  std::uint64_t expires = 0;
  if (const auto refusal = host_.registration_refusal(message, affiliation, expires)) {
    response.status_code = *refusal;
    return response;
  }
  const auto asserted = asserted_identity(message);
  const auto found = host_.registration_user(asserted);
  const auto other = host_.registration_user_by_id(affiliation.user_id);
  if ((found && found->peer.empty() && found->expires > std::time(nullptr)) || (other && other->sip != asserted)) {
    response.status_code = 403;
    return response;
  }
  if (expires == 0) {
    if (found && found->peer == peer) {
      host_.withdraw_peer_user(asserted, affiliation.user_id);
      event(event_name("peer_user_withdrawn"), {{"user_id", affiliation.user_id}, {"server", peer}});
    }
    response.headers = {{"Expires", "0"}};
    return response;
  }
  std::set<std::string> groups;
  for (const auto &group : affiliation.groups) {
    if (!host_.registration_group_allowed(group, affiliation.user_id, peer)) {
      response.status_code = 403;
      return response;
    }
    groups.insert(group);
  }
  const bool changed = changes(found, affiliation, peer, groups);
  host_.update_peer_user(asserted, affiliation, peer, groups, expires);
  response.headers = {{"Expires", std::to_string(expires)}};
  if (!changed) return response;
  host_.peer_user_changed(asserted, found, groups);
  const auto registered = host_.registration_user(asserted);
  event(event_name("peer_user_registered"),
        {{"user_id", affiliation.user_id}, {"server", peer}, {"groups", registered ? registered->groups : groups}});
  return response;
}

} // namespace mcx
