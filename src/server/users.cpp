//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Users, groups and their policies as the server holds them (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the authorised user sending a SIP request. A local client's request arrives through the SIP core
// with its asserted identity in From; a peer participating server asserts its user's identity.
McServer::User &McServer::authenticated(const SipMessage &message) {
  const auto peer = message.source_address == core_address_ ? std::string{} : peer_at(message.source_address);
  if (message.source_address != core_address_ && peer.empty()) throw std::runtime_error("untrusted SIP source");
  auto asserted = asserted_identity(message);
  if (asserted.empty() || (peer.empty() && asserted != message.from_uri))
    throw std::runtime_error("asserted SIP identity mismatch");
  if (!peer.empty() && role_ == "participating")
    throw std::runtime_error("a participating server does not control calls");
  if (auto *standard = standard_peer_caller(message, peer, asserted)) return *standard;
  auto found = users_.find(asserted);
  if (found == users_.end() || found->second.expires <= std::time(nullptr)) throw UnknownUser();
  if (found->second.peer != peer) throw std::runtime_error("user is not served by the requesting server");
  return found->second;
}

//------------------------------------------------------------------------------
// TS 100 392-19-1 clause 9.2.1 NOTE 3 (TS 29.379 clause 10.1.3.1.1): a peer taking the standard affiliation, an IWF,
// asserts its own PSI and names the calling user in <mcptt-calling-user-id>; where the IWF affiliates on behalf of its
// users, the MCPTT system "will need to accept call setup and floor control requests" from users it has no
// affiliation of. The calling user is then a user served by the peer, holding the groups the peer's affiliated
// identities hold. Returns nullptr for any other request.
McServer::User *McServer::standard_peer_caller(const SipMessage &message, const std::string &peer,
                                               const std::string &asserted) {
  if (peer.empty()) return nullptr;
  const auto found_peer = peers_.find(peer);
  if (found_peer == peers_.end() || !found_peer->second.standard_affiliation ||
      bare_uri(asserted) != found_peer->second.service_uri)
    return nullptr;
  const auto info = message_info(message, svc_);
  if (info.calling_user.empty()) throw UnknownUser();
  std::set<std::string> groups;
  for (const auto &[sip, user] : users_)
    if (user.peer == peer && user.id != info.calling_user && user.expires > std::time(nullptr))
      groups.insert(user.groups.begin(), user.groups.end());
  auto &caller = users_[info.calling_user];
  if (!caller.peer.empty() && caller.peer != peer) throw std::runtime_error("user is served by another server");
  if (caller.id.empty()) {
    caller.id = caller.sip = info.calling_user;
    caller.peer = peer;
    caller.expires = std::time(nullptr) + static_cast<std::int64_t>(4294967295LL);
    event("standard_peer_caller", {{"user_id", caller.id}, {"server", peer}});
  }
  if (!info.client_id.empty()) caller.client = info.client_id;
  // A caller individually affiliated keeps its own groups; one admitted through the peer's affiliation, those.
  if (!standard_affiliated(caller.id)) caller.groups = std::move(groups);
  return &caller;
}

//------------------------------------------------------------------------------
// TS 100 392-19-1 clause 9.2.1 NOTES 3 and 5: a user served by a standard peer is vouched for in a group when another
// identity of that peer, a member of the group (the IWF's own), is affiliated to it.
bool McServer::standard_peer_vouched(const User &user, const std::string &group, const Json &profile) const {
  if (user.peer.empty()) return false;
  const auto peer = peers_.find(user.peer);
  if (peer == peers_.end() || !peer->second.standard_affiliation) return false;
  const auto members = profile.value("members", std::vector<std::string>{});
  for (const auto &[sip, other] : users_)
    if (other.peer == user.peer && other.id != user.id && other.groups.contains(group) &&
        std::find(members.begin(), members.end(), other.id) != members.end())
      return true;
  return false;
}

//------------------------------------------------------------------------------
// TS 29.380 clause 6.4.4.4 step 1c: an IWF's floor participant names the LMR user it requests the floor for. On the
// leg of a standard peer's own identity, a User ID naming a user that no other server or registration serves is
// that peer's user (the trust of standard_peer_caller).
bool McServer::standard_peer_names(const std::string &leg_user, const std::string &named) {
  const auto *own = by_id(leg_user);
  if (own == nullptr || own->peer.empty()) return false;
  const auto peer = peers_.find(own->peer);
  if (peer == peers_.end() || !peer->second.standard_affiliation) return false;
  const auto *user = by_id(named);
  return user == nullptr || user->peer == own->peer;
}

//------------------------------------------------------------------------------
// The members of a group call: those of the group document, and the users a standard peer vouches for in the group
// (TS 100 392-19-1 clause 9.2.1 NOTES 3 and 5), so that they stay in the call and take part in floor arbitration.
std::vector<std::string> McServer::call_members(const Json &profile, const std::string &group) const {
  auto members = profile.at("members").get<std::vector<std::string>>();
  for (const auto &[sip, user] : users_)
    if (user.groups.contains(group) && std::find(members.begin(), members.end(), user.id) == members.end() &&
        standard_peer_vouched(user, group, profile))
      members.push_back(user.id);
  return members;
}

//------------------------------------------------------------------------------
// Helper: whether the user has standard per-group affiliations of its own (peer_group_affiliation.cpp).
bool McServer::standard_affiliated(const std::string &id) const {
  for (const auto &[group, members] : standard_affiliations_)
    if (members.contains(id)) return true;
  return false;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.1: the group document of a group or regroup from the GMS. A regroup takes its entire
// configuration from the preconfigured group, without <preconfigured-group-use-only>, and its members are
// those of the constituent groups, or for a user regroup the users named.
Json McServer::group_profile(const std::string &id) {
  if (const auto found = regroups_.find(id); found != regroups_.end()) {
    auto group = service_members(internal("gms", "/internal/group?id=" + url_encode(found->second.preconfigured)));
    group["id"] = id;
    group.erase("preconfigured_use_only");
    group["regrouped"] = false;
    std::vector<std::string> members = found->second.users;
    for (const auto &constituent : found->second.groups) {
      Json document;
      try {
        document = service_members(internal("gms", "/internal/group?id=" + url_encode(constituent)));
      } catch (const std::exception &) {
        continue;
      }
      // A temporary group whose document names no priorities takes those of its
      // first constituent group that has them (TS 24.481 clause 7.2.4.2 leaves the
      // temporary group's <on-network-group-priority> optional).
      if (found->second.temporary && !group.contains("priority_policy") && document.contains("priority_policy"))
        group["priority_policy"] = document["priority_policy"];
      for (const auto &id_value : document.value("members", std::vector<std::string>{}))
        if (std::find(members.begin(), members.end(), id_value) == members.end()) members.push_back(id_value);
    }
    group["members"] = members;
    return with_protection(std::move(group));
  }
  return with_protection(service_members(internal("gms", "/internal/group?id=" + url_encode(id))));
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.2.8: <protect-media> and <protect-floor-control-signalling> are "true" when not present.
// The group document is given both explicitly, so that every reader sees the same values; a protected group needs
// the key management client of this server.
Json McServer::with_protection(Json group) const {
  for (const auto *name : {"protect_media", "protect_floor"})
    if (!group.contains(name) || !group[name].is_boolean()) group[name] = true;
  if ((group["protect_media"].get<bool>() || group["protect_floor"].get<bool>()) && !keys_)
    throw std::runtime_error("protected group keying unavailable");
  return group;
}

//------------------------------------------------------------------------------
// Helper: whether the group document lists the given ID among its members.
bool McServer::member(const Json &group, const std::string &id) {
  auto members = group.at("members").get<std::vector<std::string>>();
  return std::find(members.begin(), members.end(), id) != members.end();
}

//------------------------------------------------------------------------------
// Helper: whether the policy's list under key names the ID; an absent list authorises nobody (unlike
// policy_allows).
bool McServer::policy_allows_listed(const Json &policy, const char *key, const std::string &id) {
  if (!policy.contains(key)) return false;
  const auto allowed = policy.at(key).get<std::vector<std::string>>();
  return std::find(allowed.begin(), allowed.end(), id) != allowed.end();
}

//------------------------------------------------------------------------------
// Helper: whether the policy's list under key names the ID; an absent list authorises every member.
bool McServer::policy_allows(const Json &policy, const char *key, const std::string &id) const {
  if (!policy.contains(key)) return true; // provisioned member-wide permission by default
  const auto allowed = policy.at(key).get<std::vector<std::string>>();
  return std::find(allowed.begin(), allowed.end(), id) != allowed.end();
}

} // namespace mcx
