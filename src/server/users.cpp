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
  auto found = users_.find(asserted);
  if (found == users_.end() || found->second.expires <= std::time(nullptr)) throw UnknownUser();
  if (found->second.peer != peer) throw std::runtime_error("user is not served by the requesting server");
  return found->second;
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
