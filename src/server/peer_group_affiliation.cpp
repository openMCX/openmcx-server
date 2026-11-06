//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The controlling function owning a group receives group affiliation changes and subscriptions from another server in
// the standard form: one PUBLISH or SUBSCRIBE per group and user, with an mcptt-info body naming the group and the
// user and a per-group PIDF (TS 24.379 clauses 9.2.2.3.3 to 9.2.2.3.5). An interworking function serving users
// homed in it sends these (TS 29.379 clauses 9.2.1.2.6 and 9.2.1.2.7, TS 23.283 IWF-1). The users so affiliated
// are kept as users served by that peer (ServedUser.peer), keyed by their MCPTT ID, so that the group's calls reach
// them through the peer as they reach a peer participating function's users.
//
// openmcx's own participating functions still use the per-user peer registration of parts/peer_registration.hpp
// (the deviation listed in docs/LIMITATIONS.md).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 29.379 V19.2.0 (Rel-19), RFC 3903, RFC 6665.
#include "server.hpp"

#include "request_values.hpp"

#include <ctime>
#include <optional>

namespace mcx {

namespace {

// TS 24.379 clauses 9.2.2.3.3 step 3 and 9.2.2.3.4 step 3: the only nonzero Expires accepted, 2^32 - 1.
constexpr std::uint64_t standard_expires = 4294967295ULL;

//------------------------------------------------------------------------------
// Helper: an xs:dateTime in UTC, for the "expires" attribute of a notification (TS 24.379 table 9.3.1.2-1).
std::string date_time(std::int64_t seconds) {
  const std::time_t time = static_cast<std::time_t>(seconds);
  std::tm utc{};
  gmtime_r(&time, &utc);
  char text[32];
  std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &utc);
  return text;
}

//------------------------------------------------------------------------------
// Helper: the application/pidf+xml body of a request, a part of a multipart body or the whole body.
std::optional<std::string> pidf_body(const SipMessage &message) {
  for (const auto &part : message.parts)
    if (part.content_type == "application/pidf+xml") return part.body;
  if (message.content_type == "application/pidf+xml") return message.body;
  return std::nullopt;
}

} // namespace

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.2.3.3 and 9.2.2.3.4, conditions 1 and 2: a PUBLISH or SUBSCRIBE whose mcptt-info names, in
// <mcptt-request-uri>, a group controlled here (a functional alias subscription names an alias instead, and
// openmcx's own peer registration carries no mcptt-info). A subscription dialog already created this way counts too.
bool McServer::standard_group_request(const SipMessage &message) {
  if (group_affiliation_subscriptions_.contains(message.dialog_id)) return true;
  if (!std::any_of(message.parts.begin(), message.parts.end(),
                   [this](const BodyPart &part) { return part.content_type == svc_.info_mime; }))
    return false;
  try {
    const auto info = message_info(message, svc_);
    if (info.request_uri.empty() || !group_controller(info.request_uri).empty()) return false;
    static_cast<void>(group_profile(info.request_uri));
    return true;
  } catch (const std::exception &) {
    return false;
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3 steps 1 to 6 and 9.2.2.3.4 steps 1 to 5: the group and user named, the Expires check
// (423 with Min-Expires 4294967295), the group's existence and the user's membership (403). Returns the refusal, or
// nothing with the group, user and Expires read.
std::optional<SipResponse> McServer::standard_group_refusal(const SipMessage &message, std::string &group,
                                                            std::string &user, std::uint64_t &expires) {
  SipResponse response;
  // Condition 3: the MCPTT ICSI in P-Asserted-Service.
  if (get_header(message.headers, "P-Asserted-Service") != svc_.icsi) {
    response.status_code = 403;
    return response;
  }
  const auto info = message_info(message, svc_);
  group = info.request_uri;
  user = info.calling_user;
  const auto parsed = parse_expires(get_header(message.headers, "Expires"));
  if (!parsed || (*parsed != 0 && *parsed < standard_expires)) {
    response.status_code = 423;
    response.headers = {{"Min-Expires", std::to_string(standard_expires)}};
    return response;
  }
  expires = *parsed;
  Json profile;
  try {
    profile = group_profile(group);
  } catch (const std::exception &) {
    response.status_code = 403;
    return response;
  }
  if (user.empty() || !member(profile, user)) {
    response.status_code = 403;
    return response;
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3: a group affiliation status change of one user from another server.
SipResponse McServer::group_affiliation_publish(const SipMessage &message, const std::string &peer) {
  std::string group, user_id;
  std::uint64_t expires = 0;
  if (auto refusal = standard_group_refusal(message, group, user_id, expires)) return *refusal;
  // A user served here is not taken over by another server.
  if (const auto *local = by_id(user_id); local && local->peer.empty() && local->expires > std::time(nullptr)) {
    SipResponse refused;
    refused.status_code = 403;
    return refused;
  }
  const auto pidf = pidf_body(message);
  if (!pidf) {
    SipResponse refused;
    refused.status_code = 400;
    return refused;
  }
  const auto document = parse_group_affiliation(*pidf);

  // Step 10 a0: a de-affiliation the group document forbids for an activated functional alias.
  if (const auto known = users_.find(user_id);
      expires == 0 && known != users_.end() && !deaffiliation_forbidden(known->second, {group}).empty()) {
    SipResponse refused;
    refused.status_code = 403;
    return refused;
  }
  auto &entry = users_[user_id];

  // Step 6: 200 (OK) with the selected expiration time.
  SipResponse response;
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(expires)}};
  // Steps 7 and 8: a PIDF of another group or user changes nothing.
  if (document.group_id != group || document.members.size() != 1 || document.members.front().user_id != user_id) {
    if (entry.id.empty()) users_.erase(user_id);
    return response;
  }

  // Steps 10 and 11: the user's entry in the group, with its clients, or none.
  auto &members = standard_affiliations_[group];
  std::vector<std::string> clients;
  for (const auto &client : document.members.front().clients) clients.push_back(client.client_id);
  if (expires == 0 || clients.empty())
    members.erase(user_id);
  else
    members[user_id] = {clients, peer, std::time(nullptr) + static_cast<std::int64_t>(expires)};

  // The user as a user served by the peer: its groups are those its standard affiliations name.
  entry.id = user_id;
  entry.sip = user_id;
  entry.peer = peer;
  entry.client = clients.empty() ? entry.client : clients.front();
  // The user's service is the peer's to vouch for; its entry lasts as long as a standard affiliation may.
  entry.expires = std::time(nullptr) + static_cast<std::int64_t>(standard_expires);
  std::set<std::string> groups;
  for (const auto &[affiliated_group, affiliated] : standard_affiliations_)
    if (affiliated.contains(user_id)) groups.insert(affiliated_group);
  event("standard_group_affiliation",
        {{"user_id", user_id}, {"group", group}, {"server", peer}, {"affiliated", groups.contains(group)}});
  apply_affiliation(entry, std::move(groups));

  // Steps 12 and 13: the notification carries the handled p-id.
  schedule([this, group, user_id, p_id = document.publication_id] { notify_group_affiliation(group, user_id, p_id); });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.4: a subscription to one user's affiliation status in a group; an in-dialog SUBSCRIBE
// refreshes it or, with Expires 0, ends it (RFC 6665 section 4.2.1.4: a final NOTIFY "terminated").
SipResponse McServer::group_affiliation_subscribe(const SipMessage &message, const std::string &peer) {
  SipResponse response;
  response.status_code = 200;
  if (const auto found = group_affiliation_subscriptions_.find(message.dialog_id);
      found != group_affiliation_subscriptions_.end()) {
    if (get_header(message.headers, "Expires") == "0") {
      const auto subscription = found->second;
      group_affiliation_subscriptions_.erase(found);
      response.headers = {{"Expires", "0"}};
      schedule([this, subscription, dialog = message.dialog_id] {
        sip_.notify(dialog, "presence", "terminated;reason=timeout", "application/pidf+xml",
                    group_affiliation_xml(group_affiliation_state(subscription.group, subscription.user, {})));
      });
      return response;
    }
    response.headers = {{"Expires", std::to_string(standard_expires)}};
    return response;
  }
  std::string group, user_id;
  std::uint64_t expires = 0;
  if (auto refusal = standard_group_refusal(message, group, user_id, expires)) return *refusal;
  if (expires == 0) {
    // A fetch of the current state only (TS 29.379 clause 9.2.1.2.7 step 5): one NOTIFY, no subscription kept.
    response.headers = {{"Expires", "0"}};
    schedule([this, group, user_id, dialog = message.dialog_id] {
      sip_.notify(dialog, "presence", "terminated;reason=timeout", "application/pidf+xml",
                  group_affiliation_xml(group_affiliation_state(group, user_id, {})));
    });
    return response;
  }
  group_affiliation_subscriptions_[message.dialog_id] = {group, user_id, peer};
  response.headers = {{"Expires", std::to_string(standard_expires)}};
  event("standard_group_affiliation_subscribed", {{"user_id", user_id}, {"group", group}, {"server", peer}});
  // RFC 6665 section 4.2.1.2: the notifier sends a NOTIFY at once.
  schedule([this, dialog = message.dialog_id, group, user_id] {
    if (group_affiliation_subscriptions_.contains(dialog))
      sip_.notify(dialog, "presence", "active;expires=" + std::to_string(standard_expires), "application/pidf+xml",
                  group_affiliation_xml(group_affiliation_state(group, user_id, {})));
  });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.5 step 3: the user's entry in the group as a per-group PIDF, with "expires" on each
// client and the handled p-id when a PUBLISH caused it; no tuple when the user is not affiliated.
GroupAffiliation McServer::group_affiliation_state(const std::string &group, const std::string &user_id,
                                                   const std::string &p_id) const {
  GroupAffiliation document;
  document.group_id = group;
  document.publication_id = p_id;
  if (const auto members = standard_affiliations_.find(group); members != standard_affiliations_.end())
    if (const auto entry = members->second.find(user_id); entry != members->second.end()) {
      GroupAffiliation::Member member{user_id, {}};
      for (const auto &client : entry->second.clients) member.clients.push_back({client, date_time(entry->second.expires)});
      document.members.push_back(std::move(member));
    }
  return document;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.5 step 4: a NOTIFY on every subscription to the user's status in the group.
void McServer::notify_group_affiliation(const std::string &group, const std::string &user_id, const std::string &p_id) {
  const auto body = group_affiliation_xml(group_affiliation_state(group, user_id, p_id));
  for (const auto &[dialog, subscription] : group_affiliation_subscriptions_)
    if (subscription.group == group && subscription.user == user_id)
      sip_.notify(dialog, "presence", "active;expires=" + std::to_string(standard_expires), "application/pidf+xml",
                  body);
}

} // namespace mcx
