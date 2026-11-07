//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCData server's peers and the standard per-group affiliation it receives from them.
//
// A peer is another server configured in mcdata.servers (the layout of the MCPTT server's mcptt.servers,
// parts/peers.hpp), trusted by its address. The one such peer so far is an interworking function (TS 23.283 IWF-2),
// which affiliates the users homed in it to MCData groups owned here in the standard form: one PUBLISH per group and
// user, with an mcdata-info body naming the group and the user and a per-group PIDF, and a subscription to learn the
// outcome (TS 29.582 clauses 8.3.2.6 and 8.3.2.7). This file is the receiving side of that form, the MCData server
// owning the group (TS 24.282 clauses 8.3.3.3 to 8.3.3.5); the users so affiliated are kept as users served by that
// peer (ServedUser.peer), keyed by their MCData ID.
//
// The other way round, this server's users affiliate to groups a peer owns in the same form (TS 24.282 clauses
// 8.3.2.6 and 8.3.2.7; mcdata.group_controllers).
//
// Not yet: the SPK protection of MCData signalling and XML with a peer (TS 29.582 clauses 6.5, 6.6; TS 24.282 clause
// 6.6.3), and data, alerts and notices for the peer's users, which need routing to the peer.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 29.582 V19.0.0 (Rel-19), RFC 3903, RFC 6665.
#include "data_server.hpp"

#include <ctime>
#include <limits>
#include <optional>

namespace mcx {

namespace {

// TS 24.282 clauses 8.3.3.3 step 3 and 8.3.3.4 step 3: the only nonzero Expires accepted, 2^32 - 1.
constexpr std::uint64_t standard_expires = 4294967295ULL;

//------------------------------------------------------------------------------
// Helper: an xs:dateTime in UTC, for the "expires" attribute of a notification (TS 24.282 clause 8.3.3.5 step 3a).
std::string date_time(std::int64_t seconds) {
  const std::time_t time = static_cast<std::time_t>(seconds);
  std::tm utc{};
  gmtime_r(&time, &utc);
  char text[32];
  std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &utc);
  return text;
}

//------------------------------------------------------------------------------
// Helper: the body part of a type, a part of a multipart body or the whole body; nullopt when there is none.
std::optional<std::string> body_of(const SipMessage &message, std::string_view type) {
  for (const auto &part : message.parts)
    if (part.content_type == type) return part.body;
  if (message.content_type == type) return message.body;
  return std::nullopt;
}

} // namespace

//------------------------------------------------------------------------------
// The peers of mcdata.servers (parts/peers.hpp).
void DataServer::load_peers(bool disable_tls) {
  const auto servers = cfg_.at("mcdata").value("servers", Json::object());
  for (const auto &[name, entry] : servers.items()) peers_[name] = configured_peer(name, entry, disable_tls);
  // The users a peer serves (ServicePeer::users): reachable through it, and senders through it, while this server
  // runs (an interworking function's TETRA users, TS 100 392-19-1 clause 8.2.1).
  for (const auto &[name, peer] : peers_)
    for (const auto &id : peer.users) {
      auto &user = users_[id];
      user.id = id;
      user.sip = id;
      user.peer = name;
      user.expires = std::numeric_limits<std::int64_t>::max();
    }
}

//------------------------------------------------------------------------------
// A request from a peer: OPTIONS, and the PUBLISH and SUBSCRIBE of TS 24.282 clauses 8.3.3.3 and 8.3.3.4 (an
// in-dialog SUBSCRIBE of a subscription created so too). Anything else is not yet taken from a peer (403).
SipResponse DataServer::peer_request(const SipMessage &request, const std::string &peer) {
  SipResponse response;
  response.status_code = 200;
  try {
    if (request.method == "OPTIONS") return response;
    // TS 29.582 clause 9.2.2.3.1 (TS 24.282 clause 6.3.1.1): a group standalone SDS for one of the peer's users.
    if (request.method == "MESSAGE" && request.request_uri == service_uri_ && accepts(request, mcdata::sds_icsi)) {
      // TS 24.282 clause 9.2.2.3.2: an SDS for a user served here (the peer as controlling function); otherwise one of
      // the peer's users sending (clause 9.2.2.3.1 at the peer).
      if (const auto *info_part = part(request, mcdata::info_mime)) {
        const auto info = mcdata::parse_info(info_part->body);
        if (auto *target = by_id(info.request_uri); target && target->peer.empty())
          return peer_sds_to_user(request, *target, info, peer);
      }
      return peer_sds(request, peer);
    }
    const auto event_name = get_header(request.headers, "Event");
    if (request.method == "SUBSCRIBE" && group_affiliation_subscriptions_.contains(request.dialog_id))
      return group_affiliation_subscribe(request, peer);
    // TS 24.282 clause 8.3.2.7: a NOTIFY of this server's subscription to a user's status at a group the peer owns.
    if (request.method == "NOTIFY" && standard_outgoing_dialogs_.contains(request.dialog_id))
      return standard_affiliation_notify(request);
    // Conditions 1, 2 and 4 of clauses 8.3.3.3 and 8.3.3.4: the PSI of this controlling function, an mcdata-info
    // body, the presence event package.
    if ((request.method == "PUBLISH" || request.method == "SUBSCRIBE") && event_name == "presence" &&
        request.request_uri == service_uri_ && body_of(request, mcdata::info_mime))
      return request.method == "PUBLISH" ? group_affiliation_publish(request, peer)
                                         : group_affiliation_subscribe(request, peer);
    event("mcdata_peer_request_refused", {{"method", request.method}, {"server", peer}});
    response.status_code = 403;
    return response;
  } catch (const std::exception &error) {
    event("mcdata_peer_request_rejected", {{"method", request.method}, {"server", peer}, {"reason", error.what()}});
    response.status_code = 400;
    return response;
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.3.3 conditions 2 and 3 and steps 1 to 5 (clause 8.3.3.4 the same): the group and user named
// (<mcdata-request-uri>, <mcdata-calling-user-id>), the MCData ICSI in P-Asserted-Service, the Expires check (423 with
// Min-Expires 4294967295), the group's existence and the user's membership (403). Returns the refusal, or nothing with
// the group, user and Expires read.
std::optional<SipResponse> DataServer::standard_group_refusal(const SipMessage &request, std::string &group,
                                                              std::string &user, std::uint64_t &expires) {
  SipResponse response;
  response.status_code = 403;
  const auto info = mcdata::parse_info(*body_of(request, mcdata::info_mime));
  group = info.request_uri;
  user = info.calling_user;
  if (group.empty() || user.empty() || get_header(request.headers, "P-Asserted-Service") != mcdata::icsi)
    return response;
  const auto parsed = parse_expires(get_header(request.headers, "Expires"));
  if (!parsed || (*parsed != 0 && *parsed < standard_expires)) {
    response.status_code = 423;
    response.headers = {{"Min-Expires", std::to_string(standard_expires)}};
    return response;
  }
  expires = *parsed;
  const auto document = group_document(group);
  if (!document || !document->contains("mcdata") ||
      !listed(document->at("mcdata").value("members", Json::array()), user))
    return response;
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.3.3: a group affiliation status change of one user from a peer.
SipResponse DataServer::group_affiliation_publish(const SipMessage &request, const std::string &peer) {
  std::string group, user_id;
  std::uint64_t expires = 0;
  if (auto refusal = standard_group_refusal(request, group, user_id, expires)) {
    event("mcdata_standard_affiliation_refused",
          {{"user_id", user_id}, {"group", group}, {"server", peer}, {"status", refusal->status_code}});
    return *refusal;
  }
  SipResponse refused;
  refused.status_code = 403;
  // A user served here is not taken over by a peer.
  if (const auto *local = by_id(user_id); local && local->peer.empty()) return refused;
  // Condition 5: the per-group PIDF.
  const auto pidf = body_of(request, "application/pidf+xml");
  if (!pidf) {
    refused.status_code = 400;
    return refused;
  }
  const auto document = parse_group_affiliation(*pidf);

  // Step 6: 200 (OK) with the selected expiration time.
  SipResponse response;
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(expires)}};
  // Steps 7 and 8: a PIDF of another group or user, or of the other service, changes nothing.
  if (!document.mcdata || document.group_id != group || document.members.size() != 1 ||
      document.members.front().user_id != user_id)
    return response;

  // Steps 9 to 11: the user's entry in the group, with its clients and expiration time, or none.
  auto &members = standard_affiliations_[group];
  std::vector<std::string> clients;
  for (const auto &client : document.members.front().clients) clients.push_back(client.client_id);
  if (expires == 0 || clients.empty())
    members.erase(user_id);
  else
    members[user_id] = {clients, peer, std::time(nullptr) + static_cast<std::int64_t>(expires)};

  // The user as a user served by the peer: its groups are those its standard affiliations name; its service is the
  // peer's to vouch for, so its entry lasts as long as a standard affiliation may.
  auto &entry = users_[user_id];
  entry.id = user_id;
  entry.sip = user_id;
  entry.peer = peer;
  if (!clients.empty()) entry.client = clients.front();
  entry.expires = std::time(nullptr) + static_cast<std::int64_t>(standard_expires);
  std::set<std::string> groups;
  for (const auto &[affiliated_group, affiliated] : standard_affiliations_)
    if (affiliated.contains(user_id)) groups.insert(affiliated_group);
  entry.groups = std::move(groups);
  event("mcdata_standard_affiliation", {{"user_id", user_id},
                                        {"group", group},
                                        {"server", peer},
                                        {"affiliated", entry.groups.contains(group)},
                                        {"groups", entry.groups}});

  // Steps 12 and 13: the notification carries the handled p-id. Step 14 (an outstanding MCData emergency alert on the
  // group, clause 16.2.3.3) needs the alert routed to the peer, which comes with the peer's data (TS 29.582 cl. 18).
  pending_.push_back([this, group, user_id, p_id = document.publication_id] {
    notify_group_affiliation(group, user_id, p_id);
  });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.3.4: a subscription to one user's affiliation status in a group; an in-dialog SUBSCRIBE
// refreshes it or, with Expires 0, ends it (RFC 6665 section 4.2.1.4: a final NOTIFY "terminated"). An initial
// SUBSCRIBE with Expires 0 fetches the state once (TS 29.582 clause 8.3.2.7).
SipResponse DataServer::group_affiliation_subscribe(const SipMessage &request, const std::string &peer) {
  SipResponse response;
  response.status_code = 200;
  const auto terminate = [this](const std::string &dialog, const std::string &group, const std::string &user) {
    pending_.push_back([this, dialog, group, user] {
      sip_.notify(dialog, "presence", "terminated;reason=timeout", "application/pidf+xml",
                  group_affiliation_xml(group_affiliation_state(group, user, {})));
    });
  };
  if (const auto found = group_affiliation_subscriptions_.find(request.dialog_id);
      found != group_affiliation_subscriptions_.end()) {
    if (get_header(request.headers, "Expires") == "0") {
      const auto subscription = found->second;
      group_affiliation_subscriptions_.erase(found);
      response.headers = {{"Expires", "0"}};
      terminate(request.dialog_id, subscription.group, subscription.user);
      event("mcdata_standard_affiliation_unsubscribed", {{"user_id", subscription.user}, {"group", subscription.group}});
      return response;
    }
    response.headers = {{"Expires", std::to_string(standard_expires)}};
    return response;
  }
  std::string group, user_id;
  std::uint64_t expires = 0;
  if (auto refusal = standard_group_refusal(request, group, user_id, expires)) return *refusal;
  // Condition 5: the per-user restriction (clause 8.4.2) names the same MCData ID.
  const auto filter = body_of(request, simple_filter_mime);
  if (!filter || parse_functional_alias_filter(*filter) != user_id) {
    response.status_code = 403;
    return response;
  }
  if (expires == 0) {
    response.headers = {{"Expires", "0"}};
    terminate(request.dialog_id, group, user_id);
    return response;
  }
  // Step 6, and the subscription kept for clause 8.3.3.5.
  group_affiliation_subscriptions_[request.dialog_id] = {group, user_id, peer};
  response.headers = {{"Expires", std::to_string(standard_expires)}};
  event("mcdata_standard_affiliation_subscribed", {{"user_id", user_id}, {"group", group}, {"server", peer}});
  // RFC 6665 section 4.2.1.2: the notifier sends a NOTIFY at once.
  pending_.push_back([this, dialog = request.dialog_id, group, user_id] {
    if (group_affiliation_subscriptions_.contains(dialog))
      sip_.notify(dialog, "presence", "active;expires=" + std::to_string(standard_expires), "application/pidf+xml",
                  group_affiliation_xml(group_affiliation_state(group, user_id, {})));
  });
  return response;
}

//------------------------------------------------------------------------------
// TS 29.582 clause 9.2.2.3.1 steps 6 to 10 as received: the request names the peer's user in
// <mcdata-calling-user-id> (step 8) and asserts the peer's PSI (step 10); it is then the procedure of TS 24.282
// clause 9.2.2.4.2 for that user as sender (or, for an SDS NOTIFICATION, TS 24.282 clause 12.2.3 for that user as
// notifier): a group SDS ("group-sds") or a one-to-one SDS ("one-to-one-sds", its target
// in the resource list, TS 29.582 clause 9.2.2.2.1 step 1).
SipResponse DataServer::peer_sds(const SipMessage &request, const std::string &peer) {
  const auto asserted = asserted_identity(request);
  const auto *info_part = part(request, mcdata::info_mime);
  const auto *signalling = part(request, mcdata::signalling_mime);
  const auto *data = part(request, mcdata::payload_mime);
  if (asserted != peers_.at(peer).service_uri || !info_part || !signalling)
    return reject(403, "199 expected MIME bodies not in the request", asserted, "message");
  auto info = mcdata::parse_info(info_part->body);
  const auto found = users_.find(info.calling_user);
  if (found == users_.end() || found->second.peer != peer)
    return reject(404, "141 user unknown to the participating function", info.calling_user, "message");
  // TS 29.582 clause 12.2.1.2: a disposition notification from the peer's user, to the originator in the resource
  // list (TS 24.282 clauses 12.2.2.1 and 12.2.3).
  if (mcdata::message_type(signalling->body) == mcdata::MessageType::SdsNotification) {
    event("mcdata_peer_notification", {{"user_id", info.calling_user}, {"server", peer}});
    return notification(request, found->second, info, *signalling);
  }
  if (!data) return reject(403, "199 expected MIME bodies not in the request", asserted, "message");
  if ((info.request_type != "group-sds" && info.request_type != "one-to-one-sds") ||
      mcdata::message_type(signalling->body) != mcdata::MessageType::SdsSignalling)
    return reject(403, "", info.calling_user, "message");
  // The client the peer names for its user (TS 100 392-19-1 clause 13.2.3.2: how it determines it is its own).
  found->second.client = info.client_id;
  event("mcdata_peer_sds", {{"user_id", info.calling_user}, {"server", peer}, {"group_id", info.request_uri}});
  return sds(request, found->second, info, *signalling, *data);
}

//------------------------------------------------------------------------------
bool DataServer::peer_vouched(const User &sender, const std::string &group) const {
  if (sender.peer.empty()) return false;
  const auto members = standard_affiliations_.find(group);
  if (members == standard_affiliations_.end()) return false;
  const auto now = std::time(nullptr);
  for (const auto &[id, entry] : members->second)
    if (entry.peer == sender.peer && entry.expires > now) return true;
  return false;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.3.5 step 3: the user's entry in the group as a per-group PIDF in the MCData namespace, with
// "expires" on each client (step 3a) and the handled p-id when a PUBLISH caused it (step 3b); no tuple when the user
// is not affiliated.
GroupAffiliation DataServer::group_affiliation_state(const std::string &group, const std::string &user,
                                                     const std::string &p_id) const {
  GroupAffiliation document;
  document.mcdata = true;
  document.group_id = group;
  document.publication_id = p_id;
  if (const auto members = standard_affiliations_.find(group); members != standard_affiliations_.end())
    if (const auto entry = members->second.find(user); entry != members->second.end()) {
      GroupAffiliation::Member member{user, {}};
      for (const auto &client : entry->second.clients)
        member.clients.push_back({client, date_time(entry->second.expires)});
      document.members.push_back(std::move(member));
    }
  return document;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.3.5 step 4: a NOTIFY on every subscription to the user's status in the group.
void DataServer::notify_group_affiliation(const std::string &group, const std::string &user, const std::string &p_id) {
  const auto body = group_affiliation_xml(group_affiliation_state(group, user, p_id));
  for (const auto &[dialog, subscription] : group_affiliation_subscriptions_)
    if (subscription.group == group && subscription.user == user) {
      sip_.notify(dialog, "presence", "active;expires=" + std::to_string(standard_expires), "application/pidf+xml",
                  body);
      event("mcdata_standard_affiliation_notified", {{"user_id", user}, {"group", group}, {"p_id", p_id}});
    }
}

//------------------------------------------------------------------------------
// Helper: the peer owning a group in the standard form (mcdata.group_controllers naming a peer with
// standard_affiliation), or empty.
std::string DataServer::standard_controller(const std::string &group) const {
  const auto controllers = cfg_.at("mcdata").value("group_controllers", Json::object());
  if (!controllers.contains(group)) return {};
  const auto name = controllers.at(group).get<std::string>();
  const auto peer = peers_.find(name);
  return peer != peers_.end() && peer->second.standard_affiliation ? name : std::string{};
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 8.3.2.6 and 8.3.2.7 (TS 29.582 clauses 8.3.3.3 and 8.3.3.4 at the peer): after the user's
// affiliations changed, each group owned by a standard peer that the user joined gets a subscription and then an
// affiliation PUBLISH; each one it left a de-affiliation PUBLISH (Expires 0).
void DataServer::sync_standard_affiliations(const User &user) {
  if (!user.peer.empty()) return;
  for (const auto &group : user.groups) {
    const auto peer = standard_controller(group);
    if (peer.empty() || standard_outgoing_.contains({user.id, group})) continue;
    standard_outgoing_[{user.id, group}] = {};
    subscribe_standard_affiliation(user, group, peer);
  }
  for (auto &[key, outgoing] : standard_outgoing_) {
    if (key.first != user.id || outgoing.leaving || user.groups.contains(key.second)) continue;
    outgoing.leaving = true;
    if (outgoing.subscribed) publish_standard_affiliation(user.id, user.client, key.second, false);
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.2.7: the subscription to the user's affiliation status at the group's owner, with the
// mcdata-info naming the group and the user and the per-user filter (clause 8.4.2).
void DataServer::subscribe_standard_affiliation(const User &user, const std::string &group, const std::string &peer) {
  mcdata::Info info;
  info.request_uri = group;
  info.calling_user = user.id;
  const auto [type, body] = message_body({{mcdata::info_mime, mcdata::info_xml(info)},
                                          {std::string(simple_filter_mime), affiliation_user_filter_xml(user.id, true)}},
                                         "mcdata-" + random_id());
  const auto dialog = sip_.subscribe(
      peers_.at(peer).service_uri, "presence", static_cast<unsigned>(standard_expires),
      peer_route(peers_, peer, {{"P-Asserted-Service", mcdata::icsi}, {"Accept", "application/pidf+xml"}}),
      [this, id = user.id, client = user.client, group](const SipResponse &response) {
        if (response.status_code < 200) return;
        pending_.push_back([this, id, client, group, refused = response.status_code >= 300] {
          const auto found = standard_outgoing_.find({id, group});
          if (found == standard_outgoing_.end()) return;
          if (refused) {
            standard_affiliation_lost(id, group, "subscription refused");
            return;
          }
          found->second.subscribed = true;
          publish_standard_affiliation(id, client, group, !found->second.leaving);
        });
      },
      type, body);
  standard_outgoing_[{user.id, group}].dialog = dialog;
  standard_outgoing_dialogs_[dialog] = {user.id, group};
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.2.6: the PUBLISH of an affiliation (Expires 4294967295, the client listed) or a de-affiliation
// (Expires 0, no client), with this server's PSI asserted and a new p-id; a refused affiliation removes the group, a
// de-affiliation ends the subscription whatever the answer.
void DataServer::publish_standard_affiliation(const std::string &id, const std::string &client,
                                              const std::string &group, bool affiliating) {
  const auto peer = standard_controller(group);
  auto &outgoing = standard_outgoing_.at({id, group});
  outgoing.pending_pid = random_id();
  mcdata::Info info;
  info.request_uri = group;
  info.calling_user = id;
  GroupAffiliation document;
  document.mcdata = true;
  document.group_id = group;
  document.publication_id = outgoing.pending_pid;
  document.members = {{id, {}}};
  if (affiliating) document.members.front().clients.push_back({client, ""});
  const auto [type, body] = message_body(
      {{mcdata::info_mime, mcdata::info_xml(info)}, {"application/pidf+xml", group_affiliation_xml(document)}},
      "mcdata-" + random_id());
  sip_.publish(peers_.at(peer).service_uri, type, body,
               peer_route(peers_, peer,
                          {{"Event", "presence"},
                           {"Expires", affiliating ? std::to_string(standard_expires) : "0"},
                           {"P-Asserted-Service", mcdata::icsi},
                           {"P-Asserted-Identity", "<" + service_uri_ + ">"}}),
               [this, id, group, affiliating](const SipResponse &response) {
                 if (response.status_code < 200) return;
                 pending_.push_back([this, id, group, affiliating, failed = response.status_code >= 300] {
                   if (!standard_outgoing_.contains({id, group})) return;
                   if (!affiliating)
                     end_standard_affiliation(id, group);
                   else if (failed)
                     standard_affiliation_lost(id, group, "affiliation refused");
                 });
               });
  event("mcdata_standard_affiliation_sent",
        {{"user_id", id}, {"group", group}, {"server", peer}, {"affiliating", affiliating}});
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.2.7, on receiving a NOTIFY: the user's client listed is the affiliation confirmed; not listed
// while confirmed, or in the notification of the affiliation's own p-id, the affiliation is gone or refused.
SipResponse DataServer::standard_affiliation_notify(const SipMessage &request) {
  SipResponse response;
  response.status_code = 200;
  const auto key = standard_outgoing_dialogs_.at(request.dialog_id);
  if (get_header(request.headers, "Subscription-State").starts_with("terminated"))
    standard_outgoing_dialogs_.erase(request.dialog_id);
  const auto found = standard_outgoing_.find(key);
  const auto pidf = body_of(request, "application/pidf+xml");
  if (found == standard_outgoing_.end() || !pidf || found->second.leaving) return response;
  const auto document = parse_group_affiliation(*pidf);
  const auto *user = by_id(key.first);
  bool listed = false;
  for (const auto &member : document.members)
    if (member.user_id == key.first)
      for (const auto &client : member.clients) listed = listed || (user && client.client_id == user->client);
  if (listed && !found->second.confirmed) {
    found->second.confirmed = true;
    event("mcdata_standard_affiliation_confirmed", {{"user_id", key.first}, {"group", key.second}});
  } else if (!listed && (found->second.confirmed || (!document.publication_id.empty() &&
                                                     document.publication_id == found->second.pending_pid))) {
    pending_.push_back([this, key] { standard_affiliation_lost(key.first, key.second, "not affiliated at the owner"); });
  }
  return response;
}

//------------------------------------------------------------------------------
// The owner refused or removed the affiliation: the user is no longer affiliated to the group here either, and its
// client learns that from its own notification (TS 24.282 clause 8.3.2.5).
void DataServer::standard_affiliation_lost(const std::string &id, const std::string &group, const std::string &reason) {
  end_standard_affiliation(id, group);
  event("mcdata_standard_affiliation_lost", {{"user_id", id}, {"group", group}, {"reason", reason}});
  if (auto *user = by_id(id); user && user->groups.erase(group)) schedule_notify(*user);
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2.3: the subscription ends with an in-dialog SUBSCRIBE, Expires 0.
void DataServer::end_standard_affiliation(const std::string &id, const std::string &group) {
  const auto found = standard_outgoing_.find({id, group});
  if (found == standard_outgoing_.end()) return;
  if (found->second.subscribed)
    sip_.request_in_dialog(found->second.dialog, "SUBSCRIBE", "", "",
                           {{"Event", "presence"},
                            {"Expires", "0"},
                            {"Accept", "application/pidf+xml"},
                            {"P-Asserted-Service", mcdata::icsi}});
  else
    standard_outgoing_dialogs_.erase(found->second.dialog);
  standard_outgoing_.erase(found);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.2.3.1 steps 9 to 13 with the peer as the controlling function: the request to the peer's PSI
// (step 9), the mcdata-info with the sender's MCData ID (step 12) and the client's other elements, the SDS feature tag
// and ICSI, this server's PSI asserted (step 13), the SDS bodies unchanged; the peer's final answer is passed on to
// the client with its Warning.
SipResponse DataServer::relay_sds_to_peer(const SipMessage &request, const User &sender, const mcdata::Info &info,
                                          const std::string &peer, const std::vector<BodyPart> &binary) {
  std::vector<BodyPart> parts{{mcdata::info_mime, mcdata::info_xml(info)}};
  parts.insert(parts.end(), binary.begin(), binary.end());
  const auto [type, body] = message_body(parts, "mcdata-" + random_id());
  const std::string sds_icsi = mcdata::sds_icsi;
  const auto transaction = request.transaction_id;
  sip_.request("MESSAGE", peers_.at(peer).service_uri, type, body,
               peer_route(peers_, peer,
                          {{"Accept-Contact", "*;+g.3gpp.mcdata.sds;require;explicit"},
                           {"Accept-Contact", "*;+g.3gpp.icsi-ref=\"" + url_encode(sds_icsi) + "\";require;explicit"},
                           {"P-Asserted-Service", sds_icsi},
                           {"P-Asserted-Identity", "<" + service_uri_ + ">"}}),
               [this, transaction, id = sender.id, group = info.request_uri](const SipResponse &answer) {
                 if (answer.status_code < 200) return;
                 SipResponse reply;
                 reply.status_code = answer.status_code;
                 reply.reason = answer.reason;
                 if (const auto warning = get_header(answer.headers, "Warning"); !warning.empty())
                   reply.headers = {{"Warning", std::string(warning)}};
                 pending_.push_back([this, transaction, reply] { sip_.respond(transaction, reply); });
                 event("mcdata_sds_peer_answer", {{"user_id", id}, {"group_id", group}, {"status", answer.status_code}});
               });
  event("mcdata_sds_relayed_to_peer", {{"user_id", sender.id}, {"group_id", info.request_uri}, {"server", peer}});
  SipResponse response;
  response.deferred = true;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.2.3.2 for a peer's SDS: the user named in <mcdata-request-uri> served here gets the SDS (the
// peer's mcdata-info with the calling user and group, the signalling and payload unchanged); 200 (OK) once sent.
SipResponse DataServer::peer_sds_to_user(const SipMessage &request, User &target, const mcdata::Info &info,
                                         const std::string &peer) {
  const auto *signalling = part(request, mcdata::signalling_mime);
  const auto *data = part(request, mcdata::payload_mime);
  if (asserted_identity(request) != peers_.at(peer).service_uri || !signalling || !data)
    return reject(403, "199 expected MIME bodies not in the request", target.id, "message");
  deliver(target, info, {*signalling, *data}, "sds");
  event("mcdata_peer_sds_delivered",
        {{"user_id", target.id}, {"server", peer}, {"group_id", info.calling_group}, {"from", info.calling_user}});
  SipResponse response;
  response.status_code = 200;
  return response;
}

} // namespace mcx
