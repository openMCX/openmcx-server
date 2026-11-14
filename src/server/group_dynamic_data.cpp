//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Subscription to group dynamic data (members of McServer): the participating MCVideo function passes the client's
// subscription on to the controlling MCVideo function of the group (TS 24.281 clause 8.2.2.2.16), which accepts it
// (clause 8.2.2.3.9) and notifies every change of the group's dynamic data (clause 8.2.2.3.10). A server with both
// roles takes a subscription to a group it owns as the controlling function itself. The group's dynamic data is the
// one the MBMS Group Dynamic Data Notify carries (mbms.cpp), with the affiliated members of clause 8.3.1.2.
// MCVideo only: the MCPTT and MCData servers answer these requests as before.
//
// Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), RFC 3856, RFC 6665.

#include "server.hpp"

#include <ctime>

namespace mcx {

namespace {
//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.1.2 item 14: an "expires" attribute (xs:dateTime) for a POSIX time.
std::string date_time(std::int64_t at) {
  const auto time = static_cast<std::time_t>(at);
  std::tm calendar{};
  gmtime_r(&time, &calendar);
  char text[32];
  std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &calendar);
  return text;
}

//------------------------------------------------------------------------------
// Helper: the application/simple-filter+xml part (clause 8.2.1.6 step 7), or nullptr (parts_of: message_parts.hpp).
const BodyPart *filter_part(const std::vector<BodyPart> &parts) { return part_of(parts, simple_filter_mime); }

//------------------------------------------------------------------------------
// Helper: the Expires header field, none when absent.
std::optional<std::string_view> expires_of(const SipMessage &message) {
  const auto value = get_header(message.headers, "Expires");
  return value.empty() ? std::nullopt : std::optional(value);
}

// RFC 6665 section 4.1.2.3: the Subscription-State of an active subscription to group dynamic data (it lasts until
// ended, clause 8.2.1.6 step 4).
const std::string gdd_active = "active;expires=" + std::string(gdd_max_expires);
} // namespace

//------------------------------------------------------------------------------
// TS 24.380 clause 10A.1 and clause 8.5.4 (TS 24.581 clauses 10.5.1 and 9.4.4), TS 24.281 clause 8.3.1.2 items 3
// to 8: whether a group call is ongoing on the group, its emergency (0) or imminent peril (1) state and the MC service
// ID that set it.
GroupDynamicData McServer::group_dynamic_data(const std::string &group) const {
  GroupDynamicData data;
  data.group = group;
  data.call_ongoing = std::ranges::any_of(
      sessions_, [&](const auto &entry) { return entry.second->group == group && !entry.second->private_call; });
  if (const auto found = priorities_.find(group); found != priorities_.end()) {
    const auto &state = found->second;
    if (state.emergency || state.imminent) data.status = state.emergency ? 0 : 1;
    const auto &setters = state.emergency ? state.emergency_users : state.imminent_users;
    if (data.status && !setters.empty()) data.status_changer = *setters.begin();
  }
  return data;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.1.2 (per-group dynamic data): <groupStatus> "emergency" or "in-peril" (table 8.3.1.2-3) with
// "ModifiedBy"; <additionalData> with "groupCallOngoing" and "groupRegroupAlias" (the temporary group of a group
// regroup the group is a constituent of, TS 24.281 clause 21); one <tuple> per affiliated MCVideo ID (items 9 and 10)
// with one <affiliation> per client of the user (items 12 to 14: the "expires" is the end of the client's service
// authorisation, which ends its affiliations, clause 8.2.2.3.10 step 2 a) and its activated functional aliases
// (item 15). The affiliation is that of TS 24.379 clause 9.2.2.2.11 (McServer::affiliated): live service
// authorisation and the group among the client's affiliations, or membership of a user regroup.
GroupDynamicDataDocument McServer::group_dynamic_data_document(const std::string &group) const {
  const auto data = group_dynamic_data(group);
  GroupDynamicDataDocument document;
  document.group = group;
  if (data.status) document.group_status = *data.status == 0 ? "emergency" : "in-peril";
  document.modified_by = data.status_changer;
  document.call_ongoing = data.call_ongoing;
  document.broadcast_alias = data.broadcast_alias;
  document.regroup_alias = data.regroup_alias;
  if (const auto regroup = regrouped_.find(group); document.regroup_alias.empty() && regroup != regrouped_.end())
    document.regroup_alias = regroup->second;
  const auto now = std::time(nullptr);
  const auto regroup = regroups_.find(group);
  std::map<std::string, GroupDynamicDataMember> members;
  for (const auto &[sip, user] : users_) {
    if (user.expires <= now) continue;
    const bool regrouped = regroup != regroups_.end() && regroup->second.affiliated.contains(user.id);
    if (!user.groups.contains(group) && !regrouped) continue;
    auto &member = members[user.id];
    member.id = user.id;
    member.clients.push_back({user.client, date_time(user.expires)});
  }
  for (const auto &[alias, ids] : functional_aliases_.activations())
    for (const auto &id : ids)
      if (const auto member = members.find(id); member != members.end())
        member->second.functional_aliases.push_back(alias);
  for (auto &[id, member] : members) document.members.push_back(std::move(member));
  return document;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.3.10 step 2: the body of a subscription, restricted by its filter (clause 8.3.2.2).
std::string McServer::gdd_body(const GroupDynamicDataSubscriptions::Subscription &subscription) const {
  return group_dynamic_data_xml(group_dynamic_data_document(subscription.group), &subscription.filter);
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.2.16 condition 4 and clause 8.2.2.3.9 condition 4 (Event "presence") with condition 2 and
// clause 8.3.2.2 (the per-group dynamic data filter, which tells this subscription from the affiliation status
// determination of clause 8.2.1.3 and the functional alias status subscriptions in the same event package).
bool McServer::is_gdd_subscribe(const SipMessage &message, const std::string &event_name) const {
  if (svc_.service != Service::mcvideo || message.method != "SUBSCRIBE" || event_name != "presence") return false;
  if (gdd_subscriptions_.contains(message.dialog_id)) return true;
  const auto parts = parts_of(message);
  const auto *filter = filter_part(parts);
  if (!filter) return false;
  try {
    return parse_group_dynamic_data_filter(filter->body).has_value();
  } catch (const std::exception &) {
    return true; // a per-group dynamic data filter that breaks clause 8.3.2.2, or no filter at all: 400 below
  }
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.1.6 at the server serving the user: a re-SUBSCRIBE of a subscription held here; else the
// initial SUBSCRIBE: the group in <mcvideo-request-uri> (clause 8.2.2.2.16 step 1), the user from P-Asserted-Identity
// (step 2, authenticated), the ICSI in P-Asserted-Service (condition 3: a different one is refused, none is taken as
// the SIP core's omission). A group controlled by another function: clause 8.2.2.2.16; one owned here: clause
// 8.2.2.3.9 with the user as the handled MCVideo ID.
bool McServer::group_dynamic_data_subscribe(const SipMessage &message, User &user, const std::string &event_name,
                                            SipResponse &response) {
  if (!is_gdd_subscribe(message, event_name)) return false;
  if (gdd_subscriptions_.contains(message.dialog_id)) {
    response = owned_gdd_resubscribe(message);
    return true;
  }
  const auto refuse = [&](int status, const std::string &reason) {
    response.status_code = status;
    event("group_dynamic_data_subscription_rejected", {{"user_id", user.id}, {"status", status}, {"reason", reason}});
    return true;
  };
  const auto parts = parts_of(message);
  GroupDynamicDataFilter filter;
  try {
    filter = *parse_group_dynamic_data_filter(filter_part(parts)->body);
  } catch (const std::exception &error) {
    return refuse(400, std::string("invalid filter: ") + error.what());
  }
  McpttInfo info;
  try {
    info = message_info(message, svc_);
  } catch (const std::exception &) {
    return refuse(403, "no mcvideo-info");
  }
  if (info.request_uri.empty()) return refuse(403, "no mcvideo-request-uri");
  if (const auto service = get_header(message.headers, "P-Asserted-Service");
      !service.empty() && service.find(svc_.icsi) == std::string_view::npos)
    return refuse(403, "P-Asserted-Service is not the MCVideo ICSI");
  if (const auto owner = group_controller(info.request_uri); !owner.empty()) {
    response = relay_gdd_subscribe(message, user, info.request_uri, owner);
    return true;
  }
  response = owned_gdd_subscribe(message, info.request_uri, user.id, {}, filter);
  return true;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.3.9 from the participating function on a peer: conditions 2 (both <mcvideo-request-uri> and
// <mcvideo-calling-user-id>) and 1 (a group this server owns), then steps 1 to 6; or a request in the dialog of a
// subscription held here.
bool McServer::peer_group_dynamic_data_subscribe(const SipMessage &message, const std::string &peer,
                                                 const std::string &event_name, SipResponse &response) {
  if (!is_gdd_subscribe(message, event_name)) return false;
  if (gdd_subscriptions_.contains(message.dialog_id)) {
    response = owned_gdd_resubscribe(message);
    return true;
  }
  const auto refuse = [&](int status, const std::string &reason) {
    response.status_code = status;
    event("group_dynamic_data_subscription_rejected", {{"peer", peer}, {"status", status}, {"reason", reason}});
    return true;
  };
  const auto parts = parts_of(message);
  GroupDynamicDataFilter filter;
  try {
    filter = *parse_group_dynamic_data_filter(filter_part(parts)->body);
  } catch (const std::exception &error) {
    return refuse(400, std::string("invalid filter: ") + error.what());
  }
  McpttInfo info;
  try {
    info = message_info(message, svc_);
  } catch (const std::exception &) {
    return refuse(403, "no mcvideo-info");
  }
  if (info.request_uri.empty() || info.calling_user.empty())
    return refuse(403, "mcvideo-request-uri or mcvideo-calling-user-id missing");
  if (!group_controller(info.request_uri).empty()) return refuse(403, "group not owned here");
  response = owned_gdd_subscribe(message, info.request_uri, info.calling_user, peer, filter);
  return true;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.3.9: condition 5 (a filter that names a group names the served one); step 3 (423 with
// Min-Expires 4294967295 for an Expires absent or below it); step 4 (403 for a group the group management server does
// not know); step 5 (403 for a handled MCVideo ID that is no member of the group: the local authorisation); step 6
// (200). Then the NOTIFY of clause 8.2.2.3.10 with the current data (RFC 6665 section 4.2.1.2); with Expires 0 that
// NOTIFY ends it at once (a fetch, clause 8.2.1.6 step 5).
SipResponse McServer::owned_gdd_subscribe(const SipMessage &message, const std::string &group, const std::string &user,
                                          const std::string &peer, const GroupDynamicDataFilter &filter) {
  SipResponse response;
  const auto log = [&](int status, const std::string &reason) {
    event("group_dynamic_data_subscription_rejected",
          {{"group_id", group}, {"user_id", user}, {"peer", peer}, {"status", status}, {"reason", reason}});
  };
  if (!filter.group.empty() && filter.group != group) {
    response.status_code = 403;
    log(403, "filter names another group");
    return response;
  }
  const auto expires = classify_gdd_expires(expires_of(message));
  bool exists = false, authorised = false;
  if (expires == GddExpires::subscribe || expires == GddExpires::fetch) try {
      const auto profile = group_profile(group);
      exists = true;
      authorised = member(profile, user);
    } catch (const std::exception &) {
      // Step 4: no such group (or no group management server to say so).
    }
  response.status_code = gdd_subscribe_status(expires, exists, authorised);
  if (response.status_code == 423) response.headers = {{"Min-Expires", std::string(gdd_max_expires)}};
  if (response.status_code != 200) {
    log(response.status_code, expires == GddExpires::too_brief   ? "Expires below 4294967295"
                              : expires == GddExpires::malformed ? "malformed Expires"
                              : !exists                          ? "unknown group"
                                                                 : "not authorised");
    return response;
  }
  const bool fetch = expires == GddExpires::fetch;
  response.headers = {{"Expires", fetch ? "0" : std::string(gdd_max_expires)}};
  GroupDynamicDataSubscriptions::Subscription subscription{group, user, peer, filter, {}};
  event(fetch ? "group_dynamic_data_fetched" : "group_dynamic_data_subscribed",
        {{"group_id", group}, {"user_id", user}, {"peer", peer}});
  if (fetch) {
    schedule([this, dialog = message.dialog_id, subscription] {
      notify_gdd(dialog, gdd_body(subscription), "terminated;reason=timeout");
    });
    return response;
  }
  gdd_subscriptions_.add(message.dialog_id, std::move(subscription));
  schedule([this, dialog = message.dialog_id] {
    if (!gdd_subscriptions_.contains(dialog)) return;
    notify_gdd(dialog, gdd_subscriptions_.current(dialog, [this](const auto &held) { return gdd_body(held); }),
               gdd_active);
  });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.1.6 (re-subscribe or de-subscribe in the dialog) with RFC 6665 section 4.2.1.2: Expires
// 4294967295 refreshes the subscription, 0 ends it; either way a NOTIFY with the current data follows, the last one
// "terminated". A new filter in the request replaces the old one. The Expires rule is that of clause 8.2.2.3.9 step 3.
SipResponse McServer::owned_gdd_resubscribe(const SipMessage &message) {
  SipResponse response;
  const auto expires = classify_gdd_expires(expires_of(message));
  if (expires == GddExpires::malformed) {
    response.status_code = 400;
    return response;
  }
  if (expires == GddExpires::too_brief) {
    response.status_code = 423;
    response.headers = {{"Min-Expires", std::string(gdd_max_expires)}};
    return response;
  }
  const auto parts = parts_of(message);
  if (const auto *part = filter_part(parts)) try {
      if (auto filter = parse_group_dynamic_data_filter(part->body)) {
        auto subscription = *gdd_subscriptions_.find(message.dialog_id);
        subscription.filter = std::move(*filter);
        gdd_subscriptions_.add(message.dialog_id, std::move(subscription));
      }
    } catch (const std::exception &) {
      response.status_code = 400;
      return response;
    }
  response.status_code = 200;
  const bool end = expires == GddExpires::fetch;
  response.headers = {{"Expires", end ? "0" : std::string(gdd_max_expires)}};
  const auto *subscription = gdd_subscriptions_.find(message.dialog_id);
  event(end ? "group_dynamic_data_unsubscribed" : "group_dynamic_data_refreshed",
        {{"group_id", subscription->group}, {"user_id", subscription->user}});
  schedule([this, dialog = message.dialog_id, end] {
    if (!gdd_subscriptions_.contains(dialog)) return;
    const auto body = gdd_subscriptions_.current(dialog, [this](const auto &held) { return gdd_body(held); });
    if (end) gdd_subscriptions_.erase(dialog);
    notify_gdd(dialog, body, end ? "terminated;reason=timeout" : gdd_active);
  });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.3.10 step 3: the NOTIFY with the application/pidf+xml body. RFC 6665 section 4.2.2: a
// failure response to it (such as 481) ends the subscription.
void McServer::notify_gdd(const std::string &dialog, const std::string &body, const std::string &state) {
  sip_.notify(dialog, "presence", state, "application/pidf+xml", body, {}, [this, dialog](const SipResponse &answer) {
    if (answer.status_code < 300) return;
    schedule([this, dialog, status = answer.status_code] {
      if (gdd_subscriptions_.erase(dialog))
        event("group_dynamic_data_subscription_ended", {{"dialog", dialog}, {"status", status}});
    });
  });
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.3.10: every 100 ms, a NOTIFY to each subscription whose group's dynamic data (as its filter
// selects it) changed since the last one. A local subscriber no longer authorised for the service is gone: its
// subscription ends (RFC 6665 section 4.2.2, reason "noresource").
void McServer::group_dynamic_data_tick(std::uint64_t now) {
  if (gdd_subscriptions_.size() == 0 || now < gdd_next_check_) return;
  gdd_next_check_ = now + 100;
  std::vector<std::string> gone;
  for (const auto &[dialog, subscription] : gdd_subscriptions_.all()) {
    if (!subscription.peer.empty()) continue;
    const auto *user = by_id(subscription.user);
    if (!user || user->expires <= std::time(nullptr)) gone.push_back(dialog);
  }
  for (const auto &dialog : gone) {
    const auto body = gdd_subscriptions_.current(dialog, [this](const auto &held) { return gdd_body(held); });
    gdd_subscriptions_.erase(dialog);
    notify_gdd(dialog, body, "terminated;reason=noresource");
  }
  for (const auto &[dialog, body] : gdd_subscriptions_.changed([this](const auto &held) { return gdd_body(held); }))
    notify_gdd(dialog, body, gdd_active);
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.2.16 steps 3 and 4: the user is authorised (its service authorisation; the group
// membership is the controlling function's step 5); the SUBSCRIBE towards the controlling function of the group
// (step 4 a: its PSI), with this function's PSI in P-Asserted-Identity (4 b), the mcvideo-info with the group and
// the user (4 c) and the other signalling elements of the request (4 d: its other bodies, Expires, Accept and the
// P-Asserted-Service). The final response comes back to the client (last paragraph). A SUBSCRIBE without Expires is
// answered here as the controlling function would (clause 8.2.2.3.9 step 3), a malformed one with 400.
SipResponse McServer::relay_gdd_subscribe(const SipMessage &message, const User &user, const std::string &group,
                                          const std::string &owner) {
  SipResponse response;
  const auto expires_value = expires_of(message);
  const auto expires = classify_gdd_expires(expires_value);
  if (expires == GddExpires::malformed || !expires_value) {
    response.status_code = expires_value ? 400 : 423;
    if (!expires_value) response.headers = {{"Min-Expires", std::string(gdd_max_expires)}};
    return response;
  }
  const auto peer = peers_.find(owner);
  if (peer == peers_.end()) {
    response.status_code = 403;
    event("group_dynamic_data_subscription_rejected", {{"user_id", user.id}, {"reason", "unknown peer " + owner}});
    return response;
  }
  McpttInfo info;
  info.request_uri = group;
  info.calling_user = user.id;
  std::vector<BodyPart> parts{{svc_.info_mime, service_info_xml_(info)}};
  for (const auto &part : parts_of(message))
    if (part.content_type != svc_.info_mime) parts.push_back(part);
  const auto boundary = "mcx-" + random_id();
  const auto [type, body] = message_body(parts, boundary);
  auto headers = route_to(owner, relayed_headers(message.headers));
  headers.push_back({"P-Asserted-Identity", "<" + own_service_uri() + ">"});
  const auto accept = get_header(message.headers, "Accept");
  headers.push_back({"Accept", accept.empty() ? std::string("application/pidf+xml") : std::string(accept)});
  if (get_header(headers, "P-Asserted-Service").empty()) headers.push_back({"P-Asserted-Service", svc_.icsi});
  auto relay = std::make_shared<GddRelay>();
  relay->peer = owner;
  relay->client_dialog = message.dialog_id;
  const auto seconds = static_cast<unsigned>(std::stoull(std::string(*expires_value)));
  relay->upstream_dialog = sip_.subscribe(
      peer->second.service_uri, "presence", seconds, headers,
      [this, weak = std::weak_ptr<GddRelay>(relay), id = message.transaction_id](const SipResponse &answer) {
        if (answer.status_code < 200) return;
        schedule([this, weak, id, answer] {
          SipResponse reply;
          reply.status_code = answer.status_code;
          reply.reason = answer.reason;
          reply.headers = relayed_headers(answer.headers);
          for (const auto *name : {"Expires", "Min-Expires"})
            if (const auto value = get_header(answer.headers, name); !value.empty())
              reply.headers.push_back({name, std::string(value)});
          sip_.respond(id, reply);
          const auto relay = weak.lock();
          if (!relay) return;
          if (answer.status_code >= 300) {
            event("group_dynamic_data_relay_rejected", {{"status", answer.status_code}});
            end_gdd_relay(relay);
            return;
          }
          relay->accepted = true;
          for (const auto &held : std::exchange(relay->pending, {})) forward_gdd_notify(relay, held);
        });
      },
      type, body);
  gdd_relays_[relay->client_dialog] = relay;
  gdd_relays_[relay->upstream_dialog] = relay;
  event("group_dynamic_data_relayed", {{"user_id", user.id}, {"group_id", group}, {"server", owner}});
  response.deferred = true;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.2.16, last paragraph: the controlling function's NOTIFYs go to the client and the client's
// responses to them back (held until the client's SUBSCRIBE is answered); the client's re-SUBSCRIBE or de-SUBSCRIBE
// (clause 8.2.1.6) goes on in the upstream dialog and its response comes back.
SipResponse McServer::relay_gdd_in_dialog(const SipMessage &message, const std::shared_ptr<GddRelay> &relay) {
  SipResponse response;
  response.status_code = 200;
  if (message.method == "NOTIFY" && message.dialog_id == relay->upstream_dialog) {
    GddRelay::Held held{std::string(get_header(message.headers, "Subscription-State")), message.content_type,
                        message.body, message.transaction_id};
    if (held.body.empty() && !message.parts.empty()) {
      const auto [type, body] = message_body(message.parts, "mcx-" + random_id());
      held.content_type = type;
      held.body = body;
    }
    if (relay->accepted)
      schedule([this, relay, held] { forward_gdd_notify(relay, held); });
    else
      relay->pending.push_back(std::move(held));
    response.deferred = true;
    return response;
  }
  if (message.method == "SUBSCRIBE" && message.dialog_id == relay->client_dialog) {
    const auto expires = std::string(get_header(message.headers, "Expires"));
    std::vector<SipHeader> headers{
        {"Event", "presence"}, {"Accept", "application/pidf+xml"}, {"P-Asserted-Service", svc_.icsi}};
    if (!expires.empty()) headers.push_back({"Expires", expires});
    sip_.request_in_dialog(relay->upstream_dialog, "SUBSCRIBE", message.content_type, message.body, headers,
                           [this, id = message.transaction_id](const SipResponse &answer) {
                             if (answer.status_code < 200) return;
                             SipResponse reply;
                             reply.status_code = answer.status_code;
                             reply.reason = answer.reason;
                             for (const auto *name : {"Expires", "Min-Expires"})
                               if (const auto value = get_header(answer.headers, name); !value.empty())
                                 reply.headers.push_back({name, std::string(value)});
                             schedule([this, id, reply] { sip_.respond(id, reply); });
                           });
    response.deferred = true;
    return response;
  }
  response.status_code = message.method == "SUBSCRIBE" || message.method == "NOTIFY" ? 481 : 405;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.2.16, last paragraph: one NOTIFY to the client, its response to the controlling function;
// a "terminated" one ends the relay.
void McServer::forward_gdd_notify(const std::shared_ptr<GddRelay> &relay, const GddRelay::Held &held) {
  sip_.notify(relay->client_dialog, "presence", held.state, held.content_type, held.body, {},
              [this, id = held.transaction](const SipResponse &answer) {
                SipResponse reply;
                reply.status_code = answer.status_code;
                reply.reason = answer.reason;
                schedule([this, id, reply] { sip_.respond(id, reply); });
              });
  if (held.state.starts_with("terminated")) end_gdd_relay(relay);
}

//------------------------------------------------------------------------------
// Helper: the relay is forgotten under both its dialogs.
void McServer::end_gdd_relay(const std::shared_ptr<GddRelay> &relay) {
  gdd_relays_.erase(relay->client_dialog);
  gdd_relays_.erase(relay->upstream_dialog);
}

} // namespace mcx
