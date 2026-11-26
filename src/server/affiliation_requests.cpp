//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The affiliation of a user as other users see and change it (members of McServer): the subscriptions to a user's
// affiliation status, several per user (its own clients' and those of authorised users), their notification and
// their end; the subscription to another user's affiliation status passed on to the server serving that user; and the
// affiliation status change request in negotiated mode, passed on to the target user's client.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), RFC 6665.

#include "server.hpp"

namespace mcx {

namespace {
//------------------------------------------------------------------------------
// Helper: the Expires header field of a request, if present.
std::optional<std::string_view> expires_header(const SipMessage &message) {
  for (const auto &header : message.headers) {
    std::string name = header.name;
    for (auto &character : name) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    if (name == "expires") return std::string_view(header.value);
  }
  return std::nullopt;
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.1.3 and 9.2.2.2.4 (TS 24.281 clauses 8.2.1.3 and 8.2.2.2.4): a served user's subscription to
// its own affiliation status or, naming another MC service ID in <mcptt-request-uri>, to that user's; any other event
// package is refused with 489. Each subscription has its own dialog and none replaces another (RFC 6665 section 4.2).
// Expires 0 ends the subscription in its dialog, or out of it fetches the current state (clause 9.2.1.3 step 5):
// either way one final NOTIFY with the current state on its own dialog. The subscription only carries the
// notifications: ending it leaves the affiliations as they are (clause 9.2.2.2.4). Another user served elsewhere: the
// SUBSCRIBE goes on to its server (clause 9.2.2.2.10).
void McServer::affiliation_subscribe(const SipMessage &message, User &user, const std::string &event_name,
                                     SipResponse &response) {
  if (event_name != "presence") {
    response.status_code = 489;
    return;
  }
  if (affiliation_resubscribe(message, response)) return;
  const auto expires = affiliation_subscription_expires(expires_header(message));
  if (!expires) {
    response.status_code = 400;
    return;
  }
  // Clause 9.2.2.2.4 step 1: the served MC service ID in <mcptt-request-uri>; a SUBSCRIBE without the service
  // information (or without that element) is the subscriber's own. Step 2: the originating MC service ID is the
  // asserted identity's, the authenticated user.
  std::string served;
  if (!message.body.empty() || !message.parts.empty()) try {
      served = message_info(message, svc_).request_uri;
    } catch (const std::exception &) {
      served.clear(); // a body without the service information names no other user
    }
  if (served.empty()) served = user.id;
  if (served != user.id) {
    const auto route = affiliation_route_of(served, {});
    if (route.kind == AffiliationRoute::Kind::to_peer) {
      response =
          relay_presence_subscribe(message, user.id, served, route.peer, *expires, "affiliation_subscription_relayed");
      return;
    }
    if (route.kind == AffiliationRoute::Kind::unknown) {
      response.status_code = 404;
      event("affiliation_subscription_rejected", {{"user_id", user.id}, {"target", served}, {"status", 404}});
      return;
    }
  }
  // Step 4: another user's affiliation status only for an authorised originating user.
  bool authorised = false;
  if (served != user.id) try {
      authorised = may_determine_affiliation(user_profile(user.id));
    } catch (const std::exception &) {
      authorised = false; // no user profile: no right
    }
  if (const auto status = affiliation_subscribe_status(served, user.id, authorised); status != 200) {
    response.status_code = status;
    event("affiliation_subscription_rejected", {{"user_id", user.id}, {"target", served}, {"status", status}});
    return;
  }
  accept_affiliation_subscription(message, served, user.id, *expires, response);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.4 step 5 with RFC 6665 sections 4.2.1.1 and 4.2.1.2: the 200 (OK) with the granted Expires,
// then the NOTIFY with the current state (clause 9.2.2.2.5) on this subscription's dialog only; a fetch (Expires 0)
// gets one final NOTIFY and is not kept.
void McServer::accept_affiliation_subscription(const SipMessage &message, const std::string &served,
                                               const std::string &subscriber, std::uint64_t expires_s,
                                               SipResponse &response) {
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(expires_s)}};
  const auto dialog = message.dialog_id;
  if (expires_s == 0) {
    schedule([this, served, dialog] {
      if (const auto *user = by_id(served)) notify_affiliation(dialog, *user, {}, "terminated;reason=timeout");
    });
    return;
  }
  affiliation_subscriptions_.add(dialog, served, subscriber, std::time(nullptr) + static_cast<std::int64_t>(expires_s));
  if (served != subscriber) event("affiliation_subscription_accepted", {{"user_id", subscriber}, {"target", served}});
  schedule([this, served, dialog, expires_s] {
    if (const auto *user = by_id(served))
      notify_affiliation(dialog, *user, {}, "active;expires=" + std::to_string(expires_s));
  });
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.1.2: a SUBSCRIBE in the dialog of an affiliation status subscription refreshes it (the Expires
// asked for, at most the longest), or with Expires 0 ends it; either way a NOTIFY with the current state follows.
bool McServer::affiliation_resubscribe(const SipMessage &message, SipResponse &response) {
  const auto *held = affiliation_subscriptions_.find(message.dialog_id);
  if (!held) return false;
  const auto expires = affiliation_subscription_expires(expires_header(message));
  if (!expires) {
    response.status_code = 400;
    return true;
  }
  const auto served = held->served;
  const auto dialog = message.dialog_id;
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(*expires)}};
  if (*expires == 0) {
    affiliation_subscriptions_.erase(dialog);
    schedule([this, served, dialog] {
      if (const auto *user = by_id(served)) notify_affiliation(dialog, *user, {}, "terminated;reason=timeout");
    });
    return true;
  }
  affiliation_subscriptions_.add(dialog, served, held->subscriber,
                                 std::time(nullptr) + static_cast<std::int64_t>(*expires));
  schedule([this, served, dialog, seconds = *expires] {
    if (const auto *user = by_id(served))
      notify_affiliation(dialog, *user, {}, "active;expires=" + std::to_string(seconds));
  });
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.4 at the terminating participating function (steps 1, 3 to 5: the originating MC service ID
// in <mcptt-calling-user-id>), and clause 9.2.2.2.10 when the user is served by yet another server; a SUBSCRIBE in the
// dialog of such a subscription. Told from the functional alias status subscription by its simple filter (TS 24.379
// clause 9A.2.2.3.4) and from the group dynamic data subscription, handled before, by its filter.
bool McServer::peer_affiliation_subscribe(const SipMessage &message, const std::string &peer,
                                          const std::string &event_name, SipResponse &response) {
  if (message.method != "SUBSCRIBE" || event_name != "presence") return false;
  if (affiliation_resubscribe(message, response)) return true;
  if (peer_alias_subscriptions_.contains(message.dialog_id) ||
      std::any_of(message.parts.begin(), message.parts.end(),
                  [](const BodyPart &part) { return part.content_type == simple_filter_mime; }))
    return false;
  McpttInfo info;
  try {
    info = message_info(message, svc_);
  } catch (const std::exception &) {
    return false; // no service information: not this procedure
  }
  if (info.request_uri.empty() || info.calling_user.empty() || info.service.contains("request-type")) return false;
  const auto expires = affiliation_subscription_expires(expires_header(message));
  if (!expires) {
    response.status_code = 400;
    return true;
  }
  const auto route = affiliation_route_of(info.request_uri, peer);
  if (route.kind == AffiliationRoute::Kind::to_peer) {
    response = relay_presence_subscribe(message, info.calling_user, info.request_uri, route.peer, *expires,
                                        "affiliation_subscription_relayed");
    return true;
  }
  if (route.kind == AffiliationRoute::Kind::unknown) {
    response.status_code = 404;
    return true;
  }
  bool authorised = false;
  if (info.request_uri != info.calling_user) try {
      authorised = may_determine_affiliation(user_profile(info.calling_user));
    } catch (const std::exception &) {
      authorised = false; // no user profile: no right
    }
  if (const auto status = affiliation_subscribe_status(info.request_uri, info.calling_user, authorised);
      status != 200) {
    response.status_code = status;
    event("affiliation_subscription_rejected",
          {{"user_id", info.calling_user}, {"target", info.request_uri}, {"status", status}, {"server", peer}});
    return true;
  }
  accept_affiliation_subscription(message, info.request_uri, info.calling_user, *expires, response);
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.5 (TS 24.281 clause 8.2.2.2.5): the served user's affiliation status, every client and
// group (clause 9.3.1), with the handled p-id when a PUBLISH caused the notification (step 3d).
void McServer::notify_affiliation(const std::string &dialog, const User &served, const std::string &publication_id,
                                  const std::string &state) {
  sip_.notify(dialog, "presence", state, "application/pidf+xml",
              affiliation_xml(affiliation_status(svc_, served, publication_id), true));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.5: the NOTIFY of the user's affiliation status to each of its subscriptions.
void McServer::notify(User &user) {
  // A peer's user gets affiliation notifications from its own server.
  if (!user.peer.empty()) return;
  // Clause 9.2.2.2.5 step 3d: the <p-id> only when a PUBLISH caused the notification (its handled p-id).
  const auto publication_id = std::exchange(user.handled_pid, std::string{});
  const auto now = std::time(nullptr);
  for (const auto &dialog : affiliation_subscriptions_.of_served(user.id, now)) {
    const auto *held = affiliation_subscriptions_.find(dialog);
    const auto remaining = held ? held->expires - now : 0;
    notify_affiliation(dialog, user, publication_id, "active;expires=" + std::to_string(remaining));
  }
}

//------------------------------------------------------------------------------
// TS 23.280 clause 10.8 with RFC 6665 section 4.2.2: when the user's binding goes, the subscriptions to its
// affiliation status end with "noresource" (the last state: no group), and those it holds to other users' with
// "rejected" (its authorisation is gone).
void McServer::end_affiliation_subscriptions(const User &user) {
  const auto now = std::time(nullptr);
  for (const auto &dialog : affiliation_subscriptions_.of_served(user.id, now))
    notify_affiliation(dialog, user, {}, "terminated;reason=noresource");
  for (const auto &dialog : affiliation_subscriptions_.of_subscriber(user.id)) {
    const auto *held = affiliation_subscriptions_.find(dialog);
    if (!held || held->served == user.id || held->expires <= now) continue;
    if (const auto *served = by_id(held->served)) notify_affiliation(dialog, *served, {}, "terminated;reason=rejected");
  }
  for (const auto &dialog : affiliation_subscriptions_.of_served(user.id, 0)) affiliation_subscriptions_.erase(dialog);
  for (const auto &dialog : affiliation_subscriptions_.of_subscriber(user.id)) affiliation_subscriptions_.erase(dialog);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.2.2.8 to 9.2.2.2.10 (clause 9.2.2.2.10 NOTE 4, the choice of affiliation_subscriptions.hpp):
// served here while its service authorisation lasts; else the peer that registered the user, or the controlling
// server of a participating-only server.
AffiliationRoute McServer::affiliation_route_of(const std::string &target, const std::string &from_peer) {
  const auto now = std::time(nullptr);
  const auto *served = by_id(target);
  const bool here = served && served->peer.empty() && served->expires > now;
  std::string registered_by;
  for (const auto &[sip, user] : users_)
    if (user.id == target && !user.peer.empty() && user.expires > now) registered_by = user.peer;
  auto route = affiliation_route(here, registered_by, call_controller(), from_peer);
  if (route.kind == AffiliationRoute::Kind::to_peer && !peers_.contains(route.peer))
    route = {AffiliationRoute::Kind::unknown, {}};
  return route;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.4 (TS 24.281 annex F.4).
bool McServer::is_affiliation_command(const SipMessage &message) const {
  const auto mime = affiliation_command_mime(svc_);
  return std::any_of(message.parts.begin(), message.parts.end(),
                     [&](const BodyPart &part) { return part.content_type == mime; }) ||
         message.content_type == mime;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.1.4 received (TS 24.281 clause 8.2.1.4): an affiliation status change request in negotiated
// mode from the originating MC service ID for the target in <mcptt-request-uri>.
//   - The target served here: clause 9.2.2.2.8: the originating user must be authorised (step 3, 403 otherwise); the
//     MESSAGE goes on to the public user identity bound to the target (step 4) with an Accept-Contact requiring the
//     ICSI (step 5), its service information naming the target and the originating user, and the client's answer
//     comes back.
//   - The target served by another server: the MESSAGE goes on to that server's terminating participating function
//     with this function's PSI in P-Asserted-Identity and the service information naming the target and the
//     originating user, as clause 9.2.2.2.9 asks for the PUBLISH of mandatory mode (TS 24.379 has no procedure of the
//     originating participating function for this MESSAGE); the answer comes back.
//   - No server known to serve the target: 404.
SipResponse McServer::negotiated_affiliation(const SipMessage &message, const std::string &originator, McpttInfo info,
                                             const std::string &from_peer) {
  SipResponse response;
  const auto target = info.request_uri;
  if (target.empty() || originator.empty()) {
    response.status_code = 403;
    return response;
  }
  const auto route = affiliation_route_of(target, from_peer);
  if (route.kind == AffiliationRoute::Kind::unknown) {
    response.status_code = 404;
    event("negotiated_affiliation_rejected", {{"user_id", originator}, {"target", target}, {"status", 404}});
    return response;
  }

  // The request as it goes on: the service information names the target and the originating user (TS 24.379 clause
  // 9.2.2.2.8 steps 1 and 2 read them), the other parts (the affiliation command) unchanged.
  info.request_uri = target;
  info.calling_user = originator;
  info.client_id.clear();
  std::vector<BodyPart> parts{{svc_.info_mime, service_info_xml_(info)}};
  for (const auto &part : parts_of(message))
    if (part.content_type != svc_.info_mime) parts.push_back(part);
  SipMessage forwarded = message;
  std::tie(forwarded.content_type, forwarded.body) = message_body(parts, "mcx-" + random_id());
  forwarded.parts = parts;
  // Accept-Contact and P-Asserted-Service are set below, not copied.
  std::erase_if(forwarded.headers, [](const SipHeader &header) {
    std::string name = header.name;
    for (auto &character : name) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    return name == "accept-contact" || name == "a" || name == "p-asserted-service";
  });

  if (route.kind == AffiliationRoute::Kind::to_peer) {
    event("negotiated_affiliation_relayed", {{"user_id", originator}, {"target", target}, {"server", route.peer}});
    return relay_message(forwarded, peers_.at(route.peer).service_uri,
                         route_to(route.peer, {{"P-Asserted-Identity", "<" + own_service_uri() + ">"},
                                               {"P-Asserted-Service", svc_.icsi}}));
  }

  // Clause 9.2.2.2.8 step 3.
  bool authorised = false;
  try {
    authorised = may_request_affiliation(user_profile(originator));
  } catch (const std::exception &) {
    authorised = false; // no user profile: no right
  }
  if (!authorised) {
    response.status_code = 403;
    event("negotiated_affiliation_rejected", {{"user_id", originator}, {"target", target}, {"status", 403}});
    return response;
  }
  // Steps 4 and 5.
  const auto *served = by_id(target);
  event("negotiated_affiliation_forwarded", {{"user_id", originator}, {"target", target}});
  return relay_message(forwarded, served->sip,
                       user_route(*served, {{"P-Asserted-Service", svc_.icsi}, {"Accept-Contact", icsi_accept()}}));
}

} // namespace mcx
