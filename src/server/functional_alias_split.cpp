//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Functional aliases on split servers: the MCPTT server serving the user passes each status change on to the MCPTT
// server owning the alias and follows its outcome (TS 24.379 clauses 9A.2.2.2.6 and 9A.2.2.2.7), and the owning
// server decides and notifies (clauses 9A.2.2.3.3 to 9A.2.2.3.5) (members of McServer). MCVideo follows the same
// clauses of TS 24.281 clause 20.2.2.
//
// Between the servers the per-functional alias document names the user in the tuple id, as TS 24.379 clauses
// 9A.2.2.2.7 step 1 b), 9A.2.2.3.3 step 9 and the filter of clause 9A.3.2.2 read it (clause 9A.3.1.2 item 5 sets the
// tuple id to the alias instead); a received document is accepted in either form.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 3903, RFC 4661, RFC 6665.

#include "server.hpp"

#include <ctime>

namespace mcx {

namespace {
//------------------------------------------------------------------------------
// TS 24.379 clause 9A.3.1.2: the "expires" attribute (xs:dateTime) of an activation lasting `seconds` from now.
std::string activation_expiry(std::uint64_t seconds) {
  const auto at = static_cast<std::time_t>(std::time(nullptr) + static_cast<std::int64_t>(seconds));
  std::tm calendar{};
  gmtime_r(&at, &calendar);
  char text[32];
  std::strftime(text, sizeof text, "%Y-%m-%dT%H:%M:%SZ", &calendar);
  return text;
}

//------------------------------------------------------------------------------
// Helper: the user a per-functional alias document is about: the tuple id, or the "user" of its one entry.
std::string document_user(const FunctionalAliasStatus &status, const std::string &alias) {
  if (!status.tuple_id.empty() && status.tuple_id != alias) return status.tuple_id;
  return status.entries.size() == 1 ? status.entries.front().user : std::string{};
}
} // namespace

//------------------------------------------------------------------------------
// Helper: whether another MCPTT server owns the aliases this server's users activate (a participating server with
// mcptt.functional_alias_controller or a controlling function, TS 24.379 clause 9A.2.2.2.6 NOTE 5).
bool McServer::aliases_owned_elsewhere() const { return role_ == "participating" && !alias_controller().empty(); }

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.2.3 at a server not owning the aliases: the participating checks (steps 4 to 5), the 200
// (step 8), the served user's functional alias information entries (steps 10 to 14), the status change of each
// changed alias passed on to the owning server (step 15, clause 9A.2.2.2.6) and the NOTIFY with the handled p-id-fa
// (steps 16 and 17, clause 9A.2.2.2.5). An Expires 0 deactivates the listed aliases, a nonzero one activates them
// (OpenMCX's clients list the aliases they change, as for the server owning them).
SipResponse McServer::served_alias_publish(const SipMessage &message, const User &user, const McpttInfo &info,
                                           const std::string &body) {
  SipResponse response;
  const auto reject = [&](int status, const std::string &reason, const std::string &warning = {}) {
    response.status_code = status;
    if (!warning.empty()) response.headers = {{"Warning", warning_value(warning)}};
    event("functional_alias_rejected", {{"user_id", user.id}, {"status", status}, {"reason", reason}});
    return response;
  };
  if (info.request_uri != user.id) return reject(403, "request URI is not the publishing user");
  FunctionalAliasRequest request;
  try {
    request = parse_functional_alias(body);
  } catch (const std::exception &error) {
    return reject(400, error.what());
  }
  if (request.mcdata || request.mcvideo != (svc_.service == Service::mcvideo))
    return reject(400, "functional alias of another service");
  if (request.user_id != user.id || request.client_id != user.client || request.aliases.empty())
    return reject(403, "identity mismatch");

  // Steps 4A and 4B (MCPTT only): the aliases the user may change, those whose <mcptt-user-list> names it.
  if (svc_.service == Service::mcptt)
    for (const auto &alias : request.aliases) {
      Json definition;
      try {
        definition = internal("cms", "/internal/functional-alias?id=" + url_encode(alias));
      } catch (const std::exception &) {
        definition = nullptr;
      }
      const auto users = definition.is_null() ? std::vector<std::string>{}
                                              : definition.value(alias_user_list(), std::vector<std::string>{});
      if (std::find(users.begin(), users.end(), user.id) == users.end())
        return reject(403, "user may not change " + alias, warn(Warning::alias_status_not_authorised));
    }
  // Step 5.
  const auto expires = std::string(get_header(message.headers, "Expires"));
  const bool deactivate = expires == "0";
  if (!deactivate && expires != "4294967295") {
    response.status_code = 423;
    response.headers = {{"Min-Expires", "4294967295"}};
    return response;
  }
  // Steps 10 to 14: the candidate entries replace the served ones.
  auto &entries = served_aliases_[user.id];
  std::vector<std::pair<std::string, bool>> onward; // alias, activation
  for (const auto &alias : request.aliases) {
    const auto found = entries.find(alias);
    if (deactivate) {
      if (found == entries.end()) continue;
      found->second.status = "deactivating";
      onward.emplace_back(alias, false);
      continue;
    }
    auto &entry = entries[alias];
    if (entry.status == "activated" && !request.take_over) continue; // a refresh of an active alias
    entry.status = "activating";
    entry.publish_id = request.publish_id;
    entry.take_over = request.take_over;
    onward.emplace_back(alias, true);
  }
  if (entries.empty()) served_aliases_.erase(user.id);
  if (auto possible = alias_takeover_possible_.find(user.id); possible != alias_takeover_possible_.end()) {
    for (const auto &alias : request.aliases) possible->second.erase(alias);
    if (possible->second.empty()) alias_takeover_possible_.erase(possible);
  }
  // Step 15 (clause 9A.2.2.2.6), then steps 16 and 17 (clause 9A.2.2.2.5) once the 200 is sent.
  schedule([this, id = user.id, onward, pid = request.publish_id] {
    for (const auto &[alias, activation] : onward) send_alias_onward(id, alias, activation);
    alias_status_changed({id}, {}, id, pid);
  });
  event(deactivate ? "functional_alias_deactivation_passed_on" : "functional_alias_activation_passed_on",
        {{"user_id", user.id}, {"aliases", request.aliases}, {"take_over", request.take_over}});

  // Step 8.
  response.status_code = 200;
  response.headers = {{"Expires", deactivate ? "0" : "4294967295"}, {"SIP-ETag", random_id()}};
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.2.6: the PUBLISH with the served user's (de)activation of one alias to the server owning it.
// A final refusal or a timeout (timer F) removes the user's entry for the alias; an accepted activation is then
// followed by the owning server's status (clause 9A.2.2.2.7), an accepted deactivation ends it. The owning server
// offers no take-over between servers, so an activation refused while the definition allows a take-over the user has
// the right to (TS 24.484 clauses 8.4.2.1 and 8.3.2.1) is offered here as "take-over-possible" (clause 3.1).
void McServer::send_alias_onward(const std::string &id, const std::string &alias, bool activation) {
  const auto owner = alias_controller();
  const auto users = served_aliases_.find(id);
  if (owner.empty() || users == served_aliases_.end() || !users->second.contains(alias)) return;
  auto &entry = users->second.at(alias);
  entry.onward_id = random_id(); // step 7: the current p-id-fa
  // Steps 2 and 10: the alias and the user in the mcptt-info, the per-functional alias status of the served user.
  McpttInfo info;
  info.request_uri = alias;
  info.calling_user = id;
  FunctionalAliasStatus status;
  status.mcvideo = svc_.service == Service::mcvideo;
  status.entity = alias;
  status.tuple_id = id;
  status.per_alias = true;
  status.publish_id = entry.onward_id;
  if (activation) {
    status.entries.push_back({{}, id, "activating", {}});
    status.take_over = entry.take_over; // NOTE 8
  }
  const auto boundary = "mcx-" + random_id();

  // Steps 1, 3 to 6: the owning server's PSI, the ICSI, Expires and this server's identity.
  auto headers = route_to(owner, {{"Event", "presence"},
                                  {"P-Asserted-Identity", "<" + own_service_uri() + ">"},
                                  {"P-Asserted-Service", svc_.icsi},
                                  {"Expires", activation ? "4294967295" : "0"}});
  sip_.publish(peers_.at(owner).service_uri, "multipart/mixed; boundary=" + boundary,
               multipart_body({{svc_.info_mime, service_info_xml_(info)},
                               {"application/pidf+xml", functional_alias_status_xml(status)}},
                              boundary),
               headers, [this, id, alias, activation, pid = entry.onward_id](const SipResponse &answer) {
                 if (answer.status_code < 200) return;
                 schedule([this, id, alias, activation, pid, code = answer.status_code] {
                   onward_alias_answered(id, alias, activation, pid, code);
                 });
               });
  event("functional_alias_onward_publish",
        {{"user_id", id}, {"alias", alias}, {"activation", activation}, {"take_over", entry.take_over}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.2.6 (the outcome of the PUBLISH) and clause 9A.2.2.2.7 (the subscription that follows it).
void McServer::onward_alias_answered(const std::string &id, const std::string &alias, bool activation,
                                     const std::string &pid, int code) {
  const auto users = served_aliases_.find(id);
  if (users == served_aliases_.end()) return;
  const auto found = users->second.find(alias);
  if (found == users->second.end() || found->second.onward_id != pid) return; // a later change superseded it
  if (code >= 300) {
    // Clause 9A.2.2.2.6: the entry is removed.
    const bool offered = activation && !found->second.take_over && alias_takeover_offered(id, alias);
    users->second.erase(found);
    if (offered) alias_takeover_possible_[id].insert(alias);
    unsubscribe_alias_owner(id, alias);
    event("functional_alias_onward_refused",
          {{"user_id", id}, {"alias", alias}, {"status", code}, {"take_over_possible", offered}});
  } else if (!activation) {
    users->second.erase(found);
    unsubscribe_alias_owner(id, alias);
  } else {
    subscribe_alias_owner(id, alias);
    return; // clause 9A.2.2.2.7: the owning server's NOTIFY tells whether the activation took effect
  }
  if (users->second.empty()) served_aliases_.erase(users);
  alias_status_changed({id}, {});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 3.1 and clause 9A.2.2.3.3 step 6: whether a refused activation may be offered for take-over: the
// alias allows it (<allow-takeover>) and the user has <allow-takeover-functional-alias-other-user>.
bool McServer::alias_takeover_offered(const std::string &id, const std::string &alias) {
  try {
    const auto definition = internal("cms", "/internal/functional-alias?id=" + url_encode(alias));
    return definition.value("allow_takeover", false) && user_profile(id).value("functional_alias_takeover", false);
  } catch (const std::exception &) {
    return false;
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.2.7: the subscription to the served user's status for one alias at the owning server:
// Expires 4294967295, the alias and the user in the mcptt-info, and the filter naming the user (clause 9A.3.2.2).
void McServer::subscribe_alias_owner(const std::string &id, const std::string &alias) {
  for (const auto &[dialog, followed] : alias_upstream_)
    if (followed.user == id && followed.alias == alias) return;
  const auto owner = alias_controller();
  McpttInfo info;
  info.request_uri = alias;
  info.calling_user = id;
  const auto boundary = "mcx-" + random_id();
  const auto dialog = sip_.subscribe(
      peers_.at(owner).service_uri, "presence", 4294967295u,
      route_to(owner, {{"P-Asserted-Identity", "<" + own_service_uri() + ">"},
                       {"P-Asserted-Service", svc_.icsi},
                       {"Accept", "application/pidf+xml"}}),
      [this, id, alias](const SipResponse &response) {
        if (response.status_code < 300) return;
        schedule([this, id, alias] {
          std::erase_if(alias_upstream_,
                        [&](const auto &entry) { return entry.second.user == id && entry.second.alias == alias; });
          // Without the owning server's status the activation is not known to have taken effect.
          if (auto users = served_aliases_.find(id); users != served_aliases_.end()) {
            users->second.erase(alias);
            if (users->second.empty()) served_aliases_.erase(users);
          }
          alias_status_changed({id}, {});
        });
      },
      "multipart/mixed; boundary=" + boundary,
      multipart_body(
          {{svc_.info_mime, service_info_xml_(info)},
           {std::string(simple_filter_mime), functional_alias_filter_xml(id, false, svc_.service == Service::mcvideo)}},
          boundary));
  alias_upstream_[dialog] = {id, alias};
  event("functional_alias_owner_subscribed", {{"user_id", id}, {"alias", alias}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.2.7: de-subscribe, an in-dialog SUBSCRIBE with Expires 0.
void McServer::unsubscribe_alias_owner(const std::string &id, const std::string &alias) {
  for (auto it = alias_upstream_.begin(); it != alias_upstream_.end(); ++it)
    if (it->second.user == id && it->second.alias == alias) {
      sip_.request_in_dialog(it->first, "SUBSCRIBE", "", "",
                             {{"Event", "presence"},
                              {"Expires", "0"},
                              {"Accept", "application/pidf+xml"},
                              {"P-Asserted-Service", svc_.icsi}});
      alias_upstream_.erase(it);
      return;
    }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.2.7: the owning server's NOTIFY with the per-functional alias status of the served user.
// Listed: an activating entry becomes "activated" (step 1). Not listed: an activated or deactivating entry becomes
// "deactivated" (step 2), and so does an activating one when the NOTIFY carries its p-id-fa (step 3); a deactivated
// entry is removed and its status sent to the user's subscriptions (clause 9A.2.2.2.5).
SipResponse McServer::owner_alias_notify(const SipMessage &message) {
  SipResponse response;
  response.status_code = 200;
  const auto upstream = alias_upstream_.find(message.dialog_id);
  if (upstream == alias_upstream_.end()) {
    response.status_code = 481;
    return response;
  }
  const auto [id, alias] = upstream->second;
  if (get_header(message.headers, "Subscription-State").starts_with("terminated")) alias_upstream_.erase(upstream);
  FunctionalAliasStatus status;
  bool parsed = false;
  for (const auto &part :
       message.parts.empty() ? std::vector<BodyPart>{{message.content_type, message.body}} : message.parts) {
    if (part.content_type != "application/pidf+xml") continue;
    try {
      status = parse_functional_alias_status(part.body);
      parsed = true;
    } catch (const std::exception &) {
      response.status_code = 400;
      return response;
    }
  }
  if (!parsed) return response;
  const bool listed =
      std::any_of(status.entries.begin(), status.entries.end(), [&](const auto &entry) { return entry.user == id; }) ||
      (document_user(status, alias) == id && !status.entries.empty());
  const auto users = served_aliases_.find(id);
  if (users == served_aliases_.end()) return response;
  const auto found = users->second.find(alias);
  if (found == users->second.end()) return response;
  auto &entry = found->second;
  bool changed = false;
  if (listed && entry.status == "activating") {
    entry.status = "activated";
    changed = true;
  } else if (!listed && (entry.status == "activated" || entry.status == "deactivating" ||
                         (entry.status == "activating" && status.publish_id == entry.onward_id))) {
    users->second.erase(found);
    if (users->second.empty()) served_aliases_.erase(users);
    unsubscribe_alias_owner(id, alias);
    changed = true;
  }
  if (changed) {
    event("functional_alias_owner_status", {{"user_id", id}, {"alias", alias}, {"active", listed}});
    schedule([this, id] { alias_status_changed({id}, {}); });
  }
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.2.6 for a user whose service authorisation ends: each alias the user holds or is
// activating is deactivated at the owning server.
void McServer::deactivate_served_aliases(const std::string &id) {
  const auto users = served_aliases_.find(id);
  if (users == served_aliases_.end()) return;
  for (auto &[alias, entry] : users->second) entry.status = "deactivating";
  std::vector<std::string> aliases;
  for (const auto &[alias, entry] : users->second) aliases.push_back(alias);
  for (const auto &alias : aliases) send_alias_onward(id, alias, false);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.3 at the server owning the aliases: the PUBLISH of a serving server for one alias and
// one user: 423 below 4294967295 (step 3), 403 for an unknown alias (step 4), a user not in its user list (step 4a),
// the maximum reached (step 5) or a take-over not allowed (step 6); else 200 (step 7), the user's activation or
// deactivation (steps 10 to 12), and the NOTIFY of the status with the handled p-id-fa (steps 13 and 14).
SipResponse McServer::owned_alias_publish(const SipMessage &message, const std::string &peer) {
  SipResponse response;
  const auto reject = [&](int status, const std::string &reason) {
    response.status_code = status;
    event("functional_alias_rejected", {{"peer", peer}, {"status", status}, {"reason", reason}});
    return response;
  };
  if (svc_.service != Service::mcptt && svc_.service != Service::mcvideo) return reject(403, "service");
  const auto info = message_info(message, svc_);
  const auto &alias = info.request_uri; // step 1
  const auto &id = info.calling_user;   // step 2
  if (alias.empty() || id.empty()) return reject(403, "alias or user missing");
  FunctionalAliasStatus status;
  try {
    for (const auto &part : message.parts)
      if (part.content_type == "application/pidf+xml") status = parse_functional_alias_status(part.body);
  } catch (const std::exception &error) {
    return reject(400, error.what());
  }
  if (status.mcvideo != (svc_.service == Service::mcvideo) || status.mcdata) return reject(400, "service");
  const auto expires = std::string(get_header(message.headers, "Expires"));
  const bool deactivate = expires == "0";
  if (!deactivate && expires != "4294967295") { // step 3
    response.status_code = 423;
    response.headers = {{"Min-Expires", "4294967295"}};
    return response;
  }
  Json definition;
  try {
    definition = internal("cms", "/internal/functional-alias?id=" + url_encode(alias));
  } catch (const std::exception &) {
    return reject(403, "unknown functional alias " + alias); // step 4
  }
  // Steps 8 and 9: a document about another alias or user changes nothing.
  const bool applies = status.entity == alias && document_user(status, alias) == id;
  auto change = functional_aliases_.change();
  std::vector<std::pair<std::string, std::string>> taken;
  if (applies && deactivate) {
    std::erase(change.next[alias], id); // step 11
  } else if (applies) {
    const auto may_take_over = [&] { return user_profile(id).value("functional_alias_takeover", false); };
    const AliasAdmissionRules rules{svc_.service, status.take_over, true, false, may_take_over};
    switch (AliasRegistry::admit(change, alias, id, definition, rules)) {
    case AliasAdmission::Admitted: break;
    case AliasAdmission::NotListed: return reject(403, "user may not activate " + alias); // step 4a
    case AliasAdmission::NoneAllowed:
    case AliasAdmission::LimitReached:
      return reject(403, status.take_over ? "take-over not possible for " + alias        // step 6
                                          : "maximum activations reached for " + alias); // step 5
    }
  }
  taken = functional_aliases_.commit(std::move(change));
  std::set<std::string> changed_users{id};
  for (const auto &[taken_alias, previous] : taken) {
    changed_users.insert(previous);
    event("functional_alias_taken_over", {{"alias", taken_alias}, {"from", previous}, {"by", id}});
  }
  event(deactivate ? "functional_alias_deactivated" : "functional_alias_activated",
        {{"user_id", id},
         {"aliases", std::vector<std::string>{alias}},
         {"take_over", status.take_over},
         {"from_peer", peer}});
  schedule([this, changed_users, alias, publisher = id, pid = status.publish_id] {
    alias_status_changed(changed_users, {alias}, publisher, pid);
  });
  response.status_code = 200; // step 7
  response.headers = {{"Expires", deactivate ? "0" : "4294967295"}, {"SIP-ETag", random_id()}};
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.4: a serving server's subscription to one user's status for one alias: the alias and the
// user in the mcptt-info and the same user in the filter (conditions), 423 below 4294967295 (step 3), 403 for an
// unknown alias (step 4) or a user its user list does not name (step 5, the local policy), else 200 (step 6) and the
// NOTIFY of the status (clause 9A.2.2.3.5). An in-dialog SUBSCRIBE refreshes it, or ends it with Expires 0.
SipResponse McServer::owned_alias_subscribe(const SipMessage &message, const std::string &peer) {
  SipResponse response;
  const auto refuse = [&](int status, const std::string &reason) {
    response.status_code = status;
    event("functional_alias_subscription_rejected", {{"peer", peer}, {"status", status}, {"reason", reason}});
    return response;
  };
  const auto expires = std::string(get_header(message.headers, "Expires"));
  if (const auto existing = peer_alias_subscriptions_.find(message.dialog_id);
      existing != peer_alias_subscriptions_.end()) {
    response.status_code = 200;
    response.headers = {{"Expires", expires == "0" ? "0" : "4294967295"}};
    if (expires == "0") existing->second.ended = true;
    schedule([this, dialog = message.dialog_id] { notify_peer_alias(dialog); });
    return response;
  }
  const auto info = message_info(message, svc_);
  std::string filtered;
  for (const auto &part : message.parts)
    if (part.content_type == simple_filter_mime) try {
        filtered = parse_functional_alias_filter(part.body);
      } catch (const std::exception &) {
        return refuse(400, "invalid filter");
      }
  if (info.request_uri.empty() || info.calling_user.empty() || filtered != info.calling_user)
    return refuse(403, "alias, user or filter missing");
  if (expires != "0" && expires != "4294967295") { // step 3
    response.headers = {{"Min-Expires", "4294967295"}};
    return refuse(423, "Expires below 4294967295");
  }
  Json definition;
  try {
    definition = internal("cms", "/internal/functional-alias?id=" + url_encode(info.request_uri));
  } catch (const std::exception &) {
    return refuse(403, "unknown functional alias " + info.request_uri); // step 4
  }
  const auto users = definition.value(alias_user_list(), std::vector<std::string>{});
  if (std::find(users.begin(), users.end(), info.calling_user) == users.end())
    return refuse(403, "not authorised for " + info.request_uri); // step 5
  peer_alias_subscriptions_[message.dialog_id] = {info.request_uri, info.calling_user, expires == "0"};
  response.status_code = 200; // step 6
  response.headers = {{"Expires", expires}};
  event("functional_alias_peer_subscribed",
        {{"peer", peer}, {"alias", info.request_uri}, {"user_id", info.calling_user}});
  schedule([this, dialog = message.dialog_id] { notify_peer_alias(dialog); });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.5: the NOTIFY of one user's status for one alias to a serving server: the user's tuple
// with its "expires" (step 3a) while active, none otherwise; the handled p-id-fa (step 3b).
void McServer::notify_peer_alias(const std::string &dialog, const std::string &publish_id) {
  const auto found = peer_alias_subscriptions_.find(dialog);
  if (found == peer_alias_subscriptions_.end()) return;
  const auto subscription = found->second;
  FunctionalAliasStatus status;
  status.mcvideo = svc_.service == Service::mcvideo;
  status.entity = subscription.alias;
  status.per_alias = true;
  status.publish_id = publish_id;
  if (functional_aliases_.active(subscription.alias, subscription.user)) {
    status.tuple_id = subscription.user;
    status.entries.push_back({{}, subscription.user, {}, activation_expiry(max_expires_s)});
  }
  sip_.notify(dialog, "presence", subscription.ended ? "terminated;reason=timeout" : "active", "application/pidf+xml",
              functional_alias_status_xml(status));
  if (subscription.ended) peer_alias_subscriptions_.erase(dialog);
}

} // namespace mcx
