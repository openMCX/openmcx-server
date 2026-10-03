// Functional aliases: activation and deactivation, status subscriptions and notifications, and the binding of
// a functional alias to groups (members of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: whether the identity is a functional alias: an active one, or one the CMS defines.
bool McServer::is_functional_alias(const std::string &id) {
  if (functional_aliases_.contains(id)) return true;
  try {
    return internal("cms", "/internal/functional-alias?id=" + url_encode(id)).value("id", "") == id;
  } catch (const std::exception &) {
    return false;
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9A.2.2.2.3 and 9A.2.2.3.3: activation, refresh, take-over and deactivation.
// All listed aliases are checked before any state changes.
SipResponse McServer::functional_alias_publish(const SipMessage &message, const User &user, const McpttInfo &info,
                                               const std::string &body) {
  SipResponse response;
  const auto reject = [&](int status, const std::string &reason) {
    response.status_code = status;
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
  // The service's own namespace: TS 24.379 clause 9A.3.1 or TS 24.281 clause 20.3.1.
  if (request.mcdata != (svc_.service == Service::mcdata) || request.mcvideo != (svc_.service == Service::mcvideo))
    return reject(400, "functional alias of another service");
  if (request.user_id != user.id || request.client_id != user.client || request.aliases.empty())
    return reject(403, "identity mismatch");
  const auto expires = std::string(get_header(message.headers, "Expires"));
  const bool deactivate = expires == "0";
  if (!deactivate && expires != "4294967295") {
    response.status_code = 423;
    response.headers = {{"Min-Expires", "4294967295"}};
    return response;
  }
  auto change = functional_aliases_.change();
  const AliasAdmissionRules rules{svc_.service, request.take_over, true, false,
                                  [&] { return user_profile(user.id).value("functional_alias_takeover", false); }};
  for (const auto &alias : request.aliases) {
    Json definition;
    try {
      definition = internal("cms", "/internal/functional-alias?id=" + url_encode(alias));
    } catch (const std::exception &) {
      return reject(403, "unknown functional alias " + alias);
    }
    if (deactivate) {
      std::erase(change.next[alias], user.id);
      continue;
    }
    // <mcptt-user-list> or, for MCVideo, <mcvideo-user-list> (TS 24.484 clauses 8.4.2.1 and 9.4.2.1); take-over needs
    // <allow-takeover> and the user's <allow-takeover-functional-alias-other-user> (TS 24.484 clauses 8.4.2.1 and
    // 8.3.2.1).
    switch (AliasRegistry::admit(change, alias, user.id, definition, rules)) {
    case AliasAdmission::NotListed: return reject(403, "user may not activate " + alias);
    case AliasAdmission::NoneAllowed: return reject(403, "no activations allowed for " + alias);
    case AliasAdmission::LimitReached: return reject(403, "maximum activations reached for " + alias);
    case AliasAdmission::Admitted: break;
    }
  }
  const auto taken = functional_aliases_.commit(std::move(change));
  std::set<std::string> changed_users{user.id};
  for (const auto &[alias, previous] : taken) {
    changed_users.insert(previous);
    event("functional_alias_taken_over", {{"alias", alias}, {"from", previous}, {"by", user.id}});
  }
  schedule([this, changed_users, aliases = std::set<std::string>(request.aliases.begin(), request.aliases.end()),
            publisher = user.id,
            pid = request.publish_id] { alias_status_changed(changed_users, aliases, publisher, pid); });
  event(deactivate ? "functional_alias_deactivated" : "functional_alias_activated",
        {{"user_id", user.id}, {"aliases", request.aliases}, {"take_over", request.take_over}});
  response.status_code = 200;
  response.headers = {{"Expires", deactivate ? "0" : "4294967295"}, {"SIP-ETag", random_id()}};
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.6: a user's activations end with its service authorization, and so do
// its status subscriptions.
void McServer::deactivate_functional_aliases(const std::string &id) {
  const auto aliases = functional_aliases_.deactivate(id);
  std::erase_if(alias_subscriptions_, [&](const auto &entry) { return entry.second.subscriber == id; });
  if (!aliases.empty()) schedule([this, id, aliases] { alias_status_changed({id}, aliases); });
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9A.2.2.2.4 and 9A.2.2.3.4 (TS 24.281 clauses 20.2.2.2.4 and 20.2.2.3.4): a SUBSCRIBE with
// <req-type> "functional-alias-status-determination" for the subscriber's own aliases, or
// "fa-user-status-determination" for the users of an alias. The local policy of TS 24.379 clause 9A.2.2.3.4
// step 5 (TS 24.281 clause 20.2.2.3.4 step 5) lets the users that may activate an alias follow it. Expires 0
// fetches the state once; an in-dialog SUBSCRIBE refreshes or ends the subscription.
// The aliases are held by the server owning them, so a participating-only server
// with an alias controller refuses (its users' activations are not known here).
SipResponse McServer::alias_subscribe(const SipMessage &message, const User &user, const McpttInfo &info,
                                      const std::string &req_type) {
  SipResponse response;
  const auto refuse = [&](int status, const std::string &reason) {
    response.status_code = status;
    event("functional_alias_subscription_rejected", {{"user_id", user.id}, {"status", status}, {"reason", reason}});
    return response;
  };
  const auto expires_text = get_header(message.headers, "Expires");
  const auto requested = parse_expires(expires_text);
  if (!expires_text.empty() && !requested) return refuse(400, "invalid Expires");
  // TS 24.379 clause 9A.2.2.3.4 step 3 (TS 24.281 clause 20.2.2.3.4 step 3): the server owning the alias accepts a
  // subscription to its users only for the state once (Expires 0) or for good (Expires 4294967295).
  if (req_type == "fa-user-status-determination" && !alias_subscriptions_.contains(message.dialog_id) &&
      (!requested || (*requested != 0 && *requested < max_expires_s))) {
    response.headers = {{"Min-Expires", std::to_string(max_expires_s)}};
    return refuse(423, "Expires below 4294967295");
  }
  // TS 24.379 clause 9A.2.2.2.4 sets no rule on the duration: without Expires, the default of this server.
  const auto expires = requested.value_or(default_subscription_s);
  AliasSubscription subscription;
  if (const auto existing = alias_subscriptions_.find(message.dialog_id); existing != alias_subscriptions_.end()) {
    if (existing->second.subscriber != user.id) return refuse(403, "subscription of another user");
    subscription = existing->second;
  } else {
    if (role_ == "participating" && !alias_controller().empty())
      return refuse(403, "aliases held by the owning server");
    if (req_type == "functional-alias-status-determination") {
      // TS 24.379 clause 9A.2.2.2.4 step 4: another user's aliases would need an authorisation this server has
      // no policy for.
      if (info.request_uri != user.id) return refuse(403, "status of another user");
      subscription.user = user.id;
    } else {
      Json definition;
      try {
        definition = internal("cms", "/internal/functional-alias?id=" + url_encode(info.request_uri));
      } catch (const std::exception &) {
        return refuse(403, "unknown functional alias " + info.request_uri);
      }
      const auto users = definition.value(alias_user_list(), std::vector<std::string>{});
      if (std::find(users.begin(), users.end(), user.id) == users.end())
        return refuse(403, "not authorised for " + info.request_uri);
      subscription.alias = info.request_uri;
    }
    subscription.subscriber = user.id;
  }
  subscription.expires = std::time(nullptr) + static_cast<std::int64_t>(expires);
  alias_subscriptions_[message.dialog_id] = subscription;
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(expires)}};
  event("functional_alias_subscribed", {{"user_id", user.id}, {"alias", subscription.alias}, {"expires", expires}});
  schedule([this, dialog = message.dialog_id] { notify_alias_status(dialog); });
  return response;
}

//------------------------------------------------------------------------------
// Helper: the application/resource-lists+xml body part of a message, or null.
const BodyPart *McServer::resource_lists_part(const SipMessage &message) {
  for (const auto &part : message.parts)
    if (part.content_type == resource_lists_mime) return &part;
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.4 step 2b-iii and TS 24.281 clause 6.3.3.4 step 2b-iii: a participant's
// <functional-alias> in the conference event is the alias it presented, else the one it bound to the
// session's group while that alias is active.
std::string McServer::conference_alias(const Session &session, const std::string &user) const {
  if (const auto found = session.participant_aliases.find(user); found != session.participant_aliases.end())
    return found->second;
  const auto bindings = alias_bindings_.find(user);
  if (bindings == alias_bindings_.end()) return {};
  const auto bound = bindings->second.find(session.group);
  return bound != bindings->second.end() && functional_alias_active(bound->second, user) ? bound->second
                                                                                         : std::string{};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.4.2.2.2 steps 3 and 4 (TS 24.281 clause 20.4.2.2.2): the participating function's checks
// of a binding request, returning the refusal warning or empty.
std::string McServer::alias_binding_refusal(const User &user, const SipMessage &message, const McpttInfo &info) {
  if (!user_profile(user.id).value("functional_alias_binding", false))
    return warn(Warning::alias_binding_not_authorised);
  const bool binding = info.service.contains("binding-ind") && info.service.at("binding-ind") == "true";
  const bool unbinding = info.service.contains("binding-ind") && info.service.at("binding-ind") == "false";
  const auto *lists = resource_lists_part(message);
  if (!lists ||
      !(binding ? info.service.contains("binding-fa-uri") : unbinding && info.service.contains("unbinding-fa-uri")))
    return warn(Warning::alias_binding_target_unknown);
  try {
    if (parse_resource_list_targets(lists->body).empty()) return warn(Warning::alias_binding_target_unknown);
  } catch (const std::exception &) {
    return warn(Warning::alias_binding_target_unknown);
  }
  return {};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.4.2.3.2 (TS 24.281 clause 20.4.2.3.2): the controlling function binds the alias to the
// listed groups, or unbinds it from them; a group bound to another alias of the same user refuses the binding
// with warning 178.
SipResponse McServer::alias_binding_message(const SipMessage &message, const User &user, const McpttInfo &info) {
  SipResponse response;
  const auto refuse = [&](const std::string &warning) {
    response.status_code = 403;
    response.headers = {{"Warning", "399 mcx \"" + warning + "\""}};
    event("functional_alias_binding_rejected", {{"user_id", user.id}, {"warning", warning}});
    return response;
  };
  if (const auto warning = alias_binding_refusal(user, message, info); !warning.empty()) return refuse(warning);
  const bool binding = info.service.at("binding-ind") == "true";
  const auto alias = info.service.at(binding ? "binding-fa-uri" : "unbinding-fa-uri");
  const auto groups = parse_resource_list_targets(resource_lists_part(message)->body);
  auto &bound = alias_bindings_[user.id];
  if (binding) {
    for (const auto &group : groups)
      if (const auto found = bound.find(group); found != bound.end() && found->second != alias)
        return refuse(warn(Warning::alias_binding_exists));
    for (const auto &group : groups) bound[group] = alias;
  } else {
    for (const auto &group : groups)
      if (const auto found = bound.find(group); found != bound.end() && found->second == alias) bound.erase(found);
  }
  if (bound.empty()) alias_bindings_.erase(user.id);
  event(binding ? "functional_alias_bound" : "functional_alias_unbound",
        {{"user_id", user.id}, {"alias", alias}, {"groups", groups}});
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9A.2.2.2.5 and 9A.2.2.3.5 (TS 24.281 clauses 20.2.2.2.5 and 20.2.2.3.5): the NOTIFY with
// the per-user or per-functional alias status (TS 24.379 clause 9A.3.1.2, TS 24.281 clause 20.3.1.2); the
// p-id-fa of the PUBLISH that caused it. An expired or fetched subscription ends with it.
void McServer::notify_alias_status(const std::string &dialog, const std::string &publish_id) {
  const auto found = alias_subscriptions_.find(dialog);
  if (found == alias_subscriptions_.end()) return;
  const auto &subscription = found->second;
  FunctionalAliasStatus status;
  status.mcvideo = svc_.service == Service::mcvideo;
  status.mcdata = svc_.service == Service::mcdata;
  status.publish_id = publish_id;
  if (subscription.alias.empty()) {
    const auto *served = by_id(subscription.user);
    status.entity = subscription.user;
    status.tuple_id = served && !served->client.empty() ? served->client : subscription.user;
    for (const auto &[alias, users] : functional_aliases_.activations())
      if (std::find(users.begin(), users.end(), subscription.user) != users.end())
        status.entries.push_back({alias, {}, "activated"});
  } else {
    status.entity = status.tuple_id = subscription.alias;
    status.per_alias = true;
    for (const auto &user : functional_alias_users(subscription.alias)) status.entries.push_back({{}, user, {}});
  }
  const auto now = std::time(nullptr);
  const bool ended = subscription.expires <= now;
  sip_.notify(dialog, "presence",
              ended ? "terminated;reason=timeout" : "active;expires=" + std::to_string(subscription.expires - now),
              "application/pidf+xml", functional_alias_status_xml(status));
  event("functional_alias_status_notified", {{"user_id", subscription.subscriber},
                                             {"entries", status.entries.size()},
                                             {"alias", subscription.alias},
                                             {"terminated", ended}});
  if (ended) alias_subscriptions_.erase(found);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9A.2.2.2.5 and 9A.2.2.3.5: the subscriptions following the changed users or aliases; the
// publisher's own per-user NOTIFY and the per-alias ones carry the handled p-id-fa.
void McServer::alias_status_changed(const std::set<std::string> &users, const std::set<std::string> &aliases,
                                    const std::string &publisher, const std::string &publish_id) {
  std::vector<std::pair<std::string, std::string>> due;
  for (const auto &[dialog, subscription] : alias_subscriptions_)
    if (subscription.alias.empty() ? users.contains(subscription.user) : aliases.contains(subscription.alias))
      due.emplace_back(dialog,
                       subscription.alias.empty() && subscription.user != publisher ? std::string{} : publish_id);
  for (const auto &[dialog, pid] : due) notify_alias_status(dialog, pid);
}

} // namespace mcx
