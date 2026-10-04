// Requester authorisation and priority call conditions of the controlling function (TS 24.379 clause 6.3.3.1).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the requester's own ruleset.
Json McServer::requester_rules(const User &user, const char *section) {
  return user_profile(user.id).value(section, Json::object());
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.5.3.1, 11.1.7.3.1, 11.1.8.3.1, 11.1.9.3.1 and 10.1.5.3.1: the originating
// participating function checks a call-back, remotely initiated call, transfer or forwarding request
// against the served user's ruleset.
std::string McServer::service_request_refusal(const User &user, const McpttInfo &info) {
  const auto type = info.service.contains("request-type") ? info.service.at("request-type") : std::string{};
  if (type.empty()) return {};
  Json profile;
  try {
    profile = user_profile(user.id);
  } catch (const std::exception &) {
    return {};
  } // the controlling function decides
  const auto rules = profile.value("private_call", Json::object());
  const std::map<std::string, std::pair<const char *, Warning>> needed{
      {"private-call-call-back-request", {"callback", Warning::call_back_not_authorised}},
      {"private-call-call-back-cancel-request", {"callback_cancel", Warning::call_back_cancel_not_authorised}},
      {"remotely-initiated-private-call-request", {"remote_init", Warning::remote_private_call_not_authorised}},
      {"transfer-private-call-request", {"transfer", Warning::transfer_not_authorised}},
      {"forward-private-call-request", {"forward_manual", Warning::forwarding_not_authorised}}};
  if (type == "remotely-initiated-group-call-request")
    return private_policy_flag(profile.value("group_call", Json::object()), "remote_init")
               ? std::string{}
               : warn(Warning::remote_group_call_not_authorised);
  const auto found = needed.find(type);
  return found == needed.end() || private_policy_flag(rules, found->second.first) ? std::string{}
                                                                                  : warn(found->second.second);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.8.3.2 and 11.1.9.3.2: the terminating participating function caches the mapping of
// a transfer or forwarding request authorised by a peer's controlling function for a served user; the
// follow-up private call with call-transfer-ind or call-forwarding-ind is checked against it here.
void McServer::remember_service_mapping(const std::string &id, const McpttInfo &info) {
  const auto type = info.service.contains("request-type") ? info.service.at("request-type") : std::string{};
  const auto deadline = monotonic_ms() + 60000;
  if (type == "transfer-private-call-request" && !info.called_party.empty())
    transfer_mappings_[id] = {info.called_party, deadline};
  else if (type == "forward-private-call-request" && info.service.contains("forwarding-target-id"))
    forwarding_mappings_[id] = {info.service.at("forwarding-target-id"), deadline};
  else if (type == "remotely-initiated-group-call-request")
    remember_ric_priority(id, info.calling_group, info);
  else if (type == "remotely-initiated-private-call-request")
    remember_ric_priority(id, info.called_party, info);
}

//------------------------------------------------------------------------------
// Helper: the application priority a remotely initiated call request asked for, kept for its follow-up call.
void McServer::remember_ric_priority(const std::string &remote, const std::string &target, const McpttInfo &info) {
  const auto value = info.service.find("ric-app-level-priority");
  if (value == info.service.end() || target.empty()) {
    ric_priorities_.erase(remote);
    return;
  }
  ric_priorities_[remote] = {target, value->second, monotonic_ms() + 60000};
}

//------------------------------------------------------------------------------
// The follow-up call of a remotely initiated call request may carry the
// requested application priority once; the emergency and imminent peril values
// stay reserved for those calls (TS 24.379 clauses 6.2.8.1.2 and 6.2.8.1.12).
bool McServer::ric_priority(const std::string &user, const std::string &target, const std::string &requested,
                            const Json &values) {
  const auto found = ric_priorities_.find(user);
  if (requested.empty() || found == ric_priorities_.end()) return false;
  const auto entry = found->second;
  if (entry.target != target || entry.value != requested || entry.deadline < monotonic_ms() ||
      requested == values.value("emergency", std::string{}) || requested == values.value("imminent", std::string{}))
    return false;
  ric_priorities_.erase(found);
  event("ric_priority_accepted", {{"user_id", user}, {"target", target}, {"resource_priority", requested}});
  return true;
}

//------------------------------------------------------------------------------
// Helper: the priority state of a call: a private or ad hoc call keeps its own (an ad hoc call may be an
// emergency or imminent peril call, TS 24.379 clause 17.4.2.2 step 3A), a group call that of its group.
const McServer::PriorityState &McServer::call_priority(const Session &session) {
  if (session.private_call || session.adhoc) return session.priority;
  return priorities_[session.group];
}

//------------------------------------------------------------------------------
// Helper: whether the priority policy lists the user under the given authorisation.
bool McServer::priority_allowed(const Json &policy, const char *key, const std::string &id) {
  const auto ids = policy.value(key, std::vector<std::string>{});
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}

//------------------------------------------------------------------------------
// Helper: the name of a priority state (emergency, imminent or normal).
const char *McServer::priority_name(const PriorityState &state) {
  return state.emergency ? "emergency" : state.imminent ? "imminent" : "normal";
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.1.19: the Resource-Priority header field value provisioned for the call state.
std::vector<SipHeader> McServer::priority_headers(const Json &, const PriorityState &state) const {
  const auto values = service_resource_priority();
  const auto value = values.value(priority_name(state), std::string{});
  if (value.empty()) {
    if (state.emergency || state.imminent)
      throw std::runtime_error("priority Resource-Priority values are not provisioned");
    return {};
  }
  if (value.find_first_of("\r\n ,") != std::string::npos || value.find('.') == std::string::npos)
    throw std::runtime_error("invalid provisioned Resource-Priority");
  return {{"Resource-Priority", value}};
}

//------------------------------------------------------------------------------
// Helper: the emergency, imminent peril and alert indications of the mcptt-info set from the call state.
void McServer::populate_priority(McpttInfo &info, const PriorityState &state) const {
  info.emergency.reset();
  info.imminent_peril.reset();
  info.alert.reset();
  if (state.emergency) {
    info.emergency = true;
    info.alert = state.alerts.contains(info.calling_user);
  } else if (state.imminent)
    info.imminent_peril = true;
}

//------------------------------------------------------------------------------
// Helper: the emergency alert location a message carries, if any.
std::optional<EmergencyLocation> McServer::message_location(const SipMessage &message) {
  return parse_emergency_location_parts(message.parts.empty() ? parse_body_parts(message.content_type, message.body)
                                                              : message.parts);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.1.12: the mcptt-info and, for an emergency alert, the location-info of its
// originator.
std::vector<BodyPart> McServer::priority_parts(const McpttInfo &info, const PriorityState *state) const {
  auto parts = service_parts(info);
  if (info.alert == true) {
    if (!state) {
      const auto group = priorities_.find(info.calling_group);
      if (group != priorities_.end()) state = &group->second;
    }
    if (state) {
      const auto origin = info.originated_by.empty() ? info.calling_user : info.originated_by;
      const auto location = state->alert_locations.find(origin);
      if (location != state->alert_locations.end())
        parts.push_back({svc_.location_mime, service_location_xml(location->second, svc_)});
    }
  }
  return parts;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.1.11: a SIP MESSAGE notifying a member of the in-progress emergency or imminent
// peril state or of an emergency alert.
void McServer::priority_message(User &target, McpttInfo info) {
  info.request_uri = target.id;
  const auto boundary = "mcx-" + random_id();
  sip_.request("MESSAGE", target.sip, "multipart/mixed; boundary=" + boundary,
               multipart_body(priority_parts(info), boundary),
               user_route(target, {{"P-Asserted-Service", svc_.icsi},
                                   {"Accept-Contact", feature_accept()},
                                   {"Accept-Contact", icsi_accept()}}));
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.3.1.6, 6.3.3.1.10 and 6.3.3.1.15: the next queued priority state change goes to
// a participant in a SIP re-INVITE; a failed one is retried.
void McServer::send_priority_notification(const std::shared_ptr<Leg> &leg) {
  if (!leg->active || leg->priority_notification_pending || leg->priority_notifications.empty() ||
      monotonic_ms() < leg->priority_notification_retry)
    return;
  auto notification = leg->priority_notifications.front();
  const auto &state = call_priority(*leg->session);
  if (notification.info.emergency == true)
    notification.info.alert = state.alerts.contains(notification.info.calling_user);
  leg->priority_notification_pending = true;
  try {
    sip_.reinvite(
        leg->dialog, leg->local, priority_parts(notification.info, &state),
        [this, weak = std::weak_ptr<Leg>(leg)](const SipResponse &response) {
          if (response.status_code < 200) return;
          auto leg = weak.lock();
          if (!leg) return;
          leg->priority_notification_pending = false;
          if (response.status_code < 300) {
            if (!leg->priority_notifications.empty()) leg->priority_notifications.pop_front();
            leg->priority_notification_retry = monotonic_ms() + 100;
          } else {
            if (leg->priority_notifications.size() > 1) leg->priority_notifications.pop_front();
            leg->priority_notification_retry = monotonic_ms() + 2000;
            event("priority_notification_retry", {{"user_id", leg->user}, {"status", response.status_code}});
          }
        },
        notification.headers);
  } catch (const std::exception &error) {
    leg->priority_notification_pending = false;
    leg->priority_notification_retry = monotonic_ms() + 500;
    event("priority_notification_retry", {{"reason", error.what()}, {"user_id", leg->user}});
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.3.1.6 and 6.3.3.1.11: a priority state change of a group goes to its participants
// in a SIP re-INVITE and to its affiliated members not in the call in a SIP MESSAGE; a new alert goes
// to every affiliated member.
void McServer::priority_fanout(const std::string &group, const std::string &sender, McpttInfo change, bool alert_only) {
  change.calling_group = group;
  change.calling_user = sender;
  change.broadcast.reset(); // state notifications describe priority, not the call type
  const auto &state = priorities_.at(group);
  // An emergency upgrade with alert=false requests no new alert; it does not cancel an existing alert.
  if (change.emergency == true) change.alert = state.alerts.contains(sender);
  auto found = sessions_.find(group);
  const auto session = found == sessions_.end() ? std::shared_ptr<Session>{} : found->second;
  const auto &profile = state.profile;
  for (auto &[sip, target] : users_) {
    if (!affiliated(target.id, group) || !member(profile, target.id)) continue;
    // Alert state is per originator and independent of call-state coalescing.
    if (target.id != sender && !alert_only && change.alert) {
      auto alert = change;
      alert.emergency.reset();
      alert.imminent_peril.reset();
      priority_message(target, alert);
    }
    bool participating = false;
    if (session && !alert_only)
      for (const auto &leg : session_legs(*session)) {
        if (leg->user != target.id || !leg->active) continue;
        if (target.id == sender && leg->priority_notifications.empty()) continue;
        participating = true;
        auto info = change;
        info.session_type = session->chat ? "chat" : "prearranged";
        info.request_uri = target.id;
        // Each notification describes the authoritative call state, so an unsent
        // transition can be superseded without building an unbounded queue.
        if (!state.emergency && !state.imminent) {
          info.emergency = false;
          info.imminent_peril.reset();
        } else if (state.imminent) {
          info.emergency.reset();
          info.imminent_peril = true;
        } else {
          info.emergency = true;
          info.imminent_peril.reset();
        }
        const auto keep = leg->priority_notification_pending ? 1u : 0u;
        while (leg->priority_notifications.size() > keep) leg->priority_notifications.pop_back();
        leg->priority_notifications.push_back(
            {std::move(info), priority_headers(profile.value("priority_policy", Json::object()), state)});
        send_priority_notification(leg);
      }
    // A chat member being invited into the priority call learns the state from that INVITE.
    if (!participating && target.id != sender && !(session && session->chat && has_leg(*session, target.id)))
      priority_message(target, change);
  }
}

//------------------------------------------------------------------------------
// Only the initiator of a broadcast group call may make it an emergency or
// imminent-peril call or cancel that state (project policy; receivers cannot
// transmit, TS 24.380 clause 6.3.5.3.4).
SipResponse &McServer::broadcast_priority_refused(SipResponse &response) {
  response.status_code = 403;
  response.headers = {
      {"Warning", "399 mcx \"" +
                      warn(Warning::function_not_allowed, "priority change by a broadcast group call receiver") +
                      "\""}};
  event("broadcast_priority_refused", {});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.3.1.13 and 6.3.3.1.17: the controlling function checks a priority request (the
// combination of indications, the user's authorisations, Resource-Priority); a refusal is a SIP 403
// with the current state (clause 6.3.3.1.14), a partly authorised request is corrected.
bool McServer::validate_priority(const SipMessage &message, const User &user, const Json &profile, McpttInfo &info,
                                 SipResponse &response, std::optional<McpttInfo> &correction, bool alert_only) {
  const auto policy = profile.value("priority_policy", Json::object());
  const auto requested_emergency = info.emergency, requested_imminent = info.imminent_peril;
  const auto found = priorities_.find(info.request_uri);
  const PriorityState state = found == priorities_.end() ? PriorityState{} : found->second;
  auto reject = [&](const std::string &reason) {
    response.status_code = 403;
    response.headers.push_back({"Warning", "399 mcx \"" + reason + "\""});
    McpttInfo current;
    current.emergency = state.emergency;
    current.imminent_peril = state.imminent;
    current.alert = state.alerts.contains(info.originated_by.empty() ? user.id : info.originated_by);
    response.parts = priority_parts(current);
    response.content_type = svc_.info_mime;
    response.body = service_info_xml_(current);
    return false;
  };
  const auto location = message_location(message);
  if (info.alert == true && !location) return reject("emergency alert requires CurrentCoordinate location");
  // Broadcast is a call-setup indication; an alert MESSAGE never carries it. An
  // emergency or imminent-peril broadcast group call is allowed (local policy,
  // TS 24.380 clause 8.2.3.15: the Floor Indicator combines B with D or E).
  if (info.broadcast.value_or(false) && alert_only) return reject(warn(Warning::invalid_mime_combination));
  if ((!info.calling_user.empty() && info.calling_user != user.id) || info.alert_received || info.emergency_received)
    return reject("priority identity mismatch");
  if (!alert_only && ((info.emergency == true && (!info.alert || info.imminent_peril)) ||
                      (info.imminent_peril && (info.emergency || info.alert)) || (!info.emergency && info.alert)))
    return reject(warn(Warning::invalid_mime_combination));
  if (alert_only && ((!info.alert && info.emergency != false) || info.imminent_peril || info.emergency == true))
    return reject(warn(Warning::invalid_mime_combination));
  // TS 24.379 and TS 24.281 clause 6.3.3.1.13: the rights of the caller's user profile, the profile's group entry
  // (a dedicated group, or the group the user has selected) and the group document's action for the caller.
  const auto rights = user_profile(user.id);
  const auto group_rights = rights.value("group_call", Json::object());
  const auto private_rights = rights.value("private_call", Json::object());
  const auto& group_id = info.request_uri;
  auto entry_allows = [&](const char *key) {
    const auto dedicated = group_rights.value(key, std::string());
    return dedicated.empty() || dedicated == group_id;
  };
  auto group_allows = [&](const char *action, const char *members) {
    return profile.value(action, false) || priority_allowed(policy, members, user.id);
  };
  const bool alert_right = group_rights.value("alert", false) || private_rights.value("alert", false);
  const bool alert_cancel_right = group_rights.value("alert_cancel", false) || private_rights.value("alert_cancel", false);
  // Clause 6.3.3.1.13.2.
  if (info.emergency == true && !(group_rights.value("emergency", false) && entry_allows("emergency_group") &&
                                  group_allows("allow_emergency_call", "emergency_users")))
    return reject("emergency call not authorized");
  // Clause 6.3.3.1.13.4: local policy: the user's <allow-cancel-group-emergency>, or the group's list of those who
  // may cancel.
  if (info.emergency == false &&
      !(group_rights.value("emergency_cancel", false) || priority_allowed(policy, "emergency_cancel_users", user.id)))
    return reject("emergency cancellation not authorized");
  // Clause 6.3.3.1.13.5.
  if (info.imminent_peril == true && !(group_rights.value("imminent", false) && entry_allows("imminent_group") &&
                                       group_allows("allow_imminent_peril", "imminent_users")))
    return reject("imminent peril not authorized");
  // Clause 6.3.3.1.13.6: <allow-cancel-imminent-peril> of the user profile.
  if (info.imminent_peril == false && !group_rights.value("imminent_cancel", false))
    return reject("imminent peril cancellation not authorized");
  if (!info.originated_by.empty() && (!info.alert || *info.alert))
    return reject("originated-by requires alert cancellation");
  // Clause 6.3.3.1.13.1: <allow-activate-emergency-alert>, the <EmergencyAlert> entry and the group's action.
  if (info.alert == true &&
      !(alert_right && entry_allows("alert_group") && group_allows("allow_emergency_alert", "alert_users"))) {
    if (alert_only) return reject("emergency alert not authorized");
    correction = McpttInfo{};
    correction->emergency = true;
    correction->alert = false;
    info.alert.reset();
  }
  if (info.alert == false && info.emergency != true &&
      state.alerts.contains(info.originated_by.empty() ? user.id : info.originated_by) && !alert_cancel_right) {
    if (alert_only) return reject("alert cancellation not authorized");
    correction = McpttInfo{};
    correction->alert = true;
    info.alert.reset();
  }
  if (info.imminent_peril == true && state.emergency) {
    correction = McpttInfo{};
    correction->imminent_peril = false;
    correction->emergency = true;
    info.imminent_peril.reset();
  }
  if (correction) response.headers.push_back({"Warning", "399 mcx \"" + warn(Warning::info_pending) + "\""});
  if (info.emergency == false) {
    const auto session = sessions_.find(info.request_uri);
    if (session != sessions_.end()) {
      const auto owner = session->second->arbitrator->owner();
      if (owner && *owner != user.id && state.emergency_users.contains(*owner))
        return reject("another emergency user is transmitting");
    }
  }
  const auto requested = std::string(get_header(message.headers, "Resource-Priority"));
  const auto values = service_resource_priority();
  if (!requested.empty() && !ric_priority(user.id, info.request_uri, requested, values)) {
    bool known = false;
    for (const auto *name : {"normal", "emergency", "imminent"})
      if (values.value(name, std::string{}) == requested) known = true;
    if (!known ||
        (requested == values.value("emergency", std::string{}) && !state.emergency && requested_emergency != true) ||
        (requested == values.value("imminent", std::string{}) && !state.imminent && requested_imminent != true))
      return reject("Resource-Priority is not authorized by call state");
  }
  PriorityState next = state;
  if (info.emergency) next.emergency = *info.emergency;
  if (info.imminent_peril && !next.emergency) next.imminent = *info.imminent_peril;
  if (info.emergency == true && !policy.value("emergency_timeout_ms", 300000u))
    return reject("invalid emergency timer configuration");
  (void)priority_headers(policy, next); // Validate provisioning before publishing any state.
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.6: the group's emergency, imminent peril and alert state takes the admitted request;
// the emergency state starts its deadline (in-progress emergency timer, clause 6.3.3.1.16) and the
// participants' floor priority classes follow the new state.
void McServer::apply_priority(const std::string &group, const std::string &user, const McpttInfo &info,
                              const Json &profile, std::optional<EmergencyLocation> location) {
  const auto policy = profile.value("priority_policy", Json::object());
  auto &state = priorities_[group];
  state.profile = profile;
  if (info.emergency) {
    if (*info.emergency) {
      if (!state.emergency) {
        const auto timeout = policy.value("emergency_timeout_ms", 300000u);
        if (!timeout) throw std::runtime_error("emergency_timeout_ms must be positive");
        state.emergency_deadline = monotonic_ms() + timeout;
      }
      state.emergency_users.insert(user);
      state.imminent = false;
      state.imminent_users.clear();
    } else {
      state.emergency_users.clear();
      state.emergency_deadline = 0;
      const auto session = sessions_.find(group);
      if (session != sessions_.end()) session->second->normal_since = monotonic_ms();
    }
    state.emergency = *info.emergency;
  }
  if (info.imminent_peril && !state.emergency) {
    state.imminent = *info.imminent_peril;
    if (*info.imminent_peril)
      state.imminent_users.insert(user);
    else
      state.imminent_users.clear();
  }
  if (info.alert) {
    const auto target = info.originated_by.empty() ? user : info.originated_by;
    if (*info.alert) {
      if (!location) throw std::runtime_error("missing admitted emergency alert location");
      state.alerts.insert(target);
      state.alert_locations[target] = *location;
    } else if (info.emergency != true) {
      state.alerts.erase(target);
      state.alert_locations.erase(target);
    }
  }
  if (const auto session = sessions_.find(group); session != sessions_.end())
    for (const auto &leg : session_legs(*session->second)) {
      const unsigned numeric = std::min<unsigned>(session->second->arbitrator->admitted_priority(leg->user).value_or(0),
                                                  leg->local.floor_priority.value_or(0));
      const std::uint8_t rank = state.emergency_users.contains(leg->user)                      ? 3
                                : !state.emergency && state.imminent_users.contains(leg->user) ? 2
                                : priority_allowed(policy, "floor_preemptive_users", leg->user) &&
                                        numeric >= policy.value("preemptive_priority", 99u)
                                    ? 1
                                    : 0;
      session->second->arbitrator->set_priority_class(leg->user, rank);
    }
  event("priority_changed",
        {{"group_id", group}, {"priority", priority_name(state)}, {"user_id", user}, {"alerts", state.alerts}});
}

//------------------------------------------------------------------------------
// TS 24.380 clause 14.3.3: the "mc_priority" answered is the offered one capped by the user's configured
// floor priority and the number of levels; none for a receive-only user.
void McServer::negotiate_priority(Leg &leg, const Json &profile, std::optional<std::uint8_t> offer) {
  if (!offer) {
    leg.local.floor_priority.reset();
    return;
  }
  const auto policy = profile.value("priority_policy", Json::object());
  if (priority_allowed(policy, "receive_only_users", leg.user)) {
    leg.local.floor_priority.reset();
    return;
  }
  const auto caps = policy.value("floor_priority_caps", profile.value("floor_priority_caps", Json::object()));
  // TS 24.380 clause 4.1.1.4: the configured cap, or the member's <user-priority> of the group document.
  const unsigned cap = caps.contains(leg.user) ? caps.value(leg.user, 0u)
                                               : profile.value("user_priorities", Json::object()).value(leg.user, 0u);
  const unsigned levels = policy.value("num_levels", 99u);
  if (cap > 99 || levels > 99) throw std::runtime_error("invalid configured floor priority hierarchy");
  leg.local.floor_priority = static_cast<std::uint8_t>(std::min({unsigned(*offer), cap, levels}));
}

//------------------------------------------------------------------------------
// Helper: the floor arbitration options from the service configuration.
FloorArbitratorOptions McServer::floor_options() const {
  const auto &settings = cfg_.at(svc_.name);
  FloorArbitratorOptions options;
  if (std::string_view(svc_.name) == "mcptt") {
    // TS 24.380 clause 11 with TS 24.484 clause 8.4: <transmit-time>/<time-limit> (T2), <floor-control-queue> and
    // <fc-timers-counters> of the MCPTT service configuration document.
    const auto timers = service_config_.value("fc_timers_counters", Json::object());
    options.max_talk_ms = service_config_.value("transmit_time_limit_ms", 30000u);
    options.media_idle_ms = timers.value("t1", 4000u);
    options.revoke_grace_ms = timers.value("t3", 3000u);
    options.revoke_retry_ms = timers.value("t8", 1000u);
    options.grant_retry_ms = timers.value("t20", 1000u);
    options.max_grant_transmissions = timers.value("c20", 3u);
    options.idle_retry_ms = timers.value("t7", 1000u);
    options.max_idle_transmissions = timers.value("c7", 10u);
    options.queue_enabled = service_config_.value("floor_queue", false);
    return options;
  }
  // MCVideo transmission control (TS 24.581): the MCVideo server's settings.
  options.max_talk_ms = settings.value("max_talk_ms", 30000u);
  options.media_idle_ms = settings.value("floor_media_idle_ms", 4000u);
  options.revoke_grace_ms = settings.value("floor_revoke_grace_ms", 3000u);
  options.revoke_retry_ms = settings.value("floor_revoke_retry_ms", 1000u);
  options.grant_retry_ms = settings.value("floor_grant_retry_ms", 1000u);
  options.max_grant_transmissions = settings.value("floor_grant_transmissions", 3u);
  options.idle_retry_ms = settings.value("floor_idle_retry_ms", 0u);
  options.max_idle_transmissions = settings.value("floor_idle_transmissions", 10u);
  options.queue_enabled = settings.value("floor_queue", false);
  return options;
}

} // namespace mcx
