// Private calls: on-demand private and first-to-answer calls at the combined participating and controlling
// function, their authorisation, forwarding, transfer, emergency upgrade and cancellation, and end-to-end media
// protection (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19),
// TS 24.484 V19.6.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19), RFC 3891, RFC 5359,
// RFC 5373.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.484: the user profile of an MCPTT (or MCVideo) ID from the configuration management server.
Json McServer::user_profile(const std::string &id) {
  auto profile = internal("cms", std::string("/internal/user?") + svc_.id_claim + "=" + url_encode(id));
  if (profile.value(svc_.id_claim, "") != id) throw std::runtime_error("user profile unavailable");
  return service_user_profile(std::move(profile), id);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.2 steps 8 and 9: a called user's <private-call> ruleset.
Json McServer::callee_private_policy(const std::string &id) {
  return user_profile(id).value("private_call", Json::object());
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.1.2.1.1 step 11 and 11.1.6.2.1.1: a protected private offer carries
// an I_MESSAGE, except a first-to-answer request whose key comes with the answer
// (TS 33.180 clause 7.2.4.2). The caller needs a CSK for floor control, and protected
// media is not carried across MCPTT servers. Returns a warning, or empty.
std::optional<std::string> McServer::protected_private_refusal(const User &user, const MediaDescription &media,
                                                               bool first_to_answer) const {
  if (!media.protected_media) return std::nullopt;
  if (!user.peer.empty() && !floor_keys(user))
    return warn(Warning::function_not_allowed,
                std::string("protected media not supported across ") + svc_.label + " servers");
  if (first_to_answer != media.key_mgmt.empty() || !floor_keys(user) || !floor_keys(user)->floor_ready() ||
      media.payload_type != 96 || media.octet_aligned)
    return "";
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.8.2.3 and annex D.4: the KRR for an I_MESSAGE whose receiver KMS (IDRkmsr) is not the KMS
// keying the callee, or nothing. The initiator's KMS is left open (ANY).
std::optional<std::string> McServer::kms_redirect(const std::string &mikey, const std::string &callee) const {
  std::pair<std::string, std::string> receiver;
  std::string expected;
  try {
    receiver = KeyClient::receiver(mikey);
    expected = keys_->kms_uri_of(callee);
  } catch (const std::exception &) {
    return std::nullopt;
  }
  if (receiver.second == expected) return std::nullopt;
  keying::KmsRedirect redirect{own_service_uri(),
                               KeyClient::initiator(mikey),
                               KeyClient::initiator_kms(mikey),
                               receiver.first,
                               receiver.second,
                               {},
                               {expected}};
  return keying::krr_xml(redirect, static_cast<std::uint64_t>(std::time(nullptr)) + 2208988800ULL);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 7.2.2: the terminating side of a protected private call: a callee
// served by this server with a CSK. Returns a warning for a callee that cannot take it, or nothing.
std::optional<std::string> McServer::protected_callee_refusal(const User &callee) const {
  if (!callee.peer.empty() && !floor_keys(callee))
    return warn(Warning::function_not_allowed,
                std::string("protected media not supported across ") + svc_.label + " servers");
  if (!floor_keys(callee) || !floor_keys(callee)->floor_ready()) return "";
  return std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: the call policy of a private call: the configured one, with two participants, the call ending when
// the initiator leaves, and no floor protection or required members.
Json McServer::private_call_policy() const {
  auto policy = cfg_.at(svc_.name).value("private_call", Json::object());
  policy["minimum_participants"] = 2;
  policy["end_when_initiator_leaves"] = true;
  policy["protect_floor"] = false;
  policy.erase("required_members");
  return policy;
}

//------------------------------------------------------------------------------
// Helper: the number of private calls the user takes part in. A call the user has put on hold for an announced
// transfer (TS 24.379 clause 11.1.8.2.3), or one an announced transfer replaces (except), does not count.
std::size_t McServer::private_calls(const std::string &id, const Session *except) const {
  std::size_t count = 0;
  for (const auto &[key, session] : sessions_)
    if (session->private_call && !session->ambient_released && session.get() != except &&
        std::find(session->members.begin(), session->members.end(), id) != session->members.end() &&
        std::none_of(legs_.begin(), legs_.end(), [&](const auto &entry) {
          return entry.second->session == session && entry.second->user == id && entry.second->held;
        }))
      ++count;
  return count;
}

//------------------------------------------------------------------------------
// Helper: the user has a dialog in any call other than an ambient call being released.
bool McServer::in_call(const std::string &id) const {
  for (const auto &[dialog, leg] : legs_)
    if (leg->user == id && !leg->session->ambient_released) return true;
  return false;
}

//------------------------------------------------------------------------------
// Helper: reject the INVITE of a private or first-to-answer call: set the status and the Warning, report the
// rejection and return the response.
SipResponse McServer::private_call_rejected(SipResponse &response, const User &user, int status,
                                            const std::string &warning) {
  response.status_code = status;
  if (!warning.empty()) response.headers = {{"Warning", "399 mcx \"" + warning + "\""}};
  event("private_call_rejected", {{"user_id", user.id}, {"status", status}, {"warning", warning}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 3 to 8: the caller, the service request and the single
// application/resource-lists+xml body naming the invitees (returned in resources). Returns the rejection, or
// nothing.
std::optional<SipResponse> McServer::private_invite_admission(const SipMessage &message, const User &user,
                                                              const McpttInfo &info, SipResponse &response,
                                                              const BodyPart *&resources) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return private_call_rejected(response, user, status, warning);
  };
  if (info.client_id != user.client || (!info.calling_user.empty() && info.calling_user != user.id) ||
      !info.calling_group.empty() || !accepts_mcptt(message))
    return reject(403);
  // Pre-established sessions and session-addressed rejoin are not implemented.
  if (message.request_uri != cfg_.at(svc_.name).at("service_uri").get<std::string>()) return reject(404);
  if (info.imminent_peril || info.broadcast.value_or(false))
    return reject(403, warn(Warning::function_not_allowed, "imminent peril or broadcast private call"));
  if ((info.alert == true && info.emergency != true) || info.emergency == false)
    return reject(403, warn(Warning::invalid_mime_combination));
  for (const auto &part : message.parts)
    if (part.content_type == resource_lists_mime) {
      if (resources) return reject(403, warn(Warning::called_party_unknown));
      resources = &part;
    }
  if (!resources) return reject(403, warn(Warning::called_party_unknown));
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 11A and 12, with clause 11.1.1.4.2 steps 12a to 12d for a call to a
// functional alias: authorise a first-to-answer call and determine its invitees. Returns the rejection, or
// nothing.
std::optional<SipResponse> McServer::first_to_answer_invitees(const User &user, const McpttInfo &info,
                                                              const BodyPart &resources, SipResponse &response,
                                                              std::vector<std::string> &invitees, bool &list_exempt) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return private_call_rejected(response, user, status, warning);
  };
  // The controlling function imposes manual commencement (TS 24.379 clause 11.1.1.4.1 step 3),
  // so the caller's commencement-mode authorisation does not apply.
  std::vector<std::string> requested;
  try {
    requested = parse_resource_list_targets(resources.body);
  } catch (const std::exception &) {
    return reject(403, warn(Warning::called_party_unknown));
  }
  const auto caller_policy = user_profile(user.id).value("private_call", Json::object());
  if (info.call_to_functional_alias == true) {
    // TS 24.379 clause 11.1.1.4.2 steps 12a to 12d: invite every user that activated the called alias.
    if (requested.size() != 1) return reject(403, warn(Warning::called_party_unknown));
    if (!private_policy_flag(caller_policy, "allow")) return reject(403, warn(Warning::private_call_not_authorised));
    if (!private_policy_flag(caller_policy, "first_to_answer"))
      return reject(403, warn(Warning::first_to_answer_not_authorised));
    invitees = functional_alias_users(requested.front());
    std::erase(invitees, user.id);
    list_exempt = true;
    if (invitees.empty()) return reject(403, warn(Warning::called_party_unknown));
  } else {
    auto decision = authorize_first_to_answer(caller_policy, user.id, requested);
    if (!decision) return reject(decision.status, decision.warning);
    invitees = std::move(decision.targets);
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 9 to 11: the called user of a private call (request.target) and the
// caller's authorisation, with the cached mapping of a transferred or forwarded call (steps 11c and 11d); a
// call to a functional alias is redirected (clause 11.1.1.4.2 step 8a). Returns the rejection or the
// redirection, or nothing.
std::optional<SipResponse> McServer::private_call_target(const SipMessage &message, const User &user,
                                                         const McpttInfo &info, const BodyPart &resources,
                                                         SipResponse &response, PrivateCallRequest &request,
                                                         std::vector<std::string> &invitees, bool &list_exempt) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return private_call_rejected(response, user, status, warning);
  };
  try {
    request.target = parse_private_call_target(resources.body);
  } catch (const std::exception &) {
    return reject(403, warn(Warning::called_party_unknown));
  }
  request.answer_mode = std::string(get_header(message.headers, "Answer-Mode"));
  request.priv_answer_mode = std::string(get_header(message.headers, "Priv-Answer-Mode"));
  auto caller_policy = user_profile(user.id).value("private_call", Json::object());
  list_exempt = info.call_to_functional_alias == true || info.service.contains("call-transfer-ind") ||
                info.service.contains("call-forwarding-ind");
  if (auto refused = private_call_mapping_refusal(user, info, request, response, caller_policy)) return refused;
  // TS 24.379 clause 11.1.1.3.1.1 step 11e iii: the <PrivateCall> list does not restrict a call to a functional alias.
  if (info.call_to_functional_alias == true && caller_policy.is_object()) caller_policy["any_target"] = true;
  const auto decision = authorize_private_call(caller_policy, request, svc_);
  if (!decision) return reject(decision.status, decision.warning);
  if (info.call_to_functional_alias == true) {
    // TS 24.379 clause 11.1.1.4.2 step 8a: resolve the alias and redirect with 300 Multiple Choices.
    auto users = functional_alias_users(request.target);
    std::erase(users, user.id);
    if (users.empty()) return reject(403, warn(Warning::called_party_unknown));
    McpttInfo redirect;
    redirect.request_uri = users.front();
    redirect.called_functional_alias = request.target;
    response.status_code = 300;
    response.reason = "Multiple Choices";
    response.content_type = svc_.info_mime;
    response.body = service_info_xml_(redirect);
    response.headers = {{"Contact", "<" + session_service_ + ";mcptt-session=" + random_id() + ">"}};
    event("functional_alias_resolved", {{"user_id", user.id}, {"alias", request.target}, {"selected", users.front()}});
    return response;
  }
  invitees = {request.target};
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 11c and 11d: a transferred or forwarded call needs the cached mapping
// (consumed here); it then bypasses the <PrivateCall> list (caller_policy "any_target"). Returns the
// rejection, or nothing.
std::optional<SipResponse> McServer::private_call_mapping_refusal(const User &user, const McpttInfo &info,
                                                                  const PrivateCallRequest &request,
                                                                  SipResponse &response, Json &caller_policy) {
  // TS 24.379 clause 11.1.1.3.1.1 steps 11c and 11d: a transferred or forwarded call needs the
  // cached mapping; it then bypasses the <PrivateCall> list.
  const auto indicated = [&](const char *name) {
    return info.service.contains(name) && info.service.at(name) == "true";
  };
  // The reasons are MCPTT only (TS 24.379 clauses 11.1.8 and 11.1.9); only an indicated
  // transfer or forwarding turns one into warning text.
  for (auto [name, cache, warning] :
       {std::tuple{"call-transfer-ind", &transfer_mappings_, Warning::transfer_not_authorised},
        std::tuple{"call-forwarding-ind", &forwarding_mappings_, Warning::forwarding_not_authorised}}) {
    if (!indicated(name)) continue;
    const auto found = cache->find(user.id);
    // A user served by a peer: its participating server checked the mapping.
    if (found == cache->end() && !user.peer.empty()) {
      if (caller_policy.is_object()) caller_policy["any_target"] = true;
      continue;
    }
    if (found == cache->end() || found->second.target != request.target || found->second.deadline < monotonic_ms())
      return private_call_rejected(response, user, 403, warn(warning));
    cache->erase(found);
    if (caller_policy.is_object()) caller_policy["any_target"] = true;
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.8.2.2: the transferred user's call replaces the requester's call with the target
// (RFC 3891), so the target is not busy with the call replaced (returned in replaced). Returns the
// rejection, or nothing.
std::optional<SipResponse> McServer::private_call_replaced(const std::string &replaces, const User &user,
                                                           const McpttInfo &info, bool first_to_answer,
                                                           const PrivateCallRequest &request, SipResponse &response,
                                                           std::shared_ptr<Session> &replaced) {
  if (first_to_answer || !info.service.contains("call-transfer-ind")) return private_call_rejected(response, user, 403);
  const auto call_id = replaces.substr(0, replaces.find(';'));
  if (const auto leg = legs_.find(call_id); leg != legs_.end() && leg->second->user == request.target &&
                                            leg->second->session->private_call &&
                                            leg->second->session->transfer_announced)
    replaced = leg->second->session;
  if (!replaced) return private_call_rejected(response, user, 481);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.3.1.13.1 and 6.3.3.1.13.2: emergency private call and alert authorisation of an
// emergency request (priority, and the correction of a refused alert). Returns the rejection, or nothing.
std::optional<SipResponse> McServer::private_call_emergency(const SipMessage &message, const User &user,
                                                            const McpttInfo &info, bool first_to_answer,
                                                            const PrivateCallRequest &request,
                                                            std::vector<std::string> &invitees, SipResponse &response,
                                                            PriorityState &priority,
                                                            std::optional<McpttInfo> &correction) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return private_call_rejected(response, user, status, warning);
  };
  const auto policy = user_profile(user.id).value("private_call", Json::object());
  // An emergency first-to-answer call is an emergency private call to each
  // invitee (definition in TS 24.379 clause 3.1): keep only the authorised recipients.
  if (first_to_answer)
    std::erase_if(invitees, [&](const std::string &target) { return !authorize_emergency_private(policy, target); });
  if (first_to_answer ? invitees.empty() : !authorize_emergency_private(policy, request.target)) {
    // TS 24.379 clause 6.3.3.1.14: the rejection reports emergency-ind false.
    McpttInfo current;
    current.emergency = false;
    response.content_type = svc_.info_mime;
    response.body = service_info_xml_(current);
    return reject(403, "emergency private call not authorized");
  }
  priority.emergency = true;
  priority.emergency_users.insert(user.id);
  if (info.alert == true) {
    const auto location = message_location(message);
    if (!location) return reject(403, "emergency alert requires CurrentCoordinate location");
    const bool alert_allowed =
        first_to_answer
            ? std::all_of(invitees.begin(), invitees.end(),
                          [&](const std::string &target) { return authorize_private_alert(policy, target); })
            : authorize_private_alert(policy, request.target);
    if (alert_allowed) {
      priority.alerts.insert(user.id);
      priority.alert_locations[user.id] = *location;
    } else {
      correction = McpttInfo{};
      correction->emergency = true;
      correction->alert = false;
    }
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 1 and 14: the Resource-Priority of the request (an emergency value as in
// clause 11.1.1.4.3 step 4), the media offer, its end-to-end protection (TS 33.180 clause 7.2.2) and the KMS of a
// protected offer (TS 33.180 clause 5.2.8.2.3). Returns the rejection or the KMS Redirect Response, or nothing.
std::optional<SipResponse> McServer::private_call_media_refusal(const SipMessage &message, const User &user,
                                                                const McpttInfo &info, bool first_to_answer,
                                                                const PrivateCallRequest &request,
                                                                const PriorityState &priority, SipResponse &response) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return private_call_rejected(response, user, status, warning);
  };
  if (!ric_priority(user.id, request.target, std::string(get_header(message.headers, "Resource-Priority")),
                    service_resource_priority()) &&
      !private_resource_priority_allowed(message, priority, info.emergency == true))
    return reject(403, "Resource-Priority is not authorized by call state");
  try {
    (void)priority_headers(cfg_.at(svc_.name), priority);
  } catch (const std::exception &) {
    return reject(403, "emergency Resource-Priority values are not provisioned");
  }
  if (!message.remote_media) return reject(488);
  if (const auto refusal = protected_private_refusal(user, *message.remote_media, first_to_answer))
    return reject(488, *refusal);
  // TS 33.180 clause 5.2.8.2.3 and annex D.4: a PCK keyed to a KMS that does not key the callee
  // is answered 488 with a KMS Redirect Response naming the one that does.
  if (message.remote_media->protected_media && !first_to_answer && keys_)
    if (auto redirect = kms_redirect(message.remote_media->key_mgmt, request.target)) {
      response.status_code = 488;
      response.content_type = keying::krr_mime;
      response.body = *redirect;
      event("kms_redirect_sent", {{"user_id", user.id}, {"target", request.target}});
      return response;
    }
  try {
    validate_remote(user.id, *message.remote_media, false, true);
  } catch (const std::exception &error) {
    event("sdp_rejected", {{"reason", error.what()}});
    return reject(488);
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.2 steps 4 to 11: the terminating participating function for one invitee
// (forwarding, the callee's <private-call> ruleset, protection), then the busy check; a reachable invitee is
// added to callees, otherwise its rejection is kept there. Returns the rejection of the whole INVITE (the call
// is forwarded), or nothing.
std::optional<SipResponse> McServer::private_invitee_check(const SipMessage &message, const User &user,
                                                           const McpttInfo &info, bool first_to_answer,
                                                           const std::string &target, unsigned limit,
                                                           const Session *replaced, SipResponse &response,
                                                           PrivateCallees &callees) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return private_call_rejected(response, user, status, warning);
  };
  const auto *callee = by_id(target);
  // Forwarding applies to a private call not already forwarded (one forwarding per call).
  const bool may_forward = !first_to_answer && !info.service.contains("call-forwarding-ind");
  const auto forwarding = [&](const Json &policy, const char *key) {
    return may_forward && policy.is_object() ? policy.value(key, std::string{}) : std::string{};
  };
  if (!callee || callee->expires <= std::time(nullptr)) {
    // TS 24.379 clause 11.1.1.3.2 step 6: an unregistered user with forwarding on no answer
    // is forwarded at once.
    Json callee_policy;
    try {
      callee_policy = callee_private_policy(target);
    } catch (const std::exception &) {
      // No policy for the callee: no forwarding.
    }
    if (const auto no_answer = forwarding(callee_policy, "forward_no_answer"); !no_answer.empty()) {
      forward_private_call(user.id, target, no_answer, "no-answer");
      return reject(480, warn(Warning::call_forwarded));
    }
    callees.last_rejection = {480, ""};
    return std::nullopt;
  }
  Json callee_policy;
  try {
    callee_policy = callee_private_policy(target);
  } catch (const std::exception &) {
    callees.last_rejection = {404, ""};
    return std::nullopt;
  }
  if (const auto callee_decision = authorize_private_callee(callee_policy, user.id, svc_); !callee_decision) {
    callees.last_rejection = callee_decision;
    return std::nullopt;
  }
  // TS 24.379 clause 11.1.1.3.2 step 4: immediate forwarding configured for the called user.
  if (const auto immediate = forwarding(callee_policy, "forward_immediate"); !immediate.empty()) {
    forward_private_call(user.id, target, immediate, "immediate");
    return reject(480, warn(Warning::call_forwarded));
  }
  // TS 24.379 clause 11.1.1.3.2 step 11 (clause 6.3.2.5): TNP1 for forwarding on no answer, from the called
  // user's profile.
  if (const auto no_answer = forwarding(callee_policy, "forward_no_answer"); !no_answer.empty()) {
    callees.no_answer_target = no_answer;
    callees.no_answer_timeout = callee_policy.value("forward_no_answer_timeout_ms", 20000u);
  }
  if (message.remote_media->protected_media)
    if (const auto refusal = protected_callee_refusal(*callee)) {
      callees.last_rejection = {488, *refusal};
      return std::nullopt;
    }
  release_listened_to(target, ambient_reason("for"));
  if (private_calls(target, replaced) >= limit) {
    callees.last_rejection = {486, ""};
    return std::nullopt;
  }
  callees.reachable.push_back(target);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.4.1: the session of a private or first-to-answer call with its reachable invitees,
// priority, transfer, forwarding on no answer, commencement mode (RFC 5373) and media control.
std::shared_ptr<McServer::Session>
McServer::make_private_session(const SipMessage &message, const User &user, const McpttInfo &info, bool first_to_answer,
                               bool list_exempt, const BodyPart &resources, const PrivateCallRequest &request,
                               const PriorityState &priority, const std::shared_ptr<Session> &replaced,
                               const std::string &replaces, const PrivateCallees &callees, const Json &policy) {
  const auto &reachable = callees.reachable;
  auto session = std::make_shared<Session>();
  session->private_call = true;
  session->protected_private = message.remote_media->protected_media;
  session->private_key_mgmt = message.remote_media->key_mgmt;
  session->first_to_answer = first_to_answer;
  if (video_one_to_one(info.session_type)) session->video_mode = info.session_type;
  session->list_exempt = list_exempt;
  session->invitees = reachable;
  if (!info.functional_alias.empty() && functional_alias_active(info.functional_alias, user.id))
    session->initiator_alias = session->participant_aliases[user.id] = info.functional_alias;
  if (!info.called_functional_alias.empty())
    session->called_alias = info.called_functional_alias;
  else if (first_to_answer && info.call_to_functional_alias == true)
    session->called_alias = parse_resource_list_targets(resources.body).front();
  session->priority = priority;
  session->private_request = request;
  session->transfer_announced =
      info.service.contains("transfer-announced-ind") && info.service.at("transfer-announced-ind") == "true";
  if (replaced) session->replaces_header = replaces;
  if (!callees.no_answer_target.empty()) {
    session->no_answer_target = callees.no_answer_target;
    session->no_answer_deadline = monotonic_ms() + callees.no_answer_timeout;
  }
  session->group = "private:" + random_id();
  session->uri = session_service_ + ";mcptt-session=" + random_id();
  session->initiator = user.id;
  session->policy = policy;
  session->created = session->last_media = session->normal_since = monotonic_ms();
  session->members = {user.id};
  session->members.insert(session->members.end(), reachable.begin(), reachable.end());
  // Controlling function forwards the requested commencement mode (RFC 5373);
  // a first-to-answer call always rings (TS 24.379 clause 11.1.1.4.1 step 3).
  if (first_to_answer)
    session->answer_headers.push_back({"Priv-Answer-Mode", "Manual"});
  else if (!request.priv_answer_mode.empty())
    session->answer_headers.push_back({"Priv-Answer-Mode", request.priv_answer_mode});
  else if (!request.answer_mode.empty())
    session->answer_headers.push_back({"Answer-Mode", request.answer_mode});
  session->arbitrator = make_media_control(session->members, floor_options());
  // TS 24.379 clause 11.1.2.4.2 and TS 24.281 clause 10.2.3: an offer without a media plane control
  // channel asks for a private call without floor (or transmission) control.
  session->no_media_control = message.remote_media->control == MediaControl::none;
  return session;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.4.2: the caller's leg and the answer kept for it until an invitee answers; the
// caller gets 180 Ringing (a first-to-answer caller 100 Trying), and the session and leg are stored.
// Returns the rejection, or nothing.
std::optional<SipResponse>
McServer::private_caller_answer(const SipMessage &message, const User &user, const McpttInfo &info,
                                bool first_to_answer, const PrivateCallRequest &request, const PriorityState &priority,
                                const std::optional<McpttInfo> &correction, const std::shared_ptr<Session> &session,
                                SipResponse &response) {
  auto leg = make_leg(user.id, session);
  if (!session->no_media_control && leg->local.floor_ssrc == message.remote_media->floor_ssrc)
    return private_call_rejected(response, user, 488);
  leg->dialog = message.dialog_id;
  leg->origin = true;
  leg->incoming_offer = true;
  leg->remote = *message.remote_media;
  leg->local.payload_type = message.remote_media->payload_type;
  leg->local.octet_aligned = message.remote_media->octet_aligned;
  leg->local.queueing = leg->local.queueing && message.remote_media->queueing;
  leg->local.floor_priority.reset(); // no group priority hierarchy in a private call
  // TS 24.281 clause 13.2.2.1 with TS 24.581 clause 6.2: the pushing caller asks for the
  // permission to transmit in its offer, which the answer accepts (TS 24.581 clause 14.3.5).
  if (session->video_mode == "one-to-one video push")
    leg->local.implicit_request = message.remote_media->implicit_request;
  response.status_code = 200;
  response.local_media = leg->local;
  response.contact_uri = session->uri;
  response.focus = true;
  McpttInfo answer;
  answer.session_type = info.session_type;
  answer.request_uri = request.target;
  answer.calling_user = user.id;
  populate_priority(answer, priority);
  response.parts = priority_parts(answer, &session->priority);
  response.headers = priority_headers(cfg_.at(svc_.name), priority);
  if (correction) response.headers.push_back({"Warning", "399 mcx \"" + warn(Warning::info_pending) + "\""});
  leg->pending_priority_info = correction;
  leg->answer = response;
  leg->awaiting_answer = true;
  // A first-to-answer caller sees 183 once any invitee rings (TS 24.379 clause 11.1.1.4.2).
  response.status_code = first_to_answer ? 100 : 180;
  // A protected first-to-answer call has no SDP answer before the 200: its answer
  // carries the PCK of the invitee that answers (TS 33.180 clause 7.2.4.3 step 8).
  if (first_to_answer && session->protected_private) {
    response.local_media.reset();
    response.deferred = true; // the SIP engine sends the SDP answer with the 200
  }
  response.reason = first_to_answer ? "Trying" : "Ringing";
  sessions_[session->group] = session;
  add_leg(leg);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.4.1: invite the reachable invitees of a new private or first-to-answer call, once
// any ambient call or relayed call with them is released.
void McServer::schedule_private_invitations(const std::shared_ptr<Session> &session) {
  auto invite = [this, session] {
    session->invitation_deferred = false;
    for (const auto &target : session->invitees) invite_private_target(session, target);
    complete_setup(session); // fails the call if no invitee could be reached
  };
  // An invitee's ambient call is released first (TS 24.379 clause 11.1.6.4.3, TS 24.281 clause 15.4.3), and
  // the invitation waits for the end of that dialog with the invitee: sent at once,
  // the two may cross on the way to a user served by another function, whose client
  // then refuses the invitation as busy.
  if (const auto ambient = releasing_ambient(session->invitees)) {
    session->invitation_deferred = true;
    ambient->after_release.push_back(std::move(invite));
  } else if (const auto relay = releasing_relay(session->invitees)) {
    session->invitation_deferred = true;
    relay->after_release.push_back(std::move(invite));
  } else
    schedule(std::move(invite));
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.1.3.1.1 and 11.1.1.4.2: the combined originating participating and controlling function
// receives the INVITE of an on-demand private or first-to-answer call: authorise the caller and each invitee
// (clause 11.1.1.3.2 at the terminating participating function), forward or redirect where configured, answer
// and invite the reachable invitees.
SipResponse McServer::private_invite(const SipMessage &message, const User &user, const McpttInfo &info) {
  SipResponse response;
  const bool first_to_answer = info.session_type == "first-to-answer";
  bool list_exempt = false;
  const auto reject = [&](int status, const std::string &warning = {}) {
    return private_call_rejected(response, user, status, warning);
  };
  if (const auto existing = legs_.find(message.dialog_id); existing != legs_.end())
    return private_reinvite(message, user, info, existing->second);
  const BodyPart *resources = nullptr;
  if (auto refused = private_invite_admission(message, user, info, response, resources)) return *refused;
  PrivateCallRequest request;
  request.caller = user.id;
  std::vector<std::string> invitees;
  if (auto refused = first_to_answer ? first_to_answer_invitees(user, info, *resources, response, invitees, list_exempt)
                                     : private_call_target(message, user, info, *resources, response, request, invitees,
                                                           list_exempt))
    return *refused;
  // TS 24.379 clause 11.1.8.2.2: the transferred user's call replaces the requester's call with
  // the target (RFC 3891), so the target is not busy with the call replaced.
  const auto replaces = std::string(get_header(message.headers, "Replaces"));
  std::shared_ptr<Session> replaced;
  if (!replaces.empty())
    if (auto refused = private_call_replaced(replaces, user, info, first_to_answer, request, response, replaced))
      return *refused;
  // Emergency private call and alert authorisation (TS 24.379 clauses 6.3.3.1.13.1 and 6.3.3.1.13.2).
  PriorityState priority;
  std::optional<McpttInfo> correction;
  if (info.emergency == true)
    if (auto refused = private_call_emergency(message, user, info, first_to_answer, request, invitees, response,
                                              priority, correction))
      return *refused;
  if (auto refused = private_call_media_refusal(message, user, info, first_to_answer, request, priority, response))
    return *refused;
  auto policy = private_call_policy();
  policy["protect_floor"] = message.remote_media->protected_media;
  const auto limit = policy.value("max_calls", 1u);
  if (private_calls(user.id) >= limit) return reject(486, warn(Warning::max_private_calls));
  // Terminating participating function per invitee (TS 24.379 clause 11.1.1.3.2 steps 7 to 9),
  // then the busy check. A first-to-answer call keeps the invitees that pass;
  // a private call relays the single callee's rejection.
  PrivateCallees callees;
  for (const auto &target : invitees)
    if (auto refused = private_invitee_check(message, user, info, first_to_answer, target, limit, replaced.get(),
                                             response, callees))
      return *refused;
  if (callees.reachable.empty())
    return first_to_answer ? reject(480) : reject(callees.last_rejection.status, callees.last_rejection.warning);
  auto session = make_private_session(message, user, info, first_to_answer, list_exempt, *resources, request, priority,
                                      replaced, replaces, callees, policy);
  if (auto refused =
          private_caller_answer(message, user, info, first_to_answer, request, priority, correction, session, response))
    return *refused;
  schedule_private_invitations(session);
  event("private_call_created", {{"user_id", user.id},
                                 {"target", request.target},
                                 {"invitees", callees.reachable},
                                 {"session_uri", session->uri},
                                 {"first_to_answer", first_to_answer},
                                 {"answer_mode", first_to_answer                    ? "manual"
                                                 : request.priv_answer_mode.empty() ? request.answer_mode
                                                                                    : "force-auto"}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.4.1: the controlling function invites one callee of a private, first-to-answer,
// ambient listening or video call, with the service information, priority, commencement mode and Contact of
// the call, and records the callee's provisional and final responses (183 to the caller of a first-to-answer
// call once an invitee rings, clause 11.1.1.4.2).
void McServer::invite_private_target(const std::shared_ptr<Session> &session, const std::string &target) {
  if (!current_session(session)) return;
  const auto *callee = by_id(target);
  if (!callee || callee->expires <= std::time(nullptr)) {
    session->failure_status = 480;
    return;
  }
  std::shared_ptr<Leg> leg;
  try {
    leg = make_leg(target, session);
  } catch (const CapacityReached &) {
    session->failure_status = 500;
    session->capacity_reached = true;
    event("call_rejected_capacity", {{"session_uri", session->uri}, {"retry_after", capacity_retry_after()}});
    return;
  }
  leg->local.floor_priority.reset();
  McpttInfo info;
  info.session_type = !session->ambient.empty()      ? svc_.ambient
                      : session->first_to_answer     ? "first-to-answer"
                      : !session->video_mode.empty() ? session->video_mode
                                                     : "private";
  if (!session->ambient.empty()) {
    // TS 24.379 clause 11.1.6.4.1: the controlling function receives from the listened-to user only.
    info.ambient_listening_type = session->ambient;
    leg->local.direction = target == session->listened_to ? "recvonly" : "sendonly";
  }
  info.request_uri = target;
  info.calling_user = session->initiator;
  info.functional_alias = session->initiator_alias;
  if (session->called_alias.size()) info.called_functional_alias = session->called_alias;
  populate_priority(info, session->priority);
  if (session->transfer_announced) info.service["transfer-announced-ind"] = "true";
  auto headers = session->answer_headers;
  for (const auto &header : priority_headers(cfg_.at(svc_.name), session->priority)) headers.push_back(header);
  headers.push_back({"Contact", focus_contact(*session)});
  if (!session->replaces_header.empty()) headers.push_back({"Replaces", session->replaces_header});
  leg->local.key_mgmt = session->private_key_mgmt;
  leg->dialog = sip_.invite(
      callee->sip, leg->local, priority_parts(info, &session->priority),
      [this, weak = std::weak_ptr<Session>(session)](const SipResponse &response) {
        const auto session = weak.lock();
        if (!session) return;
        if (response.status_code == 180 && session->first_to_answer && !session->progress_sent) {
          session->progress_sent = true;
          schedule([this, session] {
            if (!current_session(session)) return;
            for (const auto &leg : session_legs(*session))
              if (leg->awaiting_answer) {
                SipResponse progress;
                progress.status_code = 183;
                progress.reason = "Session Progress";
                sip_.answer(leg->dialog, progress);
              }
          });
        }
        if (response.status_code >= 200 && response.status_code < 300 && session->transfer_announced)
          for (const auto &part : response.parts)
            if (part.content_type == svc_.info_mime) {
              try {
                const auto answer = parse_service_info_(part.body);
                if (const auto value = answer.service.find("replaces-header-value"); value != answer.service.end())
                  session->replaces_value = value->second;
              } catch (const std::exception &) {
                // A malformed info body carries no Replaces value.
              }
            }
        if (response.status_code < 300) return;
        session->failure_status = response.status_code;
        session->failure_warning = std::string(get_header(response.headers, "Warning"));
      },
      user_route(*callee, headers));
  leg->local.key_mgmt.clear(); // offered once; never in a re-INVITE or refresh
  add_leg(leg);
  event("private_call_invite",
        {{"user_id", target}, {"session_uri", session->uri}, {"first_to_answer", session->first_to_answer}});
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.1.4.3 step 4 and 11.1.1.4.4 step 4: an emergency Resource-Priority needs
// an authorised emergency request or an in-progress emergency private call.
bool McServer::private_resource_priority_allowed(const SipMessage &message, const PriorityState &state,
                                                 bool emergency_requested) const {
  const auto requested = std::string(get_header(message.headers, "Resource-Priority"));
  if (requested.empty()) return true;
  const auto values = service_resource_priority();
  if (requested == values.value("emergency", std::string{})) return emergency_requested || state.emergency;
  return requested == values.value("normal", std::string{});
}

//------------------------------------------------------------------------------
// Helper: reject a re-INVITE of a private call: set the status and the Warning, with with_state the unchanged
// emergency and alert state, report the rejection and return the response.
SipResponse McServer::private_priority_rejected(SipResponse &response, const User &user, const McpttInfo &info,
                                                const PriorityState &state, int status, const std::string &warning,
                                                bool with_state) {
  response.status_code = status;
  if (!warning.empty()) response.headers = {{"Warning", "399 mcx \"" + warning + "\""}};
  if (with_state) {
    // TS 24.379 clause 11.1.1.4.4 steps 3b and 3c: report the unchanged emergency and alert state.
    McpttInfo current;
    current.emergency = state.emergency;
    if (info.alert == false)
      current.alert = state.alerts.contains(info.originated_by.empty() ? user.id : info.originated_by);
    response.parts = service_parts(current);
  }
  event("private_priority_rejected", {{"user_id", user.id}, {"status", status}, {"warning", warning}});
  return response;
}

//------------------------------------------------------------------------------
// RFC 5359 section 2.1: hold and resume of a private call, a re-INVITE that changes only the direction.
// Returns the answer, or nothing for any other re-INVITE.
std::optional<SipResponse> McServer::private_hold_resume(const SipMessage &message, const User &user,
                                                         const McpttInfo &info, const std::shared_ptr<Leg> &leg,
                                                         const Session &session) {
  // Hold and resume (RFC 5359 section 2.1): a re-INVITE that changes only the direction.
  if (const auto &old = leg->remote;
      session.private_call && leg->user == user.id && leg->active && session.established && !info.emergency &&
      !info.imminent_peril && old && message.remote_media && old->address == message.remote_media->address &&
      old->audio_port == message.remote_media->audio_port && old->control == message.remote_media->control &&
      old->floor_port == message.remote_media->floor_port && old->payload_type == message.remote_media->payload_type &&
      message.remote_media->direction != old->direction &&
      (message.remote_media->direction == "sendonly" || message.remote_media->direction == "sendrecv")) {
    SipResponse response;
    leg->held = message.remote_media->direction == "sendonly";
    leg->remote->direction = message.remote_media->direction;
    leg->local.direction = leg->held ? "recvonly" : "sendrecv";
    response.status_code = 200;
    response.local_media = leg->local;
    event(leg->held ? "private_call_held" : "private_call_resumed",
          {{"user_id", user.id}, {"session_uri", session.uri}});
    return response;
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.1.4.3 step 3 and 11.1.1.4.4 step 3: authorise the upgrade to, or the cancellation of,
// an emergency private call (and its alert) with the requester's ruleset, giving the next priority state and the
// correction of a refused alert change. Returns the rejection, or nothing.
std::optional<SipResponse> McServer::private_priority_request(const SipMessage &message, const User &user,
                                                              const McpttInfo &info, const Session &session,
                                                              SipResponse &response, PriorityState &next,
                                                              std::optional<McpttInfo> &correction) {
  const auto &state = session.priority;
  const auto reject = [&](int status, const std::string &warning, bool with_state = false) {
    return private_priority_rejected(response, user, info, state, status, warning, with_state);
  };
  const auto peer = user.id == session.initiator ? session.private_request.target : session.initiator;
  const auto policy = user_profile(user.id).value("private_call", Json::object());
  if (*info.emergency) {
    if (!authorize_emergency_private(policy, peer)) return reject(403, "emergency private call not authorized", true);
    next.emergency = true;
    next.emergency_users.insert(user.id);
    if (info.alert == true) {
      const auto location = message_location(message);
      if (!location) return reject(403, "emergency alert requires CurrentCoordinate location");
      if (authorize_private_alert(policy, peer)) {
        next.alerts.insert(user.id);
        next.alert_locations[user.id] = *location;
      } else {
        correction = McpttInfo{};
        correction->emergency = true;
        correction->alert = false;
      }
    }
  } else {
    if (!private_policy_flag(policy, "emergency_cancel"))
      return reject(403, "emergency private call cancellation not authorized", true);
    next.emergency = false;
    next.emergency_users.clear();
    if (info.alert == false) {
      const auto origin = info.originated_by.empty() ? user.id : info.originated_by;
      if (private_policy_flag(policy, "alert_cancel")) {
        next.alerts.erase(origin);
        next.alert_locations.erase(origin);
      } else {
        correction = McpttInfo{};
        correction->alert = true;
      }
    }
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.1.4.5 and 11.1.1.4.6: re-INVITE the other party of a private call with the new
// emergency and alert state.
void McServer::notify_private_priority_change(const Session &session, const std::shared_ptr<Leg> &leg, const User &user,
                                              const McpttInfo &info, const std::vector<SipHeader> &headers) {
  const auto &state = session.priority;
  for (const auto &other : session_legs(session)) {
    if (other == leg || !other->active) continue;
    McpttInfo change;
    change.session_type = "private";
    change.request_uri = other->user;
    change.calling_user = user.id;
    change.emergency = state.emergency;
    if (!state.emergency && info.alert == false) {
      change.alert = false;
      change.originated_by = info.originated_by;
    }
    const auto keep = other->priority_notification_pending ? 1u : 0u;
    while (other->priority_notifications.size() > keep) other->priority_notifications.pop_back();
    other->priority_notifications.push_back({std::move(change), headers});
    send_priority_notification(other);
  }
}

//------------------------------------------------------------------------------
// In-dialog upgrade to, or cancellation of, an emergency private call
// (TS 24.379 clauses 11.1.1.4.3 to 11.1.1.4.6). Either party may request it with its
// own ruleset; the other party is informed by a re-INVITE.
SipResponse McServer::private_reinvite(const SipMessage &message, const User &user, McpttInfo info,
                                       const std::shared_ptr<Leg> &leg) {
  SipResponse response;
  const auto session = leg->session;
  auto &state = session->priority;
  const auto reject = [&](int status, const std::string &warning, bool with_state = false) {
    return private_priority_rejected(response, user, info, state, status, warning, with_state);
  };
  if (auto answer = private_hold_resume(message, user, info, leg, *session)) return *answer;
  if (!session->private_call || leg->user != user.id || !leg->active || !session->established || !info.emergency ||
      info.imminent_peril || (session->first_to_answer && session->private_request.target.empty()))
    return reject(488, warn(Warning::function_not_allowed, "private call re-INVITE"));
  if ((!info.calling_user.empty() && info.calling_user != user.id) || (info.alert == true && !*info.emergency))
    return reject(403, warn(Warning::invalid_mime_combination));
  if (!leg->remote || !message.remote_media) return reject(488, "");
  const auto &old = *leg->remote;
  if (old.address != message.remote_media->address || old.audio_port != message.remote_media->audio_port ||
      old.floor_port != message.remote_media->floor_port || old.floor_ssrc != message.remote_media->floor_ssrc ||
      old.payload_type != message.remote_media->payload_type ||
      old.octet_aligned != message.remote_media->octet_aligned || old.queueing != message.remote_media->queueing ||
      old.control != message.remote_media->control)
    return reject(488, "");
  std::optional<McpttInfo> correction;
  PriorityState next = state;
  if (auto refused = private_priority_request(message, user, info, *session, response, next, correction))
    return *refused;
  if (!private_resource_priority_allowed(message, state, *info.emergency) ||
      (!*info.emergency &&
       std::string(get_header(message.headers, "Resource-Priority")) ==
           service_resource_priority().value("emergency", std::string{})))
    return reject(403, "Resource-Priority is not authorized by call state");
  std::vector<SipHeader> headers;
  try {
    headers = priority_headers(cfg_.at(svc_.name), next);
  } catch (const std::exception &) {
    return reject(403, "emergency Resource-Priority values are not provisioned");
  }
  state = next;
  leg->pending_priority_info = correction;
  response.status_code = 200;
  response.local_media = leg->local;
  McpttInfo current;
  current.session_type = "private";
  current.request_uri = user.id;
  current.calling_user = user.id;
  populate_priority(current, state);
  if (!state.emergency) current.emergency = false; // a downgrade is signalled explicitly
  response.parts = priority_parts(current, &state);
  response.headers = headers;
  if (correction) {
    response.headers.push_back({"Warning", "399 mcx \"" + warn(Warning::info_pending) + "\""});
    schedule([this, dialog = leg->dialog] { send_priority_correction(dialog); });
  }
  notify_private_priority_change(*session, leg, user, info, headers);
  event("private_priority_changed", {{"user_id", user.id},
                                     {"session_uri", session->uri},
                                     {"priority", priority_name(state)},
                                     {"alerts", state.alerts}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.4.2 (200 OK of a first-to-answer call, steps 5 and 8): the first invitee to answer is
// selected; every other invitee is cancelled (early) or released with "not selected for call".
void McServer::select_first_answer(const std::shared_ptr<Session> &session, const std::shared_ptr<Leg> &winner) {
  session->private_request.target = winner->user;
  session->members = {session->initiator, winner->user};
  const auto now = monotonic_ms();
  for (const auto &leg : session_legs(*session)) {
    if (leg->origin || leg == winner) continue;
    notices(*session, session->arbitrator->remove(leg->user, now));
    release_not_selected(*leg);
  }
  for (const auto &leg : session_legs(*session))
    if (leg->awaiting_answer) {
      McpttInfo answer;
      answer.session_type = "first-to-answer";
      answer.calling_user = session->initiator;
      answer.called_party = winner->user;
      // Keep the emergency/alert state of an emergency first-to-answer call.
      populate_priority(answer, session->priority);
      leg->answer.parts = priority_parts(answer, &session->priority);
      // TS 24.379 clause 11.1.1.4.2 (200 OK of a first-to-answer call, step 2): the answering invitee's I_MESSAGE
      // reaches the caller unchanged in the SDP answer (TS 33.180 clause 7.2.4.3 steps 7 and 8).
      if (session->protected_private && leg->answer.local_media)
        leg->answer.local_media->key_mgmt = winner->remote ? winner->remote->key_mgmt : std::string{};
    }
  event("first_to_answer_selected", {{"user_id", winner->user}, {"session_uri", session->uri}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.4.2 (200 OK of a first-to-answer call, steps 8a and 8b): release an invitee that was not
// selected, with the <release-reason> "not selected for call".
void McServer::release_not_selected(Leg &leg) {
  const bool confirmed = leg.active;
  leg.active = false;
  McpttInfo reason;
  reason.release_reason = "not selected for call";
  // An early leg is cancelled; the reason is still used if its 2xx crosses the CANCEL.
  sip_.bye(leg.dialog, {}, {}, service_parts(reason));
  event("first_to_answer_released", {{"user_id", leg.user}, {"confirmed", confirmed}});
}

//------------------------------------------------------------------------------
// Helper: periodic revalidation: withdrawal of the caller's private-call authority
// or of either party's service authorization releases the call.
void McServer::revalidate_private(const std::shared_ptr<Session> &session) {
  if (session->ambient_released) return;
  try {
    if (!session->server_video.empty()) {
      // A call to the server itself (TS 24.281 clauses 13.2.3.2.3 and 12.2.3.2.5): its user's own
      // authorisation, not the private-call rules, which it has no called party for.
      const bool push = session->server_video == "record";
      if (!user_profile(session->initiator)
               .value(push ? "allow_video_push_to_server" : "allow_video_pull_from_server", false))
        throw std::runtime_error(warn(Warning::function_not_allowed, "server video authorisation withdrawn"));
      const auto *participant = by_id(session->initiator);
      if (!participant || participant->expires <= std::time(nullptr))
        throw std::runtime_error("participant authorization expired");
      return;
    }
    if (!session->ambient.empty()) {
      const auto policy = user_profile(session->initiator).value("private_call", Json::object());
      if (!private_policy_flag(policy, session->ambient == "remote-init" ? "ambient_remote" : "ambient_local"))
        throw std::runtime_error(warn(Warning::ambient_not_authorised));
      if (const auto decision = authorize_private_call(policy, session->private_request, svc_); !decision)
        throw std::runtime_error(decision.warning);
      const auto callee = callee_private_policy(session->private_request.target);
      if (callee.is_object() && callee.contains("callable") && callee.at("callable") == false)
        throw std::runtime_error(warn(Warning::not_callable_in_private_call));
      for (const auto &id : session->members) {
        const auto *participant = by_id(id);
        if (!participant || participant->expires <= std::time(nullptr))
          throw std::runtime_error("participant authorization expired");
      }
      return;
    }
    if (session->first_to_answer) {
      const auto policy = user_profile(session->initiator).value("private_call", Json::object());
      if (!policy.value("allow", false) || !policy.value("first_to_answer", false))
        throw std::runtime_error("first-to-answer authorisation withdrawn");
      if (session->private_request.target.empty()) return; // still ringing every invitee
    }
    auto policy = user_profile(session->initiator).value("private_call", Json::object());
    if (session->list_exempt && policy.is_object()) policy["any_target"] = true;
    const auto decision = authorize_private_call(policy, session->private_request, svc_);
    if (!decision) throw std::runtime_error(decision.warning);
    const auto callee_decision =
        authorize_private_callee(callee_private_policy(session->private_request.target), session->initiator, svc_);
    if (!callee_decision) throw std::runtime_error(callee_decision.warning);
    for (const auto &id : session->members) {
      const auto *participant = by_id(id);
      if (!participant || participant->expires <= std::time(nullptr))
        throw std::runtime_error("participant authorization expired");
    }
  } catch (const std::exception &error) {
    event("private_call_revoked", {{"reason", error.what()}, {"session_uri", session->uri}});
    for (const auto &leg : session_legs(*session)) {
      leg->active = false;
      sip_.bye(leg->dialog);
    }
  }
}

} // namespace mcx
