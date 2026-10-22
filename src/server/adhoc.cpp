//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Ad hoc group calls and ad hoc group emergency alerts: setup, rejoin, participant list or criteria and their
// modification (members of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the session policy of an ad hoc group call: at least two participants, no floor protection, no
// required members. An MCPTT ad hoc group call is released when the initiator leaves unless configured otherwise
// (local policy of TS 24.379 clause 6.3.8.1 item 3); TS 24.281 clause 6.3.8.1 item 3 limits that to a pre-arranged
// MCVideo group call, so an MCVideo ad hoc group call goes on without its initiator.
Json McServer::adhoc_call_policy() const {
  auto policy = cfg_.at(svc_.name).value("adhoc_call", Json::object());
  policy["minimum_participants"] = 2;
  policy["protect_floor"] = false;
  if (svc_.service == Service::mcvideo)
    policy["end_when_initiator_leaves"] = false;
  else if (!policy.contains("end_when_initiator_leaves"))
    policy["end_when_initiator_leaves"] = true;
  policy.erase("required_members");
  return policy;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.2.2 step 10: a new ad hoc group identity, in the domain of the service URI.
std::string McServer::adhoc_group_identity() const {
  const auto service = cfg_.at(svc_.name).at("service_uri").get<std::string>();
  const auto at = service.find('@');
  return "sip:adhoc-" + random_id() + "@" +
         (at == std::string::npos ? std::string("localhost") : service.substr(at + 1));
}

//------------------------------------------------------------------------------
// Helper: the leg for an INVITE received from a client (originator or rejoining member); null (answered 488)
// when the INVITE has no SDP offer or the client's floor SSRC is the server's.
std::shared_ptr<McServer::Leg> McServer::incoming_leg(const SipMessage &message, const User &user,
                                                      const std::shared_ptr<Session> &session) {
  if (!message.remote_media) return nullptr;
  auto leg = make_leg(user.id, session);
  if (leg->local.floor_ssrc == message.remote_media->floor_ssrc) return nullptr;
  leg->dialog = message.dialog_id;
  leg->incoming_offer = true;
  leg->remote = *message.remote_media;
  leg->local.payload_type = message.remote_media->payload_type;
  leg->local.octet_aligned = message.remote_media->octet_aligned;
  leg->local.queueing = leg->local.queueing && message.remote_media->queueing;
  leg->local.floor_priority.reset(); // no group priority hierarchy for an ad hoc group
  return leg;
}

//------------------------------------------------------------------------------
// Helper: reject the INVITE of an ad hoc group call: set the status and the Warning, report the rejection and
// return the response.
SipResponse McServer::adhoc_rejected(SipResponse &response, const User &user, int status, const std::string &warning) {
  response.status_code = status;
  if (!warning.empty()) response.headers = {{"Warning", warning_value(warning)}};
  event("adhoc_call_rejected", {{"user_id", user.id}, {"status", status}, {"warning", warning}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.4.1.1: an invited member rejoins an ongoing ad hoc group call by its session identity.
SipResponse McServer::adhoc_rejoin(const SipMessage &message, const User &user, const McpttInfo &info,
                                   SipResponse &response, McpttInfo &answer) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return adhoc_rejected(response, user, status, warning);
  };
  std::shared_ptr<Session> session;
  for (const auto &[key, candidate] : sessions_)
    if (candidate->adhoc && candidate->uri == message.request_uri) session = candidate;
  if (!session || (!info.request_uri.empty() && info.request_uri != session->group)) return reject(404);

  // Invited members are implicitly affiliated to the ad hoc group (TS 24.379 clause 17.4.2.2 step 16).
  if (std::find(session->members.begin(), session->members.end(), user.id) == session->members.end())
    return reject(403, warn(Warning::adhoc_participation_not_allowed));
  if (has_leg(*session, user.id)) return reject(486);
  auto leg = incoming_leg(message, user, session);
  if (!leg) return reject(488);
  response.status_code = 200;
  response.local_media = leg->local;
  response.contact_uri = session->uri;
  response.focus = true;
  answer.calling_group = session->group;
  answer.calling_user = session->initiator;
  response.parts = service_parts(answer);
  add_leg(leg);
  event("adhoc_call_rejoined", {{"user_id", user.id}, {"group_id", session->group}, {"session_uri", session->uri}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.2.2 steps 7A and 7B: a call on the ad hoc group of an emergency alert needs that alert,
// and joins the ongoing session of the group when there is one (clause 17.4.7.1.1). Returns the rejection or
// the answer of the join, or nothing for a new session.
std::optional<SipResponse> McServer::adhoc_alert_group_join(const SipMessage &message, const User &user,
                                                            const McpttInfo &info, SipResponse &response,
                                                            McpttInfo &answer) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return adhoc_rejected(response, user, status, warning);
  };
  const auto alert = adhoc_alerts_.find(info.request_uri);
  if (alert == adhoc_alerts_.end()) return reject(403, warn(Warning::adhoc_participants_unknown));
  if (const auto ongoing = sessions_.find(info.request_uri); ongoing != sessions_.end()) {
    // TS 24.379 clause 17.4.2.2 step 7B: join the ongoing session of that ad hoc group (clause 17.4.7.1.1).
    const auto session = ongoing->second;
    if (std::find(session->members.begin(), session->members.end(), user.id) == session->members.end())
      return reject(403, warn(Warning::adhoc_participation_not_allowed));
    if (has_leg(*session, user.id)) return reject(486);
    auto leg = incoming_leg(message, user, session);
    if (!leg) return reject(488);
    response.status_code = 200;
    response.local_media = leg->local;
    response.contact_uri = session->uri;
    response.focus = true;
    answer.calling_group = session->group;
    answer.calling_user = session->initiator;
    response.parts = service_parts(answer);
    add_leg(leg);
    return response;
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.2.2 steps 7A and 12: the invitees of a new ad hoc group call: the recipients and the
// initiator of the emergency alert (step 12d), or the users of the application/resource-lists+xml body.
// Returns the rejection, or nothing.
std::optional<SipResponse> McServer::adhoc_listed_invitees(const SipMessage &message, const User &user,
                                                           const McpttInfo &info, bool alert_group,
                                                           SipResponse &response, std::vector<std::string> &invitees) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return adhoc_rejected(response, user, status, warning);
  };
  if (alert_group) {
    const auto &alert = adhoc_alerts_.at(info.request_uri);
    invitees.assign(alert.recipients.begin(), alert.recipients.end());
    if (alert.initiator != user.id) invitees.push_back(alert.initiator);
    std::erase(invitees, user.id);
  }
  for (const auto &part : message.parts)
    if (part.content_type == resource_lists_mime && !alert_group) {
      if (!invitees.empty()) return reject(403, warn(Warning::adhoc_participants_unknown));
      try {
        invitees = parse_resource_list_targets(part.body);
      } catch (const std::exception &) {
        return reject(403, warn(Warning::adhoc_participants_unknown));
      }
    }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.2.2 steps 3B to 3D: authorise an emergency or imminent peril ad hoc group call and
// its Resource-Priority, giving the priority of the call. Returns the rejection, or nothing.
std::optional<SipResponse> McServer::adhoc_priority(const SipMessage &message, const User &user, const McpttInfo &info,
                                                    const Json &adhoc_policy, SipResponse &response,
                                                    PriorityState &priority) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return adhoc_rejected(response, user, status, warning);
  };
  // TS 24.379 clause 17.4.2.2 steps 3B to 3D: priority authorisation and Resource-Priority.
  const auto flag = [&](const char *key) {
    return adhoc_policy.is_object() && adhoc_policy.contains(key) && adhoc_policy.at(key).is_boolean() &&
           adhoc_policy.at(key).get<bool>();
  };
  if ((info.adhoc_emergency == true && !flag("emergency")) || (info.imminent_peril == true && !flag("imminent"))) {
    McpttInfo current;
    if (info.adhoc_emergency)
      current.adhoc_emergency = false;
    else
      current.imminent_peril = false;
    response.content_type = svc_.info_mime;
    response.body = service_info_xml_(current);
    return reject(
        403, info.adhoc_emergency
                 ? warn(Warning::function_not_allowed, "user authorisation: emergency adhoc group call not authorized")
                 : warn(Warning::function_not_allowed,
                        "user authorisation: imminent peril adhoc group call not authorized"));
  }
  priority.emergency = info.adhoc_emergency == true;
  priority.imminent = info.imminent_peril == true;
  if (priority.emergency) priority.emergency_users.insert(user.id);
  if (priority.imminent) priority.imminent_users.insert(user.id);
  {
    const auto requested = std::string(get_header(message.headers, "Resource-Priority"));
    const auto values = service_resource_priority();
    if (!requested.empty() && ((requested == values.value("emergency", std::string{}) && !priority.emergency) ||
                               (requested == values.value("imminent", std::string{}) && !priority.imminent)))
      return reject(403, warn(Warning::function_not_allowed, "Resource-Priority not authorized by call state"));
    try {
      (void)priority_headers(cfg_.at(svc_.name), priority);
    } catch (const std::exception &) {
      return reject(403, "priority Resource-Priority values are not provisioned");
    }
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.2.2 steps 12b and 12c: the users invited to an ad hoc group call: the listed users with
// each functional alias replaced by the users that activated it (via_alias), or the users that meet the
// participant criteria, within the maximum number of participants. Returns the rejection, or nothing.
std::optional<SipResponse> McServer::adhoc_resolve_invitees(const User &user, const McpttInfo &info, bool has_criteria,
                                                            const Json &service_policy, SipResponse &response,
                                                            std::vector<std::string> &invitees,
                                                            std::map<std::string, std::string> &via_alias) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return adhoc_rejected(response, user, status, warning);
  };
  if (!has_criteria) {
    std::vector<std::string> expanded;
    for (const auto &entry : invitees) {
      if (!is_functional_alias(entry)) {
        if (std::find(expanded.begin(), expanded.end(), entry) == expanded.end()) expanded.push_back(entry);
        continue;
      }
      auto users = functional_alias_users(entry);
      std::erase(users, user.id);
      if (users.empty()) return reject(403, warn(Warning::called_party_unknown));
      for (const auto &id : users)
        if (std::find(expanded.begin(), expanded.end(), id) == expanded.end()) {
          expanded.push_back(id);
          via_alias[id] = entry;
        }
    }
    if (expanded.size() > service_policy.value("max_participants", 0u))
      return reject(403, warn(Warning::adhoc_too_many_participants));
    invitees = std::move(expanded);
  }
  if (has_criteria) {
    // TS 24.379 clause 17.4.2.2 step 12c: determine the users that meet the criteria.
    try {
      invitees = resolve_participant_criteria(info.participant_criteria, user.id);
    } catch (const std::exception &) {
      return reject(403, warn(Warning::adhoc_participants_unknown));
    }
    if (invitees.empty()) return reject(403, warn(Warning::adhoc_participants_unknown));
    if (invitees.size() > service_policy.value("max_participants", 0u))
      return reject(403, warn(Warning::adhoc_too_many_participants));
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.2.2 steps 10 to 16: the session of a new ad hoc group call with its group identity,
// priority, criteria, participants and media control.
std::shared_ptr<McServer::Session> McServer::make_adhoc_session(const User &user, const McpttInfo &info,
                                                                bool alert_group, bool has_criteria,
                                                                const PriorityState &priority,
                                                                const std::vector<std::string> &invitees,
                                                                const std::map<std::string, std::string> &via_alias) {
  auto session = std::make_shared<Session>();
  session->adhoc = true;
  session->priority = priority;
  session->criteria = alert_group ? std::string{} : info.participant_criteria;
  if (has_criteria) session->criteria_matches = {invitees.begin(), invitees.end()};
  session->participant_aliases = via_alias; // reused for the called alias per invitee
  session->broadcast = info.broadcast.value_or(false);
  if (!info.functional_alias.empty() && functional_alias_active(info.functional_alias, user.id))
    session->initiator_alias = info.functional_alias;
  // TNG2 (in-progress emergency group call timer) releases the ad hoc session (TS 24.379 clause 17.4.2.2 step 14A).
  if (priority.emergency)
    session->priority.emergency_deadline = monotonic_ms() + session_policy_timeout("emergency_timeout_ms", 300000u);
  // The ad hoc group of an emergency alert keeps its identity (TS 24.379 clause 17.4.2.2 step 10).
  session->group = alert_group ? info.request_uri : adhoc_group_identity();
  session->uri = session_service_ + ";mcptt-session=" + random_id();
  session->initiator = user.id;
  session->policy = adhoc_call_policy();
  session->created = session->last_media = session->normal_since = monotonic_ms();
  session->members = {user.id};
  session->members.insert(session->members.end(), invitees.begin(), invitees.end());
  session->arbitrator = make_media_control(session->members, floor_options());
  return session;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.2.1.1: invite each listed user of a new ad hoc group call, then complete the setup.
void McServer::schedule_adhoc_invitations(const std::shared_ptr<Session> &session,
                                          const std::vector<std::string> &invitees) {
  auto invite = [this, session, invitees] {
    session->invitation_deferred = false;
    for (const auto &id : invitees) {
      try {
        invite_adhoc_member(session, id);
      } catch (const std::exception &error) {
        event("adhoc_invite_failed", {{"reason", error.what()}, {"user_id", id}});
      }
    }
    complete_setup(session);
  };
  // TS 24.379 clause 11.1.6.4.3: an ambient listening call of the initiator or an invitee being released ends first,
  // with the BYE to its listening user, so that this user is free to be invited.
  if (const auto ambient = releasing_ambient(session->members)) {
    session->invitation_deferred = true;
    ambient->after_release.push_back(std::move(invite));
  } else
    schedule(std::move(invite));
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 17.3.2.1.1 and 17.4.2.2: combined participating and controlling function for an ad hoc
// group call initiated with a participant list, and for rejoining one by its session identity
// (clause 17.4.4.1.1).
SipResponse McServer::adhoc_invite(const SipMessage &message, const User &user, const McpttInfo &info) {
  SipResponse response;
  const auto reject = [&](int status, const std::string &warning = {}) {
    return adhoc_rejected(response, user, status, warning);
  };
  if (const auto existing = legs_.find(message.dialog_id); existing != legs_.end())
    return adhoc_modify(message, user, info, existing->second);
  if (info.client_id != user.client || (!info.calling_user.empty() && info.calling_user != user.id) ||
      !accepts_mcptt(message))
    return reject(403);

  // A broadcast ad hoc call reuses the broadcast floor and release rules, and
  // may be an emergency or imminent-peril call like a broadcast group call.
  // TS 24.379 clause 6.3.3.1.25: an ad hoc call signals emergency with <adhoc-emergency-ind>;
  // it never combines with imminent peril, and a setup request cannot cancel.
  if (info.emergency || info.alert || info.adhoc_alert || (info.adhoc_emergency && info.imminent_peril) ||
      info.adhoc_emergency == false || info.imminent_peril == false)
    return reject(403, warn(Warning::invalid_mime_combination));
  if (!message.remote_media) return reject(488);
  if (message.remote_media->protected_media)
    return reject(488, warn(Warning::function_not_allowed, "end-to-end security for adhoc group call not implemented"));

  try {
    validate_remote(user.id, *message.remote_media);
  } catch (const std::exception &error) {
    event("sdp_rejected", {{"reason", error.what()}});
    return reject(488);
  }
  McpttInfo answer;
  answer.session_type = "adhoc";
  answer.request_uri = user.id;
  if (message.request_uri.starts_with(session_service_ + ";mcptt-session="))
    return adhoc_rejoin(message, user, info, response, answer);
  if (message.request_uri != cfg_.at(svc_.name).at("service_uri").get<std::string>()) return reject(404);

  // TS 24.379 clause 17.4.2.2 steps 7A, 7B and 12d: a call on the ad hoc group of an emergency alert.
  const bool alert_group = info.adhoc_emergency_alert_group == true;
  if (alert_group)
    if (auto joined = adhoc_alert_group_join(message, user, info, response, answer)) return *joined;
  std::vector<std::string> invitees;
  if (auto refused = adhoc_listed_invitees(message, user, info, alert_group, response, invitees)) return *refused;
  const auto adhoc_policy = user_profile(user.id).value("adhoc_call", Json::object());
  PriorityState priority;
  if (auto refused = adhoc_priority(message, user, info, adhoc_policy, response, priority)) return *refused;
  const bool has_criteria = !info.participant_criteria.empty() && !alert_group;
  const auto service_policy = cfg_.at(svc_.name).value("adhoc_call", Json::object());
  const auto decision = authorize_adhoc_call(service_policy, adhoc_policy, user.id, invitees, has_criteria, svc_);
  if (!decision) return reject(decision.status, decision.warning);

  // TS 24.379 clause 17.4.2.2 step 12b: list entries that are functional aliases stand for the
  // users that activated them (145 when none has).
  std::map<std::string, std::string> via_alias;
  if (auto refused = adhoc_resolve_invitees(user, info, has_criteria, service_policy, response, invitees, via_alias))
    return *refused;

  auto session = make_adhoc_session(user, info, alert_group, has_criteria, priority, invitees, via_alias);
  auto leg = incoming_leg(message, user, session);
  if (!leg) return reject(488);
  leg->origin = true;
  response.status_code = 200;
  response.local_media = leg->local;
  response.contact_uri = session->uri;
  response.focus = true;
  answer.calling_group = session->group;
  answer.calling_user = user.id;
  if (priority.emergency) answer.adhoc_emergency = true;
  if (priority.imminent) answer.imminent_peril = true;
  answer.participant_criteria = session->criteria;
  if (session->broadcast) answer.broadcast = true;
  response.parts = service_parts(answer);
  response.headers = priority_headers(cfg_.at(svc_.name), priority);
  leg->answer = response;
  leg->awaiting_answer = true;

  // TS 24.379 clause 17.4.2.2: the controlling function answers the caller with the 200 (OK) that an invited member's
  // 200 (OK) or 183 (Session Progress) brings, and sends no other provisional response.
  response.status_code = 100;
  response.reason = "Trying";
  sessions_[session->group] = session;
  add_leg(leg);
  schedule_adhoc_invitations(session, invitees);
  event("adhoc_call_created",
        {{"user_id", user.id}, {"group_id", session->group}, {"session_uri", session->uri}, {"invitees", invitees}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.2.1.1: invite one listed user. Users without a live service
// authorization cannot be reached and are skipped.
void McServer::invite_adhoc_member(const std::shared_ptr<Session> &session, const std::string &id) {
  if (!current_session(session)) return;
  const auto *user = by_id(id);
  if (user && user->expires <= std::time(nullptr)) user = nullptr;
  if (!user || has_leg(*session, id)) return;

  // TS 24.379 clause 17.4.2.2.1 step 6 (the terminating participating function): an invitee whose user profile has no
  // <allow-adhoc-group-call-participation> is not invited (403, warning 188).
  if (!user_profile(id).value("adhoc_call", Json::object()).value("participation", false)) {
    event("adhoc_invitee_rejected", {{"user_id", id},
                                     {"group_id", session->group},
                                     {"status", 403},
                                     {"warning", warn(Warning::adhoc_participation_not_allowed)}});
    return;
  }
  release_listened_to(id, ambient_reason("for"));
  auto leg = make_leg(id, session);
  leg->local.floor_priority.reset();
  McpttInfo info;
  info.session_type = "adhoc";
  info.request_uri = id;
  info.calling_group = session->group;
  info.calling_user = session->initiator;

  // TS 24.379 clause 17.4.2.1.1 steps 4c, 4e, 6 and 7.
  info.participant_criteria = session->criteria;
  info.functional_alias = session->initiator_alias;
  if (session->participant_aliases.contains(id)) info.called_functional_alias = session->participant_aliases.at(id);
  if (session->broadcast) info.broadcast = true;
  if (session->priority.emergency)
    info.adhoc_emergency = true;
  else if (session->priority.imminent)
    info.imminent_peril = true;
  auto headers = priority_headers(cfg_.at(svc_.name), session->priority);
  headers.push_back({"Answer-Mode", session->policy.value("answer_mode", "Auto")});
  headers.push_back({"Contact", focus_contact(*session)});
  leg->dialog = sip_.invite(user->sip, leg->local, service_parts(info), {}, user_route(*user, headers));
  add_leg(leg);
  event("adhoc_call_invite", {{"user_id", id}, {"group_id", session->group}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.6.1: the users meeting the criteria, as the controlling function's local policy
// determines them: the members of, or the users affiliated to, the named groups; never the initiator.
std::vector<std::string> McServer::resolve_participant_criteria(const std::string &text, const std::string &initiator) {
  std::vector<std::string> ids;
  const auto add = [&](const std::string &id) {
    if (id != initiator && std::find(ids.begin(), ids.end(), id) == ids.end()) ids.push_back(id);
  };
  for (const auto &criterion : parse_participant_criteria(text)) {
    if (criterion.kind == "member") {
      for (const auto &id : group_profile(criterion.group).at("members").get<std::vector<std::string>>()) add(id);
    } else {
      for (const auto &[sip, user] : users_)
        if (affiliated(user.id, criterion.group)) add(user.id);
    }
  }
  return ids;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 17.4.5.1.1 and 17.4.6.1: add a participant to the ad hoc group session and invite it.
void McServer::add_adhoc_participant(const std::shared_ptr<Session> &session, const std::string &id) {
  if (std::find(session->members.begin(), session->members.end(), id) == session->members.end()) {
    session->members.push_back(id);
    notices(*session, session->arbitrator->add(id));
  }
  invite_adhoc_member(session, id);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.3.1.2.1: the controlling function removes a participant from the call.
void McServer::remove_adhoc_participant(const std::shared_ptr<Session> &session, const std::string &id) {
  if (id == session->initiator) return;
  std::erase(session->members, id);
  notices(*session, session->arbitrator->remove(id, monotonic_ms()));
  for (const auto &leg : session_legs(*session))
    if (leg->user == id) {
      leg->active = false;
      sip_.bye(leg->dialog);
    }
  event("adhoc_participant_removed", {{"user_id", id}, {"group_id", session->group}});
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 17.4.6.1 and 17.4.5.2.1 steps 4 and 5: invite users newly meeting the criteria, unless removed
// by a modification or already in the group (one who left stays in it, clause 17.2.4); remove those that no longer
// do, unless invited by a modification (clause 17.2.6).
void McServer::apply_participant_criteria(const std::shared_ptr<Session> &session) {
  const auto resolved = resolve_participant_criteria(session->criteria, session->initiator);
  const std::set<std::string> now(resolved.begin(), resolved.end());
  const auto limit = cfg_.at(svc_.name).value("adhoc_call", Json::object()).value("max_participants", 0u);
  const auto member = [&](const std::string &id) {
    return std::find(session->members.begin(), session->members.end(), id) != session->members.end();
  };
  for (const auto &id : resolved)
    if (!session->criteria_matches.contains(id) && !session->manual_removals.contains(id) && !member(id) &&
        session->members.size() - 1 < limit)
      add_adhoc_participant(session, id);
  for (const auto &id : std::vector<std::string>(session->members.begin(), session->members.end()))
    if (id != session->initiator && !now.contains(id) && !session->manual_invites.contains(id))
      remove_adhoc_participant(session, id);
  session->criteria_matches = now;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.5.1.1: modify the participant list or criteria in the established call.
SipResponse McServer::adhoc_modify(const SipMessage &message, const User &user, const McpttInfo &info,
                                   const std::shared_ptr<Leg> &leg) {
  SipResponse response;
  const auto session = leg->session;
  const auto reject = [&](int status, const std::string &warning = {}) {
    response.status_code = status;
    if (!warning.empty()) response.headers = {{"Warning", warning_value(warning)}};
    event("adhoc_modify_rejected", {{"user_id", user.id}, {"status", status}, {"warning", warning}});
    return response;
  };
  if (!session->adhoc || leg->user != user.id || !leg->active || !session->established)
    return reject(488, warn(Warning::function_not_allowed, "adhoc group call re-INVITE"));
  if (!leg->remote || !message.remote_media) return reject(488);
  const auto &old = *leg->remote;
  if (old.address != message.remote_media->address || old.audio_port != message.remote_media->audio_port ||
      old.floor_port != message.remote_media->floor_port || old.floor_ssrc != message.remote_media->floor_ssrc ||
      old.payload_type != message.remote_media->payload_type)
    return reject(488);
  const auto policy = user_profile(user.id).value("adhoc_call", Json::object());
  if (!policy.is_object() || !policy.value("modify", false))
    return reject(403, warn(Warning::adhoc_modify_not_authorised));

  std::vector<std::string> entries;
  for (const auto &part : message.parts)
    if (part.content_type == resource_lists_mime) {
      try {
        entries = parse_resource_list_targets(part.body);
      } catch (const std::exception &) {
        return reject(403, warn(Warning::adhoc_participants_unknown));
      }
    }
  // TS 24.379 clause 17.4.5.1.1 step 4: the list (a) and the criteria (b) are handled independently. A client sends
  // the session's information as established (clause 17.2.6.1.1 step 1), so the criteria it already has come with a
  // list change and are no change; a request with neither is refused.
  bool criteria = !info.participant_criteria.empty();
  if (criteria && !entries.empty() && info.participant_criteria == session->criteria) criteria = false;
  if ((entries.empty() && !criteria) || (criteria && session->criteria.empty()))
    return reject(403, warn(Warning::adhoc_participants_unknown));

  if (criteria) {
    try {
      (void)parse_participant_criteria(info.participant_criteria);
    } catch (const std::exception &) {
      return reject(403, warn(Warning::adhoc_participants_unknown));
    }
  }

  const auto limit = cfg_.at(svc_.name).value("adhoc_call", Json::object()).value("max_participants", 0u);
  if (!entries.empty()) {
    ParticipantChanges changes;
    try {
      changes = split_participant_changes(entries);
    } catch (const std::exception &) {
      return reject(403, warn(Warning::adhoc_participants_unknown));
    }
    // TS 24.379 clause 17.4.5.1.1 step 3a: a functional alias stands for the users that activated it, invited (each
    // told the called alias) or removed; 403 with warning 145 only when no user at all is left to invite or remove.
    bool aliases = false;
    const auto resolve = [&](const std::vector<std::string> &listed, bool inviting) {
      std::vector<std::string> out;
      for (const auto &entry : listed) {
        auto users = is_functional_alias(entry) ? functional_alias_users(entry) : std::vector<std::string>{entry};
        if (is_functional_alias(entry)) {
          aliases = true;
          std::erase(users, user.id);
        }
        for (const auto &id : users)
          if (std::find(out.begin(), out.end(), id) == out.end()) {
            out.push_back(id);
            if (inviting && is_functional_alias(entry)) session->participant_aliases[id] = entry;
          }
      }
      return out;
    };
    changes.invite = resolve(changes.invite, true);
    changes.remove = resolve(changes.remove, false);
    if (aliases && changes.invite.empty() && changes.remove.empty())
      return reject(403, warn(Warning::called_party_unknown));
    std::size_t count = session->members.size() - 1;
    for (const auto &id : changes.invite)
      if (std::find(session->members.begin(), session->members.end(), id) == session->members.end()) ++count;
    for (const auto &id : changes.remove)
      if (std::find(session->members.begin(), session->members.end(), id) != session->members.end()) --count;
    if (count > limit) return reject(403, warn(Warning::adhoc_too_many_participants));
    for (const auto &id : changes.remove) {
      remove_adhoc_participant(session, id);
      session->manual_invites.erase(id);
      session->manual_removals.insert(id);
    }
    for (const auto &id : changes.invite)
      if (id != session->initiator) {
        add_adhoc_participant(session, id);
        session->manual_removals.erase(id);
        session->manual_invites.insert(id);
      }
  }
  if (criteria) {
    session->criteria = info.participant_criteria;
    apply_participant_criteria(session);
  }
  response.status_code = 200;
  response.local_media = leg->local;
  McpttInfo current;
  current.session_type = "adhoc";
  current.request_uri = user.id;
  current.calling_group = session->group;
  current.calling_user = session->initiator;
  current.participant_criteria = session->criteria;
  response.parts = service_parts(current);
  event("adhoc_participants_modified",
        {{"user_id", user.id}, {"group_id", session->group}, {"members", session->members}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 12.1A.3.3 steps 1 and 2: the SIP MESSAGE to one user with the ad hoc group emergency alert
// (<adhoc-alert-ind> "true") or its withdrawal ("false").
void McServer::send_adhoc_alert(const AdhocAlert &alert, const std::string &group, const std::string &target,
                                bool active) {
  auto *user = by_id(target);
  if (!user || user->expires <= std::time(nullptr)) return;
  McpttInfo info;
  info.request_uri = target;
  info.calling_user = alert.initiator;
  info.calling_group = group;
  info.adhoc_alert = active;
  info.participant_criteria = alert.criteria;
  // TS 24.379 clause 6.3.3.1.23 steps 3 and 4: the <mc-org> of the alert's originator (the system's organisation).
  if (active) info.organization = service_config_.value("organization", std::string{});
  auto parts = service_parts(info);
  if (active && alert.location) parts.push_back({svc_.location_mime, service_location_xml(*alert.location, svc_)});
  const auto [type, body] = message_body(parts, "mcx-" + random_id());
  sip_.request("MESSAGE", user->sip, type, body,
               user_route(*user, {{"P-Asserted-Service", svc_.icsi},
                                  {"Accept-Contact", feature_accept()},
                                  {"Accept-Contact", icsi_accept()}}));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 12.1A.3.3: notify users newly meeting the criteria and withdraw the alert
// from those that no longer do.
void McServer::update_adhoc_alert(const std::string &group) {
  auto &alert = adhoc_alerts_.at(group);
  std::set<std::string> now;
  try {
    const auto resolved = resolve_participant_criteria(alert.criteria, alert.initiator);
    now = {resolved.begin(), resolved.end()};
  } catch (const std::exception &error) {
    event("adhoc_alert_criteria_failed", {{"group_id", group}, {"reason", error.what()}});
    return;
  }
  for (const auto &id : now)
    if (!alert.recipients.contains(id)) send_adhoc_alert(alert, group, id, true);
  for (const auto &id : alert.recipients)
    if (!now.contains(id)) send_adhoc_alert(alert, group, id, false);
  alert.recipients = now;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 12.1A.3.1 and 12.1A.3.2: ad hoc group emergency alert and its cancellation.
SipResponse McServer::adhoc_alert_message(const SipMessage &message, const User &user, const McpttInfo &info) {
  SipResponse response;
  const auto reject = [&](int status, const std::string &warning) {
    response.status_code = status;
    if (!warning.empty()) response.headers = {{"Warning", warning_value(warning)}};
    McpttInfo current;
    current.adhoc_alert = !*info.adhoc_alert;
    response.content_type = svc_.info_mime;
    response.body = service_info_xml_(current);
    event("adhoc_alert_rejected", {{"user_id", user.id}, {"status", status}, {"warning", warning}});
    return response;
  };
  if (info.client_id != user.client || !accepts_mcptt(message) ||
      message.request_uri != cfg_.at(svc_.name).at("service_uri").get<std::string>())
    return reject(403, "");
  const auto policy = user_profile(user.id).value("adhoc_call", Json::object());
  if (*info.adhoc_alert) {
    if (!policy.is_object() || !policy.value("alert", false))
      return reject(
          403, warn(Warning::function_not_allowed, "user authorisation: adhoc group emergency alert not authorized"));
    if (info.participant_criteria.empty()) return reject(403, warn(Warning::adhoc_participants_unknown));
    try {
      (void)parse_participant_criteria(info.participant_criteria);
    } catch (const std::exception &) {
      return reject(403, warn(Warning::adhoc_participants_unknown));
    }
    const auto group = adhoc_group_identity();
    AdhocAlert alert{user.id, user.client, info.participant_criteria, {}, message_location(message), monotonic_ms()};
    adhoc_alerts_[group] = alert;
    update_adhoc_alert(group);
    if (adhoc_alerts_.at(group).recipients.empty()) {
      adhoc_alerts_.erase(group);
      return reject(403, warn(Warning::adhoc_participants_unknown));
    }
    response.status_code = 200;
    McpttInfo answer;
    answer.calling_group = group;
    answer.participant_criteria = info.participant_criteria;
    response.content_type = svc_.info_mime;
    response.body = service_info_xml_(answer);
    // TS 24.379 clause 12.1A.3.1 step 3e: confirm receipt to the originator.
    schedule([this, group, id = user.id, client = user.client] {
      if (adhoc_alerts_.contains(group))
        send_adhoc_alert_receipt(group, id, client, true, adhoc_alerts_.at(group).criteria);
    });
    event("adhoc_alert_started",
          {{"user_id", user.id}, {"group_id", group}, {"recipients", adhoc_alerts_.at(group).recipients}});
    return response;
  }
  if (!policy.is_object() || !policy.value("alert_cancel", false))
    return reject(403, warn(Warning::function_not_allowed,
                            "user authorisation: adhoc group emergency alert cancellation not authorized"));
  auto found = adhoc_alerts_.find(info.request_uri);
  if (found == adhoc_alerts_.end() || found->second.initiator != user.id) return reject(404, "");
  for (const auto &id : found->second.recipients) send_adhoc_alert(found->second, found->first, id, false);
  event("adhoc_alert_cancelled", {{"user_id", user.id}, {"group_id", found->first}});

  // TS 24.379 clause 12.1A.3.2 step 4 g) (TS 24.281 clause 12.1A.3.2 step 4 g)): after the 200 (OK), confirm
  // receipt of the cancellation to the originator, with the client ID of the request.
  schedule([this, group = found->first, id = user.id, client = info.client_id] {
    send_adhoc_alert_receipt(group, id, client, false, {});
  });
  adhoc_alerts_.erase(found);
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 12.1A.3.1 step 3e and 12.1A.3.2 step 4 g) with clause 6.3.3.1.20: the SIP MESSAGE to the
// originator confirming receipt of the ad hoc group emergency alert (<adhoc-alert-ind> "true") or of its
// cancellation ("false"), with <adhoc-alert-ind-rcvd> "true" and the ad hoc group identity.
void McServer::send_adhoc_alert_receipt(const std::string &group, const std::string &id, const std::string &client,
                                        bool active, const std::string &criteria) {
  auto *target = by_id(id);
  if (!target) return;
  McpttInfo receipt;
  receipt.request_uri = id;
  receipt.client_id = client;
  receipt.calling_group = group;
  receipt.adhoc_alert = active;
  receipt.adhoc_alert_received = true;
  receipt.participant_criteria = criteria;
  sip_.request("MESSAGE", target->sip, svc_.info_mime, service_info_xml_(receipt),
               user_route(*target, {{"P-Asserted-Service", svc_.icsi}, {"Accept-Contact", feature_accept()}}));
}

//------------------------------------------------------------------------------
// Helper (local policy): withdrawal of the initiator's ad hoc authority or of the service releases the call.
void McServer::revalidate_adhoc(const std::shared_ptr<Session> &session) {
  try {
    // Only the initiator's authority and the service are rechecked; the
    // participant set may change by modification or criteria.
    std::vector<std::string> none;
    const auto decision = authorize_adhoc_call(cfg_.at(svc_.name).value("adhoc_call", Json::object()),
                                               user_profile(session->initiator).value("adhoc_call", Json::object()),
                                               session->initiator, none, true, svc_);
    if (!decision) throw std::runtime_error(decision.warning);
    if (!session->criteria.empty()) apply_participant_criteria(session);
  } catch (const std::exception &error) {
    event("adhoc_call_revoked", {{"reason", error.what()}, {"session_uri", session->uri}});
    for (const auto &leg : session_legs(*session)) {
      leg->active = false;
      sip_.bye(leg->dialog);
    }
  }
}

//------------------------------------------------------------------------------
// Helper: a timeout of the configured ad hoc call policy (configuration "adhoc_call"), or the fallback.
unsigned McServer::session_policy_timeout(const char *key, unsigned fallback) const {
  return cfg_.at(svc_.name).value("adhoc_call", Json::object()).value(key, fallback);
}

} // namespace mcx
