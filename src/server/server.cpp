// The shared core of the MCPTT and MCVideo servers: construction, the run loop, the SIP dialog state callback, the
// periodic tick with its call supervision, and the status (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19),
// TS 23.379 V19.11.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 29.283.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// The SIP dialog state callback: a confirmed leg becomes active and is told the floor (or transmission) state of
// its call; a disconnected leg leaves its call, which is released per TS 24.379 clause 6.3.8.1 (or clauses
// 11.1.6.4.3 and 11.1.6.4.4 for an ambient listening call).
void McServer::state(std::string_view dialog, SipCallState state, int code) {
  if (const auto relay = relays_.find(std::string(dialog)); relay != relays_.end()) {
    // A rejected INVITE disconnects before its final response is dispatched:
    // end the relay one round later, so that the response is relayed first.
    if (state == SipCallState::disconnected)
      schedule([this, relay = relay->second] { schedule([this, relay] { end_relay(relay); }); });
    return;
  }
  auto it = legs_.find(std::string(dialog));
  if (it == legs_.end()) return;
  auto leg = it->second;
  auto session = leg->session;
  if (state == SipCallState::confirmed)
    leg_confirmed(leg, session);
  else if (state == SipCallState::disconnected)
    leg_disconnected(leg, session, code);
}

//------------------------------------------------------------------------------
// The SIP dialog state callback, a confirmed leg: it becomes active (a first-to-answer invitee answering after
// another won is released; an answer stops TNP1, TS 24.379 clause 6.3.2.5), the call counts as established, and the
// leg is told the floor (or transmission) state of its call.
void McServer::leg_confirmed(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session) {
  if (session->first_to_answer && !leg->origin) {
    if (!session->private_request.target.empty() && session->private_request.target != leg->user) {
      leg->active = true; // answered after another invitee won: release it
      release_not_selected(*leg);
      return;
    }
    if (session->private_request.target.empty()) {
      leg->active = true;
      select_first_answer(session, leg);
    }
  }
  leg->active = true;
  if (!leg->origin) session->no_answer_deadline = 0; // TS 24.379 clause 6.3.2.5: answered before TNP1 expired
  schedule([this, id = leg->dialog] { send_priority_correction(id); });
  event("participant_active", {{"user_id", leg->user}, {"session_uri", session->uri}});
  if (session->chat) {
    // A chat session counts as established once two members have joined.
    std::size_t active = 0;
    for (const auto &other : session_legs(*session)) active += other->active;
    if (active >= 2) session->established = true;
  } else if (leg->origin)
    session->established = true;
  schedule([this, session] {
    complete_setup(session);
    notify_conference(session);
  });
  schedule([this, leg, session] { initial_floor_state(leg, session); });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4 (TS 24.581 clause 6.3.4): a newly active leg is told the floor (or transmission) state of
// its call: Floor Taken or Floor Idle, the originator's implicit Transmission Request (TS 24.281 clause 6.4), or
// the ambient listening floor. Runs as a scheduled task after the leg was confirmed.
void McServer::initial_floor_state(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session) {
  if (!current_session(session) || !leg->active) return;
  if (!session->ambient.empty()) {
    ambient_floor(session, *leg);
    return;
  }
  if (initial_service_state(leg, session)) return;
  if (session->no_media_control) return; // nothing to arbitrate (TS 24.281 clause 10.2.3)
  const auto owner = session->arbitrator->owner();
  if (owner) {
    send_notice(*leg, FloorNotice{FloorNoticeKind::Taken, leg->user, *owner, 0});
  } else {
    send_notice(*leg, FloorNotice{FloorNoticeKind::Idle, leg->user, "", 0});
    session->arbitrator->start_idle(monotonic_ms());
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.8.1: a disconnected leg becomes inactive and leaves its call in a scheduled task.
void McServer::leg_disconnected(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session, int code) {
  leg->active = false;
  schedule([this, leg, session] { release_departed_leg(leg, session); });
  event("participant_left", {{"user_id", leg->user}, {"status", code}, {"session_uri", session->uri}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.8.1 (or clauses 11.1.6.4.3 and 11.1.6.4.4 for an ambient listening call): remove the
// departed leg, release its floor, and release the call when the initiator left or one participant is left.
void McServer::release_departed_leg(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session) {
  if (!current_session(session) || !legs_.contains(leg->dialog)) return;
  // Remove the departed leg before dispatching floor notices to survivors.
  legs_.erase(leg->dialog);
  session->dialogs.erase(leg->dialog);
  leg->audio.reset();
  leg->floor.reset();
  notices(*session, session->arbitrator->release(leg->user, monotonic_ms()));
  if (!session->ambient.empty()) {
    // TS 24.379 clause 11.1.6.4.3: the listening user's BYE follows the listened-to user's
    // release; TS 24.379 clause 11.1.6.4.4: a participant's BYE releases the other one.
    if (session->ambient_released && leg->user == session->listened_to) {
      release_ambient_listening(*session);
      for (auto &next : std::exchange(session->after_release, {})) schedule(std::move(next));
    } else
      for (const auto &other : session_legs(*session))
        if (!other->awaiting_answer) sip_.bye(other->dialog);
    if (session->dialogs.empty()) {
      sessions_.erase(session->group);
      event("ambient_call_released", {{"session_uri", session->uri}, {"reason", session->ambient_release_reason}});
    } else
      complete_setup(session);
    return;
  }
  if (!session->chat && leg->origin &&
      (!session->established || session->broadcast || session->policy.value("end_when_initiator_leaves", true)))
    for (const auto &other : session_legs(*session)) sip_.bye(other->dialog);
  notify_conference(session, session->dialogs.empty());
  if (session->dialogs.empty()) {
    sessions_.erase(session->group);
  } else if (session->established && session->dialogs.size() == 1 && !session->adhoc) {
    // TS 24.379 clause 6.3.8.1 item 2 (one participant left) does not list ad hoc group calls.
    sip_.bye(*session->dialogs.begin());
  } else
    complete_setup(session);
}

//------------------------------------------------------------------------------
// The periodic tick: the location, document subscription, temporary group, SEAL ticks; floor key,
// emergency (in-progress emergency state timer), ad hoc alert and preemption supervision; the release of calls per
// TS 24.379 clauses 6.3.8.1 and 6.3.8.2 (T4, TNG3, private call timer, minimum affiliated members) and TS 23.379
// clause 10.6.2.5.2 step 3 (broadcast); policy revalidation; expiry of subscriptions and registrations; and the
// status file.
void McServer::tick() {
  auto now = monotonic_ms();
  location_.tick(now);
  docsub_tick(now);
  temporary_tick(now);
  seal_tick();
  for (auto &[dialog, leg] : legs_)
    if (leg->active && !floor_key_ready(*leg)) stop_unkeyed_leg(*leg, "floor key expired or unavailable");
  for (const auto &[dialog, sub] : key_subscriptions_)
    if (!sub.pending && now >= sub.next_poll) schedule([this, dialog] { notify_key(dialog); });
  expire_emergency_states(now);
  for (const auto &[dialog, leg] : legs_) send_priority_notification(leg);
  supervise_adhoc_alerts(now);
  resume_preempted_fanouts(now);
  for (const auto &[group, session] : sessions_)
    if (session->private_call && session->no_answer_deadline && now >= session->no_answer_deadline)
      schedule([this, session] {
        if (current_session(session) && session->no_answer_deadline) expire_no_answer(session);
      });
  for (const auto &[group, session] : sessions_) supervise_session(group, session, now);
  retry_floor_messages(now);
  expire_users(now);
  if (now - last_save_ > 200) save_status(now);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.1.16 steps 1 and 2: on expiry of TNG2 (in-progress emergency group call timer) the group
// leaves the in-progress emergency state, and its members are told.
void McServer::expire_emergency_states(std::uint64_t now) {
  for (auto &[group, priority] : priorities_) {
    if (priority.emergency && priority.emergency_deadline && now >= priority.emergency_deadline) {
      McpttInfo change;
      change.emergency = false;
      const auto profile = priority.profile;
      apply_priority(group, "", change, profile);
      schedule([this, group, change] { priority_fanout(group, "", change); });
      event("emergency_timer_expired", {{"group_id", group}});
    }
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 12.1A: an ad hoc group emergency alert ends when its initiator is no longer authorised;
// otherwise its recipients are revised every 2 s.
void McServer::supervise_adhoc_alerts(std::uint64_t now) {
  for (auto it = adhoc_alerts_.begin(); it != adhoc_alerts_.end();) {
    const auto *initiator = by_id(it->second.initiator);
    if (!initiator || initiator->expires <= std::time(nullptr)) {
      for (const auto &id : it->second.recipients) send_adhoc_alert(it->second, it->first, id, false);
      it = adhoc_alerts_.erase(it);
      continue;
    }
    if (now - it->second.last_check >= 2000) {
      it->second.last_check = now;
      update_adhoc_alert(it->first);
    }
    ++it;
  }
}

//------------------------------------------------------------------------------
// A group call waiting for members preempted from their other calls fans out once their dialogs closed, or after
// 5 s.
void McServer::resume_preempted_fanouts(std::uint64_t now) {
  for (const auto &[group, session] : sessions_) {
    if (session->awaiting_users.empty() || session->awaiting_fanout) continue;
    // Wait until each preempted user's dialog has actually closed (not only been ended).
    std::set<std::string> busy;
    for (const auto &[dialog, leg] : legs_)
      if (leg->session != session) busy.insert(leg->user);
    bool waiting = false;
    for (const auto &id : session->awaiting_users) waiting = waiting || busy.contains(id);
    // Proceed after 5 s even if a preempted participant has not confirmed release.
    if (!waiting || now - session->awaiting_since > 5000) {
      session->awaiting_fanout = true;
      schedule([this, session] {
        session->awaiting_users.clear(); // setup supervision resumes with the fan-out
        fanout(session, session->initiator);
      });
    }
  }
}

//------------------------------------------------------------------------------
// The supervision of one call in the tick: its setup, the release of an ambient listening call at the private call
// timer (TS 24.379 clause 11.1.6.4.1 step 9), the timers of TS 24.379 clauses 6.3.8.1 and 6.3.8.2, the floor
// timers, the end of a broadcast (TS 23.379 clause 10.6.2.5.2 step 3) and the policy revalidation every 2 s.
void McServer::supervise_session(const std::string &group, const std::shared_ptr<Session> &session, std::uint64_t now) {
  complete_setup(session);
  if (!session->ambient.empty()) {
    // TS 24.379 clause 11.1.6.4.1 step 9: the private call timer runs from the invitation. The
    // listened-to user transmits throughout, so there is no inactivity release.
    const auto duration = session->policy.value("maximum_duration_ms", 3600000u);
    if (duration && now >= session->created && now - session->created >= duration)
      release_ambient(session, "private-call-expiry");
  } else if (session->established || session->chat) {
    supervise_call_timers(group, session, now);
  }
  notices(*session, session->arbitrator->tick(now));
  service_session_tick(session, now);
  // TS 23.379 clause 10.6.2.5.2 step 3: the broadcast ends when the initiator's
  // transmission completes (release, revoke or media timeout).
  // After an override, the call ends when the overriding transmission does.
  const auto broadcast_owner = session->arbitrator->owner();
  if (session->broadcast && session->broadcast_transmitted && !session->broadcast_released &&
      (!broadcast_owner ||
       (*broadcast_owner != session->initiator && !session->broadcast_overriders.contains(*broadcast_owner)))) {
    session->broadcast_released = true;
    event("broadcast_transmission_complete", {{"group_id", group}, {"session_uri", session->uri}});
    for (const auto &leg : session_legs(*session)) sip_.bye(leg->dialog);
  }
  if (session->private_call && now - session->last_policy_check >= 2000) {
    session->last_policy_check = now;
    revalidate_private(session);
  } else if (session->adhoc && now - session->last_policy_check >= 2000) {
    session->last_policy_check = now;
    revalidate_adhoc(session);
  } else if (now - session->last_policy_check >= 2000) {
    session->last_policy_check = now;
    revalidate_group_call(group, session, now);
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.8.1 and 6.3.8.2: in an established (or chat) call, invite the members pending late entry,
// and release the call at T4 (Inactivity), at the private call timer or TNG3 (maximum duration), at TNG2 for an
// emergency ad hoc call (clause 17.4.2.2 step 13), or when too few members are affiliated.
void McServer::supervise_call_timers(const std::string &group, const std::shared_ptr<Session> &session,
                                     std::uint64_t now) {
  // A lone chat joiner is also supervised by the inactivity timer (T4).
  invite_late_entries(session);
  const auto inactivity = session->policy.value("inactivity_timeout_ms", 60000u);
  const auto duration = session->policy.value("maximum_duration_ms", 3600000u);
  // Priority expiry may reset normal_since later than this tick's snapshot.
  // For a private call, maximum_duration_ms is the TS 24.379 private call timer.
  // TS 24.379 clause 17.4.2.2 step 13: a priority ad hoc call runs without TNG3; TNG2 ends an
  // emergency ad hoc call.
  const auto &priority = call_priority(*session);
  const bool timed = !priority.emergency && !(session->adhoc && priority.imminent);
  const bool tng2 =
      session->adhoc && priority.emergency && priority.emergency_deadline && now >= priority.emergency_deadline;
  // TS 24.379 clause 11.1.4.1 NOTE: a private call without floor control is ended only by a
  // client; it has neither T4 (Inactivity) nor the private call timer.
  const bool supervised = !session->no_media_control;
  if ((supervised && inactivity && now >= session->last_media && now - session->last_media >= inactivity) ||
      (supervised && duration && timed && now >= session->normal_since && now - session->normal_since >= duration) ||
      tng2 ||
      (!session->private_call && !session->adhoc &&
       !sufficient_affiliation(group, session->members, session->policy, false)))
    for (const auto &leg : session_legs(*session)) sip_.bye(leg->dialog);
}

//------------------------------------------------------------------------------
// Late entry (TS 24.379 clause 9.2.2.2.3, new affiliations of a user): the members pending late entry are invited,
// unless they joined (they leave the list once their leg is active).
void McServer::invite_late_entries(const std::shared_ptr<Session> &session) {
  for (auto it = session->late_entry_pending.begin(); it != session->late_entry_pending.end();) {
    auto id = *it;
    if (has_leg(*session, id)) {
      bool active = false;
      for (const auto &leg : session_legs(*session))
        if (leg->user == id && leg->active) active = true;
      if (active)
        it = session->late_entry_pending.erase(it);
      else
        ++it;
      continue;
    }
    it = session->late_entry_pending.erase(it);
    try {
      invite_member(session, id);
    } catch (const std::exception &error) {
      event("late_entry_failed", {{"reason", error.what()}, {"session_uri", session->uri}});
    }
  }
}

//------------------------------------------------------------------------------
// The policy revalidation of a group call every 2 s: expired conference subscriptions are notified, the group
// document's protection policy must not change, the members follow the group document, and a participant no longer
// a member (or every participant, when the document is unavailable) is disconnected.
void McServer::revalidate_group_call(const std::string &group, const std::shared_ptr<Session> &session,
                                     std::uint64_t now) {
  bool expired_conference = false;
  for (const auto &[id, sub] : session->subscriptions)
    if (sub.expires <= std::time(nullptr)) expired_conference = true;
  if (expired_conference) notify_conference(session);
  std::vector<std::string> revoked;
  try {
    auto policy = group_profile(group);
    if (policy.value("protect_floor", false) != session->policy.value("protect_floor", false))
      throw std::runtime_error("established floor protection policy changed");
    for (const auto &leg : session_legs(*session))
      if (leg->local.protected_media != policy.value("protect_media", false))
        throw std::runtime_error("established media protection policy changed");
    session->policy = policy.value("call_policy", cfg_.at(svc_.name).value("call_policy", Json::object()));
    session->policy["protect_floor"] = policy.value("protect_floor", false);
    if (session->hierarchy.empty()) {
      const auto members = policy.at("members").get<std::vector<std::string>>();
      for (const auto &id : session->members)
        if (std::find(members.begin(), members.end(), id) == members.end())
          notices(*session, session->arbitrator->remove(id, now));
      for (const auto &id : members) notices(*session, session->arbitrator->add(id));
      session->members = members;
      for (const auto &leg : session_legs(*session))
        if (!member(policy, leg->user)) revoked.push_back(leg->user);
    } else if (!member(policy, session->initiator)) {
      // A hierarchy call keeps its resolved receivers; losing the initiator ends it.
      for (const auto &leg : session_legs(*session)) revoked.push_back(leg->user);
    }
  } catch (const std::exception &error) {
    event("group_policy_unavailable", {{"reason", error.what()}, {"session_uri", session->uri}});
    for (const auto &leg : session_legs(*session)) revoked.push_back(leg->user);
  }
  for (const auto &id : revoked) {
    if (auto *user = by_id(id)) user->groups.erase(group);
    disconnect_user(id, session);
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.13 (Floor Ack message): the floor control messages awaiting a Floor Ack are retransmitted;
// the ones that failed are reported.
void McServer::retry_floor_messages(std::uint64_t now) {
  for (auto &[dialog, leg] : legs_) {
    if (!leg->active || !leg->remote || !leg->floor_retries) continue;
    for (const auto &packet : leg->floor_retries->tick(now)) transmit_floor(*leg, packet);
    for (const auto type : leg->floor_retries->take_failed())
      event("floor_ack_timeout",
            {{"user_id", leg->user}, {"session_uri", leg->session->uri}, {"type", static_cast<unsigned>(type)}});
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.1.3 and 7.3.3: an expired affiliation status subscription removes the user's affiliations,
// an expired service authorisation removes the user (its functional aliases, calls and relays); the users served
// here are registered again with their controllers at the registration refresh interval.
void McServer::expire_users(std::uint64_t now) {
  for (auto &[sip, user] : users_)
    if (!user.subscription.empty() && user.subscription_expires <= std::time(nullptr)) {
      user.subscription.clear();
      user.groups.clear();
      disconnect_user(user.id);
      register_with_controllers(user);
    }
  std::vector<std::string> expired;
  for (auto &[sip, user] : users_)
    if (user.expires && user.expires <= std::time(nullptr)) {
      user.expires = 0;
      user.groups.clear();
      expired.push_back(user.id);
    }
  for (auto &id : expired) {
    deactivate_functional_aliases(id);
    disconnect_user(id);
    end_user_relays(id);
    if (const auto *user = by_id(id)) register_with_controllers(*user, true);
  }
  peer_registration_.refresh(now);
}

//------------------------------------------------------------------------------
// The status file (at most every 200 ms): authorised and affiliated users, functional aliases, location, document
// subscriptions, XML protection counters, SEAL, relays, ad hoc alerts, regroups, group priorities and
// calls.
void McServer::save_status(std::uint64_t now) {
  status_["ready"] = true;
  status_["authorized_users"] = 0;
  status_["affiliated_users"] = 0;
  // The groups each authorised user is affiliated with here, local or served
  // by a peer, so that a test can wait for an affiliation to reach this server.
  status_["affiliations"] = Json::object();
  for (auto &[sip, user] : users_)
    if (user.expires > std::time(nullptr)) {
      status_["authorized_users"] = status_.value("authorized_users", 0u) + 1;
      if (!user.groups.empty()) {
        status_["affiliated_users"] = status_.value("affiliated_users", 0u) + 1;
        status_["affiliations"][user.id] = user.groups;
      }
    }
  status_["functional_aliases"] = functional_aliases_.activations();
  status_["location"] = location_.status();
  status_["group_document_subscriptions"] = docsub_status();
  status_["configuration_subscriptions"] = {{"counters", configsub_counters_.json()},
                                            {"active", config_subscriptions_.size()}};
  status_["xml_protection"] = {
      {"enabled", xml_protection()}, {"encrypted", xml_encrypted_},         {"decrypted", xml_decrypted_},
      {"refused", xml_refused_},     {"integrity", integrity_protection()}, {"signed", xml_signed_},
      {"verified", xml_verified_}};
  status_["server_role"] = role_;
  status_["seal"] = seal_status_;
  status_["relayed_calls"] = relays_.size() / 2;
  // The media port pairs in use and available.
  status_["media_ports"] = {{"total", media_slots}, {"used", legs_.size() + relays_.size()}};
  status_["adhoc_alerts"] = Json::object();
  for (const auto &[group, alert] : adhoc_alerts_)
    status_["adhoc_alerts"][group] = {{"initiator", alert.initiator}, {"recipients", alert.recipients}};
  status_["regroups"] = Json::object();
  for (const auto &[id, state] : regroups_)
    status_["regroups"][id] = {{"preconfigured", state.preconfigured},
                               {"groups", state.groups},
                               {"users", state.users},
                               {"affiliated", state.affiliated},
                               {"controller", state.controller},
                               {"controlling", state.controlling},
                               {"creator", state.creator},
                               {"temporary", state.temporary}};
  status_["regrouped_groups"] = regrouped_;
  status_["group_priority"] = Json::object();
  for (const auto &[group, priority] : priorities_)
    status_["group_priority"][group] = {{"priority", priority_name(priority)},
                                        {"alerts", priority.alerts},
                                        {"emergency_users", priority.emergency_users}};
  save_sessions_status();
  write_status(cfg_, status_);
  last_save_ = now;
}

//------------------------------------------------------------------------------
// The calls in the status file, and the oldest call's participants, group, session URI and floor owner.
void McServer::save_sessions_status() {
  status_["sessions"] = Json::array();
  const Session *first = nullptr;
  Json first_status;
  for (const auto &[group, session] : sessions_) {
    Json entry = session_status(group, session);
    status_["sessions"].push_back(entry);
    if (!first || session->created < first->created) {
      first = session.get();
      first_status = entry;
    }
  }
  status_["participants"] = first ? first_status["participants"] : Json::array();
  status_["group_id"] = first && !first->private_call ? first->group : "";
  status_["session_uri"] = first ? first->uri : "";
  status_["floor_owner"] = first ? first->arbitrator->owner().value_or("") : "";
}

//------------------------------------------------------------------------------
// One call in the status file: its type, initiator, floor owner, active participants, priority (TS 24.379 clause
// 6.3.3.1) and, for a private or ambient listening call, its parties.
Json McServer::session_status(const std::string &group, const std::shared_ptr<Session> &session) {
  const auto &priority = call_priority(*session);
  Json entry = {{"group_id", session->private_call ? "" : group},
                {"session_uri", session->uri},
                {"call_type", !session->ambient.empty() ? "ambient"
                              : session->private_call   ? "private"
                              : session->broadcast      ? "broadcast"
                              : session->chat           ? "chat"
                              : session->adhoc          ? "adhoc"
                                                        : "prearranged"},
                {"initiator", session->initiator},
                {"floor_owner", session->arbitrator->owner().value_or("")},
                {"participants", Json::array()},
                {"established", session->established},
                {"priority", priority_name(priority)},
                {"alerts", priority.alerts}};
  if (!session->hierarchy.empty()) {
    entry["hierarchy"] = session->hierarchy;
    entry["subordinate_groups"] = session->subordinate_groups;
  }
  if (session->private_call) {
    entry["calling_user"] = session->initiator;
    entry["called_user"] = session->private_request.target;
    entry["emergency_users"] = session->priority.emergency_users;
    entry["protected"] = session->protected_private;
    if (session->first_to_answer) {
      entry["first_to_answer"] = true;
      entry["invitees"] = session->invitees;
    }
    if (!session->ambient.empty()) {
      entry["ambient_listening_type"] = session->ambient;
      entry["listening"] = session->listening;
      entry["listened_to"] = session->listened_to;
      entry["release_reason"] = session->ambient_release_reason;
    }
  }
  for (const auto &leg : session_legs(*session))
    if (leg->active) entry["participants"].push_back(leg->user);
  return entry;
}

//------------------------------------------------------------------------------
// Construct the server from its program's service profile and its configuration: the HTTP, control, Diameter
// (TS 29.283, MCPTT-2) and SIP interfaces, the role, and the peer MCPTT servers with their SPKs (TS 33.180 clauses
// 5.5 and 11.1.3).
McServer::McServer(const ServiceProfile &service, Json cfg, bool disable_tls)
    : svc_(configured_service(service, cfg)), cfg_(std::move(cfg)), http_(cfg_.at("tls").at("ca_file")),
      control_(cfg_.at("control_fifo")),
      diameter_(cfg_.contains("diameter_config") ? std::make_unique<DiameterProfileClient>(cfg_.at("diameter_config"))
                                                 : nullptr),
      sip_(
          [&] {
            auto config = sip_config(cfg_, disable_tls);
            config.service = &svc_;
            config.asserts_service = true;
            return config;
          }(),
          {[this](const SipMessage &message) { return incoming(message); },
           [this](std::string_view dialog, SipCallState call_state, int code) { state(dialog, call_state, code); },
           [this](std::string_view dialog, const MediaDescription &media) { media_answered(dialog, media); },
           {},
           [](std::string_view reason) { event("sip_error", {{"reason", reason}}); },
           [this](std::string_view dialog) {
             const auto id = std::string(dialog);
             schedule([this, id] { send_priority_correction(id); });
           }}),
      core_address_(resolve_ipv4(cfg_.at("trusted_core"))) {
  session_service_ = cfg_.at(svc_.name).at("service_uri").get<std::string>();
  if (!disable_tls && session_service_.starts_with("sip:")) session_service_.insert(3, "s");
  const auto &mcptt = cfg_.at(svc_.name);
  role_ = mcptt.value("role", "both");
  if (role_ != "both" && role_ != "participating" && role_ != "controlling")
    throw std::runtime_error("mcptt.role must be both, participating or controlling");
  const auto servers = mcptt.value("servers", Json::object());
  for (const auto &[name, entry] : servers.items())
    peers_[name] = configured_peer(name, entry, disable_tls);
  controller_ = mcptt.value("controller", "");
  if (const auto owner = mcptt.value("functional_alias_controller", std::string{});
      !owner.empty() && !peers_.contains(owner))
    throw std::runtime_error("mcptt.functional_alias_controller is not a configured server");
  if (role_ == "participating" && controller_.empty())
    throw std::runtime_error("a participating server needs mcptt.controller");
  if (!controller_.empty() && !peers_.contains(controller_))
    throw std::runtime_error("mcptt.controller is not a configured server");
  const auto group_controllers = mcptt.value("group_controllers", Json::object());
  for (const auto &[group, name] : group_controllers.items())
    if (!peers_.contains(name.get<std::string>()))
      throw std::runtime_error("group controller " + name.get<std::string>() + " is not a configured server");
  status_ = {{"sip_transport", disable_tls ? "tcp" : "tls"},
             {"instance_id", random_id()},
             {"role", "server"},
             {"service", svc_.name},
             {"media_forwarded", 0},
             {"media_dropped", 0}};
}

//------------------------------------------------------------------------------
// The SDP answer of a leg this server offered: the answer must keep the media plane control, the floor SSRC, the
// media protection, the floor priority and the queueing of the offer; otherwise the dialog is ended.
void McServer::media_answered(std::string_view dialog, const MediaDescription &media) {
  auto it = legs_.find(std::string(dialog));
  if (it != legs_.end()) {
    try {
      const bool uncontrolled = it->second->session->no_media_control;
      validate_remote(it->second->user, media, !it->second->session->ambient.empty(), uncontrolled);
      if ((media.control == MediaControl::none) != uncontrolled)
        throw std::runtime_error("media plane control answer differs from offer");
      if (!uncontrolled && media.floor_ssrc == it->second->local.floor_ssrc)
        throw std::runtime_error("directional floor SSRC collision");
      if (media.protected_media != it->second->local.protected_media ||
          (media.protected_media && (media.payload_type != it->second->local.payload_type ||
                                     media.octet_aligned != it->second->local.octet_aligned)))
        throw std::runtime_error("protected media negotiation changed");
      if (!it->second->incoming_offer && media.floor_priority != it->second->local.floor_priority)
        throw std::runtime_error("floor priority answer differs from offer");
      if (media.queueing && !it->second->local.queueing)
        throw std::runtime_error("unoffered floor queueing in SDP answer");
      it->second->remote = media;
    } catch (const std::exception &error) {
      event("sdp_rejected", {{"reason", error.what()}});
      auto id = std::string(dialog);
      schedule([this, id] { sip_.bye(id); });
    }
  }
}

//------------------------------------------------------------------------------
// The run loop: provision the security keys, install the SIP body protection filters (TS 33.180 clause 9.3),
// then poll SIP, run the scheduled tasks, the control commands, the floor, audio and video packets of every leg
// and the relays, and tick; on quit, release every dialog.
void McServer::run() {
  if (cfg_.contains("security")) {
    keys_ = std::make_unique<KeyClient>(http_, cfg_.at("security"), cfg_.at(svc_.name).at("service_uri"));
    keys_->provision("", cfg_.at("common").at("client_id"), cfg_.at("common").at("secret"));
  }
  sip_.set_body_filters(
      [this](const SipTransmission &transmission, std::vector<BodyPart> parts) {
        return protect_outgoing(transmission, std::move(parts));
      },
      [this](const SipTransmission &transmission, std::vector<BodyPart> parts) {
        return protect_incoming(transmission, std::move(parts));
      });
  sip_.start();
  event("server_started");
  while (!stopping) {
    sip_.poll(std::chrono::milliseconds(5));
    pending_.run();
    for (auto &command : control_.read()) {
      if (command == "quit")
        stopping = 1;
      else if (command == "hangup") {
        for (auto &[dialog, leg] : legs_) sip_.bye(dialog);
        for (auto &[dialog, relay] : relays_) sip_.bye(dialog);
      } else if (command.starts_with("ambient-release ")) {
        // Administrator-triggered release (TS 24.379 clause 11.1.6.4.3) of the calls
        // listening to one user, or of every ambient listening call.
        const auto id = command.substr(16);
        std::vector<std::shared_ptr<Session>> found;
        for (const auto &[key, session] : sessions_)
          if (!session->ambient.empty() && (id == "all" || session->listened_to == id)) found.push_back(session);
        for (const auto &session : found) release_ambient(session, "administrator-action");
      } else if (command.starts_with("seal-")) {
        try {
          seal_command(command);
        } catch (const std::exception &error) {
          event("seal_command_failed", {{"command", command}, {"reason", error.what()}});
        }
      } else if (command.starts_with("regroup-remove ")) {
        // TS 24.379 clause 16.2.3.3: the controlling function decides to remove a regroup.
        const auto id = command.substr(15);
        if (!regroup_decide_remove(id)) event("regroup_remove_unknown", {{"regroup", id}});
      }
    }
    for (auto &[id, leg] : legs_) {
      for (int index = 0; index < 32; index++) {
        auto datagram = leg->floor->receive();
        if (!datagram) break;
        try {
          media_control_packet(*leg, *datagram);
        } catch (const std::exception &error) {
          status_["floor_rejected_packets"] = status_.value("floor_rejected_packets", 0ULL) + 1;
          event("floor_rejected", {{"reason", error.what()}});
        }
      }
      for (int index = 0; index < 32; index++) {
        auto datagram = leg->audio->receive();
        if (!datagram) break;
        try {
          audio_packet(*leg, *datagram);
        } catch (const std::exception &error) {
          status_["media_rejected_packets"] = status_.value("media_rejected_packets", 0ULL) + 1;
          event("media_rejected", {{"reason", error.what()}});
        }
      }
      if (leg->video) service_media_packets(*leg);
    }
    for (auto &[id, relay] : relays_)
      if (id == relay->client_dialog) {
        relay_packets(*relay, RelayStream::floor);
        relay_packets(*relay, RelayStream::audio);
        relay_packets(*relay, RelayStream::video);
      }
    tick();
  }
  for (auto &[dialog, leg] : legs_) sip_.bye(dialog);
  for (auto &[dialog, relay] : relays_) sip_.bye(dialog);
  for (int index = 0; index < 20; index++) sip_.poll(std::chrono::milliseconds(10));
  sip_.stop();
}

} // namespace mcx
