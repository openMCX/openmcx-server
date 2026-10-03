// Group call sessions: legs, invitations, the broadcast hierarchy, setup completion, conference and group key
// notifications and protected floor control packets (members of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19),
// TS 24.481 V19.3.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 24.229, RFC 5875.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.1.1 and 8.2: the public service identity for establishing a pre-established session:
// mcptt.pre_established_uri, by default the service URI with an mcptt-pre-established parameter so that the
// SIP core routes it to this server.
std::string McServer::pre_established_uri() const {
  const auto &mcptt = cfg_.at(svc_.name);
  return mcptt.value("pre_established_uri", mcptt.at("service_uri").get<std::string>() + ";mcptt-pre-established");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.2.1.1 steps 12 and 13: an implicit floor request (mc_implicit_request) is accepted only
// in an ambient listening call. TS 24.379 clause 11.1.2: an MCPTT call without floor control is accepted only
// where uncontrolled_allowed (a private call). Checks a client's SDP offer against the service, the negotiated
// profile and the client's authenticated address.
void McServer::validate_remote(const std::string &user, const MediaDescription &media, bool implicit_allowed,
                               bool uncontrolled_allowed) {
  // The service's media plane control, video and implicit request (check_service_media).
  check_service_media(media, implicit_allowed, uncontrolled_allowed);
  if ((media.protected_media && !keys_) || (media.queueing && !cfg_.at(svc_.name).value("floor_queue", false)))
    throw std::runtime_error("unsupported negotiated profile");
  // A peer's user is reached through its participating server's relay.
  const auto *served = by_id(user);
  if (served && !served->peer.empty()) {
    if (!peer_media(peers_.at(served->peer), media.address) || media.floor_address != media.address)
      throw std::runtime_error("SDP address is not the authenticated client");
    return;
  }
  std::string expected;
  if (cfg_.at("peers").contains(user)) expected = address_of(cfg_.at("peers").at(user));
  // A user the configuration names no device host for (one created in MCX Admin):
  // with sip.core_checks_media_address, the SIP core has already refused any SDP
  // whose address is not the sender's (the P-CSCF's check, TS 24.229 clause 5.2.7.2), so
  // the address is the authenticated client's. The floor channel must still share it.
  if (expected.empty() && cfg_.at("sip").value("core_checks_media_address", false)) {
    if (media.floor_address != media.address) throw std::runtime_error("SDP address is not the authenticated client");
    return;
  }
  if (expected.empty() || media.address != expected || media.floor_address != media.address)
    throw std::runtime_error("SDP address is not the authenticated client");
}

//------------------------------------------------------------------------------
// Helper: a new leg of the session for a user: its local media description and its media sockets.
std::shared_ptr<McServer::Leg> McServer::make_leg(const std::string &id, const std::shared_ptr<Session> &session) {
  const auto offset = media_offset();
  auto leg = std::make_shared<Leg>();
  leg->user = id;
  leg->session = session;
  leg->local = local_media(cfg_, offset);
  leg->local.queueing = cfg_.at(svc_.name).value("floor_queue", false);
  // A private call is protected when its caller offers a PCK; an ad hoc call is clear.
  leg->local.protected_media = session->private_call
                                   ? session->protected_private
                                   : !session->adhoc && group_profile(session->group).value("protect_media", false);
  auto address = cfg_.at("media").at("bind").get<std::string>();
  if (session->no_media_control) {
    // No m=application, hence none of its parameters (TS 24.379 clause 11.1.2, TS 24.281 clause 10.2.3).
    // Speech is relayed with its sender's SSRC, so the server announces none of its own.
    leg->local.control = MediaControl::none;
    leg->local.queueing = leg->local.implicit_request = leg->local.granted = false;
    leg->local.floor_priority.reset();
    leg->local.audio_ssrc = 0;
  }
  // The service's media besides speech and floor control: MCVideo transmission control and video.
  leg->video = service_media(leg->local, offset, address);
  leg->audio = std::make_unique<UdpSocket>(address, leg->local.audio_port);
  leg->floor = std::make_unique<UdpSocket>(address, leg->local.floor_port);
  return leg;
}

//------------------------------------------------------------------------------
// Helper: whether the session is still the current session of its group.
bool McServer::current_session(const std::shared_ptr<Session> &session) const {
  const auto it = sessions_.find(session->group);
  return it != sessions_.end() && it->second == session;
}

//------------------------------------------------------------------------------
// Helper: the legs of the session's dialogs.
std::vector<std::shared_ptr<McServer::Leg>> McServer::session_legs(const Session &session) const {
  std::vector<std::shared_ptr<Leg>> result;
  for (const auto &dialog : session.dialogs) {
    const auto it = legs_.find(dialog);
    if (it != legs_.end()) result.push_back(it->second);
  }
  return result;
}

//------------------------------------------------------------------------------
// Helper: whether the user has a leg in the session.
bool McServer::has_leg(const Session &session, const std::string &id) const {
  for (const auto &leg : session_legs(session))
    if (leg->user == id) return true;
  return false;
}

//------------------------------------------------------------------------------
// Helper: register the leg under its dialog and add the dialog to its session.
void McServer::add_leg(const std::shared_ptr<Leg> &leg) {
  legs_[leg->dialog] = leg;
  leg->session->dialogs.insert(leg->dialog);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.5.5 and 10.1.1.4.1.1: the controlling function invites one affiliated member (in a
// broadcast hierarchy, one affiliated to a subordinate group or its own group) to the group session.
void McServer::invite_member(const std::shared_ptr<Session> &session, const std::string &id) {
  if (!current_session(session)) return;
  auto *user = by_id(id);
  if (!user || has_leg(*session, id) || !policy_allows(session->policy, "join_members", id)) return;
  std::string associated;
  if (!affiliated(id, session->group)) {
    if (session->hierarchy == "group-broadcast") {
      for (const auto &sub : session->subordinate_groups)
        if (affiliated(id, sub)) {
          associated = sub;
          break;
        }
    } else if (session->hierarchy == "user-broadcast" && !user->groups.empty() &&
               affiliated(id, *user->groups.begin())) {
      associated = *user->groups.begin();
    }
    if (associated.empty()) return;
  }
  if (session->dialogs.size() >= session->policy.value("max_participants", session->members.size())) return;
  if (!user->peer.empty() && !floor_keys(*user) && !session->private_call && !session->adhoc) {
    const auto group = group_profile(session->group);
    if (group.value("protect_media", false) || group.value("protect_floor", false)) {
      event("fanout_skipped", {{"user_id", id}, {"reason", "protected media not supported across MCPTT servers"}});
      return;
    }
  }
  release_listened_to(id, ambient_reason("for"));
  auto leg = make_leg(id, session);
  McpttInfo info;
  info.session_type = session->chat ? "chat" : "prearranged";
  info.request_uri = id;
  info.functional_alias = session->initiator_alias;
  if (session->broadcast) info.broadcast = true;
  info.associated_group = associated;
  info.calling_group = session->group;
  info.calling_user = session->initiator;
  const auto profile = group_profile(session->group);
  negotiate_priority(*leg, profile, std::uint8_t{99});
  const auto state = priorities_[session->group];
  populate_priority(info, state);
  auto headers = priority_headers(profile.value("priority_policy", Json::object()), state);
  headers.push_back({"Answer-Mode", session->policy.value("answer_mode", "Auto")});
  headers.push_back({"Contact", focus_contact(*session)});
  leg->dialog = sip_.invite(user->sip, leg->local, priority_parts(info), {}, user_route(*user, headers));
  add_leg(leg);
  event("call_fanout", {{"user_id", id}, {"session_uri", session->uri}});
}

//------------------------------------------------------------------------------
// TS 23.379 clauses 10.6.2.5.2.1 and 10.6.2.5.2.2: resolve the broadcast hierarchy, release ongoing
// non-emergency calls of the users it reaches, and leave groups (or users)
// in an emergency call untouched and uninvited.
void McServer::prepare_broadcast_hierarchy(Session &session, const Json &profile, const std::string &type,
                                           const std::string &initiator) {
  session.hierarchy = type;
  std::vector<std::string> members{initiator};
  const auto add = [&](const std::string &id) {
    if (std::find(members.begin(), members.end(), id) == members.end()) members.push_back(id);
  };
  const auto release = [&](const std::shared_ptr<Session> &other, const std::string &only = {}) {
    for (const auto &leg : session_legs(*other)) {
      if (!only.empty() && leg->user != only) continue;
      session.awaiting_users.insert(leg->user);
      leg->active = false;
      sip_.bye(leg->dialog);
    }
    event("broadcast_preempted_call",
          {{"group_id", other->group}, {"user_id", only}, {"broadcast_group", session.group}});
  };
  if (type == "group-broadcast") {
    for (const auto &sub : profile.value("subordinate_groups", std::vector<std::string>{})) {
      const auto priority = priorities_.find(sub);
      if (priority != priorities_.end() && priority->second.emergency) {
        event("broadcast_subordinate_skipped", {{"group_id", sub}, {"reason", "emergency"}});
        continue;
      }
      session.subordinate_groups.push_back(sub);
      for (const auto &id : group_profile(sub).at("members").get<std::vector<std::string>>()) add(id);
      if (const auto ongoing = sessions_.find(sub); ongoing != sessions_.end()) release(ongoing->second);
    }
  } else {
    for (const auto &id : profile.at("members").get<std::vector<std::string>>()) {
      std::vector<std::shared_ptr<Session>> calls;
      bool emergency = false;
      for (const auto &[key, other] : sessions_)
        if (!other->private_call && has_leg(*other, id)) {
          calls.push_back(other);
          if (call_priority(*other).emergency) emergency = true;
        }
      if (emergency && id != initiator) {
        event("broadcast_member_skipped", {{"user_id", id}, {"reason", "emergency"}});
        continue;
      }
      add(id);
      for (const auto &other : calls) release(other, id);
    }
  }
  session.awaiting_users.erase(initiator);
  session.members = members;
  session.awaiting_since = monotonic_ms();
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.4.1.1 step 12a (and clause 10.1.1.4.2 step 15d): at the participant limit, a
// joiner of higher <user-priority> displaces the lowest-priority participant
// (clause 10.1.1.4.4.3). Local policy: the group's user_priorities map (absent = 0),
// and an emergency or imminent peril request outranks every normal user.
bool McServer::preempt_lower_priority_participant(const std::shared_ptr<Session> &session, const Json &profile,
                                                  const std::string &joiner, const McpttInfo &info) {
  const auto priorities = profile.value("user_priorities", Json::object());
  const auto rank = [&](const std::string &id) { return priorities.is_object() ? priorities.value(id, 0) : 0; };
  const int requested = (info.emergency == true || info.imminent_peril == true) ? 1 << 16 : rank(joiner);
  std::shared_ptr<Leg> lowest;
  for (const auto &leg : session_legs(*session))
    if (leg->active && leg->user != joiner && (!lowest || rank(leg->user) < rank(lowest->user))) lowest = leg;
  if (!lowest || rank(lowest->user) >= requested) return false;
  event("participant_preempted", {{"user_id", lowest->user}, {"by", joiner}, {"session_uri", session->uri}});
  lowest->active = false;
  notices(*session, session->arbitrator->release(lowest->user, monotonic_ms()));
  sip_.bye(lowest->dialog);
  return true;
}

//------------------------------------------------------------------------------
// Helper: whether the group is in the emergency or imminent peril state.
bool McServer::in_priority(const std::string &group) const {
  const auto found = priorities_.find(group);
  return found != priorities_.end() && (found->second.emergency || found->second.imminent);
}

//------------------------------------------------------------------------------
// Helper: invite each member of the session that has no leg yet (invite_member decides who is eligible).
void McServer::invite_chat_members(const std::shared_ptr<Session> &session) {
  if (!current_session(session)) return;
  for (const auto &id : session->members)
    if (!has_leg(*session, id)) {
      try {
        invite_member(session, id);
      } catch (const std::exception &error) {
        event("fanout_failed", {{"reason", error.what()}, {"user_id", id}, {"session_uri", session->uri}});
      }
    }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.1.1: the controlling function invites the members of the group session, the
// required members (clause 6.3.3.3) first, then completes the setup.
void McServer::fanout(const std::shared_ptr<Session> &session, const std::string &origin) {
  if (!current_session(session)) return;
  auto invitees = session->members;
  const auto required = session->policy.value("required_members", std::vector<std::string>{});
  std::stable_sort(invitees.begin(), invitees.end(), [&](const auto &left, const auto &right) {
    const auto needed = [&](const auto &id) {
      return std::find(required.begin(), required.end(), id) != required.end();
    };
    return needed(left) && !needed(right);
  });
  for (auto &id : invitees) {
    if (id == origin) continue;
    try {
      invite_member(session, id);
    } catch (const std::exception &error) {
      event("fanout_failed", {{"reason", error.what()}, {"user_id", id}, {"session_uri", session->uri}});
    }
  }
  complete_setup(session);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.3: the answer to the originator once the minimum number of participants and every
// required member have accepted; the failure once nobody is pending or at the setup timeout.
void McServer::complete_setup(const std::shared_ptr<Session> &session) {
  if (!current_session(session) || !session->awaiting_users.empty() || session->invitation_deferred) return;
  std::shared_ptr<Leg> origin;
  std::size_t accepted = 1;
  bool pending = false;
  std::set<std::string> accepted_ids;
  for (const auto &leg : session_legs(*session)) {
    if (leg->awaiting_answer)
      origin = leg;
    else if (leg->active) {
      ++accepted;
      accepted_ids.insert(leg->user);
    } else
      pending = true;
  }
  if (!origin) return;
  accepted_ids.insert(origin->user);
  bool required_present = true;
  for (const auto &id : session->policy.value("required_members", std::vector<std::string>{}))
    if (!accepted_ids.contains(id)) required_present = false;
  if (accepted >= session->policy.value("minimum_participants", 2u) && required_present) {
    origin->awaiting_answer = false;
    // TS 24.379 clause 11.1.8.2.3 step 2b: the target's <replaces-header-value> reaches the requester.
    if (!session->replaces_value.empty())
      for (auto &part : origin->answer.parts)
        if (part.content_type == svc_.info_mime) {
          auto info = parse_service_info_(part.body);
          info.service["replaces-header-value"] = session->replaces_value;
          part.body = service_info_xml_(info);
        }
    sip_.answer(origin->dialog, origin->answer);
    event("call_admitted", {{"session_uri", session->uri}, {"accepted", accepted}});
  } else if (!pending || monotonic_ms() - session->created >= session->policy.value("setup_timeout_ms", 30000u)) {
    origin->awaiting_answer = false;
    SipResponse failure;
    failure.status_code = pending ? 408 : 480;
    failure.reason = pending ? "Request Timeout" : "Temporarily Unavailable";
    // A private call has one callee: relay its decline/busy outcome and warning
    // (e.g. 480 warn(Warning::declined)). Other codes map to 480.
    static const std::set<int> relayed{480, 486, 488, 603};
    if (session->private_call && !session->first_to_answer && session->ambient.empty() && !pending &&
        relayed.contains(session->failure_status)) {
      failure.status_code = session->failure_status;
      failure.reason.clear();
      if (!session->failure_warning.empty()) failure.headers = {{"Warning", session->failure_warning}};
    }
    // No media ports for a callee: lack of resources (TS 24.379 clause 11.1.1.3.1.1 step 1), retried later.
    if (session->capacity_reached && !pending) {
      failure.status_code = 500;
      failure.reason = "Server Internal Error";
      failure.headers = {{"Retry-After", std::to_string(capacity_retry_after())}};
    }
    sip_.answer(origin->dialog, failure);
    event("call_setup_failed", {{"session_uri", session->uri}, {"status", failure.status_code}});
    for (const auto &leg : session_legs(*session))
      if (leg != origin) sip_.bye(leg->dialog);
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.3.4 (content of clause 6.3.3.4): the controlling function's NOTIFY of the conference
// event package to each subscriber; the subscription terminates when the session ends, it expires or the
// subscriber leaves.
void McServer::notify_conference(const std::shared_ptr<Session> &session, bool ending) {
  for (auto it = session->subscriptions.begin(); it != session->subscriptions.end();) {
    auto &sub = it->second;
    const bool expired = sub.expires <= std::time(nullptr);
    const auto *user = by_id(sub.user);
    const bool departing = !has_leg(*session, sub.user) || !user || user->expires <= std::time(nullptr);
    const bool terminated = ending || expired || departing;
    ConferenceInfo conference;
    conference.session_uri = session->uri;
    conference.group_id = session->group;
    conference.version = ++sub.version;
    conference.deleted = ending;
    if (!ending)
      for (const auto &leg : session_legs(*session))
        if (leg->active)
          if (const auto *member = by_id(leg->user))
            conference.users.push_back({leg->user, member->sip, "connected", conference_alias(*session, leg->user)});
    McpttInfo info;
    info.request_uri = sub.user;
    info.calling_group = session->group;
    auto parts = service_parts(info);
    parts.push_back({"application/conference-info+xml", conference_info_xml(conference)});
    const auto boundary = "mcx-" + random_id();
    const auto state = terminated ? std::string("terminated;reason=") + (expired ? "timeout" : "noresource")
                                  : "active;expires=" + std::to_string(sub.expires - std::time(nullptr));
    try {
      sip_.notify(sub.dialog, "conference", state, "multipart/mixed; boundary=" + boundary,
                  multipart_body(parts, boundary), {}, [this, id = sub.user](const SipResponse &response) {
                    if (response.status_code >= 300)
                      event("conference_notify_rejected",
                            {{"user_id", id}, {"status", response.status_code}, {"reason", response.reason}});
                  });
    } catch (const std::exception &error) {
      event("conference_notify_failed", {{"reason", error.what()}});
    }
    if (terminated)
      it = session->subscriptions.erase(it);
    else
      ++it;
  }
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.7 and RFC 5875: the NOTIFY of a change of the user's MCS GKTP document of a group; the
// GMS is polled for a new group key.
void McServer::notify_key(const std::string &dialog) {
  auto found = key_subscriptions_.find(dialog);
  if (found == key_subscriptions_.end() || found->second.pending) return;
  auto &sub = found->second;
  auto *user = by_id(sub.user);
  bool terminated = !user || user->expires <= std::time(nullptr) || sub.expires <= std::time(nullptr);
  std::string body;
  if (!terminated) {
    const auto &common = cfg_.at("common");
    sub.next_poll = monotonic_ms() + key_poll_ms;
    try {
      auto reply =
          http_.request("GET",
                        common.at("gms").get<std::string>() + "/internal/gktp?group_id=" + url_encode(sub.group) +
                            "&user_id=" + url_encode(sub.user) + "&known_key_id=" + std::to_string(sub.key_id),
                        {}, {}, common.at("client_id"), common.at("secret"));
      if (reply.status == 304) return;
      if (reply.status != 200)
        terminated = true;
      else {
        auto data = reply.json();
        sub.key_id = data.at("key_id");
        body = keying::gktp_xcap_diff(data.at("document").get<std::string>(), sub.group,
                                      common.at("gms").get<std::string>() + "/xcap-root/");
      }
    } catch (const std::exception &error) {
      // The GMS is unreachable or its answer malformed: the subscription stays, and the next poll retries.
      event("key_notify_failed", {{"group_id", sub.group}, {"user_id", sub.user}, {"reason", error.what()}});
      return;
    }
  }
  sub.pending = true;
  sip_.notify(dialog, "xcap-diff",
              terminated ? "terminated;reason=noresource"
                         : "active;expires=" + std::to_string(sub.expires - std::time(nullptr)),
              "application/xcap-diff+xml", body, {}, [this, dialog, terminated](const SipResponse &response) {
                if (response.status_code < 200) return;
                auto it = key_subscriptions_.find(dialog);
                if (it == key_subscriptions_.end()) return;
                if (terminated || response.status_code >= 300)
                  key_subscriptions_.erase(it);
                else
                  it->second.pending = false;
              });
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.4.2: the floor keys of a user's leg: its CSK when this server serves the user,
// the SPK of the peer that serves it otherwise (clause 9.4.5).
ProtectedCall *McServer::floor_keys(const User &user) const {
  if (user.peer.empty()) return user.protection.get();
  const auto peer = peers_.find(user.peer);
  return peer == peers_.end() ? nullptr : peer->second.spk.get();
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.4.2: whether a leg with protected floor control has its floor key.
bool McServer::floor_key_ready(const Leg &leg) {
  if (!floor_protected(leg)) return true;
  auto *user = by_id(leg.user);
  auto *keys = user ? floor_keys(*user) : nullptr;
  return keys && keys->floor_ready();
}

//------------------------------------------------------------------------------
// Helper: end a protected leg that has no usable floor key.
void McServer::stop_unkeyed_leg(Leg &leg, const std::string &reason) {
  if (!leg.active) return;
  leg.active = false;
  event("protected_leg_ended", {{"user_id", leg.user}, {"reason", reason}});
  schedule([this, id = leg.user, session = leg.session] { disconnect_user(id, session); });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5 and TS 33.180 clause 9.4.2: send a floor control packet on a leg, protected when the
// call's floor control is; a leg without a usable key is stopped.
void McServer::transmit_floor(Leg &leg, const FloorPacket &packet) {
  if (!leg.active || leg.held || !leg.remote || !leg.floor) return;
  auto bytes = encode_floor(packet);
  if (floor_protected(leg)) {
    auto *user = by_id(leg.user);
    auto *keys = user ? floor_keys(*user) : nullptr;
    if (!keys || !keys->floor_ready()) {
      stop_unkeyed_leg(leg, "floor security unavailable or expired");
      return;
    }
    try {
      bytes = keys->protect_floor(bytes);
    } catch (const std::exception &error) {
      stop_unkeyed_leg(leg, error.what());
      return;
    }
  }
  leg.floor->send(bytes, leg.remote->floor_address, leg.remote->floor_port);
}

} // namespace mcx
