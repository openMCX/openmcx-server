//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Ambient listening (MCPTT) and ambient viewing (MCVideo) calls: setup, the floor of the listened-to user and
// release by the server, also for a relayed call controlled elsewhere (members of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: reject the INVITE of an ambient listening call: set the status and the Warning, report the rejection
// and return the response.
SipResponse McServer::ambient_rejected(SipResponse &response, const User &user, int status,
                                       const std::string &warning) {
  response.status_code = status;
  if (!warning.empty()) response.headers = {{"Warning", warning_value(warning)}};
  event("ambient_call_rejected", {{"user_id", user.id}, {"status", status}, {"warning", warning}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.3.1.1 steps 4 to 8: the requested ambient listening type, the single listed user
// (request.target) and the caller's <private-call> ruleset. Returns the rejection, or nothing.
std::optional<SipResponse> McServer::ambient_caller_checks(const SipMessage &message, const User &user,
                                                           const std::string &type, SipResponse &response,
                                                           PrivateCallRequest &request) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return ambient_rejected(response, user, status, warning);
  };
  // TS 24.379 clause 11.1.6.3.1.1 step 4: the requested ambient listening type must be authorised.
  const auto caller_policy = user_profile(user.id).value("private_call", Json::object());
  if (!private_policy_flag(caller_policy, type == "remote-init" ? "ambient_remote" : "ambient_local"))
    return reject(403, warn(Warning::ambient_not_authorised));

  // TS 24.379 clause 11.1.6.3.1.1 step 6: exactly one listed user.
  const BodyPart *resources = nullptr;
  for (const auto &part : message.parts)
    if (part.content_type == resource_lists_mime) {
      if (resources) return reject(403, warn(Warning::called_party_unknown));
      resources = &part;
    }
  if (!resources) return reject(403, warn(Warning::called_party_unknown));
  request.caller = user.id;
  try {
    request.target = parse_private_call_target(resources->body);
  } catch (const std::exception &) {
    return reject(403, warn(Warning::called_party_unknown));
  }
  // TS 24.379 clause 11.1.6.3.1.1 steps 7 and 8: <allow-private-call> and the <PrivateCall> list (107, 144). The
  // commencement mode is always automatic (step 13), so its authorisation does not apply.
  if (const auto decision = authorize_private_call(caller_policy, request, svc_); !decision)
    return reject(decision.status, decision.warning);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.3.1.1 step 9 and clause 6.2.1 step 2c: the media offer of an ambient listening call,
// speech offered recvonly (remote-init) or sendonly (local-init), and its end-to-end protection. Returns the
// rejection, or nothing.
std::optional<SipResponse> McServer::ambient_media_refusal(const SipMessage &message, const User &user,
                                                           const std::string &type, SipResponse &response) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return ambient_rejected(response, user, status, warning);
  };
  if (!message.remote_media) return reject(488);
  if (const auto refusal = protected_private_refusal(user, *message.remote_media, false)) return reject(488, *refusal);
  // The SDP direction of the ambient call type (ambient_direction_refusal).
  if (const auto refusal = ambient_direction_refusal(*message.remote_media, type)) return reject(488, *refusal);
  try {
    validate_remote(user.id, *message.remote_media, true);
  } catch (const std::exception &error) {
    event("sdp_rejected", {{"reason", error.what()}});
    return reject(488);
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.3.2.1 steps 4 and 5: the terminating participating function checks the invited user:
// registered, its <private-call> ruleset and, for protected media, its CSK. Returns the rejection, or nothing.
std::optional<SipResponse> McServer::ambient_callee_refusal(const SipMessage &message, const User &user,
                                                            const PrivateCallRequest &request, SipResponse &response) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return ambient_rejected(response, user, status, warning);
  };
  // Terminating participating function (TS 24.379 clause 11.1.6.3.2.1 steps 4 and 5).
  const auto *callee = by_id(request.target);
  if (!callee || callee->expires <= std::time(nullptr)) return reject(480);
  Json callee_policy;
  try {
    callee_policy = callee_private_policy(request.target);
  } catch (const std::exception &) {
    return reject(404);
  }
  if (callee_policy.is_object() && callee_policy.contains("callable") && callee_policy.at("callable") == false)
    return reject(403, warn(Warning::not_callable_in_private_call));
  if (message.remote_media->protected_media)
    if (const auto refusal = protected_callee_refusal(*callee)) return reject(488, *refusal);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.3.1.1 step 13 and clause 11.1.6.4.1 steps 6 and 7: the session of an ambient listening
// call: its listening and listened-to users, automatic commencement and a floor kept by the listened-to user.
std::shared_ptr<McServer::Session> McServer::make_ambient_session(const SipMessage &message, const User &user,
                                                                  const std::string &type,
                                                                  const PrivateCallRequest &request,
                                                                  const Json &policy) {
  auto session = std::make_shared<Session>();
  session->private_call = true;
  session->protected_private = message.remote_media->protected_media;
  session->private_key_mgmt = message.remote_media->key_mgmt;
  session->ambient = type;
  session->listening = type == "remote-init" ? user.id : request.target;
  session->listened_to = type == "remote-init" ? request.target : user.id;
  session->private_request = request;
  session->invitees = {request.target};
  session->group = "private:" + random_id();
  session->uri = session_service_ + ";mcptt-session=" + random_id();
  session->initiator = user.id;
  session->policy = policy;
  session->created = session->last_media = session->normal_since = monotonic_ms();
  session->members = {user.id, request.target};

  // TS 24.379 clause 11.1.6.3.1.1 step 13 and clause 11.1.6.4.1 steps 6 and 7: automatic commencement, a
  // listening invitee may release the call, a listened-to invitee gets a null alert.
  session->answer_headers = {{"Priv-Answer-Mode", "Auto"}};
  session->answer_headers.push_back(type == "local-init" ? SipHeader{"Feature-Caps", ambient_release_caps()}
                                                         : SipHeader{"Alert-Info", "<file:///dev/null>"});

  // The listened-to user keeps the floor for the whole call: no T1 or T2 revocation.
  auto options = floor_options();
  const auto duration = policy.value("maximum_duration_ms", 3600000u);
  options.media_idle_ms = 0;
  options.max_talk_ms = duration ? duration : 86400000u;
  session->arbitrator = make_media_control(session->members, options);
  return session;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.6.3.1.1 and 11.1.6.4.2 (for the invited user, clauses 11.1.6.3.2.1 and 11.1.6.4.1):
// combined participating and controlling function for an on-demand ambient listening call.
SipResponse McServer::ambient_invite(const SipMessage &message, const User &user, const McpttInfo &info) {
  SipResponse response;
  const auto reject = [&](int status, const std::string &warning = {}) {
    return ambient_rejected(response, user, status, warning);
  };
  // No in-dialog procedure is defined for an ambient listening call.
  if (legs_.contains(message.dialog_id))
    return reject(488, warn(Warning::function_not_allowed, "ambient listening call re-INVITE"));
  if (info.client_id != user.client || (!info.calling_user.empty() && info.calling_user != user.id) ||
      !info.calling_group.empty() || !accepts_mcptt(message))
    return reject(403);
  if (message.request_uri != cfg_.at(svc_.name).at("service_uri").get<std::string>()) return reject(404);
  const auto type = info.ambient_listening_type;
  if (type.empty() || info.emergency || info.imminent_peril || info.alert || info.broadcast.value_or(false))
    return reject(403, warn(Warning::invalid_mime_combination));

  PrivateCallRequest request;
  if (auto refused = ambient_caller_checks(message, user, type, response, request)) return *refused;
  if (auto refused = ambient_media_refusal(message, user, type, response)) return *refused;
  if (auto refused = ambient_callee_refusal(message, user, request, response)) return *refused;
  auto policy = private_call_policy();
  policy["protect_floor"] = message.remote_media->protected_media;
  if (private_calls(user.id) >= policy.value("max_calls", 1u)) return reject(486, warn(Warning::max_private_calls));

  // TS 23.379 clause 10.14.3.1 step 2 and clause 10.14.3.2 pre-conditions: neither party may
  // be engaged in another call. A failed invitation is answered 480 (TS 24.379 clause 11.1.6.4.2).
  // A user already being listened to is busy: a second ambient request does not
  // release the first ambient listening call.
  if (in_call(user.id)) return reject(486);
  if (in_call(request.target)) return reject(480);
  auto session = make_ambient_session(message, user, type, request, policy);
  auto leg = make_leg(user.id, session);
  if (leg->local.floor_ssrc == message.remote_media->floor_ssrc) return reject(488);
  leg->dialog = message.dialog_id;
  leg->origin = true;
  leg->incoming_offer = true;
  leg->remote = *message.remote_media;
  leg->local.payload_type = message.remote_media->payload_type;
  leg->local.octet_aligned = message.remote_media->octet_aligned;
  leg->local.queueing = leg->local.queueing && message.remote_media->queueing;
  leg->local.floor_priority.reset();
  leg->local.direction = type == "remote-init" ? "sendonly" : "recvonly";
  response.status_code = 200;
  response.local_media = leg->local;
  response.contact_uri = session->uri;
  response.focus = true;
  McpttInfo answer;
  answer.session_type = svc_.ambient;
  answer.request_uri = request.target;
  answer.calling_user = user.id;
  answer.ambient_listening_type = type;
  response.parts = service_parts(answer);

  // TS 24.379 clause 11.1.6.4.2: the originator of either type may release the call.
  response.headers = {{"Feature-Caps", ambient_release_caps()}};
  leg->answer = response;
  leg->awaiting_answer = true;

  // Progress without ringing; a remotely initiated call carries a null alert
  // (TS 24.379 clause 6.3.2.2.5.1 step 1b, forwarded by the controlling function).
  response.status_code = 183;
  response.reason = "Session Progress";
  response.headers.clear();
  if (type == "remote-init") response.headers.push_back({"Alert-Info", "<file:///dev/null>"});
  sessions_[session->group] = session;
  add_leg(leg);
  schedule([this, session] {
    invite_private_target(session, session->private_request.target);
    complete_setup(session); // fails the call if the invitee could not be reached
  });
  event("ambient_call_created", {{"user_id", user.id},
                                 {"target", request.target},
                                 {"type", type},
                                 {"listening", session->listening},
                                 {"listened_to", session->listened_to},
                                 {"session_uri", session->uri}});
  return response;
}

//------------------------------------------------------------------------------
// TS 23.379 clauses 10.14.3.1 and 10.14.3.2 steps 6 and 7: once both parties are connected the floor
// is granted to the listened-to user, and the listening user gets Floor Taken
// with no permission to request the floor.
void McServer::ambient_floor(const std::shared_ptr<Session> &session, Leg &joined) {
  const auto owner = session->arbitrator->owner();
  if (owner) {
    send_notice(joined, *owner == joined.user
                            ? FloorNotice{FloorNoticeKind::Granted, joined.user, joined.user, 0, 0, 254,
                                          session->arbitrator->talk_time_remaining(monotonic_ms())}
                            : FloorNotice{FloorNoticeKind::Taken, joined.user, *owner, 0});
    return;
  }
  std::size_t connected = 0;
  for (const auto &leg : session_legs(*session)) connected += leg->active && leg->remote;
  if (connected < 2 || session->ambient_released) return;
  notices(*session, session->arbitrator->request(session->listened_to, monotonic_ms()));
  event("ambient_floor_granted", {{"user_id", session->listened_to}, {"session_uri", session->uri}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.4.3: server initiated ambient call release: BYE the
// listened-to user first; once that dialog has ended, the listening user's BYE
// carries the <release-reason> (see state()).
void McServer::release_ambient(const std::shared_ptr<Session> &session, const std::string &reason) {
  if (session->ambient.empty() || session->ambient_released) return;
  session->ambient_released = true;
  session->ambient_release_reason = reason;
  event("ambient_call_releasing", {{"session_uri", session->uri},
                                   {"reason", reason},
                                   {"listening", session->listening},
                                   {"listened_to", session->listened_to}});
  bool listened_to_leg = false;
  for (const auto &leg : session_legs(*session))
    if (leg->user == session->listened_to && !leg->awaiting_answer) {
      listened_to_leg = true;
      leg->active = false;
      sip_.bye(leg->dialog);
    }
  if (!listened_to_leg) release_ambient_listening(*session);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.4.3: an ambient call released by the server whose dialog with one of these users,
// its listened-to user, has not ended yet.
std::shared_ptr<McServer::Session> McServer::releasing_ambient(const std::vector<std::string> &users) {
  for (const auto &[key, session] : sessions_)
    if (!session->ambient.empty() && session->ambient_released &&
        std::find(users.begin(), users.end(), session->listened_to) != users.end())
      for (const auto &leg : session_legs(*session))
        if (leg->user == session->listened_to && !leg->awaiting_answer) return session;
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.4.3, on the SIP 200 (OK) to the BYE of the listened-to user, steps 2 to 4: the BYE
// to the listening user with the <release-reason>.
void McServer::release_ambient_listening(const Session &session) {
  McpttInfo release;
  release.release_reason = session.ambient_release_reason;
  for (const auto &leg : session_legs(session))
    if (leg->user == session.listening && !leg->awaiting_answer) sip_.bye(leg->dialog, {}, {}, service_parts(release));
}

//------------------------------------------------------------------------------
// TS 24.379 annex D.3 and TS 24.281 annex D.3: the ambient call release feature-capability indicator:
// g.3gpp.mcptt.ambient-listening-call-release or g.3gpp.mcvideo.ambient-viewing-call-release.
std::string McServer::ambient_release_caps() const {
  return std::string("*;+") + svc_.feature_tag + "." + svc_.ambient + "-call-release";
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.3 and TS 24.281 annex F.1.3: the <release-reason> "call-request-for-listened-to-client"
// and so on (TS 24.379 clause 11.1.6.4.3 steps 3c and 3d).
std::string McServer::ambient_reason(const char *kind) const {
  return std::string("call-request-") + kind + "-" + svc_.ambient_party + "-client";
}

//------------------------------------------------------------------------------
// TS 23.379 clause 10.14.3.3 step 1: a call request initiated by, or targeted to, a
// listened-to user releases that user's ambient listening call (TS 24.379 clause 11.1.6.4.3), here or relayed.
void McServer::release_listened_to(const std::string &id, const std::string &reason) {
  std::vector<std::shared_ptr<Session>> found;
  for (const auto &[key, session] : sessions_)
    if (!session->ambient.empty() && !session->ambient_released && session->listened_to == id) found.push_back(session);
  for (const auto &session : found) release_ambient(session, reason);
  release_relayed_ambient(id, reason);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.4.3 and TS 24.281 clause 15.4.3, extended (T12): the ambient call of a listened-to
// or viewed-to user served here and controlled elsewhere. The standards do not say how its controlling
// function learns of a call request it does not control; this participating function sees both calls, so it
// releases the relayed ambient call: first to the client, then to the controlling function with the
// <release-reason>, which that function passes on to the listening user.
// then runs once the client's side is released. Returns whether one was found.
bool McServer::release_relayed_ambient(const std::string &id, const std::string &reason, std::function<void()> then) {
  std::vector<std::shared_ptr<Relay>> found;
  for (const auto &[dialog, relay] : relays_)
    if (relay->user == id && relay->ambient_party && !relay->ended && dialog == relay->peer_dialog)
      found.push_back(relay);
  if (found.empty()) return false;
  for (const auto &relay : found) {
    if (then) relay->after_release.push_back(then), then = {};
    if (std::exchange(relay->ambient_releasing, true)) continue;
    McpttInfo release;
    release.release_reason = reason;
    event("ambient_relay_releasing", {{"user_id", id}, {"server", relay->peer}, {"reason", reason}});
    // Whichever ends the relay (this release, or the end of the client's dialog)
    // sends the BYE upstream with the reason.
    relay->bye_parts = service_parts(release);
    const auto finish = [this, weak = std::weak_ptr<Relay>(relay)] {
      const auto relay = weak.lock();
      if (!relay) return;
      const auto waiting = std::exchange(relay->after_release, {});
      end_relay(relay);
      for (const auto &next : waiting) schedule(next);
    };
    relay->client_released = true;
    try {
      sip_.bye(relay->client_dialog, [this, finish](const SipResponse &response) {
        if (response.status_code >= 200) schedule(finish);
      });
    } catch (const std::exception &) {
      schedule(finish);
    }
  }
  return true;
}

//------------------------------------------------------------------------------
// Helper (T12): a relayed ambient call being released for one of these users.
std::shared_ptr<McServer::Relay> McServer::releasing_relay(const std::vector<std::string> &users) {
  for (const auto &[dialog, relay] : relays_)
    if (relay->ambient_releasing && !relay->ended && std::find(users.begin(), users.end(), relay->user) != users.end())
      return relay;
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.4.3, extended (T12), at the controlling function: the listened-to user's leg released
// by its participating function with a <release-reason> is a release of the ambient call
// for that reason, which then reaches the listening user.
void McServer::ambient_bye_from_participant(const SipMessage &message) {
  const auto found = legs_.find(message.dialog_id);
  if (found == legs_.end()) return;
  const auto &leg = found->second;
  const auto &session = leg->session;
  if (!session || session->ambient.empty() || session->ambient_released || leg->user != session->listened_to) return;
  std::string reason;
  try {
    reason = message_info(message, svc_).release_reason;
  } catch (const std::exception &) {
    return;
  }
  if (reason != ambient_reason("for") && reason != ambient_reason("initiated-by")) return;
  session->ambient_released = true;
  session->ambient_release_reason = reason;
  event("ambient_call_releasing", {{"session_uri", session->uri},
                                   {"reason", reason},
                                   {"listening", session->listening},
                                   {"listened_to", session->listened_to},
                                   {"by", "participating function"}});
}

} // namespace mcx
