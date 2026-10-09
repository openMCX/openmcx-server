// MCData media plane sessions over MSRP: SDS and FD INVITEs and priority re-INVITEs.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the media plane leg of a dialog, or null. TS 24.282 clauses 9.2.3.3 and 9.2.3.4: standalone SDS over
// the media plane. The participating and controlling functions are collocated, so this server terminates the
// originating MSRP leg, then offers a second leg to the recipient and forwards the bodies.
std::shared_ptr<DataServer::MediaSession> DataServer::media_session(const std::string &dialog) {
  const auto found = media_.find(dialog);
  return found == media_.end() ? nullptr : found->second;
}

//------------------------------------------------------------------------------
// Helper: the MSRP callbacks of a leg: a received message, a failure, and the answer to the last SEND.
msrp::Endpoint::Callbacks DataServer::media_callbacks(const std::shared_ptr<MediaSession> &session) {
  const auto weak = std::weak_ptr<MediaSession>(session);
  return {[this, weak](const msrp::Message &received) {
            if (const auto held = weak.lock()) media_received(held, received);
          },
          [this, weak](std::string_view reason) {
            event("mcdata_media_failed",
                  {{"reason", std::string(reason)}, {"dialog", weak.lock() ? weak.lock()->dialog : std::string{}}});
          },
          [weak] {
            if (const auto held = weak.lock()) held->file_unanswered = false;
            // A standalone delivery is complete: release the leg rather than
            // hold it, so the recipient is free for the next transfer. A
            // session leg stays open until the session ends (TS 24.282 clause 9.2.4).
            if (const auto held = weak.lock(); held && !held->session) held->deadline = monotonic_ms();
          }};
}

//------------------------------------------------------------------------------
// Helper: the address this server offers on the media plane: mcdata.media.advertise
// when it differs from the SIP one.
std::string DataServer::media_address() const {
  const auto media = cfg_.at("mcdata").value("media", Json::object());
  return resolve_ipv4(media.value("advertise", cfg_.at("sip").at("advertise").get<std::string>()));
}

//------------------------------------------------------------------------------
// Helper: this server's own MSRP end of a leg, listening (setup "passive"), from which the SDP offer or answer of
// the leg is built.
MsrpMedia DataServer::media_offer(const std::shared_ptr<MediaSession> &session) {
  session->endpoint = std::make_unique<msrp::Endpoint>();
  const auto address = media_address();
  const auto local = session->endpoint->listen(address, media_callbacks(session));
  MsrpMedia media;
  media.secure = local.secure;
  media.address = address;
  media.port = local.port;
  media.path = local.text();
  media.setup = "passive"; // this server listens on both legs
  media.direction = "recvonly";
  media.accept_types = {mcdata::signalling_mime, mcdata::payload_mime};
  return media;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.4.4.5 and 9.2.4.4.6: a re-INVITE upgrades an ongoing session to an emergency
// communication or cancels that condition, and the other legs are told.
SipResponse DataServer::media_reinvite(const SipMessage &request, const std::shared_ptr<MediaSession> &leg) {
  SipResponse response;
  const auto *info_part = part(request, mcdata::info_mime);
  if (!info_part) return reject(403, "199 expected MIME bodies not in the request", leg->owner, "media-sds-emergency");
  const auto info = mcdata::parse_info(info_part->body);
  // The ad hoc group emergency and imminent peril communications are not implemented.
  if (leg->adhoc) return reject(403, "", leg->owner, "media-adhoc-priority");
  if (!leg->group.empty()) return media_group_reinvite(leg, info);
  const bool emergency = info.emergency == true;
  const auto policy = profile(leg->owner).value("mcdata", Json::object());
  if (emergency && !policy.value("emergency_private", false))
    return reject(403, "112 user not authorised to make private calls", leg->owner, "media-sds-emergency");
  if (!emergency && !policy.value("emergency_private_cancel", false))
    return reject(403, "", leg->owner, "media-sds-emergency");
  leg->emergency = emergency;
  mcdata::Info answered;
  answered.request_type = info.request_type;
  answered.calling_user = leg->owner;
  answered.emergency = emergency;
  response.status_code = 200;
  response.local_sdp = leg->sdp;
  response.parts = {{mcdata::info_mime, mcdata::info_xml(answered)}};
  response.headers = {{"P-Asserted-Service", leg->file ? mcdata::fd_icsi : mcdata::sds_icsi}};
  if (emergency)
    for (const auto &header : media_priority_headers()) response.headers.push_back(header);
  // Tell the other legs of this session, so their clients follow the condition.
  for (auto &[dialog, other] : media_) {
    if (other->key != leg->key || dialog == leg->dialog || !other->session) continue;
    other->emergency = emergency;
    mcdata::Info notice;
    notice.request_type = info.request_type;
    notice.request_uri = other->owner;
    notice.calling_user = leg->owner;
    notice.emergency = emergency;
    // TS 24.282 clause 6.3.7.1.8 step 1: the session identity with g.3gpp.mcdata and isfocus.
    auto headers = std::vector<SipHeader>{{"P-Asserted-Service", mcdata::sds_icsi},
                                          {"Contact", "<" + session_identity(leg->key) + ">;+g.3gpp.mcdata;isfocus"}};
    if (emergency)
      for (const auto &header : media_priority_headers()) headers.push_back(header);
    pending_.push_back([this, dialog, notice, headers, sdp = other->sdp] {
      try {
        sip_.reinvite_sdp(dialog, sdp, seal_for_id(notice.request_uri, {{mcdata::info_mime, mcdata::info_xml(notice)}}),
                          {}, headers);
      } catch (const std::exception &error) {
        event("mcdata_media_failed", {{"reason", error.what()}, {"dialog", dialog}});
      }
    });
  }
  count(emergency ? "media_emergency" : "media_emergency_cancelled");
  event("mcdata_session_emergency", {{"user_id", leg->owner}, {"key", leg->key}, {"emergency", emergency}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.4.4.4 with clauses 6.3.7.1.1, 6.3.7.1.8, 6.3.7.1.10 and 6.3.7.1.14: a re-INVITE on a
// group session raises or cancels the in-progress emergency or imminent peril
// state of the group, and the other legs are told.
SipResponse DataServer::media_group_reinvite(const std::shared_ptr<MediaSession> &leg, const mcdata::Info &info) {
  if (!valid_priority_combination(info))
    return reject(403, "150 invalid combinations of data received in MIME body", leg->owner, "media-group-priority");
  if (!info.emergency && !info.imminent_peril) return reject(403, "", leg->owner, "media-group-priority");
  const bool emergency = info.emergency.has_value();
  const bool enable = emergency ? *info.emergency : *info.imminent_peril;
  if (!priority_authorised(leg->owner, leg->group, emergency, enable))
    return enable ? reject_priority(leg->owner, emergency) : reject(403, "", leg->owner, "media-group-priority");
  auto &state = group_priority_[leg->group];
  bool corrected = false;
  if (emergency) {
    state.emergency = enable;
    if (enable) {
      state.imminent = false; // TS 24.282 clause 6.3.7.1.1 NOTE: an imminent peril state is upgraded
      state.originator = leg->owner;
    }
  } else if (enable && state.emergency) {
    corrected = true; // TS 24.282 clause 6.3.7.1.10: the emergency state of the group wins
  } else {
    state.imminent = enable;
    if (enable) state.originator = leg->owner;
  }
  const bool in_emergency = state.emergency, in_imminent = state.imminent;
  if (!in_emergency && !in_imminent) group_priority_.erase(leg->group);
  leg->emergency = in_emergency;
  leg->imminent = in_imminent;
  SipResponse response;
  response.status_code = 200;
  response.local_sdp = leg->sdp;
  mcdata::Info answered;
  answered.request_type = "group-sds-session";
  answered.calling_user = leg->owner;
  answered.calling_group = leg->group;
  answered.emergency = in_emergency;
  if (!in_emergency)
    answered.imminent_peril = in_imminent;
  else if (corrected)
    answered.imminent_peril = false;
  response.parts = {{mcdata::info_mime, mcdata::info_xml(answered)}};
  response.headers = {{"P-Asserted-Service", leg->file ? mcdata::fd_icsi : mcdata::sds_icsi}};
  for (const auto &header : media_priority_headers(group_level(leg->group))) response.headers.push_back(header);
  if (corrected) {
    response.headers.push_back({"Warning", warning_value("149 SIP INFO request pending")});
    send_priority_info(leg->dialog, leg->owner, leg->group);
  } else {
    media_group_notify(leg, in_emergency, in_imminent);
    // TS 24.282 clause 6.3.7.1.2: and the affiliated members that are not participating.
    std::vector<std::string> participants;
    for (const auto &[dialog, other] : media_)
      if (other->key == leg->key) participants.push_back(other->owner);
    notify_in_progress_state(leg->group, leg->owner, participants, in_emergency, in_imminent);
    count(emergency ? (enable ? "media_group_emergency" : "media_group_emergency_cancelled")
                    : (enable ? "media_imminent_peril" : "media_imminent_peril_cancelled"));
  }
  event("mcdata_group_priority", {{"user_id", leg->owner},
                                  {"group_id", leg->group},
                                  {"emergency", in_emergency},
                                  {"imminent", in_imminent},
                                  {"corrected", corrected}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.3.3.3, 9.2.3.4.3, 9.2.4.3.3, 9.2.4.4.3, 10.2.5.3.3 and 10.2.5.4.3 (with clause 24.4.2.2
// for an ad hoc group): an initial SIP INVITE request for SDS or FD over the media plane, one-to-one or to a group:
// the originating participating and controlling checks, the SDP answer and the invitation of each recipient.
SipResponse DataServer::media_invite(const SipMessage &request) {
  SipResponse response;
  // A re-INVITE inside a session: the emergency condition, not a new session.
  if (const auto existing = media_session(request.dialog_id)) return media_reinvite(request, existing);
  if (const auto tunnel = ipcons_.find(request.dialog_id); tunnel != ipcons_.end()) {
    // A re-INVITE on a tunnel leg (a session refresh) keeps the tunnel as it is.
    response.status_code = 200;
    response.local_sdp =
        request.dialog_id == tunnel->second->origin_dialog ? tunnel->second->origin_sdp : tunnel->second->target_sdp;
    return response;
  }
  const auto asserted = asserted_identity(request);
  auto found = users_.find(asserted);
  // A client asserts itself through the SIP core.
  if (asserted.empty() || asserted != request.from_uri || found == users_.end() ||
      found->second.expires <= std::time(nullptr))
    return reject(404, "141 user unknown to the participating function", asserted, "media-sds");
  auto &user = found->second;
  const BodyPart *sdp = nullptr, *info_part = nullptr, *resources = nullptr;
  for (const auto &part : request.parts) {
    if (part.content_type.starts_with("application/sdp"))
      sdp = &part;
    else if (part.content_type == mcdata::info_mime)
      info_part = &part;
    else if (part.content_type == resource_lists_mime)
      resources = &part;
  }
  if (!sdp || !info_part) return reject(403, "199 expected MIME bodies not in the request", user.id, "media-sds");
  auto info = mcdata::parse_info(info_part->body);
  if (info.request_type == "one-to-one-ipconn") return ipcon_invite(request, user, info, *sdp, resources);
  MediaInvite invite;
  if (auto refused = media_invite_kind(user, info, *sdp, invite)) return *refused;
  // TS 24.282 clause 9.2.4.4.4 step 3A with clause 6.3.7.1.9: the combination of priority indications.
  if (!valid_priority_combination(info))
    return reject(403, "150 invalid combinations of data received in MIME body", user.id, "media-sds-priority");
  const auto policy = profile(user.id).value("mcdata", Json::object());
  if (!policy.value("transmit_data", false))
    return reject(403, "200 user not authorised to transmit data", user.id, "media-sds");
  if (invite.adhoc) {
    if (auto refused = media_invite_adhoc_targets(request, user, info, policy, invite)) return *refused;
  } else if (invite.group_request) {
    if (auto refused = media_invite_group_targets(user, info, invite)) return *refused;
  } else if (auto refused = media_invite_private_target(user, policy, resources, invite)) {
    return *refused;
  }
  MsrpMedia offer;
  if (auto refused = media_invite_sdp_offer(user, *sdp, invite, offer)) return *refused;
  if (invite.file_request)
    if (auto refused = media_invite_file(request, user, policy, offer, invite)) return *refused;
  if (auto refused = media_invite_priority(request, user, info, policy, invite)) return *refused;
  // TS 24.282 clause 6.3.7.1.11: a group communication is carried at the level of its group.
  const std::string level = invite.group_request && (invite.session || invite.file_request) ? group_level(invite.group)
                            : info.emergency == true                                        ? "emergency"
                                                                                            : "normal";
  MsrpMedia answer;
  const auto leg = media_invite_leg(request, user, invite, level, answer);
  // TS 24.282 clause 10.2.5.4.4: the inviting client of a one-to-one file over the media plane is answered upon
  // the invited client's 200 (OK) response (or given its refusal); until then it gets 100 (Trying).
  const bool await_recipient =
      invite.file_request && !invite.group_request && !invite.adhoc && invite.recipients.size() == 1;
  if (!await_recipient && (invite.session || invite.file_request)) media_invite_recipients(user, invite, *leg, level);
  media_invite_answer(request, user, info, invite, *leg, level, response);
  // TS 24.282 clause 6.3.7.1.23 steps 5 and 6: the session identity, as focus, with the subservice's tags (a
  // standalone SDS has no session id of its own and gets a fresh identity).
  session_contact(response, session_identity(leg->key), invite.file_request ? "fd" : "sds");
  if (invite.file_request) media_invite_transfer(user, invite);
  if (await_recipient) {
    media_invite_file_recipient(user, invite, *leg, level, request.dialog_id, response);
    // The provisional answer carries the SDP answer and the Contact, so that the SIP engine keeps the dialog, with
    // its session identity, for the final one.
    const auto sdp = response.local_sdp;
    const auto prepared = response;
    response = SipResponse{};
    response.status_code = 100;
    response.reason = "Trying";
    response.local_sdp = sdp;
    response.contact_uri = prepared.contact_uri;
    response.contact_tags = prepared.contact_tags;
    response.focus = prepared.focus;
  }
  count(invite.file_request ? "media_files" : "media_sds");
  if (invite.adhoc) count("media_adhoc");
  event("mcdata_media_session", {{"user_id", user.id},
                                 {"target", invite.target},
                                 {"group_id", invite.group},
                                 {"file", invite.file_request},
                                 {"adhoc", invite.adhoc},
                                 {"session", invite.session},
                                 {"recipients", invite.recipients},
                                 {"dialog", request.dialog_id},
                                 {"msrp_port", answer.port}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 24.3.2.1.1 and 24.4.2.2, 9.2.3 and 10.2.5: the kind of media-plane communication an initial
// INVITE requests (SDS or FD, standalone or session, one-to-one, group or ad hoc group), or its refusal.
std::optional<SipResponse> DataServer::media_invite_kind(const User &user, const mcdata::Info &info,
                                                         const BodyPart &sdp, MediaInvite &invite) {
  // TS 24.282 clauses 24.3.2.1.1 and 24.4.2.2: an ad hoc group communication. "adhoc-group-sds-session"
  // covers both a standalone SDS and an SDS session, which the SDP offer tells
  // apart: "a=sendonly" for the first (clause 9.2.3.2.1), "a=sendrecv" for the second
  // (clause 9.2.4.2.1). A malformed offer is refused with 488 further down.
  invite.adhoc = info.request_type == "adhoc-group-sds-session" || info.request_type == "adhoc-group-fd-session";
  invite.adhoc_session = false;
  if (info.request_type == "adhoc-group-sds-session") {
    try {
      invite.adhoc_session = parse_msrp_sdp(sdp.body).direction == "sendrecv";
    } catch (const std::exception &) {
      invite.adhoc_session = false;
    }
  }
  invite.session =
      info.request_type == "one-to-one-sds-session" || info.request_type == "group-sds-session" || invite.adhoc_session;
  // TS 24.282 clause 10.2.5: file distribution over the media plane, one-to-one or to a group.
  invite.file_request = info.request_type == "one-to-one-fd" || info.request_type == "group-fd" ||
                        info.request_type == "adhoc-group-fd-session";
  invite.group_request = info.request_type == "group-sds" || info.request_type == "group-sds-session" ||
                         info.request_type == "group-fd" || invite.adhoc;
  if (info.request_type != "one-to-one-sds" && info.request_type != "group-sds" && !invite.session &&
      !invite.file_request && !invite.adhoc)
    return reject(403, "", user.id, "media-sds");
  invite.what = invite.file_request ? "media-fd" : "media-sds";
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 24.3.2.1.1 step 7 and clause 24.4.2.2 steps 6 to 17: the participants of an ad hoc group
// communication over the media plane, or the refusal.
std::optional<SipResponse> DataServer::media_invite_adhoc_targets(const SipMessage &request, const User &user,
                                                                  mcdata::Info &info, const Json &policy,
                                                                  MediaInvite &invite) {
  if (info.client_id != user.client) return reject(403, "", user.id, invite.what);
  // The ad hoc group emergency and imminent peril communications of TS 24.282 clause 24
  // are not implemented, so a request that asks for one is refused.
  if (info.emergency == true || info.imminent_peril == true) return reject(403, "", user.id, "media-adhoc-priority");
  // TS 24.282 clause 24.3.2.1.1 step 7 and clause 24.4.2.2 steps 6 to 17: the same authorisation and
  // participant determination as an ad hoc group SDS over the signalling plane.
  std::vector<const User *> targets;
  if (auto rejected = adhoc_recipients(request, user, info, policy, targets, invite.called_aliases)) return *rejected;
  invite.group = info.calling_group;
  for (const auto *recipient : targets) invite.recipients.push_back(recipient->id);
  invite.group_limit =
      limit(cfg_.at("mcdata").value("adhoc", Json::object()), invite.file_request ? "max_fd_bytes" : "max_sds_bytes");
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.3.4.4 with the group checks of clause 9.2.2.4.2 step 6 (clause 10.2.5.4.3 for FD): the
// recipients of a group communication over the media plane, or the refusal.
std::optional<SipResponse> DataServer::media_invite_group_targets(const User &user, const mcdata::Info &info,
                                                                  MediaInvite &invite) {
  // TS 24.282 clause 9.2.3.4.4 with the group checks of clause 9.2.2.4.2 step 6. The size limits are
  // applied when the payload arrives, since the INVITE does not carry it.
  invite.group = info.request_uri;
  const auto &group = invite.group;
  const bool file_request = invite.file_request;
  const char *what = invite.what;
  // The refusals before the service checks count under the request's own kind (media-sds or media-fd).
  if (info.client_id != user.client) return reject(403, "", user.id, what);
  const auto document = group_document(group);
  if (!document) return reject(404, "163 the group identity indicated in the request does not exist", user.id, what);
  if (document->value("preconfigured_use_only", false))
    return reject(403, "167 call is not allowed on the preconfigured group", user.id, what);
  const auto settings = document->value("mcdata", Json());
  if (!settings.is_object() || !listed(settings.value("members", Json::array()), user.id))
    return reject(403, "116 user is not part of the MCData group", user.id, what);
  if (!file_request && !settings.value("allow_sds", false))
    return reject(403, "206 short data service not allowed for this group", user.id, "media-sds");
  if (!file_request && !settings.value("sds_supported", false))
    return reject(488, "207 SDS services not supported for this group", user.id, "media-sds");
  // TS 24.282 clause 10.2.5.4.3 with clause 10.2.4.4.2 step 12: the FD enabler of the group.
  if (file_request && !settings.value("allow_fd", false))
    return reject(403, "213 file distribution not allowed for this group", user.id, "media-fd");
  if (file_request && !settings.value("fd_supported", false))
    return reject(488, "214 FD services not supported for this group", user.id, "media-fd");
  // TS 24.282 clause 9.2.4.4.4 steps 3B and 3C: a priority group communication is authorised by
  // the user profile and the group document (clauses 6.3.7.2.4 and 6.3.7.2.6) before the
  // remaining group checks, and only a session carries one (clause 6.2.8.1.8).
  if (info.emergency == true || info.imminent_peril == true) {
    const bool emergency_request = info.emergency == true;
    if (!invite.session) return reject(403, "", user.id, "media-sds-priority");
    if (!priority_authorised(user.id, group, emergency_request, true))
      return reject_priority(user.id, emergency_request);
  }
  if (document->value("regrouped", false)) return reject(403, "148 group is regrouped", user.id, what);
  if (!transmit_allowed(settings, user.id))
    return reject(403, "201 user not authorised to transmit data on this group identity", user.id, what);
  if (!affiliated(user.id, group)) return reject(403, "120 user is not affiliated to this group", user.id, what);
  for (const auto &member : settings.value("members", Json::array()))
    if (member.is_string() && member.get<std::string>() != user.id && affiliated(member, group))
      invite.recipients.push_back(member.get<std::string>());
  if (invite.recipients.empty()) return reject(403, "198 no users are affiliated to this group", user.id, what);
  invite.group_limit = limit(settings, file_request ? "max_fd_bytes" : "max_sds_bytes");
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.3.3 and 10.2.5.3: the recipient of a one-to-one communication over the media plane
// (the resource-lists body) and its authorisation, or the refusal.
std::optional<SipResponse> DataServer::media_invite_private_target(const User &user, const Json &policy,
                                                                   const BodyPart *resources, MediaInvite &invite) {
  auto &target = invite.target;
  try {
    if (resources) target = parse_private_call_target(resources->body);
  } catch (const std::exception &) {
    target.clear();
  }
  if (target.empty())
    return reject(403,
                  invite.file_request ? "205 unable to determine targeted user for one-to-one FD"
                                      : "204 unable to determine targeted user for one-to-one SDS",
                  user.id, invite.what);
  if (const auto list = policy.value("targets", Json::array()); !list.empty() && !listed(list, target))
    return reject(403, "229 one-to-one MCData communication not authorised to the targeted user", user.id, "media-sds");
  const auto *recipient = by_id(target);
  if (!recipient) return reject(404, "", user.id, "media-sds");
  // TS 24.282 clause 9.2.3.3: the recipient's incoming communication list.
  const auto incoming_policy = profile(target).value("mcdata", Json::object());
  // The list applies with one or more entries (TS 24.282 clause 9.2.3.3 step 4A).
  const auto incoming_list = incoming_policy.value("incoming_from", Json::array());
  if (!incoming_policy.value("incoming_any", false) && !incoming_list.empty() && !listed(incoming_list, user.id))
    return reject(403, "230 one-to-one MCData communication not authorised from this originating user", user.id,
                  "media-sds");
  invite.recipients.push_back(target);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.3.3, 9.2.4.3 and 10.2.5.3: the SDP offer of the originating client (an MSRP endpoint that
// connects) and the PCK it carries for a one-to-one communication, or a 488 refusal.
std::optional<SipResponse> DataServer::media_invite_sdp_offer(const User &user, const BodyPart &sdp,
                                                              const MediaInvite &invite, MsrpMedia &offer) {
  SipResponse response;
  try {
    offer = parse_msrp_sdp(sdp.body);
  } catch (const std::exception &error) {
    event("mcdata_media_sdp_rejected", {{"user_id", user.id}, {"reason", error.what()}});
    response.status_code = 488;
    return response;
  }
  if (offer.setup == "passive") {
    response.status_code = 488;
    return response;
  } // both sides would listen
  // TS 24.282 clauses 9.2.3.3, 9.2.4.3 and 10.2.5.3: the PCK of a one-to-one communication reaches the
  // recipient unchanged in this function's own offer; a group has no PCK.
  if (!offer.key_mgmt.empty()) {
    if (!invite.group.empty() || invite.adhoc || invite.recipients.size() != 1) {
      response.status_code = 488;
      return response;
    }
    if (media_key_mgmt_.size() >= 256) media_key_mgmt_.erase(media_key_mgmt_.begin());
    media_key_mgmt_[{user.id, invite.recipients.front()}] = offer.key_mgmt;
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.5.4.3: the FD SIGNALLING PAYLOAD of the request and the file attributes of the SDP offer
// (RFC 5547), checked against the size limits of the service, the user and the group, or the refusal.
std::optional<SipResponse> DataServer::media_invite_file(const SipMessage &request, const User &user,
                                                         const Json &policy, const MsrpMedia &offer,
                                                         MediaInvite &invite) {
  // TS 24.282 clause 10.2.5.4.3: the FD SIGNALLING PAYLOAD of the request and the file attributes
  // of the SDP offer, which carry the metadata of the file (RFC 5547).
  auto &file_bytes = invite.file_bytes;
  const auto *signalling = part(request, mcdata::signalling_mime);
  if (!signalling) return reject(403, "199 expected MIME bodies not in the request", user.id, "media-fd");
  try {
    invite.file_signalling = mcdata::decode_fd_signalling(signalling->body);
  } catch (const std::exception &error) {
    event("mcdata_media_fd_rejected", {{"user_id", user.id}, {"reason", error.what()}});
    SipResponse response;
    response.status_code = 488;
    return response;
  }
  if (offer.file_selector.empty())
    return reject(403, "199 expected MIME bodies not in the request", user.id, "media-fd");
  file_bytes = mcdata::metadata_size("file-selector:" + offer.file_selector).value_or(0);
  const auto service_limit = limit(cfg_.at("mcdata"), "max_data_size_fd_bytes");
  if (service_limit && file_bytes > service_limit)
    return reject(403,
                  "220 user not authorised for FD due to exceeding the maximum amount of data that can be sent in "
                  "a single request",
                  user.id, "media-fd");
  if (!invite.group_request) {
    if (const auto max = limit(policy, "max_data_1to1"); max && file_bytes > max)
      return reject(403,
                    "202 user not authorised for one-to-one MCData communications due to exceeding the maximum "
                    "amount of data that can be sent in a single request",
                    user.id, "media-fd");
  } else if (invite.group_limit && file_bytes > invite.group_limit) {
    return reject(403,
                  "208 user not authorised for MCData communications on this group identity due to exceeding the "
                  "maximum amount of data that can be sent in a single request",
                  user.id, "media-fd");
  }
  invite.file_offer = {offer.file_selector, offer.file_date, offer.file_description, signalling->body};
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 6.2.8.3.1.1, 6.2.8.1.8 and 6.3.7.2.6: an emergency one-to-one or a priority group
// communication requested by the INVITE: its authorisation, the group's priority state (clause 6.3.7.1.10) and an
// emergency alert sent with it (clause 6.2.8.1.1 step 3), or the refusal.
std::optional<SipResponse> DataServer::media_invite_priority(const SipMessage &request, User &user,
                                                             const mcdata::Info &info, const Json &policy,
                                                             MediaInvite &invite) {
  if (info.emergency == true && !invite.group_request) {
    // TS 24.282 clauses 6.2.8.3.1.1 and 6.3.7.2.6: only an authorised user may make a one-to-one
    // communication an emergency one, and only on a session.
    if (!invite.session) return reject(403, "", user.id, "media-sds-emergency");
    if (!policy.value("emergency_private", false))
      return reject(403, "112 user not authorised to make private calls", user.id, "media-sds-emergency");
  } else if (info.emergency == true || info.imminent_peril == true) {
    // TS 24.282 clause 6.2.8.1.8: a priority group communication, and only on a session.
    const bool emergency_request = info.emergency == true;
    // TS 24.282 clause 6.2.8.1.8: on a group SDS session or on FD using the media plane.
    if (!invite.group_request || !(invite.session || invite.file_request))
      return reject(403, "", user.id, "media-sds-priority");
    if (!priority_authorised(user.id, invite.group, emergency_request, true))
      return reject_priority(user.id, emergency_request);
    auto &state = group_priority_[invite.group];
    if (emergency_request) {
      state.emergency = true;
      state.imminent = false;
      state.originator = user.id;
    } else if (state.emergency) {
      invite.corrected = true; // TS 24.282 clause 6.3.7.1.10
    } else {
      state.imminent = true;
      state.originator = user.id;
    }
    // TS 24.282 clause 6.2.8.1.1 step 3 with clause 6.3.7.2.1: an emergency alert sent with the request.
    if (emergency_request && info.alert == true) {
      if (group_alert(request, user, invite.group, invite.alert_location))
        invite.alert = true;
      else
        invite.alert_refused = true; // TS 24.282 clause 6.3.7.1.10 step 3a
    }
    count(emergency_request ? "media_group_emergency" : "media_imminent_peril");
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.3.3.3, 9.2.4.3.3 and 10.2.5.3.3: the originating leg of an accepted media-plane
// communication, with this server's own MSRP end (the SDP answer, returned in answer), kept in media_.
std::shared_ptr<DataServer::MediaSession> DataServer::media_invite_leg(const SipMessage &request, const User &user,
                                                                       const MediaInvite &invite,
                                                                       const std::string &level, MsrpMedia &answer) {
  const bool session = invite.session, file_request = invite.file_request;
  auto leg = std::make_shared<MediaSession>();
  leg->dialog = request.dialog_id;
  leg->session = session;
  leg->file = file_request;
  leg->declared_bytes = invite.file_bytes;
  leg->emergency = level == "emergency";
  leg->imminent = level == "imminent_peril";
  leg->key = session || file_request ? random_id() : std::string{};
  leg->originator = user.id;
  leg->owner = user.id;
  leg->target = invite.target;
  leg->group = invite.group;
  leg->recipients = invite.recipients;
  leg->max_bytes = invite.group_limit;
  leg->originating = true;
  leg->adhoc = invite.adhoc;
  leg->aliases = invite.called_aliases;
  leg->started = monotonic_ms();
  leg->deadline = monotonic_ms() +
                  cfg_.at("mcdata").value("media", Json::object()).value(session ? "idle_ms" : "session_ms", 60000u);
  answer = media_offer(leg);
  if (file_request) {
    // TS 24.282 clause 10.2.5.3.2: the answer names the signalling type and repeats the selector.
    answer.accept_types = {std::string(mcdata::signalling_mime)};
    answer.file_selector = invite.file_offer.selector;
  }
  if (invite.adhoc_session) answer.direction = "sendrecv"; // TS 24.282 clause 9.2.4.3.2
  leg->sdp = msrp_sdp(answer, 1);
  media_[request.dialog_id] = leg;
  return leg;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.4.4.3 and clause 10.2.5.4.3 step 14: the invitation of every recipient of a session or a
// file transfer over the media plane, each queued on pending_.
void DataServer::media_invite_recipients(const User &user, const MediaInvite &invite, const MediaSession &leg,
                                         const std::string &level) {
  // TS 24.282 clause 9.2.4.4.3 and clause 10.2.5.4.3 step 14: every recipient is invited at once. A
  // session stays open; the legs of a file transfer end when it is relayed.
  const auto originator = user.id, key = leg.key, session_group = invite.group;
  const auto offered = invite.file_request ? std::make_shared<FileOffer>(invite.file_offer) : nullptr;
  const auto &alert_location = invite.alert_location;
  const bool alert = invite.alert;
  for (const auto &recipient : invite.recipients) {
    const auto alias = invite.called_aliases.contains(recipient) ? invite.called_aliases.at(recipient) : std::string{};
    pending_.push_back([this, originator, recipient, session_group, key, level, offered, alert_location, alert, alias] {
      media_deliver(originator, recipient, session_group, {}, {}, key, level, offered.get(), alert_location, alert,
                    alias);
    });
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.5.4.4: the recipient of a one-to-one file over the media plane is invited, and the
// inviting client gets the prepared 200 (OK) response (final) upon the recipient's 200 (OK), or the recipient's
// refusal, with its warning.
void DataServer::media_invite_file_recipient(const User &user, const MediaInvite &invite, const MediaSession &leg,
                                             const std::string &level, const std::string &origin,
                                             const SipResponse &final_answer) {
  const auto originator = user.id, key = leg.key, recipient = invite.recipients.front();
  const auto offered = std::make_shared<FileOffer>(invite.file_offer);
  const auto alert_location = invite.alert_location;
  const bool alert = invite.alert;
  const auto alias = invite.called_aliases.contains(recipient) ? invite.called_aliases.at(recipient) : std::string{};
  const auto prepared = std::make_shared<SipResponse>(final_answer);
  pending_.push_back(
      [this, originator, recipient, key, level, offered, alert_location, alert, alias, origin, prepared] {
        const auto dialog = media_deliver(originator, recipient, {}, {}, {}, key, level, offered.get(), alert_location,
                                          alert, alias, false, [this, origin, prepared](const SipResponse &response) {
                                            pending_.push_back([this, origin, prepared, response] {
                                              media_file_answered(origin, *prepared, response);
                                            });
                                          });
        if (dialog.empty()) {
          SipResponse unreachable;
          unreachable.status_code = 480;
          media_file_answered(origin, *prepared, unreachable);
        }
      });
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.5.4.4: the invited client's final response completes the inviting client's INVITE.
void DataServer::media_file_answered(const std::string &origin, const SipResponse &prepared,
                                     const SipResponse &response) {
  if (!media_session(origin)) return; // the inviting client gave up
  if (response.status_code >= 200 && response.status_code < 300) {
    sip_.answer(origin, prepared);
    return;
  }
  SipResponse refusal;
  refusal.status_code = response.status_code;
  refusal.reason = response.reason;
  if (const auto warning = get_header(response.headers, "Warning"); !warning.empty())
    refusal.headers.push_back({"Warning", std::string(warning)});
  media_.erase(origin);
  sip_.answer(origin, refusal);
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.3.3.3, 9.2.4.3.3 and 10.2.5.3.3: the 200 (OK) response to the originating client, with
// the priority it is carried at (clauses 6.2.8.3.3 and 6.3.7.1.4), a correction by SIP INFO (clause 9.2.4.4.4
// step 3) and the in-progress state for the affiliated members that are not participating (clause 6.3.7.1.2).
void DataServer::media_invite_answer(const SipMessage &request, const User &user, const mcdata::Info &info,
                                     const MediaInvite &invite, const MediaSession &leg, const std::string &level,
                                     SipResponse &response) {
  const bool corrected = invite.corrected, alert_refused = invite.alert_refused;
  const auto &group = invite.group;
  response.status_code = 200;
  response.local_sdp = leg.sdp;
  mcdata::Info answered;
  answered.request_type = info.request_type;
  answered.calling_user = user.id;
  if (invite.adhoc) answered.calling_group = group; // TS 24.282 clause 24.4.2.2: the ad hoc group identity
  if (leg.emergency) answered.emergency = true;
  if (leg.imminent) answered.imminent_peril = true;
  if (corrected) answered.imminent_peril = false; // TS 24.282 clause 6.3.7.1.10
  if (invite.alert)
    answered.alert = true; // TS 24.282 clause 6.3.7.1.3
  else if (alert_refused)
    answered.alert = false;
  response.parts = {{mcdata::info_mime, mcdata::info_xml(answered)}};
  response.headers = {{"P-Asserted-Service", invite.file_request ? mcdata::fd_icsi : mcdata::sds_icsi}};
  // TS 24.282 clauses 6.2.8.3.3 and 6.3.7.1.4: the priority the communication is carried at. An
  // ordinary communication carries no Resource-Priority header field at all.
  if (level != "normal")
    for (const auto &header : media_priority_headers(level.c_str())) response.headers.push_back(header);
  if (corrected || alert_refused) {
    // TS 24.282 clause 9.2.4.4.4 step 3 and clause 10.2.5.4.3: the correction follows in a SIP INFO request.
    response.headers.push_back({"Warning", warning_value("149 SIP INFO request pending")});
    send_priority_info(request.dialog_id, user.id, group, corrected ? std::optional<bool>(false) : std::nullopt, true,
                       alert_refused ? std::optional<bool>(false) : std::nullopt);
  }
  // TS 24.282 clause 6.3.7.1.2: the affiliated members that are not participating are told.
  if (invite.group_request && (leg.emergency || leg.imminent))
    notify_in_progress_state(group, user.id, invite.recipients, leg.emergency, leg.imminent, invite.alert_location);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 12.2: the record of a file transfer over the media plane, to which its disposition
// notifications are correlated; it is kept only long enough for them to arrive.
void DataServer::media_invite_transfer(const User &user, const MediaInvite &invite) {
  // TS 24.282 clause 12.2: the disposition notifications of this transfer are correlated with it,
  // and it is kept only long enough for them to arrive.
  FileTransfer transfer;
  transfer.originator = user.id;
  transfer.group = invite.group;
  transfer.conversation = mcdata::uuid_text(invite.file_signalling.conversation);
  transfer.application_id = invite.file_signalling.application_id;
  for (const auto &recipient : invite.recipients) transfer.recipients.insert(recipient);
  transfer.expires = monotonic_ms() + cfg_.at("mcdata").value("media", Json::object()).value("session_ms", 60000u) * 4;
  transfer.media_plane = true;
  transfers_[mcdata::uuid_text(invite.file_signalling.message)] = transfer;
}

} // namespace mcx
