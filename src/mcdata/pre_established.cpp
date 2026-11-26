//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Pre-established sessions at the participating MCData function (TS 24.282 clause 18.3), collocated with the
// controlling function: establishment by the client (clause 18.3.2.2) behind the resource sharing condition of clause
// 18.2, modification by the client (clause 18.3.4.2.1) or by this function (operator command), release by either side
// (clauses 18.3.3.2.1 and 18.3.3.2.2); and the SDS communications over the session (clause 9.2.5): the client's REFER
// that starts a one-to-one or group standalone SDS over the media plane or SDS session (clauses 9.2.5.2.2.1 and
// 9.2.5.3.2.1), handled as the INVITE of clause 9.2.5.1.1 would be by this server's controlling role (media_invite),
// its outcome reported by a re-INVITE in the session (clause 9.2.5.1.2, "establish-success" or "establish-fail");
// a communication offered to the client over its session (clauses 9.2.5.2.2.2 and 9.2.5.3.2.2: the re-INVITE
// "establish-request" of clause 9.2.5.1.3, from media_deliver); the client leaving by a REFER "BYE" (clause 9.2.5.4.2.1,
// then the re-INVITE "terminated") and this function releasing it (clause 9.2.5.4.2.2, the re-INVITE
// "terminate-request"). The media plane is TS 24.582 clause 12: the session's MSRP media, this function listening
// ("a=setup:passive"), to which the client connects anew for each communication (TS 37.579-1 table 5.3C.12.3-1 step 8).
//
// Every re-INVITE of this function in the session carries the session's SDP as its offer (RFC 3264 section 8: the
// media unchanged), so that the client's answer completes each exchange in its 2xx; TS 24.282 asks for no SDP in
// the "establish-success", "terminated" and "terminate-request" re-INVITEs (the conformance tests' TS 37.579-1 table
// 5.3C.12.4-1 sends none: the client then offers in its 2xx, RFC 3261 section 13.3.1), which this SIP engine, whose
// re-INVITEs always offer, does not send.
//
// Emergency and imminent peril communications over the session (clauses 9.2.5.2.2.1 step 4 ii and iii, 9.2.5.3.2.1
// steps 6A and 6B, 9.2.5.2.2.3, 9.2.5.2.2.4): the indications of the REFER's entry, or of its own MCData-Info, checked
// at the REFER (pre_session_priority_refused) and carried to the controlling function with the alert's location of the
// REFER; the grant in "establish-success" with the communication's Resource-Priority, the correction of clause
// 6.2.8.1.16 2) b) in it rather than after a SIP INFO (media_invite_answer); a priority communication offered over a
// session as on demand (media_deliver); the client's upgrade or cancellation by re-INVITE in the session (clause
// 6.3.7.1.18, pre_session_in_dialog) and the controlling function's to the other legs (clause 6.3.7.1.17,
// reinvite_leg).
//
// Not implemented: ICE (the answer carries no ICE attributes, which turns ICE off, RFC 8839 section 4.2.3; clause
// 18.3.2.2 steps 9 e and 12), resource sharing by the SIP core (clause 18.2 with TS 24.229 clause 7.2.13: with
// mcdata.resource_sharing "rx" the session is allowed and its resources left to the PCC deployment, "sip-core" is
// refused like "none"), the SIP INFO correction of a priority re-INVITE within the session (it goes as on demand), FD
// and ad hoc groups over the session, and separate participating and controlling MCData functions.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), TS 37.579-1 V18.1.0 (Rel-18), RFC 3261,
// RFC 3264, RFC 3515, RFC 4488, RFC 4538, RFC 2392, RFC 5366, RFC 4975, RFC 6135, RFC 8839.

#include "data_server.hpp"

namespace mcx {

namespace {

// TS 24.282 clauses 9.2.5.2.2.1 condition 3 and 9.2.5.3.2.1: the communications a REFER over the session starts.
bool pre_session_request_type(const std::string &type) {
  return type == "one-to-one-sds" || type == "one-to-one-sds-session" || type == "group-sds" ||
         type == "group-sds-session";
}

} // namespace

//------------------------------------------------------------------------------
// TS 24.282 clause 18.2: how resource sharing is supported (mcdata.resource_sharing): "none" (the default) refuses
// pre-established sessions; "rx" leaves the resources to the PCC deployment; "sip-core" (TS 24.229 clause 7.2.13) is
// not implemented for MCData and refuses them too.
std::string DataServer::pre_resource_sharing() const {
  const auto mode = cfg_.at("mcdata").value("resource_sharing", std::string("none"));
  if (mode != "none" && mode != "sip-core" && mode != "rx")
    throw std::runtime_error("mcdata.resource_sharing is none, sip-core or rx: TS 24.282 clause 18.2");
  return mode;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 18.3.2.2 step 5: 403 with warning 226 "function not allowed due to pre-established session not
// supported" when resource sharing is not supported (steps 3 and 4). Returns whether it refused.
bool DataServer::pre_session_refused(const SipMessage &request, const User &user, SipResponse &response) {
  (void)request;
  const auto mode = pre_resource_sharing();
  if (mode == "rx") return false;
  response = reject(403, "226 function not allowed due to pre-established session not supported", user.id,
                    "pre-established-session");
  event("mcdata_pre_session_refused",
        {{"user_id", user.id},
         {"reason",
          mode == "none" ? "resource sharing not supported" : "resource sharing by the SIP core not implemented"}});
  return true;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 18.3.1.2 with TS 24.582 clause 12: this function's media of the session: "m=message" on its MSRP
// listener, "a=setup:passive" (the client connects), "a=sendrecv", the MCData signalling and payload types.
MsrpMedia DataServer::pre_session_media(const PreSession &pre) const {
  auto media = pre.local;
  media.setup = "passive";
  media.direction = "sendrecv";
  media.accept_types = {mcdata::signalling_mime, mcdata::payload_mime};
  return media;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 18.3.2.2: a "SIP INVITE request for establishing a pre-established session" (the initial INVITE to
// the participating function's PSI with <pre-established-session-ind> "true", clause 18.3.2.1 step 9). Step 1: the
// PSI is this function's; step 2: the user is the served user the INVITE asserts (media_invite; every authorised
// user may hold a session); steps 3 to 5: pre_session_refused; step 6: an offer that is not an MSRP "m=message" with
// its MSRP URI, or that would listen ("passive"), gets 488; step 7: no listener gets 500; step 8: the URI of the
// session; steps 9 a to c and e: the 200 (OK) with that URI in Contact (with the SDS media feature tags), this
// function's P-Asserted-Identity (the SIP engine's), Supported "norefersub" and the SDP answer of clause 18.3.1.2;
// step 10: the session's MSRP listener (TS 24.582 clause 12), kept for the session's lifetime.
SipResponse DataServer::pre_session_invite(const SipMessage &request, const User &user, const BodyPart &sdp) {
  SipResponse response;
  if (pre_session_refused(request, user, response)) return response;
  MsrpMedia offer;
  try {
    offer = parse_msrp_sdp(sdp.body);
    if (offer.path.empty() || !offer.port) throw std::runtime_error("no MSRP URI in the offer");
    if (offer.setup == "passive") throw std::runtime_error("an offer that listens: both sides would");
  } catch (const std::exception &error) {
    event("mcdata_pre_session_refused", {{"user_id", user.id}, {"reason", error.what()}});
    response.status_code = 488;
    return response;
  }
  auto pre = std::make_shared<PreSession>();
  pre->dialog = request.dialog_id;
  pre->owner = user.id;
  pre->sip = user.sip;
  if (const auto registration = registration_call_ids_.find(user.sip); registration != registration_call_ids_.end())
    pre->registration = registration->second;
  pre->uri = session_service_ + ";mcdata-pre-session=" + random_id();
  pre->endpoint = std::make_shared<msrp::Endpoint>();
  const auto address = media_address();
  try {
    const auto local = pre->endpoint->listen(address, {{},
                                                       [this, dialog = pre->dialog](std::string_view reason) {
                                                         event("mcdata_pre_session_msrp_closed",
                                                               {{"dialog", dialog}, {"reason", std::string(reason)}});
                                                       },
                                                       {},
                                                       {}});
    pre->endpoint->keep_listening();
    pre->local.secure = local.secure;
    pre->local.address = address;
    pre->local.port = local.port;
    pre->local.path = local.text();
  } catch (const std::exception &error) {
    event("mcdata_pre_session_refused", {{"user_id", user.id}, {"reason", error.what()}});
    response.status_code = 500;
    return response;
  }
  pre->local = pre_session_media(*pre);
  pre->sdp = msrp_sdp(pre->local, 1);
  pre_sessions_[pre->dialog] = pre;
  response.status_code = 200;
  response.local_sdp = pre->sdp;
  response.contact_uri = pre->uri;
  response.contact_tags = subservice_tags("sds");
  response.headers = {{"Supported", "norefersub"}};
  count("pre_sessions");
  event("mcdata_pre_session_answered", {{"user_id", user.id},
                                        {"session_uri", pre->uri},
                                        {"dialog", pre->dialog},
                                        {"msrp_port", pre->local.port},
                                        {"ice_offered", sdp.body.find("a=candidate") != std::string::npos}});
  return response;
}

//------------------------------------------------------------------------------
// The session's dialog: confirmed (the ACK of the 200 (OK)), or ended (the client's BYE, clause 18.3.3.2.1; this
// function's, clause 18.3.3.2.2; the SIP core's): the communication over it was released (media_released) and the
// session's MSRP media go (TS 24.582 clause 12).
void DataServer::pre_session_state(const std::string &dialog, SipCallState state) {
  const auto found = pre_sessions_.find(dialog);
  if (found == pre_sessions_.end()) return;
  if (state == SipCallState::confirmed && !found->second->confirmed) {
    found->second->confirmed = true;
    event("mcdata_pre_session_established",
          {{"user_id", found->second->owner}, {"session_uri", found->second->uri}, {"dialog", dialog}});
  } else if (state == SipCallState::disconnected) {
    found->second->endpoint->close();
    event("mcdata_pre_session_released",
          {{"user_id", found->second->owner}, {"session_uri", found->second->uri}, {"dialog", dialog}});
    pre_sessions_.erase(found);
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 18.3.3.2.2 with clause 7.3: the pre-established sessions of a user are bound to the service
// authorisation and the registration they were established under (clause 18.3.2.2 steps 2 and 5). They are released
// when that binding ends (log-off, deregistration, end of the authorisation), when a new service authorisation
// replaces it (a client started again), or, with keep_registration, when the UE registers again with another Call-ID:
// the sessions established under another registration go. BYE in the session's dialog; the client may be gone, so the
// communication over the session and its media go at once (no communication is offered over it any more).
void DataServer::pre_sessions_end(const std::string &owner, const std::string &reason,
                                  const std::optional<std::string> &keep_registration) {
  std::vector<std::string> ended;
  for (const auto &[dialog, pre] : pre_sessions_)
    if (pre->owner == owner &&
        (!keep_registration || (!pre->registration.empty() && pre->registration != *keep_registration)))
      ended.push_back(dialog);
  for (const auto &dialog : ended) pre_session_end(dialog, reason);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 18.3.3.2.2: this function releases one session its client can no longer use (pre_sessions_end).
void DataServer::pre_session_end(const std::string &dialog, const std::string &reason) {
  const auto found = pre_sessions_.find(dialog);
  if (found == pre_sessions_.end()) return;
  event("mcdata_pre_session_ended", {{"user_id", found->second->owner}, {"dialog", dialog}, {"reason", reason}});
  try {
    sip_.bye(dialog, {}, {{"P-Asserted-Identity", "<" + service_uri_ + ">"}});
  } catch (const std::exception &error) {
    event("mcdata_pre_session_bye_failed", {{"user_id", found->second->owner}, {"reason", error.what()}});
  }
  media_released(dialog);
  pre_session_state(dialog, SipCallState::disconnected);
}

//------------------------------------------------------------------------------
// The client's re-INVITE or UPDATE in the session's dialog: TS 24.282 clause 18.3.4.2.1 (a modification, or a
// session refresh): 200 (OK) with the session's SDP answer, the session unchanged; during a communication over the
// session, a re-INVITE carrying MCData-Info is that communication's (media_reinvite). Empty for other dialogs.
std::optional<SipResponse> DataServer::pre_session_in_dialog(const SipMessage &request) {
  const auto found = pre_sessions_.find(request.dialog_id);
  if (found == pre_sessions_.end()) return std::nullopt;
  if (request.method == "INVITE" && part(request, mcdata::info_mime))
    if (const auto leg = media_session(request.dialog_id)) {
      // TS 24.282 clauses 9.2.5.2.2.3 and 6.3.7.1.18 (and the group communication's re-INVITE, 9.2.4.4.4): the
      // upgrade or cancellation of the communication's priority, handled by the collocated controlling function; the
      // 200 (OK) with the session's media and the participating function's P-Asserted-Identity (step 4 of the 200).
      auto response = media_reinvite(request, leg);
      if (response.status_code / 100 == 2) {
        response.local_sdp = found->second->sdp;
        response.headers.push_back({"P-Asserted-Identity", "<" + service_uri_ + ">"});
      }
      return response;
    }
  SipResponse response;
  response.status_code = 200;
  response.local_sdp = found->second->sdp;
  event("mcdata_pre_session_modified", {{"user_id", found->second->owner},
                                        {"method", request.method},
                                        {"offer", static_cast<bool>(part(request, "application/sdp"))}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.5.2.2.1 condition 1 and 9.2.5.4.2.1: the session a REFER is for: its Request-URI, the URI
// identifying the session; else the session its Target-Dialog names (RFC 4538).
std::shared_ptr<DataServer::PreSession> DataServer::pre_session_of_refer(const SipMessage &request) const {
  for (const auto &[dialog, pre] : pre_sessions_) {
    const auto tag = pre->uri.substr(pre->uri.find(";mcdata-pre-session="));
    if (request.request_uri == pre->uri || request.request_uri.find(tag) != std::string::npos) return pre;
  }
  if (const auto value = get_header(request.headers, "Target-Dialog"); !value.empty()) {
    try {
      const auto named = parse_target_dialog(value);
      for (const auto &[dialog, pre] : pre_sessions_)
        if (const auto ids = sip_.dialog_identifiers(dialog); ids && ids->call_id == named.call_id) return pre;
    } catch (const std::exception &) {
      return nullptr;
    }
  }
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.5.2.2.1 (one-to-one), 9.2.5.3.2.1 (group) and 9.2.5.4.2.1 (method "BYE"): a SIP REFER request
// outside a dialog to the session's URI. Steps 2 and 3 (9.2.5.4.2.1 steps 1 and 2): the calling user's binding, or
// 404 with warning 141; step 4 i: the user's authorisation to transmit, or 403 with warning 200; step 5: a REFER
// whose Refer-To names no resource list (or an entry this function cannot read) gets 403 with warning 145; a session
// not the user's or not established gets 481 (RFC 3515 section 2.4.3), one already carrying a communication 486;
// step 7: the controlling function is this server; steps 8 to 10 (9.2.5.4.2.1 steps 3 to 5): 200 (OK) without an
// implicit subscription (RFC 4488: Refer-Sub "false" when the REFER had it, Supported "norefersub"), with this
// function's P-Asserted-Identity. The communication (pre_session_originate) or the leave (pre_session_leave) follows
// the 200 (OK).
SipResponse DataServer::pre_session_refer(const SipMessage &request) {
  const auto asserted = asserted_identity(request);
  const auto found = users_.find(asserted);
  if (asserted.empty() || found == users_.end() || found->second.expires <= std::time(nullptr))
    return reject(404, "141 user unknown to the participating function", asserted, "pre-established-refer");
  const auto &user = found->second;
  SipResponse response;
  const auto pre = pre_session_of_refer(request);
  if (!pre || pre->sip != user.sip || !pre->confirmed) {
    response.status_code = 481;
    event("mcdata_pre_refer_refused", {{"user_id", user.id}, {"reason", "no such pre-established session"}});
    return response;
  }
  PreEstablishedReferRequest refer;
  try {
    refer = parse_pre_established_refer(request.headers, request.parts);
  } catch (const std::exception &error) {
    event("mcdata_pre_refer_refused", {{"user_id", user.id}, {"reason", error.what()}});
    return reject(403, "145 unable to determine called party", user.id, "pre-established-refer");
  }
  response.status_code = 200;
  response.headers = {{"Supported", "norefersub"}, {"P-Asserted-Identity", "<" + service_uri_ + ">"}};
  if (refer_without_subscription(request.headers) ||
      get_header(request.headers, "Refer-Sub").find("false") != std::string_view::npos)
    response.headers.push_back({"Refer-Sub", "false"});
  if (refer.leave) {
    if (pre->communication.empty()) {
      response = SipResponse{};
      response.status_code = 481;
      return response;
    }
    count("pre_session_leaves");
    event("mcdata_pre_leave_requested",
          {{"user_id", user.id}, {"session_identity", refer.session_identity}, {"dialog", pre->dialog}});
    pending_.push_back([this, dialog = pre->dialog] { pre_session_leave(dialog); });
    return response;
  }
  if (!pre->communication.empty() || media_session(pre->dialog)) {
    response = SipResponse{};
    response.status_code = 486;
    event("mcdata_pre_refer_refused", {{"user_id", user.id}, {"reason", "the session carries a communication"}});
    return response;
  }
  if (!profile(user.id).value("mcdata", Json::object()).value("transmit_data", false))
    return reject(403, "200 user not authorised to transmit data", user.id, "pre-established-refer");
  // The entry's bodies, opened as the client protected them (TS 24.282 clause 6.5.2: the bodies under its CSK, the
  // XML encrypted with it); its MCData-Info is what the INVITE of clause 9.2.5.1.1 step 9 a) carries.
  SipMessage entry_bodies;
  entry_bodies.method = "REFER";
  entry_bodies.parts = std::move(refer.entry.body);
  if (auto refused = open_signalling(user.sip, entry_bodies)) return *refused;
  refer.entry.body = std::move(entry_bodies.parts);
  mcdata::Info info;
  BodyPart *entry_info = nullptr;
  try {
    for (auto &part : refer.entry.body)
      if (part.content_type == mcdata::info_mime) {
        entry_info = &part;
        info = mcdata::parse_info(part.body);
      }
    // The priority indications of the REFER's own MCData-Info (TS 24.282 clause 9.2.5.2.1.1 1a), 9.2.5.3.2.1 6A)),
    // where the entry's has none: the INVITE to the controlling function carries them.
    if (const auto *own = part(request, mcdata::info_mime)) {
      const auto top = mcdata::parse_info(own->body);
      if (!info.emergency) info.emergency = top.emergency;
      if (!info.imminent_peril) info.imminent_peril = top.imminent_peril;
      if (!info.alert) info.alert = top.alert;
    }
  } catch (const std::exception &error) {
    event("mcdata_pre_refer_refused", {{"user_id", user.id}, {"reason", error.what()}});
    return reject(403, "145 unable to determine called party", user.id, "pre-established-refer");
  }
  if (!entry_info) return reject(403, "145 unable to determine called party", user.id, "pre-established-refer");
  if (auto refused = pre_session_priority_refused(user, info, refer.entry.target)) return *refused;
  entry_info->body = mcdata::info_xml(info);
  // TS 24.282 clause 6.3.7.1.18 step 4 c) as clause 9.2.5.1.1 does for the entry: the location information of an
  // emergency alert, a body of the REFER itself (the client's, clause 6.2.8.1.1 3) b)), goes with the INVITE.
  std::vector<BodyPart> location;
  for (const auto &body : request.parts)
    if (body.content_type == mcdata::location_mime) location.push_back(body);
  pre->communication = "originating";
  count("pre_session_refers");
  event("mcdata_pre_refer", {{"user_id", user.id},
                             {"target", refer.entry.target},
                             {"dialog", pre->dialog},
                             {"emergency", info.emergency ? Json(*info.emergency) : Json(nullptr)},
                             {"imminent", info.imminent_peril ? Json(*info.imminent_peril) : Json(nullptr)},
                             {"alert", info.alert ? Json(*info.alert) : Json(nullptr)},
                             {"resource_priority", std::string(get_header(request.headers, "Resource-Priority"))}});
  pending_.push_back(
      [this, dialog = pre->dialog, entry = std::move(refer.entry), location = std::move(location)]() mutable {
        pre_session_originate(dialog, std::move(entry), std::move(location));
      });
  return response;
}

//------------------------------------------------------------------------------
// The priority of a REFER over the session: TS 24.282 clause 9.2.5.3.2.1 steps 6A (clause 6.3.7.1.9: an invalid
// combination of the indications, 403 with warning 150) and 6B (a), c): an unauthorised emergency or imminent peril
// group communication, clauses 6.3.7.2.6 and 6.3.7.2.4, 403 with warning 233 or 236 and the refused indications, as
// on demand; b): an unauthorised emergency alert, clause 6.3.7.2.1, 403); clause 9.2.5.2.2.1 steps 4 ii and iii (a
// one-to-one communication: 403 with warning 233 without <allow-emergency-private-call>, 236 for an imminent peril
// one, which TS 24.282 defines for groups only). None: the request may go on.
std::optional<SipResponse> DataServer::pre_session_priority_refused(const User &user, const mcdata::Info &info,
                                                                    const std::string &target) {
  if (!info.emergency && !info.imminent_peril && info.alert != true) return std::nullopt;
  if (!valid_priority_combination(info))
    return reject(403, "150 invalid combinations of data received in MIME body", user.id, "pre-established-priority");
  if (info.request_type.starts_with("group-")) {
    const auto group = info.request_uri.empty() ? target : info.request_uri;
    if (info.emergency == true && !priority_authorised(user.id, group, true, true))
      return reject_priority(user.id, true);
    if (info.alert == true && !alert_authorised(user.id, group))
      return reject(403, "", user.id, "pre-established-alert");
    if (info.imminent_peril == true && !priority_authorised(user.id, group, false, true))
      return reject_priority(user.id, false);
    return std::nullopt;
  }
  if (info.emergency == true && !profile(user.id).value("mcdata", Json::object()).value("emergency_private", false))
    return reject(403, "233 user not authorised to initiate emergency communication", user.id,
                  "pre-established-priority");
  if (info.imminent_peril == true)
    return reject(403, "236 user not authorised to initiate imminent peril communication", user.id,
                  "pre-established-priority");
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.5.1.1 (steps 11 to 14 of clauses 9.2.5.2.2.1 and 9.2.5.3.2.1): the INVITE built from the REFER's
// entry: its SDP offer (the session's MSRP media, with the PCK of a one-to-one communication) and MCData-Info, the
// entry's bodies opened as the client protected them (TS 24.282 clause 6.5.2: under its CSK), the called user in a
// resource list (one-to-one) or the group in <mcdata-request-uri>; this server's controlling role handles it as a
// client's own INVITE (media_invite). Upon its 200 (OK) (clause 9.2.5.2.2.1, 2xx steps 1 and 2 a): the communication's
// leg takes the session's MSRP media (TS 24.582 clause 12) and the re-INVITE of clause 9.2.5.1.2 with
// <mcdata-communication-state> "establish-success" goes to the client, the MCData session identity in its Contact
// (as clause 9.2.5.2.2.2 step 3 iii names it to a terminating client); upon an error response, "establish-fail".
void DataServer::pre_session_originate(const std::string &dialog, ReferEntry entry, std::vector<BodyPart> location) {
  const auto found = pre_sessions_.find(dialog);
  if (found == pre_sessions_.end()) return;
  const auto pre = found->second;
  const auto fail = [&](const std::string &reason, int status) {
    event("mcdata_pre_communication_failed", {{"user_id", pre->owner}, {"reason", reason}, {"status", status}});
    pre->communication.clear();
    pre_session_reinvite(pre, "establish-fail", {}, "<" + pre->uri + ">" + subservice_tags("sds"));
  };
  SipMessage invite;
  invite.method = "INVITE";
  invite.request_uri = service_uri_;
  invite.from_uri = pre->sip;
  invite.to_uri = service_uri_;
  invite.call_id = invite.dialog_id = dialog;
  invite.source_address = core_address_;
  invite.transaction_id = "pre-established";
  invite.headers = {{"P-Asserted-Identity", "<" + pre->sip + ">"}, {"P-Asserted-Service", mcdata::sds_icsi}};
  invite.parts = std::move(entry.body); // opened by pre_session_refer
  for (auto &body : location) invite.parts.push_back(std::move(body));
  std::string request_type;
  for (auto &part : invite.parts) {
    if (part.content_type != mcdata::info_mime) continue;
    try {
      auto info = mcdata::parse_info(part.body);
      request_type = info.request_type;
      // TS 24.282 clause 9.2.5.1.1: a group communication names the group in <mcdata-request-uri>.
      if (request_type.starts_with("group-") && info.request_uri.empty()) info.request_uri = entry.target;
      part.body = mcdata::info_xml(info);
    } catch (const std::exception &error) {
      return fail(error.what(), 400);
    }
  }
  if (!pre_session_request_type(request_type)) return fail("not an SDS communication: " + request_type, 403);
  // The one-to-one communication's called user, as the client's own INVITE names it (TS 24.282 clause 9.2.3.2.3).
  if (request_type.starts_with("one-to-one-"))
    invite.parts.push_back({resource_lists_mime, private_call_resource_list(entry.target)});
  SipResponse answer;
  try {
    answer = media_invite(invite);
  } catch (const std::exception &error) {
    media_.erase(dialog);
    return fail(error.what(), 500);
  }
  const auto leg = media_session(dialog);
  if (answer.status_code / 100 != 2 || !leg) {
    media_.erase(dialog);
    return fail(std::string(get_header(answer.headers, "Warning")), answer.status_code);
  }
  // TS 24.582 clause 12: the communication uses the session's MSRP media; the listener media_invite opened goes.
  leg->endpoint = pre->endpoint;
  leg->endpoint->set_callbacks(media_callbacks(leg));
  leg->sdp = pre->sdp;
  pre->identity = answer.contact_uri.empty() ? session_identity(leg->key) : answer.contact_uri;
  mcdata::Info info;
  for (const auto &part : answer.parts)
    if (part.content_type == mcdata::info_mime) info = mcdata::parse_info(part.body);
  std::vector<SipHeader> headers;
  if (const auto priority = get_header(answer.headers, "Resource-Priority"); !priority.empty())
    headers.push_back({"Resource-Priority", std::string(priority)});
  count("pre_session_communications");
  event("mcdata_pre_communication", {{"user_id", pre->owner},
                                     {"direction", "originating"},
                                     {"request_type", request_type},
                                     {"target", entry.target},
                                     {"identity", pre->identity},
                                     {"dialog", dialog}});
  // The client refusing the re-INVITE ends the communication; the session stays.
  pre_session_reinvite(pre, "establish-success", info, focus_contact(pre->identity, "sds"), headers, {},
                       [this, dialog](const SipResponse &response) {
                         if (response.status_code / 100 == 2) return;
                         pending_.push_back([this, dialog] {
                           media_released(dialog);
                           if (const auto found = pre_sessions_.find(dialog); found != pre_sessions_.end())
                             pre_session_idle(*found->second);
                         });
                       });
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.5.4.2.1 (after the 200 (OK) to the REFER "BYE"): the user leaves the communication: its leg
// in the collocated controlling function ends as if its dialog had (steps 6 and 7, the BYE to the controlling
// function: media_released, with the release policy of clause 13.2.2.2.4.3), the session's MSRP media are kept
// (TS 24.582 clause 12), and the re-INVITE of clause 9.2.5.1.2 with <mcdata-communication-state> "terminated" goes
// to the client, the session's own URI in its Contact again.
void DataServer::pre_session_leave(const std::string &dialog) {
  const auto found = pre_sessions_.find(dialog);
  if (found == pre_sessions_.end()) return;
  const auto pre = found->second;
  media_released(dialog);
  pre_session_idle(*pre);
  event("mcdata_pre_communication_left", {{"user_id", pre->owner}, {"dialog", dialog}});
  pre_session_reinvite(pre, "terminated", {}, "<" + pre->uri + ">" + subservice_tags("sds"));
}

//------------------------------------------------------------------------------
// The session is free again: no communication, the MSRP media waiting for the next connection.
void DataServer::pre_session_idle(PreSession &pre) {
  pre.communication.clear();
  pre.identity.clear();
  pre.endpoint->set_callbacks({{},
                               [this, dialog = pre.dialog](std::string_view reason) {
                                 event("mcdata_pre_session_msrp_closed",
                                       {{"dialog", dialog}, {"reason", std::string(reason)}});
                               },
                               {},
                               {}});
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.5.1.2 and 9.2.5.1.3: a re-INVITE in the session's dialog: the MCData-Info with
// <mcdata-communication-state> state (none for a modification, clause 18.3.4), protected for the client (TS 24.282
// clause 6.5.2.4.1), Contact the MCData session identity or the session's URI, this function's P-Asserted-Identity
// and the SDS P-Asserted-Service, and as its offer the session's SDP (or sdp). One at a time (RFC 3261 section 14.1):
// a re-INVITE while another is pending waits for its final response.
void DataServer::pre_session_reinvite(const std::shared_ptr<PreSession> &pre, const std::string &state,
                                      mcdata::Info info, const std::string &contact, std::vector<SipHeader> headers,
                                      std::string sdp, SipResponseHandler handler) {
  std::vector<BodyPart> parts;
  if (!state.empty()) {
    info.communication_state = state;
    try {
      parts = seal_for(pre->sip, {{mcdata::info_mime, mcdata::info_xml(info)}});
    } catch (const CskExpired &error) {
      csk_expired_not_sent(pre->owner, "pre-established re-INVITE", error);
      return;
    }
  }
  pre_session_reinvite_parts(pre, std::move(parts), contact, std::move(headers), std::move(sdp), std::move(handler),
                             state);
}

//------------------------------------------------------------------------------
// Helper: the re-INVITE of pre_session_reinvite with its parts protected already (those of media_deliver).
void DataServer::pre_session_reinvite_parts(const std::shared_ptr<PreSession> &pre, std::vector<BodyPart> parts,
                                            const std::string &contact, std::vector<SipHeader> headers, std::string sdp,
                                            SipResponseHandler handler, std::string state) {
  if (pre->offer_pending) {
    pre->waiting.push_back([this, pre, parts, contact, headers, sdp, handler, state] {
      pre_session_reinvite_parts(pre, parts, contact, headers, sdp, handler, state);
    });
    return;
  }
  if (!pre_sessions_.contains(pre->dialog)) return;
  headers.push_back({"Contact", contact});
  headers.push_back({"P-Asserted-Identity", "<" + service_uri_ + ">"});
  headers.push_back({"P-Asserted-Service", mcdata::sds_icsi});
  pre->offer_pending = true;
  const auto dialog = pre->dialog;
  try {
    sip_.reinvite_sdp(
        dialog, sdp.empty() ? pre->sdp : sdp, parts,
        [this, dialog, state, owner = pre->owner, handler](const SipResponse &response) {
          event("mcdata_pre_session_reinvite",
                {{"user_id", owner}, {"state", state}, {"status", response.status_code}});
          if (handler) handler(response);
          pending_.push_back([this, dialog] { pre_session_reinvite_done(dialog); });
        },
        headers);
    event("mcdata_pre_session_reinvite_sent", {{"user_id", pre->owner}, {"state", state}, {"dialog", dialog}});
  } catch (const std::exception &error) {
    pre->offer_pending = false;
    event("mcdata_pre_session_reinvite_failed", {{"user_id", pre->owner}, {"state", state}, {"reason", error.what()}});
    if (handler) {
      SipResponse failed;
      failed.status_code = 500;
      handler(failed);
    }
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.5.2.2.4 and 9.2.5.3 (6.3.7.1.17: the terminating participating function relays the controlling
// function's re-INVITE that upgrades or cancels the priority of the communication, its MCData-Info, Resource-Priority
// and the session's media): on a leg over a pre-established session, a re-INVITE in the session's dialog with no
// <mcdata-communication-state> (the communication in use), the communication's MCData session identity in Contact;
// on another leg, the re-INVITE in its own dialog.
void DataServer::reinvite_leg(const std::string &dialog, const std::string &sdp, std::vector<BodyPart> parts,
                              std::vector<SipHeader> headers) {
  const auto found = pre_sessions_.find(dialog);
  if (found == pre_sessions_.end()) return sip_.reinvite_sdp(dialog, sdp, parts, {}, headers);
  const auto pre = found->second;
  std::erase_if(headers, [](const SipHeader &header) { return header.name == "Contact"; });
  pre_session_reinvite_parts(
      pre, std::move(parts), focus_contact(pre->identity, "sds"), std::move(headers), pre->sdp,
      [this, owner = pre->owner](const SipResponse &response) {
        event("mcdata_pre_priority_relayed", {{"user_id", owner}, {"status", response.status_code}});
      },
      "priority");
}

//------------------------------------------------------------------------------
// Helper: the session's re-INVITE is answered: the next one waiting goes.
void DataServer::pre_session_reinvite_done(const std::string &dialog) {
  const auto found = pre_sessions_.find(dialog);
  if (found == pre_sessions_.end()) return;
  const auto pre = found->second;
  pre->offer_pending = false;
  if (pre->waiting.empty()) return;
  auto next = std::move(pre->waiting.front());
  pre->waiting.pop_front();
  next();
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.5.2.2.2 and 9.2.5.3.2.2: the user's established session that a communication may be offered
// over: confirmed, not carrying one, with no re-INVITE pending; null when there is none.
std::shared_ptr<DataServer::PreSession> DataServer::pre_session_free(const std::string &user_id) const {
  for (const auto &[dialog, pre] : pre_sessions_)
    if (pre->owner == user_id && pre->confirmed && pre->communication.empty() && !pre->offer_pending &&
        !media_.contains(dialog))
      return pre;
  return nullptr;
}

//------------------------------------------------------------------------------
// A media plane leg ends: BYE in its dialog. A leg over a pre-established session keeps the session: the controlling
// function's BYE reaches the collocated participating function (TS 24.282 clause 9.2.5.4.2.2, whichever side started
// the communication): the re-INVITE of clause 9.2.5.1.2 with <mcdata-communication-state> "terminate-request", the
// session's URI in its Contact again; the media plane resources of the communication released (TS 24.582 clause 12:
// the client closes its MSRP connection, the session's listener stays).
void DataServer::end_media_leg(const std::string &dialog, const std::vector<SipHeader> &headers) {
  const auto found = pre_sessions_.find(dialog);
  if (found == pre_sessions_.end()) return sip_.bye(dialog, {}, headers);
  const auto pre = found->second;
  if (pre->communication.empty()) return;
  pre_session_idle(*pre);
  event("mcdata_pre_communication_released", {{"user_id", pre->owner}, {"dialog", dialog}});
  // The release reason of a BYE (TS 24.282 clause 13.2.3.2.4) is not carried: clause 9.2.5.4.2.2 names none.
  (void)headers;
  pre_session_reinvite(pre, "terminate-request", {}, "<" + pre->uri + ">" + subservice_tags("sds"));
}

//------------------------------------------------------------------------------
// The sessions' MSRP media outside a communication: accepted, read and closed (a communication's leg polls them
// during it, media_tick).
void DataServer::pre_session_tick() {
  for (const auto &[dialog, pre] : pre_sessions_) {
    const auto leg = media_.find(dialog);
    if (leg == media_.end() || leg->second->endpoint != pre->endpoint) pre->endpoint->poll();
  }
}

//------------------------------------------------------------------------------
// The operator's commands: "pre-session-release <MCData ID|all>" (TS 24.282 clause 18.3.3.2.2: BYE in the session's
// dialog; a communication over it is released with it, TS 24.582 clause 12) and "pre-session-modify <MCData ID|all>"
// (a re-INVITE in the session with its SDP, clause 18.3.4: the client answers as in clause 18.3.4.1.2).
void DataServer::pre_session_command(const std::string &command) {
  std::istringstream words(command);
  std::string verb, which;
  words >> verb >> which;
  std::vector<std::shared_ptr<PreSession>> sessions;
  for (const auto &[dialog, pre] : pre_sessions_)
    if (pre->confirmed && (which == "all" || pre->owner == which)) sessions.push_back(pre);
  if (sessions.empty()) event("mcdata_pre_session_command_unknown", {{"command", command}});
  for (const auto &pre : sessions) {
    if (verb == "pre-session-release") {
      event("mcdata_pre_session_release", {{"user_id", pre->owner}, {"dialog", pre->dialog}});
      sip_.bye(pre->dialog, {}, {{"P-Asserted-Identity", "<" + service_uri_ + ">"}});
    } else if (verb == "pre-session-modify") {
      pre_session_reinvite(pre, {}, {}, "<" + pre->uri + ">" + subservice_tags("sds"), {}, {},
                           [this, owner = pre->owner](const SipResponse &response) {
                             event("mcdata_pre_session_modified_by_server",
                                   {{"user_id", owner}, {"status", response.status_code}});
                           });
    } else {
      event("mcdata_pre_session_command_unknown", {{"command", command}});
      return;
    }
  }
}

//------------------------------------------------------------------------------
// The sessions in the status file.
Json DataServer::pre_session_status() const {
  auto out = Json::array();
  for (const auto &[dialog, pre] : pre_sessions_)
    out.push_back({{"user_id", pre->owner},
                   {"uri", pre->uri},
                   {"dialog", dialog},
                   {"confirmed", pre->confirmed},
                   {"communication", pre->communication},
                   {"identity", pre->identity},
                   {"msrp_port", pre->local.port},
                   {"connected", pre->endpoint->connected()}});
  return out;
}

} // namespace mcx
