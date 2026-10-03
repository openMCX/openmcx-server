// Release of MCData communications over the media plane, with or without prior indication, and their extension.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clause 13.2.4.4.1 step 4: the Reason header field value, with the reason-text given (its quotes and
// backslashes replaced by spaces).
std::string DataServer::reason_header(const std::string &text) {
  std::string quoted;
  for (const char character : text) quoted += character == '"' || character == '\\' ? ' ' : character;
  return "SIP;cause=200;text=\"" + quoted + "\"";
}

//------------------------------------------------------------------------------
// Helper: the reason-text of a Reason header field value; the whole value when it has none.
std::string DataServer::reason_text(const std::string &header) {
  const auto start = header.find("text=\"");
  if (start == std::string::npos) return header;
  const auto end = header.find('"', start + 6);
  return header.substr(start + 6, end == std::string::npos ? std::string::npos : end - start - 6);
}

//------------------------------------------------------------------------------
// Helper: the leg of the originator of a communication, or null.
std::shared_ptr<DataServer::MediaSession> DataServer::originating_leg(const std::string &key) {
  for (auto &[dialog, leg] : media_)
    if (leg->key == key && leg->originating) return leg;
  return nullptr;
}

//------------------------------------------------------------------------------
// Helper: the leg of a user in a communication, or null.
std::shared_ptr<DataServer::MediaSession> DataServer::leg_of(const std::string &key, const std::string &owner) {
  for (auto &[dialog, leg] : media_)
    if (leg->key == key && leg->owner == owner) return leg;
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 13.2.2.2.4.4 and 13.2.3.2.4: every leg of the communication is released with
// BYE, carrying the reason when the server or an authorised user decided it.
void DataServer::release_communication(const std::string &key, const std::string &reason, const char *counter) {
  std::vector<std::string> dialogs;
  for (const auto &[dialog, leg] : media_)
    if (leg->key == key) dialogs.push_back(dialog);
  if (dialogs.empty()) return;
  std::vector<SipHeader> headers;
  if (!reason.empty()) headers.push_back({"Reason", reason_header(reason)});
  for (const auto &dialog : dialogs) {
    media_.erase(dialog);
    pending_.push_back([this, dialog, headers] { sip_.bye(dialog, {}, headers); });
  }
  releases_.erase(key);
  count(counter);
  event("mcdata_communication_released", {{"key", key}, {"reason", reason}, {"legs", dialogs.size()}});
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 13.2.3.2 and 13.2.5.2, applied to IP connectivity: the same for an IP connectivity session.
// By value: the caller's pointer may be the map entry that is erased here.
void DataServer::release_tunnel(std::shared_ptr<IpconSession> tunnel, const std::string &reason, const char *counter) {
  ipcons_.erase(tunnel->origin_dialog);
  ipcons_.erase(tunnel->target_dialog);
  const std::vector<SipHeader> headers{{"Reason", reason_header(reason)}};
  for (const auto &dialog : {tunnel->origin_dialog, tunnel->target_dialog})
    if (!dialog.empty()) pending_.push_back([this, dialog, headers] { sip_.bye(dialog, {}, headers); });
  count(counter);
  event("mcdata_ipconn_released", {{"user_id", tunnel->originator}, {"target", tunnel->target}, {"reason", reason}});
}

//------------------------------------------------------------------------------
// TS 24.282 clause 13.2.4.4.1 steps 1 to 5 and annex H.1.2: a SIP INFO request of the g.3gpp.mcdata-com-release
// package on one leg, its bodies protected for the user of the leg.
void DataServer::send_com_release(const std::string &dialog, const std::vector<BodyPart> &parts,
                                  const std::string &reason, std::function<void(const SipResponse &)> answered) {
  std::vector<SipHeader> headers{{"Info-Package", mcdata::com_release_package},
                                 {"Content-Disposition", "Info-Package"},
                                 {"P-Asserted-Identity", "<" + service_uri_ + ">"}};
  if (!reason.empty()) headers.push_back({"Reason", reason_header(reason)});
  pending_.push_back([this, dialog, clear = parts, headers, answered] {
    try {
      auto parts = clear;
      if (const auto leg = media_session(dialog))
        if (const auto *owner = by_id(leg->owner)) parts = seal_for(owner->sip, std::move(parts));
      if (parts.size() == 1) {
        sip_.request_in_dialog(dialog, "INFO", parts.front().content_type, parts.front().body, headers,
                               [answered](const SipResponse &response) {
                                 if (answered) answered(response);
                               });
      } else {
        const std::string boundary = "mcdata-com-release";
        sip_.request_in_dialog(dialog, "INFO", "multipart/mixed;boundary=" + boundary, multipart_body(parts, boundary),
                               headers, [answered](const SipResponse &response) {
                                 if (answered) answered(response);
                               });
      }
    } catch (const std::exception &error) {
      event("mcdata_media_failed", {{"reason", error.what()}, {"dialog", dialog}});
    }
  });
}

//------------------------------------------------------------------------------
// TS 24.282 clause 13.2.4.4.1: the intent to release goes to the originator of the communication,
// and TDC3 starts when it has been accepted.
bool DataServer::release_intent_media(const std::string &key, const std::string &initiator, const std::string &reason,
                                      bool query) {
  const auto origin = originating_leg(key);
  if (!origin || releases_.contains(key)) return false;
  auto &process = releases_[key];
  process.initiator = initiator;
  process.reason = reason;
  mcdata::CommunicationRelease intent;
  intent.type = mcdata::CommReleaseType::IntentToRelease;
  intent.remaining_data_query = query;
  send_com_release(origin->dialog, {{mcdata::signalling_mime, mcdata::encode(intent)}}, reason,
                   [this, key](const SipResponse &response) {
                     if (response.status_code >= 200 && response.status_code < 300)
                       if (auto found = releases_.find(key);
                           found != releases_.end() && !found->second.extension_requested)
                         found->second.tdc3 = monotonic_ms() + release_config().value("tdc3_ms", 15000u);
                   });
  count("release_intents");
  event("mcdata_release_intent",
        {{"key", key}, {"originator", origin->owner}, {"initiator", initiator}, {"reason", reason}, {"query", query}});
  return true;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 13.2.4.4.4: the answer to an extension request. An accepted extension starts
// the limits of the communication again; a refused one releases it.
void DataServer::extension_response(const std::string &key, bool accepted) {
  const auto origin = originating_leg(key);
  if (!origin) return;
  const auto reason = releases_.contains(key) ? releases_.at(key).reason : std::string{};
  mcdata::CommunicationRelease answer;
  answer.type = mcdata::CommReleaseType::ExtensionResponse;
  answer.extension = accepted ? mcdata::ExtensionResponse::Accepted : mcdata::ExtensionResponse::Rejected;
  send_com_release(origin->dialog, {{mcdata::signalling_mime, mcdata::encode(answer)}}, {},
                   [this, key, accepted, reason](const SipResponse &) {
                     if (!accepted)
                       release_communication(key, reason.empty() ? "extension refused" : reason, "releases_server");
                   });
  if (accepted) {
    origin->started = monotonic_ms();
    origin->relayed_bytes = 0;
    releases_.erase(key);
  }
  count(accepted ? "extensions_accepted" : "extensions_rejected");
  event("mcdata_release_extension", {{"key", key}, {"accepted", accepted}});
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 13.2.4.4.2, 13.2.4.4.3, 13.2.5.2.4 and 13.2.6.2.4: a SIP INFO request of the
// g.3gpp.mcdata-com-release package from a client inside its communication.
SipResponse DataServer::com_release_info(const SipMessage &sip_request) {
  SipResponse response;
  response.status_code = 200;
  const auto leg = media_session(sip_request.dialog_id);
  const auto tunnel_entry = ipcons_.find(sip_request.dialog_id);
  if (!leg && tunnel_entry == ipcons_.end()) {
    response.status_code = 481;
    return response;
  }
  const auto parts =
      sip_request.parts.empty() ? parse_body_parts(sip_request.content_type, sip_request.body) : sip_request.parts;
  const BodyPart *signalling = nullptr, *payload = nullptr;
  for (const auto &part : parts) {
    if (part.content_type == mcdata::signalling_mime)
      signalling = &part;
    else if (part.content_type == mcdata::payload_mime)
      payload = &part;
  }
  const auto reason = reason_text(std::string(get_header(sip_request.headers, "Reason")));
  if (!leg) {
    // IP connectivity: only the release by an authorised user without prior
    // indication is implemented (TS 24.282 clause 13.2.5.2).
    const auto tunnel = tunnel_entry->second;
    if (auto refused = com_release_tunnel(sip_request, tunnel, signalling, reason)) return *refused;
    return response;
  }
  const auto key = leg->key;
  if (key.empty()) return reject(403, "", leg->owner, "com-release");
  if (payload) {
    if (auto refused = com_release_remaining(*leg, key, *payload)) return *refused;
    return response;
  }
  mcdata::CommunicationRelease request;
  try {
    if (!signalling) throw std::runtime_error("no COMMUNICATION RELEASE");
    request = mcdata::decode_communication_release(signalling->body);
  } catch (const std::exception &error) {
    event("mcdata_com_release_rejected", {{"user_id", leg->owner}, {"reason", error.what()}});
    return reject(403, "", leg->owner, "com-release");
  }
  // <allow-release-any-user> is read only when a request needs it (TS 24.282 clause 13.2.5.2.4.1
  // step 2a, clause 13.2.6.2.4.1 step 2a: "based on configuration").
  const auto authorised_user = [&] {
    if (!by_id(leg->owner)) return false;
    return profile(leg->owner).value("mcdata", Json::object()).value("release_any_user", false);
  };
  switch (request.type) {
  case mcdata::CommReleaseType::AuthUserReleaseRequest:
    // TS 24.282 clause 13.2.5.2.4.1: an authorised participant releases the communication at once.
    if (!authorised_user()) return reject(403, "", leg->owner, "com-release");
    pending_.push_back([this, key, reason] {
      release_communication(key, reason.empty() ? "released by an authorised MCData user" : reason,
                            "releases_authorised");
    });
    return response;
  case mcdata::CommReleaseType::IntentToRelease:
    // TS 24.282 clause 13.2.6.2.4.1: an authorised participant announces the release to the originator.
    if (!authorised_user() || leg->originating || releases_.contains(key))
      return reject(403, "", leg->owner, "com-release");
    release_intent_media(key, leg->owner, reason.empty() ? "release announced by an authorised MCData user" : reason,
                         request.remaining_data_query);
    return response;
  case mcdata::CommReleaseType::ExtensionRequest: {
    if (auto refused = com_release_extension_request(*leg, key, *signalling)) return *refused;
    return response;
  }
  case mcdata::CommReleaseType::ExtensionResponse: {
    // TS 24.282 clause 13.2.6.2.4.4: the authorised user's answer goes to the originator.
    auto found = releases_.find(key);
    if (found == releases_.end() || found->second.initiator != leg->owner || !found->second.extension_requested ||
        !request.extension)
      return reject(403, "", leg->owner, "com-release");
    const bool accepted = *request.extension == mcdata::ExtensionResponse::Accepted;
    pending_.push_back([this, key, accepted] { extension_response(key, accepted); });
    return response;
  }
  }
  return reject(403, "", leg->owner, "com-release");
}

//------------------------------------------------------------------------------
// TS 24.282 clause 13.2.5.2: the release of an IP connectivity session by an authorised user without prior
// indication (the only release of a tunnel implemented), or the refusal.
std::optional<SipResponse> DataServer::com_release_tunnel(const SipMessage &sip_request,
                                                          const std::shared_ptr<IpconSession> &tunnel,
                                                          const BodyPart *signalling, const std::string &reason) {
  const auto owner = sip_request.dialog_id == tunnel->origin_dialog ? tunnel->originator : tunnel->target;
  mcdata::CommunicationRelease request;
  try {
    if (signalling)
      request = mcdata::decode_communication_release(signalling->body);
    else
      throw std::runtime_error("no body");
  } catch (const std::exception &) {
    return reject(403, "", owner, "com-release");
  }
  if (request.type != mcdata::CommReleaseType::AuthUserReleaseRequest ||
      !profile(owner).value("mcdata", Json::object()).value("release_any_user", false))
    return reject(403, "", owner, "com-release");
  release_tunnel(tunnel, reason.empty() ? "released by an authorised MCData user" : reason, "releases_authorised");
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 13.2.4.4.2 and 13.2.6.2.4.2: the originator's remaining amount of data, kept with the release
// process and passed to the authorised user that announced the release, or the refusal.
std::optional<SipResponse> DataServer::com_release_remaining(const MediaSession &leg, const std::string &key,
                                                             const BodyPart &payload) {
  // TS 24.282 clauses 13.2.4.4.2 and 13.2.6.2.4.2: the originator's remaining amount of data.
  std::string remaining;
  try {
    for (const auto &item : mcdata::decode_data_payload(payload.body).payloads) remaining += item.data;
  } catch (const std::exception &) {
    return reject(403, "", leg.owner, "com-release");
  }
  auto found = releases_.find(key);
  if (found == releases_.end() || !leg.originating) return reject(403, "", leg.owner, "com-release");
  found->second.remaining = remaining;
  if (!found->second.initiator.empty())
    if (const auto initiator = leg_of(key, found->second.initiator)) {
      mcdata::Info info;
      info.request_uri = initiator->owner;
      send_com_release(initiator->dialog, {{mcdata::info_mime, mcdata::info_xml(info)}, payload});
    }
  event("mcdata_release_remaining_data", {{"key", key}, {"remaining", remaining}});
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 13.2.4.4.3 and 13.2.6.2.4.3: the originator's request for extension of an announced release,
// answered by the server or forwarded to the authorised user that announced it, or the refusal.
std::optional<SipResponse> DataServer::com_release_extension_request(const MediaSession &leg, const std::string &key,
                                                                     const BodyPart &signalling) {
  // TS 24.282 clauses 13.2.4.4.3 and 13.2.6.2.4.3: only the originator, and only once announced.
  auto found = releases_.find(key);
  if (!leg.originating || found == releases_.end() || found->second.extension_requested)
    return reject(403, "", leg.owner, "com-release");
  found->second.extension_requested = true;
  found->second.tdc3 = 0;
  if (found->second.initiator.empty()) {
    pending_.push_back([this, key] { extension_response(key, release_config().value("accept_extension", true)); });
  } else if (const auto initiator = leg_of(key, found->second.initiator)) {
    mcdata::Info info;
    info.request_uri = initiator->owner;
    send_com_release(initiator->dialog, {{mcdata::info_mime, mcdata::info_xml(info)}, signalling});
  }
  event("mcdata_release_extension_requested", {{"key", key}, {"initiator", found->second.initiator}});
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 13.2.2.2.4.1 and 13.2.2.2.4.2 steps 1 and 2: the transmission time and data
// limits of a communication. The server releases it without prior indication
// (clause 13.2.3.2), or first announces the release to the originator (clause 13.2.4) when
// mcdata.release.prior_indication is set. TDC3 then ends the communication.
void DataServer::release_tick(std::uint64_t now) {
  const auto config = release_config();
  const auto max_duration = config.value("max_duration_ms", std::uint64_t{0});
  const auto max_bytes = config.value("max_bytes", std::uint64_t{0});
  std::vector<std::pair<std::string, std::string>> exceeded;
  for (const auto &[dialog, leg] : media_) {
    if (!leg->originating || leg->key.empty() || releases_.contains(leg->key)) continue;
    if (max_duration && now - leg->started >= max_duration)
      exceeded.emplace_back(leg->key, "time limit expiry");
    else if (max_bytes && leg->relayed_bytes > max_bytes)
      exceeded.emplace_back(leg->key, "data volume limit");
  }
  for (const auto &[key, reason] : exceeded) {
    if (config.value("prior_indication", false))
      release_intent_media(key, {}, reason, true);
    else
      release_communication(key, reason, "releases_server");
  }
  std::vector<std::pair<std::string, std::string>> expired;
  for (const auto &[key, process] : releases_)
    if (process.tdc3 && process.tdc3 <= now) expired.emplace_back(key, process.reason);
  for (const auto &[key, reason] : expired) {
    event("mcdata_release_tdc3_expired", {{"key", key}});
    release_communication(key, reason.empty() ? "no extension was requested" : reason, "releases_server");
  }
  // The same limits for IP connectivity, which is released without prior indication.
  std::set<std::shared_ptr<IpconSession>> seen;
  std::vector<std::pair<std::shared_ptr<IpconSession>, std::string>> tunnels;
  for (const auto &[dialog, tunnel] : ipcons_) {
    if (!tunnel->established || !seen.insert(tunnel).second) continue;
    if (max_duration && now - tunnel->established_at >= max_duration)
      tunnels.emplace_back(tunnel, "time limit expiry");
    else if (max_bytes && tunnel->bytes > max_bytes)
      tunnels.emplace_back(tunnel, "data volume limit");
  }
  for (const auto &[tunnel, reason] : tunnels) release_tunnel(tunnel, reason, "releases_server");
}

//------------------------------------------------------------------------------
// TS 24.282 clause 13.2.2.2.4.3: a participant leaving releases its leg, and the communication
// when the release policy of clause 13.2.2.2.4.1 or 13.2.2.2.4.2 says so.
void DataServer::media_released(const std::string &dialog) {
  std::string bye_reason;
  if (const auto found = bye_reasons_.find(dialog); found != bye_reasons_.end()) {
    bye_reason = found->second;
    bye_reasons_.erase(found);
  }
  const auto leaving = media_session(dialog);
  if (!leaving) return;
  media_.erase(dialog);
  event("mcdata_media_session_released", {{"dialog", dialog}, {"owner", leaving->owner}, {"key", leaving->key}});
  if (leaving->key.empty()) return;
  std::size_t remaining = 0;
  for (const auto &[other_dialog, other] : media_)
    if (other->key == leaving->key) ++remaining;
  // Step 3 of both policies: only one or no participants are left.
  bool release = remaining <= 1;
  // TS 24.282 clause 13.2.2.2.4.1 step 4, by local policy: the initiator of a group communication leaves.
  if (!leaving->group.empty() && leaving->originating && release_config().value("initiator_leave", true))
    release = true;
  // TS 24.282 clause 13.2.2.2.4.3 step 3A: an authorised user ends an ad hoc group communication for everyone.
  if (leaving->adhoc && bye_reason.find("User requested release") != std::string::npos &&
      profile(leaving->owner).value("mcdata", Json::object()).value("release_any_user", false))
    release = true;
  if (!release) {
    event("mcdata_participant_left", {{"key", leaving->key}, {"owner", leaving->owner}, {"remaining", remaining}});
    return;
  }
  // TS 24.582 clause 7.1.2.1: the sender of a file leaves once it has sent it. A leg still
  // holding the file for a recipient whose connection is not up yet, or whose recipient has not yet answered the
  // SEND, delivers it first; its recipient releases it.
  if (leaving->file && !leaving->session) {
    std::vector<std::string> done;
    for (const auto &[dialog, other] : media_)
      if (other->key == leaving->key && other->pending_file.empty() && !other->file_unanswered) done.push_back(dialog);
    if (done.size() < remaining) {
      for (const auto &dialog : done) {
        media_.erase(dialog);
        pending_.push_back([this, dialog] { sip_.bye(dialog); });
      }
      event("mcdata_file_legs_kept",
            {{"key", leaving->key}, {"released", done.size()}, {"kept", remaining - done.size()}});
      return;
    }
  }
  release_communication(leaving->key, "", "releases_policy");
}

} // namespace mcx
