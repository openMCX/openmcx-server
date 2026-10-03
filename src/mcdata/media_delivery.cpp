// MCData media plane delivery over MSRP to the recipients' legs, and the priority conditions of a communication.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.582 clauses 7.2 and 7.3.3: a file received in an MSRP SEND request on the originating leg is relayed to the
// legs of the recipients, which were opened when the transfer was accepted. As for SDS (TS 24.582 clause 6.1.1.3.2,
// TS 24.282 clause 9.2.3.4.3), the bodies received from the sender are offered to the recipient on a second media
// plane leg.
void DataServer::media_file_received(const std::shared_ptr<MediaSession> &session, const msrp::Message &message) {
  const auto declared = session->declared_bytes;
  if (declared && message.body.size() != declared) {
    event(
        "mcdata_media_file_discarded",
        {{"reason", "size does not match the file selector"}, {"bytes", message.body.size()}, {"declared", declared}});
    session->deadline = monotonic_ms();
    return;
  }
  unsigned relayed = 0;
  const auto idle = cfg_.at("mcdata").value("media", Json::object()).value("session_ms", 60000u);
  for (auto &[dialog, other] : media_) {
    if (other->key != session->key || dialog == session->dialog || !other->endpoint) continue;
    other->deadline = monotonic_ms() + idle;
    if (other->endpoint->connected()) {
      other->endpoint->send(std::string(mcdata::file_mime), message.body);
      other->file_unanswered = true;
    } else
      other->pending_file = message.body;
    ++relayed;
    count("media_files_delivered");
  }
  counters_.add("media_file_bytes", static_cast<std::uint64_t>(message.body.size()));
  session->relayed_bytes += message.body.size();
  event("mcdata_media_file_relayed", {{"user_id", session->owner},
                                      {"group_id", session->group},
                                      {"bytes", message.body.size()},
                                      {"relayed", relayed}});
}

//------------------------------------------------------------------------------
// TS 24.582 clauses 6.3.1.3 and 6.3.2.3: an MSRP SEND request received on a leg: its signalling is opened
// (TS 24.282 clause 6.6.3.3), then it is relayed to the other legs of an SDS session or delivered to
// each recipient of a standalone SDS.
void DataServer::media_received(const std::shared_ptr<MediaSession> &session, const msrp::Message &message) {
  if (message.content_type == mcdata::file_mime) return media_file_received(session, message);
  auto bodies = message.parts();
  if (const auto *owner = by_id(session->owner))
    if (const auto *key = signalling_key(owner->sip)) {
      std::vector<BodyPart> parts;
      for (const auto &[type, value] : bodies) parts.push_back({type, value});
      try {
        parts = open_from(*key, std::move(parts));
      } catch (const std::exception &error) {
        ++signalling_refused_;
        event("mcdata_signalling_refused", {{"user_id", owner->id}, {"media", true}, {"reason", error.what()}});
        return;
      }
      bodies.clear();
      for (const auto &part : parts) bodies[part.content_type] = part.body;
    }
  const auto signalling = bodies.find(std::string(mcdata::signalling_mime));
  if (signalling == bodies.end()) return;
  bool notification = false;
  try {
    // In a session the same connection carries messages and their in-band
    // disposition notifications (TS 24.582 clause 6.1.2.5).
    notification = mcdata::message_type(signalling->second) == mcdata::MessageType::SdsNotification;
    session->message_id = notification ? mcdata::uuid_text(mcdata::decode_sds_notification(signalling->second).message)
                                       : mcdata::uuid_text(mcdata::decode_sds_signalling(signalling->second).message);
  } catch (const std::exception &error) {
    event("mcdata_media_sds_discarded", {{"reason", error.what()}});
    return;
  }
  if (session->session) {
    // TS 24.582 clause 6.3.2.3: relay to every other leg of this session, messages and
    // notifications alike; the session stays open.
    std::vector<std::pair<std::string, std::string>> forward;
    for (const auto &[type, body] : bodies) forward.emplace_back(type, body);
    const auto idle = cfg_.at("mcdata").value("media", Json::object()).value("idle_ms", 60000u);
    unsigned relayed = 0;
    for (auto &[dialog, other] : media_) {
      if (other->key != session->key || dialog == session->dialog || !other->endpoint) continue;
      other->deadline = monotonic_ms() + idle;
      if (other->endpoint->connected())
        other->endpoint->send_parts(seal_msrp(other->owner, forward));
      else
        other->pending = forward;
      ++relayed;
    }
    session->deadline = monotonic_ms() + idle;
    // TS 24.282 clause 13.2.2.2.4.1 step 2: the data of the communication, for its data limit.
    if (const auto origin = originating_leg(session->key); origin && !notification)
      for (const auto &[type, body] : bodies) origin->relayed_bytes += body.size();
    count(notification ? "notifications" : "media_delivered");
    event("mcdata_session_sds_relayed", {{"user_id", session->owner},
                                         {"key", session->key},
                                         {"message_id", session->message_id},
                                         {"notification", notification},
                                         {"relayed", relayed}});
    return;
  }
  if (!session->originating) return;
  // TS 24.582 clause 6.3.1.3 steps 2 and 3: the group's SDS size limit is applied here: the INVITE carried no
  // payload.
  const auto payload = bodies.find(std::string(mcdata::payload_mime));
  if (session->max_bytes && payload != bodies.end() && payload->second.size() > session->max_bytes) {
    event("mcdata_media_sds_discarded",
          {{"user_id", session->originator},
           {"group_id", session->group},
           {"message_id", session->message_id},
           {"reason", "217 user not authorised for SDS communications on this group identity due to message size"}});
    session->deadline = monotonic_ms();
    return;
  }
  event("mcdata_media_sds_relayed", {{"user_id", session->originator},
                                     {"group_id", session->group},
                                     {"recipients", session->recipients},
                                     {"message_id", session->message_id}});
  // The sender releases its own session once its SEND is answered (TS 24.582
  // clause 6.1.1.2.1), so this leg is left to that or to its deadline.
  std::vector<std::pair<std::string, std::string>> forward;
  for (const auto &[type, body] : bodies) forward.emplace_back(type, body);
  const auto originator = session->originator, group = session->group, message_id = session->message_id;
  for (const auto &recipient : session->recipients) {
    const auto alias = session->aliases.contains(recipient) ? session->aliases.at(recipient) : std::string{};
    pending_.push_back([this, originator, recipient, group, message_id, forward, alias] {
      media_deliver(originator, recipient, group, message_id, forward, {}, "normal", nullptr, {}, false, alias);
    });
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.7.1.4: the provisioned Resource-Priority of a priority communication.
std::vector<SipHeader> DataServer::media_priority_headers(const char *level) const {
  const auto value = cfg_.at("mcdata").value("resource_priority", Json::object()).value(level, std::string{});
  if (value.empty()) return {};
  return {{"Resource-Priority", value}};
}

//------------------------------------------------------------------------------
// Helper: the level a group communication is carried at, from the in-progress states.
const char *DataServer::group_level(const std::string &group) const {
  const auto found = group_priority_.find(group);
  if (found == group_priority_.end()) return "normal";
  return found->second.emergency ? "emergency" : found->second.imminent ? "imminent_peril" : "normal";
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.7.1.9: the valid combinations of the priority indications. <alert-ind> is
// accepted but optional here, since this implementation has no group alert on a
// session; every other combination is rejected with warning 150.
bool DataServer::valid_priority_combination(const mcdata::Info &info) {
  if (info.imminent_peril.has_value()) return !info.emergency.has_value() && info.alert != true;
  return true;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 6.3.7.2.6 and 6.3.7.2.4: the user profile and the group document both authorise
// a priority group communication; clauses 6.3.7.2.3 and 6.3.7.2.5 authorise its cancellation.
bool DataServer::priority_authorised(const std::string &user, const std::string &group, bool emergency, bool enable) {
  const auto policy = profile(user).value("mcdata", Json::object());
  if (!enable) return policy.value(emergency ? "emergency_group_cancel" : "imminent_peril_cancel", false);
  if (!policy.value(emergency ? "emergency_group" : "imminent_peril", false)) return false;
  const auto document = group_document(group);
  if (!document) return false;
  const auto settings = document->value("mcdata", Json());
  return settings.is_object() && settings.value(emergency ? "allow_emergency_call" : "allow_imminent_peril", false);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.7.2.7 and clause 9.2.4.4.4 step 3C: the rejection names the indication it refuses.
SipResponse DataServer::reject_priority(const std::string &user, bool emergency) {
  auto response = reject(403,
                         emergency ? "233 user not authorised to initiate emergency communication"
                                   : "236 user not authorised to initiate imminent peril communication",
                         user, emergency ? "media-group-emergency" : "media-imminent-peril");
  mcdata::Info refused;
  refused.request_type = "group-sds-session";
  if (emergency) {
    refused.emergency = false;
    refused.alert = false;
  } else {
    refused.imminent_peril = false;
  }
  response.content_type = std::string(mcdata::info_mime);
  response.body = mcdata::info_xml(refused);
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.7.1.10: an imminent peril request on a group that is already in an
// in-progress emergency state is answered 200 with warning 149, and the client is
// told by a SIP INFO request that it participates at the emergency level instead.
void DataServer::send_priority_info(const std::string &dialog, const std::string &user, const std::string &group,
                                    std::optional<bool> imminent, std::optional<bool> emergency,
                                    std::optional<bool> alert) {
  mcdata::Info info;
  info.request_type = "group-sds-session";
  info.request_uri = user;
  info.calling_user = user;
  info.calling_group = group;
  info.imminent_peril = imminent;
  info.emergency = emergency;
  info.alert = alert;
  pending_.push_back([this, dialog, user, body = mcdata::info_xml(info)] {
    try {
      // TS 24.282 clause 6.3.7.1.2 steps 5 and 6: the controlling function asserts its own identity.
      sip_.request_in_dialog(dialog, "INFO", mcdata::info_mime,
                             seal_for_id(user, {{mcdata::info_mime, body}}).front().body,
                             {{"Info-Package", "g.3gpp.mcdata-info"},
                              {"Content-Disposition", "Info-Package"},
                              {"P-Asserted-Identity", "<" + service_uri_ + ">"},
                              {"P-Asserted-Service", std::string(mcdata::sds_icsi)}});
    } catch (const std::exception &error) {
      event("mcdata_media_failed", {{"reason", error.what()}, {"dialog", dialog}});
    }
  });
  count("media_priority_corrections");
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.7.1.2: the affiliated members of the group that are not participating in
// the communication are told of the in-progress state with a SIP MESSAGE.
void DataServer::notify_in_progress_state(const std::string &group, const std::string &originator,
                                          const std::vector<std::string> &participants, bool emergency, bool imminent,
                                          const std::string &location) {
  const auto document = group_document(group);
  if (!document) return;
  const auto settings = document->value("mcdata", Json());
  if (!settings.is_object()) return;
  const std::set<std::string> participating(participants.begin(), participants.end());
  unsigned notified = 0;
  for (const auto &member : settings.value("members", Json::array())) {
    if (!member.is_string()) continue;
    const auto id = member.get<std::string>();
    if (id == originator || participating.contains(id) || !affiliated(id, group)) continue;
    const auto *target = by_id(id);
    if (!target) continue;
    mcdata::Info notice;
    notice.calling_group = group;
    notice.calling_user = originator;
    notice.emergency = emergency;
    if (!emergency) notice.imminent_peril = imminent;
    if (!location.empty()) notice.alert = true;
    alert_message(*target, notice, location);
    ++notified;
  }
  count("media_state_notifications");
  event("mcdata_in_progress_state_notified", {{"group_id", group},
                                              {"originator", originator},
                                              {"emergency", emergency},
                                              {"imminent", imminent},
                                              {"notified", notified}});
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.7.2.1 with clause 6.3.7.1.3: an emergency alert carried by a priority group
// communication request. It is recorded like an alert of clause 16.2 and the
// members of the group are told, so both paths share one alert state.
bool DataServer::group_alert(const SipMessage &request, User &user, const std::string &group, std::string &location) {
  const auto document = group_document(group);
  if (!document) return false;
  const auto settings = document->value("mcdata", Json());
  const auto policy = profile(user.id).value("mcdata", Json::object());
  const auto dedicated = policy.value("alert_groups", Json::array());
  if (document->value("preconfigured_use_only", false) || !settings.is_object() ||
      !settings.value("allow_emergency_alert", false) || !policy.value("emergency_alert", false) ||
      (!dedicated.empty() && !listed(dedicated, group)))
    return false;
  EmergencyAlert alert;
  alert.organization = policy.value("organization", std::string{});
  if (const auto *body = part(request, mcdata::location_mime)) {
    (void)parse_emergency_location(body->body); // bounded, well-formed Emergency report
    alert.location = body->body;
  }
  emergency_alerts_[group][user.id] = alert;
  location = alert.location;
  mcdata::Info receipt; // TS 24.282 clause 6.3.7.1.5, as for an alert of its own
  receipt.calling_group = group;
  receipt.alert = true;
  receipt.alert_received = true;
  receipt.client_id = user.client;
  schedule_receipt(user, receipt);
  count("media_alerts");
  event("mcdata_emergency_alert", {{"user_id", user.id}, {"group_id", group}, {"with", "priority communication"}});
  return true;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 6.3.7.1.1, 6.3.7.1.8 and 6.3.7.1.14: every other leg of the session is told the
// new in-progress state of the group with a re-INVITE of its own.
void DataServer::media_group_notify(const std::shared_ptr<MediaSession> &leg, bool emergency, bool imminent) {
  for (auto &[dialog, other] : media_) {
    if (other->key != leg->key || dialog == leg->dialog || !other->session) continue;
    other->emergency = emergency;
    other->imminent = imminent;
    mcdata::Info notice;
    notice.request_type = "group-sds-session";
    notice.request_uri = other->owner;
    notice.calling_user = leg->owner;
    notice.calling_group = leg->group;
    notice.emergency = emergency;
    if (!emergency) notice.imminent_peril = imminent;
    auto headers = std::vector<SipHeader>{{"P-Asserted-Service", mcdata::sds_icsi}};
    for (const auto &header : media_priority_headers(group_level(leg->group))) headers.push_back(header);
    pending_.push_back([this, dialog, notice, headers, sdp = other->sdp] {
      try {
        sip_.reinvite_sdp(dialog, sdp, seal_for_id(notice.request_uri, {{mcdata::info_mime, mcdata::info_xml(notice)}}),
                          {}, headers);
      } catch (const std::exception &error) {
        event("mcdata_media_failed", {{"reason", error.what()}, {"dialog", dialog}});
      }
    });
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.3.4.3, 9.2.4.4.3 and 10.2.5.4.4: the controlling function invites one recipient with an
// MSRP offer of its own and the mcdata-info (and FD signalling) of the communication; returns the new dialog.
std::string DataServer::media_deliver(const std::string &originator, const std::string &target,
                                      const std::string &group, const std::string &message_id,
                                      const std::vector<std::pair<std::string, std::string>> &bodies,
                                      const std::string &key, const std::string &level, const FileOffer *file,
                                      const std::string &alert_location, bool alert, const std::string &called_alias,
                                      bool session, SipResponseHandler answered) {
  const bool emergency = level == "emergency", imminent = level == "imminent_peril";
  const auto *recipient = by_id(target);
  if (!recipient) return {};
  const bool adhoc = !group.empty() && adhoc_groups_.contains(group);
  auto leg = std::make_shared<MediaSession>();
  leg->originator = originator;
  leg->owner = target;
  leg->target = target;
  leg->message_id = message_id;
  leg->pending = bodies;
  leg->key = key;
  leg->session = session || (!key.empty() && file == nullptr);
  leg->file = file != nullptr;
  leg->emergency = emergency;
  leg->imminent = imminent;
  leg->adhoc = adhoc;
  leg->deadline =
      monotonic_ms() +
      cfg_.at("mcdata").value("media", Json::object()).value(key.empty() ? "session_ms" : "idle_ms", 60000u);
  auto offer = media_offer(leg);
  if (adhoc && leg->session) offer.direction = "sendrecv"; // TS 24.282 clause 24.4.2.1.1 step 10 with clause 9.2.4.4.1
  if (const auto key = media_key_mgmt_.find({originator, target}); group.empty() && key != media_key_mgmt_.end()) {
    offer.key_mgmt = key->second;
    media_key_mgmt_.erase(key);
  }
  if (file) {
    // TS 24.282 clause 10.2.5.4.4 with clause 10.2.5.3.1: the recipient is offered the same file.
    offer.accept_types = {std::string(mcdata::signalling_mime)};
    offer.file_selector = file->selector;
    offer.file_date = file->date;
    offer.file_description = file->description;
  }
  leg->sdp = msrp_sdp(offer, 1);
  leg->group = group;
  mcdata::Info info;
  info.request_type = adhoc          ? (file ? "adhoc-group-fd-session" : "adhoc-group-sds-session")
                      : file         ? (group.empty() ? "one-to-one-fd" : "group-fd")
                      : leg->session ? (group.empty() ? "one-to-one-sds-session" : "group-sds-session")
                                     : (group.empty() ? "one-to-one-sds" : "group-sds");
  info.called_functional_alias = called_alias; // TS 24.282 clause 24.4.2.2 step 15b-iv
  info.request_uri = target;
  info.calling_user = originator;
  info.calling_group = group; // TS 24.282 clause 9.2.3.4.3: the recipient learns the group
  // TS 24.282 clause 6.3.7.1.11 steps 6 and 7: the recipient learns the in-progress state, and
  // step 6c the emergency alert that came with the request (clause 6.3.7.1.3).
  if (emergency) info.emergency = true;
  if (imminent) info.imminent_peril = true;
  if (alert) info.alert = true;
  std::vector<BodyPart> parts{{mcdata::info_mime, mcdata::info_xml(info)}};
  if (file) parts.push_back({std::string(mcdata::signalling_mime), file->signalling});
  if (alert && !alert_location.empty()) parts.push_back({std::string(mcdata::location_mime), alert_location});
  parts = seal_for(recipient->sip, std::move(parts));
  const auto dialog = sip_.invite_sdp(
      recipient->sip, leg->sdp, parts,
      [this, message_id, target, answered](const SipResponse &response) {
        if (response.status_code < 200) return;
        if (response.status_code >= 300)
          // TS 24.282 clause 10.2.5.4.4: a recipient may decline the file (480 with warning 110).
          event("mcdata_media_delivery_failed", {{"message_id", message_id},
                                                 {"target", target},
                                                 {"status", response.status_code},
                                                 {"warning", std::string(get_header(response.headers, "Warning"))}});
        else
          event("mcdata_media_delivery_answered",
                {{"message_id", message_id}, {"target", target}, {"status", response.status_code}});
        if (answered) answered(response);
      },
      [&] {
        const std::string icsi = file ? mcdata::fd_icsi : mcdata::sds_icsi;
        std::vector<SipHeader> headers{
            {"Accept-Contact", std::string("*;+g.3gpp.mcdata.") + (file ? "fd" : "sds") + ";require;explicit"},
            {"Accept-Contact", "*;+g.3gpp.icsi-ref=\"" + url_encode(icsi) + "\";require;explicit"},
            {"P-Asserted-Service", icsi}};
        if (level != "normal")
          for (const auto &header : media_priority_headers(level.c_str())) headers.push_back(header);
        // TS 24.282 clause 24.4.2.1.1 step 6: the public user identity of the inviting client.
        if (adhoc)
          if (const auto *inviting = by_id(originator)) headers.push_back({"Referred-By", "<" + inviting->sip + ">"});
        return headers;
      }());
  leg->dialog = dialog;
  media_[dialog] = leg;
  return dialog;
}

} // namespace mcx
