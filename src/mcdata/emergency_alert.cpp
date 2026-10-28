//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData emergency alerts at the combined participating and controlling MCData function (TS 24.282 clauses
// 16.2.2 and 16.2.3) and the in-progress priority state notifications (clause 6.3.7.1.2) (member functions of
// DataServer, declared in data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.7.1.2 with clause 6.3.7.1.3 or clause 6.3.7.1.5: an emergency alert notification or
// receipt to one MCData user, with the MCData ICSI.
void DataServer::alert_message(const User &target, mcdata::Info info, const std::string &location) {
  info.request_uri = target.id;
  std::vector<BodyPart> parts{{mcdata::info_mime, mcdata::info_xml(info)}};
  if (!location.empty()) parts.push_back({mcdata::location_mime, location});
  try {
    parts = seal_for(target.sip, std::move(parts));
  } catch (const CskExpired &error) {
    // TS 33.180 annex E.6.10: the recipient's CSK may no longer be used: this message is not sent (never in the clear).
    return csk_expired_not_sent(target.id, "alert", error);
  }
  const auto boundary = "mcdata-" + random_id();
  sip_.request("MESSAGE", target.sip,
               parts.size() == 1 ? std::string(mcdata::info_mime) : "multipart/mixed; boundary=" + boundary,
               parts.size() == 1 ? parts.front().body : multipart_body(parts, boundary),
               {{"Accept-Contact", "*;+g.3gpp.mcdata;require;explicit"},
                {"Accept-Contact", "*;+g.3gpp.icsi-ref=\"" + url_encode(mcdata::icsi) + "\";require;explicit"},
                {"P-Asserted-Service", std::string(mcdata::icsi)}},
               [this, id = target.id](const SipResponse &response) {
                 if (response.status_code >= 200)
                   event("mcdata_alert_delivery_result", {{"user_id", id}, {"status", response.status_code}});
               });
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.7.1.2: a member that affiliates while the group has an in-progress emergency
// or imminent peril state is told of it, as it is not participating.
void DataServer::late_in_progress_state(const User &user, const std::string &group) {
  const auto found = group_priority_.find(group);
  if (found == group_priority_.end()) return;
  mcdata::Info notice;
  notice.calling_group = group;
  notice.calling_user = found->second.originator;
  notice.emergency = found->second.emergency;
  if (!found->second.emergency) notice.imminent_peril = found->second.imminent;
  alert_message(user, notice, {});
  count("media_state_notifications");
  event("mcdata_in_progress_state_notified", {{"group_id", group},
                                              {"user_id", user.id},
                                              {"emergency", found->second.emergency},
                                              {"imminent", found->second.imminent},
                                              {"reason", "affiliation"}});
}

//------------------------------------------------------------------------------
// TS 24.282 clause 16.2.3.3: a newly affiliated member learns about the outstanding alerts of the group.
void DataServer::late_alerts(const User &user, const std::string &group) {
  const auto found = emergency_alerts_.find(group);
  if (found == emergency_alerts_.end()) return;
  for (const auto &[originator, alert] : found->second) {
    if (originator == user.id) continue;
    mcdata::Info info;
    info.calling_group = group;
    info.calling_user = originator;
    info.alert = true;
    info.organization = alert.organization;
    info.functional_alias = alert.functional_alias;
    alert_message(user, info, alert.location);
    event("mcdata_late_alert", {{"user_id", user.id}, {"group_id", group}, {"originator", originator}});
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 16.2.2.1, 16.2.3.1 and 16.2.3.2: emergency alert origination and cancellation at the
// combined participating (clause 16.2.2.1) and controlling (clauses 16.2.3.1 and 16.2.3.2) function. The in-progress
// emergency group state needs MCData emergency group communications, which
// are INVITE based and not implemented, so <emergency-ind> is not acted on.
SipResponse DataServer::emergency_alert(const SipMessage &request, User &user, mcdata::Info info) {
  SipResponse response;
  const auto group = info.request_uri;
  const auto answer = [&](int status, const std::string &warning, bool alert_state) {
    auto rejected = reject(status, warning, user.id, *info.alert ? "emergency-alert" : "emergency-alert-cancel");
    mcdata::Info state;
    state.alert = alert_state; // TS 24.282 clause 16.2.3.1 step 4a-i, clause 16.2.3.2 step 1a-i
    rejected.content_type = mcdata::info_mime;
    rejected.body = mcdata::info_xml(state);
    return rejected;
  };
  if (info.client_id != user.client || group.empty()) return reject(403, "", user.id, "emergency-alert");

  // TS 24.282 clause 16.2.3.1 step 2: the MCData ICSI (or an MCData sub-service ICSI) in Accept-Contact.
  if (!accepts(request, mcdata::icsi)) return reject(403, "", user.id, "emergency-alert");
  Json policy;
  try {
    policy = profile(user.id).value("mcdata", Json::object());
  } catch (const std::exception &) {
    policy = Json::object();
  }
  const auto document = group_document(group);
  if (!document)
    return reject(404, "163 the group identity indicated in the request does not exist", user.id, "emergency-alert");
  const auto settings = document->value("mcdata", Json::object());
  if (!*info.alert) {
    // TS 24.282 clause 6.3.7.2.2: cancellation of the sender's own alert, or with <originated-by> another user's.
    if (!policy.value("alert_cancel", false)) return answer(403, "", true);
    emergency_alert_cancelled(user, info, group, settings);
    response.status_code = 200;
    return response;
  }

  // TS 24.282 clause 6.3.7.2.1: preconfigured-use-only groups, then the user and group authorisation. Either refusal
  // is of an unauthorised request, answered with <alert-ind> "false" (clause 16.2.3.1 step 4a-i).
  if (document->value("preconfigured_use_only", false))
    return answer(403, "168 alert is not allowed on the preconfigured group", false);
  const bool group_allows = settings.is_object() && settings.value("allow_emergency_alert", false);
  const auto dedicated = policy.value("alert_groups", Json::array());
  const bool permitted = policy.value("emergency_alert", false) && (dedicated.empty() || listed(dedicated, group));
  if (!permitted || !group_allows) return answer(403, "", false);

  // TS 24.282 clause 16.2.3.1 step 4b-i: implicit affiliation of an eligible (member) user (clauses 8.3.3.6
  // and 8.3.3.7).
  if (!affiliated(user.id, group)) {
    if (!listed(settings.value("members", Json::array()), user.id))
      return reject(403, "120 user is not affiliated to this group", user.id, "emergency-alert");
    user.groups.insert(group);
    event("mcdata_implicitly_affiliated", {{"user_id", user.id}, {"group_id", group}});
    schedule_notify(user);
  }
  EmergencyAlert alert;
  alert.organization = policy.value("organization", std::string{});
  if (!info.functional_alias.empty() && alias_active(info.functional_alias, user.id))
    alert.functional_alias = info.functional_alias;
  if (const auto *location = part(request, mcdata::location_mime)) {
    (void)parse_emergency_location(location->body); // bounded, well-formed Emergency report
    alert.location = location->body;
  }
  emergency_alerts_[group][user.id] = alert;

  // TS 24.282 clause 16.2.3.1 step 4b-ii: every other affiliated member is notified (clauses 6.3.7.1.2 and
  // 6.3.7.1.3).
  unsigned notified = 0;
  for (const auto &member : settings.value("members", Json::array()))
    if (member.is_string() && member.get<std::string>() != user.id && affiliated(member, group)) {
      mcdata::Info notice;
      notice.calling_group = group;
      notice.calling_user = user.id;
      notice.alert = true;
      notice.organization = alert.organization;
      notice.functional_alias = alert.functional_alias;
      alert_message(*by_id(member), notice, alert.location);
      ++notified;
    }
  mcdata::Info receipt; // TS 24.282 clause 16.2.3.1 steps 4b-v and 4b-vi (clause 6.3.7.1.5)
  receipt.calling_group = group;
  receipt.alert = true;
  receipt.alert_received = true;
  receipt.client_id = user.client;
  schedule_receipt(user, receipt);

  event("mcdata_emergency_alert", {{"user_id", user.id}, {"group_id", group}, {"notified", notified}});
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 16.2.3.2 steps 2c and 2g to 2i: an authorised cancellation of the sender's own emergency alert,
// or with <originated-by> another user's (clause 6.3.7.2.2): the alert state ends, every other affiliated member
// is told and the receipt is scheduled.
void DataServer::emergency_alert_cancelled(const User &user, const mcdata::Info &info, const std::string &group,
                                           const Json &settings) {
  const auto originator = info.originated_by.empty() ? user.id : info.originated_by;
  if (auto found = emergency_alerts_.find(group); found != emergency_alerts_.end()) {
    found->second.erase(originator);
    if (found->second.empty()) emergency_alerts_.erase(found);
  }
  // TS 24.282 clause 16.2.3.2 step 2c: every other affiliated member is told, including the originator
  // of a cancelled third-party alert.
  if (settings.is_object())
    for (const auto &member : settings.value("members", Json::array()))
      if (member.is_string() && member.get<std::string>() != user.id && affiliated(member, group)) {
        mcdata::Info notice;
        notice.calling_group = group;
        notice.calling_user = user.id;
        notice.alert = false;
        notice.originated_by = info.originated_by;
        alert_message(*by_id(member), notice, {});
      }
  mcdata::Info receipt; // TS 24.282 clause 16.2.3.2 steps 2g to 2i
  receipt.calling_group = group;
  receipt.alert = false;
  receipt.alert_received = true;
  receipt.client_id = user.client;
  schedule_receipt(user, receipt);
  event("mcdata_emergency_alert_cancelled", {{"user_id", user.id}, {"group_id", group}, {"originator", originator}});
}

//------------------------------------------------------------------------------
// TS 24.282 clause 16.2.3.1 steps 4b-iv and 4b-v: the receipt (clause 6.3.7.1.5) follows the 200 OK.
void DataServer::schedule_receipt(const User &user, mcdata::Info receipt) {
  pending_.push_back([this, id = user.id, receipt] {
    if (const auto *target = by_id(id)) alert_message(*target, receipt, {});
  });
}

} // namespace mcx
