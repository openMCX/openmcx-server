//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Standalone SDS over the signalling control plane (one-to-one, group, ad hoc group) and its disposition notifications.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.2.3.1, 9.2.2.4.2 and 9.2.2.3.2: a standalone SDS SIP MESSAGE request at the originating
// participating (clause 9.2.2.3.1), controlling (clause 9.2.2.4.2) and terminating participating (clause 9.2.2.3.2)
// functions, which are collocated: their checks, then the delivery to every recipient and the 202 answer.
SipResponse DataServer::sds(const SipMessage &sip_request, const User &sender, mcdata::Info info,
                            const BodyPart &signalling, const BodyPart &data) {
  const auto request = info.request_type;
  const auto signalling_message = mcdata::decode_sds_signalling(signalling.body);
  // An end-to-end protected DATA PAYLOAD (TS 24.282 clause 6.6.3.1; bit 7 of its message type, TS 33.180 clause 8.5.1)
  // cannot be read here: its size is that of the Protected Payload message.
  const bool protected_payload = !data.body.empty() && (static_cast<std::uint8_t>(data.body[0]) & 0x40);
  const auto size = protected_payload ? data.body.size() : payload_size(mcdata::decode_data_payload(data.body));
  Json policy;
  try {
    policy = profile(sender.id).value("mcdata", Json::object());
  } catch (const std::exception &) {
    policy = Json::object();
  }
  const auto &service = cfg_.at("mcdata");

  // TS 24.282 clause 9.2.2.3.1 step 7a (clause 11.1 step 1).
  if (!policy.is_object() || !policy.value("transmit_data", false))
    return reject(403, "200 user not authorised to transmit data", sender.id, request.c_str());
  info.calling_user = sender.id; // TS 24.282 clause 9.2.2.3.1 step 12
  // Step 12A: present the sender's functional alias only while it is activated.
  if (!info.functional_alias.empty() && !alias_active(info.functional_alias, sender.id)) info.functional_alias.clear();
  std::map<std::string, std::string> called_aliases; // recipient -> alias it was reached through
  std::vector<BodyPart> binary{signalling, data};
  std::vector<const User *> targets;

  // TS 24.282 clause 9.2.2.2.1 step 2c: the PCK of a one-to-one SDS travels to the recipient unchanged.
  if (const auto *key = part(sip_request, "application/mikey"); key && request == "one-to-one-sds")
    binary.push_back(*key);
  if (request == "one-to-one-sds") {
    if (auto rejected = sds_one_to_one(sip_request, sender, info, request, policy, size, targets))
      return *rejected;
  } else if (request == "ad-hoc-group-sds") {
    if (auto rejected = sds_cplane_limit(service, sender, request, size)) return *rejected;
    auto result = adhoc_recipients(sip_request, sender, info, policy, targets, called_aliases);
    if (result) return *result;
    counters_.add("sds_adhoc");
  } else {
    if (auto rejected = sds_group(sender, info, request, size, targets)) return *rejected;
  }
  Dispatched sent;
  sent.originator = sender.id;
  sent.group = info.calling_group;
  sent.deadline = monotonic_ms() + disposition_wait_ms;
  sent.disposition = signalling_message.disposition;
  for (const auto *target : targets) {
    if (const auto alias = called_aliases.find(target->id); alias != called_aliases.end())
      info.called_functional_alias = alias->second; // TS 24.282 clause 9.2.2.4.2 step 6A b-ii-D
    else if (request == "ad-hoc-group-sds")
      info.called_functional_alias.clear();
    deliver(*target, info, binary, "sds");
    sent.recipients.insert(target->id);
  }
  store_communication(sender, targets, info, binary, mcdata::uuid_text(signalling_message.message),
                      mcdata::uuid_text(signalling_message.conversation), {});
  if (signalling_message.disposition != mcdata::DispositionRequest::None)
    dispatched_[mcdata::uuid_text(signalling_message.message)] = sent;
  event("mcdata_sds_relayed", {{"user_id", sender.id},
                               {"request", request},
                               {"group_id", info.calling_group},
                               {"recipients", sent.recipients},
                               {"payload_bytes", size},
                               {"conversation_id", mcdata::uuid_text(signalling_message.conversation)},
                               {"message_id", mcdata::uuid_text(signalling_message.message)},
                               {"disposition", static_cast<int>(signalling_message.disposition)}});
  SipResponse response;
  response.status_code = 202; // TS 24.282 clause 9.2.2.4.2 steps 7 and 8
  response.reason = "Accepted";
  if (request == "ad-hoc-group-sds") {
    // Project decision: the 202 names the ad hoc group identity so that the
    // sender can address follow-up messages to it (TS 24.282 gives it only
    // through ad hoc group determination, clause 24.2.7.2).
    mcdata::Info answer;
    answer.calling_group = info.calling_group;
    answer.used_priority = info.user_requested_priority;
    response.content_type = mcdata::info_mime;
    response.body = mcdata::info_xml(answer);
  }

  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.2.3.1 step 8: the signalling control plane size limit of a standalone SDS, or the refusal.
std::optional<SipResponse> DataServer::sds_cplane_limit(const Json &service, const User &sender,
                                                        const std::string &request, std::size_t size) {
  // TS 24.282 clause 9.2.2.3.1 step 8: the signalling control plane size limit.
  if (const auto max = limit(service, "max_payload_size_sds_cplane_bytes"); max && size > max)
    return reject(403, "203 message too large to send over signalling control plane", sender.id, request.c_str());
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.2.4.2 step 5 with clause 9.2.2.3.1 steps 7b, 7c and 8 and clause 9.2.2.3.2 steps 2 to 3a:
// the one target of a one-to-one standalone SDS and its authorisation, a redirection (300) for a functional alias,
// or the refusal.
std::optional<SipResponse> DataServer::sds_one_to_one(const SipMessage &sip_request, const User &sender,
                                                      const mcdata::Info &info, const std::string &request,
                                                      const Json &policy, std::size_t size,
                                                      std::vector<const User *> &targets) {
  const auto &service = cfg_.at("mcdata");
  // TS 24.282 clause 9.2.2.4.2 step 5b-i: exactly one target.
  const auto *resources = part(sip_request, resource_lists_mime);
  std::string target;
  try {
    if (resources) target = parse_private_call_target(resources->body);
  } catch (const std::exception &) {
    target.clear();
  }
  if (target.empty() || target == sender.id)
    return reject(403, "204 unable to determine targeted user for one-to-one SDS", sender.id, request.c_str());

  // TS 24.282 clause 9.2.2.3.1 steps 7b and 7c (clause 11.1 steps 1A and 7).
  if (const auto max = limit(policy, "max_data_1to1"); max && size > max)
    return reject(403,
                  "202 user not authorised for one-to-one MCData communications due to exceeding the maximum "
                  "amount of data that can be sent in a single request",
                  sender.id, request.c_str());
  if (policy.contains("targets") && !policy.at("targets").empty() &&
      !listed(policy.at("targets"), target))
    return reject(403, "229 one-to-one MCData communication not authorised to the targeted user", sender.id,
                  request.c_str());
  if (auto rejected = sds_cplane_limit(service, sender, request, size)) return *rejected;

  // TS 24.282 clause 9.2.2.4.2 step 5a (clause 11.1 step 3).
  if (const auto max = limit(service, "max_data_size_sds_bytes"); max && size > max)
    return reject(403, "218 user not authorised for one-to-one SDS communications due to message size", sender.id,
                  request.c_str());
  if (info.call_to_functional_alias == true) {
    // TS 24.282 clause 9.2.2.4.2 step 5b-ii: redirect to one user that activated the alias.
    const auto users = alias_users(target, sender.id);
    if (users.empty()) return reject(403, "145 unable to determine called party", sender.id, request.c_str());
    mcdata::Info redirect;
    redirect.request_uri = users.front(); // selection is implementation-specific (NOTE 2)
    SipResponse response;
    response.status_code = 300;
    response.reason = "Multiple Choices";
    response.content_type = mcdata::info_mime;
    response.body = mcdata::info_xml(redirect);
    response.headers = {{"Contact", "<" + service_uri_ + ">"}};
    event("mcdata_functional_alias_resolved", {{"user_id", sender.id}, {"alias", target}, {"selected", users.front()}});
    return response;
  }

  // TS 24.282 clause 9.2.2.3.2 steps 2 to 3a: the terminating user's binding and incoming list.
  const auto *callee = by_id(target);
  if (!callee) return reject(404, "", sender.id, request.c_str());
  Json callee_policy;
  try {
    callee_policy = profile(target).value("mcdata", Json::object());
  } catch (const std::exception &) {
    return reject(404, "", sender.id, request.c_str());
  }
  if (callee_policy.is_object() && callee_policy.contains("incoming_from") &&
      !callee_policy.at("incoming_from").empty() && !callee_policy.value("incoming_any", false) &&
      !listed(callee_policy.at("incoming_from"), sender.id))
    return reject(403, "230 one-to-one MCData communication not authorised from this originating user", sender.id,
                  request.c_str());
  targets.push_back(callee);
  count("sds_one_to_one");

  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.2.4.2 step 6: the group checks of a group standalone SDS and its affiliated recipients, or the
// refusal.
std::optional<SipResponse> DataServer::sds_group(const User &sender, mcdata::Info &info,
                                                 const std::string &request, std::size_t size,
                                                 std::vector<const User *> &targets) {
  if (auto rejected = sds_cplane_limit(cfg_.at("mcdata"), sender, request, size)) return *rejected;
  // TS 24.282 clause 9.2.2.4.2 step 6.
  const auto group = info.request_uri;
  const auto found = group_document(group);
  if (!found)
    return reject(404, "163 the group identity indicated in the request does not exist", sender.id, request.c_str());
  const auto &document = *found;
  if (document.value("preconfigured_use_only", false))
    return reject(403, "167 call is not allowed on the preconfigured group", sender.id, request.c_str());
  const auto settings = document.value("mcdata", Json());
  if (!settings.is_object() || !listed(settings.value("members", Json::array()), sender.id))
    return reject(403, "116 user is not part of the MCData group", sender.id, request.c_str());
  if (!settings.value("allow_sds", false))
    return reject(403, "206 short data service not allowed for this group", sender.id, request.c_str());
  if (!settings.value("sds_supported", false))
    return reject(488, "207 SDS services not supported for this group", sender.id, request.c_str());
  if (document.value("regrouped", false)) return reject(403, "148 group is regrouped", sender.id, request.c_str());
  if (!transmit_allowed(settings, sender.id))
    return reject(403, "201 user not authorised to transmit data on this group identity", sender.id, request.c_str());
  if (const auto max = limit(settings, "max_request_bytes"); max && size > max)
    return reject(403,
                  "208 user not authorised for MCData communications on this group identity due to exceeding the "
                  "maximum amount of data that can be sent in a single request",
                  sender.id, request.c_str());
  if (const auto max = limit(settings, "max_sds_bytes"); max && size > max)
    return reject(403, "217 user not authorised for SDS communications on this group identity due to message size",
                  sender.id, request.c_str());
  if (!affiliated(sender.id, group))
    return reject(403, "120 user is not affiliated to this group", sender.id, request.c_str());

  // TS 24.282 clause 6.3.4: only affiliated members receive the message.
  for (const auto &member : settings.value("members", Json::array()))
    if (const auto *target = affiliated_member(member, group, sender.id)) targets.push_back(target);
  if (targets.empty()) return reject(403, "198 no users are affiliated to this group", sender.id, request.c_str());
  info.calling_group = group; // TS 24.282 clause 9.2.2.4.1.1 step 5b
  count("sds_group");

  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.2.4.2 step 6A with the authorisation of clause 24 (ad hoc group SDS):
// resolve the recipients from the participant list, the criteria, or an existing
// ad hoc group the sender belongs to, and set the ad hoc group identity.
std::optional<SipResponse> DataServer::adhoc_recipients(const SipMessage &sip_request, const User &sender,
                                                        mcdata::Info &info, const Json &policy,
                                                        std::vector<const User *> &targets,
                                                        std::map<std::string, std::string> &called) {
  const auto request = info.request_type.c_str();
  const auto service = cfg_.at("mcdata").value("adhoc", Json::object());
  // TS 24.282 clause 24.3.2.1.1 step 7 and clause 24.4.2.2 steps 6 and 7 (warnings 238 and 239).
  if (!policy.value("adhoc", false))
    return reject(403, "238 user not authorised to initiate the adhoc group data communication", sender.id, request);
  if (!service.value("allow", false))
    return reject(403, "239 the MCData system do not support adhoc group data communication", sender.id, request);
  const auto *resources = part(sip_request, resource_lists_mime);
  std::vector<std::string> requested;
  std::string group;
  if (resources) {
    try {
      requested = parse_resource_list_targets(resources->body);
    } catch (const std::exception &) {
      return reject(403, "240 Can't determine the adhoc group participants", sender.id, request);
    }
  } else if (!info.participant_criteria.empty()) {
    if (auto rejected = adhoc_criteria_members(sender, info, requested)) return *rejected;
  } else {
    // A follow-up to an existing ad hoc group of which the sender is a member.
    const auto found = adhoc_groups_.find(info.request_uri);
    if (info.request_uri.empty() || found == adhoc_groups_.end() || !found->second.members.contains(sender.id))
      return reject(403, "240 Can't determine the adhoc group participants", sender.id, request);
    group = found->first;
    requested.assign(found->second.members.begin(), found->second.members.end());
  }
  std::vector<std::string> participants;
  const auto add = [&](const std::string &id) {
    if (id != sender.id && std::find(participants.begin(), participants.end(), id) == participants.end())
      participants.push_back(id);
  };
  // Step 6A b-ii: a listed functional alias stands for the users that activated it (A); 403 with warning 145 only when
  // no MCData ID has activated any of the listed aliases (B).
  bool aliases = false, resolved = false;
  for (const auto &id : requested) {
    if (resources && alias_definition(id)) {
      aliases = true;
      const auto users = alias_users(id, sender.id);
      resolved = resolved || !users.empty();
      for (const auto &user : users) {
        if (!called.contains(user)) called[user] = id;
        add(user);
      }
      continue;
    }
    add(id);
  }
  if (aliases && !resolved) return reject(403, "145 unable to determine called party", sender.id, request);
  if (participants.empty()) return reject(403, "240 Can't determine the adhoc group participants", sender.id, request);

  // Participant limit; the MCData warning table code is 242 (the procedure text cites MCPTT's 189).
  if (const auto max = limit(service, "max_participants"); max && participants.size() > max)
    return reject(403, "242 maximum number of allowed adhoc group participants exceeded", sender.id, request);
  // TS 24.282 clause 24.3.2.1.2 step 5: a user without <allow-adhoc-group-data-comn-participation>
  // is not delivered to (MCData table code 241; the procedure text cites 188).
  std::vector<std::string> excluded;
  adhoc_participation_filter(participants, targets, excluded);
  if (!excluded.empty()) event("mcdata_adhoc_participants_excluded", {{"user_id", sender.id}, {"excluded", excluded}});
  if (excluded.size() == participants.size())
    return reject(403, "241 user is not allowed to participate in adhoc group data communication", sender.id, request);
  if (targets.empty()) return reject(480, "", sender.id, request);
  if (group.empty()) {
    // Step 6A a): a new server-generated ad hoc group identity.
    const auto service_uri = cfg_.at("mcdata").at("service_uri").get<std::string>();
    group = "sip:adhoc-" + random_id() + service_uri.substr(service_uri.find('@'));
    auto &created = adhoc_groups_[group];
    created.members.insert(sender.id);
    for (const auto *target : targets) created.members.insert(target->id);
    event("mcdata_adhoc_group_created", {{"group_id", group}, {"initiator", sender.id}, {"members", created.members}});
  }
  adhoc_groups_[group].deadline = monotonic_ms() + service.value("lifetime_ms", 1800000u);
  info.calling_group = group; // TS 24.282 clause 9.2.2.4.1.1 step 5b
  info.participant_criteria.clear();

  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 24.4.6: the members an ad hoc group participant criteria list designates (local policy), or the
// refusal (warning 240).
std::optional<SipResponse> DataServer::adhoc_criteria_members(const User &sender, const mcdata::Info &info,
                                                              std::vector<std::string> &requested) {
  const auto request = info.request_type.c_str();
  // Criteria vocabulary is local policy (TS 24.282 clause 24.4.6): comma-separated
  // "affiliated:<MCData group>" and "member:<MCData group>". The combined
  // server resolves them directly instead of asking participating functions.
  std::size_t start = 0;
  while (start <= info.participant_criteria.size()) {
    auto end = info.participant_criteria.find(',', start);
    if (end == std::string::npos) end = info.participant_criteria.size();
    std::string criterion = info.participant_criteria.substr(start, end - start);
    start = end + 1;
    while (!criterion.empty() && criterion.front() == ' ') criterion.erase(criterion.begin());
    while (!criterion.empty() && criterion.back() == ' ') criterion.pop_back();
    const auto colon = criterion.find(':');
    const auto kind = criterion.substr(0, colon);
    const auto criterion_group = colon == std::string::npos ? std::string{} : criterion.substr(colon + 1);
    const auto document = criterion_group.empty() ? std::nullopt : group_document(criterion_group);
    if ((kind != "affiliated" && kind != "member") || !document)
      return reject(403, "240 Can't determine the adhoc group participants", sender.id, request);
    for (const auto &member : document->value("mcdata", Json::object()).value("members", Json::array()))
      if (member.is_string() && (kind == "member" || affiliated(member, criterion_group))) requested.push_back(member);
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 24.3.2.1.2 step 5: the ad hoc group participants that are delivered to (targets) and those whose
// profile lacks <allow-adhoc-group-data-comn-participation> (excluded).
void DataServer::adhoc_participation_filter(const std::vector<std::string> &participants,
                                            std::vector<const User *> &targets, std::vector<std::string> &excluded) {
  for (const auto &id : participants) {
    Json participant;
    try {
      participant = profile(id).value("mcdata", Json::object());
    } catch (const std::exception &) {
      participant = Json::object();
    }
    if (!participant.is_object() || !participant.value("adhoc_participation", false)) {
      excluded.push_back(id);
      continue;
    }
    if (const auto *target = by_id(id)) targets.push_back(target);
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 12.2.2.1 and 12.2.3: an SDS disposition notification back to the sender, relayed or, for a
// group, aggregated.
SipResponse DataServer::notification(const SipMessage &request, const User &notifier, mcdata::Info info,
                                     const BodyPart &signalling) {
  const auto notice = mcdata::decode_sds_notification(signalling.body);
  const auto *resources = part(request, resource_lists_mime);
  std::string target;
  try {
    if (resources) target = parse_private_call_target(resources->body);
  } catch (const std::exception &) {
    target.clear();
  }
  // TS 24.282 clause 12.2.3 step 3: exactly one <entry> names the originator.
  if (target.empty()) return reject(403, "145 unable to determine called party", notifier.id, "notification");
  if (notice.type == mcdata::DispositionNotification::Undelivered) {
    // TS 24.282 clause 12.2.2.1 step 5: stored for re-delivery; not sent on to the originator.
    undelivered(notifier.id, mcdata::uuid_text(notice.message));
    SipResponse response;
    response.status_code = 200;
    return response;
  }

  // TS 24.282 clause 12.2.2.1 step 6: a positive notification ends any stored re-delivery.
  held_.erase({notifier.id, mcdata::uuid_text(notice.message)});
  if (const auto adhoc = adhoc_groups_.find(info.calling_group); adhoc != adhoc_groups_.end()) {
    // TS 24.282 clause 12.2.3 step 15b for an ad hoc group: the notifier must be one of its members.
    if (!adhoc->second.members.contains(notifier.id))
      return reject(403, "116 user is not part of the MCData group", notifier.id, "notification");
  } else if (!info.calling_group.empty()) {
    // TS 24.282 clause 12.2.3 step 15b.
    const auto document = group_document(info.calling_group);
    if (!document)
      return reject(404, "163 the group identity indicated in the request does not exist", notifier.id, "notification");
    if (!listed(document->value("mcdata", Json::object()).value("members", Json::array()), notifier.id))
      return reject(403, "116 user is not part of the MCData group", notifier.id, "notification");
  }

  // Correlate with the relayed message when it was recorded (TS 24.282 clause 9.2.2.4.2 step 4).
  const auto found = dispatched_.find(mcdata::uuid_text(notice.message));
  if (found != dispatched_.end() &&
      (found->second.originator != target || !found->second.recipients.contains(notifier.id)))
    return reject(403, "", notifier.id, "notification");

  // The optional Sender MCData user ID IE must name the notifier.
  if (notice.sender && *notice.sender != notifier.id) return reject(403, "", notifier.id, "notification");
  const auto *originator = by_id(target);
  if (!originator) return reject(404, "", notifier.id, "notification");
  if (found != dispatched_.end() && !info.calling_group.empty() && notice.sender &&
      aggregation().value("enabled", false) && !found->second.aggregate_sent) {
    // TS 24.282 clause 12.2.3 step 15c: collect until TDC1 expires or every recipient has reported.
    auto &sent = found->second;
    if (!sent.tdc1) sent.tdc1 = monotonic_ms() + aggregation().value("tdc1_ms", 5000u);
    sent.collected.push_back(signalling);
    const bool last = sent.disposition == mcdata::DispositionRequest::Delivery
                          ? notice.type == mcdata::DispositionNotification::Delivered
                          : notice.type == mcdata::DispositionNotification::Read ||
                                notice.type == mcdata::DispositionNotification::DeliveredAndRead;
    if (last) sent.finished.insert(notifier.id);
    count("notifications");
    event("mcdata_notification_collected", {{"user_id", notifier.id},
                                            {"to", target},
                                            {"type", static_cast<int>(notice.type)},
                                            {"message_id", found->first},
                                            {"collected", sent.collected.size()}});
    if (sent.finished == sent.recipients) send_aggregate(found->first, sent);
    SipResponse response;
    response.status_code = 202;
    response.reason = "Accepted";
    return response;
  }
  info.calling_user = notifier.id; // TS 24.282 clause 12.2.2.1 step 10
  deliver(*originator, info, {signalling}, "notification");
  count("notifications");
  event("mcdata_notification_relayed", {{"user_id", notifier.id},
                                        {"to", target},
                                        {"type", static_cast<int>(notice.type)},
                                        {"message_id", mcdata::uuid_text(notice.message)}});
  SipResponse response;
  response.status_code = 202;
  response.reason = "Accepted";

  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 12.2.3 steps 15c-iii, 15c-iv, 16 and 17: the collected notifications to the originator,
// one application/vnd.3gpp.mcdata-signalling body each, split per NOTE 6.
void DataServer::send_aggregate(const std::string &message, Dispatched &sent) {
  sent.aggregate_sent = true;
  sent.tdc1 = 0;
  auto collected = std::move(sent.collected);
  sent.collected.clear();
  const auto *originator = by_id(sent.originator);
  if (!originator || collected.empty()) {
    event("mcdata_aggregate_dropped",
          {{"to", sent.originator}, {"message_id", message}, {"notifications", collected.size()}});
    return;
  }
  mcdata::Info info;
  info.calling_group = sent.group;
  const std::size_t per_message = std::max(1u, aggregation().value("max_per_message", 50u));
  for (std::size_t at = 0; at < collected.size(); at += per_message) {
    const std::vector<BodyPart> chunk(collected.begin() + at,
                                      collected.begin() + std::min(collected.size(), at + per_message));
    deliver(*originator, info, chunk, "aggregate");
    count("aggregates");
  }
  event("mcdata_aggregate_sent", {{"to", sent.originator},
                                  {"message_id", message},
                                  {"notifications", collected.size()},
                                  {"complete", sent.finished == sent.recipients}});
}

} // namespace mcx
