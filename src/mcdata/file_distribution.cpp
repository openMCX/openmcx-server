// File distribution over HTTP at the combined participating and controlling MCData function: media storage
// discovery, the FD request, its disposition and network-triggered notifications and its release (TS 24.282
// clauses 10.2.1.3, 10.2.4, 12.2, 12.4 and 13.2; member functions of DataServer, declared in data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clause 6.7.3.1: does the file exist on the media storage function? An HTTP HEAD of the
// file URL, authenticated as this server. Only a file of this system's media storage function is available.
bool DataServer::file_available(const std::string &url) {
  const auto &common = cfg_.at("common");
  try {
    if (!url.starts_with(file_distribution().value("content_server", std::string{}))) return false;
    return http_.request("HEAD", url, {}, {}, common.at("client_id"), common.at("secret")).status == 200;
  } catch (const std::exception &error) {
    event("mcdata_file_check_failed", {{"reason", error.what()}});
    return false;
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 12.2.3 step 6a and clause 12.4.2.2: remove a file from the media storage function.
void DataServer::delete_file(const std::string &url) {
  const auto id = url.substr(0, url.find_last_of('/'));
  const auto &common = cfg_.at("common");
  try {
    // Only a file of this system's media storage function is removed.
    if (!url.starts_with(file_distribution().value("content_server", std::string{}))) return;
    http_.request("DELETE",
                  file_distribution().value("content_server_internal", std::string{}) + "/internal/files/" +
                      id.substr(id.find_last_of('/') + 1),
                  {}, {}, common.at("client_id"), common.at("secret"));
  } catch (const std::exception &error) {
    event("mcdata_file_delete_failed", {{"reason", error.what()}});
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.4.4.2 step 9: TDC2 from the file availability in the Metadata IE, bounded
// by <max-file-availability>, or <default-file-availability> without metadata.
std::uint64_t DataServer::file_availability(const mcdata::FdSignalling &fd) {
  const auto maximum = file_distribution().value("max_file_availability_ms", 600000u);
  const auto fallback = file_distribution().value("default_file_availability_ms", 120000u);
  if (!fd.metadata) return fallback;
  const auto until = mcdata::metadata_availability(*fd.metadata);
  if (!until) return fallback;
  const auto now = static_cast<std::uint64_t>(std::time(nullptr));
  const auto requested = *until > now ? (*until - now) * 1000 : 0;
  return std::min<std::uint64_t>(requested, maximum);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.1.3: discovery of the absolute URI of the media storage function. The
// participating checks of clause 10.2.1.3.3 and the controlling checks of clause 10.2.1.3.4 are
// applied in one server, which answers with an "msf-disc-res" of its own.
SipResponse DataServer::media_storage_discovery(const User &user, const mcdata::Info &info) {
  const auto policy = profile(user.id).value("mcdata", Json::object());
  if (info.calling_group.empty()) {
    // TS 24.282 clause 10.2.1.3.3 step 7: without a group the sender must be allowed to transmit.
    if (!policy.value("transmit_data", false))
      return reject(403, "200 user not authorised to transmit data", user.id, "msf-discovery");
  } else {
    // TS 24.282 clause 10.2.1.3.4 step 4.
    const auto document = group_document(info.calling_group);
    if (!document)
      return reject(404, "163 the group identity indicated in the request does not exist", user.id, "msf-discovery");
    if (document->value("preconfigured_use_only", false))
      return reject(403, "167 call is not allowed on the preconfigured group", user.id, "msf-discovery");
    const auto settings = document->value("mcdata", Json());
    if (!settings.is_object() || !listed(settings.value("members", Json::array()), user.id))
      return reject(403, "116 user is not part of the MCData group", user.id, "msf-discovery");
    if (!settings.value("allow_fd", false))
      return reject(403, "213 file distribution not allowed for this group", user.id, "msf-discovery");
    if (!settings.value("fd_supported", false))
      return reject(488, "214 FD services not supported for this group", user.id, "msf-discovery");
    if (settings.contains("transmit_members") && !listed(settings.at("transmit_members"), user.id))
      return reject(403, "201 user not authorised to transmit data on this group identity", user.id, "msf-discovery");
    if (!affiliated(user.id, info.calling_group))
      return reject(403, "120 user is not affiliated to this group", user.id, "msf-discovery");
  }
  // TS 24.282 clause 10.2.1.3.4 step 7: the answer is a new SIP MESSAGE, not the 200 (OK).
  mcdata::Info answer;
  answer.request_type = "msf-disc-res";
  answer.calling_group = info.calling_group;
  answer.controller_psi = file_distribution().value("content_server", std::string{});
  const std::vector<BodyPart> parts{{mcdata::info_mime, mcdata::info_xml(answer)}};
  pending_.push_back([this, id = user.id, parts] {
    if (const auto *target = by_id(id)) {
      const auto boundary = "mcdata-" + random_id();
      sip_.request("MESSAGE", target->sip, "multipart/mixed; boundary=" + boundary, multipart_body(parts, boundary),
                   {{"Accept-Contact", "*;+g.3gpp.icsi-ref=\"" + url_encode(mcdata::fd_icsi) + "\";require;explicit"},
                    {"P-Asserted-Service", mcdata::fd_icsi}});
    }
  });
  event("mcdata_media_storage_discovered", {{"user_id", user.id},
                                            {"group_id", info.calling_group},
                                            {"uri", file_distribution().value("content_server", std::string{})}});
  SipResponse response;
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.4: standalone file distribution over HTTP. The participating checks of
// clause 10.2.4.3.1 and the controlling checks of clause 10.2.4.4.2 are applied in one server.
SipResponse DataServer::fd(const SipMessage &received, const User &sender, mcdata::Info info,
                           const BodyPart &signalling) {
  mcdata::FdSignalling request;
  try {
    request = mcdata::decode_fd_signalling(signalling.body);
  } catch (const std::exception &error) {
    const std::string reason = error.what();
    if (reason.find("FILEURL") != std::string::npos)
      return reject(403, "211 payload for an FD request is not FILEURL", sender.id, "fd");
    if (reason.find("file URL") != std::string::npos)
      return reject(403, "210 Only one File URL must be present in the FD request", sender.id, "fd");
    throw;
  }
  const auto policy = profile(sender.id).value("mcdata", Json::object());
  const bool group_request = info.request_type == "group-fd";
  const auto size = mcdata::metadata_size(request.metadata.value_or(std::string{})).value_or(0);
  // TS 24.282 clause 10.2.4.3.1 step 7a: <allow-transmit-data> (clause 11.1 step 1).
  if (!policy.value("transmit_data", false))
    return reject(403, "200 user not authorised to transmit data", sender.id, "fd");
  std::vector<const User *> targets;
  std::string called_alias;
  if (!group_request) {
    if (auto refused = fd_one_to_one(received, sender, info, policy, size, targets, called_alias)) return *refused;
  } else {
    if (auto refused = fd_group(sender, info, size, targets)) return *refused;
  }
  // TS 24.282 clause 10.2.4.4.2 step 7b with clause 6.7.3.
  if (!file_available(request.file_url))
    return reject(403, "212 file referenced by file URL does not exist", sender.id, "fd");
  // TS 24.282 clause 11.2: auto-receive turns a small file into a mandatory download.
  if (!request.mandatory_download) {
    const auto automatic = file_distribution().value("max_data_size_auto_recv_bytes", 0u);
    if (automatic && size && size <= automatic) request.mandatory_download = true;
  }
  const auto message_id = mcdata::uuid_text(request.message);
  FileTransfer transfer;
  transfer.originator = sender.id;
  transfer.group = info.calling_group;
  transfer.file_url = request.file_url;
  transfer.conversation = mcdata::uuid_text(request.conversation);
  transfer.expires = monotonic_ms() + file_availability(request);
  transfer.application_id = request.application_id;
  info.calling_user = sender.id;
  std::vector<BodyPart> binary{{mcdata::signalling_mime, mcdata::encode(request)}};
  // TS 33.180 clause 8.3: the PCK of a one-to-one FD request travels to the recipient unchanged.
  if (const auto *key = part(received, "application/mikey"); key && info.request_type == "one-to-one-fd")
    binary.push_back(*key);
  for (const auto *target : targets) {
    auto delivered = info;
    delivered.called_functional_alias = called_alias;
    deliver(*target, delivered, binary, "fd");
    transfer.recipients.insert(target->id);
    count("fd_delivered");
    store_communication(sender, {target}, info, binary, message_id, mcdata::uuid_text(request.conversation),
                        request.file_url);
  }
  transfers_[message_id] = transfer;
  count("fd_requests");
  event("mcdata_fd_relayed", {{"user_id", sender.id},
                              {"request", info.request_type},
                              {"group_id", info.calling_group},
                              {"recipients", transfer.recipients},
                              {"file_url", request.file_url},
                              {"mandatory_download", request.mandatory_download},
                              {"message_id", message_id},
                              {"file_bytes", size}});
  SipResponse response;
  response.status_code = 202; // TS 24.282 clause 10.2.4.4.2 steps 15 and 16
  response.reason = "Accepted";
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.4.4.2 steps 10a and 10b with clause 10.2.4.3.2 step 5A: the one recipient of a one-to-one
// FD request over HTTP and its authorisation, a redirection (300) for a functional alias, or the refusal.
std::optional<SipResponse> DataServer::fd_one_to_one(const SipMessage &received, const User &sender,
                                                     const mcdata::Info &info, const Json &policy, std::uint64_t size,
                                                     std::vector<const User *> &targets, std::string &called_alias) {
  const auto *resources = part(received, resource_lists_mime);
  std::string target;
  try {
    if (resources) target = parse_private_call_target(resources->body);
  } catch (const std::exception &) {
    target.clear();
  }
  // TS 24.282 clause 10.2.4.4.2 step 10a.
  if (target.empty()) return reject(403, "205 unable to determine targeted user for one-to-one FD", sender.id, "fd");
  if (const auto max = limit(policy, "max_data_1to1"); max && size > max)
    return reject(403,
                  "202 user not authorised for one-to-one MCData communications due to exceeding the maximum "
                  "amount of data that can be sent in a single request",
                  sender.id, "fd");
  if (const auto list = policy.value("targets", Json::array()); !list.empty() && !listed(list, target))
    return reject(403, "229 one-to-one MCData communication not authorised to the targeted user", sender.id, "fd");
  if (info.call_to_functional_alias == true) {
    // TS 24.282 clause 10.2.4.4.2 step 10b: resolve the called functional alias.
    const auto users = alias_users(target, sender.id);
    if (users.empty()) return reject(403, "145 unable to determine called party", sender.id, "fd");
    SipResponse redirect;
    redirect.status_code = 300;
    redirect.reason = "Multiple Choices";
    mcdata::Info answer;
    answer.request_uri = users.front();
    redirect.content_type = mcdata::info_mime;
    redirect.body = mcdata::info_xml(answer);
    event("mcdata_fd_alias_redirect", {{"user_id", sender.id}, {"alias", target}, {"selected", users.front()}});
    return redirect;
  }
  const auto *user = by_id(target);
  if (!user) return reject(404, "", sender.id, "fd");
  // TS 24.282 clause 10.2.4.3.2 step 5A: the recipient's incoming communication list.
  const auto incoming = profile(user->id).value("mcdata", Json::object());
  if (!incoming.value("incoming_any", false) && !listed(incoming.value("incoming_from", Json::array()), sender.id))
    return reject(403, "230 one-to-one MCData communication not authorised from this originating user", sender.id,
                  "fd");
  called_alias = info.called_functional_alias;
  targets.push_back(user);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.4.4.2 step 12: the group checks of a group FD request over HTTP and its affiliated
// recipients, or the refusal.
std::optional<SipResponse> DataServer::fd_group(const User &sender, mcdata::Info &info, std::uint64_t size,
                                                std::vector<const User *> &targets) {
  // TS 24.282 clause 10.2.4.4.2 step 12.
  const auto group = info.request_uri;
  const auto found = group_document(group);
  if (!found) return reject(404, "163 the group identity indicated in the request does not exist", sender.id, "fd");
  const auto &document = *found;
  if (document.value("preconfigured_use_only", false))
    return reject(403, "167 call is not allowed on the preconfigured group", sender.id, "fd");
  const auto settings = document.value("mcdata", Json());
  if (!settings.is_object() || !listed(settings.value("members", Json::array()), sender.id))
    return reject(403, "116 user is not part of the MCData group", sender.id, "fd");
  if (!settings.value("allow_fd", false))
    return reject(403, "213 file distribution not allowed for this group", sender.id, "fd");
  if (!settings.value("fd_supported", false))
    return reject(488, "214 FD services not supported for this group", sender.id, "fd");
  if (settings.contains("transmit_members") && !listed(settings.at("transmit_members"), sender.id))
    return reject(403, "201 user not authorised to transmit data on this group identity", sender.id, "fd");
  if (const auto max = limit(settings, "max_fd_bytes"); max && size > max)
    return reject(403,
                  "208 user not authorised for MCData communications on this group identity due to exceeding the "
                  "maximum amount of data that can be sent in a single request",
                  sender.id, "fd");
  if (!affiliated(sender.id, group)) return reject(403, "120 user is not affiliated to this group", sender.id, "fd");
  for (const auto &member : settings.value("members", Json::array()))
    if (const auto *target = affiliated_member(member, group, sender.id)) targets.push_back(target);
  if (targets.empty()) return reject(403, "198 no users are affiliated to this group", sender.id, "fd");
  info.calling_group = group;
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 12.2.2.1 and 12.2.3 for FD: relay the disposition to the originator and keep
// the stored file list (clause 12.2.2.1 step 13, clause 12.2.3 step 6).
SipResponse DataServer::fd_notification(const User &sender, mcdata::Info info, const BodyPart &signalling) {
  const auto notice = mcdata::decode_fd_notification(signalling.body);
  const auto message_id = mcdata::uuid_text(notice.message);
  const auto found = transfers_.find(message_id);
  if (found == transfers_.end())
    return reject(403, "216 unable to correlate the disposition notification", sender.id, "fd-notification");
  auto &transfer = found->second;
  if (!transfer.recipients.contains(sender.id)) return reject(403, "", sender.id, "fd-notification");
  switch (notice.type) {
  case mcdata::FdNotificationType::Completed:
    transfer.downloaded.insert(sender.id);
    count("fd_downloads");
    break;
  case mcdata::FdNotificationType::Rejected:
    transfer.rejected.insert(sender.id);
    // TS 24.282 clause 12.2.3 step 6: every recipient rejected, so the file is deleted and TDC2 stops.
    if (transfer.rejected.size() == transfer.recipients.size() && !transfer.file_url.empty()) {
      delete_file(transfer.file_url);
      event("mcdata_file_deleted", {{"message_id", message_id}, {"reason", "all recipients rejected"}});
      transfer.expires = 0;
    }
    break;
  default: break;
  }
  // TS 24.282 clause 12.2.3 step 15c: collect the group's notifications until TDC1 expires or every
  // recipient has reported a final disposition (completed or rejected).
  if (!transfer.group.empty() && notice.sender && aggregation().value("enabled", false) && !transfer.aggregate_sent) {
    if (!transfer.tdc1) transfer.tdc1 = monotonic_ms() + aggregation().value("tdc1_ms", 5000u);
    transfer.collected.push_back(signalling);
    if (notice.type == mcdata::FdNotificationType::Completed || notice.type == mcdata::FdNotificationType::Rejected)
      transfer.finished.insert(sender.id);
    count("notifications");
    event("mcdata_fd_notification_collected", {{"user_id", sender.id},
                                               {"to", transfer.originator},
                                               {"type", static_cast<int>(notice.type)},
                                               {"message_id", message_id},
                                               {"collected", transfer.collected.size()}});
    if (transfer.finished == transfer.recipients) send_file_aggregate(message_id, transfer);
    SipResponse response;
    response.status_code = 202;
    response.reason = "Accepted";
    return response;
  }
  const auto *originator = by_id(transfer.originator);
  if (originator) {
    info.calling_user = sender.id;
    info.calling_group = transfer.group;
    deliver(*originator, info, {signalling}, "fd-notification");
  }
  count("notifications");
  event("mcdata_fd_notification_relayed", {{"user_id", sender.id},
                                           {"to", transfer.originator},
                                           {"type", static_cast<int>(notice.type)},
                                           {"message_id", message_id}});
  SipResponse response;
  response.status_code = 202;
  response.reason = "Accepted";
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 12.2.3 steps 15c-iii and 15c-iv: the collected FD notifications in one SIP MESSAGE.
void DataServer::send_file_aggregate(const std::string &message, FileTransfer &transfer) {
  transfer.aggregate_sent = true;
  transfer.tdc1 = 0;
  auto collected = std::move(transfer.collected);
  transfer.collected.clear();
  const auto *originator = by_id(transfer.originator);
  if (!originator || collected.empty()) {
    event("mcdata_fd_aggregate_dropped", {{"to", transfer.originator}, {"message_id", message}});
    return;
  }
  mcdata::Info info;
  info.calling_group = transfer.group;
  const std::size_t per_message = std::max(1u, aggregation().value("max_per_message", 50u));
  for (std::size_t at = 0; at < collected.size(); at += per_message) {
    const std::vector<BodyPart> chunk(collected.begin() + at,
                                      collected.begin() + std::min(collected.size(), at + per_message));
    deliver(*originator, info, chunk, "fd-aggregate");
    count("aggregates");
  }
  event("mcdata_fd_aggregate_sent", {{"to", transfer.originator},
                                     {"message_id", message},
                                     {"notifications", collected.size()},
                                     {"complete", transfer.finished == transfer.recipients}});
}

//------------------------------------------------------------------------------
// TS 24.282 clause 12.4.2.2: TDC2 expiry tells every recipient that has not downloaded the file
// that it is no longer available, and the file is removed.
void DataServer::file_expired(const std::string &message_id, FileTransfer &transfer,
                              mcdata::FdNetworkNotificationType reason) {
  // The transfer is about to be forgotten: send whatever TDC1 still holds.
  if (transfer.tdc1) send_file_aggregate(message_id, transfer);
  transfer.expires = 0;
  mcdata::FdNetworkNotification notice;
  notice.type = reason;
  notice.date_time = static_cast<std::uint64_t>(std::time(nullptr));
  notice.conversation = mcdata::parse_uuid(transfer.conversation);
  notice.message = mcdata::parse_uuid(message_id);
  notice.application_id = transfer.application_id;
  const std::vector<BodyPart> binary{{mcdata::signalling_mime, mcdata::encode(notice)}};
  for (const auto &recipient : transfer.recipients) {
    if (transfer.downloaded.contains(recipient) || transfer.rejected.contains(recipient)) continue;
    const auto *target = by_id(recipient);
    if (!target) continue;
    mcdata::Info info;
    info.request_type = "notify"; // TS 24.282 clause 12.4.2.1
    info.calling_group = transfer.group;
    deliver(*target, info, binary, "fd-network-notification");
  }
  delete_file(transfer.file_url);
  count(reason == mcdata::FdNetworkNotificationType::Expired ? "fd_expired" : "fd_terminated");
  event("mcdata_file_unavailable",
        {{"message_id", message_id},
         {"downloaded", transfer.downloaded.size()},
         {"recipients", transfer.recipients.size()},
         {"reason", reason == mcdata::FdNetworkNotificationType::Expired ? "expired" : "deleted"}});
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.4.4.2 steps 11 and 17 with clause 6.3.6.1: release of a file distribution over
// HTTP. The originator of the transmission may terminate it; the authorised-user
// variants of clause 13 are not implemented.
SipResponse DataServer::fd_termination(const User &sender, const BodyPart &signalling, const std::string &reason) {
  const auto request = mcdata::decode_fd_http_termination(signalling.body);
  const auto message_id = mcdata::uuid_text(request.message);
  const mcdata::Uuid empty{};
  // TS 24.282 clause 10.2.4.4.2 step 11a.
  if (request.message == empty || request.conversation == empty)
    return reject(403, "223 No Conversation ID or Message ID present", sender.id, "fd-termination");
  const auto found = transfers_.find(message_id);
  // TS 24.282 clause 10.2.4.4.2 step 11b: no transmission with this Conversation ID and Message ID.
  if (found == transfers_.end() || found->second.conversation != mcdata::uuid_text(request.conversation) ||
      (!request.file_url.empty() && request.file_url != found->second.file_url))
    return reject(404, "224 No transmission available", sender.id, "fd-termination");
  auto &transfer = found->second;
  // <allow-release-any-user> (TS 24.282 clause 13.2.5.3.4.1 step 2a, "based on configuration").
  const bool release_any = profile(sender.id).value("mcdata", Json::object()).value("release_any_user", false);
  SipResponse response;
  switch (request.type) {
  case mcdata::TerminationType::IntentToRelease:
    // TS 24.282 clause 13.2.6.3.4.1: an authorised user announces the release to the originator,
    // with the reason it gave, and TDC3 runs as for the server's own intent.
    if (!release_any || transfer.intent_sent || transfer.originator == sender.id)
      return reject(403, "", sender.id, "fd-release-intent");
    transfer.release_initiator = sender.id;
    release_intent(message_id, transfer, reason.empty() ? "release announced by an authorised MCData user" : reason);
    response.status_code = 200;
    return response;
  case mcdata::TerminationType::ExtensionResponse: {
    return fd_extension_response(sender, request, message_id, transfer);
  }
  case mcdata::TerminationType::ExtensionRequest: {
    return fd_extension_request(sender, request, message_id, transfer);
  }
  case mcdata::TerminationType::Request:
    // TS 24.282 clause 10.2.4.4.2 step 17: the originator releases its own distribution.
    if (transfer.originator != sender.id) return reject(403, "", sender.id, "fd-termination");
    break;
  case mcdata::TerminationType::AuthorisedUserRequest:
    // TS 24.282 clause 13.2.5.3.4.1: an authorised user releases another user's distribution.
    if (!release_any) return reject(403, "", sender.id, "fd-termination");
    break;
  default: return reject(403, "", sender.id, "fd-termination"); // the media-plane types are not implemented
  }
  const bool by_other = request.type == mcdata::TerminationType::AuthorisedUserRequest;
  const auto originator = transfer.originator;
  // TS 24.282 clause 10.2.4.4.2 step 17a (clause 12.4.2.1): the recipients are told the file was deleted, and it is removed.
  file_expired(message_id, transfer, mcdata::FdNetworkNotificationType::Deleted);
  mcdata::FdHttpTermination answer;
  answer.conversation = request.conversation;
  answer.message = request.message;
  answer.type = mcdata::TerminationType::Response;
  answer.release = mcdata::ReleaseResponse::Success;
  answer.application_id = request.application_id;
  answer.file_url = request.file_url;
  send_termination(sender.id, answer); // step 17b, and clause 13.2.5.3.4.1 for the authorised user
  if (by_other) {
    // TS 24.282 clause 13.2.3.3.4 step 2b: the originator is told that its transmission was stopped.
    mcdata::FdHttpTermination stopped = answer;
    stopped.type = mcdata::TerminationType::TransmissionStopped;
    stopped.release.reset();
    send_termination(originator, stopped, "released by an authorised MCData user");
  }
  count(by_other ? "fd_stopped" : "fd_terminated");
  event(
      "mcdata_file_terminated",
      {{"user_id", sender.id}, {"message_id", message_id}, {"originator", originator}, {"authorised_user", by_other}});
  response.status_code = 202;
  response.reason = "Accepted";
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 13.2.6.3.4.3: the authorised user that announced a release answers the originator's request for
// extension; the answer goes to the originator, a refusal releases the transmission, and the authorised user
// learns the outcome.
SipResponse DataServer::fd_extension_response(const User &sender, const mcdata::FdHttpTermination &request,
                                              const std::string &message_id, FileTransfer &transfer) {
  SipResponse response;
  // TS 24.282 clause 13.2.6.3.4.3: the authorised user's answer goes to the originator; a refusal
  // releases the transmission, and the authorised user learns the outcome.
  if (transfer.release_initiator != sender.id || !request.extension) return reject(403, "", sender.id, "fd-extension");
  const bool accepted = *request.extension == mcdata::ExtensionResponse::Accepted;
  mcdata::FdHttpTermination answer;
  answer.conversation = request.conversation;
  answer.message = request.message;
  answer.type = mcdata::TerminationType::ExtensionResponse;
  answer.extension = *request.extension;
  answer.file_url = transfer.file_url;
  send_termination(transfer.originator, answer);
  mcdata::FdHttpTermination outcome = answer;
  outcome.type = mcdata::TerminationType::Response;
  outcome.extension.reset();
  outcome.release = accepted ? mcdata::ReleaseResponse::Failed : mcdata::ReleaseResponse::Success;
  if (accepted) {
    transfer.extended = true;
    transfer.tdc3 = 0;
    transfer.expires = monotonic_ms() + file_distribution().value("extension_ms", 60000u);
    count("fd_extended");
  } else {
    stop_transmission(message_id, "released by an authorised MCData user");
  }
  send_termination(sender.id, outcome);
  event("mcdata_file_extension",
        {{"user_id", sender.id}, {"message_id", message_id}, {"granted", accepted}, {"decided_by", "authorised user"}});
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 13.2.4.5.2.2, 13.2.4.5.4.2, 13.2.4.5.4.3 and 13.2.6.3.4.2: the originator asks to keep the
// file available: granted by the server, or forwarded to the authorised user that announced the release.
SipResponse DataServer::fd_extension_request(const User &sender, const mcdata::FdHttpTermination &request,
                                             const std::string &message_id, FileTransfer &transfer) {
  SipResponse response;
  // TS 24.282 clause 13.2.4.5.2.2 and clauses 13.2.4.5.4.2 and 13.2.4.5.4.3: the originator asks to keep the file available.
  if (transfer.originator != sender.id) return reject(403, "", sender.id, "fd-extension");
  if (!transfer.release_initiator.empty()) {
    // TS 24.282 clause 13.2.6.3.4.2: the authorised user who announced the release decides.
    if (!transfer.intent_sent || transfer.extended) return reject(403, "", sender.id, "fd-extension");
    transfer.tdc3 = 0;
    mcdata::FdHttpTermination forwarded = request;
    forwarded.file_url = transfer.file_url;
    send_termination(transfer.release_initiator, forwarded);
    event("mcdata_file_extension_forwarded", {{"message_id", message_id}, {"to", transfer.release_initiator}});
    response.status_code = 200;
    return response;
  }
  const bool granted = transfer.intent_sent && !transfer.extended;
  if (granted) {
    transfer.extended = true;
    transfer.tdc3 = 0;
    transfer.expires = monotonic_ms() + file_distribution().value("extension_ms", 60000u);
    count("fd_extended");
  }
  mcdata::FdHttpTermination answer;
  answer.conversation = request.conversation;
  answer.message = request.message;
  answer.type = mcdata::TerminationType::ExtensionResponse;
  answer.extension = granted ? mcdata::ExtensionResponse::Accepted : mcdata::ExtensionResponse::Rejected;
  answer.file_url = transfer.file_url;
  send_termination(sender.id, answer);
  event("mcdata_file_extension", {{"user_id", sender.id}, {"message_id", message_id}, {"granted", granted}});
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 13.2.1.1 and 6.3.6.1: an FD HTTP TERMINATION from the server to one MCData user,
// with the reason of a server-initiated release when there is one.
void DataServer::send_termination(const std::string &id, const mcdata::FdHttpTermination &message,
                                  const std::string &reason) {
  const std::vector<BodyPart> binary{{mcdata::signalling_mime, mcdata::encode(message)}};
  pending_.push_back([this, id, binary, reason] {
    if (const auto *target = by_id(id)) {
      mcdata::Info info;
      deliver(*target, info, binary, "fd-termination", reason);
    }
  });
}

//------------------------------------------------------------------------------
// TS 24.282 clause 13.2.3.3.4: the server releases a transmission by its own policy, deleting the
// file and telling the originator that the transmission was stopped.
bool DataServer::stop_transmission(const std::string &message_id, const std::string &reason) {
  const auto found = transfers_.find(message_id);
  if (found == transfers_.end()) return false;
  auto &transfer = found->second;
  const auto originator = transfer.originator;
  const auto conversation = transfer.conversation;
  const auto file_url = transfer.file_url;
  file_expired(message_id, transfer, mcdata::FdNetworkNotificationType::Deleted);
  mcdata::FdHttpTermination stopped;
  stopped.conversation = mcdata::parse_uuid(conversation);
  stopped.message = mcdata::parse_uuid(message_id);
  stopped.type = mcdata::TerminationType::TransmissionStopped;
  stopped.file_url = file_url;
  send_termination(originator, stopped, reason.empty() ? "communication release policy" : reason);
  count("fd_stopped");
  event("mcdata_file_stopped", {{"message_id", message_id}, {"originator", originator}, {"reason", reason}});
  return true;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 13.2.4.5.4.1: before releasing, the controlling MCData function may tell the originator of its
// intent and give it timer TDC3 (request for extension) to ask for an extension.
void DataServer::release_intent(const std::string &message_id, FileTransfer &transfer, const std::string &reason) {
  transfer.intent_sent = true;
  transfer.tdc3 = monotonic_ms() + file_distribution().value("tdc3_ms", 15000u);
  mcdata::FdHttpTermination intent;
  intent.conversation = mcdata::parse_uuid(transfer.conversation);
  intent.message = mcdata::parse_uuid(message_id);
  intent.type = mcdata::TerminationType::IntentToRelease;
  intent.file_url = transfer.file_url;
  send_termination(transfer.originator, intent, reason);
  event("mcdata_file_release_intent", {{"message_id", message_id}, {"originator", transfer.originator}});
}

} // namespace mcx
