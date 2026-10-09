// Delivery of MCData messages to terminating clients, and the holding and re-delivery of undelivered SDS
// messages (TS 24.282 clauses 9.2.2.4.1.1 and 12.2.2.1; member functions of DataServer, declared in data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.2.3.1 NOTE 4: the "payload size", the payload contents less the content type octet.
std::size_t DataServer::payload_size(const mcdata::DataPayload &payload) {
  std::size_t size = 0;
  for (const auto &content : payload.payloads) size += content.data.size();
  return size;
}

//------------------------------------------------------------------------------
// Helper: the MIME body of the given content type in a SIP request; a duplicate body is an error.
const BodyPart *DataServer::part(const SipMessage &request, const char *type) {
  const BodyPart *found = nullptr;
  for (const auto &body : request.parts)
    if (body.content_type == type) {
      if (found) throw std::runtime_error(std::string("duplicate ") + type + " body");
      found = &body;
    }
  return found;
}

//------------------------------------------------------------------------------
// Helper: whether an Accept-Contact header field (or its compact form "a") of the request carries the
// g.3gpp.icsi-ref media feature tag with the given ICSI.
bool DataServer::accepts(const SipMessage &request, std::string_view icsi) {
  for (const auto &header : request.headers) {
    std::string name = header.name;
    for (auto &character : name) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    if ((name == "accept-contact" || name == "a") && header.value.find("g.3gpp.icsi-ref") != std::string::npos &&
        header.value.find(url_encode(std::string(icsi))) != std::string::npos)
      return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// Helper: an error response with an optional MCData Warning header field (warn-code 399), counted and logged.
SipResponse DataServer::reject(int status, const std::string &warning, const std::string &user, const char *what) {
  SipResponse response;
  response.status_code = status;
  if (!warning.empty()) response.headers = {{"Warning", warning_value(warning)}};
  count("rejected");
  event("mcdata_rejected", {{"user_id", user}, {"request", what}, {"status", status}, {"warning", warning}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.2.4.1.1 and clause 12.2.3 steps 7 to 14: SIP MESSAGE from the controlling MCData
// function to a terminating client (combined with the terminating participating function).
void DataServer::deliver(const User &target, mcdata::Info info, const std::vector<BodyPart> &binary,
                         const std::string &what, const std::string &reason) {
  if (what == "sds") hold(target.id, info, binary);
  info.request_uri = target.id;
  // TS 24.282 clause 9.2.2.4.1.1 step 5c: the requested application priority is delivered as the
  // used priority (local policy keeps the requested value).
  if (what == "sds" || what == "redelivery") info.used_priority = info.user_requested_priority;
  info.user_requested_priority.reset();
  info.access_token.clear();
  info.client_id.clear();
  std::vector<BodyPart> parts{{mcdata::info_mime, mcdata::info_xml(info)}};
  parts.insert(parts.end(), binary.begin(), binary.end());
  parts = seal_for(target.sip, std::move(parts));
  const auto boundary = "mcdata-" + random_id();
  // TS 24.282 clause 9.2.2.4.1.1 steps 2 and 3 and clause 10.2.4.4.1 steps 2 and 3: the SDS or FD service
  // ICSI and feature tag.
  const bool file = what.starts_with("fd");
  const std::string service = file ? mcdata::fd_icsi : mcdata::sds_icsi;
  std::vector<SipHeader> headers{
      {"Accept-Contact", std::string("*;+g.3gpp.mcdata.") + (file ? "fd" : "sds") + ";require;explicit"},
      {"Accept-Contact", "*;+g.3gpp.icsi-ref=\"" + url_encode(service) + "\";require;explicit"},
      {"P-Asserted-Service", service}};
  // TS 24.282 clause 13.2.3.3.4 step 2a: the reason of a server-initiated release.
  if (!reason.empty()) headers.push_back({"Reason", "SIP ;cause=200 ;text=\"" + reason + "\""});
  const auto [type, body] = message_body(parts, boundary);
  sip_.request("MESSAGE", target.sip, type, body, headers, [this, id = target.id, what](const SipResponse &response) {
    if (response.status_code < 200) return;
    if (response.status_code < 300 && what == "sds") count("sds_delivered");
    event("mcdata_delivery_result", {{"user_id", id},
                                     {"request", what},
                                     {"status", response.status_code},
                                     {"warning", std::string(get_header(response.headers, "Warning"))}});
  });
}

//------------------------------------------------------------------------------
// TS 24.282 clause 12.2.2.1 step 5: keeps a copy of a delivered SDS message for a possible UNDELIVERED notification.
void DataServer::hold(const std::string &recipient, const mcdata::Info &info, const std::vector<BodyPart> &binary) {
  if (binary.empty()) return;
  const auto key =
      std::make_pair(recipient, mcdata::uuid_text(mcdata::decode_sds_signalling(binary.front().body).message));
  if (!held_.contains(key)) held_order_.push_back(key);
  held_[key] = {info, binary, monotonic_ms() + redelivery().value("retention_ms", 600000u), 0, 0};
  const auto capacity = redelivery().value("max_held", 1000u);
  while (held_order_.size() > capacity) {
    held_.erase(held_order_.front());
    held_order_.pop_front();
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 12.2.2.1 step 5: store the message for re-delivery and start TDP1. The number of
// re-delivery attempts is bounded by local policy.
void DataServer::undelivered(const std::string &recipient, const std::string &message) {
  count("undelivered");
  const auto found = held_.find({recipient, message});
  if (found == held_.end()) {
    event("mcdata_undelivered_unknown", {{"user_id", recipient}, {"message_id", message}});
    return;
  }
  if (found->second.attempts >= redelivery().value("max_attempts", 3u)) {
    count("redelivery_abandoned");
    event("mcdata_redelivery_abandoned",
          {{"user_id", recipient}, {"message_id", message}, {"attempts", found->second.attempts}});
    held_.erase(found);
    return;
  }
  found->second.redeliver_at = monotonic_ms() + redelivery().value("tdp1_ms", 60000u);
  found->second.retain_until = std::max(found->second.retain_until, found->second.redeliver_at + 1);
  event("mcdata_redelivery_scheduled",
        {{"user_id", recipient}, {"message_id", message}, {"attempt", found->second.attempts + 1}});
}

//------------------------------------------------------------------------------
// TS 24.282 table F.2.1-1: on expiry of TDP1, re-deliver the stored message to the MCData user.
void DataServer::redeliver(const std::pair<std::string, std::string> &key, Held &held) {
  held.redeliver_at = 0;
  const auto *target = by_id(key.first);
  const bool group = !held.info.calling_group.empty() && !adhoc_groups_.contains(held.info.calling_group);
  if (!target || (group && !affiliated(key.first, held.info.calling_group))) {
    // The user logged off or left the group: retry at the next TDP1 while the copy is retained.
    held.redeliver_at = monotonic_ms() + redelivery().value("tdp1_ms", 60000u);
    if (held.redeliver_at >= held.retain_until) {
      count("redelivery_abandoned");
      event("mcdata_redelivery_abandoned",
            {{"user_id", key.first}, {"message_id", key.second}, {"attempts", held.attempts}});
      held.retain_until = 0;
    }
    return;
  }
  ++held.attempts;
  held.retain_until = monotonic_ms() + redelivery().value("retention_ms", 600000u);
  count("sds_redelivered");
  event("mcdata_sds_redelivered", {{"user_id", key.first}, {"message_id", key.second}, {"attempt", held.attempts}});
  deliver(*target, held.info, held.binary, "redelivery");
}

} // namespace mcx
