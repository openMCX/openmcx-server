//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Incoming MCData SIP MESSAGE requests: the participating function's checks and the dispatch to the procedures.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.2.3.1, 10.2.4.3.1 and 12.2.2.1: an MCData SIP MESSAGE request received by the
// participating function; the sender is identified and the request dispatched by its MIME bodies.
SipResponse DataServer::message(const SipMessage &sip_request) {
  const auto asserted = asserted_identity(sip_request);
  auto found = users_.find(asserted);
  // TS 24.282 clause 9.2.2.3.1 steps 2 to 3 and clause 12.2.2.1 steps 2 to 3.
  if (asserted.empty() || asserted != sip_request.from_uri || found == users_.end() ||
      found->second.expires <= std::time(nullptr))
    return reject(404, "141 user unknown to the participating function", asserted, "message");
  auto &user = found->second;
  if (sip_request.request_uri != service_uri_)
    return reject(404, "142 unable to determine the controlling function", user.id, "message");

  // The mcdata-info body, parsed once.
  std::optional<mcdata::Info> parsed_info;
  if (const auto *info_part = part(sip_request, mcdata::info_mime)) parsed_info = mcdata::parse_info(info_part->body);
  if (parsed_info) {
    // TS 24.282 clause 16.2.2.1: a "SIP MESSAGE request for emergency notification".
    const auto &alert_info = *parsed_info;
    if (alert_info.alert) {
      if (!alert_info.calling_user.empty() && alert_info.calling_user != user.id)
        return reject(403, "", user.id, "emergency-alert");
      return emergency_alert(sip_request, user, alert_info);
    }
  }
  const bool file = accepts(sip_request, mcdata::fd_icsi);
  if (parsed_info) {
    // TS 24.282 clause 10.2.1.3.4: "SIP MESSAGE request for absolute URI discovery request".
    const auto &discovery = *parsed_info;
    if (discovery.request_type == "msf-disc-req") return media_storage_discovery(user, discovery);
    // TS 24.282 clause 21.3.3.2: control of the storage of communications.
    if (discovery.request_type == "store-comms-in-msgstore-ctrl-req")
      return msgstore_control(sip_request, user, discovery);
  }
  if (!file && !accepts(sip_request, mcdata::sds_icsi)) return reject(403, "", user.id, "message");
  const auto *signalling = part(sip_request, mcdata::signalling_mime);
  const auto *data = part(sip_request, mcdata::payload_mime);
  if (!parsed_info || !signalling)
    return reject(403, "199 expected MIME bodies not in the request", user.id, "message");
  auto info = *parsed_info;
  if (!info.calling_user.empty() && info.calling_user != user.id) return reject(403, "", user.id, "message");
  const auto type = mcdata::message_type(signalling->body);

  // TS 24.282 clause 10.2.4.4.2 steps 3 to 5 and clause 12.2 for file distribution over HTTP.
  if (file || type == mcdata::MessageType::FdSignalling || type == mcdata::MessageType::FdNotification) {
    return message_fd(sip_request, user, info, *signalling, type);
  }
  if (type == mcdata::MessageType::SdsNotification)
    return notification(sip_request, user, info, *signalling);
  if (type != mcdata::MessageType::SdsSignalling || !data)
    return reject(403, "199 expected MIME bodies not in the request", user.id, "message");
  if ((info.request_type == "group-sds" || info.request_type == "ad-hoc-group-sds") && info.client_id != user.client)
    return reject(403, "", user.id, info.request_type.c_str());
  if (info.request_type != "one-to-one-sds" && info.request_type != "group-sds" &&
      info.request_type != "ad-hoc-group-sds")
    return reject(403, "", user.id, "message");
  return sds(sip_request, user, info, *signalling, *data);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.4.4.2 steps 3 to 5 and clause 12.2 for file distribution over HTTP: an FD request, FD
// notification or FD HTTP TERMINATION goes to its procedure.
SipResponse DataServer::message_fd(const SipMessage &sip_request, const User &user, const mcdata::Info &info,
                                   const BodyPart &signalling, mcdata::MessageType type) {
  if (type == mcdata::MessageType::FdNotification) return fd_notification(user, info, signalling);
  if (type == mcdata::MessageType::FdHttpTermination)
    return fd_termination(user, signalling, reason_text(std::string(get_header(sip_request.headers, "Reason"))));
  if (type != mcdata::MessageType::FdSignalling)
    return reject(
        403, "209 one FD SIGNALLING PAYLOAD message or FD HTTP TERMINATION message only must be present in FD request",
        user.id, "fd");
  if (info.request_type != "one-to-one-fd" && info.request_type != "group-fd") return reject(403, "", user.id, "fd");
  if (info.request_type == "group-fd" && info.client_id != user.client) return reject(403, "", user.id, "fd");
  return fd(sip_request, user, info, signalling);
}

} // namespace mcx
