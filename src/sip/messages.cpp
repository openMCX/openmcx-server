//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SIP messages: contacts, bodies and their protection hooks, conversion of pjsip messages to the engine's types.
//
// Specifications: RFC 3261, RFC 3840, RFC 4579, RFC 5621, RFC 2046, RFC 2392, TS 24.379 V19.7.0 (Rel-19),
// TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 24.229.

#include "sip_impl.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.1.8: the bare Contact URI of this endpoint, a sip: URI with the transport in use
// (transport=tls, or transport=tcp for debug), with ;ob for an RFC 5626 outbound client (section 5.4). IMS uses no
// SIPS (TS 24.229): TLS protects the hop, and a SIPS Contact is only sent where RFC 3261 requires it (as_sips).
[[nodiscard]] std::string SipEngine::Impl::contact_target() const {
  return "sip:" + identity_user(config.identity) + "@" + config.advertise_address + ":" +
         std::to_string(config.listen_port) + (config.tls.enabled ? ";transport=tls" : ";transport=tcp") +
         (config.outbound_instance.empty() ? "" : ";ob");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.2.1, TS 24.281 clause 7.2.1 and TS 24.282 clause 7.2.1: the media feature tags and the
// g.3gpp.icsi-ref ICSI values of the configured services for the Contact header field (RFC 3840).
[[nodiscard]] std::string SipEngine::Impl::service_tags() const {
  std::string tags = std::string(";+") + config.service->feature_tag;
  std::string icsis = config.service->icsi_encoded;
  for (const auto *other : config.other_services) {
    tags += std::string(";+") + other->feature_tag;
    icsis += std::string(",") + other->icsi_encoded;
  }
  return tags + ";+g.3gpp.icsi-ref=\"" + icsis + "\"";
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.1.8 and RFC 4579: the Contact of a response: this endpoint's, or the checked public URI with
// the service tags (or the response's own), with ;isfocus for a conference focus.
[[nodiscard]] std::string SipEngine::Impl::response_contact(const SipResponse &response) const {
  std::string contact = contact_uri();
  if (!response.contact_uri.empty()) {
    const auto &uri = response.contact_uri;
    if (uri.size() > 2048 || uri.find_first_of("<>\r\n \t") != uri.npos ||
        (!uri.starts_with("sip:") && !uri.starts_with("sips:"))) {
      throw std::invalid_argument("invalid public SIP Contact URI");
    }
    contact = "<" + uri + ">" + (response.contact_tags.empty() ? service_tags() : response.contact_tags);
  }
  if (response.focus) contact += ";isfocus";
  return contact;
}

//------------------------------------------------------------------------------
// RFC 3261 sections 8.1.1.8 and 12.1.1: a Contact header field value with its sip: URI made a SIPS URI, for a
// request to a SIPS target and for the answer to a request that started a dialog with one.
[[nodiscard]] std::string SipEngine::Impl::as_sips(std::string contact) {
  const auto at = contact.starts_with('<') ? 1U : 0U;
  if (contact.compare(at, 4, "sip:") == 0) contact.insert(at + 3, "s");
  return contact;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.1.8: whether a request to this Request-URI, routed through the SIP core (the top Route),
// carries a SIPS URI that the Contact must then match.
[[nodiscard]] bool SipEngine::Impl::sips_target(std::string_view request_uri) const {
  return ascii_lower(std::string(request_uri)).starts_with("sips:") ||
         ascii_lower(config.core_uri).starts_with("sips:");
}

//------------------------------------------------------------------------------
// RFC 3261 section 12.1.1: whether a request that starts a dialog has a SIPS URI in its Request-URI, in its top
// Record-Route or, without Record-Route, in its Contact.
[[nodiscard]] bool SipEngine::Impl::sips_request(const pjsip_rx_data *data) {
  const auto *msg = data->msg_info.msg;
  if (PJSIP_URI_SCHEME_IS_SIPS(msg->line.req.uri)) return true;
  if (const auto *route = data->msg_info.record_route; route != nullptr)
    return PJSIP_URI_SCHEME_IS_SIPS(route->name_addr.uri);
  const auto *contact = static_cast<const pjsip_contact_hdr *>(pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, nullptr));
  return contact != nullptr && contact->uri != nullptr && PJSIP_URI_SCHEME_IS_SIPS(contact->uri);
}

//------------------------------------------------------------------------------
// Helper: true when two body part lists have the same content types, bodies and Content-IDs in the same order.
bool SipEngine::Impl::same_parts(const std::vector<BodyPart> &left, const std::vector<BodyPart> &right) {
  if (left.size() != right.size()) return false;
  for (std::size_t index = 0; index < left.size(); ++index)
    if (left[index].content_type != right[index].content_type || left[index].body != right[index].body ||
        left[index].content_id != right[index].content_id)
      return false;
  return true;
}

//------------------------------------------------------------------------------
// RFC 3261 section 20.16: the method of a message's CSeq header field (empty without one).
std::string SipEngine::Impl::cseq_method(pjsip_msg *message) {
  const auto *cseq = static_cast<const pjsip_cseq_hdr *>(pjsip_msg_find_hdr(message, PJSIP_H_CSEQ, nullptr));
  return cseq == nullptr ? std::string{} : string_from(cseq->method.name);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3: the transmit hook for application signalling protection; runs after every sending path,
// before the message is printed, passes the body parts to the outgoing filter and rebuilds the body
// (multipart/mixed with Content-ID per RFC 5621, RFC 2392) when the filter changed them.
pj_status_t SipEngine::Impl::protect_outgoing(pjsip_tx_data *data) {
  auto *owner = active.load();
  if (owner == nullptr || !owner->outgoing_filter || data == nullptr || data->msg == nullptr ||
      data->msg->body == nullptr)
    return PJ_SUCCESS;
  try {
    auto *message = data->msg;
    SipTransmission transmission;
    transmission.response = message->type == PJSIP_RESPONSE_MSG;
    transmission.address = data->tp_info.dst_name;
    transmission.method = transmission.response ? cseq_method(message) : string_from(message->line.req.method.name);
    if (!transmission.response) transmission.request_uri = print_uri(message->line.req.uri);
    transmission.from_uri = bare_header_uri(message, PJSIP_H_FROM);
    transmission.to_uri = bare_header_uri(message, PJSIP_H_TO);
    transmission.headers = collect_headers(message);

    const auto type = content_type_from(message);
    auto text = print_body(message->body);
    // A multipart body is printed with a leading line break before its first delimiter.
    if (type.starts_with("multipart/") && text.starts_with("\r\n--")) text.erase(0, 2);
    if (type.empty() || text.empty()) return PJ_SUCCESS;
    std::vector<BodyPart> parts;
    try {
      parts = parse_body_parts(type, text);
    } catch (const std::exception &) {
      return PJ_SUCCESS; // not a body the filter protects
    }

    auto filtered = owner->outgoing_filter(transmission, parts);
    if (same_parts(parts, filtered)) return PJ_SUCCESS;
    if (filtered.size() == 1 && !type.starts_with("multipart/"))
      message->body = make_text_body(data->pool, filtered.front().content_type, filtered.front().body);
    else {
      // A real multipart body: the INVITE session later looks for the SDP in it.
      message->body = make_multipart_body(data->pool, filtered);
    }
    pjsip_tx_data_invalidate_msg(data);
  } catch (const std::exception &error) {
    owner->report_error(std::string("outgoing body protection: ") + error.what());
    return PJ_EINVAL;
  } catch (...) {
    owner->report_error("outgoing body protection: unknown error");
    return PJ_EINVAL;
  }
  return PJ_SUCCESS;
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.2 and RFC 5621: converts a received response (status, reason, body and parts, headers,
// Call-ID) and applies incoming protection; 503 when there is no message (transport failure).
[[nodiscard]] SipResponse SipEngine::Impl::response_from(pjsip_rx_data *data) const {
  SipResponse response;
  if (data == nullptr || data->msg_info.msg == nullptr) {
    response.status_code = 503;
    response.reason = "SIP transport failure";
    return response;
  }
  auto *message = data->msg_info.msg;
  response.status_code = message->line.status.code;
  response.reason = string_from(message->line.status.reason);
  response.content_type = content_type_from(message);
  if (response.content_type.starts_with("multipart/") && message->body) {
    pj_str_t raw{};
    if (pjsip_multipart_get_raw(message->body, nullptr, &raw) != PJ_SUCCESS || !raw.ptr || raw.slen < 0 ||
        static_cast<std::size_t>(raw.slen) > kMaximumSipBodyBytes)
      throw std::invalid_argument("multipart response lacks retained MIME data");
    response.body = string_from(raw);
    if (response.body.starts_with("\r\n--")) response.body.erase(0, 2);
  } else
    response.body = print_body(message->body);
  if (!response.body.empty()) response.parts = parse_body_parts(response.content_type, response.body);
  response.headers = collect_headers(message);
  protect_incoming(message, data->pkt_info.src_name, response);
  response.dialog_id = call_id_from(message);
  return response;
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.1 and RFC 5621: converts a received request (method, URIs, Call-ID, body and parts, the
// audio or video SDP, headers) and applies incoming protection.
[[nodiscard]] SipMessage SipEngine::Impl::message_from(pjsip_rx_data *data) const {
  auto *message = data->msg_info.msg;
  SipMessage result;
  result.method = string_from(message->line.req.method.name);
  result.request_uri = print_uri(message->line.req.uri);
  result.from_uri = bare_header_uri(message, PJSIP_H_FROM);
  result.to_uri = bare_header_uri(message, PJSIP_H_TO);
  result.call_id = call_id_from(message);
  result.dialog_id = result.call_id;
  result.source_address = data->pkt_info.src_name;

  result.content_type = content_type_from(message);
  if (result.content_type.starts_with("multipart/") && message->body != nullptr) {
    pj_str_t raw_body{};
    if (pjsip_multipart_get_raw(message->body, nullptr, &raw_body) == PJ_SUCCESS && raw_body.ptr != nullptr &&
        raw_body.slen >= 0 && static_cast<std::size_t>(raw_body.slen) <= kMaximumSipBodyBytes) {
      result.body = string_from(raw_body);
      if (result.body.starts_with("\r\n--")) {
        result.body.erase(0, 2);
      }
    } else {
      throw std::invalid_argument("multipart body does not retain raw MIME data");
    }
  } else {
    result.body = print_body(message->body);
  }

  result.headers = collect_headers(message);
  if (!result.body.empty()) {
    try {
      if (result.content_type.starts_with("multipart/")) {
        result.parts = parse_body_parts(result.content_type, result.body);
      } else {
        result.parts.push_back({result.content_type, result.body});
      }
      for (const auto &part : result.parts) {
        if (part.content_type.starts_with("application/sdp")) {
          // Media that is not MCPTT or MCVideo audio and video, such as the
          // MSRP stream of the MCData media plane, is left to the application.
          if (part.body.find("m=audio") != std::string::npos || part.body.find("m=video") != std::string::npos)
            result.remote_media = parse_sdp(part.body);
          break;
        }
      }
    } catch (const std::exception &error) {
      throw std::invalid_argument(std::string("invalid incoming SIP body with Content-Type '") + result.content_type +
                                  "': " + error.what());
    }
  }

  protect_incoming(message, result.source_address, result);
  return result;
}

//------------------------------------------------------------------------------
// Helper: passes an error text to the application's error callback, ignoring its exceptions.
void SipEngine::Impl::report_error(std::string_view error) noexcept {
  if (callbacks.on_error) {
    try {
      callbacks.on_error(error);
    } catch (...) {
      // The error report is the last resort: a failing error callback has nowhere left to report to.
    }
  }
}

} // namespace mcx
