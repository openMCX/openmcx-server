//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SipEngine::Impl on reSIProcate: received requests (as receive_request of the pjproject engine, without the dialog
// usages of later phases), their responses, and deferred responses.
//
// Specifications: RFC 3261 sections 8.2, 8.2.2.3, 8.2.6, 17.2.2 and 20.40, TS 33.180 V19.4.0 (Rel-19) clause 9.3.

#include "resip_impl.hpp"

#include "resip/stack/Helper.hxx"

#include <algorithm>
#include <stdexcept>

namespace mcx {
namespace {

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.2.3: the option tags this endpoint supports itself (as pjsip's 100rel and timer modules).
constexpr std::string_view kSupported[] = {"100rel", "timer"};

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.2.3: the option tags of the Require header fields that neither the endpoint nor the application
// (SipConfig::accepted_extensions) supports, comma separated.
std::string unsupported_required(const SipConfig &config, const std::vector<SipHeader> &headers) {
  std::string unsupported;
  for (const auto &header : headers) {
    if (!sip_detail::ascii_equal(header.name, "Require")) continue;
    std::size_t at = 0;
    while (at <= header.value.size()) {
      auto end = header.value.find(',', at);
      if (end == std::string::npos) end = header.value.size();
      auto tag = header.value.substr(at, end - at);
      tag.erase(0, tag.find_first_not_of(" \t"));
      tag.erase(tag.find_last_not_of(" \t") + 1);
      const auto known = [&tag](std::string_view option) { return sip_detail::ascii_equal(option, tag); };
      if (!tag.empty() && std::none_of(std::begin(kSupported), std::end(kSupported), known) &&
          std::none_of(config.accepted_extensions.begin(), config.accepted_extensions.end(), known)) {
        if (!unsupported.empty()) unsupported += ", ";
        unsupported += tag;
      }
      at = end + 1;
    }
  }
  return unsupported;
}

//------------------------------------------------------------------------------
// Helper: a response with status and reason.
SipResponse status(int code, std::string reason) {
  SipResponse response;
  response.status_code = code;
  response.reason = std::move(reason);
  return response;
}
} // namespace

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.6: a response to a received request: the request's Via, From, To (with a tag), Call-ID and
// CSeq, the application's header fields and body (one body, or its parts as multipart/mixed); outgoing protection on
// the request's source address; the stack sends it in the request's server transaction.
std::string SipEngine::Impl::send_response(const resip::SipMessage &request, const SipResponse &response,
                                           const std::string &to_tag) {
  if (response.status_code < 100 || response.status_code > 699) throw std::invalid_argument("invalid SIP status");
  if (response.reason.find_first_of("\r\n") != std::string::npos ||
      response.content_type.find_first_of("\r\n") != std::string::npos)
    throw std::invalid_argument("invalid SIP response reason or content type");
  for (const auto &header : response.headers) resip_engine::check_header(header);
  std::string content_type = response.content_type, body = response.body;
  if (content_type.empty() && !response.parts.empty()) {
    if (response.parts.size() == 1) {
      content_type = response.parts.front().content_type;
      body = response.parts.front().body;
    } else {
      content_type = "multipart/mixed; boundary=mcx-response";
      body = multipart_body(response.parts, "mcx-response");
    }
  }
  if (body.size() > sip_detail::kMaximumSipBodyBytes) throw std::invalid_argument("SIP body exceeds configured bound");

  resip::SipMessage base;
  resip::Helper::makeResponse(base, request, response.status_code,
                              response.reason.empty() ? resip::Data::Empty : resip::Data(response.reason));
  if (!to_tag.empty()) base.header(resip::h_To).param(resip::p_tag) = resip::Data(to_tag);
  // The prepared response as text, without its Content-Length, with the application's header fields and body.
  auto text = resip_engine::text_of(base);
  text.erase(text.find("\r\n\r\n") + 2);
  std::string section;
  // Helper::makeResponse adds an empty Contact to an answer that creates a dialog: the engine sets its own.
  for (const auto &header : resip_engine::headers_of(base))
    if (!sip_detail::ascii_equal(header.name, "Content-Length") && !sip_detail::ascii_equal(header.name, "Contact"))
      section += header.name + ": " + header.value + "\r\n";
  for (const auto &header : response.headers) section += header.name + ": " + header.value + "\r\n";
  if (!content_type.empty()) section += "Content-Type: " + content_type + "\r\n";
  const auto start_line = text.substr(0, text.find("\r\n"));
  text = start_line + "\r\n" + section + "Content-Length: " + std::to_string(content_type.empty() ? 0 : body.size()) +
         "\r\n\r\n" + (content_type.empty() ? std::string() : body);

  text = protect_outgoing(text, resip::Tuple::inet_ntop(request.getSource()).c_str());
  const resip::Data wire(text);
  std::unique_ptr<resip::SipMessage> message(resip::SipMessage::make(wire, false));
  if (message == nullptr) throw std::invalid_argument("invalid SIP response");
  if (response.status_code >= 200) transaction_ended(request.getTransactionId().c_str());
  stack->send(std::move(message), &user);
  return text;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2 (as receive_request of the pjproject engine): a received request. ACK and CANCEL go to the
// INVITE dialogs (dialogs.cpp), as does any request with a To tag. An initial request whose Call-ID is a dialog's
// gets 482 (Loop Detected, a merged request, section 8.2.2.2), an initial INVITE with an unknown required extension
// 420 (Bad Extension, section 8.2.2.3), both before the application. Otherwise the application's response: kept for
// SipEngine::respond (deferred), the UAS dialog of an INVITE answered 1xx or 2xx with media (or deferred provisional),
// or sent at once; 400 Bad Request when the request cannot be handled.
void SipEngine::Impl::receive_request(const resip::SipMessage &message) {
  const auto method = message.method();
  try {
    if (method == resip::ACK) return receive_ack(message);
    if (method == resip::CANCEL) return receive_cancel(message);
    if (message.header(resip::h_To).exists(resip::p_tag)) return receive_in_dialog(message);
    const bool invite = method == resip::INVITE;
    if (dialogs.contains(message.header(resip::h_CallId).value().c_str())) {
      send_response(message, status(482, "Loop Detected"));
      return;
    }
    SipMessage request = message_from(message);
    if (invite) {
      const auto unsupported = unsupported_required(config, request.headers);
      if (!unsupported.empty()) {
        auto refusal = status(420, "Bad Extension");
        refusal.headers.push_back({"Unsupported", unsupported});
        send_response(message, refusal);
        return;
      }
    }

    request.transaction_id = std::to_string(++next_transaction);
    SipResponse response = safe_application_response(request);

    if (response.deferred && !invite) {
      if (method == resip::SUBSCRIBE)
        throw std::logic_error("deferred SUBSCRIBE on reSIProcate: prototype/resiprocate/PLAN.md phase 3d");
      // RFC 3261 section 17.2.2: the server transaction waits for the response (SipEngine::respond).
      deferred[request.transaction_id] = std::make_unique<resip::SipMessage>(message);
      return;
    }
    if (invite && response.status_code >= 100 && response.status_code < 300 &&
        (response.local_media || response.local_sdp || (response.deferred && response.status_code < 200))) {
      (void)receive_initial_invite(message, request, response);
      return;
    }
    if (method == resip::SUBSCRIBE && response.status_code >= 200 && response.status_code < 300) {
      report_error("subscriptions on reSIProcate: prototype/resiprocate/PLAN.md phase 3d");
      send_response(message, status(501, "Not Implemented"));
      return;
    }
    send_response(message, response);
    return;
  } catch (const std::exception &error) {
    report_error(error.what());
  } catch (...) {
    report_error("unknown SIP request handling error");
  }
  if (method == resip::ACK) return;
  try {
    send_response(message, status(400, "Bad Request"));
  } catch (...) {
    // The request may already have its answer; there is nothing left to tell.
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.6: the application's final response to a deferred request (an unknown or answered identifier
// is ignored).
void SipEngine::Impl::respond_deferred(const std::string &transaction_id, const SipResponse &response) {
  const auto found = deferred.find(transaction_id);
  if (found == deferred.end()) return;
  // A deferred re-INVITE (dialogs.cpp): a provisional answer keeps it waiting; its dialog may have ended meanwhile.
  if (found->second->method() == resip::INVITE) {
    const auto dialog = dialogs.find(found->second->header(resip::h_CallId).value().c_str());
    if (dialog == dialogs.end() || !dialog->second->incoming_offer) {
      deferred.erase(found);
      return;
    }
    if (response.status_code > 100 && response.status_code < 200) {
      answer_offer(*dialog->second, *found->second, response);
      return;
    }
    const auto request = std::move(found->second);
    deferred.erase(found);
    answer_offer(*dialog->second, *request, response);
    return;
  }
  if (response.status_code < 200 || response.status_code > 699)
    throw std::invalid_argument("invalid deferred response status");
  const auto request = std::move(found->second);
  deferred.erase(found);
  send_response(*request, response);
}

} // namespace mcx
