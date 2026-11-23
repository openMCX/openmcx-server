//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SipEngine::Impl on reSIProcate: received requests and responses as the application sees them (SipMessage,
// SipResponse), the body filters of application signalling protection, and the header and address helpers.
//
// Specifications: RFC 3261 sections 7, 8.1.1.8, 8.1.2 and 20, RFC 2046 section 5.1, RFC 5621, TS 33.180 V19.4.0
// (Rel-19) clause 9.3, TS 24.379 V19.7.0 (Rel-19) clause 6.6.

#include "resip_impl.hpp"

#include "resip/stack/Uri.hxx"

#include <arpa/inet.h>
#include <netdb.h>

#include <stdexcept>

namespace mcx {
namespace resip_engine {

//------------------------------------------------------------------------------
// RFC 3261 section 7.3: the header fields of a message as it is encoded, in order (folded lines joined).
std::vector<SipHeader> headers_of(const resip::SipMessage &message) {
  const auto wire = text_of(message);
  const auto end = wire.find("\r\n\r\n");
  const auto section = wire.substr(0, end == std::string::npos ? wire.size() : end);
  std::vector<SipHeader> headers;
  std::size_t at = section.find("\r\n"); // past the start line
  while (at != std::string::npos && at < section.size()) {
    at += 2;
    auto line_end = section.find("\r\n", at);
    std::string line = section.substr(at, line_end == std::string::npos ? std::string::npos : line_end - at);
    // RFC 3261 section 7.3.1: a line starting with white space continues the previous one.
    while (line_end != std::string::npos && line_end + 2 < section.size() &&
           (section[line_end + 2] == ' ' || section[line_end + 2] == '\t')) {
      const auto next = section.find("\r\n", line_end + 2);
      line += " " + section.substr(line_end + 2, next == std::string::npos ? std::string::npos : next - line_end - 2);
      line_end = next;
    }
    const auto colon = line.find(':');
    if (colon != std::string::npos) {
      auto value = line.substr(colon + 1);
      value.erase(0, value.find_first_not_of(" \t"));
      auto name = line.substr(0, colon);
      name.erase(name.find_last_not_of(" \t") + 1);
      headers.push_back({name, value});
    }
    at = line_end;
  }
  return headers;
}

//------------------------------------------------------------------------------
// Helper: the numeric IPv4 address of a host, or the host as it is when it does not resolve.
std::string resolve_address(const std::string &host) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  addrinfo *found = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &found) != 0 || found == nullptr) return host;
  char text[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(found->ai_addr)->sin_addr, text, sizeof text);
  freeaddrinfo(found);
  return text;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.2: the next hop of a request: the host of its top Route (a loose route), else of its
// Request-URI.
std::string next_hop_host(const std::string &text) {
  const resip::Data wire(text);
  std::unique_ptr<resip::SipMessage> message(resip::SipMessage::make(wire, false));
  if (message == nullptr) throw std::invalid_argument("invalid SIP request");
  if (message->exists(resip::h_Routes) && !message->header(resip::h_Routes).empty())
    return message->header(resip::h_Routes).front().uri().host().c_str();
  return message->header(resip::h_RequestLine).uri().host().c_str();
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.3: a header field must have a name and neither may hold CR or LF (no header injection).
void check_header(const SipHeader &header) {
  if (header.name.empty() || header.name.find_first_of("\r\n: \t") != std::string::npos ||
      header.value.find_first_of("\r\n") != std::string::npos)
    throw std::invalid_argument("invalid SIP header");
}

namespace {
//------------------------------------------------------------------------------
// Helper: the raw body of a message, and its Content-Type as sent (empty without a body).
std::pair<std::string, std::string> body_of(const resip::SipMessage &message) {
  const auto &raw = message.getRawBody();
  std::string body(raw.getBuffer() == nullptr ? "" : std::string(raw.getBuffer(), raw.getLength()));
  // No body for Content-Length 0: a Content-Type without a body is not reported, so
  // that an empty final NOTIFY "application/pidf+xml" is a NOTIFY without state (RFC 6665 section 4.1.2.3), not an
  // empty document.
  const auto content_type = body.empty() ? std::string() : std::string(get_header(headers_of(message), "Content-Type"));
  // A multipart body may start with a line break before its first delimiter (RFC 2046 section 5.1.1 preamble).
  if (content_type.starts_with("multipart/") && body.starts_with("\r\n--")) body.erase(0, 2);
  return {content_type, body};
}

//------------------------------------------------------------------------------
// Helper: the transmission of a message for the body filters.
SipTransmission transmission_of(const resip::SipMessage &message, const std::string &address,
                                const std::vector<SipHeader> &headers) {
  SipTransmission transmission;
  transmission.response = message.isResponse();
  transmission.address = address;
  if (transmission.response) {
    // RFC 3261 section 20.16: a response's method is its CSeq's.
    const auto &cseq = message.header(resip::h_CSeq);
    transmission.method = cseq.method() == resip::UNKNOWN ? cseq.unknownMethodName().c_str()
                                                          : resip::getMethodName(cseq.method()).c_str();
  } else {
    transmission.method = message.methodStr().c_str();
  }
  if (!transmission.response) transmission.request_uri = text_of(message.header(resip::h_RequestLine).uri());
  transmission.from_uri = text_of(message.header(resip::h_From).uri());
  transmission.to_uri = text_of(message.header(resip::h_To).uri());
  transmission.headers = headers;
  transmission.call_id = message.header(resip::h_CallId).value().c_str();
  return transmission;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3: the parts through the incoming filter; the raw
// body is kept consistent with them; a refusal is the message's protection_error.
template <class Received>
void protect_incoming(const SipBodyFilter &filter, const resip::SipMessage &message, const std::string &source,
                      Received &result) {
  if (!filter || result.parts.empty()) return;
  try {
    auto filtered = filter(transmission_of(message, source, result.headers), result.parts);
    const bool same = filtered.size() == result.parts.size() &&
                      std::equal(filtered.begin(), filtered.end(), result.parts.begin(), [](const auto &a, const auto &b) {
                        return a.content_type == b.content_type && a.body == b.body && a.content_id == b.content_id;
                      });
    if (same) return;
    result.parts = std::move(filtered);
    if (result.parts.size() == 1) {
      result.content_type = result.parts.front().content_type;
      result.body = result.parts.front().body;
    } else {
      result.content_type = "multipart/mixed; boundary=mcx-opened";
      result.body = multipart_body(result.parts, "mcx-opened");
    }
  } catch (const std::exception &error) {
    result.protection_error = error.what();
  }
}
} // namespace
} // namespace resip_engine

using namespace resip_engine;

//------------------------------------------------------------------------------
// RFC 3261 section 7.1 and RFC 5621: a received request: method, URIs,
// Call-ID (also its dialog identifier), source, body and parts, the audio or video SDP, header fields; then incoming
// protection.
SipMessage SipEngine::Impl::message_from(const resip::SipMessage &message) const {
  SipMessage result;
  result.method = message.methodStr().c_str();
  result.request_uri = text_of(message.header(resip::h_RequestLine).uri());
  result.from_uri = text_of(message.header(resip::h_From).uri());
  result.to_uri = text_of(message.header(resip::h_To).uri());
  result.call_id = message.header(resip::h_CallId).value().c_str();
  result.dialog_id = result.call_id;
  result.source_address = resip::Tuple::inet_ntop(message.getSource()).c_str();
  std::tie(result.content_type, result.body) = body_of(message);
  if (result.body.size() > sip_detail::kMaximumSipBodyBytes) throw std::invalid_argument("SIP body exceeds bound");
  result.headers = headers_of(message);
  if (!result.body.empty()) {
    try {
      if (result.content_type.starts_with("multipart/"))
        result.parts = parse_body_parts(result.content_type, result.body);
      else
        result.parts.push_back({result.content_type, result.body});
      for (const auto &part : result.parts) {
        // The SDP of a MESSAGE offers no session (TS 24.379 clause 14.2.2.2 step 5); other media than audio and video
        // (the MSRP stream of the MCData media plane) is left to the application.
        if (part.content_type.starts_with("application/sdp") && result.method != "MESSAGE") {
          if (part.body.find("m=audio") != std::string::npos || part.body.find("m=video") != std::string::npos)
            result.remote_media = parse_sdp(part.body);
          break;
        }
      }
    } catch (const std::exception &error) {
      throw std::invalid_argument("invalid incoming SIP body with Content-Type '" + result.content_type +
                                  "': " + error.what());
    }
  }
  protect_incoming(incoming_filter, message, result.source_address, result);
  return result;
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.2 and RFC 5621: a received or locally generated
// response (a timeout's 408, a transport failure's 503): status, reason, body and parts, header fields, its Call-ID as
// dialog identifier; then incoming protection.
SipResponse SipEngine::Impl::response_from(const resip::SipMessage &message) const {
  SipResponse response;
  response.status_code = message.header(resip::h_StatusLine).statusCode();
  response.reason = message.header(resip::h_StatusLine).reason().c_str();
  std::tie(response.content_type, response.body) = body_of(message);
  if (!response.body.empty()) {
    response.parts = response.content_type.starts_with("multipart/")
                         ? parse_body_parts(response.content_type, response.body)
                         : std::vector<BodyPart>{{response.content_type, response.body}};
  }
  response.headers = headers_of(message);
  const std::string source = resip::Tuple::inet_ntop(message.getSource()).c_str();
  protect_incoming(incoming_filter, message, source, response);
  response.dialog_id = message.header(resip::h_CallId).value().c_str();
  return response;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3: the body parts of a message about to be sent to
// the address through the outgoing filter; when it changed them, the body is rebuilt: one part as a plain body (of a
// message that had no multipart body), several as multipart/mixed (RFC 5621, RFC 2392).
std::string SipEngine::Impl::protect_outgoing(const std::string &text, const std::string &address) const {
  if (!outgoing_filter) return text;
  const resip::Data wire(text);
  std::unique_ptr<resip::SipMessage> message(resip::SipMessage::make(wire, false));
  if (message == nullptr) throw std::invalid_argument("invalid SIP message");
  const auto [type, body] = body_of(*message);
  if (type.empty() || body.empty()) return text;
  std::vector<BodyPart> parts;
  try {
    parts = parse_body_parts(type, body);
  } catch (const std::exception &) {
    return text; // not a body the filter protects
  }
  const auto headers = headers_of(*message);
  auto filtered = outgoing_filter(transmission_of(*message, address, headers), parts);
  const bool same = filtered.size() == parts.size() &&
                    std::equal(filtered.begin(), filtered.end(), parts.begin(), [](const auto &a, const auto &b) {
                      return a.content_type == b.content_type && a.body == b.body && a.content_id == b.content_id;
                    });
  if (same) return text;
  std::string new_type, new_body;
  if (filtered.size() == 1 && !type.starts_with("multipart/")) {
    new_type = filtered.front().content_type;
    new_body = filtered.front().body;
  } else {
    new_type = "multipart/mixed; boundary=mcx-protected";
    new_body = multipart_body(filtered, "mcx-protected");
  }
  // The header section with the new Content-Type and Content-Length, then the new body.
  std::string section;
  for (const auto &line_header : headers) {
    if (sip_detail::ascii_equal(line_header.name, "Content-Type") ||
        sip_detail::ascii_equal(line_header.name, "Content-Length"))
      continue;
    section += line_header.name + ": " + line_header.value + "\r\n";
  }
  const auto start_line = text.substr(0, text.find("\r\n"));
  return start_line + "\r\n" + section + "Content-Type: " + new_type +
         "\r\nContent-Length: " + std::to_string(new_body.size()) + "\r\n\r\n" + new_body;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.1.8: this endpoint's Contact header field value with the service tags (contact_target and
// service_tags of src/sip_common).
std::string SipEngine::Impl::contact_uri() const {
  return "<" + sip_detail::contact_target(config) + ">" + sip_detail::service_tags(config);
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.1.8: whether a request goes to a SIPS URI (its Request-URI's, or the core's).
bool SipEngine::Impl::sips_target(std::string_view request_uri) const {
  return sip_detail::ascii_lower(std::string(request_uri)).starts_with("sips:") ||
         sip_detail::ascii_lower(config.core_uri).starts_with("sips:");
}

} // namespace mcx
