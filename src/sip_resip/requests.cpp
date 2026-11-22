//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SipEngine::Impl on reSIProcate: requests outside dialogs (as send_request of the pjproject engine) and their final
// responses.
//
// Specifications: RFC 3261 sections 8.1, 8.1.1, 8.1.2, 18.2.1 and 20, RFC 7315 section 5.4, TS 24.229 V19.7.0
// (Rel-19) clause 5.1.2A.1.1.

#include "resip_impl.hpp"

#include "resip/stack/MessageDecorator.hxx"

#include <openssl/rand.h>

#include <stdexcept>

namespace mcx {
namespace {

//------------------------------------------------------------------------------
// Helper: random lower-case hexadecimal text of the given number of bytes (tags, Call-ID, branch).
std::string random_hex(std::size_t bytes) {
  std::vector<unsigned char> value(bytes);
  if (RAND_bytes(value.data(), static_cast<int>(value.size())) != 1) throw std::runtime_error("random SIP identifier");
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (const auto octet : value) {
    out.push_back(digits[octet >> 4]);
    out.push_back(digits[octet & 15]);
  }
  return out;
}

// RFC 3261 section 18.2.1 with the pjproject engine's published address: once reSIProcate has chosen the transport
// (from the top Via's sent-by, the listen address and port), the sent-by names the advertised address and the
// listening port, as pjsip's transport publishes them.
class AdvertisedVia : public resip::MessageDecorator {
public:
  AdvertisedVia(std::string host, int port) : host_(std::move(host)), port_(port) {}

  void decorateMessage(resip::SipMessage &message, const resip::Tuple &, const resip::Tuple &,
                       const resip::Data &) override {
    if (!message.exists(resip::h_Vias) || message.header(resip::h_Vias).empty()) return;
    auto &via = message.header(resip::h_Vias).front();
    previous_host_ = via.sentHost();
    previous_port_ = via.sentPort();
    via.sentHost() = resip::Data(host_);
    via.sentPort() = port_;
  }

  void rollbackMessage(resip::SipMessage &message) override {
    if (!message.exists(resip::h_Vias) || message.header(resip::h_Vias).empty()) return;
    auto &via = message.header(resip::h_Vias).front();
    via.sentHost() = previous_host_;
    via.sentPort() = previous_port_;
  }

  resip::MessageDecorator *clone() const override { return new AdvertisedVia(host_, port_); }

private:
  std::string host_;
  int port_;
  resip::Data previous_host_;
  int previous_port_ = 0;
};

//------------------------------------------------------------------------------
// RFC 3261 section 25.1: a method is a token of at most 32 characters (the pjproject engine's bound).
bool valid_method(std::string_view method) {
  if (method.empty() || method.size() > 32U) return false;
  return std::all_of(method.begin(), method.end(), [](char character) {
    return std::isalnum(static_cast<unsigned char>(character)) || std::string_view("-.!%*_+`'~").find(character) !=
                                                                       std::string_view::npos;
  });
}

//------------------------------------------------------------------------------
// RFC 3261 sections 8.1.1.8 and 12.1.1: a Contact header field value with its sip: URI made a SIPS URI.
std::string as_sips(std::string contact) {
  const auto at = contact.starts_with('<') ? 1U : 0U;
  if (contact.compare(at, 4, "sip:") == 0) contact.insert(at + 3, "s");
  return contact;
}
} // namespace

//------------------------------------------------------------------------------
// RFC 3261 section 8.1 (as send_request of the pjproject engine): a request outside a dialog through the SIP core:
// From the identity with a new tag, To the Request-URI (or the application's To), a new Call-ID, CSeq 1, this
// endpoint's Contact (SIPS for a SIPS target), the preloaded Route to the core unless the application names a Route
// (RFC 3261 section 8.1.2), its header fields, P-Access-Network-Info when configured (TS 24.229 clause 5.1.2A.1.1),
// the body; then outgoing protection on the next hop's address, and the handler gets the final response.
void SipEngine::Impl::send_request(std::string_view method, std::string_view request_uri,
                                   std::string_view content_type, std::string_view body,
                                   const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  ensure_started();
  if (!valid_method(method) || request_uri.empty() || request_uri.find_first_of("\r\n \t<>") != std::string::npos)
    throw std::invalid_argument("invalid SIP request method or URI");
  if (content_type.find_first_of("\r\n") != std::string_view::npos)
    throw std::invalid_argument("invalid SIP content type");
  if (body.size() > sip_detail::kMaximumSipBodyBytes) throw std::invalid_argument("SIP body exceeds configured bound");
  for (const auto &header : headers) resip_engine::check_header(header);

  // RFC 3261 section 8.1.1.2: the To URI is the Request-URI unless the application names another.
  const auto to_override = get_header(headers, "To");
  const std::string to = to_override.empty() ? sip_detail::name_addr(request_uri) : std::string(to_override);
  const auto contact = sips_target(request_uri) ? as_sips(contact_uri()) : contact_uri();
  const char *transport = config.tls.enabled ? "TLS" : "TCP";

  std::string text = std::string(method) + " " + std::string(request_uri) + " SIP/2.0\r\n";
  text += "Via: SIP/2.0/" + std::string(transport) + " " + config.listen_address + ":" +
          std::to_string(config.listen_port) + ";branch=z9hG4bK" + random_hex(12) + ";rport\r\n";
  text += "Max-Forwards: 70\r\n";
  text += "From: " + sip_detail::name_addr(config.identity) + ";tag=" + random_hex(8) + "\r\n";
  text += "To: " + to + "\r\n";
  text += "Call-ID: " + random_hex(16) + "\r\n";
  text += "CSeq: 1 " + std::string(method) + "\r\n";
  text += "Contact: " + contact + "\r\n";
  if (get_header(headers, "Route").empty()) {
    auto route = "<" + config.core_uri;
    if (route.find(";lr") == std::string::npos) route += ";lr";
    text += "Route: " + route + ">\r\n";
  }
  for (const auto &header : headers)
    if (!sip_detail::ascii_equal(header.name, "To")) text += header.name + ": " + header.value + "\r\n";
  if (!config.access_network_info.empty() && method != "CANCEL" && method != "ACK" &&
      get_header(headers, "P-Access-Network-Info").empty())
    text += "P-Access-Network-Info: " + config.access_network_info + "\r\n";
  if (!content_type.empty()) text += "Content-Type: " + std::string(content_type) + "\r\n";
  text += "Content-Length: " + std::to_string(content_type.empty() ? 0 : body.size()) + "\r\n\r\n";
  if (!content_type.empty()) text += body;

  // TS 33.180 clause 9.3: the outgoing filter on the next hop's address; a refusal sends nothing.
  text = protect_outgoing(text, resip_engine::resolve_address(resip_engine::next_hop_host(text)));
  const resip::Data wire(text);
  std::unique_ptr<resip::SipMessage> request(resip::SipMessage::make(wire, false));
  if (request == nullptr) throw std::invalid_argument("invalid SIP request");
  request->addOutboundDecorator(std::make_unique<AdvertisedVia>(config.advertise_address, config.listen_port));
  pending[request->getTransactionId().c_str()] = std::move(handler);
  stack->send(std::move(request), &user);
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.3: a final response (received, or the stack's own for a timeout or a transport failure) goes to
// the application's general response callback, then to the request's handler; provisional responses are not passed.
void SipEngine::Impl::receive_response(const resip::SipMessage &message) {
  if (message.header(resip::h_StatusLine).statusCode() < 200) return;
  const auto found = pending.find(message.getTransactionId().c_str());
  if (found == pending.end()) return;
  auto handler = std::move(found->second);
  pending.erase(found);
  SipResponse response;
  try {
    response = response_from(message);
  } catch (const std::exception &error) {
    report_error(std::string("received SIP response: ") + error.what());
    response.status_code = 500;
    response.reason = "Invalid SIP response";
  }
  try {
    if (callbacks.on_response) callbacks.on_response(response);
    if (handler) handler(response);
  } catch (const std::exception &error) {
    report_error(error.what());
  } catch (...) {
    report_error("unknown SIP response handler error");
  }
}

} // namespace mcx
