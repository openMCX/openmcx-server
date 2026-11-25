//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SipEngine::Impl on reSIProcate: requests outside dialogs, their final
// responses with the digest retry, and the digest registration.
//
// Specifications: RFC 3261 sections 8.1, 8.1.1, 8.1.2, 8.1.3.5, 10.2, 18.1.1, 18.2.1, 20 and 22, RFC 2617 section
// 3.2.2, RFC 5626 section 4.2, TS 24.229 V19.7.0 (Rel-19) clauses 5.1.1.4.1, 5.1.1.7 and 5.1.2A.1.1.

#include "resip_impl.hpp"

#include "resip/stack/Helper.hxx"
#include "resip/stack/MessageDecorator.hxx"

#include <openssl/rand.h>

#include <algorithm>
#include <stdexcept>

namespace mcx {
namespace resip_engine {

//------------------------------------------------------------------------------
// Helper: random lower-case hexadecimal text of the given number of bytes.
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

//------------------------------------------------------------------------------
// Helper: the values of the header fields of a name, joined with ", " (RFC 3261 section 7.3.1).
std::string joined_header(const std::vector<SipHeader> &headers, std::string_view name) {
  std::string out;
  for (const auto &header : headers)
    if (sip_detail::ascii_equal(header.name, name)) out += (out.empty() ? "" : ", ") + header.value;
  return out;
}
} // namespace resip_engine

using resip_engine::random_hex;

namespace {
// RFC 3261 section 18.2.1 with the engine's published address: once reSIProcate has chosen the transport
// (from the top Via's protocol and sent-by), the sent-by names the advertised address and the port the transport is
// published with (TS 24.229 clause 5.1.2A.1.1 b: with IMS AKA, the protected server port).
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
  // RFC 3261 sections 9.1 and 17.1.1.3: the stack's CANCEL and its ACK of a failure response carry the INVITE's Via.
  bool copyToStackCancels() const override { return true; }
  bool copyToStackFailureAcks() const override { return true; }

private:
  std::string host_;
  int port_;
  resip::Data previous_host_;
  int previous_port_ = 0;
};

//------------------------------------------------------------------------------
// RFC 3261 section 25.1: a method is a token, here of at most 32 characters.
bool valid_method(std::string_view method) {
  if (method.empty() || method.size() > 32U) return false;
  return std::all_of(method.begin(), method.end(), [](char character) {
    return std::isalnum(static_cast<unsigned char>(character)) ||
           std::string_view("-.!%*_+`'~").find(character) != std::string_view::npos;
  });
}

//------------------------------------------------------------------------------
// RFC 3261 sections 8.1.1.8 and 12.1.1: a Contact header field value with its sip: URI made a SIPS URI.
std::string as_sips(std::string contact) {
  const auto at = contact.starts_with('<') ? 1U : 0U;
  if (contact.compare(at, 4, "sip:") == 0) contact.insert(at + 3, "s");
  return contact;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.2: the preloaded Route towards the SIP core, a loose route.
std::string core_route(const SipConfig &config) {
  auto route = "<" + config.core_uri;
  if (route.find(";lr") == std::string::npos) route += ";lr";
  return route + ">";
}

//------------------------------------------------------------------------------
// Helper: the status code of a response.
int status_of(const resip::SipMessage &message) { return message.header(resip::h_StatusLine).statusCode(); }
} // namespace

//------------------------------------------------------------------------------
// The hop of a request without IMS AKA: the TLS (or debug TCP) transport of the listen port, through the Route.
SipEngine::Impl::Hop SipEngine::Impl::default_hop() const {
  Hop hop;
  hop.type = config.tls.enabled ? resip::TLS : resip::TCP;
  hop.via_port = config.listen_port;
  hop.advertised_port = config.listen_port;
  return hop;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.1: a request as text: Via (the hop's protocol and sent-by port on the listen address, a new
// branch, rport), Max-Forwards, the Route header fields, From with its tag, To, Call-ID, CSeq, Contact, the given header
// fields, P-Access-Network-Info when configured (TS 24.229 clause 5.1.2A.1.1, not in ACK and CANCEL), the body.
std::string SipEngine::Impl::write_request(const OutgoingRequest &request, const Hop &hop) const {
  std::string text = request.method + " " + request.request_uri + " SIP/2.0\r\n";
  // The sent-by names the listen address and the port that picks the transport (with IMS AKA, the one of the set);
  // once the transport is chosen it is rewritten to the advertised address and port (AdvertisedVia): the stack
  // replaces a sent-by that is not an address of its own (a host name) with the interface's address.
  text += "Via: SIP/2.0/" + std::string(resip::toData(hop.type).c_str()) + " " + config.listen_address + ":" +
          std::to_string(hop.via_port) + ";branch=z9hG4bK" + random_hex(12) + ";rport\r\n";
  text += "Max-Forwards: 70\r\n";
  for (const auto &route : request.routes) text += "Route: " + route + "\r\n";
  text += "From: " + sip_detail::name_addr(request.from) + ";tag=" + request.from_tag + "\r\n";
  text += "To: " + request.to + "\r\n";
  text += "Call-ID: " + request.call_id + "\r\n";
  text += "CSeq: " + std::to_string(request.cseq) + " " + request.method + "\r\n";
  if (!request.contact.empty()) text += "Contact: " + request.contact + "\r\n";
  for (const auto &header : request.headers) text += header.name + ": " + header.value + "\r\n";
  if (!config.access_network_info.empty() && request.method != "CANCEL" && request.method != "ACK" &&
      get_header(request.headers, "P-Access-Network-Info").empty())
    text += "P-Access-Network-Info: " + config.access_network_info + "\r\n";
  if (!request.content_type.empty()) text += "Content-Type: " + request.content_type + "\r\n";
  text += "Content-Length: " + std::to_string(request.content_type.empty() ? 0 : request.body.size()) + "\r\n\r\n";
  if (!request.content_type.empty()) text += request.body;
  return text;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1: a request outside a dialog: From the identity with a
// new tag, To the Request-URI (or the application's To), a new Call-ID, CSeq 1, this endpoint's Contact (or the
// application's; SIPS for a
// SIPS target), the preloaded Route (to the SIP core; with IMS AKA the P-CSCF and the Service-Route, TS 24.229 clause
// 5.1.2A.1.1) unless the application names a Route, its header fields, the body; with IMS AKA over the set in use
// with the sec-agree header fields (RFC 3329 section 2.3.1).
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

  OutgoingRequest request;
  request.method = std::string(method);
  request.request_uri = std::string(request_uri);
  request.from = config.identity;
  request.from_tag = random_hex(8);
  // RFC 3261 section 8.1.1.2: the To URI is the Request-URI unless the application names another.
  const auto to_override = get_header(headers, "To");
  request.to = to_override.empty() ? sip_detail::name_addr(request_uri) : std::string(to_override);
  request.call_id = random_hex(16);
  // A Contact among the headers replaces this endpoint's (as for an INVITE, create_invite): the media feature tags a
  // service asks for in one request, such as the MCData SDS tag of a REFER over a pre-established session (TS 24.282
  // clauses 9.2.5.2.1.1 step 9 and 9.2.5.3.1.1 step 8). It must build on contact_target().
  const auto override_contact = get_header(headers, "Contact");
  const auto contact = override_contact.empty() ? contact_uri() : std::string(override_contact);
  request.contact = sips_target(request_uri) ? as_sips(contact) : contact;
  if (get_header(headers, "Route").empty())
    request.routes = aka ? aka_routes() : std::vector<std::string>{core_route(config)};
  for (const auto &header : headers)
    if (!sip_detail::ascii_equal(header.name, "To") && !sip_detail::ascii_equal(header.name, "Contact"))
      request.headers.push_back(header);
  request.content_type = std::string(content_type);
  request.body = std::string(body);

  Hop hop = default_hop();
  if (aka) {
    aka_prepare(request);
    hop = aka_hop(*aka->current);
  }
  Pending entry;
  entry.handler = std::move(handler);
  dispatch(write_request(request, hop), hop, std::move(entry));
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3: the outgoing filter on the next hop's address (the forced target's, or the Route's or
// Request-URI's), then the request to the stack; a refusal of the filter sends nothing.
std::string SipEngine::Impl::dispatch(std::string text, Hop hop, Pending entry) {
  std::string host;
  if (!hop.force_target.empty())
    host = resip::Uri(resip::Data(hop.force_target)).host().c_str();
  else
    host = resip_engine::next_hop_host(text);
  text = protect_outgoing(text, resip_engine::resolve_address(host));
  const resip::Data wire(text);
  std::unique_ptr<resip::SipMessage> request(resip::SipMessage::make(wire, false));
  if (request == nullptr) throw std::invalid_argument("invalid SIP request");
  if (aka) aka_size_hop(*request, hop);
  // One address lookup of the next hop's host (no NAPTR or SRV, as OpenMCX's SIP cores need), and so that the
  // requests to one next hop leave in the order sent: a reSIProcate SRV lookup for a Route without port (a proxy's
  // Record-Route) would let a later request with a port overtake it. The host stays a name, which TLS verifies.
  if (hop.force_target.empty()) {
    const auto &next = request->exists(resip::h_Routes) && !request->header(resip::h_Routes).empty()
                           ? request->header(resip::h_Routes).front().uri()
                           : request->header(resip::h_RequestLine).uri();
    const bool secure = next.scheme() == "sips" || hop.type == resip::TLS;
    std::string transport = next.exists(resip::p_transport) ? next.param(resip::p_transport).c_str()
                                                            : std::string(resip::toData(hop.type).c_str());
    if (next.scheme() == "sips") transport = "tls";
    const auto port = next.port() != 0 ? next.port() : (secure ? 5061 : 5060);
    std::string target_host = next.host().c_str();
    if (target_host.find(':') != std::string::npos && !target_host.starts_with('[')) target_host = "[" + target_host + "]";
    hop.force_target = "sip:" + target_host + ":" + std::to_string(port) + ";transport=" + sip_detail::ascii_lower(transport);
  }
  return send_message(std::move(request), std::move(hop), std::move(entry));
}

//------------------------------------------------------------------------------
// Helper: a request (protected, final) to the stack on its hop; its response goes to the entry.
std::string SipEngine::Impl::send_message(std::unique_ptr<resip::SipMessage> request, Hop hop, Pending entry) {
  if (!hop.force_target.empty()) request->setForceTarget(resip::Uri(resip::Data(hop.force_target)));
  entry.text = resip_engine::text_of(*request);
  entry.hop = hop;
  request->addOutboundDecorator(std::make_unique<AdvertisedVia>(config.advertise_address, hop.advertised_port));
  const std::string transaction = request->getTransactionId().c_str();
  // RFC 3261 section 17.1.1.3: an ACK of a 2xx is sent without a transaction and gets no response.
  if (request->method() != resip::ACK) {
    if (aka) aka_track_sent(transaction, hop);
    pending[transaction] = std::move(entry);
  }
  stack->send(std::move(request), &user);
  transmit();
  return transaction;
}

//------------------------------------------------------------------------------
// RFC 3261 sections 8.1.3.5 and 22.2: a 401 or 407 to a request is answered
// once with the configured digest credentials: the request again with a new branch, the CSeq incremented ("MUST be
// incremented") and the Authorization or Proxy-Authorization of the challenge. False when there is nothing to retry.
bool SipEngine::Impl::retry_with_credentials(const resip::SipMessage &challenge, Pending &entry) {
  if (!sip_detail::has_credentials(config)) {
    report_error("SIP authentication challenge received without configured digest credentials");
    return false;
  }
  const resip::Data wire(entry.text);
  std::unique_ptr<resip::SipMessage> request(resip::SipMessage::make(wire, false));
  if (request == nullptr) return false;
  auto &cseq = request->header(resip::h_CSeq);
  cseq.sequence() = cseq.sequence() + 1;
  request->header(resip::h_Vias).front().param(resip::p_branch).reset(resip::Data(random_hex(12)));
  try {
    resip::Helper::addAuthorization(*request, challenge, resip::Data(config.username), resip::Data(config.password),
                                    resip::Data(random_hex(8)), nonce_count);
  } catch (const std::exception &error) {
    report_error(std::string("SIP digest authentication: ") + error.what());
    return false;
  }
  if (!request->exists(resip::h_Authorizations) && !request->exists(resip::h_ProxyAuthorizations)) {
    report_error("SIP digest authentication: no challenge this endpoint can answer");
    return false;
  }
  if (entry.purpose == Purpose::registration && registration) registration->cseq = cseq.sequence();
  // A request of a dialog: its CSeq is the dialog's next one; a retried INVITE or offer keeps the dialog's view.
  const auto purpose = entry.purpose;
  const auto dialog_id = entry.dialog_id;
  Dialog *dialog = nullptr;
  if (const auto found = dialogs.find(dialog_id); !dialog_id.empty() && found != dialogs.end()) {
    dialog = found->second.get();
    dialog->local_cseq = std::max(dialog->local_cseq, cseq.sequence());
    if (purpose == Purpose::offer) dialog->offer_cseq = cseq.sequence();
  }
  entry.retried = true;
  const auto transaction = send_message(std::move(request), entry.hop, std::move(entry));
  if (dialog != nullptr && purpose == Purpose::invite) dialog->invite_transaction = transaction;
  return true;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.3: a final response (received, or the stack's own for a timeout or a transport failure) goes to
// what its request was sent for: the application's handler (after a digest retry), the digest registration, or the
// IMS AKA registration procedure; provisional responses are not passed.
void SipEngine::Impl::receive_response(const resip::SipMessage &message) {
  // RFC 3261 section 9.1: the response to this side's CANCEL (the stack gives it the INVITE's transaction identifier)
  // says nothing of the INVITE, whose own final response follows.
  if (message.header(resip::h_CSeq).method() == resip::CANCEL) return;
  const std::string transaction = message.getTransactionId().c_str();
  const auto found = pending.find(transaction);
  if (found == pending.end()) {
    // RFC 3261 section 13.2.2.4: a retransmitted 2xx of an INVITE (its transaction is over): the ACK again.
    if (status_of(message) / 100 == 2 && message.header(resip::h_CSeq).method() == resip::INVITE) {
      const auto dialog = dialogs.find(message.header(resip::h_CallId).value().c_str());
      if (dialog != dialogs.end() && dialog->second->uac && dialog->second->ack_cseq == message.header(resip::h_CSeq).sequence())
        send_ack(*dialog->second, dialog->second->ack_cseq);
    }
    return;
  }
  if (status_of(message) < 200) {
    if (found->second.purpose == Purpose::invite) invite_response(message, found->second);
    return;
  }
  Pending entry = std::move(found->second);
  pending.erase(found);
  transaction_ended(transaction);

  const int status = status_of(message);
  if (message.isFromWire() && (status == 401 || status == 407) && entry.purpose != Purpose::aka_register &&
      !entry.retried && retry_with_credentials(message, entry))
    return;
  if (entry.purpose == Purpose::aka_register) return aka_registration_result(message);
  if (entry.purpose == Purpose::registration) return registration_result(message);
  if (entry.purpose == Purpose::invite) return invite_response(message, entry);
  if (entry.purpose == Purpose::offer) return offer_response(message, entry);
  if (entry.purpose == Purpose::bye) return bye_response(message, entry);
  if (entry.purpose == Purpose::prack) return;
  if (entry.purpose == Purpose::subscribe) return subscribe_response(message, entry);
  SipResponse response;
  try {
    response = response_from(message);
  } catch (const std::exception &error) {
    report_error(std::string("received SIP response: ") + error.what());
    response.status_code = 500;
    response.reason = "Invalid SIP response";
  }
  dispatch_response(response, entry.handler);
  // RFC 6665 section 4.2.2: this side's terminating NOTIFY, answered: the subscription dialog goes.
  if (entry.ends_subscription)
    if (const auto dialog = dialogs.find(entry.dialog_id); dialog != dialogs.end() && !dialog->second->invite)
      dialogs.erase(dialog);
}

//------------------------------------------------------------------------------
// Helper: a response to the application's general response callback, then to the request's handler; what they throw
// is reported.
void SipEngine::Impl::dispatch_response(const SipResponse &response, const SipResponseHandler &handler) const {
  try {
    if (callbacks.on_response) callbacks.on_response(response);
    if (handler) handler(response);
  } catch (const std::exception &error) {
    report_error(std::string("response handler (") + std::to_string(response.status_code) + "): " + error.what());
  } catch (...) {
    report_error("unknown SIP response handler error");
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 10.2 and RFC 5626 section 4.2: the Contact of a
// REGISTER: this endpoint's (or the registration feature tags in place of the service tags), the media feature tags,
// and +sip.instance with reg-id for an outbound client; SIPS for a SIPS registrar.
std::string SipEngine::Impl::register_contact() const {
  const auto &instance = config.outbound_instance;
  if (instance.find_first_of("\"<>\r\n") != std::string::npos)
    throw std::invalid_argument("invalid SIP outbound instance");
  const auto contact = (config.registration_features.empty()
                            ? contact_uri()
                            : "<" + sip_detail::contact_target(config) + ">" + config.registration_features) +
                       config.media_feature_tags +
                       (instance.empty() ? "" : ";+sip.instance=\"<" + instance + ">\";reg-id=1");
  const auto registrar = "sip:" + sip_detail::identity_domain(config.identity);
  return sips_target(registrar) ? as_sips(contact) : contact;
}

//------------------------------------------------------------------------------
// RFC 3261 section 10.2: a REGISTER of the identity: the Request-URI the home
// domain, From and To the identity, the registration's Call-ID and From tag with the next CSeq, the Contact, Expires
// (0 removes the binding, section 10.2.2), the preloaded Route to the SIP core (the outbound proxy), the body when
// given (the next REGISTER of a refresh has none). A connection a registration_ended() is closing goes first, so that
// this REGISTER opens a new one.
void SipEngine::Impl::register_digest(unsigned expires, std::string_view content_type, std::string_view body,
                                      SipResponseHandler handler) {
  ensure_started();
  if (ending_flow) end_registration();
  if (!registration) {
    registration.emplace();
    registration->call_id = random_hex(16);
    registration->from_tag = random_hex(8);
  }
  registration->expires = expires;
  registration->handler = std::move(handler);
  cancel(Timer::registration_refresh);

  OutgoingRequest request;
  request.method = "REGISTER";
  request.request_uri = "sip:" + sip_detail::identity_domain(config.identity);
  request.from = config.identity;
  request.from_tag = registration->from_tag;
  request.to = sip_detail::name_addr(config.identity);
  request.call_id = registration->call_id;
  request.cseq = ++registration->cseq;
  request.contact = register_contact();
  request.routes = {core_route(config)};
  request.headers.push_back({"Expires", std::to_string(expires)});
  request.content_type = std::string(content_type);
  request.body = std::string(body);
  const auto hop = default_hop();
  Pending entry;
  entry.purpose = Purpose::registration;
  dispatch(write_request(request, hop), hop, std::move(entry));
}

//------------------------------------------------------------------------------
// RFC 3261 section 10.2.4 and TS 24.229 clause 5.1.1.4.1: a 2xx
// grants an expiry (our Contact's expires parameter, else Expires, else what was asked): the refresh comes 600 s
// before it for more than 1200 s, half way otherwise; the response goes to the handler of register_account (kept for
// the refreshes).
void SipEngine::Impl::registration_result(const resip::SipMessage &message) {
  if (!registration) return;
  const int status = status_of(message);
  if (status / 100 == 2 && registration->expires > 0) {
    unsigned granted = registration->expires;
    bool contact_found = false;
    if (message.exists(resip::h_Contacts)) {
      for (const auto &contact : message.header(resip::h_Contacts)) {
        if (contact.isAllContacts() || !contact.exists(resip::p_expires)) continue;
        const auto &uri = contact.uri();
        if (uri.port() == config.listen_port && std::string(uri.host().c_str()) == config.advertise_address) {
          granted = contact.param(resip::p_expires);
          contact_found = true;
          break;
        }
      }
    }
    if (!contact_found && message.exists(resip::h_Expires) && message.header(resip::h_Expires).value() > 0)
      granted = std::min<unsigned>(granted, message.header(resip::h_Expires).value());
    if (granted > 0) {
      const unsigned before = granted > 1200 ? 600 : granted - granted / 2;
      schedule(Timer::registration_refresh, std::chrono::seconds(granted - before));
    }
    if (message.isFromWire()) registration->flow = message.getSource();
  }
  SipResponse response;
  try {
    response = response_from(message);
  } catch (const std::exception &error) {
    report_error(std::string("received SIP response: ") + error.what());
    response.status_code = 500;
    response.reason = "Invalid SIP response";
  }
  dispatch_response(response, registration->handler);
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.7: the closing of a registration's TLS connection, once its transactions had time to end
// (registration_ended): reSIProcate's flow is closed.
void SipEngine::Impl::end_registration() {
  cancel(Timer::flow_end);
  if (!ending_flow) return;
  stack->terminateFlow(*ending_flow);
  ending_flow.reset();
}

} // namespace mcx
