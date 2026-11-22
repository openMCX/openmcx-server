//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The private implementation of mcx::SipEngine (include/mcx/sip.hpp) on reSIProcate 1.14 (prototype/resiprocate/
// PLAN.md, phase 3a): the stack in one epoll poll group driven from SipEngine::poll, its TLS (with the TLS profile) or
// debug TCP transport, and a transaction user that turns received requests and responses into the engine's SipMessage
// and SipResponse. Requests are written as text, as the pjproject engine builds them through pjsip, and parsed into
// reSIProcate messages; the body filters run before a message is handed to the stack, on the next hop's address.
//
// Phase 3a covers the engine core: requests and responses outside dialogs (request, publish, respond with deferred
// responses), the 420 check of an initial INVITE, the body filters. Registration and IMS AKA (3b), INVITE sessions
// (3c) and subscriptions and the rest (3d) refuse with a std::logic_error naming their phase.
//
// Private to src/sip_resip/.
//
// Specifications: RFC 3261, RFC 2046, RFC 5621, TS 24.229 V19.7.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 33.180
// V19.4.0 (Rel-19).
#pragma once

#include "mcx/sip.hpp"

#include "../sip_common/sip_common.hpp"

#include "resip/stack/SipMessage.hxx"
#include "resip/stack/SipStack.hxx"
#include "resip/stack/TransactionUser.hxx"
#include "rutil/FdPoll.hxx"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

// The engine's transaction user: every request and response of the stack comes to its queue.
class ResipUser : public resip::TransactionUser {
public:
  const resip::Data &name() const override;
  // The next message of the queue, if any.
  std::unique_ptr<resip::SipMessage> next();
};

struct SipEngine::Impl {
  Impl(SipConfig value, SipCallbacks handlers);
  ~Impl();

  // lifecycle.cpp
  void start();
  void stop() noexcept;
  void poll(std::chrono::milliseconds timeout);
  void ensure_started() const;
  void report_error(std::string_view error) const noexcept;

  // requests.cpp
  void send_request(std::string_view method, std::string_view request_uri, std::string_view content_type,
                    std::string_view body, const std::vector<SipHeader> &headers, SipResponseHandler handler);
  void receive_response(const resip::SipMessage &message);

  // incoming.cpp
  void receive_request(const resip::SipMessage &message);
  void send_response(const resip::SipMessage &request, const SipResponse &response);
  void respond_deferred(const std::string &transaction_id, const SipResponse &response);

  // messages.cpp
  [[nodiscard]] SipMessage message_from(const resip::SipMessage &message) const;
  [[nodiscard]] SipResponse response_from(const resip::SipMessage &message) const;
  // Runs the outgoing body filter on text about to be sent to the address; the text with the filtered body, or the
  // text as it was. Throws when the filter does (the message is then not sent).
  [[nodiscard]] std::string protect_outgoing(const std::string &text, const std::string &address) const;
  [[nodiscard]] std::string contact_uri() const;
  [[nodiscard]] bool sips_target(std::string_view request_uri) const;

  SipConfig config;
  SipCallbacks callbacks;
  SipBodyFilter outgoing_filter, incoming_filter;
  bool started = false;
  std::unique_ptr<resip::FdPollGrp> poll_group;
  std::unique_ptr<resip::SipStack> stack;
  ResipUser user;
  // The handlers of the requests sent, by transaction identifier (the top Via's branch).
  std::map<std::string, SipResponseHandler> pending;
  // Deferred requests (SipResponse::deferred), by the engine's transaction identifier.
  std::map<std::string, std::unique_ptr<resip::SipMessage>> deferred;
  unsigned long next_transaction = 0;
};

namespace resip_engine {
//------------------------------------------------------------------------------
// Helper: the text of a reSIProcate value that encodes itself (a URI, a header value).
template <class Value> std::string text_of(const Value &value) {
  resip::Data data;
  {
    resip::DataStream stream(data);
    value.encode(stream);
  }
  return std::string(data.c_str(), data.size());
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.3: the header fields of a message as name and value, in order, as it would be sent.
[[nodiscard]] std::vector<SipHeader> headers_of(const resip::SipMessage &message);

//------------------------------------------------------------------------------
// Helper: the numeric IPv4 address of a host (as the application resolves the SIP core, resolve_ipv4), or the host
// itself when it does not resolve.
[[nodiscard]] std::string resolve_address(const std::string &host);

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.2: the host of the next hop of a request written as text: its top Route's URI, else its
// Request-URI.
[[nodiscard]] std::string next_hop_host(const std::string &text);

//------------------------------------------------------------------------------
// RFC 3261 section 7.3: throws std::invalid_argument for a header field name or value with CR or LF, or an empty name.
void check_header(const SipHeader &header);
} // namespace resip_engine

} // namespace mcx
