//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The private implementation of mcx::SipEngine (include/mcx/sip.hpp) on reSIProcate 1.14 (prototype/resiprocate/
// PLAN.md): the stack in one epoll poll group driven from SipEngine::poll, its transports, and a transaction user that
// turns received requests and responses into the engine's SipMessage and SipResponse. Requests are written as text
// and parsed into reSIProcate messages; the body filters run before a
// message is handed to the stack, on the next hop's address.
//
// The engine core (requests, responses, deferred responses, body filters), registration with digest authentication
// and IMS AKA (ims_aka.cpp, aka_transports.hpp), and dialogs on the engine's own dialog layer (dialogs.cpp): INVITE
// sessions and subscriptions (PLAN.md phases 3a to 3d).
//
// Private to src/sip/.
//
// Specifications: RFC 3261, RFC 2046, RFC 5621, RFC 3329, TS 24.229 V19.7.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19),
// TS 33.180 V19.4.0 (Rel-19), TS 33.203 V19.1.0 (Rel-19).
#pragma once

#include "mcx/ims_aka.hpp"
#include "mcx/sip.hpp"
#include "mcx/xfrm.hpp"

#include "../sip_common/sip_common.hpp"
#include "aka_transports.hpp"

#include "resip/stack/SipMessage.hxx"
#include "resip/stack/SipStack.hxx"
#include "resip/stack/TransactionUser.hxx"
#include "rutil/FdPoll.hxx"

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
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
  // Whether the queue holds a message (SipEngine::Impl::poll does not wait then).
  bool pending() { return mFifo.messageAvailable(); }
};

struct SipEngine::Impl {
  using Clock = std::chrono::steady_clock;

  Impl(SipConfig value, SipCallbacks handlers);
  ~Impl();

  // Where a request goes (RFC 3261 section 18.1.1): reSIProcate picks the transport from the top Via's protocol and
  // sent-by port (the listen address), the next hop is forced when set, and once the transport is chosen the sent-by
  // is rewritten to the advertised address and port.
  struct Hop {
    resip::TransportType type = resip::TCP;
    int via_port = 0;
    std::string force_target; // a SIP URI, or empty for the Route or Request-URI
    int advertised_port = 0;
  };

  // A request written by the engine, before its Via (RFC 3261 section 8.1.1).
  struct OutgoingRequest {
    std::string method, request_uri, from, from_tag, to, call_id;
    unsigned cseq = 1;
    std::string contact;             // the Contact header field value, or empty for none
    std::vector<std::string> routes; // Route header field values, in order
    std::vector<SipHeader> headers;  // the application's or the procedure's, as given
    std::string content_type, body;
  };

  // What a response to a request sent goes to.
  enum class Purpose { request, registration, aka_register, invite, offer, bye, prack, subscribe };

  struct Pending {
    SipResponseHandler handler;
    Purpose purpose = Purpose::request;
    // The request as sent (after outgoing protection), for a retry with credentials (RFC 3261 section 22.2).
    std::string text;
    Hop hop;
    bool retried = false;
    // The dialog of an in-dialog request or initial INVITE (its identifier).
    std::string dialog_id;
    // RFC 6665 section 4.2.2: a NOTIFY with Subscription-State "terminated": its final response ends the dialog.
    bool ends_subscription = false;
  };

  // RFC 3261 section 12: a dialog of this engine, an INVITE session (dialogs.cpp), keyed by its Call-ID.
  struct Dialog {
    enum class State { calling, early, connecting, confirmed, terminated };
    std::string id;
    bool uac = false;
    // An INVITE session, or a subscription dialog (RFC 6665).
    bool invite = true;
    State state = State::calling;
    std::string call_id, local_tag, remote_tag;
    // The From or To header field values of this side and of the peer, without tags.
    std::string local_name, remote_name;
    // RFC 3261 section 12.1: the remote target (the peer's Contact URI) and the route set, in the order used.
    std::string remote_target;
    std::vector<std::string> route_set;
    // A pinned route set (a Route of the application, a peer route): not replaced by Record-Route.
    bool route_frozen = false;
    std::uint32_t local_cseq = 0;
    std::optional<std::uint32_t> remote_cseq;
    // This side's Contact in its requests, and in its answers (UAS).
    std::string contact, response_contact;
    bool sips = false;
    // UAC: the initial INVITE's transaction (CANCEL) and its handler; the ACK of the 2xx, sent again for a
    // retransmission (RFC 3261 section 13.2.2.4).
    std::string invite_transaction;
    SipResponseHandler initial_handler;
    std::string ack_text;
    std::uint32_t ack_cseq = 0;
    bool provisional_reported = false;
    // UAS: the initial INVITE until its final answer; the application headers of the last provisional answer, which
    // the final one keeps unless it sets them itself.
    std::unique_ptr<resip::SipMessage> invite_request;
    std::vector<SipHeader> provisional_headers;
    bool final_answer = false;
    bool answer_sdp_pending = false;
    // RFC 3262: the INVITE requires reliable provisional responses; the last RSeq sent.
    bool reliable = false;
    std::uint32_t rseq = 0;
    // RFC 3261 section 13.3.1.4: the 2xx sent, retransmitted over UDP until its ACK.
    std::string answer_text;
    std::chrono::milliseconds answer_interval{0};
    std::optional<std::uint32_t> pending_ack_cseq;
    // RFC 3261 section 14 and RFC 3311: the offer this side sent (re-INVITE or UPDATE) and its handler; a received
    // offer waiting for its answer (SipEngine::respond); its method.
    SipResponseHandler offer_handler;
    std::uint32_t offer_cseq = 0;
    std::unique_ptr<resip::SipMessage> incoming_offer;
    bool terminating = false;
    std::vector<BodyPart> bye_parts;
    sip_detail::SdpOrigin sdp_origin;
    // The last SDP this side sent (a session refresh by re-INVITE repeats it).
    std::string local_sdp;
    // RFC 4028: the session interval and whether this side refreshes; whether the peer allows UPDATE.
    unsigned session_expires = 0;
    bool refresher = false;
    bool peer_allows_update = false;
  };

  // RFC 3261 section 10.2: the digest registration of the identity.
  struct Registration {
    std::string call_id, from_tag;
    unsigned cseq = 0, expires = 0;
    SipResponseHandler handler;
    // The connection the last REGISTER's response came on (RFC 3261 section 18; TS 24.229 clause 5.1.1.7).
    std::optional<resip::Tuple> flow;
  };

  // The engine's timers, each due once (SipEngine::poll fires them).
  enum class Timer {
    registration_refresh,
    flow_end,
    aka_refresh,
    aka_pending,
    aka_old,
    aka_expiry,
    // Per INVITE dialog (keyed by its identifier): the 2xx retransmission and the end of the wait for its ACK
    // (RFC 3261 section 13.3.1.4), the session refresh and the session's expiry (RFC 4028 section 10).
    answer_retransmit,
    answer_timeout,
    session_refresh,
    session_expiry,
  };
  using TimerKey = std::pair<Timer, std::string>;

  // TS 33.203 clause 7.1: one set of IPsec security associations, its ports and SPIs, and its transports.
  struct AkaSet {
    std::uint16_t port_uc = 0, port_us = 0, port_pc = 0, port_ps = 0;
    std::uint32_t spi_uc = 0, spi_us = 0, spi_pc = 0, spi_ps = 0;
    std::string alg, ealg;
    // IK_ESP and CK_ESP (TS 33.203 annex I), and the AES-GCM or AES-GMAC salt before the per-SA bits.
    std::vector<std::uint8_t> integrity_key, encryption_key, salt;
    // The Security-Server of the 401 that created the set, mirrored in Security-Verify (TS 24.229 clause 5.1.1.4.2 e).
    std::string security_server;
    std::vector<xfrm::SecurityAssociation> sas;
    // The transports of port_uc: TCP (connections from port_uc to port_ps) and, over UDP, the UDP one; the stack owns
    // them, the keys remove them.
    unsigned tcp_key = 0, udp_key = 0;
    resip_engine::FilteredUdpTransport *udp = nullptr;
    // The SIP level lifetime (TS 24.229 clause 5.1.1.5.1).
    Clock::time_point expires{};
    // TS 33.203 clause 7.4.1a: the transactions started over the set (their identifiers).
    std::set<std::string> transactions;
  };

  // How a REGISTER of the AKA procedure is protected (TS 33.203 clause 7.4.1a).
  enum class AkaRoute { unprotected, current, pending };

  struct Aka {
    std::unique_ptr<aka::SoftIsim> isim;
    std::unique_ptr<xfrm::Xfrm> xfrm;
    // Over UDP: the transport on port_us (sends from port_uc of the set in use).
    resip_engine::ProtectedUdpTransport *udp_us = nullptr;
    // The connection of the last unprotected REGISTER (closed once the procedure ends).
    std::optional<resip::Tuple> unprotected_flow;
    std::unique_ptr<AkaSet> current, pending, old;
    aka::SecMechanism offer;
    std::string security_client;
    AkaRoute register_route = AkaRoute::unprotected;
    std::string call_id, from_tag;
    std::uint32_t cseq = 0;
    std::string realm;
    std::string authorization, pending_authorization, algorithm, pending_algorithm;
    std::vector<std::string> service_routes, associated_uris;
    unsigned expires = 0;
    std::string content_type, body;
    SipResponseHandler handler;
    bool busy = false;
    bool reregistration = false;
    AkaRoute route = AkaRoute::unprotected;
    unsigned resyncs = 0, restarts = 0;
    bool old_release_scheduled = false;
  };

  // lifecycle.cpp
  void start();
  void stop() noexcept;
  void poll(std::chrono::milliseconds timeout);
  // One SipStack::process of at most the given wait, marked as under way (transmit).
  void run_stack(unsigned wait_ms);
  // The stack's work due now, without waiting (lifecycle.cpp).
  void drain();
  // What was just handed to the stack goes to the wire now, in the call that sends it: a request
  // or response leaves before what the application does next (an HTTP GET after the SIP notification that announces
  // it, TS 24.282 clause 10.2.1.2.2). Nothing when called from within the stack's own processing.
  void transmit();
  bool stack_running = false;
  // PLAN.md phase 4: the application's sockets that end the stack's wait (lifecycle.cpp).
  void watch(std::span<const int> sockets);
  void ensure_started() const;
  void report_error(std::string_view error) const noexcept;
  void schedule(Timer timer, std::chrono::milliseconds delay, const std::string &key = {});
  void cancel(Timer timer, const std::string &key = {}) noexcept;
  void fire(Timer timer, const std::string &key);

  // requests.cpp
  void send_request(std::string_view method, std::string_view request_uri, std::string_view content_type,
                    std::string_view body, const std::vector<SipHeader> &headers, SipResponseHandler handler);
  [[nodiscard]] std::string write_request(const OutgoingRequest &request, const Hop &hop) const;
  // Both return the request's transaction identifier.
  std::string dispatch(std::string text, Hop hop, Pending pending);
  std::string send_message(std::unique_ptr<resip::SipMessage> message, Hop hop, Pending pending);
  void receive_response(const resip::SipMessage &message);
  [[nodiscard]] bool retry_with_credentials(const resip::SipMessage &challenge, Pending &pending);
  void dispatch_response(const SipResponse &response, const SipResponseHandler &handler) const;
  [[nodiscard]] Hop default_hop() const;
  void register_digest(unsigned expires, std::string_view content_type, std::string_view body,
                       SipResponseHandler handler);
  void registration_result(const resip::SipMessage &message);
  void end_registration();
  [[nodiscard]] std::string register_contact() const;

  // dialogs.cpp
  [[nodiscard]] std::string create_invite(std::string_view request_uri, const MediaDescription &local_media,
                                          const std::vector<BodyPart> &parts, SipResponseHandler handler,
                                          const std::vector<SipHeader> &headers, const std::string *sdp_text);
  [[nodiscard]] OutgoingRequest dialog_request(Dialog &dialog, std::string_view method) const;
  std::string send_in_dialog(Dialog &dialog, OutgoingRequest request, Pending entry);
  void send_dialog_request(std::string_view dialog_id, std::string_view method, const std::vector<SipHeader> &headers,
                           std::string_view content_type, std::string_view body, SipResponseHandler handler);
  [[nodiscard]] std::string create_subscribe(std::string_view request_uri, std::string_view event, unsigned expires,
                                             const std::vector<SipHeader> &headers, SipResponseHandler handler,
                                             std::string_view content_type, std::string_view body);
  void subscribe_response(const resip::SipMessage &message, Pending &entry);
  void accept_subscription(const resip::SipMessage &message, const SipResponse &response);
  void invite_response(const resip::SipMessage &message, Pending &entry);
  void offer_response(const resip::SipMessage &message, Pending &entry);
  void bye_response(const resip::SipMessage &message, Pending &entry);
  void send_ack(Dialog &dialog, std::uint32_t cseq);
  void receive_in_dialog(const resip::SipMessage &message);
  void receive_cancel(const resip::SipMessage &message);
  void receive_ack(const resip::SipMessage &message);
  [[nodiscard]] bool receive_initial_invite(const resip::SipMessage &message, SipMessage &request,
                                            const SipResponse &response);
  void receive_offer(Dialog &dialog, const resip::SipMessage &message);
  void answer_offer(Dialog &dialog, const resip::SipMessage &offer, SipResponse response);
  void answer_invite(Dialog &dialog, const SipResponse &response);
  void send_dialog_response(Dialog &dialog, const resip::SipMessage &request, const SipResponse &response,
                            const std::vector<SipHeader> &extra);
  void send_offer(std::string_view dialog_id, std::string_view method, std::string sdp,
                  const std::vector<BodyPart> &parts, SipResponseHandler handler, const std::vector<SipHeader> &headers);
  void end_dialog(std::string_view dialog_id, SipResponseHandler handler, const std::vector<SipHeader> &headers,
                  const std::vector<BodyPart> &parts);
  // The identifier is a copy: callers pass the dialog's own, which goes with it.
  void terminate(std::string dialog_id, int cause);
  void report_media(const Dialog &dialog, const std::string &content_type, const std::string &body);
  void session_timer_from(Dialog &dialog, const resip::SipMessage &message, bool as_uas);
  void refresh_session(const std::string &dialog_id);
  void update_target(Dialog &dialog, const resip::SipMessage &message, bool from_response);
  [[nodiscard]] std::vector<SipHeader> session_headers(const Dialog &dialog, bool request) const;
  [[nodiscard]] std::string response_contact(const SipResponse &response) const;
  void notify_call_state(std::string_view id, SipCallState state, int cause) const noexcept;
  [[nodiscard]] SipResponse safe_application_response(const SipMessage &request);

  // incoming.cpp
  void receive_request(const resip::SipMessage &message);
  // Returns the response as sent; to_tag names the To tag of an answer that creates a dialog.
  std::string send_response(const resip::SipMessage &request, const SipResponse &response,
                            const std::string &to_tag = {});
  void respond_deferred(const std::string &transaction_id, const SipResponse &response);

  // messages.cpp
  [[nodiscard]] SipMessage message_from(const resip::SipMessage &message) const;
  [[nodiscard]] SipResponse response_from(const resip::SipMessage &message) const;
  [[nodiscard]] std::string protect_outgoing(const std::string &text, const std::string &address) const;
  [[nodiscard]] std::string contact_uri() const;
  [[nodiscard]] bool sips_target(std::string_view request_uri) const;

  // ims_aka.cpp
  void aka_start();
  void aka_stop() noexcept;
  void aka_register(unsigned expires, std::string_view content_type, std::string_view body,
                    SipResponseHandler handler);
  void aka_send_register(AkaRoute route, bool new_offer, const std::string &authorization);
  void aka_registration_result(const resip::SipMessage &message);
  void aka_forget_registration();
  void aka_registration_ended();
  void aka_challenge(const resip::SipMessage &message);
  void aka_registered(const resip::SipMessage &message);
  void aka_failed(const SipResponse &response);
  void aka_install(AkaSet &set);
  void aka_delete(std::unique_ptr<AkaSet> &set) noexcept;
  void aka_use(AkaSet *set);
  [[nodiscard]] aka::SecMechanism aka_new_offer() const;
  [[nodiscard]] std::string aka_unprotected_authorization() const;
  // A request outside a dialog over the set in use: its Route, its sec-agree header fields and its hop.
  void aka_prepare(OutgoingRequest &request) const;
  [[nodiscard]] std::vector<std::string> aka_routes() const;
  [[nodiscard]] Hop aka_hop(const AkaSet &set) const;
  [[nodiscard]] Hop aka_unprotected_hop() const;
  // RFC 3261 section 18.1.1: over UDP, a request of 1300 bytes or more goes over TCP from port_uc.
  void aka_size_hop(resip::SipMessage &request, Hop &hop) const;
  [[nodiscard]] bool aka_accept(const resip::SipMessage &message, int local_port);
  void aka_track_sent(const std::string &transaction, const Hop &hop);
  void aka_old_check();
  [[nodiscard]] bool transaction_alive(const std::string &transaction) const;
  void transaction_ended(const std::string &transaction);

  SipConfig config;
  SipCallbacks callbacks;
  SipBodyFilter outgoing_filter, incoming_filter;
  bool started = false;
  std::unique_ptr<resip::FdPollGrp> poll_group;
  // PLAN.md phase 4: an epoll set of the application's sockets, itself one item of the stack's poll group (readable
  // while one of them is); the sockets in it, by descriptor with their inode (a closed descriptor leaves the set, and
  // its number may come back for another socket).
  struct WakeItem : resip::FdPollItemIf {
    void processPollEvent(resip::FdPollEventMask) override {}
  } wake_item;
  int wake_epoll = -1;
  resip::FdPollItemHandle wake_handle = nullptr;
  std::map<int, unsigned long> wake_sockets;
  std::unique_ptr<resip::SipStack> stack;
  ResipUser user;
  std::map<std::string, Pending> pending;
  std::map<std::string, std::unique_ptr<resip::SipMessage>> deferred;
  unsigned long next_transaction = 0;
  // The received message being handled, for error reports ("INVITE of <Call-ID>", "486 to INVITE of <Call-ID>").
  std::string handling;
  std::optional<Registration> registration;
  // A registration's connection to close once the transactions on it are over (registration_ended).
  std::optional<resip::Tuple> ending_flow;
  std::map<TimerKey, Clock::time_point> timers;
  std::unique_ptr<Aka> aka;
  std::map<std::string, std::unique_ptr<Dialog>> dialogs;
  // TS 33.203 clause 7.4.1a: when each transaction of a set ended (none: still running), and whether it was over UDP.
  struct TransactionEnd {
    std::optional<Clock::time_point> at;
    bool udp = false;
  };
  std::map<std::string, TransactionEnd> transactions;
  // RFC 2617 section 3.2.2: the nonce count of the digest responses.
  unsigned nonce_count = 0;
};

namespace resip_engine {
//------------------------------------------------------------------------------
// Helper: the text of a reSIProcate value that encodes itself (a URI, a header value, a message).
template <class Value> std::string text_of(const Value &value) {
  resip::Data data;
  {
    resip::DataStream stream(data);
    value.encode(stream);
  }
  return std::string(data.c_str(), data.size());
}

[[nodiscard]] std::vector<SipHeader> headers_of(const resip::SipMessage &message);
[[nodiscard]] std::string resolve_address(const std::string &host);
[[nodiscard]] std::string next_hop_host(const std::string &text);
void check_header(const SipHeader &header);
// Helper: random lower-case hexadecimal text of the given number of bytes (tags, Call-ID, branch, cnonce).
[[nodiscard]] std::string random_hex(std::size_t bytes);
// Helper: the values of the header fields of a name, joined with ", ".
[[nodiscard]] std::string joined_header(const std::vector<SipHeader> &headers, std::string_view name);
} // namespace resip_engine

} // namespace mcx
