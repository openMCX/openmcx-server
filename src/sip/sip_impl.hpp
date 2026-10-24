//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The private implementation of mcx::SipEngine (include/mcx/sip.hpp): the SIP user agent and
// application server core of OpenMCX over pjsip (RFC 3261, as TS 24.229 profiles it for the MC
// services), with its registrations (RFC 3261 section 10), subscriptions (RFC 6665), session
// timers (RFC 4028) and the MC services' body protection hooks (TS 33.180 clause 9).
//
// Private to src/sip/: declared here, its member functions defined in the files of this directory.
//
// Specifications: TS 24.229, TS 33.180 V19.4.0 (Rel-19), RFC 3261, RFC 3262, RFC 4028, RFC 4566, RFC 5621,
// RFC 6665.

#pragma once

#include "mcx/ims_aka.hpp"
#include "mcx/sip.hpp"
#include "mcx/xfrm.hpp"

#include <openssl/rand.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <pjmedia/sdp.h>
#include <pjsip-ua/sip_100rel.h>
#include <pjsip-ua/sip_timer.h>
#include <pjsip.h>
#include <pjsip/sip_multipart.h>
#include <pjsip/sip_transport_tcp.h>
#include <pjsip/sip_transport_tls.h>
#include <pjsip_ua.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace mcx {
// The SIP engine's own helpers (helpers.cpp), shared by the files of src/sip/.
namespace sip_detail {
// Helper: the largest SIP message body printed or accepted, in bytes.
inline constexpr std::size_t kMaximumSipBodyBytes = 1024U * 1024U;

//------------------------------------------------------------------------------
// RFC 3261 section 7.3.1: compares header field names case-insensitively (ASCII only).
[[nodiscard]] bool ascii_equal(std::string_view left, std::string_view right) noexcept;

//------------------------------------------------------------------------------
// Helper: returns an ASCII lower-case copy of a value.
[[nodiscard]] std::string ascii_lower(std::string_view value);

//------------------------------------------------------------------------------
// Helper: true when both a username and a password are configured for digest authentication.
[[nodiscard]] bool has_credentials(const SipConfig &config) noexcept;

//------------------------------------------------------------------------------
// RFC 3261 section 19.1.1: returns the user part of a SIP URI identity; throws when user or host is missing.
[[nodiscard]] std::string identity_user(std::string_view identity);

//------------------------------------------------------------------------------
// RFC 3261 section 19.1.1: the home domain of an identity: the host of its SIP URI, without port or parameters.
[[nodiscard]] std::string identity_domain(std::string_view identity);

//------------------------------------------------------------------------------
// Helper: a non-owning pj_str_t view of a string (pjsip does not modify it).
[[nodiscard]] pj_str_t pj_view(std::string_view value);

//------------------------------------------------------------------------------
// Helper: copies a pj_str_t into a std::string (empty when null).
[[nodiscard]] std::string string_from(const pj_str_t &value);

//------------------------------------------------------------------------------
// Helper: the pjlib text of a status code.
[[nodiscard]] std::string status_error(pj_status_t status);

//------------------------------------------------------------------------------
// Helper: throws std::runtime_error naming the operation when a pjlib status is not PJ_SUCCESS.
void require_success(pj_status_t status, std::string_view operation);

//------------------------------------------------------------------------------
// RFC 3261 section 19.1: prints a URI in Request-URI form (empty when null).
[[nodiscard]] std::string print_uri(const pjsip_uri *uri);

//------------------------------------------------------------------------------
// RFC 3261 section 7.4: prints a message body, growing the buffer up to kMaximumSipBodyBytes.
[[nodiscard]] std::string print_body(pjsip_msg_body *body);

//------------------------------------------------------------------------------
// RFC 3261 section 20.15: prints a Content-Type media type with its parameters.
[[nodiscard]] std::string print_media_type(const pjsip_media_type &type);

//------------------------------------------------------------------------------
// RFC 3261 section 7.3: collects every header field of a message as name and value.
[[nodiscard]] std::vector<SipHeader> collect_headers(pjsip_msg *message);

//------------------------------------------------------------------------------
// RFC 3261 section 20.20: returns the URI of a From or To style header without display name or tag.
[[nodiscard]] std::string bare_header_uri(pjsip_msg *message, pjsip_hdr_e type);

//------------------------------------------------------------------------------
// RFC 3261 section 20.8: returns the Call-ID of a message.
[[nodiscard]] std::string call_id_from(pjsip_msg *message);

//------------------------------------------------------------------------------
// RFC 3261 section 20.15: returns the Content-Type of a message body (empty without body).
[[nodiscard]] std::string content_type_from(pjsip_msg *message);

//------------------------------------------------------------------------------
// RFC 4028 section 4 and RFC 3261 section 26.2: checks the SIP configuration (session expiry, TLS and identity).
void validate_config(const SipConfig &config);

//------------------------------------------------------------------------------
// RFC 3261 section 20.15: builds a message body of the given Content-Type in the pool.
[[nodiscard]] pjsip_msg_body *make_text_body(pj_pool_t *pool, std::string_view content_type, std::string_view body);

//------------------------------------------------------------------------------
// RFC 3261 section 7.3: creates a header field in the pool; rejects CR/LF injection.
[[nodiscard]] pjsip_hdr *create_header(pj_pool_t *pool, const SipHeader &header);

//------------------------------------------------------------------------------
// Helper: appends one header field to an outgoing message.
void add_header(pjsip_tx_data *data, const SipHeader &header);

//------------------------------------------------------------------------------
// RFC 3261 section 20.10: appends header fields to an outgoing message; a single Contact override replaces the
// generated Contact.
void add_headers(pjsip_tx_data *data, const std::vector<SipHeader> &headers);

//------------------------------------------------------------------------------
// RFC 3261 sections 7.3.1 and 20.37: adds a server's own header fields to its answer to an initial INVITE, or to its
// initial INVITE: option tags of a Supported header field join the message's Supported header field; any other header
// field is added unless the message already has one of that name.
void add_answer_headers(pjsip_tx_data *data, const std::vector<SipHeader> &headers);

//------------------------------------------------------------------------------
// RFC 4566: parses SDP text into a pjmedia session allocated in the pool.
[[nodiscard]] pjmedia_sdp_session *parse_sdp_text(pj_pool_t *pool, const std::string &text);

//------------------------------------------------------------------------------
// RFC 4566: parses the local SDP built from the media description (session version 1).
[[nodiscard]] pjmedia_sdp_session *parse_local_sdp(pj_pool_t *pool, const MediaDescription &media);

//------------------------------------------------------------------------------
// RFC 5621 and RFC 2046 section 5.1.3: builds a multipart/mixed body with the SDP first, then the given parts; the SDP
// alone is a plain application/sdp body (RFC 3261 section 7.4).
[[nodiscard]] pjsip_msg_body *make_body_with_sdp(pj_pool_t *pool, const std::string &sdp,
                                                 const std::vector<BodyPart> &parts);

//------------------------------------------------------------------------------
// RFC 5621: builds an INVITE body from the local SDP and the given parts (see make_body_with_sdp).
[[nodiscard]] pjsip_msg_body *make_invite_body(pj_pool_t *pool, const MediaDescription &media,
                                               const std::vector<BodyPart> &parts);

//------------------------------------------------------------------------------
// RFC 2046 section 5.1.3, RFC 5621 and RFC 2392: builds a multipart/mixed body of the parts in the pool, each with
// its Content-ID when it has one.
[[nodiscard]] pjsip_msg_body *make_multipart_body(pj_pool_t *pool, const std::vector<BodyPart> &parts);

//------------------------------------------------------------------------------
// RFC 3261 section 7.4 and RFC 5621: the body of an answer without SDP: one part as a plain body of its own type,
// several as multipart/mixed with the boundary.
[[nodiscard]] pjsip_msg_body *make_parts_body(pj_pool_t *pool, const std::vector<BodyPart> &parts,
                                              std::string_view boundary);

//------------------------------------------------------------------------------
// Helper: drops the reference an outgoing message held by its creator (pjsip_tx_data_dec_ref).
struct TxDataRelease {
  void operator()(pjsip_tx_data *data) const noexcept { (void)pjsip_tx_data_dec_ref(data); }
};

// Helper: an outgoing message owned until it is handed to a pjsip send call, which takes the reference whether it
// succeeds or not.
using TxData = std::unique_ptr<pjsip_tx_data, TxDataRelease>;
} // namespace sip_detail

using namespace sip_detail;

//------------------------------------------------------------------------------
// RFC 3261, RFC 6665 and RFC 4028 over pjsip: the state of the SIP engine: its endpoint, registration, client
// request tokens, INVITE and SUBSCRIBE dialogs, deferred responses and body protection filters (TS 33.180
// clause 9.3).
struct SipEngine::Impl {
  struct RequestToken {
    Impl *owner = nullptr;
    SipResponseHandler handler;
    pj_pool_t *pool = nullptr;
    pjsip_auth_clt_sess auth{};
    bool auth_initialized = false;
    bool retried = false;
    bool initial_subscription = false;
    bool terminating_subscription = false;
    pjsip_dialog *dialog = nullptr;
    // pjsip completes a request inside the send call when it cannot send it
    // (a name that does not resolve, a refused connection): the completion
    // handler then runs, reports the outcome and leaves the token to the sender.
    bool sending = false;
    bool completed = false;
  };

  struct Dialog {
    std::string id;
    pjsip_dialog *dialog = nullptr;
    pjsip_inv_session *invite = nullptr;
    SipResponseHandler initial_handler;
    SipResponseHandler reinvite_handler;
    int reinvite_cseq = -1;
    int pending_ack_cseq = -1;
    bool terminating = false;
    bool final_answer = false;
    // An incoming INVITE accepted without an SDP answer (deferred provisional).
    bool answer_sdp_pending = false;
    std::string response_contact;
    // RFC 3261 section 12.1.1: the dialog was started with a SIPS URI, so this side's Contact is a SIPS URI too.
    bool sips_contact = false;
    // Body for the BYE; kept when a CANCEL was sent, in case a 2xx crosses it.
    std::vector<BodyPart> bye_parts;
  };

  struct PendingResponse {
    pjsip_dialog *dialog = nullptr;
    pjsip_transaction *transaction = nullptr;
    pjsip_tx_data *data = nullptr;
  };

  // A request answered later through SipEngine::respond. A non-INVITE keeps its
  // server transaction and a prepared response; a re-INVITE its dialog and CSeq.
  struct DeferredResponse {
    std::string dialog_id;
    pjsip_dialog *dialog = nullptr;
    pjsip_transaction *transaction = nullptr;
    pjsip_tx_data *data = nullptr;
    bool reinvite = false;
    int cseq = -1;
    // An initial SUBSCRIBE: a copy of the request, from which the dialog is
    // created (or the rejection sent) once answered. Over TCP or TLS the
    // request is not retransmitted meanwhile.
    pjsip_rx_data *subscribe = nullptr;
    SipMessage request;
  };

  // TS 33.203 clause 7 and TS 24.229 clauses 5.1.1.2.2, 5.1.1.4.2, 5.1.1.5 and 5.1.1.6.2: the IMS AKA registration of
  // a UE (SipConfig::aka), its own REGISTER transactions (not pjsip_regc, which would answer the 401 itself before the
  // security associations exist) and its sets of security associations (ims_aka.cpp).
  struct AkaSet {
    std::uint16_t port_uc = 0, port_us = 0, port_pc = 0, port_ps = 0;
    std::uint32_t spi_uc = 0, spi_us = 0, spi_pc = 0, spi_ps = 0;
    std::string alg, ealg;
    // IK_ESP and CK_ESP (TS 33.203 annex I).
    std::vector<std::uint8_t> integrity_key, encryption_key;
    // The Security-Server of the 401 that created the set, mirrored in Security-Verify (TS 24.229 clause 5.1.1.4.2 e).
    std::string security_server;
    std::vector<xfrm::SecurityAssociation> sas;
    // The TCP connection from port_uc to port_ps (TS 33.203 clause 7.1, TCP case), held while the set exists.
    pjsip_transport *connection = nullptr;
    // Over UDP: the UDP transport bound to port_uc that every request and response of the set leaves from (TS 33.203
    // clause 7.1, UDP case), published with port_us for Via.
    pjsip_transport *udp = nullptr;
    // The SIP level lifetime (TS 24.229 clause 5.1.1.5.1), monotonic milliseconds.
    std::uint64_t expires_ms = 0;
  };

  // How a REGISTER of the AKA procedure is protected (TS 33.203 clause 7.4.1a).
  enum class AkaRoute { unprotected, current, pending };

  struct Aka {
    std::unique_ptr<aka::SoftIsim> isim;
    std::unique_ptr<xfrm::Xfrm> xfrm;
    pjsip_tpfactory *unprotected_factory = nullptr;
    pjsip_transport *unprotected_connection = nullptr;
    // Over UDP: the transports on port_us (receiving; its sends go out from port_uc of the set in use) and on the
    // unprotected port, and pjsip's send function of the first.
    pjsip_transport *udp_us = nullptr, *udp_unprotected = nullptr;
    pj_status_t (*udp_us_send)(pjsip_transport *, pjsip_tx_data *, const pj_sockaddr_t *, int, void *,
                               pjsip_transport_callback) = nullptr;
    // TS 33.203 clause 7.4.1a: the set in use, the temporary set of the authentication in progress, and the old set
    // kept until the new one has carried a message from the P-CSCF and its transactions are over.
    std::unique_ptr<AkaSet> current, pending, old;
    // The Security-Client of the REGISTER in progress (TS 24.229 clause 5.1.1.5.1 step 4: repeated unchanged in the
    // protected REGISTER) and the proposal it carries.
    aka::SecMechanism offer;
    std::string security_client;
    std::string call_id, from_tag;
    std::uint32_t cseq = 0;
    std::string realm;
    // TS 24.229 clause 5.1.1.4.2 a: the Authorization of the last successful authentication, repeated in later
    // REGISTERs; and the one of the protected REGISTER in progress.
    std::string authorization, pending_authorization, algorithm, pending_algorithm;
    std::vector<std::string> service_routes, associated_uris;
    // The registration asked for: its expiry, body and handler.
    unsigned expires = 0;
    std::string content_type, body;
    SipResponseHandler handler;
    bool busy = false;
    AkaRoute route = AkaRoute::unprotected;
    unsigned resyncs = 0, restarts = 0;
    bool old_release_scheduled = false;
    pj_timer_entry refresh_timer{}, pending_timer{}, old_timer{}, expiry_timer{};
  };

  std::unique_ptr<Aka> aka;

  void aka_start(const pj_sockaddr &local, const pjsip_host_port &advertised);
  void aka_stop() noexcept;
  void aka_register(unsigned expires, std::string_view content_type, std::string_view body, SipResponseHandler handler);
  void aka_send_register(AkaRoute route, bool new_offer, const std::string &authorization);
  void aka_registration_result(pjsip_rx_data *data, int status, std::string_view reason);
  void aka_challenge(pjsip_rx_data *data);
  void aka_registered(pjsip_rx_data *data);
  void aka_failed(const SipResponse &response);
  void aka_finish(const SipResponse &response);
  void aka_install(AkaSet &set);
  void aka_delete(std::unique_ptr<AkaSet> &set) noexcept;
  pjsip_transport *aka_connection(AkaSet &set);
  pjsip_transport *aka_unprotected_connection();
  pjsip_transport *aka_request_transport(AkaSet &set);
  static pj_status_t aka_udp_send(pjsip_transport *transport, pjsip_tx_data *data, const pj_sockaddr_t *remote,
                                  int remote_length, void *token, pjsip_transport_callback callback);
  static pjsip_transport *aka_udp_to_tcp(pjsip_tx_data *data);
  void aka_use_current();
  void aka_apply(pjsip_tx_data *data);
  void aka_apply(pjsip_dialog *dialog);
  [[nodiscard]] std::vector<std::string> aka_routes() const;
  [[nodiscard]] bool aka_accept(pjsip_rx_data *data);
  [[nodiscard]] aka::SecMechanism aka_new_offer() const;
  void aka_schedule(pj_timer_entry &entry, std::uint64_t delay_ms, int id);
  static void aka_register_complete(void *token, pjsip_event *event);
  static void aka_timer(pj_timer_heap_t *heap, pj_timer_entry *entry);
  static pj_bool_t aka_filter(pjsip_rx_data *data);
  pjsip_module aka_module{};

  std::vector<std::string> pending_subscription_cleanup;
  // Sessions ended by our BYE keep our reference until that BYE's transaction
  // ends: a BYE from the peer crossing ours disconnects the session, and the
  // response to ours must not then reach a destroyed session.
  std::set<pjsip_inv_session *> bye_references;
  std::vector<pjsip_inv_session *> released_bye_references;

  // In-dialog requests of an INVITE dialog whose 401/407 challenge the INVITE
  // session layer answers itself: it sends the request again with the next CSeq,
  // and that transaction takes over the application's handler.
  struct AuthRetry {
    std::string method;
    std::uint32_t cseq = 0;
    RequestToken *token = nullptr;
  };

  std::map<pjsip_dialog *, std::vector<AuthRetry>> auth_retries;

  RequestToken *adopt_auth_retry(pjsip_transaction *transaction);

  std::vector<std::string> pending_acks;
  pjsip_module ack_module{};

  static pj_bool_t observe_ack(pjsip_rx_data *data);

  // The SIP message log (log level debug): one event per message received or sent, from a module next to
  // the transport layer; registered only at those levels, so it costs nothing otherwise.
  pjsip_module trace_module{};

  static pj_bool_t trace_received(pjsip_rx_data *data);

  static pj_status_t trace_sent(pjsip_tx_data *data);

  void release_bye_references();

  void release_pending_subscriptions();

  SipConfig config;
  SipCallbacks callbacks;
  bool started = false;
  bool pj_initialized = false;
  bool cache_initialized = false;
  pj_caching_pool cache{};
  pjsip_endpoint *endpoint = nullptr;
  pjsip_tpfactory *tls_factory = nullptr;
  pjsip_regc *registration = nullptr;
  SipResponseHandler registration_handler;
  pjsip_module module{};
  // Rewrites outgoing bodies just before the transport layer prints them.
  pjsip_module protection_module{};
  SipBodyFilter outgoing_filter, incoming_filter;
  std::unordered_map<std::string, std::unique_ptr<Dialog>> dialogs;
  std::vector<PendingResponse> pending_responses;
  std::unordered_map<std::string, DeferredResponse> deferred_responses;
  std::uint64_t next_transaction = 0;

  inline static std::atomic<Impl *> active{nullptr};

  Impl(SipConfig value, SipCallbacks handlers);

  ~Impl() { stop(); }

  [[nodiscard]] std::string contact_target() const;

  [[nodiscard]] std::string service_tags() const;

  [[nodiscard]] std::string contact_uri() const { return "<" + contact_target() + ">" + service_tags(); }

  [[nodiscard]] std::string response_contact(const SipResponse &response) const;

  [[nodiscard]] static std::string as_sips(std::string contact);

  [[nodiscard]] bool sips_target(std::string_view request_uri) const;

  [[nodiscard]] static bool sips_request(const pjsip_rx_data *data);

  static bool same_parts(const std::vector<BodyPart> &left, const std::vector<BodyPart> &right);

  static std::string cseq_method(pjsip_msg *message);

  static pj_status_t protect_outgoing(pjsip_tx_data *data);

  // TS 33.180 clause 9.3: passes the bodies of a received message through the incoming filter, before the
  // application sees them; a filter failure is reported in protection_error.
  template <class Message> void protect_incoming(pjsip_msg *message, const std::string &source, Message &result) const {
    if (!incoming_filter || result.parts.empty()) return;
    SipTransmission transmission;
    transmission.response = message->type == PJSIP_RESPONSE_MSG;
    transmission.address = source;
    transmission.method = transmission.response ? cseq_method(message) : string_from(message->line.req.method.name);
    if (!transmission.response) transmission.request_uri = print_uri(message->line.req.uri);
    transmission.from_uri = bare_header_uri(message, PJSIP_H_FROM);
    transmission.to_uri = bare_header_uri(message, PJSIP_H_TO);
    transmission.headers = result.headers;
    try {
      auto filtered = incoming_filter(transmission, result.parts);
      if (same_parts(result.parts, filtered)) return;
      result.parts = std::move(filtered);
      // The raw body is kept consistent with the parts, which some handlers parse again.
      // A body that loses its signatures and keeps one part is a single body again.
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

  [[nodiscard]] SipResponse response_from(pjsip_rx_data *data) const;

  [[nodiscard]] SipMessage message_from(pjsip_rx_data *data) const;

  void report_error(std::string_view error) noexcept;

  void notify_call_state(std::string_view id, SipCallState state, int cause) noexcept;

  void dispatch_response(const SipResponse &response, SipResponseHandler &handler);

  void initialize_auth(RequestToken &token);

  void finish_token(RequestToken *token) noexcept;

  // Sends with the token marked as sending. Returns true when the request already completed inside the call: its
  // handler has run and the caller releases the token.
  template <typename Send> static bool send_with_token(RequestToken *token, pj_status_t &status, Send &&send) {
    token->sending = true;
    status = send();
    token->sending = false;
    return token->completed;
  }

  static void destroy_token(RequestToken *token) noexcept;

  // Helper: releases a request token (destroy_token) when its owner goes.
  struct TokenRelease {
    void operator()(RequestToken *token) const noexcept { destroy_token(token); }
  };

  // A request token owned by its sender until pjsip has the request; the transaction's completion then releases it
  // (send_complete, dialog_transaction_state).
  using OwnedToken = std::unique_ptr<RequestToken, TokenRelease>;

  [[nodiscard]] OwnedToken make_token(SipResponseHandler handler);

  // Sends a request under its token: on success pjsip owns the token, on failure it is released and the error
  // thrown; a request that completed inside the send call has reported to its handler.
  template <typename Send> void send_owned(OwnedToken token, Send &&send, std::string_view operation) {
    pj_status_t status = PJ_SUCCESS;
    if (send_with_token(token.get(), status, std::forward<Send>(send))) return;
    require_success(status, operation);
    (void)token.release(); // owned by the transaction now
  }

  // Helper: runs a pjsip callback body; an exception must not cross the C frames of pjsip, so any is reported.
  template <typename Body> static void guarded(Impl *owner, Body &&body) noexcept {
    try {
      body();
    } catch (const std::exception &error) {
      if (owner != nullptr) owner->report_error(error.what());
    } catch (...) {
      if (owner != nullptr) owner->report_error("unknown SIP callback error");
    }
  }

  // Helper: ends an outgoing dialog whose creation failed part way: its entry, its session (or the dialog itself
  // while it has none).
  void abandon_dialog(pjsip_dialog *dialog, const std::string &id, bool session) noexcept;

  // Helper: ends an INVITE session whose creation or answer failed part way, without reporting it; an incoming
  // INVITE (request) is first answered 500 where that is still possible.
  void abandon_invite(pjsip_inv_session *invite, const std::string &id, pjsip_rx_data *request = nullptr) noexcept;

  // RFC 3261 section 14.1: sends a re-INVITE in a confirmed dialog with the offer and body the builders make in the
  // session's and the request's pools.
  void send_reinvite(std::string_view dialog_id, const std::function<pjmedia_sdp_session *(pj_pool_t *)> &offer,
                     const std::function<pjsip_msg_body *(pj_pool_t *)> &body, SipResponseHandler handler,
                     const std::vector<SipHeader> &headers);

  static void send_complete(void *opaque, pjsip_event *event);

  static void dialog_transaction_state(pjsip_transaction *transaction, pjsip_event *event);

  static void registration_complete(pjsip_regc_cbparam *parameter);

  [[nodiscard]] static SipResponse safe_application_response(Impl &owner, const SipMessage &request);

  [[nodiscard]] std::string unsupported_required_extensions(pjsip_msg *message) const;

  [[nodiscard]] bool verify_initial_invite(pjsip_rx_data *data);

  static pj_bool_t receive_request(pjsip_rx_data *data);

  static void invite_state_changed(pjsip_inv_session *invite, pjsip_event *event);

  void follow_invite_state(pjsip_inv_session *invite, pjsip_event *event);

  static pj_status_t receive_reinvite(pjsip_inv_session *invite, const pjmedia_sdp_session *, pjsip_rx_data *data);

  static void invite_transaction_changed(pjsip_inv_session *invite, pjsip_transaction *tsx, pjsip_event *event);

  static void invite_media_updated(pjsip_inv_session *invite, pj_status_t status);

  void send_response(pjsip_rx_data *data, const SipResponse &response, pjsip_dialog *dialog);

  void answer_reinvite(pjsip_inv_session *invite, pjsip_rx_data *data, const std::string &dialog_id, int cseq,
                       SipResponse response);

  void defer_response(pjsip_rx_data *data, const SipMessage &request);

  void respond_deferred(const std::string &id, const SipResponse &response);

  void send_pending_responses();

  void accept_subscription(pjsip_rx_data *data, const SipMessage &request, const SipResponse &response);

  static void take_session_refresh(pjsip_rx_data *data);

  [[nodiscard]] std::optional<int> accept_invite(pjsip_rx_data *data, const SipMessage &request,
                                                 const SipResponse &response);

  static std::vector<BodyPart> answer_parts(const SipResponse &response, const pjsip_dialog *dialog);

  void start();

  void stop() noexcept;

  void ensure_started() const;

  static void pin_dialog_route(pjsip_dialog *dialog, std::string_view route, bool freeze = true);

  static std::vector<SipHeader> without_route(const std::vector<SipHeader> &headers);

  void add_core_route(pjsip_tx_data *data, const std::vector<SipHeader> &headers = {}) const;

  [[nodiscard]] std::string core_route() const;

  void send_request(std::string_view method_text, std::string_view request_uri, std::string_view content_type,
                    std::string_view body, const std::vector<SipHeader> &headers, SipResponseHandler handler);

  [[nodiscard]] std::string create_subscribe(std::string_view request_uri, std::string_view event, unsigned expires,
                                             const std::vector<SipHeader> &headers, SipResponseHandler handler,
                                             std::string_view content_type, std::string_view body);

  void send_dialog_request(std::string_view dialog_id, const pjsip_method &method,
                           const std::vector<SipHeader> &headers, std::string_view content_type, std::string_view body,
                           SipResponseHandler handler);

  [[nodiscard]] std::string create_invite(std::string_view request_uri, const MediaDescription &local_media,
                                          const std::vector<BodyPart> &application_parts, SipResponseHandler handler,
                                          const std::vector<SipHeader> &headers, const std::string *sdp_text = nullptr);
};
} // namespace mcx
