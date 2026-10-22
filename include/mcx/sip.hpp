//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The SIP user agent of the MC services: its configuration, the messages it hands to the application, the
// signalling protection hooks of its bodies, and the SipEngine that registers, sends requests, answers and keeps
// dialogs over the SIP core (TS 24.229) or directly to a peer server.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19),
// TS 33.180 V19.4.0 (Rel-19), TS 24.229, RFC 3261, RFC 4028.

#pragma once

#include "mcx/protocol.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the TLS transport of the SIP endpoint, its certificates and their verification.
struct SipTlsConfig {
  bool enabled = true;
  bool verify_server = true;
  std::string ca_file;
  std::string cert_file;
  std::string key_file;
};

//------------------------------------------------------------------------------
// RFC 3261 section 7.3.1: a header field, name and value.
struct SipHeader {
  std::string name;
  std::string value;
};

//------------------------------------------------------------------------------
// Helper: the configuration of a SIP endpoint, its registration, session timer and MC service.
struct SipConfig {
  std::string listen_address;
  std::string advertise_address;
  std::uint16_t listen_port = 5061;
  std::string core_uri;
  std::string identity;
  std::string username;
  std::string password;
  SipTlsConfig tls;
  unsigned session_expires = 1800;
  // The MC service this endpoint declares in its Contact and, unless the
  // caller names another, in the P-Preferred-Service of an INVITE.
  const ServiceProfile *service = &mcptt_service;
  // A server asserts that service instead (P-Asserted-Service): TS 24.379 clause 6.3.3.1.2 step 3 and
  // TS 24.281 clause 6.3.3.1.2 step 3 for the controlling function's INVITE.
  bool asserts_service = false;
  // Further MC services of a UE sharing this registration (TS 24.281 clause 7.2.1AA):
  // their feature tags and ICSIs are added to the Contact.
  std::vector<const ServiceProfile *> other_services;
  // An incoming INVITE whose Session-Expires names no refresher is answered
  // with refresher=uas, so that this endpoint refreshes the session: the
  // MCPTT client's answer (TS 24.379 clause 6.2.3.1.1 step 5). Otherwise the UAC
  // refreshes (RFC 4028 section 9).
  bool uas_refresher = false;
  // The media feature tags of the REGISTER Contact, each with its leading ';'
  // (TS 24.379 clause 7.2.1AA, TS 24.282 clause 7.2.1AA). Empty: the MCPTT ones.
  std::string registration_features;
  // RFC 5626 (SIP Outbound), for a client: its instance identifier (a URN, the MC client ID). When set, the REGISTER
  // Contact carries +sip.instance and reg-id=1 and every Contact URI ;ob, so that the SIP core reaches this endpoint
  // over the connection it registered on, never by connecting to its Contact (a client behind NAT, or on the
  // server's own computer). Empty (servers): plain Contacts.
  std::string outbound_instance;
  // A server's own header fields of its answers to an initial INVITE, other than 100 (Trying): its
  // P-Asserted-Identity and the option tags of its Supported header field (TS 24.379 clauses 6.3.2.1.5 and
  // 6.3.3.2.3, TS 24.281 clauses 6.3.2.1.4 and 6.3.3.2.3, TS 24.282 clause 6.3.7.1.23). Empty for a client.
  std::vector<SipHeader> invite_provisional_headers;
  std::vector<SipHeader> invite_success_headers;
  // A server's own header fields of its initial INVITE requests: its P-Asserted-Identity, unless the request names
  // one, and the "tdialog" and "norefersub" option tags of its Supported header field (TS 24.379 clauses 6.3.2.2.3,
  // 6.3.2.2.5.2 and 6.3.2.2.6.2; TS 24.281 clauses 6.3.2.2.3, 6.3.2.2.5.2 and 6.3.2.2.6.2). Empty for a client.
  std::vector<SipHeader> invite_request_headers;
  // A server's own header fields of its 200 (OK) to a re-INVITE: its P-Asserted-Identity and the "norefersub" and
  // "tdialog" option tags (TS 24.379 clauses 10.1.1.3.1.3, 10.1.1.4.7, 11.1.1.3.1.3; TS 24.281 clauses 9.2.1.3.1.3,
  // 9.2.1.4.7, 10.2.2.3.1.3). Empty for a client.
  std::vector<SipHeader> reinvite_success_headers;
};

//------------------------------------------------------------------------------
// RFC 3261 section 7.3.1: the value of the first header field with the name (case-insensitive), or empty.
[[nodiscard]] std::string_view get_header(const std::vector<SipHeader> &headers, std::string_view name) noexcept;

//------------------------------------------------------------------------------
// RFC 5373 section 2: the answer-mode-value of an Answer-Mode or Priv-Answer-Mode header field value, without its
// parameters ("Auto;require" is "Auto"); empty when the header field is absent. Values other than "Auto" and "Manual"
// are to be ignored ("implementations MUST ignore unknown values").
[[nodiscard]] inline std::string answer_mode_value(std::string_view field) {
  field = field.substr(0, field.find(';'));
  const auto first = field.find_first_not_of(" \t");
  if (first == std::string_view::npos) return {};
  return std::string(field.substr(first, field.find_last_not_of(" \t") - first + 1));
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.1: a received request as the application sees it, with its bodies and SDP offer.
struct SipMessage {
  std::string method;
  std::string request_uri;
  std::string from_uri;
  std::string to_uri;
  std::string call_id;
  std::string dialog_id;
  std::string source_address;
  std::string content_type;
  std::string body;
  std::vector<SipHeader> headers;
  std::vector<BodyPart> parts;
  std::optional<MediaDescription> remote_media;
  // Handle for a deferred response (SipResponse::deferred, SipEngine::respond).
  std::string transaction_id;
  // Set when the incoming body filter refused the body (for example XML content
  // that cannot be decrypted); the parts are then left as received.
  std::string protection_error;
};

//------------------------------------------------------------------------------
// RFC 3261 section 7.2: the application's response to a request, or a received response.
struct SipResponse {
  int status_code = 500;
  std::string reason;
  std::string dialog_id;
  std::string content_type;
  std::string body;
  std::vector<SipHeader> headers;
  std::vector<BodyPart> parts;
  std::optional<MediaDescription> local_media;
  // An answer whose media is not MCPTT audio, such as the MSRP stream of the
  // MCData media plane: the SDP is supplied ready-made.
  std::optional<std::string> local_sdp;
  // Optional public session URI, without angle brackets or header parameters.
  std::string contact_uri;
  bool focus = false;
  // With contact_uri: the media feature tags of the Contact, each with its leading ';', in place of the configured
  // services' tags, such as an MCData subservice's (TS 24.282 clause 6.3.7.1.23 step 6).
  std::string contact_tags;
  // For an incoming INVITE from a peer server reached without the SIP core: the
  // Route header value used for every request in the new dialog.
  std::string peer_route;
  // A non-INVITE request (including an initial SUBSCRIBE) or re-INVITE answered
  // later with SipEngine::respond, for example after relaying it to another
  // server. A re-INVITE gets 100 at once.
  // On a provisional answer to an initial INVITE, local_media may be absent: the
  // SDP answer is then given with the final SipEngine::answer.
  bool deferred = false;
  // As SipMessage::protection_error, for a received response.
  std::string protection_error;
  // Body parts of a 2xx INVITE answer that depend on the dialog, built once its
  // local (To) and remote (From) tags exist; appended to parts.
  std::function<std::vector<BodyPart>(std::string_view local_tag, std::string_view remote_tag)> dialog_parts;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6, TS 24.282 clause 6.5, TS 33.180 clause 9.3: application signalling protection:
// the bodies of every message are passed through filters on the way out, once the
// destination is resolved, and on the way in, before the application sees them.
struct SipTransmission {
  bool response = false;
  std::string address;     // the resolved destination, or the source of a received message
  std::string method;      // the request's, or the CSeq method of a response
  std::string request_uri; // of a request
  std::string from_uri, to_uri;
  std::vector<SipHeader> headers;
};

//------------------------------------------------------------------------------
// Helper: a body filter of SipTransmission, returning the bodies to send or to deliver.
using SipBodyFilter = std::function<std::vector<BodyPart>(const SipTransmission &, std::vector<BodyPart>)>;

//------------------------------------------------------------------------------
// RFC 3261 section 12: the state of an INVITE dialog, early, confirmed or ended.
enum class SipCallState {
  early,
  confirmed,
  disconnected,
};

//------------------------------------------------------------------------------
// Helper: the handler of the final response to a request.
using SipResponseHandler = std::function<void(const SipResponse &)>;

//------------------------------------------------------------------------------
// Helper: the application's handlers of incoming requests, dialog state, SDP, responses, errors and ACKs.
struct SipCallbacks {
  std::function<SipResponse(const SipMessage &)> on_request;
  std::function<void(std::string_view, SipCallState, int)> on_call_state;
  std::function<void(std::string_view, const MediaDescription &)> on_media;
  std::function<void(const SipResponse &)> on_response;
  std::function<void(std::string_view)> on_error;
  std::function<void(std::string_view)> on_ack;
};

//------------------------------------------------------------------------------
// RFC 3261, RFC 4028, TS 24.229: the SIP user agent of an MC client or server, client and server transactions,
// dialogs and session timers.
class SipEngine {
public:
  explicit SipEngine(SipConfig config, SipCallbacks callbacks = {});
  ~SipEngine() noexcept;

  SipEngine(const SipEngine &) = delete;
  SipEngine &operator=(const SipEngine &) = delete;
  SipEngine(SipEngine &&) = delete;
  SipEngine &operator=(SipEngine &&) = delete;

  void start();
  void stop() noexcept;
  [[nodiscard]] bool running() const noexcept;
  void poll(std::chrono::milliseconds timeout);
  // Retained non-INVITE dialogs, for operational resource diagnostics.
  [[nodiscard]] std::size_t subscription_count() const noexcept;

  // An incoming filter may throw; the message then carries protection_error.
  void set_body_filters(SipBodyFilter outgoing, SipBodyFilter incoming);
  void register_account(unsigned expires, SipResponseHandler handler = {});
  // A re-REGISTER with a body. Later refreshes carry none. The Contact already has the
  // service's media feature tag and g.3gpp.icsi-ref.
  void register_account(unsigned expires, std::string_view content_type, std::string_view body,
                        SipResponseHandler handler);
  // RFC 3261 section 10.2.2: removes this engine's registration (its Contact with Expires 0) and stops refreshing it;
  // register_account registers again.
  void unregister_account(SipResponseHandler handler = {});
  // Requests, INVITEs and SUBSCRIBEs go through the SIP core unless their
  // headers include an explicit Route, which then selects the next hop; for an
  // INVITE or SUBSCRIBE it is also the dialog's fixed route set.
  void request(std::string_view method, std::string_view request_uri, std::string_view content_type = {},
               std::string_view body = {}, const std::vector<SipHeader> &headers = {}, SipResponseHandler handler = {});
  void publish(std::string_view request_uri, std::string_view content_type, std::string_view body,
               const std::vector<SipHeader> &headers = {}, SipResponseHandler handler = {});
  void request_in_dialog(std::string_view dialog_id, std::string_view method, std::string_view type,
                         std::string_view body, const std::vector<SipHeader> &headers = {},
                         SipResponseHandler handler = {});

  [[nodiscard]] std::string subscribe(std::string_view request_uri, std::string_view event, unsigned expires,
                                      const std::vector<SipHeader> &headers = {}, SipResponseHandler handler = {},
                                      std::string_view content_type = {}, std::string_view body = {});
  void notify(std::string_view dialog_id, std::string_view event, std::string_view subscription_state,
              std::string_view content_type, std::string_view body, const std::vector<SipHeader> &headers = {},
              SipResponseHandler handler = {});

  [[nodiscard]] std::string invite(std::string_view request_uri, const MediaDescription &local_media,
                                   const std::vector<BodyPart> &application_parts, SipResponseHandler handler = {},
                                   const std::vector<SipHeader> &headers = {});
  // An INVITE whose offer is supplied as SDP text (the MCData media plane).
  [[nodiscard]] std::string invite_sdp(std::string_view request_uri, std::string_view sdp,
                                       const std::vector<BodyPart> &application_parts, SipResponseHandler handler = {},
                                       const std::vector<SipHeader> &headers = {});
  // Complete an incoming INVITE initially answered with a provisional response.
  // A stale answer after cancellation is harmless.
  void answer(std::string_view dialog_id, const SipResponse &response);
  void reinvite(std::string_view dialog_id, const MediaDescription &media, const std::vector<BodyPart> &parts,
                SipResponseHandler handler = {}, const std::vector<SipHeader> &headers = {});
  // A re-INVITE whose offer is supplied as SDP text (the MCData media plane).
  void reinvite_sdp(std::string_view dialog_id, std::string_view sdp, const std::vector<BodyPart> &parts,
                    SipResponseHandler handler = {}, const std::vector<SipHeader> &headers = {});
  // Send the final response to a request whose handler returned deferred.
  // A response after the dialog has ended is dropped.
  void respond(std::string_view transaction_id, const SipResponse &response);
  // This endpoint's own contact URI, without angle brackets or feature tags, as
  // the transport in use describes it. A Contact override must build on it, since
  // it becomes the remote target of the dialog for in-dialog requests.
  [[nodiscard]] std::string contact_target() const;

  // End an established call or cancel a pending call. Repeated ends are harmless.
  // A single application part becomes the BYE body; a CANCEL carries none.
  void bye(std::string_view dialog_id, SipResponseHandler handler = {}, const std::vector<SipHeader> &headers = {},
           const std::vector<BodyPart> &parts = {});

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace mcx
