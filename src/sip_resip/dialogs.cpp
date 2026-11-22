//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SipEngine::Impl on reSIProcate: INVITE dialogs on the transaction layer (prototype/resiprocate/PLAN.md phase 3c,
// decision 1: the engine's own dialog layer, not reSIProcate's DUM). The behaviour is the pjproject engine's INVITE
// session: the UAC's INVITE with a required session timer, its provisional and final responses, the ACK of a 2xx (and
// of its retransmissions), CANCEL of an early call and BYE after a 2xx that crossed it; the UAS's dialog, deferred
// and immediate answers, the 2xx retransmitted over UDP until its ACK, 487 to a cancelled INVITE; re-INVITE and UPDATE
// offers both ways with one offer at a time (491 to a crossing one), BYE both ways, in-dialog INFO and MESSAGE, PRACK
// for reliable provisional responses, and session timers (RFC 4028). Requests are written as text, as the engine's
// requests outside dialogs are, and go through the same outgoing protection and IMS AKA hop.
//
// Specifications: RFC 3261 sections 9, 12, 13, 14 and 15, RFC 3262, RFC 3264, RFC 3311, RFC 4028, RFC 5621,
// TS 24.229 V19.7.0 (Rel-19) clauses 5.1.2A.1 and 5.1.3.1, TS 24.379 V19.7.0 (Rel-19) clauses 6.3 and 8.3.

#include "resip_impl.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <charconv>
#include <stdexcept>

namespace mcx {
using sip_detail::next_sdp_origin;
using sip_detail::record_sdp_text;
namespace {
using sip_detail::ascii_equal;


// RFC 4028 section 4: this endpoint's Min-SE (the pjproject session timer's default).
constexpr unsigned kMinimumSessionExpires = 90;
// RFC 3261 section 17.1.1.1: T1, the first 2xx retransmission interval; 64*T1 is the wait for its ACK.
constexpr std::chrono::milliseconds kT1{500};
// RFC 3261 section 13.3.1.4 and RFC 3262 section 3: the methods this endpoint allows in an INVITE dialog, as the
// pjproject engine's INVITE session lists them in requests and in answers.
constexpr const char *kAllowRequest = "INVITE, ACK, BYE, CANCEL, UPDATE";
constexpr const char *kAllowAnswer = "INVITE, ACK, BYE, CANCEL, UPDATE, PRACK";

//------------------------------------------------------------------------------
// Helper: a random number in [1, 32767], an initial CSeq (RFC 3261 section 8.1.1.5: "MUST be less than 2**31").
std::uint32_t initial_cseq() {
  std::uint16_t value = 0;
  if (RAND_bytes(reinterpret_cast<unsigned char *>(&value), sizeof value) != 1) throw std::runtime_error("random CSeq");
  return 1U + (value & 0x7fffU);
}

//------------------------------------------------------------------------------
// RFC 5621 and RFC 2046 section 5.1.3: an SDP alone as application/sdp, or first in a multipart/mixed body with the
// parts.
std::pair<std::string, std::string> sdp_body(const std::string &sdp, const std::vector<BodyPart> &parts) {
  if (parts.empty()) return {"application/sdp", sdp};
  std::vector<BodyPart> all{{"application/sdp", sdp}};
  all.insert(all.end(), parts.begin(), parts.end());
  const auto boundary = "mcx-" + resip_engine::random_hex(12);
  return {"multipart/mixed; boundary=" + boundary, multipart_body(all, boundary)};
}

//------------------------------------------------------------------------------
// Helper: the SDP of a body (the body itself, or its application/sdp part), empty without one.
std::string sdp_of(const std::string &content_type, const std::string &body) {
  if (body.empty()) return {};
  const auto type = sip_detail::ascii_lower(content_type);
  if (type.starts_with("application/sdp")) return body;
  if (!type.starts_with("multipart/")) return {};
  try {
    for (const auto &part : parse_body_parts(content_type, body))
      if (sip_detail::ascii_lower(part.content_type).starts_with("application/sdp")) return part.body;
  } catch (const std::exception &) {
  }
  return {};
}

//------------------------------------------------------------------------------
// RFC 3261 sections 7.3.1, 20.32 and 20.37 (as add_answer_headers of the pjproject engine): a server's own header
// fields joined to a message's: option tags of Supported and Require join the header field of that name; any other
// header field is added unless the message has one of that name.
void merge_headers(std::vector<SipHeader> &headers, const std::vector<SipHeader> &extra) {
  for (const auto &header : extra) {
    const auto existing = std::find_if(headers.begin(), headers.end(),
                                       [&](const SipHeader &known) { return ascii_equal(known.name, header.name); });
    const bool tags = ascii_equal(header.name, "Require") || ascii_equal(header.name, "Supported");
    if (existing == headers.end()) {
      headers.push_back(header);
      continue;
    }
    if (!tags) continue;
    std::size_t at = 0;
    while (at <= header.value.size()) {
      auto end = std::min(header.value.find(',', at), header.value.size());
      auto tag = header.value.substr(at, end - at);
      tag.erase(0, tag.find_first_not_of(" \t"));
      tag.erase(tag.find_last_not_of(" \t") + 1);
      at = end + 1;
      if (tag.empty()) continue;
      bool present = false;
      std::size_t from = 0;
      const auto &value = existing->value;
      while (from <= value.size()) {
        auto stop = std::min(value.find(',', from), value.size());
        auto known = value.substr(from, stop - from);
        known.erase(0, known.find_first_not_of(" \t"));
        known.erase(known.find_last_not_of(" \t") + 1);
        present = present || ascii_equal(known, tag);
        from = stop + 1;
      }
      if (!present) existing->value += ", " + tag;
    }
  }
}

//------------------------------------------------------------------------------
// Helper: whether a comma-separated header field (Require, Supported, Allow) lists a token.
bool lists(const std::vector<SipHeader> &headers, std::string_view name, std::string_view token) {
  for (const auto &header : headers) {
    if (!ascii_equal(header.name, name)) continue;
    std::size_t at = 0;
    while (at <= header.value.size()) {
      const auto end = std::min(header.value.find(',', at), header.value.size());
      auto value = header.value.substr(at, end - at);
      value.erase(0, value.find_first_not_of(" \t"));
      value.erase(value.find_last_not_of(" \t") + 1);
      if (ascii_equal(value, token)) return true;
      at = end + 1;
    }
  }
  return false;
}

//------------------------------------------------------------------------------
// RFC 4028 sections 4 and 5: the interval and refresher of a Session-Expires (or its compact form "x"); 0 without one.
std::pair<unsigned, std::string> session_expires_of(const std::vector<SipHeader> &headers) {
  auto value = std::string(get_header(headers, "Session-Expires"));
  if (value.empty()) value = std::string(get_header(headers, "x"));
  if (value.empty()) return {0, {}};
  unsigned interval = 0;
  const auto digits = value.find_first_not_of(" \t");
  if (digits == std::string::npos) return {0, {}};
  std::from_chars(value.data() + digits, value.data() + value.size(), interval);
  std::string refresher;
  const auto lower = sip_detail::ascii_lower(value);
  if (const auto at = lower.find("refresher="); at != std::string::npos) {
    refresher = lower.substr(at + 10);
    refresher = refresher.substr(0, refresher.find_first_of(" \t;,"));
  }
  return {interval, refresher};
}

//------------------------------------------------------------------------------
// Helper: a header field value without its tag parameter (a From or To as the dialog keeps it).
std::string without_tag(const resip::NameAddr &value) {
  resip::NameAddr copy(value);
  copy.remove(resip::p_tag);
  return resip_engine::text_of(copy);
}

//------------------------------------------------------------------------------
// Helper: the status code of a response.
int status_of(const resip::SipMessage &message) { return message.header(resip::h_StatusLine).statusCode(); }

//------------------------------------------------------------------------------
// Helper: the raw body of a message and its Content-Type.
std::pair<std::string, std::string> body_and_type(const resip::SipMessage &message) {
  const auto &raw = message.getRawBody();
  std::string body = raw.getBuffer() == nullptr ? std::string() : std::string(raw.getBuffer(), raw.getLength());
  std::string type;
  if (!body.empty() && message.exists(resip::h_ContentType))
    type = resip_engine::text_of(message.header(resip::h_ContentType));
  if (sip_detail::ascii_lower(type).starts_with("multipart/") && body.starts_with("\r\n--")) body.erase(0, 2);
  return {type, body};
}
} // namespace

//------------------------------------------------------------------------------
// Helper: reports a call state change to the application, catching what it throws.
void SipEngine::Impl::notify_call_state(std::string_view id, SipCallState state, int cause) const noexcept {
  if (!callbacks.on_call_state) return;
  try {
    callbacks.on_call_state(id, state, cause);
  } catch (const std::exception &error) {
    report_error(std::string("call state callback (") + std::to_string(cause) + "): " + error.what());
  } catch (...) {
    report_error("unknown SIP call state callback error");
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2: the application's response to a request; 501 without a handler, 500 when it throws.
SipResponse SipEngine::Impl::safe_application_response(const SipMessage &request) {
  SipResponse response;
  if (!callbacks.on_request) {
    response.status_code = 501;
    response.reason = "Not Implemented";
    return response;
  }
  try {
    return callbacks.on_request(request);
  } catch (const std::exception &error) {
    report_error("request handler (" + request.method + "): " + error.what());
  } catch (...) {
    report_error("unknown SIP application error");
  }
  response.status_code = 500;
  response.reason = "Application Error";
  return response;
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.4.1 (as response_contact of the pjproject engine): the Contact of an answer: this endpoint's,
// or the application's public session URI with its or the services' tags, ";isfocus" for a focus, and the media
// feature tags.
std::string SipEngine::Impl::response_contact(const SipResponse &response) const {
  std::string contact = contact_uri();
  if (!response.contact_uri.empty()) {
    const auto &uri = response.contact_uri;
    if (uri.size() > 2048 || uri.find_first_of("<>\r\n \t") != uri.npos ||
        (!uri.starts_with("sip:") && !uri.starts_with("sips:")))
      throw std::invalid_argument("invalid public SIP Contact URI");
    contact = "<" + uri + ">" + (response.contact_tags.empty() ? sip_detail::service_tags(config) : response.contact_tags);
  } else if (!response.contact_tags.empty()) {
    contact = "<" + sip_detail::contact_target(config) + ">" + response.contact_tags;
  }
  if (response.focus) contact += ";isfocus";
  return contact + config.media_feature_tags;
}

//------------------------------------------------------------------------------
// RFC 3261 section 12.2.1.1: a request in the dialog: the remote target as Request-URI, the route set, From and To
// with the tags, the Call-ID, the next local CSeq (ACK and CANCEL keep the INVITE's, set by the caller), this side's
// Contact for target-refresh requests.
SipEngine::Impl::OutgoingRequest SipEngine::Impl::dialog_request(Dialog &dialog, std::string_view method) const {
  OutgoingRequest request;
  request.method = std::string(method);
  request.request_uri = dialog.remote_target;
  request.from = dialog.local_name;
  request.from_tag = dialog.local_tag;
  request.to = dialog.remote_name + (dialog.remote_tag.empty() ? "" : ";tag=" + dialog.remote_tag);
  request.call_id = dialog.call_id;
  if (method != "ACK" && method != "CANCEL") request.cseq = ++dialog.local_cseq;
  request.routes = dialog.route_set;
  if (method == "INVITE" || method == "UPDATE" || method == "SUBSCRIBE" || method == "NOTIFY" || method == "REFER")
    request.contact = dialog.contact;
  return request;
}

//------------------------------------------------------------------------------
// Helper: a request of a dialog to the stack: with IMS AKA over the set in use with its sec-agree header fields
// (TS 33.203 clause 7.4.1a), and over UDP on TCP when the route set names TCP (the P-CSCF's Record-Route of a request
// that went over TCP).
std::string SipEngine::Impl::send_in_dialog(Dialog &dialog, OutgoingRequest request, Pending entry) {
  Hop hop = default_hop();
  if (aka) {
    aka_prepare(request);
    hop = aka_hop(*aka->current);
    if (config.aka.udp && !dialog.route_set.empty() &&
        sip_detail::ascii_lower(dialog.route_set.front()).find("transport=tcp") != std::string::npos) {
      hop.type = resip::TCP;
      const resip::Uri target{resip::Data(hop.force_target)};
      hop.force_target = "sip:" + std::string(target.host().c_str()) + ":" + std::to_string(target.port()) +
                         ";transport=tcp";
    }
  }
  entry.dialog_id = dialog.id;
  return dispatch(write_request(request, hop), hop, std::move(entry));
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.2 (as create_invite of the pjproject engine): a new INVITE dialog: From the identity with a new
// tag, To the Request-URI, a new Call-ID and CSeq, the Contact with the media feature tags (TS 24.229 clause 5.1.3.1)
// or the application's, a pinned route set when the application names a Route (otherwise the preloaded route, and the
// route set the 2xx records); Allow, Supported and Require "timer", Session-Expires and Min-SE (RFC 4028, the session
// timer required); the MCPTT service unless the application names one (TS 24.379 clause 6.3.3.1.2 steps 2 to 4); the
// SDP offer with a new origin (RFC 3264 section 8) and the application parts. Returns the dialog id (its Call-ID).
std::string SipEngine::Impl::create_invite(std::string_view request_uri, const MediaDescription &local_media,
                                           const std::vector<BodyPart> &parts, SipResponseHandler handler,
                                           const std::vector<SipHeader> &headers, const std::string *sdp_text) {
  ensure_started();
  if (request_uri.empty() || request_uri.find_first_of("\r\n \t<>") != std::string_view::npos)
    throw std::invalid_argument("invalid SIP request URI");
  for (const auto &header : headers) resip_engine::check_header(header);
  auto dialog = std::make_unique<Dialog>();
  dialog->uac = true;
  dialog->id = dialog->call_id = resip_engine::random_hex(16);
  dialog->local_tag = resip_engine::random_hex(8);
  dialog->local_name = sip_detail::name_addr(config.identity);
  dialog->remote_name = sip_detail::name_addr(request_uri);
  dialog->remote_target = std::string(request_uri);
  dialog->local_cseq = initial_cseq();
  dialog->sips = sips_target(request_uri);
  const auto override_contact = get_header(headers, "Contact");
  dialog->contact = override_contact.empty() ? contact_uri() + config.media_feature_tags : std::string(override_contact);
  if (dialog->sips) {
    const auto at = dialog->contact.starts_with('<') ? 1U : 0U;
    if (dialog->contact.compare(at, 4, "sip:") == 0) dialog->contact.insert(at + 3, "s");
  }
  if (const auto route = get_header(headers, "Route"); !route.empty()) {
    dialog->route_set = {std::string(route)};
    dialog->route_frozen = true;
  }
  if (sdp_text)
    record_sdp_text(dialog->sdp_origin, *sdp_text);
  else
    next_sdp_origin(dialog->sdp_origin, local_media);
  dialog->local_sdp = sdp_text ? *sdp_text : make_sdp(local_media, dialog->sdp_origin.id, dialog->sdp_origin.version);
  dialog->initial_handler = std::move(handler);

  auto request = dialog_request(*dialog, "INVITE");
  if (request.routes.empty()) request.routes = aka ? aka_routes() : std::vector<std::string>{[&] {
    auto route = "<" + config.core_uri;
    if (route.find(";lr") == std::string::npos) route += ";lr";
    return route + ">";
  }()};
  request.headers = {{"Allow", kAllowRequest},
                     {"Supported", "timer"},
                     {"Require", "timer"},
                     {"Session-Expires", std::to_string(config.session_expires)},
                     {"Min-SE", std::to_string(kMinimumSessionExpires)}};
  if (get_header(headers, "P-Preferred-Service").empty() && get_header(headers, "P-Asserted-Service").empty() &&
      config.service != nullptr) {
    request.headers.push_back({config.asserts_service ? "P-Asserted-Service" : "P-Preferred-Service",
                               config.service->icsi});
    request.headers.push_back({"Accept-Contact", std::string("*;+") + config.service->feature_tag + ";require;explicit"});
    request.headers.push_back({"Accept-Contact", std::string("*;+g.3gpp.icsi-ref=\"") + config.service->icsi_encoded +
                                                     "\";require;explicit"});
  }
  for (const auto &header : headers)
    if (!ascii_equal(header.name, "Route") && !ascii_equal(header.name, "Contact")) request.headers.push_back(header);
  merge_headers(request.headers, config.invite_request_headers);
  std::tie(request.content_type, request.body) = sdp_body(dialog->local_sdp, parts);

  const auto id = dialog->id;
  auto &stored = *dialog;
  dialogs[id] = std::move(dialog);
  try {
    Pending entry;
    entry.purpose = Purpose::invite;
    stored.invite_transaction = send_in_dialog(stored, std::move(request), std::move(entry));
  } catch (...) {
    dialogs.erase(id);
    throw;
  }
  return id;
}

//------------------------------------------------------------------------------
// RFC 3261 sections 12.1.2 and 12.2.1.2: the dialog from a response (the remote tag, the remote target from its
// Contact, the route set from its Record-Route in reverse unless pinned) or from a target-refresh request (the remote
// target).
void SipEngine::Impl::update_target(Dialog &dialog, const resip::SipMessage &message, bool from_response) {
  if (from_response && dialog.remote_tag.empty() && message.header(resip::h_To).exists(resip::p_tag))
    dialog.remote_tag = message.header(resip::h_To).param(resip::p_tag).c_str();
  if (message.exists(resip::h_Contacts) && !message.header(resip::h_Contacts).empty() &&
      !message.header(resip::h_Contacts).front().isAllContacts())
    dialog.remote_target = resip_engine::text_of(message.header(resip::h_Contacts).front().uri());
  if (from_response && !dialog.route_frozen && message.exists(resip::h_RecordRoutes) &&
      (dialog.state == Dialog::State::calling || status_of(message) / 100 == 2)) {
    std::vector<std::string> routes;
    for (const auto &route : message.header(resip::h_RecordRoutes)) routes.push_back(resip_engine::text_of(route));
    std::reverse(routes.begin(), routes.end());
    dialog.route_set = std::move(routes);
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.2.2.4: the ACK of a 2xx: the INVITE's CSeq, no Contact, the route set.
void SipEngine::Impl::send_ack(Dialog &dialog, std::uint32_t cseq) {
  auto request = dialog_request(dialog, "ACK");
  request.cseq = cseq;
  dialog.ack_cseq = cseq;
  send_in_dialog(dialog, std::move(request), Pending{});
}

//------------------------------------------------------------------------------
// RFC 3261 sections 13.2.2, 9.1 and 13.2.2.4 (as follow_invite_state of the pjproject engine): a response to the
// initial INVITE. A provisional one with a tag makes the dialog early (reported once, with the first such response to
// the handler; RFC 3262: a reliable one is acknowledged with PRACK). A 2xx is acknowledged; it confirms the call
// (media, state, then the handler), or ends it with BYE when this side has cancelled it meanwhile. A failure ends it.
void SipEngine::Impl::invite_response(const resip::SipMessage &message, Pending &entry) {
  const auto found = dialogs.find(entry.dialog_id);
  if (found == dialogs.end()) return;
  auto &dialog = *found->second;
  const int status = status_of(message);
  const std::uint32_t cseq = message.header(resip::h_CSeq).sequence();
  if (status < 200) {
    if (status == 100 || !message.header(resip::h_To).exists(resip::p_tag)) return;
    update_target(dialog, message, true);
    const bool first = dialog.state == Dialog::State::calling;
    if (first) dialog.state = Dialog::State::early;
    // RFC 3262 section 4: PRACK with RAck for a reliable provisional response.
    const auto headers = resip_engine::headers_of(message);
    if (lists(headers, "Require", "100rel") && !get_header(headers, "RSeq").empty()) {
      auto prack = dialog_request(dialog, "PRACK");
      prack.headers.push_back({"RAck", std::string(get_header(headers, "RSeq")) + " " + std::to_string(cseq) + " INVITE"});
      Pending pending_prack;
      pending_prack.purpose = Purpose::prack;
      send_in_dialog(dialog, std::move(prack), std::move(pending_prack));
    }
    if (first && !dialog.terminating) {
      const auto id = dialog.id;
      notify_call_state(id, SipCallState::early, status);
      if (!dialog.provisional_reported) {
        dialog.provisional_reported = true;
        SipResponse response;
        try {
          response = response_from(message);
        } catch (const std::exception &error) {
          report_error(error.what());
          return;
        }
        const auto handler = dialog.initial_handler;
        dispatch_response(response, handler);
      }
    }
    return;
  }

  SipResponse response;
  try {
    response = response_from(message);
  } catch (const std::exception &error) {
    report_error(std::string("received SIP response: ") + error.what());
    response.status_code = status;
  }
  if (status < 300) {
    update_target(dialog, message, true);
    send_ack(dialog, cseq);
    const auto id = dialog.id;
    if (dialog.terminating) {
      // RFC 3261 section 9.1: a 2xx crossed this side's CANCEL: the call is ended with BYE instead of reported.
      dialog.state = Dialog::State::confirmed;
      auto bye = dialog_request(dialog, "BYE");
      if (!dialog.bye_parts.empty()) {
        bye.content_type = dialog.bye_parts.front().content_type;
        bye.body = dialog.bye_parts.front().body;
      }
      Pending ending;
      ending.purpose = Purpose::bye;
      send_in_dialog(dialog, std::move(bye), std::move(ending));
      return;
    }
    dialog.state = Dialog::State::confirmed;
    const auto headers = resip_engine::headers_of(message);
    dialog.peer_allows_update = lists(headers, "Allow", "UPDATE");
    session_timer_from(dialog, message, false);
    // The application's callbacks below may end the dialog: what they need is taken first.
    auto handler = std::move(dialog.initial_handler);
    dialog.initial_handler = {};
    const auto [type, body] = body_and_type(message);
    report_media(dialog, type, body);
    notify_call_state(id, SipCallState::confirmed, status);
    dispatch_response(response, handler);
    return;
  }
  // RFC 3261 section 13.2.2.3: a failure ends the call (the stack acknowledges it).
  auto handler = std::move(dialog.initial_handler);
  terminate(dialog.id, status);
  dispatch_response(response, handler);
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.1 and RFC 3311 section 5.1: the final response to this side's re-INVITE (acknowledged when 2xx)
// or UPDATE: the negotiated media and the session timer on 2xx, then the handler; 481 or 408 ends the dialog
// (RFC 3261 section 12.2.1.2).
void SipEngine::Impl::offer_response(const resip::SipMessage &message, Pending &entry) {
  const auto found = dialogs.find(entry.dialog_id);
  if (found == dialogs.end()) return;
  auto &dialog = *found->second;
  const int status = status_of(message);
  const auto cseq = message.header(resip::h_CSeq).sequence();
  if (status / 100 == 2) {
    update_target(dialog, message, true);
    if (message.header(resip::h_CSeq).method() == resip::INVITE) send_ack(dialog, cseq);
    session_timer_from(dialog, message, false);
    const auto [type, body] = body_and_type(message);
    report_media(dialog, type, body);
  }
  SipResponse response;
  try {
    response = response_from(message);
  } catch (const std::exception &error) {
    report_error(std::string("received SIP response: ") + error.what());
    response.status_code = status;
  }
  SipResponseHandler handler;
  if (cseq >= dialog.offer_cseq) {
    handler = std::move(dialog.offer_handler);
    dialog.offer_handler = {};
    dialog.offer_cseq = 0;
  }
  const auto id = dialog.id;
  dispatch_response(response, handler);
  if ((status == 481 || status == 408) && dialogs.contains(id)) end_dialog(id, {}, {}, {});
}

//------------------------------------------------------------------------------
// RFC 3261 section 15.1.1: the final response to this side's BYE ends the session (reported disconnected, then the
// handler of SipEngine::bye gets it).
void SipEngine::Impl::bye_response(const resip::SipMessage &message, Pending &entry) {
  const auto found = dialogs.find(entry.dialog_id);
  if (found == dialogs.end()) return;
  SipResponse response;
  try {
    response = response_from(message);
  } catch (const std::exception &error) {
    report_error(error.what());
    response.status_code = status_of(message);
  }
  auto handler = std::move(found->second->initial_handler);
  terminate(entry.dialog_id, 200);
  dispatch_response(response, handler);
}

//------------------------------------------------------------------------------
// Helper: the dialog ends: its timers stop, it is forgotten and the application hears it disconnected with the cause.
void SipEngine::Impl::terminate(std::string dialog_id, int cause) {
  const auto found = dialogs.find(dialog_id);
  if (found == dialogs.end()) return;
  for (const auto timer : {Timer::answer_retransmit, Timer::answer_timeout, Timer::session_refresh,
                           Timer::session_expiry})
    cancel(timer, dialog_id);
  dialogs.erase(found);
  notify_call_state(dialog_id, SipCallState::disconnected, cause);
}

//------------------------------------------------------------------------------
// RFC 3264 sections 5 and 6 (as invite_media_updated of the pjproject engine): the peer's SDP of a completed offer and
// answer, when it describes audio or video, to the application's media callback.
void SipEngine::Impl::report_media(const Dialog &dialog, const std::string &content_type, const std::string &body) {
  if (!callbacks.on_media) return;
  const auto sdp = sdp_of(content_type, body);
  if (sdp.find("m=audio") == std::string::npos && sdp.find("m=video") == std::string::npos) return;
  try {
    callbacks.on_media(dialog.id, parse_sdp(sdp));
  } catch (const std::exception &error) {
    report_error(error.what());
  } catch (...) {
    report_error("unknown SIP media callback error");
  }
}

//------------------------------------------------------------------------------
// RFC 4028 sections 7, 8, 9 and 10: the session timer from a received request (this side answers it: the refresher it
// names, else the one this side chooses for an initial INVITE, SipConfig::uas_refresher) or from a 2xx to this side's
// request (the refresher it names); this side refreshes half way, or ends the session shortly before its expiry.
void SipEngine::Impl::session_timer_from(Dialog &dialog, const resip::SipMessage &message, bool as_uas) {
  const auto [interval, refresher] = session_expires_of(resip_engine::headers_of(message));
  if (interval == 0) {
    if (!as_uas) {
      dialog.session_expires = 0;
      cancel(Timer::session_refresh, dialog.id);
      cancel(Timer::session_expiry, dialog.id);
    }
    return;
  }
  dialog.session_expires = interval;
  const bool initial = dialog.state == Dialog::State::calling || dialog.state == Dialog::State::early;
  if (!as_uas)
    dialog.refresher = refresher != "uas"; // this side sent the request: "uac" is this side
  else if (refresher == "uas")
    dialog.refresher = true;
  else if (refresher == "uac")
    dialog.refresher = false;
  else if (initial)
    dialog.refresher = config.uas_refresher; // RFC 4028 section 9: the UAS chooses
  // else: a refresh without refresher keeps the dialog's
  cancel(Timer::session_refresh, dialog.id);
  cancel(Timer::session_expiry, dialog.id);
  if (dialog.refresher)
    schedule(Timer::session_refresh, std::chrono::seconds(std::max(1U, interval / 2)), dialog.id);
  else
    schedule(Timer::session_expiry, std::chrono::seconds(interval - std::min(32U, interval / 3)), dialog.id);
}

//------------------------------------------------------------------------------
// RFC 4028: the session timer header fields of this side's request (Supported, Session-Expires with the refresher
// from the receiver's view, Min-SE) or of its 2xx answer (Session-Expires with the refresher, Require "timer").
std::vector<SipHeader> SipEngine::Impl::session_headers(const Dialog &dialog, bool request) const {
  if (dialog.session_expires == 0) return {};
  const auto interval = std::to_string(dialog.session_expires);
  if (request)
    return {{"Supported", "timer"},
            {"Session-Expires", interval + ";refresher=" + (dialog.refresher ? "uac" : "uas")},
            {"Min-SE", std::to_string(kMinimumSessionExpires)}};
  return {{"Supported", "timer"},
          {"Session-Expires", interval + ";refresher=" + (dialog.refresher ? "uas" : "uac")},
          {"Require", "timer"}};
}

//------------------------------------------------------------------------------
// RFC 4028 section 10: this side's session refresh: an UPDATE without body when the peer allows it, otherwise a
// re-INVITE with the last SDP; with an offer in progress, a little later.
void SipEngine::Impl::refresh_session(const std::string &dialog_id) {
  const auto found = dialogs.find(dialog_id);
  if (found == dialogs.end() || found->second->terminating) return;
  auto &dialog = *found->second;
  if (dialog.state != Dialog::State::confirmed || dialog.offer_handler || dialog.incoming_offer) {
    schedule(Timer::session_refresh, std::chrono::seconds(2), dialog_id);
    return;
  }
  auto request = dialog_request(dialog, dialog.peer_allows_update ? "UPDATE" : "INVITE");
  request.headers = session_headers(dialog, true);
  if (!dialog.peer_allows_update) {
    // RFC 3264 section 8: the same description again, its version unchanged.
    std::tie(request.content_type, request.body) = sdp_body(dialog.local_sdp, {});
  }
  dialog.offer_cseq = request.cseq;
  dialog.offer_handler = [](const SipResponse &) {};
  Pending entry;
  entry.purpose = Purpose::offer;
  send_in_dialog(dialog, std::move(request), std::move(entry));
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.1 and RFC 3311 section 5.1 (as send_reinvite and update of the pjproject engine): an offer in a
// confirmed dialog with no offer pending: a re-INVITE or UPDATE with the SDP (and the parts), the session timer header
// fields and the application's.
void SipEngine::Impl::send_offer(std::string_view dialog_id, std::string_view method, std::string sdp,
                                 const std::vector<BodyPart> &parts, SipResponseHandler handler,
                                 const std::vector<SipHeader> &headers) {
  ensure_started();
  const auto found = dialogs.find(std::string(dialog_id));
  if (found == dialogs.end() || found->second->terminating)
    throw std::invalid_argument(std::string(method) + " requires active dialog");
  auto &dialog = *found->second;
  if (dialog.state != Dialog::State::confirmed || dialog.offer_handler || dialog.incoming_offer)
    throw std::runtime_error("an offer is already pending or the dialog is not confirmed (RFC 3311 section 5.1)");
  for (const auto &header : headers) resip_engine::check_header(header);
  auto request = dialog_request(dialog, method);
  request.headers = session_headers(dialog, true);
  request.headers.insert(request.headers.end(), headers.begin(), headers.end());
  dialog.local_sdp = std::move(sdp);
  std::tie(request.content_type, request.body) = sdp_body(dialog.local_sdp, parts);
  dialog.offer_cseq = request.cseq;
  dialog.offer_handler = handler ? std::move(handler) : [](const SipResponse &) {};
  Pending entry;
  entry.purpose = Purpose::offer;
  try {
    send_in_dialog(dialog, std::move(request), std::move(entry));
  } catch (...) {
    dialog.offer_handler = {};
    dialog.offer_cseq = 0;
    throw;
  }
}

//------------------------------------------------------------------------------
// RFC 3261 sections 15.1.1 and 9.1 (as bye of the pjproject engine): ends a call: BYE in a confirmed dialog (with at
// most one body part), CANCEL of this side's early INVITE (the body kept for the BYE should a 2xx cross it), 487 to an
// INVITE this side has not answered yet. Repeated ends are harmless.
void SipEngine::Impl::end_dialog(std::string_view dialog_id, SipResponseHandler handler,
                                 const std::vector<SipHeader> &headers, const std::vector<BodyPart> &parts) {
  ensure_started();
  const auto found = dialogs.find(std::string(dialog_id));
  if (found == dialogs.end() || found->second->terminating) return;
  auto &dialog = *found->second;
  for (const auto &header : headers) resip_engine::check_header(header);
  dialog.terminating = true;
  dialog.bye_parts = parts;
  if (handler) dialog.initial_handler = std::move(handler);
  const auto id = dialog.id;
  if (dialog.uac && (dialog.state == Dialog::State::calling || dialog.state == Dialog::State::early)) {
    // RFC 3261 section 9.1: the stack sends the CANCEL once a provisional response has arrived.
    stack->cancelClientInviteTransaction(resip::Data(dialog.invite_transaction), nullptr);
    transmit();
    return;
  }
  if (!dialog.uac && !dialog.final_answer && dialog.invite_request) {
    SipResponse terminated;
    terminated.status_code = 487;
    terminated.reason = "Request Terminated";
    send_dialog_response(dialog, *dialog.invite_request, terminated, {{"Allow", kAllowAnswer}});
    terminate(id, 487);
    return;
  }
  auto bye = dialog_request(dialog, "BYE");
  bye.headers = headers;
  if (!parts.empty()) {
    bye.content_type = parts.front().content_type;
    bye.body = parts.front().body;
  }
  Pending entry;
  entry.purpose = Purpose::bye;
  send_in_dialog(dialog, std::move(bye), std::move(entry));
}

//------------------------------------------------------------------------------
// Helper: a response in a dialog: the dialog's tag in To, the extra header fields first.
void SipEngine::Impl::send_dialog_response(Dialog &dialog, const resip::SipMessage &request,
                                           const SipResponse &response, const std::vector<SipHeader> &extra) {
  SipResponse full = response;
  full.headers = extra;
  full.headers.insert(full.headers.end(), response.headers.begin(), response.headers.end());
  const auto text = send_response(request, full, dialog.local_tag);
  if (response.status_code / 100 == 2 && request.method() == resip::INVITE) {
    // RFC 3261 section 13.3.1.4: over UDP the 2xx is retransmitted until its ACK; 64*T1 without one ends the call.
    dialog.pending_ack_cseq = request.header(resip::h_CSeq).sequence();
    const bool udp = request.getSource().getType() == resip::UDP;
    if (udp) {
      dialog.answer_text = text;
      dialog.answer_interval = kT1;
      schedule(Timer::answer_retransmit, kT1, dialog.id);
    }
    schedule(Timer::answer_timeout, kT1 * 64, dialog.id);
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.3.1 (as accept_invite and answer of the pjproject engine): an answer to the dialog's INVITE:
// a provisional one (the Contact, Allow, the provisional header fields of the configuration; RFC 3262 with RSeq when
// the INVITE requires 100rel) makes the dialog early; a 2xx (the Contact, Allow, the session timer, the SDP answer
// with the parts and the dialog parts, the success header fields of the configuration) waits for its ACK; a failure
// ends the call. The final answer keeps the last provisional answer's header fields that it does not set itself,
// except Alert-Info (RFC 3261 section 20.4).
void SipEngine::Impl::answer_invite(Dialog &dialog, const SipResponse &response) {
  const int status = response.status_code;
  const auto &invite = *dialog.invite_request;
  std::vector<SipHeader> extra;
  if (status > 100 && status < 300) extra.push_back({"Contact", dialog.response_contact});
  if (status > 100) extra.push_back({"Allow", kAllowAnswer});
  SipResponse answer = response;
  if (status >= 200) {
    std::vector<SipHeader> kept;
    for (const auto &header : dialog.provisional_headers) {
      if (ascii_equal(header.name, "Alert-Info")) continue;
      const bool replaced = std::any_of(response.headers.begin(), response.headers.end(),
                                        [&](const SipHeader &own) { return ascii_equal(own.name, header.name); });
      if (!replaced) kept.push_back(header);
    }
    answer.headers = kept;
    answer.headers.insert(answer.headers.end(), response.headers.begin(), response.headers.end());
  }
  if (status / 100 == 2) {
    const auto session = session_headers(dialog, false);
    extra.insert(extra.end(), session.begin(), session.end());
    if (response.local_sdp)
      record_sdp_text(dialog.sdp_origin, *response.local_sdp);
    else if (response.local_media)
      next_sdp_origin(dialog.sdp_origin, *response.local_media);
    if (response.local_sdp || response.local_media)
      dialog.local_sdp = response.local_sdp ? *response.local_sdp
                                            : make_sdp(*response.local_media, dialog.sdp_origin.id,
                                                       dialog.sdp_origin.version);
    auto parts = response.parts;
    if (response.dialog_parts)
      for (auto &part : response.dialog_parts(dialog.local_tag, dialog.remote_tag)) parts.push_back(std::move(part));
    std::tie(answer.content_type, answer.body) = sdp_body(dialog.local_sdp, parts);
    answer.parts.clear();
    merge_headers(answer.headers, config.invite_success_headers);
  } else if (status > 100 && status < 200) {
    merge_headers(answer.headers, config.invite_provisional_headers);
    if (dialog.reliable) {
      extra.push_back({"Require", "100rel"});
      extra.push_back({"RSeq", std::to_string(++dialog.rseq)});
    }
    answer.content_type.clear();
    answer.body.clear();
    answer.parts.clear();
  }
  send_dialog_response(dialog, invite, answer, extra);
  const auto id = dialog.id;
  if (status < 200) {
    dialog.provisional_headers = response.headers;
    if (dialog.state == Dialog::State::calling) {
      dialog.state = Dialog::State::early;
      notify_call_state(id, SipCallState::early, status);
    }
    return;
  }
  dialog.final_answer = true;
  if (status < 300) {
    dialog.state = Dialog::State::connecting;
    const auto [type, body] = body_and_type(invite);
    report_media(dialog, type, body);
    notify_call_state(id, SipCallState::early, status);
    return;
  }
  terminate(id, status);
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.3.1 (as accept_invite of the pjproject engine): the UAS dialog of an initial INVITE that the
// application answers 1xx or 2xx: a new local tag, the remote tag, target and route set (its Record-Route, or the
// application's peer route, pinned), this side's Contact (SIPS for a SIPS request), the session timer (RFC 4028: 422
// below Min-SE) and RFC 3262 when the INVITE requires 100rel; then the answer. False when the INVITE was refused here
// (the application then hears the call disconnected with the status).
bool SipEngine::Impl::receive_initial_invite(const resip::SipMessage &message, SipMessage &request,
                                             const SipResponse &response) {
  if (dialogs.contains(request.dialog_id)) throw std::invalid_argument("SIP Call-ID collision");
  if (response.status_code >= 200 && !response.local_media && !response.local_sdp)
    throw std::invalid_argument("a final INVITE answer needs local media");
  auto dialog = std::make_unique<Dialog>();
  dialog->id = request.dialog_id;
  dialog->call_id = message.header(resip::h_CallId).value().c_str();
  dialog->local_tag = resip_engine::random_hex(8);
  dialog->remote_tag = message.header(resip::h_From).exists(resip::p_tag)
                           ? message.header(resip::h_From).param(resip::p_tag).c_str()
                           : "";
  dialog->local_name = without_tag(message.header(resip::h_To));
  dialog->remote_name = without_tag(message.header(resip::h_From));
  if (!message.exists(resip::h_Contacts) || message.header(resip::h_Contacts).empty())
    throw std::invalid_argument("INVITE without Contact (RFC 3261 section 8.1.1.8)");
  dialog->remote_target = resip_engine::text_of(message.header(resip::h_Contacts).front().uri());
  if (message.exists(resip::h_RecordRoutes))
    for (const auto &route : message.header(resip::h_RecordRoutes))
      dialog->route_set.push_back(resip_engine::text_of(route));
  if (dialog->route_set.empty() && !response.peer_route.empty()) {
    dialog->route_set = {response.peer_route};
    dialog->route_frozen = true;
  }
  dialog->remote_cseq = message.header(resip::h_CSeq).sequence();
  dialog->local_cseq = initial_cseq();
  // RFC 3261 section 12.1.1: a SIPS Request-URI, top Record-Route or (without one) Contact makes this side's SIPS.
  const auto lower = [](const std::string &text) { return sip_detail::ascii_lower(text); };
  dialog->sips = lower(request.request_uri).starts_with("sips:") ||
                 (!dialog->route_set.empty() && !dialog->route_frozen
                      ? lower(dialog->route_set.front()).find("<sips:") != std::string::npos ||
                            lower(dialog->route_set.front()).starts_with("sips:")
                      : lower(dialog->remote_target).starts_with("sips:"));
  const auto sipsify = [&](std::string contact) {
    if (!dialog->sips) return contact;
    const auto at = contact.starts_with('<') ? 1U : 0U;
    if (contact.compare(at, 4, "sip:") == 0) contact.insert(at + 3, "s");
    return contact;
  };
  dialog->response_contact = sipsify(response_contact(response));
  dialog->contact = dialog->response_contact;
  dialog->answer_sdp_pending = !response.local_media && !response.local_sdp;
  // RFC 3264 section 8: the dialog's first SDP takes a new origin (answer_invite repeats it for an answer that names
  // its media again).
  if (response.local_sdp)
    record_sdp_text(dialog->sdp_origin, *response.local_sdp);
  else if (response.local_media)
    next_sdp_origin(dialog->sdp_origin, *response.local_media);
  if (response.local_sdp || response.local_media)
    dialog->local_sdp = response.local_sdp ? *response.local_sdp
                                           : make_sdp(*response.local_media, dialog->sdp_origin.id,
                                                      dialog->sdp_origin.version);
  dialog->reliable = lists(request.headers, "Require", "100rel");
  // RFC 4028 sections 8 and 9: the session interval the INVITE asks, at least this side's Min-SE.
  const auto [interval, refresher] = session_expires_of(request.headers);
  if (interval != 0 && interval < kMinimumSessionExpires) {
    SipResponse too_small;
    too_small.status_code = 422;
    too_small.reason = "Session Interval Too Small";
    too_small.headers.push_back({"Min-SE", std::to_string(kMinimumSessionExpires)});
    send_response(message, too_small);
    notify_call_state(request.dialog_id, SipCallState::disconnected, 422);
    return false;
  }
  dialog->invite_request = std::make_unique<resip::SipMessage>(message);
  auto &stored = *dialog;
  const auto id = dialog->id;
  dialogs[id] = std::move(dialog);
  try {
    if (interval != 0) session_timer_from(stored, message, true);
    answer_invite(stored, response);
  } catch (...) {
    // The INVITE is answered 500 in its dialog where that is still possible, and the dialog goes.
    try {
      SipResponse failure;
      failure.status_code = 500;
      failure.reason = "Server Internal Error";
      if (const auto found = dialogs.find(id); found != dialogs.end() && !found->second->final_answer)
        send_dialog_response(*found->second, message, failure, {});
    } catch (...) {
    }
    terminate(id, 500);
    throw;
  }
  return true;
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.3.1.4 and RFC 3264: the ACK of a 2xx this side sent: the retransmissions stop, the application
// hears it (on_ack), and the first one confirms the call; an SDP in it answers an offer of the 2xx.
void SipEngine::Impl::receive_ack(const resip::SipMessage &message) {
  const auto found = dialogs.find(message.header(resip::h_CallId).value().c_str());
  if (found == dialogs.end()) return;
  auto &dialog = *found->second;
  if (!dialog.pending_ack_cseq || *dialog.pending_ack_cseq != message.header(resip::h_CSeq).sequence()) return;
  dialog.pending_ack_cseq.reset();
  dialog.answer_text.clear();
  cancel(Timer::answer_retransmit, dialog.id);
  cancel(Timer::answer_timeout, dialog.id);
  const auto id = dialog.id;
  const auto [type, body] = body_and_type(message);
  if (!body.empty()) report_media(dialog, type, body);
  if (callbacks.on_ack) {
    try {
      callbacks.on_ack(id);
    } catch (const std::exception &error) {
      report_error(error.what());
    } catch (...) {
      report_error("unknown SIP ACK callback error");
    }
  }
  if (const auto again = dialogs.find(id); again != dialogs.end() && again->second->state == Dialog::State::connecting) {
    again->second->state = Dialog::State::confirmed;
    again->second->invite_request.reset();
    notify_call_state(id, SipCallState::confirmed, 200);
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 9.2: a CANCEL (the stack has matched it to an INVITE server transaction): 200 to it and, when the
// INVITE has no final answer yet, 487 (Request Terminated) to the INVITE, which ends the call.
void SipEngine::Impl::receive_cancel(const resip::SipMessage &message) {
  SipResponse ok;
  ok.status_code = 200;
  ok.reason = "OK";
  const auto found = dialogs.find(message.header(resip::h_CallId).value().c_str());
  const bool pending = found != dialogs.end() && !found->second->uac && !found->second->final_answer &&
                       found->second->invite_request &&
                       found->second->invite_request->getTransactionId() == message.getTransactionId();
  if (!pending) {
    send_response(message, ok);
    return;
  }
  auto &dialog = *found->second;
  send_response(message, ok, dialog.local_tag);
  SipResponse terminated;
  terminated.status_code = 487;
  terminated.reason = "Request Terminated";
  send_dialog_response(dialog, *dialog.invite_request, terminated, {{"Allow", kAllowAnswer}});
  terminate(dialog.id, 487);
}

//------------------------------------------------------------------------------
// RFC 3261 section 12.2.2: a request in a dialog of this engine: 481 for an unknown dialog, 500 for a CSeq not above
// the last; BYE ends the call (the application sees it first); re-INVITE and UPDATE with an offer go to receive_offer
// (491 while this side's offer is pending, RFC 3261 section 14.2 and RFC 3311 section 5.2); an UPDATE without offer
// refreshes the session (RFC 4028); PRACK is answered 200; other requests (INFO, MESSAGE) go to the application as
// outside a dialog.
void SipEngine::Impl::receive_in_dialog(const resip::SipMessage &message) {
  const std::string call_id = message.header(resip::h_CallId).value().c_str();
  const auto found = dialogs.find(call_id);
  const auto from_tag = message.header(resip::h_From).exists(resip::p_tag)
                            ? std::string(message.header(resip::h_From).param(resip::p_tag).c_str())
                            : std::string();
  const auto to_tag = std::string(message.header(resip::h_To).param(resip::p_tag).c_str());
  const auto respond = [&](int code, const char *reason, std::vector<SipHeader> headers = {}) {
    SipResponse response;
    response.status_code = code;
    response.reason = reason;
    response.headers = std::move(headers);
    send_response(message, response);
  };
  if (found == dialogs.end() || found->second->local_tag != to_tag)
    return respond(481, "Call/Transaction Does Not Exist");
  auto &dialog = *found->second;
  // RFC 6665 section 4.1.2.4: "the subscriber MUST be prepared to receive NOTIFY requests before the SUBSCRIBE
  // transaction has completed": a NOTIFY to this side's SUBSCRIBE dialog without its remote tag establishes it.
  if (!dialog.invite && dialog.uac && dialog.remote_tag.empty() && message.method() == resip::NOTIFY && !from_tag.empty()) {
    dialog.remote_tag = from_tag;
    if (message.exists(resip::h_Contacts) && !message.header(resip::h_Contacts).empty())
      dialog.remote_target = resip_engine::text_of(message.header(resip::h_Contacts).front().uri());
    if (!dialog.route_frozen && message.exists(resip::h_RecordRoutes)) {
      dialog.route_set.clear();
      for (const auto &route : message.header(resip::h_RecordRoutes))
        dialog.route_set.push_back(resip_engine::text_of(route));
    }
    dialog.state = Dialog::State::confirmed;
  }
  if (dialog.remote_tag != from_tag) return respond(481, "Call/Transaction Does Not Exist");
  const auto cseq = message.header(resip::h_CSeq).sequence();
  if (dialog.remote_cseq && cseq <= *dialog.remote_cseq) return respond(500, "Server Internal Error");
  dialog.remote_cseq = cseq;
  const auto method = message.method();
  const auto id = dialog.id;

  if (method == resip::BYE && dialog.invite) {
    respond(200, "OK");
    try {
      (void)safe_application_response(message_from(message));
    } catch (const std::exception &error) {
      report_error(error.what());
    }
    const auto again = dialogs.find(id);
    if (again == dialogs.end()) return;
    if (!again->second->uac && !again->second->final_answer && again->second->invite_request) {
      SipResponse terminated;
      terminated.status_code = 487;
      terminated.reason = "Request Terminated";
      send_dialog_response(*again->second, *again->second->invite_request, terminated, {});
    }
    terminate(id, 200);
    return;
  }
  if (method == resip::PRACK && dialog.invite) return respond(200, "OK");
  const auto [type, body] = body_and_type(message);
  const bool offer = !sdp_of(type, body).empty();
  if (dialog.invite && (method == resip::INVITE || (method == resip::UPDATE && offer))) {
    if (dialog.offer_handler) return respond(491, "Request Pending");
    if (dialog.incoming_offer) return respond(500, "Server Internal Error", {{"Retry-After", "1"}});
    update_target(dialog, message, false);
    return receive_offer(dialog, message);
  }
  if (method == resip::UPDATE && dialog.invite) {
    // RFC 4028 section 7: a session refresh without offer.
    update_target(dialog, message, false);
    session_timer_from(dialog, message, true);
    SipResponse ok;
    ok.status_code = 200;
    ok.reason = "OK";
    auto extra = session_headers(dialog, false);
    extra.insert(extra.begin(), {"Contact", dialog.contact});
    send_dialog_response(dialog, message, ok, extra);
    return;
  }
  // INFO, MESSAGE, NOTIFY, SUBSCRIBE and the others: as outside a dialog (the application's response, deferrable but
  // for a SUBSCRIBE refresh).
  SipMessage request = message_from(message);
  request.transaction_id = std::to_string(++next_transaction);
  SipResponse response = safe_application_response(request);
  if (response.deferred) {
    if (method == resip::SUBSCRIBE) throw std::invalid_argument("an in-dialog SUBSCRIBE cannot be deferred");
    deferred[request.transaction_id] = std::make_unique<resip::SipMessage>(message);
    return;
  }
  // The application may have ended the dialog meanwhile.
  const auto still = dialogs.find(id);
  if (still == dialogs.end()) {
    send_response(message, response);
    return;
  }
  auto &current = *still->second;
  // RFC 6665 section 4.2.1: the 2xx to a SUBSCRIBE refresh carries the notifier's Contact.
  if (method == resip::SUBSCRIBE && response.status_code / 100 == 2 &&
      std::none_of(response.headers.begin(), response.headers.end(),
                   [](const SipHeader &header) { return ascii_equal(header.name, "Contact"); }))
    response.headers.insert(response.headers.begin(), {"Contact", current.contact});
  send_response(message, response);
  // RFC 6665 section 4.1.3: a NOTIFY with Subscription-State "terminated", accepted, ends the subscription.
  if (!current.invite && method == resip::NOTIFY && response.status_code / 100 == 2 &&
      sip_detail::ascii_lower(std::string(get_header(request.headers, "Subscription-State"))).starts_with("terminated"))
    dialogs.erase(id);
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2 (as create_subscribe of the pjproject engine): a subscription dialog and its initial
// SUBSCRIBE: From the identity with a new tag, To the Request-URI, a new Call-ID and CSeq, this side's Contact (or the
// application's, which the dialog keeps), a pinned route set for an application Route (otherwise the preloaded route),
// Event, Expires, the application's header fields and body. Returns the dialog id (its Call-ID).
std::string SipEngine::Impl::create_subscribe(std::string_view request_uri, std::string_view event, unsigned expires,
                                              const std::vector<SipHeader> &headers, SipResponseHandler handler,
                                              std::string_view content_type, std::string_view body) {
  ensure_started();
  if (request_uri.empty() || request_uri.find_first_of("\r\n \t<>") != std::string_view::npos)
    throw std::invalid_argument("invalid SIP request URI");
  if (event.find_first_of("\r\n") != std::string_view::npos || content_type.find_first_of("\r\n") != std::string_view::npos)
    throw std::invalid_argument("invalid SUBSCRIBE event or content type");
  for (const auto &header : headers) resip_engine::check_header(header);
  auto dialog = std::make_unique<Dialog>();
  dialog->uac = true;
  dialog->invite = false;
  dialog->id = dialog->call_id = resip_engine::random_hex(16);
  dialog->local_tag = resip_engine::random_hex(8);
  dialog->local_name = sip_detail::name_addr(config.identity);
  dialog->remote_name = sip_detail::name_addr(request_uri);
  dialog->remote_target = std::string(request_uri);
  dialog->local_cseq = initial_cseq();
  dialog->sips = sips_target(request_uri);
  const auto override_contact = get_header(headers, "Contact");
  dialog->contact = override_contact.empty() ? contact_uri() : std::string(override_contact);
  if (dialog->sips) {
    const auto at = dialog->contact.starts_with('<') ? 1U : 0U;
    if (dialog->contact.compare(at, 4, "sip:") == 0) dialog->contact.insert(at + 3, "s");
  }
  if (const auto route = get_header(headers, "Route"); !route.empty()) {
    dialog->route_set = {std::string(route)};
    dialog->route_frozen = true;
  }
  auto request = dialog_request(*dialog, "SUBSCRIBE");
  if (request.routes.empty()) request.routes = aka ? aka_routes() : std::vector<std::string>{[&] {
    auto route = "<" + config.core_uri;
    if (route.find(";lr") == std::string::npos) route += ";lr";
    return route + ">";
  }()};
  request.headers = {{"Event", std::string(event)}, {"Expires", std::to_string(expires)}};
  for (const auto &header : headers)
    if (!ascii_equal(header.name, "Route") && !ascii_equal(header.name, "Contact")) request.headers.push_back(header);
  if (!body.empty()) {
    request.content_type = std::string(content_type);
    request.body = std::string(body);
  }
  const auto id = dialog->id;
  auto &stored = *dialog;
  dialogs[id] = std::move(dialog);
  try {
    Pending entry;
    entry.purpose = Purpose::subscribe;
    entry.handler = std::move(handler);
    send_in_dialog(stored, std::move(request), std::move(entry));
  } catch (...) {
    dialogs.erase(id);
    throw;
  }
  return id;
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2.1: the final response to the initial SUBSCRIBE: a 2xx establishes the dialog (unless a
// NOTIFY already has), a failure ends it (no dialog is kept); then the handler.
void SipEngine::Impl::subscribe_response(const resip::SipMessage &message, Pending &entry) {
  const int status = status_of(message);
  if (const auto found = dialogs.find(entry.dialog_id); found != dialogs.end()) {
    if (status / 100 == 2) {
      update_target(*found->second, message, true);
      found->second->state = Dialog::State::confirmed;
    } else if (status >= 300) {
      dialogs.erase(found);
    }
  }
  SipResponse response;
  try {
    response = response_from(message);
  } catch (const std::exception &error) {
    report_error(std::string("received SIP response: ") + error.what());
    response.status_code = status;
  }
  dispatch_response(response, entry.handler);
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.1 (as accept_subscription of the pjproject engine): the notifier's dialog of an initial
// SUBSCRIBE that the application accepts: a new local tag, the subscriber's tag, target and route set, this side's
// Contact (SIPS for a SIPS request); then the 2xx with that Contact.
void SipEngine::Impl::accept_subscription(const resip::SipMessage &message, const SipResponse &response) {
  const std::string call_id = message.header(resip::h_CallId).value().c_str();
  if (dialogs.contains(call_id)) throw std::invalid_argument("SIP Call-ID collision");
  if (!message.exists(resip::h_Contacts) || message.header(resip::h_Contacts).empty())
    throw std::invalid_argument("SUBSCRIBE without Contact (RFC 6665 section 4.1.2)");
  auto dialog = std::make_unique<Dialog>();
  dialog->invite = false;
  dialog->id = dialog->call_id = call_id;
  dialog->local_tag = resip_engine::random_hex(8);
  dialog->remote_tag = message.header(resip::h_From).exists(resip::p_tag)
                           ? message.header(resip::h_From).param(resip::p_tag).c_str()
                           : "";
  dialog->local_name = without_tag(message.header(resip::h_To));
  dialog->remote_name = without_tag(message.header(resip::h_From));
  dialog->remote_target = resip_engine::text_of(message.header(resip::h_Contacts).front().uri());
  if (message.exists(resip::h_RecordRoutes))
    for (const auto &route : message.header(resip::h_RecordRoutes))
      dialog->route_set.push_back(resip_engine::text_of(route));
  dialog->remote_cseq = message.header(resip::h_CSeq).sequence();
  dialog->local_cseq = initial_cseq();
  const auto lower = [](const std::string &text) { return sip_detail::ascii_lower(text); };
  const std::string request_uri = resip_engine::text_of(message.header(resip::h_RequestLine).uri());
  dialog->sips = lower(request_uri).starts_with("sips:") ||
                 (!dialog->route_set.empty() ? lower(dialog->route_set.front()).find("<sips:") != std::string::npos
                                             : lower(dialog->remote_target).starts_with("sips:"));
  dialog->contact = contact_uri();
  if (dialog->sips) {
    const auto at = dialog->contact.starts_with('<') ? 1U : 0U;
    if (dialog->contact.compare(at, 4, "sip:") == 0) dialog->contact.insert(at + 3, "s");
  }
  dialog->state = Dialog::State::confirmed;
  auto &stored = *dialog;
  dialogs[call_id] = std::move(dialog);
  try {
    send_dialog_response(stored, message, response, {{"Contact", stored.contact}});
  } catch (...) {
    dialogs.erase(call_id);
    throw;
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.2 and RFC 3311 section 5.2 (as receive_reinvite and receive_offer of the pjproject engine): a
// re-INVITE or an UPDATE with an offer goes to the application; a re-INVITE answered deferred waits (the stack has sent
// 100 Trying) for SipEngine::respond; otherwise the answer now.
void SipEngine::Impl::receive_offer(Dialog &dialog, const resip::SipMessage &message) {
  SipMessage request;
  try {
    request = message_from(message);
  } catch (const std::exception &error) {
    report_error(error.what());
    SipResponse refused;
    refused.status_code = 488;
    refused.reason = "Not Acceptable Here";
    return send_dialog_response(dialog, message, refused, {});
  }
  request.transaction_id = std::to_string(++next_transaction);
  dialog.incoming_offer = std::make_unique<resip::SipMessage>(message);
  const auto id = dialog.id;
  const auto response = safe_application_response(request);
  const auto found = dialogs.find(id);
  if (found == dialogs.end()) return;
  if (response.deferred && message.method() == resip::INVITE) {
    deferred[request.transaction_id] = std::make_unique<resip::SipMessage>(message);
    return;
  }
  answer_offer(*found->second, message, response);
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.2, RFC 3311 section 5.2 and RFC 3264 section 6 (as answer_reinvite of the pjproject engine): the
// answer to a received re-INVITE or UPDATE offer: a 2xx with the SDP answer (the dialog's origin, its version raised
// when the description changed), the Contact, the session timer and, for a re-INVITE, the success header fields of the
// configuration; 488 for a 2xx without media; an error with its body; a provisional one (to a deferred re-INVITE)
// without SDP, the final answer still to come. The negotiated media then reach on_media.
void SipEngine::Impl::answer_offer(Dialog &dialog, const resip::SipMessage &offer, SipResponse response) {
  const bool invite = offer.method() == resip::INVITE;
  if (invite && response.status_code > 100 && response.status_code < 200) {
    SipResponse provisional = response;
    provisional.content_type.clear();
    provisional.body.clear();
    provisional.parts.clear();
    send_dialog_response(dialog, offer, provisional, {});
    return;
  }
  if (response.status_code < 200) response.status_code = 500;
  if (response.status_code < 300 && !response.local_media && !response.local_sdp) {
    response.status_code = 488;
    response.reason = "Not Acceptable Here";
  }
  std::vector<SipHeader> extra;
  if (response.status_code < 300) {
    session_timer_from(dialog, offer, true);
    if (response.local_sdp)
      record_sdp_text(dialog.sdp_origin, *response.local_sdp);
    else
      next_sdp_origin(dialog.sdp_origin, *response.local_media);
    dialog.local_sdp = response.local_sdp ? *response.local_sdp
                                          : make_sdp(*response.local_media, dialog.sdp_origin.id,
                                                     dialog.sdp_origin.version);
    std::tie(response.content_type, response.body) = sdp_body(dialog.local_sdp, response.parts);
    response.parts.clear();
    extra.push_back({"Contact", dialog.contact});
    extra.push_back({"Allow", kAllowAnswer});
    const auto session = session_headers(dialog, false);
    extra.insert(extra.end(), session.begin(), session.end());
    if (invite && !config.reinvite_success_headers.empty()) {
      if (std::none_of(extra.begin(), extra.end(), [](const SipHeader &h) { return ascii_equal(h.name, "Supported"); }))
        extra.push_back({"Supported", "100rel, timer"});
      merge_headers(extra, config.reinvite_success_headers);
    }
  } else if (response.content_type.empty() && !response.parts.empty()) {
    std::tie(response.content_type, response.body) = message_body(response.parts, "mcx-reinvite-error");
    response.parts.clear();
  }
  dialog.incoming_offer.reset();
  send_dialog_response(dialog, offer, response, extra);
  if (response.status_code < 300) {
    const auto [type, body] = body_and_type(offer);
    report_media(dialog, type, body);
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 12.2.1 (as send_dialog_request of the pjproject engine): INFO, MESSAGE, SUBSCRIBE or NOTIFY in a
// dialog, with the
// application's header fields and body; the handler gets the final response (after a digest retry).
void SipEngine::Impl::send_dialog_request(std::string_view dialog_id, std::string_view method,
                                          const std::vector<SipHeader> &headers, std::string_view content_type,
                                          std::string_view body, SipResponseHandler handler) {
  ensure_started();
  const auto found = dialogs.find(std::string(dialog_id));
  if (found == dialogs.end()) throw std::invalid_argument("unknown SIP dialog");
  for (const auto &header : headers) resip_engine::check_header(header);
  if (content_type.find_first_of("\r\n") != std::string_view::npos)
    throw std::invalid_argument("invalid SIP content type");
  auto request = dialog_request(*found->second, method);
  request.headers = headers;
  request.content_type = std::string(content_type);
  request.body = std::string(body);
  Pending entry;
  entry.handler = std::move(handler);
  // RFC 6665 section 4.2.2: this side's NOTIFY that terminates the subscription ends the dialog once answered.
  entry.ends_subscription =
      method == "NOTIFY" &&
      sip_detail::ascii_lower(std::string(get_header(headers, "Subscription-State"))).starts_with("terminated");
  send_in_dialog(*found->second, std::move(request), std::move(entry));
}

} // namespace mcx
