//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// mcx::SipEngine (include/mcx/sip.hpp) on reSIProcate: the public operations over SipEngine::Impl (resip_impl.hpp).
//
// Specifications: RFC 3261, RFC 3903, TS 24.379 V19.7.0 (Rel-19) clause 7.2.

#include "resip_impl.hpp"

#include "mcx/runtime.hpp"

#include <algorithm>
#include <stdexcept>

namespace mcx {
SipEngine::SipEngine(SipConfig config, SipCallbacks callbacks)
    : impl_(std::make_unique<Impl>(std::move(config), std::move(callbacks))) {}

SipEngine::~SipEngine() noexcept = default;

void SipEngine::start() { impl_->start(); }

void SipEngine::stop() noexcept { impl_->stop(); }

bool SipEngine::running() const noexcept { return impl_->started; }

void SipEngine::poll(std::chrono::milliseconds timeout) { impl_->poll(timeout); }

// The dialogs that are not INVITE sessions (the subscription dialogs of RFC 6665).
std::size_t SipEngine::subscription_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(impl_->dialogs.begin(), impl_->dialogs.end(),
                                                [](const auto &entry) { return !entry.second->invite; }));
}

void SipEngine::set_body_filters(SipBodyFilter outgoing, SipBodyFilter incoming) {
  impl_->outgoing_filter = std::move(outgoing);
  impl_->incoming_filter = std::move(incoming);
}

//------------------------------------------------------------------------------
// RFC 3261 section 10.2: registers (or refreshes the registration of) the identity: with IMS AKA its own procedure
// (TS 24.229 clauses 5.1.1.2.2 and 5.1.1.4.2, ims_aka.cpp), otherwise with digest credentials through the SIP core.
void SipEngine::register_account(unsigned expires, SipResponseHandler handler) {
  impl_->ensure_started();
  if (expires == 0) throw std::invalid_argument("SIP registration expiry must be nonzero");
  if (impl_->aka) return impl_->aka_register(expires, {}, {}, std::move(handler));
  if (!sip_detail::has_credentials(impl_->config))
    throw std::invalid_argument("SIP REGISTER requires digest credentials");
  impl_->register_digest(expires, {}, {}, std::move(handler));
}

//------------------------------------------------------------------------------
// RFC 3261 section 10.2 and TS 24.379 clause 7.2.1: a REGISTER with a body (for example the service authorisation
// document) on the existing registration.
void SipEngine::register_account(unsigned expires, std::string_view content_type, std::string_view body,
                                 SipResponseHandler handler) {
  impl_->ensure_started();
  if (impl_->aka) return impl_->aka_register(expires, content_type, body, std::move(handler));
  if (!impl_->registration) throw std::logic_error("a REGISTER with a body follows the initial registration");
  impl_->register_digest(expires, content_type, body, std::move(handler));
}

//------------------------------------------------------------------------------
// RFC 3261 section 10.2.2: removes the registration of this engine's Contact (Expires 0; TS 24.229 clause 5.1.1.6.2
// with IMS AKA, protected by the set in use, whose 200 removes the SAs); no refresh follows.
void SipEngine::unregister_account(SipResponseHandler handler) {
  impl_->ensure_started();
  if (impl_->aka) return impl_->aka_register(0, {}, {}, std::move(handler));
  if (!impl_->registration) throw std::logic_error("no SIP registration to remove");
  impl_->register_digest(0, {}, {}, std::move(handler));
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.7: the S-CSCF ended the registration (reg event NOTIFY): "the UE shall delete all security
// associations or TLS sessions towards the P-CSCF". Digest: the registration goes with its refresh, and its TLS
// connection is closed once the transactions still on it (the NOTIFY's answer) had time to end; the next
// register_account opens a new one. IMS AKA: aka_registration_ended().
void SipEngine::registration_ended() {
  if (impl_->aka) return impl_->aka_registration_ended();
  if (!impl_->registration) return;
  const auto flow = impl_->registration->flow;
  impl_->registration.reset();
  impl_->cancel(Impl::Timer::registration_refresh);
  if (flow && impl_->config.tls.enabled) {
    impl_->end_registration(); // an earlier one first
    impl_->ending_flow = flow;
    impl_->schedule(Impl::Timer::flow_end, std::chrono::seconds(2));
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1: a request outside a dialog (Impl::send_request).
void SipEngine::request(std::string_view method, std::string_view request_uri, std::string_view content_type,
                        std::string_view body, const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  impl_->send_request(method, request_uri, content_type, body, headers, std::move(handler));
}

//------------------------------------------------------------------------------
// RFC 3903 section 4 and TS 24.379 clause 7.2: a PUBLISH outside a dialog.
void SipEngine::publish(std::string_view request_uri, std::string_view content_type, std::string_view body,
                        const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  request("PUBLISH", request_uri, content_type, body, headers, std::move(handler));
}

std::string SipEngine::subscribe(std::string_view request_uri, std::string_view event, unsigned expires,
                                 const std::vector<SipHeader> &headers, SipResponseHandler handler,
                                 std::string_view content_type, std::string_view body) {
  if (event.empty()) throw std::invalid_argument("SUBSCRIBE requires event");
  return impl_->create_subscribe(request_uri, event, expires, headers, std::move(handler), content_type, body);
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.2: a NOTIFY with Event and Subscription-State in a subscription dialog; "terminated" ends it
// once answered.
void SipEngine::notify(std::string_view dialog_id, std::string_view event, std::string_view subscription_state,
                       std::string_view content_type, std::string_view body, const std::vector<SipHeader> &headers,
                       SipResponseHandler handler) {
  if (event.empty() || subscription_state.empty())
    throw std::invalid_argument("NOTIFY requires Event and Subscription-State");
  auto notify_headers = headers;
  notify_headers.push_back({"Event", std::string(event)});
  notify_headers.push_back({"Subscription-State", std::string(subscription_state)});
  impl_->send_dialog_request(dialog_id, "NOTIFY", notify_headers, content_type, body, std::move(handler));
}


//------------------------------------------------------------------------------
// RFC 3515 section 2.4.1 with RFC 4488 section 4: a REFER outside a dialog with its parts (TS 24.379 clauses 6.2.4.2
// and 10.1.2.2.2.1); no implicit subscription is kept: the handler gets the final response.
void SipEngine::refer(std::string_view request_uri, const std::vector<BodyPart> &parts,
                      const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  if (get_header(headers, "Refer-To").empty()) throw std::invalid_argument("REFER without Refer-To: RFC 3515");
  if (parts.empty()) return request("REFER", request_uri, {}, {}, headers, std::move(handler));
  const auto [type, body] = message_body(parts, "mcx-refer");
  request("REFER", request_uri, type, body, headers, std::move(handler));
}

//------------------------------------------------------------------------------
// RFC 3261 section 12.2.1: INFO or MESSAGE in an INVITE dialog, or SUBSCRIBE in a subscription dialog.
void SipEngine::request_in_dialog(std::string_view dialog_id, std::string_view method, std::string_view type,
                                  std::string_view body, const std::vector<SipHeader> &headers,
                                  SipResponseHandler handler) {
  // SUBSCRIBE: the refresh or end of a subscription this engine created (RFC 6665 section 4.1.2).
  if (method != "INFO" && method != "MESSAGE" && method != "SUBSCRIBE")
    throw std::invalid_argument("unsupported application dialog method");
  impl_->send_dialog_request(dialog_id, method, headers, type, body, std::move(handler));
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.2: an INVITE with an SDP offer built from local media; returns its dialog id.
std::string SipEngine::invite(std::string_view request_uri, const MediaDescription &local_media,
                              const std::vector<BodyPart> &application_parts, SipResponseHandler handler,
                              const std::vector<SipHeader> &headers) {
  return impl_->create_invite(request_uri, local_media, application_parts, std::move(handler), headers, nullptr);
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.2: an INVITE with the given SDP offer text (the MCData media plane); returns its dialog id.
std::string SipEngine::invite_sdp(std::string_view request_uri, std::string_view sdp,
                                  const std::vector<BodyPart> &application_parts, SipResponseHandler handler,
                                  const std::vector<SipHeader> &headers) {
  if (sdp.empty()) throw std::invalid_argument("an INVITE offer needs an SDP body");
  const std::string text(sdp);
  return impl_->create_invite(request_uri, MediaDescription{}, application_parts, std::move(handler), headers, &text);
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.3.1 (as answer of the pjproject engine): a later answer to an incoming INVITE, with the SDP
// answer when it is still pending; dropped for an unknown, ending or answered dialog (a stale answer after
// cancellation is harmless).
void SipEngine::answer(std::string_view dialog_id, const SipResponse &response) {
  impl_->ensure_started();
  if (response.status_code < 100 || response.status_code > 699)
    throw std::invalid_argument("invalid INVITE answer status");
  const auto found = impl_->dialogs.find(std::string(dialog_id));
  if (found == impl_->dialogs.end() || found->second->terminating || found->second->final_answer ||
      !found->second->invite_request) {
    debug_line("SIP answer " + std::to_string(response.status_code) + " for dialog " + std::string(dialog_id) +
               " dropped");
    return;
  }
  auto &dialog = *found->second;
  if (dialog.uac) throw std::invalid_argument("only an incoming INVITE can be answered");
  if (!response.contact_uri.empty() || response.focus || !response.contact_tags.empty()) {
    auto contact = impl_->response_contact(response);
    if (dialog.sips) {
      const auto at = contact.starts_with('<') ? 1U : 0U;
      if (contact.compare(at, 4, "sip:") == 0) contact.insert(at + 3, "s");
    }
    dialog.response_contact = contact;
  }
  if (dialog.answer_sdp_pending && response.status_code >= 200 && response.status_code < 300) {
    if (!response.local_media && !response.local_sdp)
      throw std::invalid_argument("a 2xx INVITE answer needs local media");
    dialog.answer_sdp_pending = false;
  }
  impl_->answer_invite(dialog, response);
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.1: a re-INVITE with a new SDP offer built from local media in a confirmed dialog.
void SipEngine::reinvite(std::string_view dialog_id, const MediaDescription &media, const std::vector<BodyPart> &parts,
                         SipResponseHandler handler, const std::vector<SipHeader> &headers) {
  const auto found = impl_->dialogs.find(std::string(dialog_id));
  if (found == impl_->dialogs.end()) throw std::invalid_argument("re-INVITE requires active dialog");
  auto origin = found->second->sdp_origin;
  sip_detail::next_sdp_origin(origin, media);
  impl_->send_offer(dialog_id, "INVITE", make_sdp(media, origin.id, origin.version), parts, std::move(handler),
                    headers);
  found->second->sdp_origin = origin;
}

//------------------------------------------------------------------------------
// RFC 3311 section 5.1: an UPDATE with a new SDP offer in a confirmed dialog (TS 24.379 clauses 8.3.1.1 and 8.3.2.2).
void SipEngine::update(std::string_view dialog_id, const MediaDescription &media, SipResponseHandler handler,
                       const std::vector<SipHeader> &headers) {
  const auto found = impl_->dialogs.find(std::string(dialog_id));
  if (found == impl_->dialogs.end()) throw std::invalid_argument("UPDATE requires active dialog");
  auto origin = found->second->sdp_origin;
  sip_detail::next_sdp_origin(origin, media);
  impl_->send_offer(dialog_id, "UPDATE", make_sdp(media, origin.id, origin.version), {}, std::move(handler), headers);
  found->second->sdp_origin = origin;
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.1: a re-INVITE with the given SDP offer text in a confirmed dialog.
void SipEngine::reinvite_sdp(std::string_view dialog_id, std::string_view sdp, const std::vector<BodyPart> &parts,
                             SipResponseHandler handler, const std::vector<SipHeader> &headers) {
  impl_->ensure_started();
  if (sdp.empty()) throw std::invalid_argument("a re-INVITE offer needs an SDP body");
  const auto found = impl_->dialogs.find(std::string(dialog_id));
  if (found == impl_->dialogs.end()) throw std::invalid_argument("re-INVITE requires active dialog");
  const std::string text(sdp);
  auto origin = found->second->sdp_origin;
  sip_detail::record_sdp_text(origin, text);
  impl_->send_offer(dialog_id, "INVITE", text, parts, std::move(handler), headers);
  found->second->sdp_origin = origin;
}

//------------------------------------------------------------------------------
// RFC 3261 sections 15.1.1 and 9.1: ends an established call or cancels a pending one; BYE carries at most one body
// part. Repeated ends are harmless.
void SipEngine::bye(std::string_view dialog_id, SipResponseHandler handler, const std::vector<SipHeader> &headers,
                    const std::vector<BodyPart> &parts) {
  if (parts.size() > 1) throw std::invalid_argument("BYE carries at most one body part");
  impl_->end_dialog(dialog_id, std::move(handler), headers, parts);
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.6: the application's response to a deferred request.
void SipEngine::respond(std::string_view transaction_id, const SipResponse &response) {
  impl_->ensure_started();
  impl_->respond_deferred(std::string(transaction_id), response);
}

std::string SipEngine::contact_target() const { return sip_detail::contact_target(impl_->config); }

//------------------------------------------------------------------------------
// RFC 3261 section 12: the Call-ID and the local and remote tags of a dialog that has both.
std::optional<DialogIdentifiers> SipEngine::dialog_identifiers(std::string_view dialog_id) const {
  const auto found = impl_->dialogs.find(std::string(dialog_id));
  if (found == impl_->dialogs.end() || found->second->local_tag.empty() || found->second->remote_tag.empty())
    return std::nullopt;
  return DialogIdentifiers{found->second->call_id, found->second->local_tag, found->second->remote_tag};
}


} // namespace mcx
