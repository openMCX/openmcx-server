//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// mcx::SipEngine (include/mcx/sip.hpp) on reSIProcate: the public operations over SipEngine::Impl (resip_impl.hpp).
// The operations of later phases of prototype/resiprocate/PLAN.md throw std::logic_error naming their phase.
//
// Specifications: RFC 3261, RFC 3903, TS 24.379 V19.7.0 (Rel-19) clause 7.2.

#include "resip_impl.hpp"

#include <stdexcept>

namespace mcx {
namespace {
//------------------------------------------------------------------------------
// Helper: the refusal of an operation that a later phase of the migration writes.
[[noreturn]] void later(std::string_view what, std::string_view phase) {
  throw std::logic_error(std::string(what) + " on reSIProcate: prototype/resiprocate/PLAN.md phase " +
                         std::string(phase));
}
} // namespace

SipEngine::SipEngine(SipConfig config, SipCallbacks callbacks)
    : impl_(std::make_unique<Impl>(std::move(config), std::move(callbacks))) {}

SipEngine::~SipEngine() noexcept = default;

void SipEngine::start() { impl_->start(); }

void SipEngine::stop() noexcept { impl_->stop(); }

bool SipEngine::running() const noexcept { return impl_->started; }

void SipEngine::poll(std::chrono::milliseconds timeout) { impl_->poll(timeout); }

// No subscription dialogs before phase 3d.
std::size_t SipEngine::subscription_count() const noexcept { return 0; }

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

void SipEngine::refer(std::string_view, const std::vector<BodyPart> &, const std::vector<SipHeader> &,
                      SipResponseHandler) {
  later("REFER", "3d");
}

//------------------------------------------------------------------------------
// RFC 3903 section 4 and TS 24.379 clause 7.2: a PUBLISH outside a dialog.
void SipEngine::publish(std::string_view request_uri, std::string_view content_type, std::string_view body,
                        const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  request("PUBLISH", request_uri, content_type, body, headers, std::move(handler));
}

void SipEngine::request_in_dialog(std::string_view, std::string_view, std::string_view, std::string_view,
                                  const std::vector<SipHeader> &, SipResponseHandler) {
  later("requests in a dialog", "3c");
}

std::string SipEngine::subscribe(std::string_view, std::string_view, unsigned, const std::vector<SipHeader> &,
                                 SipResponseHandler, std::string_view, std::string_view) {
  later("subscriptions", "3d");
}

void SipEngine::notify(std::string_view, std::string_view, std::string_view, std::string_view, std::string_view,
                       const std::vector<SipHeader> &, SipResponseHandler) {
  later("subscriptions", "3d");
}

std::string SipEngine::invite(std::string_view, const MediaDescription &, const std::vector<BodyPart> &,
                              SipResponseHandler, const std::vector<SipHeader> &) {
  later("INVITE sessions", "3c");
}

std::string SipEngine::invite_sdp(std::string_view, std::string_view, const std::vector<BodyPart> &,
                                  SipResponseHandler, const std::vector<SipHeader> &) {
  later("INVITE sessions", "3c");
}

void SipEngine::answer(std::string_view, const SipResponse &) { later("INVITE sessions", "3c"); }

void SipEngine::reinvite(std::string_view, const MediaDescription &, const std::vector<BodyPart> &,
                         SipResponseHandler, const std::vector<SipHeader> &) {
  later("INVITE sessions", "3c");
}

void SipEngine::update(std::string_view, const MediaDescription &, SipResponseHandler,
                       const std::vector<SipHeader> &) {
  later("INVITE sessions", "3c");
}

void SipEngine::reinvite_sdp(std::string_view, std::string_view, const std::vector<BodyPart> &, SipResponseHandler,
                             const std::vector<SipHeader> &) {
  later("INVITE sessions", "3c");
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.6: the application's response to a deferred request.
void SipEngine::respond(std::string_view transaction_id, const SipResponse &response) {
  impl_->ensure_started();
  impl_->respond_deferred(std::string(transaction_id), response);
}

std::string SipEngine::contact_target() const { return sip_detail::contact_target(impl_->config); }

// No dialogs before phase 3c.
std::optional<DialogIdentifiers> SipEngine::dialog_identifiers(std::string_view) const { return std::nullopt; }


void SipEngine::bye(std::string_view, SipResponseHandler, const std::vector<SipHeader> &,
                    const std::vector<BodyPart> &) {
  later("INVITE sessions", "3c");
}

} // namespace mcx
