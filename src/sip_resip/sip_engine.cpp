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
// RFC 3261 section 10.2: registration needs digest credentials (or IMS AKA); written in phase 3b.
void SipEngine::register_account(unsigned, SipResponseHandler) {
  impl_->ensure_started();
  if (!impl_->config.aka.enabled && !sip_detail::has_credentials(impl_->config))
    throw std::invalid_argument("SIP REGISTER requires digest credentials");
  later("registration", "3b");
}

void SipEngine::register_account(unsigned, std::string_view, std::string_view, SipResponseHandler) {
  later("registration", "3b");
}

void SipEngine::unregister_account(SipResponseHandler) { later("registration", "3b"); }

void SipEngine::registration_ended() { later("registration", "3b"); }

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

// No security agreement before phase 3b.
std::optional<SipSecurityStatus> SipEngine::security_status() const { return std::nullopt; }

void SipEngine::bye(std::string_view, SipResponseHandler, const std::vector<SipHeader> &,
                    const std::vector<BodyPart> &) {
  later("INVITE sessions", "3c");
}

} // namespace mcx
