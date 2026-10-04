// The public interface of the SIP engine (include/mcx/sip.hpp): registration, requests, subscriptions, INVITE sessions.
//
// Specifications: RFC 3261, RFC 3264, RFC 4028, RFC 6665, RFC 3903, TS 24.379 V19.7.0 (Rel-19), TS 24.229.

#include "sip_impl.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: creates the engine's implementation from its configuration and callbacks.
SipEngine::SipEngine(SipConfig config, SipCallbacks callbacks)
    : impl_(std::make_unique<Impl>(std::move(config), std::move(callbacks))) {}

//------------------------------------------------------------------------------
// Helper: the implementation's destructor stops the engine.
SipEngine::~SipEngine() noexcept = default;

//------------------------------------------------------------------------------
// Helper: starts the PJSIP endpoint and transports (SipEngine::Impl::start).
void SipEngine::start() { impl_->start(); }

//------------------------------------------------------------------------------
// Helper: stops the engine, releasing its registration, dialogs and pending responses (SipEngine::Impl::stop).
void SipEngine::stop() noexcept { impl_->stop(); }

//------------------------------------------------------------------------------
// Helper: whether the engine has been started.
bool SipEngine::running() const noexcept { return impl_->started; }

//------------------------------------------------------------------------------
// Helper: the number of tracked dialogs that are not INVITE sessions (the subscription dialogs of RFC 6665).
std::size_t SipEngine::subscription_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(impl_->dialogs.begin(), impl_->dialogs.end(),
                                                [](const auto &entry) { return entry.second->invite == nullptr; }));
}

//------------------------------------------------------------------------------
// Helper: handles PJSIP events for at most the timeout, then sends the queued responses and releases the ended
// subscriptions and BYE references.
void SipEngine::poll(std::chrono::milliseconds timeout) {
  impl_->ensure_started();
  if (timeout.count() < 0 || timeout.count() > std::numeric_limits<long>::max()) {
    throw std::invalid_argument("invalid SIP poll timeout");
  }
  pj_time_val duration{};
  duration.sec = static_cast<long>(timeout.count() / 1000);
  duration.msec = static_cast<long>(timeout.count() % 1000);
  const pj_status_t status = pjsip_endpt_handle_events(impl_->endpoint, &duration);
  impl_->send_pending_responses();
  impl_->release_pending_subscriptions();
  impl_->release_bye_references();
  if (status != PJ_SUCCESS && status != PJ_ETIMEDOUT && status != PJ_STATUS_FROM_OS(EINTR)) {
    require_success(status, "poll PJSIP endpoint");
  }
}

//------------------------------------------------------------------------------
// Helper: sets the filters applied to outgoing and incoming message bodies (for example signalling protection).
void SipEngine::set_body_filters(SipBodyFilter outgoing, SipBodyFilter incoming) {
  impl_->outgoing_filter = std::move(outgoing);
  impl_->incoming_filter = std::move(incoming);
}

//------------------------------------------------------------------------------
// RFC 3261 section 10.2 and TS 24.379 clause 7.2.1: sends a REGISTER with a body (for example the service
// authorisation document) on the existing registration.
void SipEngine::register_account(unsigned expires, std::string_view content_type, std::string_view body,
                                 SipResponseHandler handler) {
  if (impl_->registration == nullptr) {
    throw std::logic_error("a REGISTER with a body follows the initial registration");
  }
  require_success(pjsip_regc_update_expires(impl_->registration, expires), "update SIP registration expiry");
  impl_->registration_handler = std::move(handler);
  pjsip_tx_data *created = nullptr;
  require_success(pjsip_regc_register(impl_->registration, PJ_TRUE, &created), "create REGISTER request");
  TxData data(created);
  data->msg->body = make_text_body(data->pool, content_type, body);
  require_success(pjsip_regc_send(impl_->registration, data.release()), "send REGISTER request");
}

//------------------------------------------------------------------------------
// RFC 3261 section 10.2: registers (or refreshes the registration of) the configured identity with digest
// credentials; the Request-URI names the home domain and the REGISTER reaches it through the SIP core as the
// outbound proxy.
void SipEngine::register_account(unsigned expires, SipResponseHandler handler) {
  impl_->ensure_started();
  if (!has_credentials(impl_->config)) {
    throw std::invalid_argument("SIP REGISTER requires digest credentials");
  }
  if (expires == 0) {
    throw std::invalid_argument("SIP registration expiry must be nonzero");
  }
  if (impl_->registration == nullptr) {
    require_success(pjsip_regc_create(impl_->endpoint, impl_.get(), &Impl::registration_complete, &impl_->registration),
                    "create SIP registration client");
    // RFC 3261 section 10.2: the Request-URI names the home domain; the REGISTER
    // reaches it through the SIP core as the outbound proxy.
    const auto registrar = "sip:" + identity_domain(impl_->config.identity);
    auto server = pj_view(registrar);
    auto identity = pj_view(impl_->config.identity);
    // RFC 5626 section 4.2: an outbound client registers its instance and reg-id with the Contact.
    const auto &instance = impl_->config.outbound_instance;
    if (instance.find_first_of("\"<>\r\n") != std::string::npos)
      throw std::invalid_argument("invalid SIP outbound instance");
    const auto contact_text = (impl_->config.registration_features.empty()
                                   ? impl_->contact_uri()
                                   : "<" + impl_->contact_target() + ">" + impl_->config.registration_features) +
                              (instance.empty() ? "" : ";+sip.instance=\"<" + instance + ">\";reg-id=1");
    auto contact = pj_view(contact_text);
    require_success(pjsip_regc_init(impl_->registration, &server, &identity, &identity, 1, &contact, expires),
                    "initialize SIP registration");
    pjsip_cred_info credential{};
    credential.realm = pj_view("*");
    credential.scheme = pj_view("digest");
    credential.username = pj_view(impl_->config.username);
    credential.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
    credential.data = pj_view(impl_->config.password);
    require_success(pjsip_regc_set_credentials(impl_->registration, 1, &credential),
                    "set SIP registration credentials");
    auto *pool = pjsip_endpt_create_pool(impl_->endpoint, "register-route", 512, 512);
    if (pool == nullptr) throw std::bad_alloc();
    try {
      auto *route = create_header(pool, {"Route", impl_->core_route()});
      if (route->type != PJSIP_H_ROUTE) throw std::invalid_argument("invalid SIP core route");
      pjsip_route_hdr head;
      pj_list_init(&head);
      pj_list_push_back(&head, route);
      require_success(pjsip_regc_set_route_set(impl_->registration, &head), "set SIP registration route");
    } catch (...) {
      pjsip_endpt_release_pool(impl_->endpoint, pool);
      throw;
    }
    pjsip_endpt_release_pool(impl_->endpoint, pool);
  } else {
    require_success(pjsip_regc_update_expires(impl_->registration, expires), "update SIP registration expiry");
  }
  impl_->registration_handler = std::move(handler);
  pjsip_tx_data *data = nullptr;
  require_success(pjsip_regc_register(impl_->registration, PJ_TRUE, &data), "create REGISTER request");
  require_success(pjsip_regc_send(impl_->registration, data), "send REGISTER request");
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1: sends an out-of-dialog request (SipEngine::Impl::send_request).
void SipEngine::request(std::string_view method, std::string_view request_uri, std::string_view content_type,
                        std::string_view body, const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  impl_->send_request(method, request_uri, content_type, body, headers, std::move(handler));
}

//------------------------------------------------------------------------------
// RFC 3903 and TS 24.379 clause 7.2.1A: sends a PUBLISH out of dialog.
void SipEngine::publish(std::string_view request_uri, std::string_view content_type, std::string_view body,
                        const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  request("PUBLISH", request_uri, content_type, body, headers, std::move(handler));
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2: creates a subscription with the initial SUBSCRIBE; returns its dialog id.
std::string SipEngine::subscribe(std::string_view request_uri, std::string_view event, unsigned expires,
                                 const std::vector<SipHeader> &headers, SipResponseHandler handler,
                                 std::string_view content_type, std::string_view body) {
  if (event.empty()) {
    throw std::invalid_argument("SUBSCRIBE requires event");
  }
  return impl_->create_subscribe(request_uri, event, expires, headers, std::move(handler), content_type, body);
}

//------------------------------------------------------------------------------
// RFC 3261 section 12.2.1: sends an INFO, MESSAGE or SUBSCRIBE within an existing dialog; SUBSCRIBE refreshes or
// ends a subscription this engine created (RFC 6665 section 4.1.2).
void SipEngine::request_in_dialog(std::string_view dialog_id, std::string_view method, std::string_view type,
                                  std::string_view body, const std::vector<SipHeader> &headers,
                                  SipResponseHandler handler) {
  // SUBSCRIBE: refresh or de-subscription of a subscription this engine created.
  if (method != "INFO" && method != "MESSAGE" && method != "SUBSCRIBE")
    throw std::invalid_argument("unsupported application dialog method");
  pjsip_method native{};
  auto name = pj_view(method);
  pjsip_method_init_np(&native, &name);
  impl_->send_dialog_request(dialog_id, native, headers, type, body, std::move(handler));
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.2: sends a NOTIFY with Event and Subscription-State in a subscription dialog.
void SipEngine::notify(std::string_view dialog_id, std::string_view event, std::string_view subscription_state,
                       std::string_view content_type, std::string_view body, const std::vector<SipHeader> &headers,
                       SipResponseHandler handler) {
  if (event.empty() || subscription_state.empty()) {
    throw std::invalid_argument("NOTIFY requires Event and Subscription-State");
  }
  auto notify_headers = headers;
  notify_headers.push_back({"Event", std::string(event)});
  notify_headers.push_back({"Subscription-State", std::string(subscription_state)});
  impl_->send_dialog_request(dialog_id, pjsip_notify_method, notify_headers, content_type, body, std::move(handler));
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.2: sends an INVITE with an SDP offer built from local media; returns its dialog id.
std::string SipEngine::invite(std::string_view request_uri, const MediaDescription &local_media,
                              const std::vector<BodyPart> &application_parts, SipResponseHandler handler,
                              const std::vector<SipHeader> &headers) {
  return impl_->create_invite(request_uri, local_media, application_parts, std::move(handler), headers);
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.2: sends an INVITE with the given SDP offer text; returns its dialog id.
std::string SipEngine::invite_sdp(std::string_view request_uri, std::string_view sdp,
                                  const std::vector<BodyPart> &application_parts, SipResponseHandler handler,
                                  const std::vector<SipHeader> &headers) {
  if (sdp.empty()) throw std::invalid_argument("an INVITE offer needs an SDP body");
  const std::string text(sdp);
  return impl_->create_invite(request_uri, MediaDescription{}, application_parts, std::move(handler), headers, &text);
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.3.1: sends a later (provisional or final) answer to an incoming INVITE, with the SDP answer
// (RFC 3264 section 6) when it is still pending and the answer is 2xx.
void SipEngine::answer(std::string_view dialog_id, const SipResponse &response) {
  impl_->ensure_started();
  if (response.status_code < 100 || response.status_code > 699)
    throw std::invalid_argument("invalid INVITE answer status");
  const auto found = impl_->dialogs.find(std::string(dialog_id));
  if (found == impl_->dialogs.end() || !found->second->invite || found->second->terminating ||
      found->second->final_answer)
    return;
  auto &entry = *found->second;
  auto *invite = entry.invite;
  if (invite->role != PJSIP_ROLE_UAS) throw std::invalid_argument("only an incoming INVITE can be answered");
  if (!response.contact_uri.empty() || response.focus) entry.response_contact = impl_->response_contact(response);
  const pjmedia_sdp_session *sdp = nullptr;
  if (entry.answer_sdp_pending && response.status_code >= 200 && response.status_code < 300) {
    if (!response.local_media && !response.local_sdp)
      throw std::invalid_argument("a 2xx INVITE answer needs local media");
    sdp = response.local_sdp ? parse_sdp_text(entry.dialog->pool, *response.local_sdp)
                             : parse_local_sdp(entry.dialog->pool, *response.local_media);
    entry.answer_sdp_pending = false;
  }
  pjsip_tx_data *created = nullptr;
  auto reason = pj_view(response.reason);
  require_success(
      pjsip_inv_answer(invite, response.status_code, response.reason.empty() ? nullptr : &reason, sdp, &created),
      "create deferred INVITE answer");
  TxData data(created);
  if (response.status_code >= 200 && response.status_code < 300 && response.local_sdp)
    data->msg->body = make_body_with_sdp(data->pool, *response.local_sdp, impl_->answer_parts(response, entry.dialog));
  else if (response.status_code >= 200 && response.status_code < 300 && response.local_media)
    data->msg->body = make_invite_body(data->pool, *response.local_media, impl_->answer_parts(response, entry.dialog));
  else if (response.status_code >= 300 && !response.content_type.empty())
    data->msg->body = make_text_body(data->pool, response.content_type, response.body);
  else if (response.status_code >= 300 && !response.parts.empty())
    data->msg->body = make_text_body(data->pool, "multipart/mixed; boundary=mcx-answer",
                                     multipart_body(response.parts, "mcx-answer"));
  if (response.status_code > 100 && response.status_code < 300)
    add_headers(data.get(), {{"Contact", entry.response_contact}});
  add_headers(data.get(), response.headers);
  entry.final_answer = response.status_code >= 200;
  if (response.status_code >= 200 && response.status_code < 300) {
    const auto *cseq = static_cast<const pjsip_cseq_hdr *>(pjsip_msg_find_hdr(data->msg, PJSIP_H_CSEQ, nullptr));
    if (cseq != nullptr) entry.pending_ack_cseq = cseq->cseq;
  }
  require_success(pjsip_inv_send_msg(invite, data.release()), "send deferred INVITE answer");
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.6: sends the application's response to a deferred request.
void SipEngine::respond(std::string_view transaction_id, const SipResponse &response) {
  impl_->ensure_started();
  impl_->respond_deferred(std::string(transaction_id), response);
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.1: sends a re-INVITE in a confirmed dialog with no re-INVITE pending: the offer and the body
// come from the builders, in the session's pool and in the request's.
void SipEngine::Impl::send_reinvite(std::string_view dialog_id,
                                    const std::function<pjmedia_sdp_session *(pj_pool_t *)> &offer,
                                    const std::function<pjsip_msg_body *(pj_pool_t *)> &body,
                                    SipResponseHandler handler, const std::vector<SipHeader> &headers) {
  ensure_started();
  const auto found = dialogs.find(std::string(dialog_id));
  if (found == dialogs.end() || !found->second->invite || found->second->terminating)
    throw std::invalid_argument("re-INVITE requires active dialog");
  auto &entry = *found->second;
  if (entry.invite->state != PJSIP_INV_STATE_CONFIRMED || entry.reinvite_handler)
    throw std::runtime_error("re-INVITE already pending or dialog not confirmed");
  auto *sdp = offer(entry.invite->pool_prov);
  pjsip_tx_data *created = nullptr;
  require_success(pjsip_inv_reinvite(entry.invite, nullptr, sdp, &created), "create re-INVITE");
  TxData data(created);
  data->msg->body = body(data->pool);
  add_headers(data.get(), headers);
  const auto *cseq = static_cast<const pjsip_cseq_hdr *>(pjsip_msg_find_hdr(data->msg, PJSIP_H_CSEQ, nullptr));
  if (cseq == nullptr) throw std::runtime_error("re-INVITE without CSeq");
  entry.reinvite_cseq = cseq->cseq;
  entry.reinvite_handler = handler ? std::move(handler) : [](const SipResponse &) {};
  const auto result = pjsip_inv_send_msg(entry.invite, data.release());
  if (result != PJ_SUCCESS) entry.reinvite_handler = {};
  require_success(result, "send re-INVITE");
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.1: sends a re-INVITE with a new SDP offer built from local media in a confirmed dialog.
void SipEngine::reinvite(std::string_view dialog_id, const MediaDescription &media, const std::vector<BodyPart> &parts,
                         SipResponseHandler handler, const std::vector<SipHeader> &headers) {
  impl_->send_reinvite(
      dialog_id, [&](pj_pool_t *pool) { return parse_local_sdp(pool, media); },
      [&](pj_pool_t *pool) { return make_invite_body(pool, media, parts); }, std::move(handler), headers);
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.1: sends a re-INVITE with the given SDP offer text in a confirmed dialog.
void SipEngine::reinvite_sdp(std::string_view dialog_id, std::string_view sdp, const std::vector<BodyPart> &parts,
                             SipResponseHandler handler, const std::vector<SipHeader> &headers) {
  impl_->ensure_started();
  if (sdp.empty()) throw std::invalid_argument("a re-INVITE offer needs an SDP body");
  const std::string text(sdp);
  impl_->send_reinvite(
      dialog_id, [&](pj_pool_t *pool) { return parse_sdp_text(pool, text); },
      [&](pj_pool_t *pool) { return make_body_with_sdp(pool, text, parts); }, std::move(handler), headers);
}

//------------------------------------------------------------------------------
// Helper: the routable Contact URI of this engine, with its transport (SipEngine::Impl::contact_target).
std::string SipEngine::contact_target() const { return impl_->contact_target(); }

//------------------------------------------------------------------------------
// RFC 3261 section 15.1.1: ends an INVITE session with BYE, or before it is connected with CANCEL (section 9.1)
// or a 487 response; BYE carries at most one body part.
void SipEngine::bye(std::string_view dialog_id, SipResponseHandler handler, const std::vector<SipHeader> &headers,
                    const std::vector<BodyPart> &parts) {
  if (parts.size() > 1) throw std::invalid_argument("BYE carries at most one body part");
  impl_->ensure_started();
  const auto found = impl_->dialogs.find(std::string(dialog_id));
  if (found == impl_->dialogs.end() || !found->second->invite || found->second->terminating) return;
  // Called while PJSIP reports the session's end (e.g. from a request handler
  // observing a received BYE): there is nothing left to end.
  if (found->second->invite->state == PJSIP_INV_STATE_DISCONNECTED) return;
  found->second->terminating = true;
  found->second->bye_parts = parts;
  if (handler) found->second->initial_handler = std::move(handler);
  auto *invite = found->second->invite;
  require_success(pjsip_inv_add_ref(invite), "retain ending INVITE session");
  try {
    pjsip_tx_data *created = nullptr;
    const int cause = invite->state < PJSIP_INV_STATE_CONNECTING ? 487 : 200;
    require_success(pjsip_inv_end_session(invite, cause, nullptr, &created), "end or cancel INVITE session");
    if (created != nullptr) {
      TxData data(created);
      const bool bye = data->msg->line.req.method.id == PJSIP_BYE_METHOD;
      add_headers(data.get(), headers);
      if (cause == 200 && !parts.empty())
        data->msg->body = make_text_body(data->pool, parts.front().content_type, parts.front().body);
      require_success(pjsip_inv_send_msg(invite, data.release()), "send call termination");
      if (bye && impl_->bye_references.insert(invite).second) return;
    }
  } catch (...) {
    (void)pjsip_inv_dec_ref(invite);
    throw;
  }
  (void)pjsip_inv_dec_ref(invite);
}

} // namespace mcx
