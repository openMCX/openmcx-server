// SIP responses of SipEngine::Impl: immediate and deferred responses, subscriptions, INVITE and re-INVITE answers.
//
// Specifications: RFC 3261, RFC 3264, RFC 4028, RFC 6665, RFC 2046.

#include "sip_impl.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.6 (out of dialog) and section 12.1.1 (in dialog): sends a response to a received request;
// an in-dialog response whose server transaction is not yet created is queued for send_pending_responses().
void SipEngine::Impl::send_response(pjsip_rx_data *data, const SipResponse &response, pjsip_dialog *dialog) {
  pj_str_t reason = pj_view(response.reason);
  auto *body = make_text_body(data->tp_info.pool, response.content_type, response.body);
  pjsip_hdr header_list;
  pj_list_init(&header_list);
  for (const auto &header : response.headers) {
    pj_list_push_back(&header_list, create_header(data->tp_info.pool, header));
  }
  const pjsip_hdr *headers = response.headers.empty() ? nullptr : &header_list;
  if (dialog != nullptr) {
    auto *transaction = pjsip_rdata_get_tsx(data);
    if (transaction != nullptr && transaction->state == PJSIP_TSX_STATE_NULL) {
      pjsip_tx_data *response_data = nullptr;
      require_success(pjsip_dlg_create_response(dialog, data, response.status_code,
                                                response.reason.empty() ? nullptr : &reason, &response_data),
                      "create deferred in-dialog SIP response");
      for (const auto &header : response.headers) {
        pjsip_msg_add_hdr(response_data->msg, static_cast<pjsip_hdr *>(pjsip_hdr_clone(
                                                  response_data->pool, create_header(response_data->pool, header))));
      }
      if (body != nullptr) {
        response_data->msg->body = pjsip_msg_body_clone(response_data->pool, body);
        if (response_data->msg->body == nullptr) {
          pjsip_tx_data_dec_ref(response_data);
          throw std::runtime_error("clone deferred in-dialog SIP response body");
        }
      }
      pending_responses.push_back({dialog, transaction, response_data});
      return;
    }
    require_success(pjsip_dlg_respond(dialog, data, response.status_code, response.reason.empty() ? nullptr : &reason,
                                      headers, body),
                    "send in-dialog SIP response");
  } else {
    require_success(pjsip_endpt_respond(endpoint, &module, data, response.status_code,
                                        response.reason.empty() ? nullptr : &reason, headers, body, nullptr),
                    "send SIP response");
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.2 and RFC 3264 section 6: sends the final re-INVITE answer, with the SDP answer on success
// (488 without local media); at once while the request is being received (data), or later after a deferred
// 100 Trying (data is null).
void SipEngine::Impl::answer_reinvite(pjsip_inv_session *invite, pjsip_rx_data *data, const std::string &dialog_id,
                                      int cseq, SipResponse response) {
  if (response.status_code < 200) response.status_code = 500;
  if (response.status_code < 300 && !response.local_media && !response.local_sdp) response.status_code = 488;
  const auto *sdp = (response.local_media || response.local_sdp) && response.status_code < 300
                        ? (response.local_sdp ? parse_sdp_text(invite->pool_prov, *response.local_sdp)
                                              : parse_local_sdp(invite->pool_prov, *response.local_media))
                        : nullptr;
  pjsip_tx_data *created = nullptr;
  pj_str_t reason = pj_view(response.reason);
  if (data != nullptr)
    require_success(pjsip_inv_initial_answer(invite, data, response.status_code, nullptr, sdp, &created),
                    "answer re-INVITE");
  else
    require_success(
        pjsip_inv_answer(invite, response.status_code, response.reason.empty() ? nullptr : &reason, sdp, &created),
        "answer deferred re-INVITE");
  // Released when building the body or the headers throws; handed to pjsip_inv_send_msg otherwise.
  TxData answer(created);
  if (response.status_code < 300)
    answer->msg->body = response.local_sdp ? make_body_with_sdp(answer->pool, *response.local_sdp, response.parts)
                                           : make_invite_body(answer->pool, *response.local_media, response.parts);
  else if (!response.content_type.empty())
    answer->msg->body = make_text_body(answer->pool, response.content_type, response.body);
  else if (!response.parts.empty()) {
    const auto boundary = "mcx-reinvite-error";
    answer->msg->body = make_text_body(answer->pool, "multipart/mixed; boundary=mcx-reinvite-error",
                                       multipart_body(response.parts, boundary));
  }
  add_headers(answer.get(), response.headers);
  if (response.status_code >= 200 && response.status_code < 300 && !config.reinvite_success_headers.empty()) {
    // pjsip adds the endpoint's Supported header field ("100rel, timer") to an answer that has none; the option tags
    // must join it rather than replace it.
    if (pjsip_msg_find_hdr(answer->msg, PJSIP_H_SUPPORTED, nullptr) == nullptr) {
      const auto *capability = pjsip_endpt_get_capability(endpoint, PJSIP_H_SUPPORTED, nullptr);
      if (capability != nullptr)
        pjsip_msg_add_hdr(answer->msg, static_cast<pjsip_hdr *>(pjsip_hdr_clone(answer->pool, capability)));
    }
    add_answer_headers(answer.get(), config.reinvite_success_headers);
  }
  if (response.status_code < 300) {
    auto found = dialogs.find(dialog_id);
    if (found != dialogs.end()) found->second->pending_ack_cseq = cseq;
  }
  require_success(pjsip_inv_send_msg(invite, answer.release()), "send re-INVITE answer");
}

//------------------------------------------------------------------------------
// RFC 3261 section 17.2.2: keeps the server transaction of a non-INVITE request alive with a prepared 200
// response, so that the application can respond later (respond_deferred).
void SipEngine::Impl::defer_response(pjsip_rx_data *data, const SipMessage &request) {
  if (ascii_equal(request.method, "INVITE") || ascii_equal(request.method, "SUBSCRIBE") ||
      ascii_equal(request.method, "ACK"))
    throw std::invalid_argument("an INVITE or in-dialog SUBSCRIBE cannot be deferred");
  DeferredResponse deferred;
  deferred.dialog = pjsip_rdata_get_dlg(data);
  deferred.transaction = pjsip_rdata_get_tsx(data);
  if (deferred.dialog != nullptr) {
    // The dialog layer created the server transaction.
    if (deferred.transaction == nullptr) throw std::runtime_error("in-dialog request lacks a transaction");
    deferred.dialog_id = request.dialog_id;
    require_success(pjsip_dlg_create_response(deferred.dialog, data, 200, nullptr, &deferred.data),
                    "prepare deferred in-dialog response");
  } else {
    require_success(pjsip_tsx_create_uas2(&module, data, nullptr, &deferred.transaction),
                    "create deferred server transaction");
    pjsip_tsx_recv_msg(deferred.transaction, data);
    const auto prepared = pjsip_endpt_create_response(endpoint, data, 200, nullptr, &deferred.data);
    if (prepared != PJ_SUCCESS) {
      // The transaction this function created would wait unanswered: end it.
      (void)pjsip_tsx_terminate(deferred.transaction, PJSIP_SC_INTERNAL_SERVER_ERROR);
      require_success(prepared, "prepare deferred response");
    }
  }
  // Keep the transaction alive until the application responds.
  pj_grp_lock_add_ref(deferred.transaction->grp_lock);
  try {
    deferred_responses[request.transaction_id] = deferred;
  } catch (...) {
    (void)pjsip_tx_data_dec_ref(deferred.data);
    if (deferred.dialog == nullptr) (void)pjsip_tsx_terminate(deferred.transaction, PJSIP_SC_INTERNAL_SERVER_ERROR);
    (void)pj_grp_lock_dec_ref(deferred.transaction->grp_lock);
    throw;
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.6: sends the application's response to a deferred request: a SUBSCRIBE (accepted or
// refused), a re-INVITE, or a non-INVITE request whose transaction was kept by defer_response().
void SipEngine::Impl::respond_deferred(const std::string &id, const SipResponse &response) {
  auto node = deferred_responses.extract(id);
  if (node.empty()) return;
  auto &deferred = node.mapped();
  if (deferred.subscribe != nullptr) {
    struct Release {
      pjsip_rx_data *data;

      ~Release() { pjsip_rx_data_free_cloned(data); }
    } release{deferred.subscribe};

    if (response.status_code >= 200 && response.status_code < 300)
      accept_subscription(deferred.subscribe, deferred.request, response);
    else
      send_response(deferred.subscribe, response, nullptr);
    return;
  }
  if (deferred.reinvite) {
    const auto found = dialogs.find(deferred.dialog_id);
    if (found == dialogs.end() || found->second->invite == nullptr) return;
    answer_reinvite(found->second->invite, nullptr, deferred.dialog_id, deferred.cseq, response);
    return;
  }
  auto *data = deferred.data;

  struct Release {
    pj_grp_lock_t *lock;

    ~Release() { pj_grp_lock_dec_ref(lock); }
  } release{deferred.transaction->grp_lock};

  if (deferred.transaction->state >= PJSIP_TSX_STATE_COMPLETED) {
    pjsip_tx_data_dec_ref(data);
    return;
  }
  if (deferred.dialog != nullptr) {
    const auto found = dialogs.find(deferred.dialog_id);
    if (found == dialogs.end() || found->second->dialog != deferred.dialog) {
      pjsip_tx_data_dec_ref(data);
      return;
    }
  }
  if (response.status_code < 200 || response.status_code > 699) {
    pjsip_tx_data_dec_ref(data);
    throw std::invalid_argument("invalid deferred response status");
  }
  data->msg->line.status.code = response.status_code;
  const pj_str_t reason =
      response.reason.empty() ? *pjsip_get_status_text(response.status_code) : pj_view(response.reason);
  pj_strdup(data->pool, &data->msg->line.status.reason, &reason);
  try {
    add_headers(data, response.headers);
    if (!response.content_type.empty())
      data->msg->body = make_text_body(data->pool, response.content_type, response.body);
    else if (!response.parts.empty()) {
      const auto boundary = "mcx-deferred";
      data->msg->body = make_text_body(data->pool, "multipart/mixed; boundary=mcx-deferred",
                                       multipart_body(response.parts, boundary));
    }
  } catch (...) {
    pjsip_tx_data_dec_ref(data);
    throw;
  }
  if (deferred.dialog != nullptr)
    require_success(pjsip_dlg_send_response(deferred.dialog, deferred.transaction, data),
                    "send deferred in-dialog response");
  else
    require_success(pjsip_tsx_send_msg(deferred.transaction, data), "send deferred response");
}

//------------------------------------------------------------------------------
// Helper: reports queued ACKs to the application and sends the queued in-dialog responses (send_response).
void SipEngine::Impl::send_pending_responses() {
  auto acknowledgements = std::move(pending_acks);
  pending_acks.clear();
  if (callbacks.on_ack)
    for (const auto &id : acknowledgements) callbacks.on_ack(id);
  auto responses = std::move(pending_responses);
  pending_responses.clear();
  pj_status_t first_error = PJ_SUCCESS;
  for (const auto &response : responses) {
    const pj_status_t status = pjsip_dlg_send_response(response.dialog, response.transaction, response.data);
    if (status != PJ_SUCCESS && first_error == PJ_SUCCESS) {
      first_error = status;
    }
  }
  require_success(first_error, "send deferred in-dialog SIP response");
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.1: accepts a SUBSCRIBE, creating the notifier's dialog for an initial SUBSCRIBE, and sends
// the application's 2xx response.
void SipEngine::Impl::accept_subscription(pjsip_rx_data *data, const SipMessage &request, const SipResponse &response) {
  if (auto *matched_dialog = pjsip_rdata_get_dlg(data); matched_dialog != nullptr) {
    const auto existing = dialogs.find(request.dialog_id);
    if (existing == dialogs.end() || existing->second->dialog != matched_dialog) {
      throw std::invalid_argument("SUBSCRIBE dialog is not tracked");
    }
    send_response(data, response, matched_dialog);
    return;
  }
  if (dialogs.contains(request.dialog_id)) {
    throw std::invalid_argument("SIP Call-ID collision");
  }
  const auto contact_text = contact_uri();
  auto contact = pj_view(contact_text);
  pjsip_dialog *sip_dialog = nullptr;
  require_success(pjsip_dlg_create_uas_and_inc_lock(pjsip_ua_instance(), data, &contact, &sip_dialog),
                  "create inbound SUBSCRIBE dialog");
  bool session = false;
  try {
    auto entry = std::make_unique<Dialog>();
    entry->id = request.dialog_id;
    entry->dialog = sip_dialog;
    require_success(pjsip_dlg_add_usage(sip_dialog, &module, entry.get()), "attach SUBSCRIBE dialog usage");
    require_success(pjsip_dlg_inc_session(sip_dialog, &module), "retain SUBSCRIBE dialog");
    session = true;
    dialogs[request.dialog_id] = std::move(entry);
    send_response(data, response, sip_dialog);
  } catch (...) {
    // The SUBSCRIBE is answered 500 in the dialog it created (its transaction is the dialog's), which then goes
    // with its transaction; the lock is released either way.
    (void)pjsip_dlg_respond(sip_dialog, data, PJSIP_SC_INTERNAL_SERVER_ERROR, nullptr, nullptr, nullptr);
    if (session) abandon_dialog(sip_dialog, request.dialog_id, true);
    (void)pjsip_dlg_set_mod_data(sip_dialog, module.id, nullptr);
    pjsip_dlg_dec_lock(sip_dialog);
    throw;
  }
  pjsip_dlg_dec_lock(sip_dialog);
}

//------------------------------------------------------------------------------
// RFC 4028 section 9: SipConfig::uas_refresher: an offered Session-Expires without a refresher is read as
// refresher=uas, which the session timer then answers and follows.
void SipEngine::Impl::take_session_refresh(pjsip_rx_data *data) {
  static const pj_str_t long_name = pj_str(const_cast<char *>("Session-Expires"));
  static const pj_str_t short_name = pj_str(const_cast<char *>("x"));
  auto *offered = static_cast<pjsip_sess_expires_hdr *>(
      pjsip_msg_find_hdr_by_names(data->msg_info.msg, &long_name, &short_name, nullptr));
  if (offered == nullptr || offered->refresher.slen > 0) return;
  pj_strdup2(data->tp_info.pool, &offered->refresher, "uas");
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.3.1 and RFC 3264 section 6: creates the UAS dialog and INVITE session with the session timer
// (RFC 4028 section 9) and sends the answer; returns the failure status when the offer is rejected.
[[nodiscard]] std::optional<int> SipEngine::Impl::accept_invite(pjsip_rx_data *data, const SipMessage &request,
                                                                const SipResponse &response) {
  if (dialogs.contains(request.dialog_id)) {
    throw std::invalid_argument("SIP Call-ID collision");
  }
  auto contact_text = response_contact(response);
  auto contact = pj_view(contact_text);
  pjsip_dialog *sip_dialog = nullptr;
  require_success(pjsip_dlg_create_uas_and_inc_lock(pjsip_ua_instance(), data, &contact, &sip_dialog),
                  "create inbound INVITE dialog");
  pjsip_inv_session *invite = nullptr;
  try {
    if (!response.peer_route.empty()) pin_dialog_route(sip_dialog, response.peer_route);
    // An incoming dialog still originates BYE/UPDATE through the core;
    // these requests must answer the same proxy digest challenges.
    if (has_credentials(config)) {
      pjsip_cred_info credential{};
      credential.realm = pj_view("*");
      credential.scheme = pj_view("digest");
      credential.username = pj_view(config.username);
      credential.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
      credential.data = pj_view(config.password);
      require_success(pjsip_auth_clt_set_credentials(&sip_dialog->auth_sess, 1, &credential),
                      "set incoming INVITE dialog credentials");
    }
    if (!response.local_media && !response.local_sdp && response.status_code >= 200)
      throw std::invalid_argument("a final INVITE answer needs local media");
    auto *local_sdp = response.local_sdp     ? parse_sdp_text(sip_dialog->pool, *response.local_sdp)
                      : response.local_media ? parse_local_sdp(sip_dialog->pool, *response.local_media)
                                             : nullptr;
    if (config.uas_refresher) take_session_refresh(data);
    unsigned options = PJSIP_INV_SUPPORT_TIMER;
    pjsip_tx_data *verification_response = nullptr;
    const pj_status_t verification =
        pjsip_inv_verify_request(data, &options, local_sdp, sip_dialog, endpoint, &verification_response);
    if (verification != PJ_SUCCESS) {
      int failure_code = 488;
      if (verification_response != nullptr) {
        failure_code = verification_response->msg->line.status.code;
        require_success(pjsip_endpt_send_response2(endpoint, data, verification_response, nullptr, nullptr),
                        "send media-rejected INVITE response");
      }
      pjsip_dlg_dec_lock(sip_dialog);
      return failure_code;
    }
    require_success(pjsip_inv_create_uas(sip_dialog, data, local_sdp, options, &invite),
                    "create inbound INVITE session");
    require_success(pjsip_dlg_add_usage(sip_dialog, &ack_module, nullptr), "observe dialog ACK");
    require_success(pjsip_dlg_add_usage(sip_dialog, &module, nullptr), "handle incoming call application requests");
    pjsip_timer_setting timer{};
    pjsip_timer_setting_default(&timer);
    timer.sess_expires = config.session_expires;
    require_success(pjsip_timer_init_session(invite, &timer), "configure inbound session timer");
    auto entry = std::make_unique<Dialog>();
    entry->id = request.dialog_id;
    entry->dialog = sip_dialog;
    entry->invite = invite;
    entry->final_answer = response.status_code >= 200;
    entry->answer_sdp_pending = local_sdp == nullptr;
    entry->response_contact = contact_text;
    if (response.status_code >= 200 && response.status_code < 300) entry->pending_ack_cseq = data->msg_info.cseq->cseq;
    invite->mod_data[module.id] = entry.get();
    dialogs[entry->id] = std::move(entry);
    pjsip_tx_data *created = nullptr;
    pj_str_t reason = pj_view(response.reason);
    require_success(pjsip_inv_initial_answer(invite, data, response.status_code,
                                             response.reason.empty() ? nullptr : &reason, nullptr, &created),
                    "create INVITE answer");
    TxData answer(created);
    if (response.status_code >= 200) {
      const auto parts = answer_parts(response, sip_dialog);
      answer->msg->body = response.local_sdp ? make_body_with_sdp(answer->pool, *response.local_sdp, parts)
                                             : make_invite_body(answer->pool, *response.local_media, parts);
    }
    add_headers(answer.get(), response.headers);
    if (response.status_code > 100 && response.status_code < 200)
      add_answer_headers(answer.get(), config.invite_provisional_headers);
    else if (response.status_code >= 200 && response.status_code < 300)
      add_answer_headers(answer.get(), config.invite_success_headers);
    require_success(pjsip_inv_send_msg(invite, answer.release()), "send INVITE answer");
  } catch (...) {
    // No stale entry and no session left: the INVITE is answered 500 in its dialog where that is still possible,
    // and the session (or, before it, the dialog's lock) released.
    if (invite != nullptr)
      abandon_invite(invite, request.dialog_id, data);
    else
      (void)pjsip_dlg_respond(sip_dialog, data, PJSIP_SC_INTERNAL_SERVER_ERROR, nullptr, nullptr, nullptr);
    pjsip_dlg_dec_lock(sip_dialog);
    throw;
  }
  pjsip_dlg_dec_lock(sip_dialog);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: the answer's body parts, with SipResponse::dialog_parts built from the answering dialog's tags.
std::vector<BodyPart> SipEngine::Impl::answer_parts(const SipResponse &response, const pjsip_dialog *dialog) {
  auto parts = response.parts;
  if (response.dialog_parts) {
    const auto tag = [](const pj_str_t &text) { return std::string(text.ptr, static_cast<std::size_t>(text.slen)); };
    for (auto &part : response.dialog_parts(tag(dialog->local.info->tag), tag(dialog->remote.info->tag)))
      parts.push_back(std::move(part));
  }
  return parts;
}

} // namespace mcx
