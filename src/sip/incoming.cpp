// SIP engine, incoming side: received requests, INVITE session state, re-INVITEs and negotiated media.
//
// Specifications: RFC 3261, RFC 4028, RFC 3262, RFC 3264, RFC 3311, RFC 6665, RFC 4566.

#include "sip_impl.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// RFC 3261 section 8.2: asks the application for the response to a request; 501 Not Implemented without a
// handler, 500 Application Error when the handler throws.
[[nodiscard]] SipResponse SipEngine::Impl::safe_application_response(Impl &owner, const SipMessage &request) {
  if (!owner.callbacks.on_request) {
    SipResponse response;
    response.status_code = 501;
    response.reason = "Not Implemented";
    return response;
  }
  try {
    return owner.callbacks.on_request(request);
  } catch (const std::exception &error) {
    owner.report_error(error.what());
    SipResponse response;
    response.status_code = 500;
    response.reason = "Application Error";
    return response;
  } catch (...) {
    owner.report_error("unknown SIP application error");
    SipResponse response;
    response.status_code = 500;
    response.reason = "Application Error";
    return response;
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.2.3: lists the option tags of the Require header fields that the endpoint does not support.
[[nodiscard]] std::string SipEngine::Impl::unsupported_required_extensions(pjsip_msg *message) const {
  std::string unsupported;
  auto *header = static_cast<pjsip_require_hdr *>(pjsip_msg_find_hdr(message, PJSIP_H_REQUIRE, nullptr));
  while (header != nullptr) {
    for (unsigned index = 0; index < header->count; ++index) {
      if (!pjsip_endpt_has_capability(endpoint, PJSIP_H_SUPPORTED, nullptr, &header->values[index])) {
        if (!unsupported.empty()) {
          unsupported += ", ";
        }
        unsupported += string_from(header->values[index]);
      }
    }
    header = static_cast<pjsip_require_hdr *>(pjsip_msg_find_hdr(message, PJSIP_H_REQUIRE, header->next));
  }
  return unsupported;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2.2.3 and RFC 4028: checks an initial INVITE; 420 Bad Extension with Unsupported for an
// unknown required extension, otherwise pjsip's verification (session timer supported) with its rejection or
// 400 Invalid INVITE.
[[nodiscard]] bool SipEngine::Impl::verify_initial_invite(pjsip_rx_data *data) {
  const std::string unsupported = unsupported_required_extensions(data->msg_info.msg);
  if (!unsupported.empty()) {
    SipResponse response;
    response.status_code = 420;
    response.reason = "Bad Extension";
    response.headers.push_back({"Unsupported", unsupported});
    send_response(data, response, nullptr);
    return false;
  }
  unsigned options = PJSIP_INV_SUPPORT_TIMER;
  pjsip_tx_data *failure = nullptr;
  const pj_status_t status = pjsip_inv_verify_request(data, &options, nullptr, nullptr, endpoint, &failure);
  if (status == PJ_SUCCESS) {
    return true;
  }
  if (failure != nullptr) {
    require_success(pjsip_endpt_send_response2(endpoint, data, failure, nullptr, nullptr),
                    "send rejected INVITE response");
  } else {
    SipResponse response;
    response.status_code = 400;
    response.reason = "Invalid INVITE";
    send_response(data, response, nullptr);
  }
  return false;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.2: handles a received request outside the INVITE usage: 482 Loop Detected for a colliding
// Call-ID (section 8.2.2.2), the application's response, deferred responses, INVITE acceptance, SUBSCRIBE
// acceptance (RFC 6665 section 4.2.1) and cleanup after a NOTIFY with Subscription-State terminated
// (RFC 6665 section 4.1.3); 400 Bad Request on a failure.
pj_bool_t SipEngine::Impl::receive_request(pjsip_rx_data *data) {
  auto *owner = active.load();
  if (owner == nullptr || data == nullptr || data->msg_info.msg == nullptr) {
    return PJ_FALSE;
  }
  try {
    auto *matched_dialog = pjsip_rdata_get_dlg(data);
    if (matched_dialog && pjsip_dlg_get_inv_session(matched_dialog)) {
      const auto &method = data->msg_info.msg->line.req.method;
      // INVITE usage owns call state, ACKs and session refreshes.
      // Application dialog usage must never answer these generically.
      if (method.id == PJSIP_INVITE_METHOD || method.id == PJSIP_ACK_METHOD || method.id == PJSIP_BYE_METHOD ||
          method.id == PJSIP_CANCEL_METHOD || ascii_equal(string_from(method.name), "UPDATE") ||
          pjsip_method_cmp(&method, &pjsip_prack_method) == 0)
        return PJ_FALSE;
    }
    const std::string incoming_id = call_id_from(data->msg_info.msg);
    const auto existing = owner->dialogs.find(incoming_id);
    if (existing != owner->dialogs.end() && (data->msg_info.to == nullptr || data->msg_info.to->tag.slen == 0 ||
                                             existing->second->dialog != matched_dialog)) {
      SipResponse collision;
      collision.status_code = 482;
      collision.reason = "Loop Detected";
      owner->send_response(data, collision, matched_dialog);
      return PJ_TRUE;
    }
    SipMessage request = owner->message_from(data);
    if (ascii_equal(request.method, "INVITE") && matched_dialog == nullptr && !owner->verify_initial_invite(data)) {
      return PJ_TRUE;
    }
    request.transaction_id = std::to_string(++owner->next_transaction);
    SipResponse response = safe_application_response(*owner, request);
    const std::string method = request.method;
    const bool invite = ascii_equal(method, "INVITE");
    if (response.deferred && ascii_equal(method, "SUBSCRIBE") && pjsip_rdata_get_dlg(data) == nullptr) {
      DeferredResponse deferred;
      require_success(pjsip_rx_data_clone(data, 0, &deferred.subscribe), "retain deferred SUBSCRIBE");
      deferred.request = request;
      owner->deferred_responses[request.transaction_id] = std::move(deferred);
      return PJ_TRUE;
    }
    if (response.deferred && !invite) {
      owner->defer_response(data, request);
      return PJ_TRUE;
    }
    // A deferred provisional answer leaves the SDP answer to SipEngine::answer.
    if (invite && response.status_code >= 100 && response.status_code < 300 &&
        (response.local_media.has_value() || response.local_sdp.has_value() ||
         (response.deferred && response.status_code < 200))) {
      try {
        const auto failure = owner->accept_invite(data, request, response);
        if (failure.has_value()) {
          owner->notify_call_state(request.dialog_id, SipCallState::disconnected, *failure);
        }
      } catch (...) {
        owner->notify_call_state(request.dialog_id, SipCallState::disconnected, 500);
        throw;
      }
      return PJ_TRUE;
    }
    if (ascii_equal(method, "SUBSCRIBE") && response.status_code >= 200 && response.status_code < 300) {
      owner->accept_subscription(data, request, response);
      return PJ_TRUE;
    }
    owner->send_response(data, response, pjsip_rdata_get_dlg(data));
    if (ascii_equal(method, "NOTIFY") && response.status_code >= 200 && response.status_code < 300 &&
        get_header(request.headers, "Subscription-State").starts_with("terminated")) {
      owner->pending_subscription_cleanup.push_back(request.dialog_id);
    }
    return PJ_TRUE;
  } catch (const std::exception &error) {
    owner->report_error(error.what());
  } catch (...) {
    owner->report_error("unknown SIP request handling error");
  }
  try {
    SipResponse response;
    response.status_code = 400;
    response.reason = "Bad Request";
    owner->send_response(data, response, nullptr);
  } catch (...) {
    // The request may already have its answer (or its transaction be gone); there is nothing left to tell.
  }
  return PJ_TRUE;
}

//------------------------------------------------------------------------------
// RFC 3261 sections 13 and 15: follows an INVITE session's state (early, confirmed, disconnected), ends a call
// whose 2xx crossed our CANCEL with BYE, passes a received BYE to the application, removes the dialog on
// disconnect and dispatches the initial INVITE's response.
void SipEngine::Impl::invite_state_changed(pjsip_inv_session *invite, pjsip_event *event) {
  auto *owner = active.load();
  if (owner == nullptr || invite == nullptr || owner->module.id < 0) {
    return;
  }
  guarded(owner, [&] { owner->follow_invite_state(invite, event); });
}

//------------------------------------------------------------------------------
// RFC 3261 sections 13 and 15: the body of invite_state_changed, which reports what it throws.
void SipEngine::Impl::follow_invite_state(pjsip_inv_session *invite, pjsip_event *event) {
  auto *owner = this;
  auto *dialog = static_cast<Dialog *>(invite->mod_data[owner->module.id]);
  if (dialog == nullptr) {
    return;
  }
  const std::string id = dialog->id;
  SipCallState state = SipCallState::early;
  bool notify = false;
  if (invite->state == PJSIP_INV_STATE_EARLY || invite->state == PJSIP_INV_STATE_CONNECTING) {
    state = SipCallState::early;
    notify = true;
  } else if (invite->state == PJSIP_INV_STATE_CONFIRMED && dialog->terminating && invite->role == PJSIP_ROLE_UAC) {
    // A 2xx crossed our CANCEL (RFC 3261 section 9.1): PJSIP acknowledges it but
    // leaves the session up, so end it with BYE instead of reporting it.
    try {
      pjsip_tx_data *bye = nullptr;
      require_success(pjsip_inv_end_session(invite, 200, nullptr, &bye), "end call answered after CANCEL");
      if (bye != nullptr) {
        if (!dialog->bye_parts.empty())
          bye->msg->body =
              make_text_body(bye->pool, dialog->bye_parts.front().content_type, dialog->bye_parts.front().body);
        require_success(pjsip_inv_send_msg(invite, bye), "send BYE after crossed CANCEL");
      }
    } catch (const std::exception &error) {
      owner->report_error(error.what());
    }
  } else if (invite->state == PJSIP_INV_STATE_CONFIRMED) {
    state = SipCallState::confirmed;
    notify = true;
  } else if (invite->state == PJSIP_INV_STATE_DISCONNECTED) {
    state = SipCallState::disconnected;
    notify = true;
    // The INVITE usage answers a received BYE; the application still
    // observes it (e.g. a <release-reason> body) before the disconnect.
    if (event != nullptr && event->type == PJSIP_EVENT_TSX_STATE && event->body.tsx_state.type == PJSIP_EVENT_RX_MSG &&
        event->body.tsx_state.src.rdata->msg_info.msg->type == PJSIP_REQUEST_MSG &&
        event->body.tsx_state.src.rdata->msg_info.msg->line.req.method.id == PJSIP_BYE_METHOD) {
      try {
        (void)safe_application_response(*owner, owner->message_from(event->body.tsx_state.src.rdata));
      } catch (const std::exception &error) {
        owner->report_error(error.what());
      }
    }
  }
  std::optional<SipResponse> initial_response;
  SipResponseHandler initial_handler;
  if (dialog->initial_handler && event != nullptr && event->type == PJSIP_EVENT_TSX_STATE &&
      event->body.tsx_state.type == PJSIP_EVENT_RX_MSG) {
    try {
      initial_response = owner->response_from(event->body.tsx_state.src.rdata);
      initial_handler = dialog->initial_handler;
      if (initial_response->status_code >= 200) {
        dialog->initial_handler = {};
      }
    } catch (const std::exception &error) {
      owner->report_error(error.what());
    }
  }
  if (state == SipCallState::disconnected) {
    invite->mod_data[owner->module.id] = nullptr;
    const auto found = owner->dialogs.find(id);
    if (found != owner->dialogs.end() && found->second.get() == dialog) {
      found->second->invite = nullptr;
      found->second->dialog = nullptr;
      owner->dialogs.erase(found);
    }
  }
  if (notify) {
    owner->notify_call_state(id, state, invite->cause);
  }
  if (initial_response.has_value()) {
    owner->dispatch_response(*initial_response, initial_handler);
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 14.2 and RFC 3264 section 8: handles a received re-INVITE: the application's answer now, or a
// deferred answer after 100 Trying; 488 on a failure.
pj_status_t SipEngine::Impl::receive_reinvite(pjsip_inv_session *invite, const pjmedia_sdp_session *,
                                              pjsip_rx_data *data) {
  auto *owner = active.load();
  if (!owner) return PJ_EINVALIDOP;
  try {
    auto request = owner->message_from(data);
    request.transaction_id = std::to_string(++owner->next_transaction);
    auto response = safe_application_response(*owner, request);
    if (response.deferred) {
      pjsip_tx_data *trying = nullptr;
      require_success(pjsip_inv_initial_answer(invite, data, 100, nullptr, nullptr, &trying),
                      "accept deferred re-INVITE");
      require_success(pjsip_inv_send_msg(invite, trying), "send re-INVITE 100 Trying");
      DeferredResponse deferred;
      deferred.dialog_id = request.dialog_id;
      deferred.reinvite = true;
      deferred.cseq = data->msg_info.cseq->cseq;
      owner->deferred_responses[request.transaction_id] = deferred;
      return PJ_SUCCESS;
    }
    owner->answer_reinvite(invite, data, request.dialog_id, data->msg_info.cseq->cseq, response);
  } catch (const std::exception &error) {
    owner->report_error(error.what());
    pjsip_tx_data *answer = nullptr;
    if (pjsip_inv_initial_answer(invite, data, 488, nullptr, nullptr, &answer) == PJ_SUCCESS)
      (void)pjsip_inv_send_msg(invite, answer);
  } catch (...) {
    owner->report_error("unknown re-INVITE handling error");
    pjsip_tx_data *answer = nullptr;
    if (pjsip_inv_initial_answer(invite, data, 488, nullptr, nullptr, &answer) == PJ_SUCCESS)
      (void)pjsip_inv_send_msg(invite, answer);
  }
  return PJ_SUCCESS;
}

//------------------------------------------------------------------------------
// RFC 3261 sections 14.1 and 15.1.1: releases BYE references when a sent BYE transaction terminates, and
// dispatches the final response of a sent re-INVITE (not 401/407 digest challenges) to its handler.
void SipEngine::Impl::invite_transaction_changed(pjsip_inv_session *invite, pjsip_transaction *tsx,
                                                 pjsip_event *event) {
  auto *owner = active.load();
  if (owner && invite && tsx && tsx->role == PJSIP_ROLE_UAC && tsx->method.id == PJSIP_BYE_METHOD &&
      tsx->state == PJSIP_TSX_STATE_TERMINATED && owner->bye_references.erase(invite))
    guarded(owner, [&] { owner->released_bye_references.push_back(invite); });
  if (!owner || !invite || !tsx || tsx->role != PJSIP_ROLE_UAC || tsx->method.id != PJSIP_INVITE_METHOD ||
      tsx->status_code < 200 || tsx->status_code == 401 || tsx->status_code == 407)
    return;
  auto *dialog = static_cast<Dialog *>(invite->mod_data[owner->module.id]);
  // A rejected INVITE reports both COMPLETED and later TERMINATED. Its
  // deferred termination must not consume a newer re-INVITE callback.
  // Digest retries may legitimately use a higher CSeq than the original.
  if (!dialog || !dialog->reinvite_handler || tsx->cseq < dialog->reinvite_cseq) return;
  if (tsx->state != PJSIP_TSX_STATE_COMPLETED && tsx->state != PJSIP_TSX_STATE_TERMINATED) return;
  auto handler = std::move(dialog->reinvite_handler);
  guarded(owner, [&] {
    SipResponse response;
    if (event && event->type == PJSIP_EVENT_TSX_STATE && event->body.tsx_state.type == PJSIP_EVENT_RX_MSG)
      response = owner->response_from(event->body.tsx_state.src.rdata);
    else
      response.status_code = tsx->status_code;
    owner->dispatch_response(response, handler);
  });
}

//------------------------------------------------------------------------------
// RFC 3264 section 5 and 6: reports the negotiated remote SDP of an audio or video session to the application.
void SipEngine::Impl::invite_media_updated(pjsip_inv_session *invite, pj_status_t status) {
  auto *owner = active.load();
  if (owner == nullptr || invite == nullptr || owner->module.id < 0 || !owner->callbacks.on_media) {
    return;
  }
  if (status != PJ_SUCCESS) {
    owner->report_error("SDP negotiation failed: " + status_error(status));
    return;
  }
  auto *dialog = static_cast<Dialog *>(invite->mod_data[owner->module.id]);
  if (dialog == nullptr || invite->neg == nullptr) {
    return;
  }
  const pjmedia_sdp_session *remote = nullptr;
  if (pjmedia_sdp_neg_get_active_remote(invite->neg, &remote) != PJ_SUCCESS || remote == nullptr) {
    return;
  }
  std::array<char, 8192> buffer{};
  const int length = pjmedia_sdp_print(remote, buffer.data(), buffer.size());
  if (length <= 0) {
    owner->report_error("could not print negotiated remote SDP");
    return;
  }
  const std::string_view negotiated(buffer.data(), static_cast<std::size_t>(length));
  // Media that is not MCPTT or MCVideo audio and video, such as the MSRP stream
  // of the MCData media plane, has no MediaDescription; its application reads
  // the SDP itself.
  if (negotiated.find("m=audio") == std::string_view::npos && negotiated.find("m=video") == std::string_view::npos)
    return;
  guarded(owner, [&] { owner->callbacks.on_media(dialog->id, parse_sdp(negotiated)); });
}

} // namespace mcx
