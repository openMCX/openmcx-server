//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Client transactions of SipEngine::Impl: request tokens, response dispatch, digest authentication, registration.
//
// Specifications: RFC 3261, RFC 6665.

#include "sip_impl.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: reports a call state change to the application, catching and reporting its exceptions.
void SipEngine::Impl::notify_call_state(std::string_view id, SipCallState state, int cause) noexcept {
  if (!callbacks.on_call_state) {
    return;
  }
  try {
    callbacks.on_call_state(id, state, cause);
  } catch (const std::exception &error) {
    report_error(error.what());
  } catch (...) {
    report_error("unknown SIP call-state callback error");
  }
}

//------------------------------------------------------------------------------
// Helper: passes a response to the application's general response callback, then to the request's handler.
void SipEngine::Impl::dispatch_response(const SipResponse &response, SipResponseHandler &handler) {
  if (callbacks.on_response) {
    callbacks.on_response(response);
  }
  if (handler) {
    handler(response);
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 22.2: prepares a request's digest authentication session with the configured credentials.
void SipEngine::Impl::initialize_auth(RequestToken &token) {
  token.pool = pjsip_endpt_create_pool(endpoint, "sip-auth", 2048, 2048);
  if (token.pool == nullptr) {
    throw std::runtime_error("could not allocate SIP authentication pool");
  }
  require_success(pjsip_auth_clt_init(&token.auth, endpoint, token.pool, 0), "initialize SIP digest authentication");
  token.auth_initialized = true;
  if (has_credentials(config)) {
    pjsip_cred_info credential{};
    credential.realm = pj_view("*");
    credential.scheme = pj_view("digest");
    credential.username = pj_view(config.username);
    credential.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
    credential.data = pj_view(config.password);
    require_success(pjsip_auth_clt_set_credentials(&token.auth, 1, &credential), "set SIP digest credentials");
  }
}

//------------------------------------------------------------------------------
// Helper: the end of a request's transaction: the token goes now, or, while its send call is still running, once
// that call returns (see RequestToken::sending).
void SipEngine::Impl::finish_token(RequestToken *token) noexcept {
  if (token->sending) {
    token->completed = true;
    return;
  }
  destroy_token(token);
}

//------------------------------------------------------------------------------
// Helper: a new request token of this engine for the handler, owned by the caller until the request is sent.
SipEngine::Impl::OwnedToken SipEngine::Impl::make_token(SipResponseHandler handler) {
  auto token = std::make_unique<RequestToken>();
  token->owner = this;
  token->handler = std::move(handler);
  return OwnedToken(token.release());
}

//------------------------------------------------------------------------------
// Helper: releases a request token, its authentication session and its pool (to its engine's endpoint, or directly
// when the token has no engine).
void SipEngine::Impl::destroy_token(RequestToken *token) noexcept {
  const std::unique_ptr<RequestToken> owned(token);
  if (!owned) return;
  if (owned->auth_initialized) (void)pjsip_auth_clt_deinit(&owned->auth);
  if (owned->pool == nullptr) return;
  if (owned->owner != nullptr && owned->owner->endpoint != nullptr)
    pjsip_endpt_release_pool(owned->owner->endpoint, owned->pool);
  else
    pj_pool_release(owned->pool);
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.3, section 22.2 and section 22.3: an out-of-dialog client transaction's result: a 401 or
// 407 challenge is answered once with credentials (RFC 3261 section 8.1.3.5), any other result goes to the handler.
void SipEngine::Impl::send_complete(void *opaque, pjsip_event *event) {
  auto *token = static_cast<RequestToken *>(opaque);
  if (token == nullptr) return;
  if (token->owner == nullptr) {
    destroy_token(token); // no engine to report to; the token is still this transaction's to release
    return;
  }

  auto *owner = token->owner;
  pjsip_rx_data *received = nullptr;
  pjsip_transaction *transaction = nullptr;
  if (event != nullptr && event->type == PJSIP_EVENT_TSX_STATE) {
    transaction = event->body.tsx_state.tsx;
    if (event->body.tsx_state.type == PJSIP_EVENT_RX_MSG) {
      received = event->body.tsx_state.src.rdata;
    }
  }

  if (received != nullptr && transaction != nullptr && !token->retried &&
      (transaction->status_code == 401 || transaction->status_code == 407)) {
    if (!has_credentials(owner->config)) {
      owner->report_error("SIP authentication challenge received without configured digest credentials");
    } else {
      pjsip_tx_data *authenticated = nullptr;
      const pj_status_t status =
          pjsip_auth_clt_reinit_req(&token->auth, received, transaction->last_tx, &authenticated);
      if (status == PJ_SUCCESS) {
        token->retried = true;
        pj_status_t send_status = PJ_SUCCESS;
        if (send_with_token(token, send_status, [&] {
              return pjsip_endpt_send_request(owner->endpoint, authenticated, -1, token, &Impl::send_complete);
            })) {
          destroy_token(token); // the retry completed inside the call and reported to the handler
          return;
        }
        if (send_status == PJ_SUCCESS) {
          return;
        }
      }
    }
  }

  guarded(owner, [&] {
    SipResponse response = owner->response_from(received);
    if (received == nullptr && transaction != nullptr) {
      response.status_code = transaction->status_code;
      response.reason = string_from(transaction->status_text);
    }
    owner->dispatch_response(response, token->handler);
  });
  owner->finish_token(token);
}

//------------------------------------------------------------------------------
// RFC 3261 section 12.2.1.2, section 22.2 and section 22.3: an in-dialog client transaction's result: a 401 or
// 407 challenge is answered once with credentials (by the INVITE session layer for its own dialogs), any other
// result goes to the handler; a refused initial SUBSCRIBE or a terminating NOTIFY ends the subscription dialog
// (RFC 6665).
void SipEngine::Impl::dialog_transaction_state(pjsip_transaction *transaction, pjsip_event *event) {
  auto *owner = active.load();
  if (owner == nullptr || transaction == nullptr || owner->module.id < 0 ||
      (transaction->state != PJSIP_TSX_STATE_COMPLETED && transaction->state != PJSIP_TSX_STATE_TERMINATED)) {
    return;
  }

  auto *token = static_cast<RequestToken *>(transaction->mod_data[owner->module.id]);
  if (token == nullptr) {
    token = owner->adopt_auth_retry(transaction);
    if (token == nullptr) {
      return;
    }
  }

  pjsip_rx_data *received = nullptr;
  if (event != nullptr && event->type == PJSIP_EVENT_TSX_STATE && event->body.tsx_state.type == PJSIP_EVENT_RX_MSG) {
    received = event->body.tsx_state.src.rdata;
  }

  if (received != nullptr && !token->retried && (transaction->status_code == 401 || transaction->status_code == 407) &&
      token->dialog != nullptr && pjsip_dlg_get_inv_session(token->dialog) != nullptr &&
      has_credentials(owner->config)) {
    // The INVITE session layer has already sent the request again with its
    // own credentials; the answer to that request is the one to report.
    token->retried = true;
    transaction->mod_data[owner->module.id] = nullptr;
    try {
      owner->auth_retries[token->dialog].push_back(
          {string_from(transaction->method.name), static_cast<std::uint32_t>(transaction->cseq) + 1, token});
    } catch (...) {
      owner->report_error("could not track a digest retry"); // out of memory: the retry's answer is not reported
      owner->finish_token(token);
    }
    return;
  }

  if (received != nullptr && !token->retried && (transaction->status_code == 401 || transaction->status_code == 407)) {
    if (!has_credentials(owner->config)) {
      owner->report_error("SIP authentication challenge received without configured digest credentials");
    } else {
      pjsip_tx_data *authenticated = nullptr;
      const pj_status_t auth_status =
          pjsip_auth_clt_reinit_req(&token->auth, received, transaction->last_tx, &authenticated);
      if (auth_status == PJ_SUCCESS) {
        token->retried = true;
        transaction->mod_data[owner->module.id] = nullptr;
        pj_status_t send_status = PJ_SUCCESS;
        if (send_with_token(token, send_status, [&] {
              return pjsip_dlg_send_request(token->dialog, authenticated, owner->module.id, token);
            })) {
          destroy_token(token); // the retry completed inside the call and reported to the handler
          return;
        }
        if (send_status == PJ_SUCCESS) {
          return;
        }
      }
    }
  }

  transaction->mod_data[owner->module.id] = nullptr;
  guarded(owner, [&] {
    if (token->dialog != nullptr &&
        (token->terminating_subscription || (token->initial_subscription && transaction->status_code >= 300)))
      owner->pending_subscription_cleanup.push_back(string_from(token->dialog->call_id->id));
  });
  guarded(owner, [&] {
    SipResponse response = owner->response_from(received);
    if (received == nullptr) {
      response.status_code = transaction->status_code;
      response.reason = string_from(transaction->status_text);
    }
    owner->dispatch_response(response, token->handler);
  });
  owner->finish_token(token);
}

//------------------------------------------------------------------------------
// RFC 3261 section 10.2: reports the result of a REGISTER transaction to the registration handler.
void SipEngine::Impl::registration_complete(pjsip_regc_cbparam *parameter) {
  auto *owner = parameter == nullptr ? nullptr : static_cast<Impl *>(parameter->token);
  if (owner == nullptr) {
    return;
  }
  guarded(owner, [&] {
    SipResponse response = owner->response_from(parameter->rdata);
    response.status_code = parameter->code;
    response.reason = string_from(parameter->reason);
    owner->dispatch_response(response, owner->registration_handler);
  });
}

} // namespace mcx
