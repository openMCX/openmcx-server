//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SIP engine lifecycle over pjsip: construction, start and stop, ACK and reference bookkeeping.
//
// Specifications: RFC 3261, RFC 3262, RFC 4028, RFC 6665, TS 33.180 V19.4.0 (Rel-19).

#include "mcx/runtime.hpp"
#include "mcx/tls_profile.hpp"
#include "sip_impl.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// RFC 3261 section 22.2: returns (and forgets) the request token waiting for the digest retry sent in this client
// transaction, matched by dialog, method and CSeq.
SipEngine::Impl::RequestToken *SipEngine::Impl::adopt_auth_retry(pjsip_transaction *transaction) {
  if (transaction->role != PJSIP_ROLE_UAC) return nullptr;
  auto *dialog = pjsip_tsx_get_dlg(transaction);
  const auto found = auth_retries.find(dialog);
  if (found == auth_retries.end()) return nullptr;
  const auto method = string_from(transaction->method.name);
  auto &waiting = found->second;
  for (auto it = waiting.begin(); it != waiting.end(); ++it) {
    if (it->method != method || it->cseq != static_cast<std::uint32_t>(transaction->cseq)) continue;
    auto *token = it->token;
    waiting.erase(it);
    if (waiting.empty()) auth_retries.erase(found);
    return token;
  }
  return nullptr;
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.3.1.4: notes the ACK that confirms a 2xx sent with pending_ack_cseq; never consumes it.
pj_bool_t SipEngine::Impl::observe_ack(pjsip_rx_data *data) {
  auto *owner = active.load();
  if (!owner || data->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD) return PJ_FALSE;
  guarded(owner, [&] {
    auto found = owner->dialogs.find(call_id_from(data->msg_info.msg));
    if (found != owner->dialogs.end() && found->second->dialog == pjsip_rdata_get_dlg(data) &&
        found->second->pending_ack_cseq == data->msg_info.cseq->cseq) {
      found->second->pending_ack_cseq = -1;
      owner->pending_acks.push_back(found->first);
    }
  });
  return PJ_FALSE;
}

//------------------------------------------------------------------------------
// Helper: ends an outgoing dialog whose creation failed part way: its entry goes, then its session (which destroys
// it once its transactions end), or the dialog itself while it has no session (pjsip_dlg_terminate).
void SipEngine::Impl::abandon_dialog(pjsip_dialog *dialog, const std::string &id, bool session) noexcept {
  if (const auto found = dialogs.find(id); found != dialogs.end() && found->second->dialog == dialog)
    dialogs.erase(found);
  if (!session) {
    (void)pjsip_dlg_terminate(dialog);
    return;
  }
  (void)pjsip_dlg_set_mod_data(dialog, module.id, nullptr);
  (void)pjsip_dlg_dec_session(dialog, &module);
}

//------------------------------------------------------------------------------
// Helper: ends an INVITE session whose creation or answer failed part way: its entry goes, an incoming INVITE is
// answered 500 in its dialog where that is still possible (RFC 3261 section 13.3.1), and the session is terminated
// without a call-state report (pjsip_inv_terminate), which releases its dialog.
void SipEngine::Impl::abandon_invite(pjsip_inv_session *invite, const std::string &id,
                                     pjsip_rx_data *request) noexcept {
  if (const auto found = dialogs.find(id); found != dialogs.end() && found->second->invite == invite)
    dialogs.erase(found);
  invite->mod_data[module.id] = nullptr;
  if (request != nullptr)
    (void)pjsip_dlg_respond(invite->dlg, request, PJSIP_SC_INTERNAL_SERVER_ERROR, nullptr, nullptr, nullptr);
  (void)pjsip_inv_terminate(invite, PJSIP_SC_INTERNAL_SERVER_ERROR, PJ_FALSE);
}

//------------------------------------------------------------------------------
// Helper: drops the INVITE session references held while sent BYE transactions ran.
void SipEngine::Impl::release_bye_references() {
  auto released = std::move(released_bye_references);
  released_bye_references.clear();
  for (auto *invite : released) (void)pjsip_inv_dec_ref(invite);
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.3: releases the dialogs of subscriptions terminated by a NOTIFY once callback dispatch
// has finished.
void SipEngine::Impl::release_pending_subscriptions() {
  auto pending = std::move(pending_subscription_cleanup);
  pending_subscription_cleanup.clear();
  for (const auto &id : pending) {
    auto found = dialogs.find(id);
    if (found == dialogs.end() || found->second->invite != nullptr) continue;
    auto *dialog = found->second->dialog;
    // Keep the application entry alive until PJSIP callback dispatch and
    // deferred responses have finished. Transactions retain their own refs.
    dialog->mod_data[module.id] = nullptr;
    (void)pjsip_dlg_dec_session(dialog, &module);
    dialogs.erase(found);
  }
}

//------------------------------------------------------------------------------
// Helper: stores and validates the configuration and callbacks.
SipEngine::Impl::Impl(SipConfig value, SipCallbacks handlers)
    : config(std::move(value)), callbacks(std::move(handlers)) {
  validate_config(config);
}

//------------------------------------------------------------------------------
// RFC 3261, RFC 3262 and RFC 4028: starts pjsip (transactions, user agent, INVITE usage, 100rel, session timers),
// registers the application, body protection (TS 33.180 clause 9.3) and ACK observer modules, and the TLS
// transport with mutual certificate authentication (TCP only for debug).
void SipEngine::Impl::start() {
  if (started) {
    return;
  }
  Impl *expected = nullptr;
  if (!active.compare_exchange_strong(expected, this)) {
    throw std::runtime_error("only one SIP engine may run in a process");
  }
  try {
    require_success(pj_init(), "initialize pjlib");
    pj_initialized = true;
    unsigned random_seed = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&random_seed), sizeof(random_seed)) != 1) {
      throw std::runtime_error("could not seed PJSIP random generator");
    }
    pj_srand(random_seed);
    pj_log_set_level(3);
    require_success(pjlib_util_init(), "initialize pjlib-util");
    pj_caching_pool_init(&cache, &pj_pool_factory_default_policy, 0);
    cache_initialized = true;
    require_success(pjsip_endpt_create(&cache.factory, "openmcx", &endpoint), "create PJSIP endpoint");
    require_success(pjsip_tsx_layer_init_module(endpoint), "initialize PJSIP transactions");
    require_success(pjsip_ua_init_module(endpoint, nullptr), "initialize PJSIP user agent");

    pjsip_inv_callback invite_callbacks{};
    invite_callbacks.on_state_changed = &Impl::invite_state_changed;
    invite_callbacks.on_media_update = &Impl::invite_media_updated;
    invite_callbacks.on_rx_reinvite = &Impl::receive_reinvite;
    invite_callbacks.on_tsx_state_changed = &Impl::invite_transaction_changed;
    require_success(pjsip_inv_usage_init(endpoint, &invite_callbacks), "initialize PJSIP INVITE usage");
    require_success(pjsip_100rel_init_module(endpoint), "initialize PJSIP 100rel support");
    require_success(pjsip_timer_init_module(endpoint), "initialize PJSIP session timers");

    module.name = pj_view("mod-openmcx");
    module.id = -1;
    module.priority = PJSIP_MOD_PRIORITY_APPLICATION;
    module.on_rx_request = &Impl::receive_request;
    module.on_tsx_state = &Impl::dialog_transaction_state;
    require_success(pjsip_endpt_register_module(endpoint, &module), "register OpenMCX SIP module");
    protection_module.name = pj_view("mod-openmcx-protection");
    protection_module.id = -1;
    protection_module.priority = PJSIP_MOD_PRIORITY_TRANSPORT_LAYER + 1;
    protection_module.on_tx_request = &Impl::protect_outgoing;
    protection_module.on_tx_response = &Impl::protect_outgoing;
    require_success(pjsip_endpt_register_module(endpoint, &protection_module), "register body protection");
    ack_module.name = pj_view("mod-openmcx-ack");
    ack_module.id = -1;
    ack_module.priority = PJSIP_MOD_PRIORITY_DIALOG_USAGE - 1;
    ack_module.on_rx_request = &Impl::observe_ack;
    require_success(pjsip_endpt_register_module(endpoint, &ack_module), "register ACK observer");
    if (log_level() == LogLevel::debug) {
      trace_module.name = pj_view("mod-openmcx-trace");
      trace_module.id = -1;
      // Below the transport layer: the first to see a received message and the last to see a sent one, after the
      // body protection.
      trace_module.priority = PJSIP_MOD_PRIORITY_TRANSPORT_LAYER - 1;
      trace_module.on_rx_request = &Impl::trace_received;
      trace_module.on_rx_response = &Impl::trace_received;
      trace_module.on_tx_request = &Impl::trace_sent;
      trace_module.on_tx_response = &Impl::trace_sent;
      require_success(pjsip_endpt_register_module(endpoint, &trace_module), "register SIP message log");
    }

    pjsip_tls_setting tls{};
    pjsip_tls_setting_default(&tls);
    tls.ca_list_file = pj_view(config.tls.ca_file);
    tls.cert_file = pj_view(config.tls.cert_file);
    tls.privkey_file = pj_view(config.tls.key_file);
    tls.verify_server = config.tls.verify_server ? PJ_TRUE : PJ_FALSE;
    tls.verify_client = PJ_TRUE;
    tls.require_client_cert = PJ_TRUE;
    tls.proto = PJ_SSL_SOCK_PROTO_TLS1_2 | PJ_SSL_SOCK_PROTO_TLS1_3;
    // TS 33.210 clause 6.2 (mcx/tls_profile.hpp): TLS 1.2 only with ECDHE and AEAD (TLS 1.3 keeps the library's
    // suites); the groups P-256, P-384 and P-521, no ffdhe (pjproject names no x25519).
    std::array<pj_ssl_cipher, PJ_SSL_SOCK_MAX_CIPHERS> available{};
    unsigned available_count = available.size();
    require_success(pj_ssl_cipher_get_availables(available.data(), &available_count), "list the TLS cipher suites");
    std::vector<pj_ssl_cipher> ciphers;
    const std::string allowed = std::string(":") + tls_profile::tls12_ciphers + ":";
    for (unsigned i = 0; i < available_count; ++i) {
      const char *name = pj_ssl_cipher_name(available[i]);
      if (name != nullptr && allowed.find(std::string(":") + name + ":") != std::string::npos)
        ciphers.push_back(available[i]);
    }
    if (ciphers.empty()) throw std::runtime_error("no TLS 1.2 cipher suite of the TS 33.210 profile available");
    tls.ciphers = ciphers.data();
    tls.ciphers_num = static_cast<unsigned>(ciphers.size());
    std::array<pj_ssl_curve, 3> curves{PJ_TLS_CURVE_SECP256R1, PJ_TLS_CURVE_SECP384R1, PJ_TLS_CURVE_SECP521R1};
    tls.curves = curves.data();
    tls.curves_num = static_cast<unsigned>(curves.size());

    pj_sockaddr local{};
    auto listen = pj_view(config.listen_address);
    require_success(pj_sockaddr_init(pj_AF_INET(), &local, &listen, config.listen_port), "parse SIP listen address");
    pjsip_host_port advertised{};
    advertised.host = pj_view(config.advertise_address);
    advertised.port = config.listen_port;
    if (config.aka.enabled) {
      // TS 33.203 clause 7: IMS AKA, its TCP transports and security associations (ims_aka.cpp).
      aka_start(local, advertised);
    } else if (config.tls.enabled) {
      require_success(pjsip_tls_transport_start2(endpoint, &tls, &local, &advertised, 1, &tls_factory),
                      "start SIP TLS transport");
    } else {
      require_success(pjsip_tcp_transport_start2(endpoint, &local.ipv4, &advertised, 1, &tls_factory),
                      "start debug SIP TCP transport");
    }
    started = true;
  } catch (...) {
    stop();
    throw;
  }
}

//------------------------------------------------------------------------------
// Helper: releases the IMS AKA state, pending responses, the registration and the dialogs, then destroys the
// endpoint, pool cache and pjlib; safe after a partial start.
void SipEngine::Impl::stop() noexcept {
  // The IMS AKA security associations, their connections and timers go first, while the endpoint exists.
  aka_stop();
  for (const auto &response : pending_responses) {
    if (response.data != nullptr) {
      pjsip_tx_data_dec_ref(response.data);
    }
  }
  pending_responses.clear();

  // Requests waiting for the application's answer: the SUBSCRIBE copies, the prepared responses and the references
  // that kept their transactions.
  for (auto &[id, deferred] : deferred_responses) {
    (void)id;
    if (deferred.subscribe != nullptr) (void)pjsip_rx_data_free_cloned(deferred.subscribe);
    if (deferred.data != nullptr) (void)pjsip_tx_data_dec_ref(deferred.data);
    if (!deferred.reinvite && deferred.subscribe == nullptr && deferred.transaction != nullptr)
      (void)pj_grp_lock_dec_ref(deferred.transaction->grp_lock);
  }
  deferred_responses.clear();

  // The tokens of digest retries the INVITE session layer sent and whose answers never came.
  for (auto &[dialog, retries] : auth_retries) {
    (void)dialog;
    for (const auto &retry : retries) destroy_token(retry.token);
  }
  auth_retries.clear();

  // The INVITE sessions kept while our BYEs ran.
  for (auto *invite : bye_references) (void)pjsip_inv_dec_ref(invite);
  bye_references.clear();
  release_bye_references();
  pending_acks.clear();
  pending_subscription_cleanup.clear();
  if (registration != nullptr) {
    (void)pjsip_regc_destroy(registration);
    registration = nullptr;
  }
  for (auto &[id, entry] : dialogs) {
    (void)id;
    if (entry->invite != nullptr && module.id >= 0) {
      entry->invite->mod_data[module.id] = nullptr;
    } else if (entry->dialog != nullptr && module.id >= 0) {
      (void)pjsip_dlg_set_mod_data(entry->dialog, module.id, nullptr);
      (void)pjsip_dlg_dec_session(entry->dialog, &module);
    }
  }
  dialogs.clear();
  if (endpoint != nullptr) {
    pjsip_endpt_destroy(endpoint);
    endpoint = nullptr;
  }
  if (cache_initialized) {
    pj_caching_pool_destroy(&cache);
    cache_initialized = false;
  }
  if (pj_initialized) {
    pj_shutdown();
    pj_initialized = false;
  }
  started = false;
  Impl *expected = this;
  (void)active.compare_exchange_strong(expected, nullptr);
}

//------------------------------------------------------------------------------
// Helper: throws std::logic_error when the engine is not started.
void SipEngine::Impl::ensure_started() const {
  if (!started || endpoint == nullptr) {
    throw std::logic_error("SIP engine is not started");
  }
}

namespace {
//------------------------------------------------------------------------------
// Helper: the text of a URI in a header, for the SIP message log.
std::string trace_uri(pjsip_uri_context_e context, const pjsip_uri *uri) {
  if (!uri) return {};
  char text[512];
  const int length = pjsip_uri_print(context, uri, text, sizeof(text));
  return length > 0 ? std::string(text, static_cast<std::size_t>(length)) : std::string{};
}

//------------------------------------------------------------------------------
// Helper: what a SIP message is, for the log: the method and Request-URI, or the status.
std::string trace_what(const pjsip_msg *message) {
  if (message->type == PJSIP_REQUEST_MSG)
    return std::string(message->line.req.method.name.ptr, message->line.req.method.name.slen) + " " +
           trace_uri(PJSIP_URI_IN_REQ_URI, message->line.req.uri);
  return std::to_string(message->line.status.code);
}

//------------------------------------------------------------------------------
// Helper: the dialog fields of a SIP message for the log, " | " separated: From, To, Call-ID and CSeq; never the body
// (it may carry keys and access tokens).
std::string trace_fields(const pjsip_msg *message) {
  std::string out;
  if (auto *from = static_cast<const pjsip_fromto_hdr *>(pjsip_msg_find_hdr(message, PJSIP_H_FROM, nullptr)))
    out += " | from <" + trace_uri(PJSIP_URI_IN_FROMTO_HDR, from->uri) + ">";
  if (auto *to = static_cast<const pjsip_fromto_hdr *>(pjsip_msg_find_hdr(message, PJSIP_H_TO, nullptr)))
    out += " | to <" + trace_uri(PJSIP_URI_IN_FROMTO_HDR, to->uri) + ">";
  if (auto *cid = static_cast<const pjsip_cid_hdr *>(pjsip_msg_find_hdr(message, PJSIP_H_CALL_ID, nullptr)))
    out += " | call-id " + std::string(cid->id.ptr, cid->id.slen);
  if (auto *cseq = static_cast<const pjsip_cseq_hdr *>(pjsip_msg_find_hdr(message, PJSIP_H_CSEQ, nullptr)))
    out += " | cseq " + std::to_string(cseq->cseq) + " " + std::string(cseq->method.name.ptr, cseq->method.name.slen);
  return out;
}
} // namespace

//------------------------------------------------------------------------------
// The SIP message log (log level debug): a received message, before any module handles it, as a line on stderr:
// "SIP <- INVITE sip:... | from <...> | to <...> | call-id ... | cseq 2 INVITE | 172.31.19.10:5061 TLS | 2310 bytes".
pj_bool_t SipEngine::Impl::trace_received(pjsip_rx_data *data) {
  try {
    const auto *message = data->msg_info.msg;
    debug_line("SIP <- " + trace_what(message) + trace_fields(message) + " | " + std::string(data->pkt_info.src_name) +
               ":" + std::to_string(data->pkt_info.src_port) + " " +
               (data->tp_info.transport ? data->tp_info.transport->type_name : "") + " | " +
               std::to_string(data->msg_info.len) + " bytes");
  } catch (const std::exception &) {}
  return PJ_FALSE;
}

//------------------------------------------------------------------------------
// The SIP message log: a message about to be sent, after the body protection:
// "SIP -> 100 | from <...> | to <...> | call-id ... | cseq 2 INVITE | 172.31.19.10:5061 TLS | 412 bytes".
pj_status_t SipEngine::Impl::trace_sent(pjsip_tx_data *data) {
  try {
    std::string size;
    if (data->buf.cur > data->buf.start) size = " | " + std::to_string(data->buf.cur - data->buf.start) + " bytes";
    debug_line("SIP -> " + trace_what(data->msg) + trace_fields(data->msg) + " | " +
               std::string(data->tp_info.dst_name) + ":" + std::to_string(data->tp_info.dst_port) + " " +
               (data->tp_info.transport ? data->tp_info.transport->type_name : "") + size);
  } catch (const std::exception &) {}
  return PJ_SUCCESS;
}

} // namespace mcx
