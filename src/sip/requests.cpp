// Outgoing SIP requests of SipEngine::Impl: route sets, out-of-dialog requests, SUBSCRIBE, in-dialog requests, INVITE.
//
// Specifications: RFC 3261, RFC 3608, RFC 6665, RFC 4028, RFC 3264, TS 24.379 V19.7.0 (Rel-19), TS 24.229.

#include "sip_impl.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// RFC 3261 section 12.1 and TS 24.379 clause 6.8.2: pins a dialog's route set to one next hop, for a dialog with
// a peer server reached without the SIP core: its Contact may be a public URI (a session URI) that only the core
// could route. The route every request of this dialog follows. An outgoing dialog keeps it for the whole dialog,
// because a peer's Contact is the logical session URI of its controlling function rather than a routable host.
void SipEngine::Impl::pin_dialog_route(pjsip_dialog *dialog, std::string_view route, bool freeze) {
  // An incoming dialog whose request was recorded by a proxy already has
  // the authoritative route set; only direct peering, which records none,
  // needs the peer route pinned.
  if (!pj_list_empty(&dialog->route_set)) return;
  auto *parsed = create_header(dialog->pool, {"Route", std::string(route)});
  if (parsed == nullptr || parsed->type != PJSIP_H_ROUTE) throw std::invalid_argument("invalid peer Route");
  pjsip_route_hdr head;
  pj_list_init(&head);
  pj_list_push_back(&head, parsed);
  require_success(pjsip_dlg_set_route_set(dialog, &head), "set peer dialog route");
  if (freeze) dialog->route_set_frozen = PJ_TRUE;
}

//------------------------------------------------------------------------------
// Helper: the headers without any Route header (the route is applied separately).
std::vector<SipHeader> SipEngine::Impl::without_route(const std::vector<SipHeader> &headers) {
  std::vector<SipHeader> result;
  for (const auto &header : headers)
    if (!ascii_equal(header.name, "Route")) result.push_back(header);
  return result;
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.2: adds the preloaded Route to the SIP core; an explicit Route header (direct server
// peering) replaces the core route.
void SipEngine::Impl::add_core_route(pjsip_tx_data *data, const std::vector<SipHeader> &headers) const {
  if (!get_header(headers, "Route").empty()) return;
  add_header(data, {"Route", core_route()});
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.2: the preloaded Route header value towards the SIP core, a loose route (;lr).
[[nodiscard]] std::string SipEngine::Impl::core_route() const {
  std::string route = "<" + config.core_uri;
  if (route.find(";lr") == std::string::npos) {
    route += ";lr";
  }
  return route + ">";
}

//------------------------------------------------------------------------------
// RFC 3261 section 8.1: sends an out-of-dialog request (for example MESSAGE or PUBLISH) through the SIP core,
// with digest authentication (RFC 3261 section 22) prepared; the handler receives the final response.
void SipEngine::Impl::send_request(std::string_view method_text, std::string_view request_uri,
                                   std::string_view content_type, std::string_view body,
                                   const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  ensure_started();
  if (method_text.empty() || request_uri.empty() || method_text.size() > 32U) {
    throw std::invalid_argument("invalid SIP request method or URI");
  }
  pj_str_t method_name = pj_view(method_text);
  pjsip_method method{};
  pjsip_method_init_np(&method, &method_name);
  auto target = pj_view(request_uri);
  auto from = pj_view(config.identity);
  auto to = pj_view(request_uri);
  const auto contact_text = contact_uri();
  auto contact = pj_view(contact_text);
  pjsip_tx_data *created = nullptr;
  require_success(
      pjsip_endpt_create_request(endpoint, &method, &target, &from, &to, &contact, nullptr, -1, nullptr, &created),
      "create SIP request");
  TxData data(created);
  if (!content_type.empty()) {
    data->msg->body = make_text_body(data->pool, content_type, body);
  }
  add_core_route(data.get(), headers);
  add_headers(data.get(), headers);
  auto token = make_token(std::move(handler));
  initialize_auth(*token);
  require_success(pjsip_auth_clt_init_req(&token->auth, data.get()), "initialize SIP request authentication");
  auto *request_token = token.get();
  send_owned(
      std::move(token),
      [&] { return pjsip_endpt_send_request(endpoint, data.release(), -1, request_token, &Impl::send_complete); },
      "send SIP request");
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2: creates a subscription dialog and sends the initial SUBSCRIBE with Event and Expires,
// optionally with a body; returns the dialog id (its Call-ID).
[[nodiscard]] std::string SipEngine::Impl::create_subscribe(std::string_view request_uri, std::string_view event,
                                                            unsigned expires, const std::vector<SipHeader> &headers,
                                                            SipResponseHandler handler, std::string_view content_type,
                                                            std::string_view body) {
  ensure_started();
  auto local = pj_view(config.identity);
  const auto contact_text = contact_uri();
  auto contact = pj_view(contact_text);
  auto remote = pj_view(request_uri);
  pjsip_dialog *sip_dialog = nullptr;
  require_success(pjsip_dlg_create_uac(pjsip_ua_instance(), &local, &contact, &remote, &remote, &sip_dialog),
                  "create outgoing SUBSCRIBE dialog");
  const std::string id = string_from(sip_dialog->call_id->id);
  bool session = false;
  try {
    auto entry = std::make_unique<Dialog>();
    entry->id = id;
    entry->dialog = sip_dialog;
    require_success(pjsip_dlg_inc_session(sip_dialog, &module), "retain SUBSCRIBE dialog");
    session = true;
    require_success(pjsip_dlg_add_usage(sip_dialog, &module, entry.get()), "attach SUBSCRIBE dialog usage");
    if (const auto explicit_route = get_header(headers, "Route"); !explicit_route.empty())
      pin_dialog_route(sip_dialog, explicit_route);
    if (has_credentials(config)) {
      pjsip_cred_info credential{};
      credential.realm = pj_view("*");
      credential.scheme = pj_view("digest");
      credential.username = pj_view(config.username);
      credential.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
      credential.data = pj_view(config.password);
      require_success(pjsip_auth_clt_set_credentials(&sip_dialog->auth_sess, 1, &credential),
                      "set SUBSCRIBE credentials");
    }
    pjsip_tx_data *created = nullptr;
    require_success(pjsip_dlg_create_request(sip_dialog, &pjsip_subscribe_method, -1, &created),
                    "create SUBSCRIBE request");
    TxData data(created);
    add_core_route(data.get(), headers);
    add_header(data.get(), {"Event", std::string(event)});
    add_header(data.get(), {"Expires", std::to_string(expires)});
    add_headers(data.get(), without_route(headers));
    if (!body.empty()) data->msg->body = make_text_body(data->pool, content_type, body);
    auto token = make_token(std::move(handler));
    token->dialog = sip_dialog;
    token->initial_subscription = true;
    initialize_auth(*token);
    dialogs[id] = std::move(entry);
    auto *request_token = token.get();
    send_owned(
        std::move(token), [&] { return pjsip_dlg_send_request(sip_dialog, data.release(), module.id, request_token); },
        "send SUBSCRIBE request");
  } catch (...) {
    abandon_dialog(sip_dialog, id, session);
    throw;
  }
  return id;
}

//------------------------------------------------------------------------------
// RFC 3261 section 12.2.1: sends a request within an existing dialog; a NOTIFY with Subscription-State
// terminated ends the subscription (RFC 6665 section 4.2.2).
void SipEngine::Impl::send_dialog_request(std::string_view dialog_id, const pjsip_method &method,
                                          const std::vector<SipHeader> &headers, std::string_view content_type,
                                          std::string_view body, SipResponseHandler handler) {
  ensure_started();
  const auto found = dialogs.find(std::string(dialog_id));
  if (found == dialogs.end() || found->second->dialog == nullptr) {
    throw std::invalid_argument("unknown SIP dialog");
  }
  auto *sip_dialog = found->second->dialog;
  pjsip_tx_data *created = nullptr;
  require_success(pjsip_dlg_create_request(sip_dialog, &method, -1, &created), "create in-dialog SIP request");
  TxData data(created);
  add_headers(data.get(), headers);
  if (!content_type.empty()) {
    data->msg->body = make_text_body(data->pool, content_type, body);
  }
  auto token = make_token(std::move(handler));
  token->dialog = sip_dialog;
  token->terminating_subscription = ascii_equal(string_from(method.name), "NOTIFY") &&
                                    get_header(headers, "Subscription-State").starts_with("terminated");
  initialize_auth(*token);
  auto *request_token = token.get();
  send_owned(
      std::move(token), [&] { return pjsip_dlg_send_request(sip_dialog, data.release(), module.id, request_token); },
      "send in-dialog SIP request");
}

//------------------------------------------------------------------------------
// RFC 3261 section 13.2: creates an INVITE dialog with an SDP offer (RFC 3264) and a required session timer
// (RFC 4028) and sends the INVITE; the MCPTT service headers follow TS 24.379 clause 10.1.1.2.1.1 (client) and
// clause 6.3.4.1.2 (server). Returns the dialog id (its Call-ID).
[[nodiscard]] std::string
SipEngine::Impl::create_invite(std::string_view request_uri, const MediaDescription &local_media,
                               const std::vector<BodyPart> &application_parts, SipResponseHandler handler,
                               const std::vector<SipHeader> &headers, const std::string *sdp_text) {
  ensure_started();
  auto local = pj_view(config.identity);
  const auto override_contact = get_header(headers, "Contact");
  const auto contact_text = override_contact.empty() ? contact_uri() : std::string(override_contact);
  auto contact = pj_view(contact_text);
  auto remote = pj_view(request_uri);
  pjsip_dialog *sip_dialog = nullptr;
  require_success(pjsip_dlg_create_uac(pjsip_ua_instance(), &local, &contact, &remote, &remote, &sip_dialog),
                  "create outgoing INVITE dialog");
  const std::string id = string_from(sip_dialog->call_id->id);
  pjsip_inv_session *invite_session = nullptr;
  try {
    if (has_credentials(config)) {
      pjsip_cred_info credential{};
      credential.realm = pj_view("*");
      credential.scheme = pj_view("digest");
      credential.username = pj_view(config.username);
      credential.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
      credential.data = pj_view(config.password);
      require_success(pjsip_auth_clt_set_credentials(&sip_dialog->auth_sess, 1, &credential), "set INVITE credentials");
    }
    auto *local_sdp =
        sdp_text ? parse_sdp_text(sip_dialog->pool, *sdp_text) : parse_local_sdp(sip_dialog->pool, local_media);
    require_success(
        pjsip_inv_create_uac(sip_dialog, local_sdp, PJSIP_INV_SUPPORT_TIMER | PJSIP_INV_REQUIRE_TIMER, &invite_session),
        "create outgoing INVITE session");
    require_success(pjsip_dlg_add_usage(sip_dialog, &ack_module, nullptr), "observe outgoing dialog ACK");
    require_success(pjsip_dlg_add_usage(sip_dialog, &module, nullptr), "handle outgoing call application requests");
    pjsip_timer_setting timer{};
    pjsip_timer_setting_default(&timer);
    timer.sess_expires = config.session_expires;
    require_success(pjsip_timer_init_session(invite_session, &timer), "configure outgoing session timer");
    const auto explicit_route = get_header(headers, "Route");
    if (!explicit_route.empty()) pin_dialog_route(sip_dialog, explicit_route);
    auto entry = std::make_unique<Dialog>();
    entry->id = id;
    entry->dialog = sip_dialog;
    entry->invite = invite_session;
    entry->initial_handler = std::move(handler);
    invite_session->mod_data[module.id] = entry.get();
    dialogs[id] = std::move(entry);
    pjsip_tx_data *created = nullptr;
    require_success(pjsip_inv_invite(invite_session, &created), "create INVITE request");
    TxData data(created);
    data->msg->body = sdp_text ? make_body_with_sdp(data->pool, *sdp_text, application_parts)
                               : make_invite_body(data->pool, local_media, application_parts);
    add_core_route(data.get(), headers);
    // An MCPTT call declares the MCPTT service; a caller that names its own
    // service, such as the MCData media plane, keeps its headers instead.
    if (get_header(headers, "P-Preferred-Service").empty() && get_header(headers, "P-Asserted-Service").empty()) {
      add_header(data.get(),
                 {config.asserts_service ? "P-Asserted-Service" : "P-Preferred-Service", config.service->icsi});
      add_header(data.get(), {"Accept-Contact", std::string("*;+g.3gpp.icsi-ref=\"") + config.service->icsi_encoded +
                                                    "\";+" + config.service->feature_tag + ";require;explicit"});
    }
    add_headers(data.get(), without_route(headers));
    require_success(pjsip_inv_send_msg(invite_session, data.release()), "send INVITE request");
  } catch (...) {
    if (invite_session != nullptr)
      abandon_invite(invite_session, id);
    else
      abandon_dialog(sip_dialog, id, false);
    throw;
  }
  return id;
}

} // namespace mcx
