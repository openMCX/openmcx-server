//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Incoming SIP requests: dispatch of every request to the MCPTT and MCVideo procedures (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19),
// TS 24.481 V19.3.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 and TS 24.281, the server side of their procedures: dispatch an incoming SIP request (from the SIP
// core or from a peer MCPTT/MCVideo server) to the procedure it starts or continues, and answer it. XML
// protection errors are answered first (TS 24.379 clause 6.6.1.4); each branch below names the clause it
// implements. A request that fails with an exception is refused with 403, one from a user without a binding with
// 404 (UnknownUser).
//
// The procedures below answer in `response` (this function's answer, also when they throw), so that an implicit
// affiliation guard they hold sees the final status (TS 24.379 clause 9.2.2.3.11).
SipResponse McServer::incoming(const SipMessage &message) {
  SipResponse response;
  response.status_code = 200;
  // TS 24.379 clauses 6.6.1.4 and 6.6.2.4.2: content that cannot be decrypted is refused.
  if (!message.protection_error.empty()) {
    refuse_unprotectable(message, response);
    return response;
  }
  try {
    const auto peer = message.source_address == core_address_ ? std::string{} : peer_at(message.source_address);
    // Only the SIP core and the configured peer servers are trusted sources.
    if (message.source_address != core_address_ && peer.empty()) {
      response.status_code = 403;
      return response;
    }
    if (message.method == "OPTIONS") return response;
    auto event_name = std::string(get_header(message.headers, "Event"));
    // A request in the dialog of a call relayed by this participating function goes on to the other side.
    if (const auto relay = relays_.find(message.dialog_id); relay != relays_.end())
      return relay_request(message, relay->second, !peer.empty());
    if (const auto relay = conference_relays_.find(message.dialog_id); relay != conference_relays_.end())
      return relay_conference(message, relay->second, !peer.empty());
    if (message.method == "BYE") ambient_bye_from_participant(message);
    // Requests from a peer MCPTT/MCVideo server (another function of this system).
    if (!peer.empty() && peer_request(message, peer, event_name, response)) return response;
    if (message.method == "PUBLISH" && event_name == "poc-settings") {
      if (get_header(message.headers, "Expires") == "0") service_log_off(message, response); // clause 7.3.5
      else service_authorization(message, response);
      return response;
    }
    // TS 24.379 clause 7.3.2: the SIP core's third-party REGISTER (a REGISTER reaches a server only from the core).
    if (message.method == "REGISTER" && peer.empty()) {
      third_party_register(message, response);
      return response;
    }
    // BYE outside a relayed call: only the leg's own user may end it.
    if (message.method == "BYE") {
      const auto found = legs_.find(message.dialog_id);
      const auto *owner = found == legs_.end() ? nullptr : by_id(found->second->user);
      if (!owner || owner->sip != message.from_uri) response.status_code = 481;
      return response;
    }
    // TS 24.379 clause 13.2.4.1: a location information report from a local client.
    if (message.method == "MESSAGE" && peer.empty())
      if (auto handled = location_.from_client(message)) return *handled;
    // TS 24.481 clause 6.3.13.2.2: an MCS server of this system (its PSI asserted by the SIP core)
    // subscribing to group documents, or changing the list of its subscription.
    if (message.method == "SUBSCRIBE" && event_name == "xcap-diff")
      if (const auto identity = asserted_identity(message); is_mcs_server(identity)) {
        server_document_subscribe(message, identity, response);
        return response;
      }
    auto &user = authenticated(message);
    user_request(message, user, event_name, response);
    return response;
  } catch (const CapacityReached &error) {
    // TS 24.379 clause 11.1.1.3.1.1 step 1 (clause 10.1.1.3.1.1 for group calls): lack of resources.
    event("sip_request_rejected", {{"method", message.method}, {"reason", error.what()}});
    event("call_rejected_capacity", {{"method", message.method}, {"retry_after", capacity_retry_after()}});
    response.status_code = 500;
    response.reason = "Server Internal Error";
    response.headers.push_back({"Retry-After", std::to_string(capacity_retry_after())});
    return response;
  } catch (const UnknownUser &error) {
    // TS 24.379 clause 10.1.1.3.1.1 step 2a (and the same step of every originating procedure), TS 24.281 clause
    // 10.1.1.3.1.1: no binding between the public user identity and an MC service ID, or an expired one.
    event("sip_request_rejected", {{"method", message.method}, {"reason", error.what()}});
    response.status_code = 404;
    response.headers = {{"Warning", warning_value(warn(Warning::unknown_user))}};
    return response;
  } catch (const std::exception &error) {
    event("sip_request_rejected", {{"method", message.method}, {"reason", error.what()}});
    response.status_code = 403;
    return response;
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.6.1.4 and 6.6.2.4.2: a request whose content cannot be verified or decrypted is refused with
// 403 and Warning 139 (failed integrity check, clause 6.6.3.4.2) or 140 (decryption, clause 6.6.2.4.2).
void McServer::refuse_unprotectable(const SipMessage &message, SipResponse &response) {
  ++xml_refused_;
  event("xml_refused", {{"method", message.method}, {"reason", message.protection_error}});
  response.status_code = 403;
  // TS 24.379 clause 6.6.3.4.2: 139 for a failed integrity check; TS 24.379 clause 6.6.2.4.2: 140 for
  // decryption.
  response.headers = {{"Warning", message.protection_error.starts_with("139")
                                      ? warning_value(warn(Warning::integrity_check_failed))
                                      : warning_value(warn(Warning::decrypt_failed))}};
}

//------------------------------------------------------------------------------
// A request from a peer MCPTT/MCVideo server (another function of this system): location (TS 24.379 clauses
// 13.2.3.3 and 13.2.4.2) signalling, affiliation and functional alias changes, regroup requests (TS 24.379
// clause 16), and the terminating participating function for the users served here. Returns true when `response` is
// the answer; false when the request goes on to the procedures for local requests.
bool McServer::peer_request(const SipMessage &message, const std::string &peer, const std::string &event_name,
                            SipResponse &response) {
  // TS 24.379 clauses 13.2.3.3 and 13.2.4.2: location signalling from another MCPTT server.
  if (message.method == "MESSAGE")
    if (auto handled = location_.from_peer(message, peer)) {
      response = std::move(*handled);
      return true;
    }
  if (message.method == "PUBLISH" && event_name == "presence" && peer_presence_publish(message, peer, response))
    return true;

  // TS 24.379 clauses 9A.2.2.3.4 and 9A.2.2.2.7: a serving server's subscription to a user's status for an alias,
  // and the owning server's NOTIFY to this serving server.
  if (message.method == "SUBSCRIBE" && event_name == "presence" &&
      (peer_alias_subscriptions_.contains(message.dialog_id) ||
       std::any_of(message.parts.begin(), message.parts.end(),
                   [](const BodyPart &part) { return part.content_type == simple_filter_mime; }))) {
    response = owned_alias_subscribe(message, peer);
    return true;
  }
  if (message.method == "NOTIFY" && alias_upstream_.contains(message.dialog_id)) {
    response = owner_alias_notify(message);
    return true;
  }
  // TS 24.379 clause 16: a regroup request from another MCPTT function asserts that
  // function's identity; one relayed for a user asserts the user's. A
  // notice addressed to a user served here is passed on to that user below.
  if (message.method == "MESSAGE")
    if (const auto *regroup = regroup_part(message)) {
      if (const auto target = users_.find(message.request_uri);
          target == users_.end() || !target->second.peer.empty()) {
        const auto user = users_.find(asserted_identity(message));
        if (user == users_.end() || user->second.peer != peer) {
          response = regroup_from_function(peer, *regroup, regroup_carry(message));
          return true;
        }
      }
    }
  if (terminating_request(message, peer, response)) return true;
  if (message.method == "PUBLISH" || (message.method == "SUBSCRIBE" && event_name != "conference")) {
    response.status_code = 403;
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3: a group affiliation status change from a participating function, or a served user's
// functional alias activation passed on by its participating server to this owning server (TS 24.379 clause
// 9A.2.2.3). Returns true when `response` is the answer.
bool McServer::peer_presence_publish(const SipMessage &message, const std::string &peer, SipResponse &response) {
  // A served user's functional alias activation, passed on by its
  // participating server to this owning server (TS 24.379 clause 9A.2.2.3).
  const bool alias = std::any_of(message.parts.begin(), message.parts.end(), [](const BodyPart &part) {
    return part.content_type == "application/pidf+xml" && is_functional_alias_pidf(part.body);
  });
  // TS 24.379 clause 9.2.2.3.3: a group affiliation status change from a participating function.
  if (!alias) {
    response = peer_registration_.receive(message, peer);
    return true;
  }
  // TS 24.379 clause 9A.2.2.3.3: a serving server's status change of one user for one alias.
  if (role_ == "participating") {
    response.status_code = 403;
    return true;
  }
  response = owned_alias_publish(message, peer);
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.3.2.1.2 and the terminating participating function: an INVITE or MESSAGE from a peer server
// for a user served here goes on to that user. Returns true when `response` is the answer.
bool McServer::terminating_request(const SipMessage &message, const std::string &peer, SipResponse &response) {
  // An ad hoc group call's invitation to a user served here that the inviting
  // system addressed to this system's PSI (TS 24.379 clause 17.3.2.1.2).
  if (message.method == "INVITE" && !legs_.contains(message.dialog_id) && message.request_uri == own_service_uri())
    if (const auto info = message_info(message, svc_); info.session_type == "adhoc" && !info.calling_group.empty())
      if (const auto *invited = by_id(info.request_uri); invited && invited->peer.empty()) {
        response = relay_incoming(message, peer, *invited);
        return true;
      }
  // A request for a user served here: this server's terminating participating function.
  if ((message.method == "INVITE" || message.method == "MESSAGE") && !legs_.contains(message.dialog_id))
    if (const auto local = users_.find(message.request_uri); local != users_.end() && local->second.peer.empty()) {
      if (message.method == "INVITE") {
        response = relay_incoming(message, peer, local->second);
        return true;
      }
      if (const auto *regroup = regroup_part(message))
        regroup_relayed(peer, *regroup);
      else
        remember_service_mapping(local->second.id, message_info(message, svc_));
      response = relay_message(message, local->second.sip, {});
      return true;
    }
  return false;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.3 (TS 24.281 clause 7.3.3) with TS 24.379 clause 6.6.2: service authorisation, a PUBLISH of
// poc-settings carrying the access token and client ID; the token is checked against IdMS's keys (TS 33.180
// clause 5.1.2, annex B.11.2) before the user is bound.
void McServer::service_authorization(const SipMessage &message, SipResponse &response) {
  // TS 24.379 clause 7.3.3 (TS 24.281 clause 7.3.3) with TS 24.379 clause 6.6.2: service authorisation.
  // The access token and client ID may be encrypted
  // with the CSK this request uploads, which is accepted first.
  std::optional<keying::KeyMessage> uploaded;
  std::string uploader;
  SipMessage opened = message;
  if (!open_with_uploaded_csk(message, opened, uploaded, uploader, response)) return;
  const auto &request = opened;
  auto info = message_info(request, svc_);
  auto asserted = asserted_identity(request);
  if (asserted.empty() || asserted != request.from_uri || info.access_token.empty() || info.client_id.empty()) {
    response.status_code = 403;
    return;
  }
  const auto checked = service_claims(tokens_, info.access_token, svc_, asserted, info.client_id);
  if (!checked) {
    // TS 24.379 clause 7.3.3 step 6, TS 24.281 clause 7.3.3 step 6.
    response.status_code = 403;
    response.headers = {{"Warning", warning_value(warn(Warning::service_authorisation_failed))}};
    return;
  }
  const auto &claims = *checked;

  // An OpenMCX token's subject is the MCPTT ID; an MCVideo server binds the token's MCVideo ID instead
  // (token_subject_valid). TS 33.180 table B.2.2.2-1 has no subject: another IdMS's token is not checked for it.
  if (openmcx_token(claims) && !token_subject_valid(claims)) throw std::runtime_error("access token subject mismatch");
  const auto id = claims.at(svc_.id_claim).get<std::string>();
  const auto now = std::time(nullptr);
  // A binding whose service authorisation has ended (clause 7.3.3 step 8) binds nothing any more: it goes, and the
  // user is authorised as if it had never been there.
  std::vector<std::string> ended;
  for (const auto &[sip, user] : users_)
    if (user.peer.empty() && user.expires <= now && (sip == asserted || user.id == id)) ended.push_back(sip);
  for (const auto &sip : ended) remove_binding(users_.find(sip), "service authorisation ended");
  auto old = users_.find(asserted);
  // The public user identity is bound to another MC service ID (another user still authorised with it), or is a user
  // served by a peer server.
  if (old != users_.end() &&
      (old->second.id != id || (!old->second.peer.empty() && old->second.client != info.client_id)))
    throw std::runtime_error("live authorization identity remapping refused");
  // Clause 7.3.3 steps 3a and 3b: the user is already authorised on another MCPTT client (another client ID, or
  // another public user identity). The present edition keeps one binding per MC service ID: the CMS's service
  // configuration document sets <max-simultaneous-authorizations> to 1 and refuses a user profile with a higher
  // <user-max-simultaneous-authorizations>, so another live authorisation means that the maximum is reached
  // (clause 7.3.3 step 5b, a second binding, is not in the present edition).
  for (const auto &[sip, user] : users_)
    if (user.peer.empty() && user.id == id && (sip != asserted || user.client != info.client_id)) {
      event("service_authorization_refused",
            {{"user_id", id}, {"client_id", info.client_id}, {"reason", "maximum number of service authorizations"}});
      response.status_code = 486;
      response.headers = {{"Warning", warning_value(warn(Warning::max_authorizations))}};
      return;
    }
  auto match = get_header(request.headers, "SIP-If-Match");

  // TS 24.379 clause 7.3.3 steps 5 and 7: the user is bound before the PUBLISH is processed by RFC 3903, so a
  // SIP-If-Match that names no publication of this server (RFC 3903 section 6 step 3) is answered 412 after the
  // binding.
  const bool unknown_etag = !match.empty() && (old == users_.end() || match != old->second.auth_etag);
  std::string profile; // MCPTT-2 only
  if (diameter_) {
    profile = diameter_->pull(claims.at(svc_.id_claim).get<std::string>());
    if (profile.empty()) throw std::runtime_error("empty Diameter user profile");
  }
  bind_authorized_user(claims, info, asserted, old, match, unknown_etag, uploaded, uploader, profile, response);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.2 (TS 24.281 clause 7.3.2): service authorisation from the REGISTER the client sent, which
// the SIP core includes as a message/sip body in a third-party REGISTER (TS 24.229 clause 5.4.1.7). The REGISTER's
// application/vnd.3gpp.mcptt-info+xml (access token, client ID; the CSK upload of TS 33.180 clause 9.2.1.3 with
// it) is authorised as a service authorisation PUBLISH is (steps 3, 4 and 4a; clause 7.3.3). A third-party REGISTER
// with Expires 0 is a deregistration: the user's binding ends.
void McServer::third_party_register(const SipMessage &message, SipResponse &response) {
  // Step 1: the IMS public user identity is the To of the third-party REGISTER.
  const auto identity = message.to_uri;
  if (identity.empty()) {
    response.status_code = 400;
    return;
  }
  const auto expires = std::string(get_header(message.headers, "Expires"));
  if (expires == "0") {
    remove_binding(users_.find(identity), "deregistration");
    response.headers = {{"Expires", "0"}};
    return;
  }
  // The client's REGISTER (RFC 3420): its body parts, without which there is nothing to authorise.
  std::vector<BodyPart> parts;
  for (const auto &part : parts_of(message))
    if (part.content_type == "message/sip") parts = parse_sip_fragment_parts(part.body);
  const bool has_info =
      std::any_of(parts.begin(), parts.end(), [&](const auto &part) { return part.content_type == svc_.info_mime; });
  if (!has_info) {
    response.headers = {{"Expires", expires.empty() ? "3600" : expires}};
    return;
  }
  // TS 24.379 clause 7.2.1 (TS 24.281 clause 7.2.1) with clause 6.6.1.4: under confidentiality or integrity
  // protection the REGISTER's access token and client ID are encrypted and its mcptt-info signed with the CSK. A
  // REGISTER that uploads the CSK is opened with it (service_authorization); one that uploads none, a renewal of the
  // authorisation, is opened with the CSK this server holds for the public user identity. The bodies of the
  // client's REGISTER reach the server inside the message/sip body, past the SIP body filters.
  if (std::none_of(parts.begin(), parts.end(),
                   [](const auto &part) { return part.content_type == "application/mikey"; }))
    if (!open_register_parts(identity, parts, response)) return;
  SipMessage inner = message;
  inner.method = "PUBLISH";
  inner.from_uri = identity;
  inner.content_type = "multipart/mixed";
  inner.body.clear();
  inner.parts = std::move(parts);
  inner.headers = {{"P-Asserted-Identity", "<" + identity + ">"}};
  // A re-registration of the same client refreshes the binding without ending its calls (step 4a), as a
  // publication refresh does.
  if (const auto found = users_.find(identity); found != users_.end() && !found->second.auth_etag.empty())
    inner.headers.push_back({"SIP-If-Match", found->second.auth_etag});
  service_authorization(inner, response);
  if (response.status_code != 200) return;
  // A REGISTER has no entity tag (RFC 3903 is for PUBLISH); the expiry is the registration's.
  response.headers = {{"Expires", expires.empty() ? "3600" : expires}};
  event("service_authorized_by_register", {{"user", identity}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.1.4 for the bodies of a client's REGISTER without a CSK upload: the signatures verified
// (clause 6.6.3.4.2) and the protected content decrypted (clause 6.6.2.4.2) with the CSK held for the public user
// identity. Returns false when the REGISTER is refused in `response` (403 with Warning 139 or 140).
bool McServer::open_register_parts(const std::string &identity, std::vector<BodyPart> &parts, SipResponse &response) {
  const auto key = user_xml_key(identity);
  try {
    parts = verify_parts(std::move(parts), key);
  } catch (const std::exception &) {
    response.status_code = 403;
    response.headers = {{"Warning", warning_value(warn(Warning::integrity_check_failed))}};
    return false;
  }
  for (auto &part : parts) {
    if (!mcptt_xml_part(part.content_type) || !xmlsec::is_protected(part.body)) continue;
    try {
      const auto id = xmlsec::key_id(part.body);
      if (!key || !id || *id != key->id) throw std::runtime_error("no XPK for the protected content");
      part.body = xmlsec::decrypt(part.body, *key);
      ++xml_decrypted_;
    } catch (const std::exception &) {
      ++xml_refused_;
      response.status_code = 403;
      response.headers = {{"Warning", warning_value(warn(Warning::decrypt_failed))}};
      return false;
    }
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2 (TS 33.180 clause 9.3): a service authorisation request may upload the client's CSK and
// protect its access token and client ID with it. Accept the CSK, verify the integrity of the parts and decrypt
// them into `opened`. Returns false when the request is refused in `response` (Warning 139 or 140).
bool McServer::open_with_uploaded_csk(const SipMessage &message, SipMessage &opened,
                                      std::optional<keying::KeyMessage> &uploaded, std::string &uploader,
                                      SipResponse &response) {
  if (keys_)
    for (const auto &part : parts_of(message))
      if (part.content_type == "application/mikey") {
        if (uploaded) throw std::runtime_error("duplicate CSK");
        uploader = KeyClient::initiator(part.body);
        uploaded = keys_->accept_csk(uploader, part.body);
      }
  if (uploaded) {
    const xmlsec::Key key{uploaded->key, uploaded->csb_id, uploader};
    opened.parts = parts_of(message);
    try {
      opened.parts = verify_parts(std::move(opened.parts), key);
    } catch (const std::exception &) {
      response.status_code = 403;
      response.headers = {{"Warning", warning_value(warn(Warning::integrity_check_failed))}};
      return false;
    }
    try {
      for (auto &part : opened.parts)
        if (mcptt_xml_part(part.content_type) && xmlsec::is_protected(part.body)) {
          part.body = xmlsec::decrypt(part.body, key);
          ++xml_decrypted_;
        }
    } catch (const std::exception &) {
      ++xml_refused_;
      response.status_code = 403;
      response.headers = {{"Warning", warning_value(warn(Warning::decrypt_failed))}};
      return false;
    }
    if (opened.parts.size() == 1) opened.body = opened.parts.front().body;
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.5 (TS 24.281 clause 7.3.5): a SIP PUBLISH for poc-settings with Expires 0 logs the MCPTT client
// off (clause 7.2.1A NOTE 3). The public user identity is the asserted one (step 1). RFC 3903 (step 2): a removal
// names the publication in SIP-If-Match (section 4.5); one that names no publication of the user is answered 412
// (section 6 step 3), a request with neither entity tag nor body 400 (section 6 step 5), and a single entity tag only
// (400). Then the service settings and the binding go (steps 3 and 4, remove_binding) and the answer is 200 (step 5)
// with Expires 0 and the publication's entity tag (RFC 3903 section 6 step 6).
void McServer::service_log_off(const SipMessage &message, SipResponse &response) {
  const auto asserted = asserted_identity(message);
  if (asserted.empty() || asserted != message.from_uri) {
    response.status_code = 403;
    return;
  }
  const auto match = std::string(get_header(message.headers, "SIP-If-Match"));
  auto found = users_.find(asserted);
  if (found != users_.end() && !found->second.peer.empty()) found = users_.end();
  if (match.find(',') != std::string::npos || (match.empty() && message.body.empty() && message.parts.empty())) {
    response.status_code = 400;
    return;
  }
  if (!match.empty() && (found == users_.end() || match != found->second.auth_etag)) {
    response.status_code = 412;
    return;
  }
  if (found != users_.end()) {
    event("service_logged_off", {{"user_id", found->second.id}, {"client_id", found->second.client}});
    remove_binding(found, "log-off");
  }
  response.headers = {{"Expires", "0"}, {"SIP-ETag", match.empty() ? random_id() : match}};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.5 steps 3 and 4 (TS 24.281 clause 7.3.5), and clause 7.3.3 step 8 when the service
// authorisation ends: the served user's service settings end, with all its affiliations (TS 23.280 clause 10.8: the
// affiliation status subscription is terminated, RFC 6665 section 4.2.2), its functional aliases, calls and relays,
// and its controllers learn that it is no longer served here; then the binding of its MC service ID, client ID and
// public user identity is removed.
void McServer::remove_binding(std::map<std::string, User>::iterator found, const char *reason) {
  if (found == users_.end()) return;
  auto &user = found->second;
  const auto id = user.id;
  user.expires = 0;
  user.groups.clear();
  if (!user.subscription.empty() && user.subscription_expires > std::time(nullptr))
    sip_.notify(user.subscription, "presence", "terminated;reason=noresource", "application/pidf+xml",
                affiliation_xml(affiliation_status(svc_, user, {}), true));
  user.subscription.clear();
  deactivate_functional_aliases(id);
  disconnect_user(id);
  end_user_relays(id);
  register_with_controllers(user, true);
  event("service_binding_removed", {{"user_id", id}, {"client_id", user.client}, {"reason", reason}});
  users_.erase(found);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.3 (TS 24.281 clause 7.3.3): bind the service authorised user (its MCPTT ID from the
// checked token, its client ID and its SIP identity) with its uploaded CSK (step 5), then process the PUBLISH
// by RFC 3903 (step 7): a SIP-If-Match naming no publication is answered 412 and leaves no publication, and the
// client's new publication (RFC 3903 section 5) then keeps the binding.
void McServer::bind_authorized_user(const Json &claims, const McpttInfo &info, const std::string &asserted,
                                    std::map<std::string, User>::iterator old, std::string_view match,
                                    bool unknown_etag, const std::optional<keying::KeyMessage> &uploaded,
                                    const std::string &uploader, const std::string &profile, SipResponse &response) {
  User user;
  if (old != users_.end() && (!match.empty() || old->second.auth_etag.empty()))
    user = old->second;
  else if (old != users_.end()) {
    auto id = old->second.id;
    schedule([this, id] {
      disconnect_user(id);
      end_user_relays(id);
    });
  }
  user.id = claims.at(svc_.id_claim);
  user.client = info.client_id;
  user.sip = asserted;
  user.expires = claims.at("exp");
  if (uploaded) {
    // The CSK was signed by the MCPTT ID the access token names.
    if (uploader != user.id) throw std::runtime_error("CSK uploaded by another identity");
    // The floor or transmission control keys of a call service (configured_service refuses MCData).
    if (!user.protection) user.protection = std::make_shared<ProtectedCall>(svc_.service == Service::mcvideo);
    user.protection->set_floor(*uploaded);
    user.csk = uploaded;
  }
  const bool fresh = old == users_.end();
  if (!unknown_etag) user.auth_etag = random_id();
  users_[asserted] = user;
  if (fresh || !unknown_etag)
    schedule([this, sip = asserted] {
      if (const auto found = users_.find(sip); found != users_.end()) register_with_controllers(found->second);
    });
  if (unknown_etag) {
    response.status_code = 412;
    event("service_publication_unknown", {{"user_id", user.id}});
    return;
  }
  response.headers = {{"SIP-ETag", user.auth_etag}, {"Expires", "4294967295"}};
  event("service_authorized", {{"user_id", user.id}, {"profile_bytes", profile.size()}});
  // TS 24.379 clause 14.2.2.1: when and to whom the bearers are announced is local policy: to a served user on
  // the list after each service authorisation (src/server/mbms.cpp).
  schedule([this, sip = asserted] {
    if (const auto found = users_.find(sip); found != users_.end()) mbms_announce(found->second);
  });

  // TS 24.379 clause 13.2.2: location reporting is configured upon successful service authorisation.
  schedule([this, id = user.id] { location_.configure(id); });
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.2.2: an MCS server of this system (its PSI asserted by the SIP core) subscribes to group
// documents, or changes the list of its subscription in the dialog.
void McServer::server_document_subscribe(const SipMessage &message, const std::string &identity,
                                         SipResponse &response) {
  if (refresh_document_subscription(message, response)) return;
  std::vector<std::string> groups;
  for (const auto &part : message.parts)
    if (part.content_type == resource_lists_mime) groups = subscribed_groups(part.body);
  if (groups.empty()) {
    response.status_code = 400;
    return;
  }
  response = doc_subscribe(message, identity, groups, true);
}

//------------------------------------------------------------------------------
// A request from an authenticated served user: document and key subscriptions (TS 24.481 clauses 6.3.13.3.2.2 and
// 7.7, TS 24.484 clause 6.3.13.3.2.2), conference subscription (TS 24.379 clause 10.1.3.4.1), functional alias and
// affiliation status (TS 24.379 clauses 9A.2.2 and 9.2), SIP MESSAGE services and INVITE; anything else 405.
void McServer::user_request(const SipMessage &message, User &user, const std::string &event_name,
                            SipResponse &response) {
  // TS 24.481 clause 6.3.13.3.2.2 and TS 24.484 clause 6.3.13.3.2.2: a client's subscription to group documents
  // or to configuration documents (xcap-diff), new or in its dialog.
  // TS 24.481 clause 7.7: a group member's subscription to the group's GKTP document (its group key).
  if (message.method == "SUBSCRIBE" && event_name == "xcap-diff") {
    if (!client_document_subscribe(message, user, response)) key_subscribe(message, user, response);
    return;
  }
  // TS 24.379 clause 10.1.3.4.1: a participant's subscription to the conference event package of its call.
  if (message.method == "SUBSCRIBE" && event_name == "conference") return conference_subscribe(message, user, response);
  if (message.method == "SUBSCRIBE" && event_name == "presence" && alias_status_subscribe(message, user, response))
    return;
  // TS 24.379 clause 9.2.1.3: subscription to the user's affiliation status (Expires 0 ends it).
  if (message.method == "SUBSCRIBE") return affiliation_subscribe(message, user, event_name, response);
  // TS 24.379 clause 9.2.2.2.3: affiliation status change from a client (or a functional alias activation).
  if (message.method == "PUBLISH" && event_name == "presence") return affiliation_publish(message, user, response);
  // SIP MESSAGE from a served user: regroup, private call services, functional alias binding, ad hoc alerts and
  // group emergency alerts.
  if (message.method == "MESSAGE") return user_message(message, user, response);
  // INVITE from a served user or a peer function: call setup and re-INVITE.
  if (message.method == "INVITE") return invite_request(message, user, response);
  response.status_code = 405;
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.3.2.2 and TS 24.484 clause 6.3.13.3.2.2: a client's subscription to group documents or
// to configuration documents (xcap-diff), new or in its dialog. Returns false when the request is neither (a GKTP
// subscription).
bool McServer::client_document_subscribe(const SipMessage &message, const User &user, SipResponse &response) {
  if (refresh_document_subscription(message, response)) return true;
  for (const auto &part : message.parts) {
    if (part.content_type != resource_lists_mime) continue;
    const auto groups = subscribed_groups(part.body);
    const auto configuration = groups.empty() ? subscribed_configuration(part.body) : std::vector<ConfigDocument>{};
    if (groups.empty() && configuration.empty()) continue;
    // TS 24.481 clause 6.3.13.3.2.2 step c and TS 24.484 clause 6.3.13.3.2.2 step c: the identity is that of the
    // access token.
    const auto claims = tokens_.verify(message_info(message, svc_).access_token, svc_);
    if (!claims || claims->value(svc_.id_claim, "") != user.id) {
      response.status_code = 403;
      return true;
    }
    response =
        groups.empty() ? config_subscribe(message, user.id, configuration) : doc_subscribe(message, user.id, groups);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.1.2 (TS 24.481 clause 6.3.13.3.2.2, TS 24.484 clause 6.3.13.3.2.2): a re-SUBSCRIBE in the
// dialog of a group or configuration document subscription refreshes it, or ends it with Expires 0 (the final
// NOTIFY follows). Returns false when the dialog is neither subscription's; a malformed Expires is answered 400.
// TS 24.481 clauses 6.3.13.2.1 and 6.3.13.2.2: a resource list in a group document re-SUBSCRIBE is the modified list,
// one entry for each document to be subscribed to: it replaces the subscribed groups (one left out is no longer
// followed), checked as at the initial SUBSCRIBE. RFC 5875 section 4.7: the notifier "MUST re-send the current full XML
// diff content" on a re-subscription (no conditional subscription is offered), so every re-SUBSCRIBE that does not end
// the subscription is notified again with the full state, like the initial one.
bool McServer::refresh_document_subscription(const SipMessage &message, SipResponse &response) {
  const auto documents = doc_subscriptions_.find(message.dialog_id);
  const auto configuration = config_subscriptions_.find(message.dialog_id);
  if (documents == doc_subscriptions_.end() && configuration == config_subscriptions_.end()) return false;
  const auto expires = refreshed_expires(message);
  if (!expires) {
    response.status_code = 400;
    return true;
  }
  const auto until = std::time(nullptr) + static_cast<std::time_t>(*expires);
  if (documents != doc_subscriptions_.end()) {
    auto &sub = documents->second;
    bool listed = false;
    std::vector<std::string> groups;
    for (const auto &part : message.parts)
      if (part.content_type == resource_lists_mime) {
        listed = true;
        groups = subscribed_groups(part.body);
      }
    if (listed && *expires != 0) {
      if (groups.empty()) {
        response.status_code = 400;
        return true;
      }
      // TS 24.481 clause 6.3.13.3.2.2 step d, as at the initial SUBSCRIBE: 403 only when no listed document may be
      // followed (the subscription is then left as it was); one that may not is left out.
      std::map<std::string, std::string> etags;
      std::vector<std::string> followed;
      for (const auto &group : groups) {
        if (!(sub.server ? group_exists(group) : subscription_allowed(group, sub.subscriber))) {
          docsub_count("refused");
          event("group_document_subscription_refused", {{"subscriber", sub.subscriber}, {"group", group}});
          continue;
        }
        const auto kept = sub.etags.find(group);
        etags[group] = kept == sub.etags.end() ? std::string{} : kept->second;
        followed.push_back(group);
      }
      if (etags.empty()) {
        response.status_code = 403;
        return true;
      }
      sub.etags = std::move(etags);
      event("group_document_subscription_changed", {{"subscriber", sub.subscriber}, {"groups", followed}});
    }
    sub.expires = until;
    if (*expires != 0) sub.initial = true;
    schedule([this, id = message.dialog_id] { notify_documents(id); });
  } else {
    // TS 24.484 clause 6.3.13.3.2.2 (re-SUBSCRIBE): a resource list is the modified list of documents, checked as at
    // the initial SUBSCRIBE (followed_configuration); 403 when none of them may be followed.
    auto &sub = configuration->second;
    for (const auto &part : message.parts)
      if (part.content_type == resource_lists_mime && *expires != 0) {
        const auto documents = subscribed_configuration(part.body);
        auto etags =
            documents.empty() ? decltype(sub.etags){} : followed_configuration(sub.subscriber, documents, &sub);
        if (documents.empty() || etags.empty()) {
          response.status_code = documents.empty() ? 400 : 403;
          return true;
        }
        sub.etags = std::move(etags);
      }
    sub.expires = until;
    if (*expires != 0) sub.initial = true;
    schedule([this, id = message.dialog_id] { notify_configuration(id); });
  }
  // RFC 6665 section 4.2.1.1: the 200 (OK) carries the duration granted.
  response.headers = {{"Expires", std::to_string(*expires)}};
  return true;
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.1.2 with RFC 3261 section 20.19: the duration a re-SUBSCRIBE asks for, the default of this
// server without Expires, or std::nullopt when its Expires is malformed.
std::optional<std::uint64_t> McServer::refreshed_expires(const SipMessage &message) {
  const auto text = get_header(message.headers, "Expires");
  if (text.empty()) return default_subscription_s;
  return parse_expires(text);
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.7: a group member's subscription to the group's GKTP document (its group key), checked against
// the access token and the group membership.
void McServer::key_subscribe(const SipMessage &message, const User &user, SipResponse &response) {
  const auto info = message_info(message, svc_);
  if (!keys_ || info.client_id != user.client || info.access_token.empty() ||
      message.request_uri != cfg_.at(svc_.name).at("service_uri").get<std::string>()) {
    response.status_code = 403;
    return;
  }
  const auto claims = tokens_.verify(info.access_token, svc_);
  if (!claims || claims->value(svc_.id_claim, "") != user.id ||
      (openmcx_token(*claims) && claims->value("mc_client_id", "") != user.client) ||
      !member(group_profile(info.request_uri), user.id)) {
    response.status_code = 403;
    return;
  }
  const BodyPart *resources = nullptr;
  for (const auto &part : message.parts)
    if (part.content_type == "application/resource-lists+xml") {
      if (resources) throw std::runtime_error("duplicate resources");
      resources = &part;
    }
  if (!resources) throw std::runtime_error("missing key resource selector");
  keying::validate_gktp_resource_list(resources->body, info.request_uri);

  // RFC 3261 section 20.19: a missing or malformed Expires is a bad request (400), as is one above the
  // subscription limit of this server.
  const auto expiry = parse_expires(get_header(message.headers, "Expires"));
  if (!expiry || *expiry > max_subscription_s || key_subscriptions_.size() >= max_subscriptions) {
    response.status_code = 400;
    return;
  }
  key_subscriptions_[message.dialog_id] = {user.id, info.request_uri, message.dialog_id,
                                           std::time(nullptr) + static_cast<std::int64_t>(*expiry)};
  response.headers = {{"Expires", std::to_string(*expiry)}};
  schedule([this, id = message.dialog_id] { notify_key(id); });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.3.4.1: a participant's subscription to the conference event package of its call (relayed
// when the call is controlled elsewhere).
void McServer::conference_subscribe(const SipMessage &message, const User &user, SipResponse &response) {
  if (const auto alias = session_aliases_.find(message.request_uri);
      alias != session_aliases_.end() && user.peer.empty()) {
    if (!accepts_mcptt(message)) {
      response.status_code = 403;
      return;
    }
    response = relay_subscription(message, user, alias->first, alias->second);
    return;
  }
  const auto info = message_info(message, svc_);
  auto found = sessions_.find(info.request_uri);
  if (found == sessions_.end() || found->second->uri != message.request_uri) {
    response.status_code = 404;
    return;
  }
  const auto session = found->second;
  if (!has_leg(*session, user.id) || (!info.calling_user.empty() && info.calling_user != user.id) ||
      !accepts_mcptt(message)) {
    response.status_code = 403;
    return;
  }
  if (get_header(message.headers, "Accept").find("application/conference-info+xml") == std::string_view::npos) {
    response.status_code = 406;
    return;
  }
  if (session->broadcast) {
    response.status_code = 480;
    response.headers = {{"Warning", warning_value(warn(Warning::broadcast_subscription))}};
    return;
  }
  if (!policy_allows(session->policy, "conference_members", user.id)) {
    response.status_code = 403;
    response.headers = {{"Warning", warning_value(warn(Warning::conference_subscription_not_allowed))}};
    return;
  }
  // RFC 6665 section 4.1.2.1: without Expires the subscription lasts the default; a malformed one is a bad request.
  const auto expiry = refreshed_expires(message);
  if (!expiry) {
    response.status_code = 400;
    return;
  }
  auto &subscription = session->subscriptions[message.dialog_id];
  subscription.user = user.id;
  subscription.dialog = message.dialog_id;
  subscription.expires = std::time(nullptr) + static_cast<std::int64_t>(*expiry);
  response.headers = {{"Expires", std::to_string(*expiry)}};
  schedule([this, session] { notify_conference(session); });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2: functional alias status determination, new or in its dialog. Returns false for the
// affiliation status subscription (TS 24.379 clause 9.2.1.3), which has no info body.
bool McServer::alias_status_subscribe(const SipMessage &message, const User &user, SipResponse &response) {
  // TS 24.379 clause 9A.2.2: functional alias status determination, new or in its dialog, apart from the
  // affiliation status subscription below.
  // The affiliation status subscription (TS 24.379 clause 9.2.1.3) has no info body.
  McpttInfo info;
  try {
    info = message_info(message, svc_);
  } catch (const std::exception &) {
    // No (or no valid) info body: the affiliation status subscription, decided below by its event package.
  }
  auto req_type = info.service.contains("req-type") ? info.service.at("req-type") : std::string{};
  // TS 24.379 clauses 9A.2.1.3 step 2 and 9A.2.2.2.4: MCPTT carries "functional-alias-status-determination" in
  // <request-type> (annex F.1.3); MCVideo in <req-type> (TS 24.281 clause 20.2.1.3 step 2).
  if (svc_.service == Service::mcptt && req_type == "functional-alias-status-determination") req_type.clear();
  if (svc_.service == Service::mcptt && info.service.contains("request-type") &&
      info.service.at("request-type") == "functional-alias-status-determination")
    req_type = info.service.at("request-type");
  if (alias_subscriptions_.contains(message.dialog_id) || req_type == "functional-alias-status-determination" ||
      req_type == "fa-user-status-determination") {
    response = alias_subscribe(message, user, info, req_type);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.1.3 and 9.2.2.2.4: subscription to the user's affiliation status; any other event package is
// refused with 489. Expires 0 ends the subscription in its dialog, or out of it fetches the current state (clause
// 9.2.1.3 step 5): either way one final NOTIFY with the current state on its own dialog. The subscription only carries
// the notifications: ending it leaves the affiliations as they are (clause 9.2.2.2.4).
void McServer::affiliation_subscribe(const SipMessage &message, User &user, const std::string &event_name,
                                     SipResponse &response) {
  if (event_name != "presence") {
    response.status_code = 489;
    return;
  }
  // TS 24.379 clause 9.2.2.2.4 steps 1 to 4: the mcptt-info names the served user (<mcptt-request-uri>); no user is
  // authorised for another user's affiliation status. A SUBSCRIBE without the mcptt-info is the subscriber's own.
  if (user.subscription != message.dialog_id && !message.body.empty()) {
    std::string served;
    try {
      served = message_info(message, svc_).request_uri;
    } catch (const std::exception &) {
      served.clear(); // a body without the service info names no other user
    }
    if (!served.empty() && served != user.id) {
      response.status_code = 403;
      return;
    }
  }
  if (get_header(message.headers, "Expires") == "0") {
    if (user.subscription == message.dialog_id) {
      user.subscription.clear();
      user.subscription_expires = 0;
    }
    response.headers = {{"Expires", "0"}};
    schedule([this, id = user.id, dialog = message.dialog_id] {
      if (const auto *served = by_id(id))
        sip_.notify(dialog, "presence", "terminated;reason=timeout", "application/pidf+xml",
                    affiliation_xml(affiliation_status(svc_, *served, {}), true));
    });
    return;
  }
  user.subscription = message.dialog_id;
  user.subscription_expires = std::time(nullptr) + 3600;
  response.headers = {{"Expires", "3600"}};
  auto id = user.id;
  schedule([this, id] {
    if (auto *served = by_id(id)) notify(*served);
  });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.3: affiliation status change from a client (or a functional alias activation, decided
// by the server owning the functional aliases, TS 24.379 clause 9A.2.2.2.3).
void McServer::affiliation_publish(const SipMessage &message, User &user, SipResponse &response) {
  auto info = message_info(message, svc_);
  for (const auto &part : message.parts)
    if (part.content_type == "application/pidf+xml" && is_functional_alias_pidf(part.body)) {
      // TS 24.379 clause 9A.2.2.2.3: on split servers this server answers and passes each change on to the server
      // owning the aliases (clause 9A.2.2.2.6).
      if (aliases_owned_elsewhere() && user.peer.empty()) {
        response = served_alias_publish(message, user, info, part.body);
        return;
      }
      response = functional_alias_publish(message, user, info, part.body);
      return;
    }
  // TS 24.379 clause 9.2.2.2.3 steps 1 to 4: the mcptt-info names the served user (<mcptt-request-uri>); the client
  // is the one of the PIDF's tuple (step 10), the mcptt-info needs no <mcptt-client-id> (clause 9.2.1.2 step 2).
  if (info.request_uri != user.id) {
    response.status_code = 403;
    return;
  }
  // TS 24.379 clause 9.2.2.2.3 step 5: an affiliation lasts until changed, so Expires is 4294967295 (or 0 to end it).
  const auto expires = std::string(get_header(message.headers, "Expires"));
  if (expires != "0" && expires != "4294967295") {
    response.status_code = 423;
    response.headers = {{"Min-Expires", "4294967295"}};
    return;
  }
  // RFC 3903 section 6 step 3: a PUBLISH without SIP-If-Match is an initial publication, which replaces the state
  // (a restarted client has no entity tag); one naming an entity tag other than the current one is refused with 412.
  const auto match = get_header(message.headers, "SIP-If-Match");
  if (!match.empty() && match != user.affiliation_etag) {
    response.status_code = 412;
    return;
  }
  std::optional<Affiliation> affiliation;
  for (auto &part : message.parts)
    if (part.content_type == "application/pidf+xml") {
      if (affiliation) throw std::runtime_error("duplicate PIDF");
      affiliation = parse_affiliation(part.body);
    }
  const bool removing = expires == "0";
  // The PUBLISH does not depend on a subscription to the affiliation status: without one, the outcome is not notified
  // (clause 9.2.2.2.5). Clause 9.2.1.2 NOTE 2: a client no longer interested in any group needs no PIDF, Expires 0
  // is enough (clause 9.2.2.2.3 precondition 5 asks for the PIDF all the same, a defect of the clause).
  if (affiliation
          ? !own_affiliation(*affiliation) || affiliation->user_id != user.id || affiliation->client_id != user.client
          : !removing) {
    response.status_code = 403;
    return;
  }
  std::set<std::string> groups;
  const auto limit = removing ? 0u : affiliation_limit(user.id);
  if (!removing)
    for (auto &group : affiliation->groups) {
      // Clause 9.2.2.2.3 step 8: the PUBLISH is answered 200 (OK) whatever the outcome per group. The controlling
      // function refuses a user who is not a member (clause 9.2.2.3.3 step 5), and the participating function then
      // removes the group (clause 9.2.2.2.6), so the notified status (clause 9.2.2.2.5) does not list it.
      bool admitted = false;
      try {
        admitted = member(group_profile(group), user.id);
      } catch (const std::exception &) { // an unknown group
      }
      if (!admitted) {
        event("affiliation_refused", {{"user_id", user.id}, {"group_id", group}, {"reason", "not a member"}});
        continue;
      }
      // TS 24.379 clause 9.2.2.2.3 step 7c: beyond N2, keep the groups in the order requested.
      if (limit && groups.size() >= limit) {
        event("affiliation_limited", {{"user_id", user.id}, {"group_id", group}, {"max_affiliations", limit}});
        continue;
      }
      groups.insert(group);
    }
  // TS 24.379 clause 9.2.2.3.3 step 10 a0: the controlling function refuses some de-affiliations, and the user stays
  // affiliated to those groups (the PUBLISH is still answered 200, step 8 of clause 9.2.2.2.3).
  std::set<std::string> leaving;
  for (const auto &group : user.groups)
    if (!groups.contains(group)) leaving.insert(group);
  groups.merge(deaffiliation_forbidden(user, leaving));
  user.affiliation_etag = removing ? std::string{} : random_id();
  user.handled_pid = affiliation ? affiliation->publication_id : std::string{};
  apply_affiliation(user, std::move(groups));
  response.headers = {{"Expires", removing ? "0" : "4294967295"}};
  if (!removing) response.headers.push_back({"SIP-ETag", user.affiliation_etag});
  event(removing ? "deaffiliated" : "affiliated", {{"user_id", user.id}, {"groups", user.groups}});
}

//------------------------------------------------------------------------------
// SIP MESSAGE from a served user: an MBMS listening status (TS 24.379 clause 14.2.3), regroup (TS 24.379 clause
// 16), private call services (TS 24.379 clauses 11.1.5 to 11.1.9), functional alias binding (TS 24.379 clause
// 9A.4), ad hoc alerts (TS 24.379 clause 12.1A) and group emergency alerts (TS 24.379 clause 12.1.3); a request for a
// function controlled elsewhere is passed on.
void McServer::user_message(const SipMessage &message, User &user, SipResponse &response) {
  // TS 24.379 clause 14.2.3: a listening status report for the IP multicast profile (src/server/multicast.cpp).
  if (const auto *usage = mbms_usage_part(message)) {
    response = mbms_usage_message(message, user, *usage);
    return;
  }
  // TS 24.379 clause 16: a regroup request carries its own MIME body and is not a
  // call service request, so it is handled before the rest.
  if (const auto *regroup = regroup_part(message)) {
    response = regroup_message(message, user, *regroup);
    return;
  }
  auto info = message_info(message, svc_);
  if (user.peer.empty() && message_to_controller(message, user, info, response)) return;
  if (info.adhoc_alert) {
    response = adhoc_alert_message(message, user, info);
    return;
  }
  if (info.service.contains("request-type") && info.service.at("request-type") == "fa-group-binding-req") {
    response = alias_binding_message(message, user, info);
    return;
  }
  if (info.service.contains("request-type") || info.service.contains("response-type")) {
    response = private_service_message(message, user, info);
    return;
  }
  group_alert_message(message, user, info, response);
}

//------------------------------------------------------------------------------
// The originating participating function for a group or call controlled elsewhere: a SIP MESSAGE goes on to the
// controlling function, after the checks of TS 24.379 clause 9A.4.2.2.2 (functional alias binding) and of the
// requester's authorisation (TS 24.379 clause 6.3.3.1). Returns true when `response` is the answer.
bool McServer::message_to_controller(const SipMessage &message, User &user, const McpttInfo &info,
                                     SipResponse &response) {
  // Originating participating function for a group or call controlled elsewhere.
  const bool call_service =
      info.adhoc_alert || info.service.contains("request-type") || info.service.contains("response-type");
  auto controller = call_service ? call_controller() : group_controller(info.request_uri);

  // A transfer or forwarding request concerns the user's current call
  // and goes to the function controlling it (TS 24.379 clauses 11.1.8.3 and 11.1.9.3).
  const auto type = info.service.contains("request-type") ? info.service.at("request-type") : std::string{};
  // TS 24.379 clause 9A.4.2.2.2 (TS 24.281 clause 20.4.2.2.2): the participating function checks a binding
  // request before passing it to the controlling function.
  if (type == "fa-group-binding-req" && !controller.empty())
    if (const auto warning = alias_binding_refusal(user, message, info); !warning.empty()) {
      response.status_code = 403;
      response.headers = {{"Warning", warning_value(warning)}};
      return true;
    }
  if (type == "transfer-private-call-request" || type == "forward-private-call-request")
    for (const auto &[dialog, relay] : relays_)
      if (relay->user == user.id && !relay->ended) {
        controller = relay->peer;
        break;
      }
  if (!controller.empty() && call_service)
    if (const auto warning = service_request_refusal(user, info); !warning.empty()) {
      response.status_code = 403;
      response.headers = {{"Warning", warning_value(warning)}};
      return true;
    }
  if (!controller.empty()) {
    const auto implicit = call_service ? std::string{} : begin_implicit_affiliation(user, info, true);
    response = relay_message(
        message, peers_.at(controller).service_uri,
        route_to(controller, {{"P-Asserted-Identity", "<" + user.sip + ">"}}),
        [this, id = user.id, implicit](int status) { end_implicit_affiliation(id, implicit, status < 300); });
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 12.1.3.1 to 12.1.3.3: an emergency alert, its cancellation or a change of the in-progress
// emergency (or imminent peril) state of a group, with implicit affiliation for an alert (TS 24.379 clause
// 9.2.2.3.6); the guard of that affiliation lives until the answer is final.
void McServer::group_alert_message(const SipMessage &message, User &user, McpttInfo &info, SipResponse &response) {
  // TS 24.379 clauses 12.1.3.1 to 12.1.3.3: an emergency alert, its cancellation or a change of the
  // in-progress emergency (or imminent peril) state of a group, with implicit affiliation for an alert.
  auto profile = group_profile(info.request_uri);
  ImplicitAffiliation implicit;
  // A member told of a regroup is affiliated with it (TS 24.379 clauses 16.2.2.4 and 16.3.2.4 step 3 h)).
  const bool regrouped_member = regroup_affiliated(user, info.request_uri);
  if (!user.groups.contains(info.request_uri) && !regrouped_member && info.alert == true &&
      info.client_id == user.client)
    (void)implicitly_affiliate(user, info.request_uri, profile, response, implicit);
  if (info.client_id != user.client || (!user.groups.contains(info.request_uri) && !regrouped_member) ||
      !member(profile, user.id) || message.request_uri != cfg_.at(svc_.name).at("service_uri").get<std::string>() ||
      !accepts_mcptt(message)) {
    response.status_code = 403;
    return;
  }
  std::optional<McpttInfo> correction;
  if (!validate_priority(message, user, profile, info, response, correction, true)) return;
  apply_priority(info.request_uri, user.id, info, profile, message_location(message));
  schedule([this, info, id = user.id] {
    priority_fanout(info.request_uri, id, info, !info.emergency);
    if (auto *target = by_id(id)) {
      auto receipt = info;
      receipt.calling_group = info.request_uri;
      receipt.calling_user = id;
      if (info.alert) receipt.alert_received = true;
      if (info.emergency) receipt.emergency_received = true;
      priority_message(*target, receipt);
    }
  });
}

//------------------------------------------------------------------------------
// INVITE from a served user or a peer function: call setup and re-INVITE. Pre-established sessions (TS 24.379
// clause 8.2.2) are refused; a call controlled elsewhere is relayed; ambient listening (clause 11.1.6), private
// (clause 11.1.1), ad hoc (clause 17.4.2) and server video (TS 24.281 clauses 12.2.3.2.5 and 13.2.3.2.3) calls go
// to their procedures, group calls to group_invite().
void McServer::invite_request(const SipMessage &message, User &user, SipResponse &response) {
  // TS 24.379 clause 8.2.2: setup of a pre-established session, addressed to its
  // public service identity. Steps 3 and 5: the lab has no resource sharing
  // (neither via the SIP core nor PCC/Rx, TS 24.379 clause 8.1A), so every request is refused.
  if (message.request_uri == pre_established_uri() && !legs_.contains(message.dialog_id)) {
    response.status_code = 403;
    response.headers = {
        {"Warning", warning_value(warn(Warning::function_not_allowed, "pre-established session not supported"))}};
    event("pre_established_session_refused", {{"user_id", user.id}, {"reason", "resource sharing not supported"}});
    return;
  }
  if (auto answer = plain_reinvite(message, user)) {
    response = std::move(*answer);
    return;
  }
  auto info = message_info(message, svc_);
  if (!legs_.contains(message.dialog_id) && user.peer.empty() && info.session_type == "chat" &&
      !user.groups.contains(info.request_uri) && !regroup_affiliated(user, info.request_uri) &&
      group_controller(info.request_uri) != "" && affiliation_limit_reached(user, info)) {
    too_many_affiliations(response, user);
    return;
  }
  if (!legs_.contains(message.dialog_id) && user.peer.empty() && invite_to_controller(message, user, info, response))
    return;
  if (!legs_.contains(message.dialog_id)) release_listened_to(user.id, ambient_reason("initiated-by"));

  // TS 24.379 clause 11.1.6: ambient listening call.
  if (info.session_type == svc_.ambient) {
    response = ambient_invite(message, user, info);
    return;
  }
  // TS 24.379 clause 11.1.1: private and first-to-answer call (TS 24.281 clauses 12.2.3 and 13.2.3: one-to-one
  // video pull and push).
  if (info.session_type == "private" || info.session_type == "first-to-answer" || video_one_to_one(info.session_type)) {
    response = private_invite(message, user, info);
    return;
  }
  // TS 24.379 clause 17.4.2: ad hoc group call setup.
  if (info.session_type == "adhoc") {
    response = adhoc_invite(message, user, info);
    return;
  }
  // TS 24.281 clauses 12.2.3.2.5 and 13.2.3.2.3: video pull from and push to this server (service_invite).
  if (auto answer = service_invite(message, user, info)) {
    response = std::move(*answer);
    return;
  }
  group_invite(message, user, info, response);
}

//------------------------------------------------------------------------------
// A re-INVITE in the dialog of a call leg that carries no MC service information changes nothing the MC procedures
// handle: a session refresh (RFC 4028 section 7.4), or a hold or resume of a private call (RFC 5359 section 2.1). The
// same media, or no offer, is answered 200 (OK) with the current session description (RFC 3264 section 8); a hold or
// resume goes to private_hold_resume; any other change of the media is refused with 488 (Not Acceptable Here).
// Returns nothing for a request that is not such a re-INVITE.
std::optional<SipResponse> McServer::plain_reinvite(const SipMessage &message, const User &user) {
  const auto found = legs_.find(message.dialog_id);
  if (found == legs_.end()) return std::nullopt;
  const auto parts = parts_of(message);
  if (std::any_of(parts.begin(), parts.end(), [&](const auto &part) { return part.content_type == svc_.info_mime; }))
    return std::nullopt;

  const auto leg = found->second;
  SipResponse response;
  if (leg->user != user.id || !leg->active || !leg->session) {
    response.status_code = 481;
    return response;
  }
  if (leg->session->private_call)
    if (auto answer = private_hold_resume(message, user, McpttInfo{}, leg, *leg->session)) return answer;
  const auto &old = leg->remote;
  const auto &offer = message.remote_media;
  const bool same = old && offer && old->address == offer->address && old->audio_port == offer->audio_port &&
                    old->control == offer->control && old->floor_address == offer->floor_address &&
                    old->floor_port == offer->floor_port && old->payload_type == offer->payload_type &&
                    old->octet_aligned == offer->octet_aligned && old->direction == offer->direction &&
                    old->protected_media == offer->protected_media &&
                    (!old->video || (offer->video && old->video->port == offer->video->port));
  if (offer && !same) {
    response.status_code = 488;
    event("reinvite_refused", {{"user_id", user.id}, {"reason", "media change without MC service information"}});
    return response;
  }
  response.status_code = 200;
  response.local_media = leg->local;
  event("session_refreshed", {{"user_id", user.id}, {"offer", offer.has_value()}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.2 (the originating participating function): a call controlled elsewhere (by the peer of a
// session alias, the group's controller or the call controller) is relayed there. Returns true when `response` is
// the answer.
bool McServer::invite_to_controller(const SipMessage &message, User &user, const McpttInfo &info,
                                    SipResponse &response) {
  // Originating participating function for a call controlled elsewhere.
  std::string controller, target;
  if (const auto alias = session_aliases_.find(message.request_uri); alias != session_aliases_.end()) {
    controller = alias->second.peer;
    target = alias->second.remote;
  } else if (info.session_type == "prearranged" || info.session_type == "chat") {
    controller = group_controller(info.request_uri);
  } else
    controller = call_controller();
  if (!controller.empty()) {
    if (info.session_type == "private")
      if (const auto warning = check_service_mapping(user.id, message, info); !warning.empty()) {
        response.status_code = 403;
        response.headers = {{"Warning", warning_value(warning)}};
        return true;
      }
    if (target.empty()) {
      if (message.request_uri != cfg_.at(svc_.name).at("service_uri").get<std::string>()) {
        response.status_code = 404;
        return true;
      }
      target = peers_.at(controller).service_uri;
    }
    response = relay_outgoing(message, user, controller, target);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.2 (prearranged) and clause 10.1.2.4.1 (chat): the controlling function receives a group
// call request (or a re-INVITE of a joined participant, clause 10.1.1.4.7). The implicit affiliation guard lives
// until the answer is final (TS 24.379 clause 9.2.2.3.11).
void McServer::group_invite(const SipMessage &message, User &user, McpttInfo &info, SipResponse &response) {
  const auto service = cfg_.at(svc_.name).at("service_uri").get<std::string>();
  const bool session_addressed = message.request_uri.starts_with(session_service_ + ";mcptt-session=");
  std::shared_ptr<Session> session;
  if (!find_group_session(message, info, session_addressed, session, response)) return;
  if (info.client_id != user.client || (info.session_type != "prearranged" && info.session_type != "chat")) {
    response.status_code = 403;
    return;
  }
  const bool chat_request = info.session_type == "chat";

  // TS 24.379 clause 10.1.1.4.2 (prearranged) and clause 10.1.2.4.1 (chat): the controlling function
  // receives a group call request.
  std::string calling_constituent;
  if (!regroup_constituent_allowed(user, info, calling_constituent, response)) return;
  ImplicitAffiliation implicit;
  if (!user.groups.contains(info.request_uri) && !regroup_affiliated(user, info.request_uri) && user.peer.empty() &&
      chat_request && affiliation_limit_reached(user, info)) {
    too_many_affiliations(response, user);
    return;
  }
  if (!group_call_affiliated(user, info, chat_request, calling_constituent, implicit, response)) return;
  if (!session_addressed && message.request_uri != service) {
    response.status_code = 404;
    return;
  }
  if (!message.remote_media) {
    response.status_code = 488;
    return;
  }
  auto profile = group_profile(info.request_uri);
  if (!group_call_type_allowed(user, info, profile, chat_request, response)) return;
  const auto group_type = profile.value("type", std::string("prearranged"));
  const bool hierarchy = group_type == "group-broadcast" || group_type == "user-broadcast";
  if (hierarchy && !info.broadcast.value_or(false)) {
    response.status_code = 403;
    response.headers = {
        {"Warning", warning_value(warn(Warning::function_not_allowed, "broadcast group requires broadcast-ind"))}};
    return;
  }
  if (!group_media_acceptable(message, user, profile, response)) return;
  auto admission_policy = profile.value("call_policy", cfg_.at(svc_.name).value("call_policy", Json::object()));
  admission_policy["protect_floor"] = profile.value("protect_floor", false);
  if (!group_call_admitted(message, user, info, session, profile, admission_policy, response)) return;
  std::optional<McpttInfo> correction;

  // TS 24.379 clause 10.1.1.4.7: a re-INVITE of a joined participant changing the call's priority.
  const auto updating = legs_.find(message.dialog_id);
  if (updating != legs_.end())
    return priority_reinvite(message, user, info, session, profile, updating->second, correction, response);

  // Clause 6.3.3.1.13.4, local policy: a receiver of a broadcast group call does not cancel its emergency state.
  if (session && session->broadcast && user.id != session->initiator && info.emergency == false) {
    broadcast_priority_refused(response);
    return;
  }
  if (!validate_priority(message, user, profile, info, response, correction)) return;
  const bool broadcast_request = info.broadcast.value_or(false);
  if (!group_join_allowed(user, info, session, profile, admission_policy, chat_request, broadcast_request, response))
    return;
  const bool creating = !session;
  if (creating)
    session = create_group_session(user, info, profile, admission_policy, group_type, hierarchy, broadcast_request,
                                   chat_request);
  const auto leg = group_call_leg(message, user, info, session, profile, creating, correction, response);
  if (!leg) return;
  answer_group_invite(message, user, info, session, profile, leg, creating, session_addressed, response);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.4.2 and 10.1.2.4.1: the group call a request joins, by its session URI (404 when it
// does not exist or is another group's) or by its group. Returns false when the request is refused in `response`.
bool McServer::find_group_session(const SipMessage &message, const McpttInfo &info, bool session_addressed,
                                  std::shared_ptr<Session> &session, SipResponse &response) {
  if (session_addressed) {
    for (const auto &[group, candidate] : sessions_)
      if (candidate->uri == message.request_uri) {
        session = candidate;
        break;
      }
    if (!session || session->group != info.request_uri) {
      response.status_code = 404;
      return false;
    }
  } else if (auto existing = sessions_.find(info.request_uri); existing != sessions_.end()) {
    session = existing->second;
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.4.1 steps 5, 5a and 6b (clause 10.1.1.4.2 steps 6 and 6a likewise): a call to a group
// regroup carries the constituent group it is placed from (`calling_constituent`). Returns false when the request
// is refused in `response`.
bool McServer::regroup_constituent_allowed(const User &user, const McpttInfo &info, std::string &calling_constituent,
                                           SipResponse &response) {
  // TS 24.379 clause 10.1.2.4.1 steps 5, 5a and 6b (clause 10.1.1.4.2 steps 6 and 6a likewise): a call whose group
  // identity is a group regroup carries the constituent group it is placed
  // from. NOTE 4: the function serving that constituent has already assured
  // the caller's affiliation to it, so affiliation to the regroup itself is
  // not required. A user regroup has no constituent groups and needs none.
  if (const auto held = regroups_.find(info.request_uri); held != regroups_.end() && !held->second.groups.empty()) {
    const auto &groups = held->second.groups;
    // TS 24.379 clause 10.1.1.2.1.1 step 14 d) (TS 24.281 clause 9.2.1.2.1.1 step 14 d) i)): a client names the
    // constituent group in <associated-group-id>; the function of that group passes it on in <mcptt-calling-group-id>
    // (TS 24.281 clause 6.3.4.1.4 step 4 c)), as a request from another function carries it. This server is both
    // functions for its own users; <mcptt-calling-group-id> from a user is still read (earlier clients).
    const auto constituent =
        user.peer.empty() && !info.associated_group.empty() ? info.associated_group : info.calling_group;
    if (constituent.empty()) {
      event("regroup_call_refused",
            {{"user_id", user.id}, {"regroup", info.request_uri}, {"reason", "no calling group identity"}});
      response.status_code = 403;
      return false;
    }
    if (std::find(groups.begin(), groups.end(), constituent) == groups.end()) {
      event("regroup_call_refused", {{"user_id", user.id},
                                     {"regroup", info.request_uri},
                                     {"calling_group", constituent},
                                     {"reason", "not a constituent group"}});
      response.status_code = 403;
      response.headers = {{"Warning", warning_value(warn(Warning::not_affiliated))}};
      return false;
    }
    calling_constituent = constituent;
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.4.1 step 6: the caller is affiliated to the group (or to the constituent group of a
// regroup), or affiliated implicitly for a chat join or an emergency or imminent peril call (TS 24.379 clause
// 9.2.2.3.6, `implicit` guarding it). Returns false when the request is refused in `response`.
bool McServer::group_call_affiliated(User &user, const McpttInfo &info, bool chat_request,
                                     const std::string &calling_constituent, ImplicitAffiliation &implicit,
                                     SipResponse &response) {
  if (!calling_constituent.empty() && user.groups.contains(calling_constituent)) {
    // Affiliated to the constituent group: that is the affiliation step 6 asks for.
  } else if (regroup_affiliated(user, info.request_uri)) {
    // Affiliated with the regroup by its notice (TS 24.379 clauses 16.2.2.4 and 16.3.2.4 step 3 h)).
  } else if (!user.groups.contains(info.request_uri)) {
    bool affiliated_now = false;
    if (chat_request || info.emergency == true || info.imminent_peril == true) {
      try {
        affiliated_now =
            implicitly_affiliate(user, info.request_uri, group_profile(info.request_uri), response, implicit);
      } catch (const std::exception &) {
        // The group document is not available: no implicit affiliation, refused below as not affiliated.
      }
    }
    if (!affiliated_now) {
      response.status_code = 403;
      response.headers = {{"Warning", warning_value(warn(Warning::not_affiliated))}};
      return false;
    }
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.4.1 steps 4b and 4c (clause 10.1.1.4.2 steps 5a1 and 5b) and clause 4.4.2 (warnings 117
// and 118): the caller is a member, the call type matches the group type, and the group document does not restrict
// the group (preconfigured use only, regrouped). Returns false when the request is refused in `response`.
bool McServer::group_call_type_allowed(const User &user, const McpttInfo &info, const Json &profile, bool chat_request,
                                       SipResponse &response) {
  // TS 24.379 and TS 24.281 clause 6.3.5.2 step 5a: a disabled group (<on-network-disabled>).
  if (profile.value("disabled", false)) {
    response.status_code = 403;
    response.headers = {{"Warning", warning_value(warn(Warning::group_disabled))}};
    return false;
  }
  // Step 5b: the caller is not in the group's <list>.
  if (!member(profile, user.id)) {
    response.status_code = 403;
    response.headers = {{"Warning", warning_value(warn(Warning::not_group_member))}};
    return false;
  }
  // Steps 5c and 5d: the requested call type must match the group type (<on-network-invite-members>), else 404
  // (Not Found) with warning 117 or 118 (clause 4.4.2).
  const bool chat_group = profile.value("type", std::string("prearranged")) == "chat";
  if (chat_request != chat_group) {
    response.status_code = 404;
    response.headers = {{"Warning", chat_group ? warning_value(warn(Warning::chat_group_mismatch))
                                               : warning_value(warn(Warning::prearranged_group_mismatch))}};
    return false;
  }
  // TS 24.379 clause 10.1.2.4.1 steps 4b and 4c (clause 10.1.1.4.2 steps 5a1 and 5b): group document
  // restrictions.
  if (profile.value("preconfigured_use_only", false)) {
    response.status_code = 403;
    response.headers = {{"Warning", warning_value(warn(Warning::preconfigured_use_only))}};
    return false;
  }
  if (profile.value("regrouped", false) || is_regrouped(info.request_uri)) {
    response.status_code = 403;
    response.headers = {{"Warning", warning_value(warn(Warning::regrouped))}};
    // TS 24.379 clause 10.1.2.4.1 step 4c-ii (clause 10.1.1.4.2 step 5b-iii): when the group was regrouped
    // using a preconfigured group, a copy of the notification of clause 16.2.4.1 goes to the caller as well.
    if (is_regrouped(info.request_uri))
      schedule([this, id = user.id, group = info.request_uri] { regroup_member_added(id, group); });
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.2 (SDP offer): the offered media are valid, the request accepts the MCPTT service, and
// protected media (TS 33.180 clause 7) are not requested across servers without floor keys. Returns false when the
// request is refused in `response`.
bool McServer::group_media_acceptable(const SipMessage &message, const User &user, const Json &profile,
                                      SipResponse &response) {
  try {
    validate_remote(user.id, *message.remote_media);
  } catch (const std::exception &error) {
    event("sdp_rejected", {{"reason", error.what()}});
    response.status_code = 488;
    return false;
  }
  if (!accepts_mcptt(message)) {
    response.status_code = 403;
    return false;
  }
  if (!user.peer.empty() && !floor_keys(user) &&
      (profile.value("protect_media", false) || profile.value("protect_floor", false))) {
    response.status_code = 488;
    response.headers = {{"Warning", warning_value(warn(Warning::function_not_allowed,
                                                       std::string("protected media not supported across ") +
                                                           svc_.label + " servers"))}};
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.4.2 and 10.1.2.4.1: the media protection matches the group document, the call policy authorises the caller to initiate or join, and a new call has its required affiliated
// members (TS 24.379 clause 6.3.8.2). Returns false when the request is refused in `response`.
bool McServer::group_call_admitted(const SipMessage &message, const User &user, const McpttInfo &info,
                                   const std::shared_ptr<Session> &session, const Json &profile,
                                   const Json &admission_policy, SipResponse &response) {
  if (message.remote_media->protected_media != profile.value("protect_media", false) ||
      (profile.value("protect_floor", false) && (!floor_keys(user) || !floor_keys(user)->floor_ready())) ||
      (profile.value("protect_media", false) &&
       (message.remote_media->payload_type != 96 || message.remote_media->octet_aligned))) {
    response.status_code = 488;
    return false;
  }
  if (!policy_allows(admission_policy, session ? "join_members" : "initiate_members", user.id)) {
    response.status_code = 403;
    response.headers = {{"Warning", session ? warning_value(warn(Warning::group_call_join_not_authorised))
                                            : warning_value(warn(Warning::group_call_initiation_not_authorised))}};
    return false;
  }
  if (!session && !sufficient_affiliation(info.request_uri, profile.at("members").get<std::vector<std::string>>(),
                                          admission_policy, true)) {
    response.status_code = 480;
    response.headers = {{"Warning", warning_value(warn(Warning::required_members_abandoned))}};
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.7: a re-INVITE of a joined participant changing the call's priority (emergency or
// imminent peril); the media identities and the floor ownership are kept. `leg` is a copy of the leg's pointer.
void McServer::priority_reinvite(const SipMessage &message, const User &user, McpttInfo &info,
                                 const std::shared_ptr<Session> &session, const Json &profile, std::shared_ptr<Leg> leg,
                                 std::optional<McpttInfo> &correction, SipResponse &response) {
  if (!session || leg->session != session || leg->user != user.id || !leg->active ||
      (!info.emergency && !info.imminent_peril)) {
    response.status_code = 403;
    return;
  }
  // Clause 6.3.3.1.13.4, local policy: a receiver of a broadcast group call does not cancel its emergency state.
  if (session->broadcast && user.id != session->initiator && info.emergency == false) {
    broadcast_priority_refused(response);
    return;
  }
  if (!validate_priority(message, user, profile, info, response, correction)) return;

  // Priority updates preserve established media identities and floor ownership.
  if (!leg->remote || !message.remote_media) {
    response.status_code = 488;
    return;
  }
  const auto &old = *leg->remote;
  if (old.address != message.remote_media->address || old.audio_port != message.remote_media->audio_port ||
      old.floor_port != message.remote_media->floor_port || old.floor_ssrc != message.remote_media->floor_ssrc ||
      old.payload_type != message.remote_media->payload_type ||
      old.octet_aligned != message.remote_media->octet_aligned || old.queueing != message.remote_media->queueing) {
    response.status_code = 488;
    return;
  }
  negotiate_priority(*leg, profile, message.remote_media->floor_priority);
  leg->pending_priority_info = correction;
  const bool was_priority = in_priority(session->group);
  const bool was_emergency = priorities_.contains(session->group) && priorities_.at(session->group).emergency;
  apply_priority(session->group, user.id, info, profile, message_location(message));
  if (session->chat && !was_priority && in_priority(session->group))
    schedule([this, session] { invite_chat_members(session); });
  response.local_media = leg->local;
  auto current = info;
  current.request_uri = user.id;
  current.calling_group = session->group;
  if (session->broadcast) current.broadcast = true; // the answer keeps describing the call type
  populate_priority(current, priorities_.at(session->group));

  // A downgrade must be explicitly signalled, not represented by absent flags.
  if (info.emergency == false) current.emergency = false;
  if (info.imminent_peril == false) current.imminent_peril = false;
  response.parts = priority_parts(current);
  for (const auto &header :
       priority_headers(profile.value("priority_policy", Json::object()), priorities_.at(session->group)))
    response.headers.push_back(header);
  if (info.emergency || info.imminent_peril) {
    const auto change = emergency_change(info, was_emergency, priorities_.at(session->group).emergency);
    schedule([this, group = session->group, id = user.id, info, change] {
      priority_fanout(group, id, info, false, change);
    });
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.12 and clause 10.1.1.4.2: a new participant may join: a broadcast group call is neither a chat
// call nor a replacement of an ongoing call and needs call_policy.broadcast_members; the caller is not already in
// the call, and the call has room (or a lower priority participant is preempted). Returns false when the request is
// refused in `response`.
bool McServer::group_join_allowed(const User &user, const McpttInfo &info, const std::shared_ptr<Session> &session,
                                  const Json &profile, const Json &admission_policy, bool chat_request,
                                  bool broadcast_request, SipResponse &response) {
  if (chat_request && broadcast_request) {
    response.status_code = 403;
    response.headers = {
        {"Warning", warning_value(warn(Warning::function_not_allowed, "broadcast chat group call not implemented"))}};
    return false;
  }
  if (broadcast_request && session && !session->broadcast) {
    // A broadcast on the same group cannot replace its ongoing call.
    response.status_code = 486;
    response.headers = {{"Warning", warning_value(warn(Warning::function_not_allowed, "group call in progress"))}};
    return false;
  }
  // TS 24.379 clause 4.12: any member may broadcast unless call_policy.broadcast_members restricts it.
  if (broadcast_request && !session && !policy_allows(admission_policy, "broadcast_members", user.id)) {
    response.status_code = 403;
    response.headers = {
        {"Warning", warning_value(warn(Warning::function_not_allowed, "broadcast group call not authorised"))}};
    return false;
  }
  if (session && has_leg(*session, user.id)) {
    response.status_code = 486;
    return false;
  }
  if (session && session->dialogs.size() >= session->policy.value("max_participants", session->members.size()) &&
      !preempt_lower_priority_participant(session, profile, user.id, info)) {
    response.status_code = 486;
    response.headers = {{"Warning", warning_value(warn(Warning::too_many_participants))}};
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.4.2 and 10.1.2.4.1: a new group call session (not yet published in sessions_), with its
// session URI, policy, members (or broadcast hierarchy) and floor (or transmission) control.
std::shared_ptr<McServer::Session> McServer::create_group_session(const User &user, const McpttInfo &info,
                                                                  const Json &profile, const Json &admission_policy,
                                                                  const std::string &group_type, bool hierarchy,
                                                                  bool broadcast_request, bool chat_request) {
  auto session = std::make_shared<Session>();
  session->group = info.request_uri;
  session->uri = session_service_ + ";mcptt-session=" + random_id();
  session->initiator = user.id;
  session->policy = admission_policy;
  session->broadcast = broadcast_request;
  session->chat = chat_request;
  session->created = session->last_media = session->normal_since = monotonic_ms();
  session->members = profile.at("members").get<std::vector<std::string>>();
  if (hierarchy) prepare_broadcast_hierarchy(*session, profile, group_type, user.id);
  session->arbitrator = make_media_control(session->members, floor_options());
  return session;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.2 (TS 24.281 clause 9.2): the caller's leg of the group call from its SDP offer, with
// its functional alias (clause 10.1.1.3.1.1 step 6a) and floor priority. Returns nullptr when the offer is refused
// (488 in `response`).
std::shared_ptr<McServer::Leg> McServer::group_call_leg(const SipMessage &message, const User &user,
                                                        const McpttInfo &info, const std::shared_ptr<Session> &session,
                                                        const Json &profile, bool creating,
                                                        const std::optional<McpttInfo> &correction,
                                                        SipResponse &response) {
  // TS 24.281 clause 9.2: an MCVideo group call is always under transmission control.
  if (message.remote_media->control == MediaControl::none) {
    response.status_code = 488;
    return nullptr;
  }
  auto leg = make_leg(user.id, session);
  if (leg->local.floor_ssrc == message.remote_media->floor_ssrc) {
    response.status_code = 488;
    return nullptr;
  }
  // TS 24.379 clause 10.1.1.3.1.1 step 6a: present only an activated functional alias.
  if (!info.functional_alias.empty() && functional_alias_active(info.functional_alias, user.id)) {
    session->participant_aliases[user.id] = info.functional_alias;
    if (creating) session->initiator_alias = info.functional_alias;
  }
  leg->dialog = message.dialog_id;
  leg->origin = creating;
  leg->incoming_offer = true;
  leg->pending_priority_info = correction;
  leg->remote = *message.remote_media;
  leg->local.payload_type = message.remote_media->payload_type;
  leg->local.octet_aligned = message.remote_media->octet_aligned;
  leg->local.queueing = leg->local.queueing && message.remote_media->queueing;

  // The service's part of the answer: MCVideo implicit Transmission Request and video payload type.
  answer_service_media(*leg, *message.remote_media, creating);
  negotiate_priority(*leg, profile, message.remote_media->floor_priority);
  return leg;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.2 (and clause 10.1.2.4.1 steps 11 and 16 for a chat call): answer the caller (for a
// new prearranged call, which fans out, 100 (Trying) until the 200 (OK) that the invited members' answers bring: the
// controlling function sends no other provisional response; 200 otherwise), apply the requested priority, publish
// the session and its leg.
void McServer::answer_group_invite(const SipMessage &message, const User &user, McpttInfo &info,
                                   const std::shared_ptr<Session> &session, const Json &profile,
                                   const std::shared_ptr<Leg> &leg, bool creating, bool session_addressed,
                                   SipResponse &response) {
  response.local_media = leg->local;
  response.contact_uri = session->uri;
  response.focus = true;
  const auto requested_priority = info;
  const bool was_priority = in_priority(session->group);
  const bool was_emergency = priorities_.contains(session->group) && priorities_.at(session->group).emergency;
  apply_priority(session->group, user.id, info, profile, message_location(message));
  const auto change = emergency_change(requested_priority, was_emergency, priorities_.at(session->group).emergency);

  // TS 24.379 clause 10.1.2.4.1 steps 14c-iv and 15c-iii: entering emergency or imminent peril
  // invites the affiliated members that have not joined the chat session.
  if (session->chat && !was_priority && in_priority(session->group))
    schedule([this, session] { invite_chat_members(session); });
  info.calling_user = session->initiator;
  info.calling_group = session->group;
  if (session->broadcast) info.broadcast = true; // a late joiner learns the call type
  populate_priority(info, priorities_.at(session->group));
  response.parts = priority_parts(info);
  for (const auto &header :
       priority_headers(profile.value("priority_policy", Json::object()), priorities_.at(session->group)))
    response.headers.push_back(header);
  if (creating && session->chat) {
    // TS 24.379 clause 10.1.2.4.1 steps 11 and 16: create the chat session and answer at once.
  } else if (creating) {
    leg->answer = response;
    leg->awaiting_answer = true;
    response.status_code = 100;
    response.reason = "Trying";
  } else if (!session_addressed && !session->chat) {
    response.headers.push_back({"Warning", warning_value(warn(Warning::session_exists))});
  }
  // Do not publish a phantom session if media allocation or response creation fails.
  if (creating) sessions_[session->group] = session;
  add_leg(leg);
  if (creating && !session->chat && session->awaiting_users.empty()) {
    auto start = [this, session, id = user.id] {
      session->invitation_deferred = false;
      fanout(session, id);
    };
    // TS 24.379 clause 11.1.6.4.3: a member's ambient listening call being released (the caller may be its
    // listened-to user) ends first, with the BYE to its listening user, so that this user is free to be invited;
    // until then the setup is not judged (complete_setup).
    if (const auto ambient = releasing_ambient(session->members)) {
      session->invitation_deferred = true;
      ambient->after_release.push_back(std::move(start));
    } else
      schedule(std::move(start));
  }
  if (!creating && (requested_priority.emergency || requested_priority.imminent_peril))
    schedule([this, session, id = user.id, requested_priority, change] {
      priority_fanout(session->group, id, requested_priority, false, change);
    });
  event(creating ? "call_created" : "call_joined",
        {{"group_id", session->group}, {"user_id", user.id}, {"session_uri", session->uri}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.1.18: send the pending priority correction to the inviting client in a SIP INFO
// request in the dialog of its call.
void McServer::send_priority_correction(std::string_view dialog) {
  const auto found = legs_.find(std::string(dialog));
  if (found == legs_.end() || !found->second->pending_priority_info) return;
  auto &leg = *found->second;
  auto info = *leg.pending_priority_info;
  info.request_uri = leg.user;
  if (!leg.session->private_call) info.calling_group = leg.session->group;
  info.calling_user = leg.user;
  leg.pending_priority_info.reset();
  sip_.request_in_dialog(
      leg.dialog, "INFO", svc_.info_mime, service_info_xml_(info),
      {{"Info-Package", std::string(svc_.feature_tag) + "-info"}, {"Content-Disposition", "Info-Package"}});
}

} // namespace mcx
