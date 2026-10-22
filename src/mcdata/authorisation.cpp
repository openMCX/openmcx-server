//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData server service authorisation, log-off and affiliation: the participating MCData function side of
// TS 24.282 clauses 7.3 and 8.3.2 (member functions of DataServer, declared in data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), IETF RFC 3903.

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.3: service authorisation by a SIP PUBLISH for poc-settings (access token checked at the
// IdM server, CSK upload accepted); a SIP PUBLISH with Expires 0 logs the user off (TS 24.282 clause 7.3.5).
SipResponse DataServer::authorise(const SipMessage &request, bool from_register) {
  SipResponse response;
  const auto asserted = asserted_identity(request);
  if (asserted.empty() || asserted != request.from_uri) return reject(403, "", asserted, "authorisation");
  if (get_header(request.headers, "Expires") == "0") return log_off(request, asserted); // TS 24.282 clause 7.3.5
  const auto *info_part = part(request, mcdata::info_mime);
  // The PUBLISH carries poc-settings too (clause 7.2.2); the REGISTER the client sent only the MCData info (clause
  // 7.3.2).
  if (!info_part || (!from_register && !part(request, "application/poc-settings+xml")))
    return reject(403, "101 service authorisation failed", asserted, "authorisation");

  // TS 24.282 clause 7.2.2 steps 3 and 4 and clause 7.3.3 steps 2 and 3 (clause 7.3.1A), with TS 33.180
  // clause 9.2.1.3: the CSK upload, which also keys the encryption of the access token and client ID in the
  // same request.
  std::optional<keying::KeyMessage> csk;
  std::string uploader;
  std::string info_body = info_part->body;
  if (auto refused = authorise_csk(request, asserted, info_body, csk, uploader)) return *refused;
  const auto info = mcdata::parse_info(info_body);
  if (info.access_token.empty() || info.client_id.empty())
    return reject(403, "101 service authorisation failed", asserted, "authorisation");
  const auto checked = service_claims(tokens_, info.access_token, mcdata_service, asserted, info.client_id);
  if (!checked) return reject(403, "101 service authorisation failed", asserted, "authorisation");
  const auto &claims = *checked;
  const auto id = claims.value(mcdata_service.id_claim, std::string{});
  // A binding whose service authorisation has ended (clause 7.3.3 step 8) binds nothing any more.
  std::vector<std::string> ended;
  for (const auto &[sip, other] : users_)
    if (other.expires <= std::time(nullptr) && (sip == asserted || other.id == id)) ended.push_back(sip);
  for (const auto &sip : ended) remove_binding(users_.find(sip), "service authorisation ended");
  // The public user identity is bound to another MCData ID, still authorised.
  if (const auto bound = users_.find(asserted); bound != users_.end() && bound->second.id != id)
    return reject(403, "101 service authorisation failed", asserted, "authorisation");
  // Clause 7.3.3 steps 3a and 3b: the user is already authorised on another MCData client (another client ID, or
  // another public user identity). The present edition keeps one binding per MCData ID: the CMS's service
  // configuration document sets <max-simultaneous-authorizations> to 1 and refuses a user profile with a higher
  // <user-max-simultaneous-authorizations>, so another live authorisation means that the maximum is reached
  // (clause 7.3.3 step 5b, a second binding, is not in the present edition).
  for (const auto &[sip, other] : users_)
    if (other.id == id && (sip != asserted || other.client != info.client_id))
      return reject(486, "228 maximum number of service authorizations reached", asserted, "authorisation");

  // The CSK was signed by the MCData ID the access token names.
  if (csk && uploader != id) return reject(403, "101 service authorisation failed", asserted, "authorisation");
  // TS 24.282 clause 7.3.3 steps 5 and 7: the user is bound before the PUBLISH is processed by RFC 3903, so a
  // SIP-If-Match that names no publication of this server (RFC 3903 section 6 step 3) is answered 412 after the
  // binding, and leaves no publication.
  const auto existing = users_.find(asserted);
  const auto match = std::string(get_header(request.headers, "SIP-If-Match"));
  const bool unknown_etag = !match.empty() && (existing == users_.end() || match != existing->second.auth_etag);
  auto &user = users_[asserted];
  user.id = id;
  user.client = info.client_id;
  user.sip = asserted;
  if (csk) user.csk = csk;
  user.expires = claims.at("exp").get<std::int64_t>();
  if (unknown_etag) return reject(412, "", asserted, "authorisation");
  user.auth_etag = random_id();
  response.status_code = 200;
  response.headers = {{"SIP-ETag", user.auth_etag}, {"Expires", "4294967295"}};
  event(
      "mcdata_service_authorised",
      {{"user_id", id}, {"client_id", info.client_id}, {"csk_id", user.csk ? Json(user.csk->csb_id) : Json(nullptr)}});
  pending_.push_back([this, asserted] {
    if (auto found = users_.find(asserted); found != users_.end()) implicit_affiliations(found->second);
  });

  // TS 24.282 clause 17.2.2: location reporting is configured upon successful service authorisation.
  pending_.push_back([this, id] { location_.configure(id); });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.2: service authorisation from the REGISTER the client sent, which the SIP core includes as a
// message/sip body in a third-party REGISTER (TS 24.229 clause 5.4.1.7); its mcdata-info is authorised as a service
// authorisation PUBLISH is. The IMS public user identity is the To of the third-party REGISTER (step 1); Expires 0
// logs the user off (clause 7.3.5).
SipResponse DataServer::third_party_register(const SipMessage &request) {
  const auto identity = request.to_uri;
  const auto expires = std::string(get_header(request.headers, "Expires"));
  SipResponse response;
  response.status_code = 200;
  if (identity.empty()) {
    response.status_code = 400;
    return response;
  }
  if (expires == "0") {
    if (const auto found = users_.find(identity); found != users_.end()) {
      event("mcdata_logged_off", {{"user_id", found->second.id}, {"client_id", found->second.client}});
      remove_binding(found, "log-off");
    }
    response = SipResponse{};
    response.status_code = 200;
    response.headers = {{"Expires", "0"}};
    return response;
  }
  std::vector<BodyPart> parts;
  for (const auto &body : request.parts.empty() && !request.body.empty()
                              ? parse_body_parts(request.content_type, request.body)
                              : request.parts)
    if (body.content_type == "message/sip") parts = parse_sip_fragment_parts(body.body);
  const bool has_info =
      std::any_of(parts.begin(), parts.end(), [](const auto &body) { return body.content_type == mcdata::info_mime; });
  if (!has_info) {
    response.headers = {{"Expires", expires.empty() ? "3600" : expires}};
    return response;
  }
  SipMessage inner = request;
  inner.method = "PUBLISH";
  inner.from_uri = identity;
  inner.content_type = "multipart/mixed";
  inner.body.clear();
  inner.parts = std::move(parts);
  inner.headers = {{"P-Asserted-Identity", "<" + identity + ">"}, {"Expires", "4294967295"}};
  if (const auto found = users_.find(identity); found != users_.end() && !found->second.auth_etag.empty())
    inner.headers.push_back({"SIP-If-Match", found->second.auth_etag});
  // A renewal of an authorised user comes signed and with its XML encrypted, as its PUBLISH would.
  if (auto refused = open_signalling(identity, inner)) return *refused;
  response = authorise(inner, true);
  if (response.status_code != 200) return response;
  response.headers = {{"Expires", expires.empty() ? "3600" : expires}};
  event("mcdata_authorised_by_register", {{"user", identity}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.5: a SIP PUBLISH for poc-settings with Expires 0 logs the MCData client off. The public user
// identity is the asserted one (step 1). RFC 3903 (step 2): a removal names the publication in SIP-If-Match (section
// 4.5); one that names no publication of the user is answered 412 (section 6 step 3), a request with neither entity
// tag nor body 400 (section 6 step 5), and a single entity tag only (400). Then the service settings and the binding
// go (steps 3 and 4, remove_binding) and the answer is 200 (step 5) with Expires 0 and the publication's entity tag
// (RFC 3903 section 6 step 6).
SipResponse DataServer::log_off(const SipMessage &request, const std::string &asserted) {
  const auto match = std::string(get_header(request.headers, "SIP-If-Match"));
  const auto found = users_.find(asserted);
  if (match.find(',') != std::string::npos || (match.empty() && request.body.empty() && request.parts.empty()))
    return reject(400, "", asserted, "log-off");
  if (!match.empty() && (found == users_.end() || match != found->second.auth_etag))
    return reject(412, "", asserted, "log-off");
  if (found != users_.end()) {
    event("mcdata_logged_off", {{"user_id", found->second.id}, {"client_id", found->second.client}});
    remove_binding(found, "log-off");
  }
  SipResponse response;
  response.status_code = 200;
  response.headers = {{"Expires", "0"}, {"SIP-ETag", match.empty() ? random_id() : match}};
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.5 steps 3 and 4, and clause 7.3.3 step 8 when the service authorisation ends: the user's
// service settings end, with all its affiliations (TS 23.280 clause 10.8: the affiliation status subscription is
// terminated, RFC 6665 section 4.2.2) and its functional aliases (clause 22.2.2.3.6); then the binding of its MCData
// ID, client ID and public user identity is removed.
void DataServer::remove_binding(std::map<std::string, User>::iterator found, const char *reason) {
  if (found == users_.end()) return;
  auto &user = found->second;
  user.groups.clear();
  notify_affiliation(user, {}, true);
  deactivate_aliases(user.id);
  event("mcdata_binding_removed", {{"user_id", user.id}, {"client_id", user.client}, {"reason", reason}});
  users_.erase(found);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 7.2.2 steps 3 and 4 and clause 7.3.3 steps 2 and 3 (clause 7.3.1A), with TS 33.180 clause
// 9.2.1.3: the CSK upload of a service authorisation, and the decryption of the MCData info body it (or the CSK
// already known) keys, or the refusal.
std::optional<SipResponse> DataServer::authorise_csk(const SipMessage &request, const std::string &asserted,
                                                     std::string &info_body, std::optional<keying::KeyMessage> &csk,
                                                     std::string &uploader) {
  if (const auto *upload = part(request, "application/mikey"); upload && keys_) {
    try {
      uploader = KeyClient::initiator(upload->body);
      csk = keys_->accept_csk(uploader, upload->body);
    } catch (const std::exception &error) {
      event("mcdata_csk_rejected", {{"user_id", asserted}, {"reason", error.what()}});
      return reject(488, "136 authentication of the MIKEY-SAKKE I_MESSAGE failed", asserted, "authorisation");
    }
    if (xmlsec::is_protected(info_body)) {
      try {
        info_body = xmlsec::decrypt(info_body, xml_key_of(*csk, uploader));
        ++xml_decrypted_;
      } catch (const std::exception &) {
        ++xml_refused_;
        return reject(403, "140 unable to decrypt XML content", asserted, "authorisation");
      }
    }
  } else if (const auto known = xml_key(asserted); known && xmlsec::is_protected(info_body)) {
    try {
      info_body = xmlsec::decrypt(info_body, *known);
      ++xml_decrypted_;
    } catch (const std::exception &) {
      ++xml_refused_;
      return reject(403, "140 unable to decrypt XML content", asserted, "authorisation");
    }
  }

  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.2.3: the MCData server receives an affiliation status change from the MCData client
// (a SIP PUBLISH for presence with an MCData PIDF) and affiliates the served user to the listed groups.
SipResponse DataServer::affiliate(const SipMessage &request, User &user) {
  SipResponse response;
  const auto *info_part = part(request, mcdata::info_mime);
  const auto *pidf = part(request, "application/pidf+xml");
  const bool removing = get_header(request.headers, "Expires") == "0";

  // TS 24.282 clause 8.2.2 NOTE 1: de-affiliation from every group needs no PIDF body.
  if (!info_part || (!pidf && !removing)) return reject(403, "", user.id, "affiliation");
  const auto info = mcdata::parse_info(info_part->body);
  if (info.request_uri != user.id) return reject(403, "", user.id, "affiliation");
  Affiliation affiliation;
  if (pidf) {
    affiliation = parse_affiliation(pidf->body);
    if (!affiliation.mcdata || affiliation.user_id != user.id || affiliation.client_id != user.client)
      return reject(403, "", user.id, "affiliation");
  }

  // TS 24.282 clause 8.3.2.3 step 5: an affiliation lasts until changed, so Expires is 4294967295 (or 0 to end it).
  if (const auto expires = get_header(request.headers, "Expires"); expires != "0" && expires != "4294967295") {
    auto brief = reject(423, "", user.id, "affiliation");
    brief.headers = {{"Min-Expires", "4294967295"}};
    return brief;
  }

  // RFC 3903 section 6: a PUBLISH without SIP-If-Match is an initial publication,
  // which replaces the event state rather than being refused. A client that
  // restarted has no entity tag and must still be able to affiliate; only a
  // tag that is present and does not match is a 412, as in TS 24.282 clause 7.3.3.
  const auto match = std::string(get_header(request.headers, "SIP-If-Match"));
  if (!match.empty() && match != user.affiliation_etag) return reject(412, "", user.id, "affiliation");
  std::set<std::string> groups;
  if (!removing)
    for (const auto &group : affiliation.groups) {
      const auto document = group_document(group);
      // Clause 8.3.2.3 step 8: the PUBLISH is answered 200 (OK) whatever the outcome per group; a group the user is
      // not a member of is refused by its controlling function and removed, so the notified status does not list it.
      if (!document || !document->contains("mcdata") ||
          !listed(document->at("mcdata").value("members", Json::array()), user.id)) {
        event("mcdata_affiliation_refused", {{"user_id", user.id}, {"group_id", group}, {"reason", "not a member"}});
        continue;
      }
      groups.insert(group);
    }
  const auto previous = user.groups;
  user.groups = std::move(groups);
  user.affiliation_etag = removing ? std::string{} : random_id();
  response.status_code = 200;
  response.headers = {{"Expires", removing ? "0" : "4294967295"}};
  if (!removing) response.headers.push_back({"SIP-ETag", user.affiliation_etag});
  event(removing ? "mcdata_deaffiliated" : "mcdata_affiliated", {{"user_id", user.id}, {"groups", user.groups}});
  schedule_notify(user, affiliation.publication_id);
  for (const auto &group : user.groups)
    if (!previous.contains(group))
      pending_.push_back([this, id = user.id, group] {
        if (const auto *member = by_id(id)) {
          late_alerts(*member, group);            // TS 24.282 clause 16.2.3.3
          late_in_progress_state(*member, group); // TS 24.282 clause 6.3.7.1.2: an outstanding state
        }
      });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.2.5: NOTIFY the subscriber with the per-user affiliation information, with
// the p-id of the PUBLISH that caused the change (step 3d).
void DataServer::notify_affiliation(const User &user, const std::string &publication, bool terminated) {
  if (user.subscription.empty()) return;
  const auto affiliation = affiliation_status(mcdata_service, user, publication);
  sip_.notify(
      user.subscription, "presence", terminated ? "terminated;reason=noresource" : "active", "application/pidf+xml",
      encrypt_xml(xml_key(user.sip), {{"application/pidf+xml", affiliation_xml(affiliation, true)}}).front().body);
  event("mcdata_affiliation_notified",
        {{"user_id", user.id}, {"groups", user.groups}, {"p_id", publication}, {"terminated", terminated}});
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.2.5: queue the affiliation NOTIFY to the served user, sent after the response to the
// request that changed the affiliation.
void DataServer::schedule_notify(const User &served, const std::string &publication) {
  pending_.push_back([this, id = served.id, publication] {
    if (const auto *user = by_id(id)) notify_affiliation(*user, publication);
  });
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.2.4: subscription to the affiliation status of the served MCData ID. Only the
// user's own status: no user is authorised to modify another user's affiliation.
SipResponse DataServer::affiliation_subscribe(const SipMessage &request, User &subscriber) {
  SipResponse response;
  const bool in_dialog = !subscriber.subscription.empty() && subscriber.subscription == request.dialog_id;
  if (!in_dialog) {
    // Steps 1 to 4: the served MCData ID, and no authorisation for another user's status.
    const auto *info_part = part(request, mcdata::info_mime);
    if (!info_part) return reject(403, "", subscriber.id, "affiliation-subscription");
    const auto info = mcdata::parse_info(info_part->body);
    if (info.request_uri != subscriber.id) return reject(403, "", subscriber.id, "affiliation-subscription");
  }
  if (get_header(request.headers, "Expires") == "0") {
    // A de-subscription (in dialog) or a fetch of the current state (TS 24.282 clause 8.2.3 step 5):
    // both are answered with a final NOTIFY on their own dialog.
    response.status_code = 200;
    response.headers = {{"Expires", "0"}};
    const auto dialog = request.dialog_id;
    pending_.push_back([this, id = subscriber.id, dialog] {
      auto *user = by_id(id);
      if (!user) return;
      const auto kept = user->subscription;
      user->subscription = dialog;
      notify_affiliation(*user, {}, true);
      user->subscription = kept == dialog ? std::string{} : kept;
    });
    event(in_dialog ? "mcdata_affiliation_unsubscribed" : "mcdata_affiliation_fetched", {{"user_id", subscriber.id}});
    return response;
  }
  subscriber.subscription = request.dialog_id;
  response.status_code = 200;
  response.headers = {{"Expires", "4294967295"}};

  event("mcdata_affiliation_subscribed", {{"user_id", subscriber.id}});
  schedule_notify(subscriber);
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 8.3.2.15: implicit affiliation to the groups configured in <ImplicitAffiliations>
// after service authorisation (the combined server also owns the groups, TS 24.282 clauses 8.3.3.6 and 8.3.3.7).
void DataServer::implicit_affiliations(User &user) {
  const auto policy = profile(user.id).value("mcdata", Json::object());
  std::vector<std::string> added;
  for (const auto &entry : policy.value("implicit_affiliations", Json::array())) {
    if (!entry.is_string() || user.groups.contains(entry.get<std::string>())) continue;
    const auto group = entry.get<std::string>();
    const auto document = group_document(group);
    if (!document || !document->contains("mcdata") ||
        !listed(document->at("mcdata").value("members", Json::array()), user.id)) {
      event("mcdata_implicit_affiliation_refused", {{"user_id", user.id}, {"group_id", group}});
      continue;
    }
    user.groups.insert(group);
    added.push_back(group);
  }
  if (added.empty()) return;
  event("mcdata_implicitly_affiliated", {{"user_id", user.id}, {"groups", added}, {"reason", "configured"}});
  notify_affiliation(user);
  for (const auto &group : added) late_alerts(user, group);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.3.5: affiliation check of a user at its MCData client.
bool DataServer::affiliated(const std::string &id, const std::string &group) {
  const auto *user = by_id(id);
  return user && user->groups.contains(group);
}

//------------------------------------------------------------------------------
// Helper: the served user a group document's member entry names when it is affiliated to the group and is not
// `except` (the sender), or nullptr. One lookup, so that the user cannot expire between a check and its use.
const DataServer::User *DataServer::affiliated_member(const Json &member, const std::string &group,
                                                      const std::string &except) {
  if (!member.is_string() || member.get<std::string>() == except) return nullptr;
  const auto *user = by_id(member.get<std::string>());
  return user && user->groups.contains(group) ? user : nullptr;
}

} // namespace mcx
