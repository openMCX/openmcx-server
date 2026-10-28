//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// XML integrity and confidentiality protection of the SIP bodies (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 33.180 V19.5.0 (Rel-19).

#include "server.hpp"

#include <tuple>

namespace mcx {

namespace {
//------------------------------------------------------------------------------
// TS 33.180 annex E.6.10 ("the time in UTC at which the associated key shall no longer be used") and annex E.6.9:
// whether a user's CSK may still be used as the XPK now (keying::require_in_use).
bool csk_in_use(const keying::KeyMessage &csk) {
  try {
    keying::require_in_use(csk, static_cast<std::uint64_t>(std::time(nullptr)));
    return true;
  } catch (const std::exception &) {
    return false;
  }
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.3.2 (TS 24.281 likewise): "If the <integrity-protection> element in the Service
// Configuration document [...] is set to "true" or no <integrity-protection> element is present in the Service
// Configuration document, then sending integrity protected content from the MCPTT server to the MCPTT client is
// enabled". Whether it is enabled does not depend on the keys held: a body it needs that has no usable key is not sent
// (protect_outgoing). False until the document has been read.
bool McServer::integrity_protection() const { return signalling_protection_ && signalling_protection_->integrity; }

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.5 and TS 24.379 clause 6.6.3.1 (TS 24.281 clause 6.6.3.1): "When integrity protection is
// enabled, all XML MIME bodies transported in SIP requests and responses are integrity protected", and "If
// configuration for integrity protection is turned on, then all XML MIME bodies in SIP requests and responses are
// integrity protected" (maintainer decision M11): every XML MIME body is signed, not only the bodies the clause lists
// as examples ("can be integrity protected"), except the signatures body itself.
bool McServer::signable_part(const std::string &type) const {
  return type != signed_mime && xmlsec::is_xml_mime(type);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.3.3 and TS 33.180 clause 9.3.5: sign the signable XML bodies with the XPK and add the
// signature as a body of its own (unless one is there already).
std::vector<BodyPart> McServer::sign_parts(std::vector<BodyPart> parts, const xmlsec::Key &key) {
  if (std::any_of(parts.begin(), parts.end(), [](const BodyPart &part) { return part.content_type == signed_mime; }))
    return parts;
  std::vector<xmlsec::SignedBody> bodies;
  for (auto &part : parts)
    if (signable_part(part.content_type)) {
      if (part.content_id.empty()) part.content_id = random_id().substr(0, 16) + "@mcx";
      bodies.push_back({part.content_id, part.body});
    }
  if (bodies.empty()) return parts;
  parts.push_back({signed_mime, xmlsec::sign(bodies, key, signed_ns)});
  ++xml_signed_;
  return parts;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.4.2: verify and remove the signatures; an error names warning 139.
std::vector<BodyPart> McServer::verify_parts(std::vector<BodyPart> parts, const std::optional<xmlsec::Key> &key) {
  const auto signatures =
      std::find_if(parts.begin(), parts.end(), [](const BodyPart &part) { return part.content_type == signed_mime; });
  if (signatures == parts.end()) return parts;
  if (!key) throw std::runtime_error(warn(Warning::no_signing_key));
  std::vector<xmlsec::SignedBody> bodies;
  for (const auto &part : parts)
    if (part.content_type != signed_mime && !part.content_id.empty()) bodies.push_back({part.content_id, part.body});
  try {
    (void)xmlsec::verify(signatures->body, bodies, *key);
  } catch (const std::exception &error) {
    throw std::runtime_error(std::string("139 ") + error.what());
  }
  ++xml_verified_;
  parts.erase(signatures);
  return parts;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.3.2 (TS 24.281 likewise): "If the <confidentiality-protection> element in the Service
// Configuration document [...] is set to "true" or no <confidentiality-protection> element is present [...], then
// sending confidentiality protected content from the MCPTT server to the MCPTT client is enabled", independently of
// the keys held. False until the document has been read.
bool McServer::xml_protection() const {
  return signalling_protection_ && signalling_protection_->confidentiality;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.4.1 and TS 33.180 clause 9.3.2: whether an XML body of the given content type carries
// confidentiality protected content.
bool McServer::mcptt_xml_part(const std::string &type) const {
  return type == svc_.info_mime || type == resource_lists_mime || type == "application/pidf+xml" ||
         type == svc_.location_mime || type == "application/conference-info+xml";
}

//------------------------------------------------------------------------------
// Helper: the URI without its angle brackets and parameters.
std::string McServer::bare_uri(std::string uri) {
  if (const auto open = uri.find('<'); open != std::string::npos)
    uri = uri.substr(open + 1, uri.find('>', open) - open - 1);
  if (const auto params = uri.find(';'); params != std::string::npos) uri.resize(params);
  return uri;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.2 and TS 33.180 clause 9.3.3: between a local client and the server the XPK is the
// user's CSK and the XPK-ID its CSK-ID; past its Expiry time (TS 33.180 annex E.6.10) the CSK is no XPK any more.
std::optional<xmlsec::Key> McServer::user_xml_key(const std::string &sip) const {
  const auto found = users_.find(bare_uri(sip));
  if (found == users_.end() || !found->second.csk || !found->second.peer.empty() || !csk_in_use(*found->second.csk))
    return std::nullopt;
  return xmlsec::Key{found->second.csk->key, found->second.csk->csb_id, found->second.id};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.7 (TS 24.281 clause 7.3.7): "If confidentiality protection is enabled as specified in clause
// 6.6.2.3.1, and if the participating MCPTT function received a Client Server Key (CSK) within a SIP REGISTER request
// for service authorisation or SIP PUBLISH request for service authorisation, the participating MCPTT function may
// decide to update the CSK": a SIP MESSAGE to the public user identity (step 2) with the Accept-Contact (step 3), the
// P-Asserted-Service (step 4) and the new CSK in a MIKEY-SAKKE I_MESSAGE (step 5) from this function's identity to
// the user's MC service ID (TS 33.180 clause 5.8.1). TS 33.180 clause 5.8.2 step 2: the server uses the new CSK once
// the client answers 200 (OK); until then, and after any other answer, the CSK held stays.
void McServer::send_csk_download(const std::string &id) {
  const auto found = std::find_if(users_.begin(), users_.end(), [&id](const auto &entry) {
    return entry.second.id == id && entry.second.peer.empty();
  });
  if (!keys_ || !xml_protection() || found == users_.end() || !found->second.csk) {
    event("csk_download_refused", {{"user_id", id}});
    return;
  }
  keying::KeyMessage csk;
  std::string mikey;
  try {
    std::tie(csk, mikey) = keys_->make_csk(id);
  } catch (const std::exception &error) {
    event("csk_download_refused", {{"user_id", id}, {"reason", error.what()}});
    return;
  }
  const auto sip = found->first;
  sip_.request("MESSAGE", sip, "application/mikey", mikey,
               {{"Accept-Contact", icsi_accept()}, {"P-Asserted-Service", svc_.icsi}},
               [this, sip, id, csk](const SipResponse &response) {
                 if (response.status_code < 200) return;
                 const auto user = users_.find(sip);
                 if (response.status_code != 200 || user == users_.end() || user->second.id != id) {
                   event("csk_download_failed", {{"user_id", id}, {"status", response.status_code}});
                   return;
                 }
                 if (!user->second.protection)
                   user->second.protection = std::make_shared<ProtectedCall>(svc_.service == Service::mcvideo);
                 user->second.protection->set_floor(csk, floor_ssrcs_in_use(user->second.protection.get()));
                 user->second.csk = csk;
                 event("csk_downloaded", {{"user_id", id}, {"csk_id", csk.csb_id}});
               });
  event("csk_download_sent", {{"user_id", id}, {"csk_id", csk.csb_id}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.2 and TS 33.180 clause 9.3.3: between servers the XPK is the SPK; the key derives from
// the SPK and the sending server's PSI.
std::optional<xmlsec::Key> McServer::peer_xml_key(const std::string &peer, bool sending) const {
  const auto found = peers_.find(peer);
  if (found == peers_.end() || !found->second.spk_key) return std::nullopt;
  return xmlsec::Key{found->second.spk_key->key, found->second.spk_key->csb_id,
                     sending ? own_service_uri() : found->second.service_uri};
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.6.2.3.2 and 6.6.3.3.2 (TS 24.281 likewise): encrypt the protected XML content and sign the XML
// bodies of an outgoing SIP request or response with the XPK of its recipient: towards a client as the
// <signalling-protection> elements enable it, with the client's CSK; towards a peer server as
// <protection-between-mcptt-servers>/<allow-signalling-protection> ("or no <allow-signalling-protection> element is
// present") enables it, with the SPK. A body that needs protection without a usable key (no CSK, a CSK past its
// Expiry time, TS 33.180 annex E.6.10, no SPK), or before the service configuration is known (whether it needs
// protection is not known then), is not sent: never in the clear instead. The SIP engine's local error path applies
// (the request is not sent, a response is not given).
std::vector<BodyPart> McServer::protect_outgoing(const SipTransmission &transmission, std::vector<BodyPart> parts) {
  // The requests and responses of a client's configuration management, group document or GKTP subscription follow
  // that subscription's security context, not the service configuration document (subscription_protection).
  if (const auto hiding = subscription_protection(transmission.call_id)) {
    if (!*hiding) return parts;
    throw std::runtime_error("subscription with identity hiding (CSK in the initial SUBSCRIBE): not supported, the "
                             "protection it requires cannot be applied");
  }
  const bool to_client = transmission.address == core_address_;
  const auto peer = to_client ? std::string() : peer_at(transmission.address);
  if (!to_client && peer.empty()) return parts;
  const auto any = [&parts](auto condition) { return std::any_of(parts.begin(), parts.end(), condition); };
  const bool encryptable = any([this](const BodyPart &part) {
    return mcptt_xml_part(part.content_type) && !xmlsec::is_protected(part.body);
  });
  const bool signable = !any([](const BodyPart &part) { return part.content_type == signed_mime; }) &&
                        any([this](const BodyPart &part) { return signable_part(part.content_type); });
  if (!encryptable && !signable) return parts;
  if (!signalling_protection_)
    throw std::runtime_error("the service configuration document has not been read: signalling protection unknown");
  const auto &policy = *signalling_protection_;
  const bool encrypts = encryptable && (to_client ? policy.confidentiality : policy.between_servers);
  const bool signs = signable && (to_client ? policy.integrity : policy.between_servers);
  if (!encrypts && !signs) return parts;
  const auto key = to_client ? user_xml_key(transmission.response ? transmission.from_uri : transmission.to_uri)
                             : peer_xml_key(peer, true);
  if (!key)
    throw std::runtime_error(to_client ? "no usable CSK (XPK) of the recipient for the protection enabled"
                                       : "no SPK of the peer server for the protection enabled");
  if (encrypts)
    for (auto &part : parts)
      if (mcptt_xml_part(part.content_type) && !xmlsec::is_protected(part.body)) {
        part.body = xmlsec::encrypt(part.body, *key, mcptt_xml_profile());
        ++xml_encrypted_;
      }
  if (signs) parts = sign_parts(std::move(parts), *key);
  return parts;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 and TS 24.481 clause 6.3.13.3.2.2: whether the initial SUBSCRIBE of a configuration
// management, group document or GKTP subscription carried "the CSK [...] in an application/mikey MIME body"
// (identity hiding, TS 24.484 clause 6.3.13.2.2 step d, TS 24.481 clause 6.3.13.2.1 step d).
bool McServer::csk_in_subscribe(const SipMessage &message) {
  return std::any_of(message.parts.begin(), message.parts.end(),
                     [](const BodyPart &part) { return part.content_type == "application/mikey"; });
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 (TS 24.481 clause 6.3.13.3.2.2 for the GMS, whose procedure the GKTP subscription of
// TS 24.481 clause 7.7 also follows): "Upon sending a SIP NOTIFY request associated with a subscription created as
// result of the received initial SIP SUBSCRIBE request, if the CSK is received in an application/mikey MIME body of
// the initial SIP SUBSCRIBE request, the CMS shall perform the confidentiality protection procedures and integrity
// protection procedures defined in 3GPP TS 24.379 [9] for MCPTT server". For the dialog of a client's subscription
// of these procedures: whether that protection applies (identity hiding); nothing for any other dialog (an MCS
// server's group document subscription included), whose protection is decided as before. Identity hiding is not
// supported yet: with it protection applies, and protect_outgoing then refuses (no key it could use), never clear.
// The GMK in a GKTP document stays protected by its own MIKEY-SAKKE I_MESSAGE (TS 33.180 clause 5.7) either way.
std::optional<bool> McServer::subscription_protection(const std::string &dialog) const {
  if (dialog.empty()) return std::nullopt;
  if (const auto found = config_subscriptions_.find(dialog); found != config_subscriptions_.end())
    return found->second.identity_hiding;
  if (const auto found = doc_subscriptions_.find(dialog); found != doc_subscriptions_.end() && !found->second.server)
    return found->second.identity_hiding;
  if (const auto found = key_subscriptions_.find(dialog); found != key_subscriptions_.end())
    return found->second.identity_hiding;
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.4.2 step 4: the XPK for the XPK-ID of a received signature: the SPK of the peer
// server, or the CSK of a local user while it may be used (TS 33.180 annex E.6.10).
std::optional<xmlsec::Key> McServer::key_by_id(const SipTransmission &transmission, std::uint32_t id) const {
  if (transmission.address != core_address_) {
    const auto peer = peer_at(transmission.address);
    return peer.empty() ? std::nullopt : peer_xml_key(peer, false);
  }
  for (const auto &[sip, user] : users_)
    if (user.csk && user.csk->csb_id == id && user.peer.empty())
      return csk_in_use(*user.csk) ? std::optional(xmlsec::Key{user.csk->key, user.csk->csb_id, user.id})
                                   : std::nullopt;
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.1.4: verify the integrity of the XML bodies of a received SIP request or response, then
// decrypt their confidentiality protected content, before any other procedure.
std::vector<BodyPart> McServer::protect_incoming(const SipTransmission &transmission, std::vector<BodyPart> parts) {
  const bool uploads = std::any_of(parts.begin(), parts.end(),
                                   [](const BodyPart &part) { return part.content_type == "application/mikey"; });
  // TS 24.379 clause 6.6.1.4 step 1: integrity first. The service authorisation's own CSK is checked
  // when the request is handled.
  if (const auto signatures = std::find_if(parts.begin(), parts.end(),
                                           [](const BodyPart &part) { return part.content_type == signed_mime; });
      signatures != parts.end()) {
    const auto id = xmlsec::signature_key_id(signatures->body);
    const auto key = id ? key_by_id(transmission, *id) : std::nullopt;
    if (key || !uploads) parts = verify_parts(std::move(parts), key);
  }
  for (auto &part : parts) {
    if (!mcptt_xml_part(part.content_type) || !xmlsec::is_protected(part.body)) continue;
    std::optional<xmlsec::Key> key;
    if (transmission.address == core_address_) {
      const auto id = xmlsec::key_id(part.body);
      // TS 33.180 annex E.6.10: a CSK past its Expiry time opens nothing (the content is refused below).
      for (const auto &[sip, user] : users_)
        if (id && user.csk && user.csk->csb_id == *id && user.peer.empty() && csk_in_use(*user.csk))
          key = xmlsec::Key{user.csk->key, user.csk->csb_id, user.id};
    } else if (const auto peer = peer_at(transmission.address); !peer.empty())
      key = peer_xml_key(peer, false);
    // The service authorisation's CSK is not known until the request is handled.
    if (!key && uploads) continue;
    if (!key) throw std::runtime_error("no XPK for the protected content");
    part.body = xmlsec::decrypt(part.body, *key);
    ++xml_decrypted_;
  }
  return parts;
}

} // namespace mcx
