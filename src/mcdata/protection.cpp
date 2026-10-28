//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData signalling and XML protection with clients (CSK): signalling payloads, XML confidentiality and XML integrity.
//
// Specifications: TS 33.180 V19.5.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.4.1 (table 8.5.4.1-1): the wire profile of the MCData Protected Payload message.
keying::KeyParameterWireProfile DataServer::payload_profile() const {
  // The local values of the Protected Payload message (algorithm 1, ciphertext IEI
  // 0x78), unless the security configuration names others.
  if (!cfg_.contains("security")) return {10, 1, 0x79, 0x78};
  const auto &wire = cfg_.at("security").at("key_parameter_profile");
  keying::KeyParameterWireProfile profile{
      wire.at("message_type").get<std::uint8_t>(), wire.at("algorithm").get<std::uint8_t>(),
      wire.at("key_parameters_iei").get<std::uint8_t>(), wire.at("encrypted_payload_iei").get<std::uint8_t>()};
  // TS 33.180 table 8.5.4.2-2: the agreed profile's code of DP_AES_256_GCM, if it names one (no default: TS 33.180
  // assigns no code).
  if (wire.contains("algorithm_256")) profile.algorithm_256 = wire.at("algorithm_256").get<std::uint8_t>();
  return profile;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.5.1: the CSK a client's MCData signalling is protected with, when signalling protection is
// configured; null otherwise.
const keying::KeyMessage *DataServer::signalling_key(const std::string &sip) const {
  if (!protect_signalling()) return nullptr;
  const auto found = users_.find(sip);
  return found != users_.end() && found->second.csk ? &*found->second.csk : nullptr;
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.10 ("the time in UTC at which the associated key shall no longer be used"; 0: never) and annex
// E.6.9 (Status), at each use of a client's CSK: throws CskExpired once it may no longer be used.
void DataServer::require_key_in_use(const keying::KeyMessage &csk) {
  try {
    keying::require_in_use(csk, static_cast<std::uint64_t>(std::time(nullptr)));
  } catch (const std::exception &error) {
    throw CskExpired(std::string("CSK ") + std::to_string(csk.csb_id) + ": " + error.what());
  }
}

//------------------------------------------------------------------------------
// The same for an XPK made from a client's CSK held here (xml_key_of). A CSK being uploaded is not held yet: its
// Expiry time was checked when it was accepted (KeyClient::accept_csk).
void DataServer::require_xpk_in_use(const xmlsec::Key &key) const {
  for (const auto &[sip, user] : users_)
    if (user.csk && user.csk->csb_id == key.id && user.csk->key == key.xpk) require_key_in_use(*user.csk);
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.10: before parts are protected for the client sip: throws CskExpired when the client holds a
// CSK that may no longer be used and the parts would need it: signalling to seal (signalling protection), XML content
// to encrypt (confidentiality protection) or XML bodies to sign (integrity protection, sign_outgoing).
void DataServer::require_csk_in_use(const std::string &sip, const std::vector<BodyPart> &parts) const {
  const auto found = users_.find(sip);
  if (found == users_.end() || !found->second.csk) return;
  const auto any = [&parts](auto condition) { return std::any_of(parts.begin(), parts.end(), condition); };
  const bool seals = protect_signalling() && any([](const BodyPart &part) {
                       return part.content_type == mcdata::signalling_mime && !part.body.empty();
                     });
  const bool encrypts = protects_xml() && any([](const BodyPart &part) { return xml_part(part.content_type); });
  const bool signs = integrity_protection() &&
                     !any([](const BodyPart &part) { return part.content_type == signed_mime; }) &&
                     any([](const BodyPart &part) { return xmlsec::is_xml_mime(part.content_type); });
  if (seals || encrypts || signs) require_key_in_use(*found->second.csk);
}

//------------------------------------------------------------------------------
// Helper: a message to the user that is not sent, as its CSK may no longer be used (TS 33.180 annex E.6.10).
void DataServer::csk_expired_not_sent(const std::string &user, const char *what, const std::exception &error) {
  event("mcdata_csk_expired_not_sent", {{"user_id", user}, {"what", what}, {"reason", error.what()}});
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.5.2: for MCData the XPK is the DPPK: the XML key of a CSK, with its key identifier and
// the identity it protects.
xmlsec::Key DataServer::xml_key_of(const keying::KeyMessage &csk, const std::string &id) {
  xmlsec::Key key;
  key.xpk = csk.key;
  key.id = csk.csb_id;
  key.user = id;
  return key;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.5.2.2: the key that protects the XML of a client (from its CSK), when XML protection is
// configured.
std::optional<xmlsec::Key> DataServer::xml_key(const std::string &sip) const {
  if (!protects_xml()) return std::nullopt;
  const auto found = users_.find(sip);
  if (found == users_.end() || !found->second.csk) return std::nullopt;
  return xml_key_of(*found->second.csk, found->second.id);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.2 and TS 24.282 clause 6.5.1.1: the elements and the URI attributes of the XML bodies that
// are confidentiality protected.
const xmlsec::Profile &DataServer::xml_profile() {
  static const xmlsec::Profile profile{
      {"mcdata-access-token", "mcdata-request-uri", "mcdata-calling-user-id", "mcdata-called-party-id",
       "mcdata-calling-group-id", "alert-ind", "originated-by", "mcdata-client-id", "functional-alias-URI",
       "called-functional-alias-URI",
       // TS 24.282 annex D.4: the location reported, when confidentiality protection is required.
       "CurrentServingEcgi", "NeighbouringEcgi", "MbmsSaId", "MbsfnArea", "CL_5GMbsfsaArea", "CurrentServingNcgi",
       "CL_NeighbouringNcgi", "CL_BearingAndSpeed", "longitude", "latitude", "altitude", "horizontalaccuracy",
       "verticalaccuracy"},
      {{"entry", "uri"}, {"presence", "entity"}, {"affiliation", "group"}, {"functionalAlias", "functionalAliasID"}}};
  return profile;
}

//------------------------------------------------------------------------------
// Helper: whether a MIME body is one of the XML bodies that carry protected content.
bool DataServer::xml_part(std::string_view type) {
  return type == mcdata::info_mime || type == resource_lists_mime || type == "application/pidf+xml" ||
         type == mcdata::location_mime;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 6.5.2.3.2 and 6.5.2.3.3 (TS 33.180 clause 9.3.4.2): the XML bodies sent are encrypted with the
// key given, if any.
std::vector<BodyPart> DataServer::encrypt_xml(const std::optional<xmlsec::Key> &key, std::vector<BodyPart> parts) {
  if (!key) return parts;
  for (auto &part : parts)
    if (xml_part(part.content_type)) {
      require_xpk_in_use(*key); // TS 33.180 annex E.6.10
      part.body = xmlsec::encrypt(part.body, *key, xml_profile());
      ++xml_encrypted_;
    }
  return parts;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 6.5.2.4.1 and 6.5.2.4.2: the protected XML bodies received are decrypted; protected XML without
// a key is refused.
std::vector<BodyPart> DataServer::decrypt_xml(const std::optional<xmlsec::Key> &key, std::vector<BodyPart> parts) {
  for (auto &part : parts) {
    if (!xml_part(part.content_type) || !xmlsec::is_protected(part.body)) continue;
    if (!key) throw std::runtime_error("encrypted XML from a client without an XPK");
    require_xpk_in_use(*key); // TS 33.180 annex E.6.10: refused (warning 140)
    part.body = xmlsec::decrypt(part.body, *key);
    ++xml_decrypted_;
  }
  return parts;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 6.5.1.3, 6.5.3.1 and 6.5.3.3.2 with TS 33.180 clause 9.3.5: just prior to sending, when integrity
// protection is enabled, every XML MIME body of a request or response to a client (already confidentiality protected
// where configured) is signed under its CSK; "all XML MIME bodies", not only the types clause 6.5.3.1 lists
// (maintainer decision M11).
std::vector<BodyPart> DataServer::sign_outgoing(const SipTransmission &transmission, std::vector<BodyPart> parts) {
  if (transmission.address != core_address_) return parts;
  // Before the service configuration document is read, whether its protection applies is not known: an XML body to
  // a client is not sent then, never in the clear instead.
  if (!signalling_protection_ &&
      std::any_of(parts.begin(), parts.end(), [](const BodyPart &part) { return xmlsec::is_xml_mime(part.content_type); }))
    throw std::runtime_error("the service configuration document has not been read: signalling protection unknown");
  auto uri = transmission.response ? transmission.from_uri : transmission.to_uri;
  if (const auto open = uri.find('<'); open != std::string::npos)
    uri = uri.substr(open + 1, uri.find('>', open) - open - 1);
  if (const auto params = uri.find(';'); params != std::string::npos) uri.resize(params);
  const auto found = users_.find(uri);
  // TS 24.282 clauses 6.5.2.3.2 and 6.5.3.3.2: required protection is never dropped. A message to a client whose CSK
  // this server does not hold is not sent when confidentiality protection applies to one of its XML bodies or
  // integrity protection to any of them.
  if (found == users_.end() || !found->second.csk) {
    const bool applies = std::any_of(parts.begin(), parts.end(), [this](const BodyPart &part) {
      return (protects_xml() && xml_part(part.content_type) && !xmlsec::is_protected(part.body)) ||
             (integrity_protection() && part.content_type != signed_mime && xmlsec::is_xml_mime(part.content_type));
    });
    if (applies) throw std::runtime_error("XML protection required without the client's CSK");
    return parts;
  }
  if (!integrity_protection() ||
      std::any_of(parts.begin(), parts.end(), [](const BodyPart &part) { return part.content_type == signed_mime; }))
    return parts;
  const auto key = xml_key_of(*found->second.csk, found->second.id);
  std::vector<xmlsec::SignedBody> bodies;
  for (auto &part : parts)
    if (part.content_type != signed_mime && xmlsec::is_xml_mime(part.content_type)) {
      if (part.content_id.empty()) part.content_id = random_id().substr(0, 16) + "@mcx";
      bodies.push_back({part.content_id, part.body});
    }
  if (bodies.empty()) return parts;
  // TS 33.180 annex E.6.10: not signed past the CSK's Expiry time; the message is not sent (never unsigned).
  require_key_in_use(*found->second.csk);
  parts.push_back({signed_mime, xmlsec::sign(bodies, key, "urn:3gpp:ns:mcpttSignedDoc:1.0")});
  ++xml_signed_;
  return parts;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.5.1.4 step 1 and clause 6.5.3.4: before any other procedure, the signatures of a request or
// response from a client are verified under the CSK their XPK-ID names, then removed; a failure is raised as "139 ..."
// (the request is refused with 403, clause 6.5.3.4.2 steps 3 and 5). The service authorisation that uploads the CSK
// is verified when the CSK is accepted (authorise_csk), and the client's REGISTER inside a third-party REGISTER by
// third_party_register.
std::vector<BodyPart> DataServer::verify_incoming(const SipTransmission &transmission, std::vector<BodyPart> parts) {
  const auto signatures =
      std::find_if(parts.begin(), parts.end(), [](const BodyPart &part) { return part.content_type == signed_mime; });
  if (signatures == parts.end() || transmission.address != core_address_) return parts;
  std::optional<xmlsec::Key> key;
  try {
    const auto id = xmlsec::signature_key_id(signatures->body);
    for (const auto &[sip, user] : users_)
      if (id && user.csk && user.csk->csb_id == *id) {
        require_key_in_use(*user.csk); // TS 33.180 annex E.6.10: refused with warning 139
        key = xml_key_of(*user.csk, user.id);
      }
  } catch (const std::exception &error) {
    throw std::runtime_error(std::string("139 ") + error.what());
  }
  if (!key) {
    if (std::any_of(parts.begin(), parts.end(),
                    [](const BodyPart &part) { return part.content_type == "application/mikey"; }))
      return parts;
    throw std::runtime_error("139 no XPK for the signatures");
  }
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
// TS 24.282 clause 6.5.3.4.2: the signatures among the parts verified under the key and removed; without a key, or when
// one fails, the 403 response with warning 139 (steps 3 and 5). Parts without signatures pass unchanged.
std::optional<SipResponse> DataServer::verify_signatures(std::vector<BodyPart> &parts,
                                                         const std::optional<xmlsec::Key> &key,
                                                         const std::string &user) {
  const auto signatures =
      std::find_if(parts.begin(), parts.end(), [](const BodyPart &part) { return part.content_type == signed_mime; });
  if (signatures == parts.end()) return std::nullopt;
  std::vector<xmlsec::SignedBody> bodies;
  for (const auto &part : parts)
    if (part.content_type != signed_mime && !part.content_id.empty()) bodies.push_back({part.content_id, part.body});
  try {
    if (!key) throw std::runtime_error("no XPK for the signatures");
    require_xpk_in_use(*key); // TS 33.180 annex E.6.10
    (void)xmlsec::verify(signatures->body, bodies, *key);
  } catch (const std::exception &error) {
    ++xml_refused_;
    event("mcdata_xml_refused", {{"user_id", user}, {"reason", std::string("139 ") + error.what()}});
    return reject(403, "139 integrity protection check failed", user, "integrity");
  }
  ++xml_verified_;
  parts.erase(signatures);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.5.3 over the media plane: the signalling bodies of MSRP SEND requests are
// opened as they arrive on a client's leg and sealed for the client of each leg.
std::vector<std::pair<std::string, std::string>>
DataServer::seal_msrp(const std::string &owner, std::vector<std::pair<std::string, std::string>> bodies) {
  const auto *user = by_id(owner);
  if (!user || !signalling_key(user->sip)) return bodies;
  std::vector<BodyPart> parts;
  for (auto &[type, value] : bodies) parts.push_back({type, value});
  parts = seal_for(user->sip, std::move(parts));
  bodies.clear();
  for (auto &part : parts) bodies.emplace_back(part.content_type, part.body);
  return bodies;
}

//------------------------------------------------------------------------------
// Helper: seal_for the user with this MCData ID, if it is known.
std::vector<BodyPart> DataServer::seal_for_id(const std::string &id, std::vector<BodyPart> parts) {
  const auto *user = by_id(id);
  return user ? seal_for(user->sip, std::move(parts)) : parts;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.6.3.3 (TS 33.180 clauses 8.5.4 and 9.5.3): the MCData signalling for a client is protected
// with its CSK and its XML with its XPK. The algorithm is DP_AES_128_GCM: TS 24.282 clause 4.7 uses the one "indicated
// in the Key Download procedure", which has no coding for it (TS 33.180 clause 5.8.1), so the default of table
// 8.5.4.1-1 NOTE 6 applies.
std::vector<BodyPart> DataServer::seal_for(const std::string &sip, std::vector<BodyPart> parts) {
  // TS 33.180 annex E.6.10: nothing is protected for this client with a CSK past its Expiry time (CskExpired: the
  // message is not sent).
  require_csk_in_use(sip, parts);
  const auto *key = signalling_key(sip);
  if (!key) return encrypt_xml(xml_key(sip), std::move(parts));
  for (auto &part : parts) {
    if (part.content_type != mcdata::signalling_mime || part.body.empty()) continue;
    require_key_in_use(*key);
    keying::ProtectedPayload message;
    message.message_type = static_cast<std::uint8_t>(part.body[0]) | 0x40; // TS 33.180 clause 8.5.1: bit 7
    message.unix_seconds = static_cast<std::uint64_t>(std::time(nullptr));
    message.dppk_id = key->csb_id;
    message.plain.assign(part.body.begin(), part.body.end());
    const auto sealed = keying::seal_payload(message, key->key, payload_profile());
    part.body.assign(sealed.begin(), sealed.end());
    ++signalling_sealed_;
  }
  return encrypt_xml(xml_key(sip), std::move(parts));
}

//------------------------------------------------------------------------------
// TS 24.282 clause 6.6.3.3 (TS 33.180 clause 8.5.4): the signalling bodies from a client with a CSK, opened. A
// clear body from such a client, a body under another key or one that fails authentication is refused.
std::vector<BodyPart> DataServer::open_from(const keying::KeyMessage &key, std::vector<BodyPart> parts) {
  for (auto &part : parts) {
    if (part.content_type != mcdata::signalling_mime) continue;
    require_key_in_use(key); // TS 33.180 annex E.6.10: refused past the CSK's Expiry time
    if (part.body.empty() || !(static_cast<std::uint8_t>(part.body[0]) & 0x40))
      throw std::runtime_error("clear signalling from a client that protects its signalling");
    const std::span bytes(reinterpret_cast<const std::uint8_t *>(part.body.data()), part.body.size());
    if (keying::payload_key_id(bytes) != key.csb_id) throw std::runtime_error("signalling under another key");
    // TS 33.180 annex F.1.5 (last paragraph): CSK signalling, the one use of DP_AES_256_GCM, accepted as well.
    const auto opened = keying::open_payload(bytes, key.key, payload_profile(), true);
    if (opened.plain.empty() || (opened.message_type & 0x3f) != (opened.plain[0] & 0x3f) || (opened.plain[0] & 0xc0))
      throw std::runtime_error("protected signalling type mismatch");
    part.body.assign(opened.plain.begin(), opened.plain.end());
    ++signalling_opened_;
  }
  return parts;
}

} // namespace mcx
