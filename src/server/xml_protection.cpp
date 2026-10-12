//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// XML integrity and confidentiality protection of the SIP bodies (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.1: whether integrity protection of XML bodies is configured.
bool McServer::integrity_protection() const {
  return cfg_.contains("security") && cfg_.at("security").value("integrity_protection", false);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.5: whether an XML body of the given content type is signed.
bool McServer::signable_part(const std::string &type) const {
  if (type == svc_.info_mime) return true;
  static const std::set<std::string> types{"application/poc-settings+xml",
                                           resource_lists_mime,
                                           "application/vnd.3gpp.mcptt-location-info+xml",
                                           "application/vnd.3gpp.mcptt-affiliation-command+xml",
                                           "application/conference-info+xml",
                                           "application/pidf+xml",
                                           "application/xcap-diff+xml",
                                           "application/simple-filter+xml",
                                           "application/vnd.3gpp.mcptt-regroup+xml"};
  return types.contains(type);
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
// TS 24.379 clause 6.6.2.1: whether confidentiality protection of XML content is configured (and keys are
// available).
bool McServer::xml_protection() const {
  return keys_ && cfg_.contains("security") && cfg_.at("security").value("confidentiality_protection", false);
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
// user's CSK and the XPK-ID its CSK-ID.
std::optional<xmlsec::Key> McServer::user_xml_key(const std::string &sip) const {
  const auto found = users_.find(bare_uri(sip));
  if (found == users_.end() || !found->second.csk || !found->second.peer.empty()) return std::nullopt;
  return xmlsec::Key{found->second.csk->key, found->second.csk->csb_id, found->second.id};
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
// TS 24.379 clauses 6.6.2.3.2 and 6.6.3.3.2: encrypt the protected XML content and sign the XML bodies of an
// outgoing SIP request or response with the XPK of its recipient.
std::vector<BodyPart> McServer::protect_outgoing(const SipTransmission &transmission, std::vector<BodyPart> parts) {
  if (!xml_protection() && !integrity_protection()) return parts;
  std::optional<xmlsec::Key> key;
  if (transmission.address == core_address_)
    key = user_xml_key(transmission.response ? transmission.from_uri : transmission.to_uri);
  else if (const auto peer = peer_at(transmission.address); !peer.empty())
    key = peer_xml_key(peer, true);
  if (!key) return parts;
  if (xml_protection())
    for (auto &part : parts)
      if (mcptt_xml_part(part.content_type) && !xmlsec::is_protected(part.body)) {
        part.body = xmlsec::encrypt(part.body, *key, mcptt_xml_profile());
        ++xml_encrypted_;
      }
  if (integrity_protection()) parts = sign_parts(std::move(parts), *key);
  return parts;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.4.2 step 4: the XPK for the XPK-ID of a received signature: the SPK of the peer
// server, or the CSK of a local user.
std::optional<xmlsec::Key> McServer::key_by_id(const SipTransmission &transmission, std::uint32_t id) const {
  if (transmission.address != core_address_) {
    const auto peer = peer_at(transmission.address);
    return peer.empty() ? std::nullopt : peer_xml_key(peer, false);
  }
  for (const auto &[sip, user] : users_)
    if (user.csk && user.csk->csb_id == id && user.peer.empty())
      return xmlsec::Key{user.csk->key, user.csk->csb_id, user.id};
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
      for (const auto &[sip, user] : users_)
        if (id && user.csk && user.csk->csb_id == *id && user.peer.empty())
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
