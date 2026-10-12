//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData signalling and XML protection with clients (CSK).
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.4.1 (table 8.5.4.1-1): the wire profile of the MCData Protected Payload message.
keying::KeyParameterWireProfile DataServer::payload_profile() const {
  // The local values of the Protected Payload message (algorithm 1, ciphertext IEI
  // 0x78), unless the security configuration names others.
  if (!cfg_.contains("security")) return {10, 1, 0x79, 0x78};
  const auto &wire = cfg_.at("security").at("key_parameter_profile");
  return {wire.at("message_type").get<std::uint8_t>(), wire.at("algorithm").get<std::uint8_t>(),
          wire.at("key_parameters_iei").get<std::uint8_t>(), wire.at("encrypted_payload_iei").get<std::uint8_t>()};
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
    part.body = xmlsec::decrypt(part.body, *key);
    ++xml_decrypted_;
  }
  return parts;
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
// with its CSK and its XML with its XPK.
std::vector<BodyPart> DataServer::seal_for(const std::string &sip, std::vector<BodyPart> parts) {
  const auto *key = signalling_key(sip);
  if (!key) return encrypt_xml(xml_key(sip), std::move(parts));
  for (auto &part : parts) {
    if (part.content_type != mcdata::signalling_mime || part.body.empty()) continue;
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
    if (part.body.empty() || !(static_cast<std::uint8_t>(part.body[0]) & 0x40))
      throw std::runtime_error("clear signalling from a client that protects its signalling");
    const std::span bytes(reinterpret_cast<const std::uint8_t *>(part.body.data()), part.body.size());
    if (keying::payload_key_id(bytes) != key.csb_id) throw std::runtime_error("signalling under another key");
    const auto opened = keying::open_payload(bytes, key.key, payload_profile());
    if (opened.plain.empty() || (opened.message_type & 0x3f) != (opened.plain[0] & 0x3f) || (opened.plain[0] & 0xc0))
      throw std::runtime_error("protected signalling type mismatch");
    part.body.assign(opened.plain.begin(), opened.plain.end());
    ++signalling_opened_;
  }
  return parts;
}

} // namespace mcx
