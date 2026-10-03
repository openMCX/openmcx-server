// Application signalling security: confidentiality of sensitive XML content under an XML Protection Key (XPK), and
// integrity of whole XML MIME bodies. Between a client and its server the XPK is the client's CSK, and the keys derive
// from it and the client's MC service user ID (TS 33.180 annex F.1.4).
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.281
// V19.6.0 (Rel-19).
#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// TS 33.180 clause 9.3, TS 24.282 clause 6.5 and TS 24.379 clause 6.6: application signalling security.
namespace mcx::xmlsec {
//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.3 and annex F.1.4: an XML Protection Key with its ID and the MC service user ID it is used for.
struct Key {
  std::array<std::uint8_t, 16> xpk{};
  std::uint32_t id = 0; // XPK-ID: the CSK-ID
  std::string user;     // MC service user ID of the client (P0 of TS 33.180 annex F.1.4)
};

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.4 with TS 33.220 annex B: FC 0x51 (confidentiality), P0 the MC service user ID, P1 the XPK-ID;
// the 128 least significant bits.
std::array<std::uint8_t, 16> confidentiality_key(const Key &key);

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.4 with TS 33.220 annex B: FC 0x52 (integrity), P0 the MC service user ID, P1 the XPK-ID; the 128
// least significant bits.
std::array<std::uint8_t, 16> integrity_key(const Key &key);

//------------------------------------------------------------------------------
// TS 33.180 clauses 9.3.4.2 and 9.3.4.3: the XML elements whose content is encrypted (an element carries type="Normal"
// in clear and type="Encrypted" around its <EncryptedData>), and the (element, attribute) pairs whose URI value is
// encrypted.
struct Profile {
  std::set<std::string> elements;
  std::set<std::pair<std::string, std::string>> uri_attributes;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 4.8 and TS 24.281 clause 4.8: the sensitive application data of MC service signalling, in the
// service's element names: <mcptt-request-uri> or, with the info prefix "mcvideo", <mcvideo-request-uri> and so on;
// location (TS 24.379 annex F.3) and the URI attributes of affiliation, private call, conference and functional alias
// bodies.
const Profile &signalling_profile(std::string_view info_prefix = "mcptt");

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.4.2: each listed element's content becomes <EncryptedData> (xmlenc 1.1,
// http://www.w3.org/2009/xmlenc11#aes128-gcm, KeyName = base64 XPK-ID).
std::string encrypt(std::string_view xml, const Key &key, const Profile &profile);

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.6.2.4.1 to 6.6.2.4.3: decrypts every <EncryptedData> element and encrypted URI attribute under
// the key. Throws when one cannot be decrypted (TS 24.282 clause 6.5.2.4.2: 403, warning 140).
std::string decrypt(std::string_view xml, const Key &key);

//------------------------------------------------------------------------------
// TS 33.180 clause 11.1.3: the IS proxy re-protects encrypted content under another key (as TS 24.379 clause 6.6.2.5).
// Every <EncryptedData> and encrypted URI is opened with `from` and sealed again with `to`, so exactly the same
// content stays protected.
std::string reencrypt(std::string_view xml, const Key &from, const Key &to);

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.4.1: true when the document holds <EncryptedData> or an encrypted URI.
bool is_protected(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.4.1: the XPK-ID (KeyName, or the key-id of an encrypted URI) of protected content, which
// selects the key before decryption; nothing when the content is in clear.
std::optional<std::uint32_t> key_id(std::string_view xml);

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.4.3 and TS 24.282 clause 6.5.2.3.4: the confidentiality protection domain of an encrypted URI,
// sip:<base64 ciphertext>;iv=<base64 IV>;key-id=<base64 XPK-ID>;alg=128-aes-gcm@<confidentiality protection domain>.
inline constexpr const char *encryption_domain = "mc1-encryption.3gppnetwork.org";

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.4.3 and TS 24.282 clause 6.5.2.3.4: encrypts a URI in an XML attribute.
std::string encrypt_uri(std::string_view uri, const Key &key);

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.4.3: decrypts an encrypted URI of an XML attribute.
std::string decrypt_uri(std::string_view uri, const Key &key);

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.4.3: whether a URI is encrypted (it has the confidentiality protection domain).
bool is_encrypted_uri(std::string_view uri);

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.5, TS 24.379 clause 6.6.3 and TS 24.282 clause 6.5.3: integrity of whole XML MIME bodies. Each
// body, named by its Content-ID, gets an xmldsig <Signature> (a SHA-256 digest of the body's octets referenced as
// cid:<id>, and HMAC-SHA256 over the exclusive canonical SignedInfo under the integrity key of TS 33.180 annex F.1.4,
// KeyName the XPK-ID) in a <signatures> document in the given namespace (urn:3gpp:ns:mcpttSignedDoc:1.0).
struct SignedBody {
  std::string content_id;
  std::string body;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.5 and TS 24.379 clause 6.6.3: the <signatures> document with one signature per body.
std::string sign(const std::vector<SignedBody> &bodies, const Key &key, std::string_view root_namespace);

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.4.2: the XPK-ID of the first signature, which selects the key before verification.
std::optional<std::uint32_t> signature_key_id(std::string_view signatures);

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.4.2: verifies every signature against the body its reference names; throws when one fails
// (403, warning 139). Returns the Content-IDs verified.
std::set<std::string> verify(std::string_view signatures, const std::vector<SignedBody> &bodies, const Key &key);
} // namespace mcx::xmlsec
