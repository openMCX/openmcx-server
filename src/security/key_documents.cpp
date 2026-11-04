//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Key management documents: the KMS response XML (KmsInit, KmsKeyProv, KmsCertCache) over TLS, the KMS Redirect
// Response, and the MCS GKTP document with its xcap-diff subscription and notification bodies.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), RFC 4825, RFC 4826, RFC 5874, RFC 5875.
#include "mcx/key_documents.hpp"

#include "mcx/kms_xml_signature.hpp"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <charconv>
#include <ctime>
#include <limits>
#include <memory>
#include <stdexcept>

namespace mcx::keying {
namespace {
constexpr auto kmsns = "urn:3gpp:ns:mcsecKMSInterface:1.0";
constexpr auto pocns = "urn:oma:xml:poc:list-service";
constexpr auto gktpns = "urn:3gpp:ns:mcpttGKTP:1.0";
constexpr auto xsins = "http://www.w3.org/2001/XMLSchema-instance";
constexpr auto xencns = "http://www.w3.org/2001/04/xmlenc#";
constexpr auto dsigns = "http://www.w3.org/2000/09/xmldsig#";
// TS 33.180 clause 9.3.4.2 and annex D.3.3.2: the AES-256 key wrap (RFC 3394) for TrK-encrypted keys.
constexpr auto kw_aes256 = "http://www.w3.org/2001/04/xmlenc#kw-aes256";

//------------------------------------------------------------------------------
// Helper: throws the given reason when a condition fails.
void require(bool ok, const char *reason) {
  if (!ok) throw std::runtime_error(reason);
}

//------------------------------------------------------------------------------
// Helper: escapes an XML text or attribute value; refuses NUL and control characters.
std::string escape(std::string_view in) {
  require(in.find('\0') == in.npos, "embedded NUL in XML value");
  std::string out;
  for (char character : in) {
    switch (character) {
    case '&': out += "&amp;"; break;
    case '<': out += "&lt;"; break;
    case '>': out += "&gt;"; break;
    case '\"': out += "&quot;"; break;
    case '\'': out += "&apos;"; break;
    default: require(static_cast<unsigned char>(character) >= 32, "control in XML value"); out += character;
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: an element with escaped text content.
std::string tag(std::string_view name, std::string_view value) {
  return "<" + std::string(name) + ">" + escape(value) + "</" + std::string(name) + ">";
}

//------------------------------------------------------------------------------
// Helper: lower-case hexBinary encoding.
std::string hex(std::span<const std::uint8_t> bytes) {
  const char *digits = "0123456789abcdef";
  std::string out;
  for (auto octet : bytes) {
    out += digits[octet >> 4];
    out += digits[octet & 15];
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: hexBinary decoding, ignoring white space.
Bytes unhex(std::string_view text) {
  std::string compact;
  for (char character : text)
    if (character != ' ' && character != '\r' && character != '\n' && character != '\t') compact += character;
  require(compact.size() % 2 == 0 && !compact.empty(), "invalid hexBinary length");
  Bytes out;
  for (std::size_t index = 0; index < compact.size(); index += 2) {
    unsigned value = 0;
    auto result = std::from_chars(compact.data() + index, compact.data() + index + 2, value, 16);
    require(result.ec == std::errc{} && result.ptr == compact.data() + index + 2, "invalid hexBinary");
    out.push_back(value);
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: a decimal unsigned integer.
std::uint64_t number(std::string_view value) {
  std::uint64_t parsed = 0;
  auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
  require(result.ec == std::errc{} && result.ptr == value.data() + value.size(), "invalid integer");
  return parsed;
}

//------------------------------------------------------------------------------
// Helper: an NTP time (seconds since 1900) as a UTC date and time "YYYY-MM-DDThh:mm:ssZ".
std::string date(std::uint64_t ntp) {
  require(ntp >= 2208988800ULL && ntp - 2208988800ULL <= 253402300799ULL, "unsupported timestamp");
  time_t seconds = ntp - 2208988800ULL;
  tm calendar{};
  require(gmtime_r(&seconds, &calendar) != nullptr, "timestamp conversion failed");
  char buffer[32];
  require(strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &calendar) != 0, "timestamp formatting failed");
  return buffer;
}

//------------------------------------------------------------------------------
// Helper: the NTP time of an xsd:dateTime (XML Schema Part 2 clause 3.2.7, the type of the Time, ValidFrom and ValidTo
// elements of TS 33.180 annex D.3.5.1): "YYYY-MM-DDThh:mm:ss", optional fractional seconds (dropped), and the time zone
// "Z" or "+hh:mm"/"-hh:mm". A dateTime without a time zone is refused: it names no instant (clause 3.2.7.3), and
// TS 33.180 does not say which zone it would be in.
std::uint64_t timevalue(std::string_view value) {
  const auto digits = [&](std::size_t at, std::size_t count) {
    require(at + count <= value.size(), "invalid timestamp");
    int out = 0;
    for (std::size_t i = at; i < at + count; ++i) {
      require(value[i] >= '0' && value[i] <= '9', "invalid timestamp");
      out = out * 10 + (value[i] - '0');
    }
    return out;
  };
  require(value.size() >= 20 && value[4] == '-' && value[7] == '-' && value[10] == 'T' && value[13] == ':' &&
              value[16] == ':',
          "invalid timestamp");
  tm calendar{};
  calendar.tm_year = digits(0, 4) - 1900;
  calendar.tm_mon = digits(5, 2) - 1;
  calendar.tm_mday = digits(8, 2);
  calendar.tm_hour = digits(11, 2);
  calendar.tm_min = digits(14, 2);
  calendar.tm_sec = digits(17, 2);
  std::size_t at = 19;
  if (at < value.size() && value[at] == '.') {
    ++at;
    const auto start = at;
    while (at < value.size() && value[at] >= '0' && value[at] <= '9') ++at;
    require(at > start, "invalid timestamp");
  }
  require(at < value.size(), "timestamp without a time zone");
  long offset = 0;
  if (value[at] == 'Z') {
    ++at;
  } else {
    require((value[at] == '+' || value[at] == '-') && at + 6 == value.size() && value[at + 3] == ':',
            "invalid timestamp time zone");
    const int hours = digits(at + 1, 2), minutes = digits(at + 4, 2);
    require(hours < 14 || (hours == 14 && minutes == 0), "invalid timestamp time zone");
    require(minutes < 60, "invalid timestamp time zone");
    offset = (value[at] == '+' ? 1 : -1) * (hours * 3600L + minutes * 60L);
    at += 6;
  }
  require(at == value.size(), "invalid timestamp");
  const tm given = calendar;
  auto unix_time = timegm(&calendar);
  require(calendar.tm_year == given.tm_year && calendar.tm_mon == given.tm_mon && calendar.tm_mday == given.tm_mday &&
              calendar.tm_hour == given.tm_hour && calendar.tm_min == given.tm_min && calendar.tm_sec == given.tm_sec,
          "invalid calendar timestamp");
  unix_time -= offset;
  require(unix_time >= 0, "invalid timestamp");
  return std::uint64_t(unix_time) + 2208988800ULL;
}

//------------------------------------------------------------------------------
// Helpers: base64 text and its octets (RFC 4648 section 4), white space in the text ignored.
std::string base64(std::span<const std::uint8_t> data) {
  std::string out(4 * ((data.size() + 2) / 3) + 1, '\0');
  const int length =
      EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data.data(), static_cast<int>(data.size()));
  require(length >= 0, "base64 failed");
  out.resize(static_cast<std::size_t>(length));
  return out;
}

Bytes unbase64(std::string_view text) {
  std::string clean;
  for (const char character : text)
    if (character != ' ' && character != '\n' && character != '\r' && character != '\t') clean.push_back(character);
  require(!clean.empty() && clean.size() % 4 == 0, "invalid base64");
  Bytes out(clean.size() / 4 * 3);
  const int length = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char *>(clean.data()),
                                     static_cast<int>(clean.size()));
  require(length >= 0, "invalid base64");
  out.resize(static_cast<std::size_t>(length) - (clean.ends_with("==") ? 2 : clean.ends_with("=") ? 1 : 0));
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.5 and annex D.3.1: the KeyName of an XPK, the base64 of its 32-bit identifier (network order).
std::string key_name_of(const transport::Xpk &xpk) {
  const std::uint8_t id[4] = {std::uint8_t(xpk.id >> 24), std::uint8_t(xpk.id >> 16), std::uint8_t(xpk.id >> 8),
                              std::uint8_t(xpk.id)};
  return base64(id);
}

//------------------------------------------------------------------------------
// Helper: whether a node is an element with the given local name and namespace.
bool named(xmlNode *node, std::string_view local, std::string_view ns) {
  return node && node->type == XML_ELEMENT_NODE && local == reinterpret_cast<const char *>(node->name) && node->ns &&
         node->ns->href && ns == reinterpret_cast<const char *>(node->ns->href);
}

using Document = std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)>;

//------------------------------------------------------------------------------
// Helper: parses a document without network access; refuses a DTD and more than 1 MiB.
Document document(std::string_view input) {
  require(!input.empty() && input.size() <= 1048576 && input.find('\0') == input.npos, "invalid XML size");
  auto *raw = xmlReadMemory(input.data(), int(input.size()), "security.xml", nullptr,
                            XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
  Document doc(raw, xmlFreeDoc);
  require(raw && !raw->intSubset && !raw->extSubset, "invalid XML or forbidden DTD");
  return doc;
}

//------------------------------------------------------------------------------
// Helper: the only child element with the given name, or null if optional and absent.
xmlNode *one(xmlNode *parent, std::string_view name, std::string_view ns = kmsns, bool mandatory = true) {
  xmlNode *found = nullptr;
  for (auto *node = parent->children; node; node = node->next)
    if (named(node, name, ns)) {
      require(!found, "duplicate security XML element");
      found = node;
    }
  require(found || !mandatory, "missing security XML element");
  return found;
}

//------------------------------------------------------------------------------
// Helper: the text content of an element that has only text children.
std::string content(xmlNode *node) {
  require(node != nullptr, "missing XML text");
  for (auto *child = node->children; child; child = child->next)
    require(child->type == XML_TEXT_NODE || child->type == XML_CDATA_SECTION_NODE, "nontext security XML value");
  auto *value = xmlNodeGetContent(node);
  std::string out = value ? reinterpret_cast<char *>(value) : "";
  xmlFree(value);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the text of the only child element with the given name.
std::string field(xmlNode *node, std::string_view name) { return content(one(node, name)); }

//------------------------------------------------------------------------------
// Helper: the value of an attribute, or empty.
std::string attr(xmlNode *node, const char *name) {
  auto *value = xmlGetProp(node, BAD_CAST name);
  std::string out = value ? reinterpret_cast<char *>(value) : "";
  xmlFree(value);
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 tables D.3.2.2-1 and D.3.3.2-1: refuses a revoked KMS certificate or key set, and one used outside its
// ValidFrom and ValidTo.
void bounds(xmlNode *node, std::uint64_t now) {
  if (auto *revoked = one(node, "Revoked", kmsns, false))
    require(content(revoked) == "false" || content(revoked) == "0", "revoked security key");
  if (auto *start = one(node, "ValidFrom", kmsns, false))
    require(now >= timevalue(content(start)), "key not yet valid");
  if (auto *end = one(node, "ValidTo", kmsns, false)) require(now < timevalue(content(end)), "expired security key");
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.7.8: refuses a GKTP document with an unknown element whose "must-understand" attribute is
// "true"; other unknown elements are ignored.
void gktp_extensions(xmlNode *node) {
  for (auto *element = node; element; element = element->next) {
    if (element->type != XML_ELEMENT_NODE) continue;
    bool known = named(element, "group", pocns) || named(element, "list-service", pocns) ||
                 named(element, "GKTPs", gktpns) || named(element, "GMK-GKTPs", gktpns) ||
                 named(element, "GKTP", gktpns);
    require(known || (attr(element, "must-understand") != "true" && attr(element, "must-understand") != "1"),
            "unsupported mandatory GKTP extension");
    if (element->children) gktp_extensions(element->children);
  }
}

//------------------------------------------------------------------------------
// Helper: refuses any XML signature (TS 33.180 annex D.3.1); these TLS-profile parsers have no verifying profile.
void no_signature(xmlNode *node) {
  for (auto *current = node; current; current = current->next) {
    require(!named(current, "Signature", "http://www.w3.org/2000/09/xmldsig#"),
            "XML signatures require a verifying profile");
    if (current->children) no_signature(current->children);
  }
}

//------------------------------------------------------------------------------
// TS 33.180 annexes D.1 and D.3.1: the document of a KMS response. A SignedKmsResponse with a ds:Signature is verified
// under the integrity key of the user's transport keys (the InK, else the TrK, clause 5.3.2), which its KeyName must
// name (clause 9.3.5, "base64 encoded" XPK-ID); its Signature-ID, if any, is not read (annex D.3.5.3 gives no text
// form). The verified KmsResponse is what is parsed. Without transport keys a signature is refused (TLS profile).
Document open_response(std::string_view xml, std::string_view user, const transport::TransportKeys *keys) {
  auto doc = document(xml);
  auto *root = xmlDocGetRootElement(doc.get());
  bool signed_response = false;
  if (named(root, "SignedKmsResponse", kmsns))
    for (auto *child = root->children; child; child = child->next) signed_response |= named(child, "Signature", dsigns);
  if (!signed_response) return doc;
  const auto xpk = keys ? transport::integrity_xpk(*keys) : std::nullopt;
  require(xpk.has_value(), "XML signatures require a verifying profile");
  require(kmsxml::key_name(xml) == key_name_of(*xpk), "KMS response signed with another key");
  auto key = transport::integrity_key(*xpk, std::string(user));
  std::string payload;
  try {
    payload = kmsxml::verify_payload(xml, key);
  } catch (...) {
    OPENSSL_cleanse(key.data(), key.size());
    throw;
  }
  OPENSSL_cleanse(key.data(), key.size());
  return document(payload);
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.1 (table D.3.1-1): checks the KmsResponse (or the KmsResponse of an unsigned SignedKmsResponse)
// is bound to the user, the KMS and the request, is at most 5 minutes old or ahead and carries no KmsError; returns its
// KmsMessage. The Version attribute is optional (annex D.3.5.1: fixed="1.0.0", not required).
xmlNode *envelope(xmlDoc *doc, std::string_view user, std::string_view kms, std::string_view request,
                  std::uint64_t now) {
  auto *root = xmlDocGetRootElement(doc);
  no_signature(root);
  if (named(root, "SignedKmsResponse", kmsns)) root = one(root, "KmsResponse");
  require(named(root, "KmsResponse", kmsns) &&
              (!xmlHasProp(root, BAD_CAST "Version") || attr(root, "Version") == "1.0.0"),
          "invalid KMS response");
  require(field(root, "UserUri") == user && field(root, "KmsUri") == kms && field(root, "ClientReqUrl") == request,
          "KMS response binding mismatch");
  auto timestamp = timevalue(field(root, "Time"));
  require((timestamp > now ? timestamp - now : now - timestamp) <= 300, "stale KMS response");
  require(!one(root, "KmsError", kmsns, false), "KMS returned an error");
  return one(root, "KmsMessage");
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.1 (table D.3.1-1): a KmsResponse to the user and request with the given KmsMessage content;
// with transport keys a SignedKmsResponse under their integrity key (annex D.1; Id "kmsResponse", the Reference
// target).
std::string response(const PublicParameters &parameters, std::string_view user, std::string_view request,
                     std::uint64_t now, std::string body, const transport::TransportKeys *keys = nullptr) {
  require(!user.empty() && !request.empty() && !parameters.period.kms_uri.empty(), "empty KMS response identity");
  const auto xpk = keys ? transport::integrity_xpk(*keys) : std::nullopt;
  const auto payload = "<KmsResponse xmlns=\"" + std::string(kmsns) + "\" xmlns:xsi=\"" + xsins + "\"" +
                       (xpk ? " Id=\"kmsResponse\"" : "") + " Version=\"1.0.0\">" + tag("UserUri", user) +
                       tag("KmsUri", parameters.period.kms_uri) + tag("Time", date(now)) + tag("ClientReqUrl", request) +
                       "<KmsMessage>" + body + "</KmsMessage></KmsResponse>";
  if (!xpk) return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + payload;
  auto key = transport::integrity_key(*xpk, std::string(user));
  std::string out;
  try {
    out = kmsxml::sign_payload(payload, key, key_name_of(*xpk));
  } catch (...) {
    OPENSSL_cleanse(key.data(), key.size());
    throw;
  }
  OPENSSL_cleanse(key.data(), key.size());
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 tables D.3.2.2-1 and D.3.3.2-1: an elliptic curve point must be an uncompressed octet string (0x04) of the
// given size.
void point(std::span<const std::uint8_t> encoded, std::size_t size) {
  require(encoded.size() == size && encoded[0] == 4, "invalid EC point octet encoding");
}

//------------------------------------------------------------------------------
// TS 33.180 table D.3.3.2-1: a key element of type KeyContentType (unencrypted, hexBinary), or with a TrK of type
// EncKeyContentType: an xenc:EncryptedKey with kw-aes256 under the TrK's confidentiality key (clause 9.3.4.2, annex
// F.1.4 FC 0x51), the KeyName the base64 TrK-ID, and the test suite's padding before the wrap (transport_keys.hpp).
std::string keytag(std::string_view name, std::span<const std::uint8_t> value, const transport::TransportKeys *keys,
                   std::string_view user) {
  const auto trk = keys ? transport::confidentiality_xpk(*keys) : std::nullopt;
  if (!trk)
    return "<" + std::string(name) + " xsi:type=\"KeyContentType\">" + hex(value) + "</" + std::string(name) + ">";
  auto kek = transport::confidentiality_key(*trk, std::string(user));
  Bytes wrapped;
  try {
    wrapped = transport::wrap_key_material(kek, value);
  } catch (...) {
    OPENSSL_cleanse(kek.data(), kek.size());
    throw;
  }
  OPENSSL_cleanse(kek.data(), kek.size());
  return "<" + std::string(name) + " xsi:type=\"EncKeyContentType\"><EncryptedKey xmlns=\"" + xencns +
         "\"><EncryptionMethod Algorithm=\"" + kw_aes256 + "\"/><ds:KeyInfo xmlns:ds=\"" + dsigns + "\"><ds:KeyName>" +
         key_name_of(*trk) + "</ds:KeyName></ds:KeyInfo><CipherData><CipherValue>" + base64(wrapped) +
         "</CipherValue></CipherData></EncryptedKey></" + std::string(name) + ">";
}

//------------------------------------------------------------------------------
// TS 33.180 table D.3.3.2-1: the value of a key element: the unencrypted KeyContentType of the KMS interface
// namespace, or with a TrK the EncKeyContentType (clause 9.3.4.2, annex D.3.3.2): one xenc:EncryptedKey with kw-aes256,
// its KeyName the base64 TrK-ID, unwrapped under the TrK's confidentiality key (annex F.1.4 FC 0x51, P0 the user)
// with the test suite's padding (transport_keys.hpp).
Bytes keyfield(xmlNode *parent, std::string_view name, const transport::TransportKeys *keys, std::string_view user) {
  auto *node = one(parent, name);
  auto *type = xmlGetNsProp(node, BAD_CAST "type", BAD_CAST xsins);
  require(type != nullptr, "missing key content type");
  std::string type_text = reinterpret_cast<char *>(type);
  xmlFree(type);
  auto sep = type_text.find(':');
  std::string prefix = sep == type_text.npos ? "" : type_text.substr(0, sep);
  auto local = sep == type_text.npos ? type_text : type_text.substr(sep + 1);
  auto *ns = xmlSearchNs(node->doc, node, prefix.empty() ? nullptr : BAD_CAST prefix.c_str());
  const bool kms_type = ns && ns->href && std::string_view(reinterpret_cast<const char *>(ns->href)) == kmsns;
  if (kms_type && local == "KeyContentType") return unhex(content(node));
  require(kms_type && local == "EncKeyContentType", "unsupported or invalid key content");
  const auto trk = keys ? transport::confidentiality_xpk(*keys) : std::nullopt;
  require(trk.has_value(), "encrypted key material requires the TrK");
  auto *encrypted = one(node, "EncryptedKey", xencns);
  auto *method = one(encrypted, "EncryptionMethod", xencns);
  require(attr(method, "Algorithm") == kw_aes256, "unsupported key encryption algorithm");
  require(content(one(one(encrypted, "KeyInfo", dsigns), "KeyName", dsigns)) == key_name_of(*trk),
          "key encrypted under another TrK");
  const auto wrapped = unbase64(content(one(one(encrypted, "CipherData", xencns), "CipherValue", xencns)));
  auto kek = transport::confidentiality_key(*trk, std::string(user));
  Bytes out;
  try {
    out = transport::unwrap_key_material(kek, wrapped);
  } catch (...) {
    OPENSSL_cleanse(kek.data(), kek.size());
    throw;
  }
  OPENSSL_cleanse(kek.data(), kek.size());
  return out;
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.1 and annex D.3.2 (table D.3.2.2-1): the KmsInit response with the Root KMS certificate
// (UserIdFormat 2, the key period, Z_T and KPAK, parameter set 1).
std::string kms_init_xml(const PublicParameters &parameters, std::string_view user, std::string_view request,
                         std::uint64_t now, const transport::TransportKeys *keys) {
  point(parameters.authentication_key, 65);
  point(parameters.encryption_key, 257);
  require(parameters.period.seconds && parameters.period.offset < parameters.period.seconds, "invalid key period");
  return response(parameters, user, request, now,
                  "<KmsInit Version=\"1.0.0\"><KmsCertificate Version=\"1.1.0\" Role=\"Root\">" +
                      tag("KmsUri", parameters.period.kms_uri) + tag("UserIdFormat", "2") +
                      tag("UserKeyPeriod", std::to_string(parameters.period.seconds)) +
                      tag("UserKeyOffset", std::to_string(parameters.period.offset)) +
                      tag("PubEncKey", hex(parameters.encryption_key)) +
                      tag("PubAuthKey", hex(parameters.authentication_key)) + tag("ParameterSet", "1") +
                      "</KmsCertificate></KmsInit>",
                  keys);
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.3 (table D.3.3.2-1): the KmsKeyProv response with the user's key set for the current key
// period (UID, validity, RSK, SSK and PVT).
std::string kms_keyprov_xml(const PublicParameters &parameters, const IdentityKeys &keys, std::string_view request,
                            std::uint64_t now, const transport::TransportKeys *transport_keys) {
  require(keys.signing_pair.size() == 96 && parameters.period.seconds &&
              keys.period_number == (now - parameters.period.offset) / parameters.period.seconds,
          "invalid signing pair or key period");
  point(keys.receiver_secret, 257);
  Bytes pvt{4};
  pvt.insert(pvt.end(), keys.signing_pair.begin() + 32, keys.signing_pair.end());
  auto start = keys.period_number * parameters.period.seconds + parameters.period.offset;
  return response(
      parameters, keys.uri, request, now,
      "<KmsKeyProv Version=\"1.0.0\"><KmsKeySet Version=\"1.1.0\">" + tag("KmsUri", parameters.period.kms_uri) +
          tag("UserUri", keys.uri) + tag("UserID", uid(keys.uri, parameters.period, now)) +
          tag("ValidFrom", date(start)) + tag("ValidTo", date(start + parameters.period.seconds)) +
          tag("KeyPeriodNo", std::to_string(keys.period_number)) +
          keytag("UserDecryptKey", keys.receiver_secret, transport_keys, keys.uri) +
          keytag("UserSigningKeySSK", std::span(keys.signing_pair).first(32), transport_keys, keys.uri) +
          keytag("UserPubTokenPVT", pvt, transport_keys, keys.uri) + "</KmsKeySet></KmsKeyProv>",
      transport_keys);
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.2 (table D.3.2.2-1) and clause 5.3.5: reads the Root KMS certificate of a KmsInit response.
PublicParameters parse_kms_init(std::string_view xml, std::string_view user, std::string_view kms,
                                std::string_view request, std::uint64_t now, const transport::TransportKeys *keys) {
  auto doc = open_response(xml, user, keys);
  auto *message = envelope(doc.get(), user, kms, request, now);
  auto *init = one(message, "KmsInit");
  auto *cert = one(init, "KmsCertificate");
  require(attr(cert, "Version") == "1.1.0" && attr(cert, "Role") == "Root" && field(cert, "KmsUri") == kms &&
              field(cert, "UserIdFormat") == "2",
          "unsupported KMS certificate");
  bounds(cert, now);
  if (auto *params = one(cert, "ParameterSet", kmsns, false))
    require(content(params) == "1", "unsupported parameter set");
  auto period = number(field(cert, "UserKeyPeriod")), offset = number(field(cert, "UserKeyOffset"));
  require(period > 0 && period <= UINT32_MAX && offset < period, "invalid KMS key period");
  PublicParameters parameters{{std::string(kms), std::uint32_t(period), std::uint32_t(offset)},
                              unhex(field(cert, "PubAuthKey")),
                              unhex(field(cert, "PubEncKey"))};
  point(parameters.authentication_key, 65);
  point(parameters.encryption_key, 257);
  return parameters;
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.3.3 (table D.3.3.2-1) and clause 5.3.6: reads the user's key set of a KmsKeyProv response and
// validates it against the KMS certificate.
IdentityKeys parse_kms_keyprov(std::string_view xml, const PublicParameters &parameters, std::string_view user,
                               std::string_view request, std::uint64_t now, const transport::TransportKeys *transport_keys,
                               UidDetection detection) {
  auto doc = open_response(xml, user, transport_keys);
  auto *message = envelope(doc.get(), user, parameters.period.kms_uri, request, now);
  auto *prov = one(message, "KmsKeyProv");
  auto *keyset = one(prov, "KmsKeySet");
  require(attr(keyset, "Version") == "1.1.0" && field(keyset, "KmsUri") == parameters.period.kms_uri &&
              field(keyset, "UserUri") == user && field(keyset, "UserID") == uid(user, parameters.period, now),
          "KMS keyset identity mismatch");
  bounds(keyset, now);
  IdentityKeys out;
  out.uri = user;
  out.period_number = number(field(keyset, "KeyPeriodNo"));
  out.receiver_secret = keyfield(keyset, "UserDecryptKey", transport_keys, user);
  out.signing_pair = keyfield(keyset, "UserSigningKeySSK", transport_keys, user);
  auto pvt = keyfield(keyset, "UserPubTokenPVT", transport_keys, user);
  point(pvt, 65);
  point(out.receiver_secret, 257);
  // TS 33.180 table D.3.3.2-1: the SSK is an "OCTET STRING encoding of an integer as described in section 6 of
  // [31]" (RFC 6090 section 6.2: "an octet string S of length k", k not fixed): leading zero octets are dropped and
  // the integer is left-padded to the 32 octets of the P-256 order; validate_identity checks its value.
  auto &ssk = out.signing_pair;
  while (ssk.size() > 32 && ssk.front() == 0) ssk.erase(ssk.begin());
  require(!ssk.empty() && ssk.size() <= 32, "invalid SSK size");
  ssk.insert(ssk.begin(), 32 - ssk.size(), 0);
  out.signing_pair.insert(out.signing_pair.end(), pvt.begin() + 1, pvt.end());
  // TS 33.180 annex F.2.1.1 does not say which UID form enters ECCSI and SAKKE (spec defect, reported): with
  // raw_then_text, the key set is validated for the 32 octets first (the ETSI test suite's reading,
  // f_ECCSI_GenerateSskPvtPair; maintainer decision 2026-11-02, a labelled exception to rule 7), then for the base64
  // text (OpenMCX's form). The RFC 6507 5.1.2 and RFC 6508 6.1.2 checks are the ones made in any case; a key set
  // valid in neither form is refused.
  if (detection == UidDetection::raw_then_text) {
    auto raw = parameters;
    raw.uid_form = UidForm::raw;
    try {
      validate_identity(raw, out, now);
      out.uid_form = UidForm::raw;
      return out;
    } catch (const std::exception &) {
      // not keys for the 32 octets: the text form below
    }
  }
  auto text = parameters;
  text.uid_form = UidForm::text;
  validate_identity(text, out, now);
  out.uid_form = UidForm::text;
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 annexes D.2.5 and D.3.2: the KmsCertCache response of a KMS without External KMSs: no certificates.
std::string kms_certcache_xml(const PublicParameters &home, std::string_view user, std::string_view request,
                              std::uint64_t now) {
  return response(home, user, request, now, "<KmsCertCache Version=\"1.0.0\"></KmsCertCache>");
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.2.2 (table D.2.2-1): the SignedKmsRequest of a KM client with an InK or TrK (Id "xmldoc", the
// Reference target; the Version of the KmsRequestType, 1.1.0). No Signature-ID or TrK-ID element (annex D.3.5.3 gives
// no text form, a spec defect, reported).
std::string kms_request_xml(std::string_view user, std::string_view kms, std::string_view request, std::uint64_t now,
                            const transport::TransportKeys &keys) {
  require(!user.empty() && !kms.empty() && !request.empty(), "empty KMS request identity");
  const auto xpk = transport::integrity_xpk(keys);
  require(xpk.has_value(), "a signed KMS request needs an InK or TrK");
  const auto payload = "<KmsRequest xmlns=\"" + std::string(kmsns) + "\" Id=\"xmldoc\" Version=\"1.1.0\">" +
                       tag("UserUri", user) + tag("KmsUri", kms) + tag("Time", date(now)) + tag("ClientReqUrl", request) +
                       "</KmsRequest>";
  auto key = transport::integrity_key(*xpk, std::string(user));
  std::string out;
  try {
    out = kmsxml::sign_payload(payload, key, key_name_of(*xpk));
  } catch (...) {
    OPENSSL_cleanse(key.data(), key.size());
    throw;
  }
  OPENSSL_cleanse(key.data(), key.size());
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.2.2: the KMS's checks of a SignedKmsRequest (signature, XML, KmsUri, Time, ClientReqUrl).
std::string verify_kms_request(std::string_view xml,
                               const std::function<transport::TransportKeys(const std::string &)> &keys_of,
                               std::string_view kms, std::string_view request, std::uint64_t now,
                               std::uint64_t window) {
  std::string user;
  {
    auto doc = document(xml);
    auto *root = xmlDocGetRootElement(doc.get());
    require(named(root, "SignedKmsRequest", kmsns), "not a signed KMS request");
    user = field(one(root, "KmsRequest"), "UserUri");
  }
  const auto keys = keys_of(user);
  const auto xpk = transport::integrity_xpk(keys);
  require(xpk.has_value(), "no InK or TrK for the request's user");
  require(kmsxml::key_name(xml) == key_name_of(*xpk), "KMS request signed with another key");
  auto key = transport::integrity_key(*xpk, user);
  std::string payload;
  try {
    payload = kmsxml::verify_payload(xml, key);
  } catch (...) {
    OPENSSL_cleanse(key.data(), key.size());
    throw;
  }
  OPENSSL_cleanse(key.data(), key.size());
  auto doc = document(payload);
  auto *root = xmlDocGetRootElement(doc.get());
  no_signature(root);
  require(named(root, "KmsRequest", kmsns) && (!xmlHasProp(root, BAD_CAST "Version") || attr(root, "Version") == "1.1.0"),
          "invalid KMS request");
  require(field(root, "UserUri") == user && field(root, "KmsUri") == kms, "KMS request for another KMS");
  require(field(root, "ClientReqUrl") == request, "KMS request for another resource");
  const auto timestamp = timevalue(field(root, "Time"));
  require((timestamp > now ? timestamp - now : now - timestamp) <= window, "KMS request outside the time window");
  return user;
}

constexpr auto krrns = "urn:3gpp:ns:mcsecKMSKRR:1.0";

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.8.2.1 and annex D.4: a KMS Redirect Response (unsigned; the signature of annex D.4.2 is
// optional); an empty KMS list stands for "ANY".
std::string krr_xml(const KmsRedirect &redirect, std::uint64_t now) {
  const auto list = [](const char *name, const std::vector<std::string> &uris) {
    std::string out = "<" + std::string(name) + ">";
    if (uris.empty()) out += "<ANY></ANY>";
    for (const auto &uri : uris) out += tag("KmsUri", uri);
    return out + "</" + name + ">";
  };
  require(!redirect.creator.empty() && !redirect.initiator.empty() && !redirect.receiver.empty() &&
              redirect.initiator_list.size() <= 16 && redirect.receiver_list.size() <= 16,
          "invalid KRR");
  std::array<std::uint8_t, 8> id{};
  require(RAND_bytes(id.data(), id.size()) == 1, "KRR id");
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><KmsRedirectResponse xmlns=\"" + std::string(krrns) +
         "\" Version=\"1.0.0\" Id=\"" + hex(id) + "\">" + tag("Time", date(now)) +
         tag("KRRCreatorUri", redirect.creator) + tag("InitiatorUri", redirect.initiator) +
         tag("InitiatorKmsUri", redirect.initiator_kms) + tag("ReceiverUri", redirect.receiver) +
         tag("ReceiverKmsUri", redirect.receiver_kms) + list("InitiatorKmsList", redirect.initiator_list) +
         list("ReceiverKmsList", redirect.receiver_list) + "</KmsRedirectResponse>";
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.8.2.1 and annex D.4: reads a KMS Redirect Response.
KmsRedirect parse_krr(std::string_view xml) {
  auto doc = document(xml);
  auto *root = xmlDocGetRootElement(doc.get());
  require(named(root, "KmsRedirectResponse", krrns) && attr(root, "Version") == "1.0.0", "not a KMS Redirect Response");
  KmsRedirect redirect{content(one(root, "KRRCreatorUri", krrns)),
                       content(one(root, "InitiatorUri", krrns)),
                       content(one(root, "InitiatorKmsUri", krrns)),
                       content(one(root, "ReceiverUri", krrns)),
                       content(one(root, "ReceiverKmsUri", krrns)),
                       {},
                       {}};
  const auto list = [&](const char *name, std::vector<std::string> &out) {
    for (auto *node = one(root, name, krrns)->children; node; node = node->next)
      if (named(node, "KmsUri", krrns)) {
        require(out.size() < 16, "too many KMS URIs");
        out.push_back(content(node));
      }
  };
  list("InitiatorKmsList", redirect.initiator_list);
  list("ReceiverKmsList", redirect.receiver_list);
  return redirect;
}

//------------------------------------------------------------------------------
// TS 24.481 clauses 7.7.2 and 7.7.8: an MCS GKTP document with one <GKTP> of <GMK-GKTPs> (the MIKEY-SAKKE
// I_MESSAGE carrying the GMK) and its activation time.
std::string gktp_document_xml(std::string_view group, std::string_view id, std::span<const std::uint8_t> mikey,
                              std::uint64_t now) {
  require(!group.empty() && !id.empty() && !mikey.empty(), "empty GKTP document");
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><group xmlns=\"" + std::string(pocns) + "\" xmlns:mgktp=\"" +
         gktpns + "\"><list-service uri=\"" + escape(group) + "\"><mgktp:GKTPs><mgktp:GMK-GKTPs><mgktp:GKTP id=\"" +
         escape(id) + "\" activationtime=\"" + date(now) + "\">" + hex(mikey) +
         "</mgktp:GKTP></mgktp:GMK-GKTPs></mgktp:GKTPs></list-service></group>";
}

//------------------------------------------------------------------------------
// TS 24.481 clauses 7.7.2 and 7.7.8: the GMK GKTP of the MCS GKTP document of a group, whatever its activation time
// (the GMS may send the next one ahead of a key change).
Bytes parse_gktp_document(std::string_view xml, std::string_view group) {
  auto doc = document(xml);
  auto *root = xmlDocGetRootElement(doc.get());
  gktp_extensions(root);
  require(named(root, "group", pocns), "invalid GKTP document root");
  auto *list = one(root, "list-service", pocns);
  require(attr(list, "uri") == group, "GKTP group mismatch");
  auto *all = one(list, "GKTPs", gktpns);
  auto *gmks = one(all, "GMK-GKTPs", gktpns);
  auto *gktp = one(gmks, "GKTP", gktpns);
  require(!attr(gktp, "id").empty(), "missing GKTP id");
  return unhex(content(gktp));
}

//------------------------------------------------------------------------------
// TS 24.481 clauses 6.3.13.2.1, 7.7.3 and 7.7.10: the XCAP path of the <GKTPs> element of the MCS GKTP document of a
// group (relative to the XCAP root), the group ID percent-encoded where RFC 4825 section 6.2 asks it (characters not
// permitted in a path segment; ':' and '@' are permitted, RFC 3986 section 3.3, and stay as in TS 24.481 annex A).
std::string gktp_selector(std::string_view group) {
  require(!group.empty(), "empty group URI");
  const char *digits = "0123456789ABCDEF";
  std::string encoded;
  for (unsigned char character : group) {
    if ((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
        (character >= '0' && character <= '9') || character == '-' || character == '.' || character == '_' ||
        character == '~' || character == ':' || character == '@')
      encoded += character;
    else {
      encoded += '%';
      encoded += digits[character >> 4];
      encoded += digits[character & 15];
    }
  }
  return "org.3gpp.MCPTT-GKTP/global/byGroupID/" + encoded +
         "/~~/group/list-service/mgktp:GKTPs?xmlns(mgktp=urn:3gpp:ns:mcpttGKTP:1.0)";
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.2.1: the application/resource-lists+xml body (RFC 4826) of a SUBSCRIBE to the <GKTPs>
// element of a group's GKTP document.
std::string gktp_resource_list(std::string_view group) {
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><resource-lists "
         "xmlns=\"urn:ietf:params:xml:ns:resource-lists\"><list><entry uri=\"" +
         escape(gktp_selector(group)) + "\"/></list></resource-lists>";
}

namespace {
constexpr auto diffns = "urn:ietf:params:xml:ns:xcap-diff";
constexpr auto listns = "urn:ietf:params:xml:ns:resource-lists";

//------------------------------------------------------------------------------
// Helper: the only child element, which must have the given name.
xmlNode *only_element(xmlNode *parent, std::string_view name, std::string_view ns) {
  auto *child = one(parent, name, ns);
  for (auto *node = parent->children; node; node = node->next)
    if (node->type == XML_ELEMENT_NODE) require(node == child, "unexpected element in security subscription");
  return child;
}

//------------------------------------------------------------------------------
// Helper: an element serialised on its own, with the namespace declarations it needs.
std::string standalone_node(xmlNode *node) {
  Document doc(xmlNewDoc(BAD_CAST "1.0"), xmlFreeDoc);
  require(bool(doc), "XML allocation failed");
  auto *copy = xmlDocCopyNode(node, doc.get(), 1);
  require(copy != nullptr, "XML clone failed");
  xmlDocSetRootElement(doc.get(), copy);
  require(xmlReconciliateNs(doc.get(), copy) >= 0, "XML namespace reconciliation failed");
  auto *buffer = xmlBufferCreate();
  require(buffer != nullptr, "XML buffer allocation failed");
  auto result = xmlNodeDump(buffer, doc.get(), copy, 0, 0);
  std::string out = result >= 0 ? reinterpret_cast<const char *>(xmlBufferContent(buffer)) : "";
  xmlBufferFree(buffer);
  require(result >= 0, "XML serialization failed");
  return out;
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.3.3 and RFC 5875: the xcap-diff body (RFC 5874) of a NOTIFY carrying the <GKTPs>
// element of a group's GKTP document.
std::string gktp_xcap_diff(std::string_view source, std::string_view group, std::string_view xcap_root) {
  auto doc = document(source);
  auto *root = xmlDocGetRootElement(doc.get());
  require(named(root, "group", pocns), "invalid GKTP source");
  auto *list = only_element(root, "list-service", pocns);
  require(attr(list, "uri") == group, "GKTP source group mismatch");
  auto *payload = only_element(list, "GKTPs", gktpns);
  gktp_extensions(payload);
  require(!xcap_root.empty(), "missing XCAP root");
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><xcap-diff xmlns=\"" + std::string(diffns) + "\" xcap-root=\"" +
         escape(xcap_root) + "\"><element sel=\"" + escape(gktp_selector(group)) + "\" exists=\"true\">" +
         standalone_node(payload) + "</element></xcap-diff>";
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.2.1 and RFC 5875: rebuilds the GKTP document of a group from the xcap-diff body
// (RFC 5874) of a NOTIFY, checking the XCAP root and the selector.
std::string parse_gktp_xcap_diff(std::string_view source, std::string_view group, std::string_view xcap_root) {
  auto doc = document(source);
  auto *root = xmlDocGetRootElement(doc.get());
  require(named(root, "xcap-diff", diffns) && attr(root, "xcap-root") == xcap_root, "XCAP diff root binding mismatch");
  auto *element = only_element(root, "element", diffns);
  auto exists = attr(element, "exists");
  require(attr(element, "sel") == gktp_selector(group) && (exists.empty() || exists == "true" || exists == "1"),
          "XCAP diff selector or existence mismatch");
  auto *payload = only_element(element, "GKTPs", gktpns);
  gktp_extensions(payload);
  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><group xmlns=\"" + std::string(pocns) + "\"><list-service uri=\"" +
         escape(group) + "\">" + standalone_node(payload) + "</list-service></group>";
}

//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.3.3: a subscription body must be exactly the resource list for the <GKTPs> element of
// the group.
void validate_gktp_resource_list(std::string_view source, std::string_view group) {
  auto doc = document(source);
  auto *root = xmlDocGetRootElement(doc.get());
  require(named(root, "resource-lists", listns), "invalid resource-list namespace");
  auto *list = only_element(root, "list", listns);
  auto *entry = only_element(list, "entry", listns);
  require(attr(entry, "uri") == gktp_selector(group), "subscription selector mismatch");
  for (auto *node = entry->children; node; node = node->next)
    require(node->type != XML_ELEMENT_NODE, "unsupported subscription entry content");
}
} // namespace mcx::keying
