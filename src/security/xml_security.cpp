//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Application signalling security (XML protection): the XPK-derived keys, XML content and URI attribute encryption,
// re-encryption by a server, and XML signatures over MIME bodies, for MCPTT, MCVideo and MCData.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 4648,
// RFC 5288.
#include "mcx/xml_security.hpp"

#include <libxml/c14n.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <vector>

namespace mcx::xmlsec {
namespace {
using Bytes = std::vector<std::uint8_t>;
constexpr const char *xenc = "http://www.w3.org/2001/04/xmlenc#";
constexpr const char *dsig = "http://www.w3.org/2000/09/xmldsig#";
constexpr const char *gcm = "http://www.w3.org/2009/xmlenc11#aes128-gcm";

//------------------------------------------------------------------------------
// Helper: throws the given error when a condition fails.
void require(bool condition, const char *what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.4: a signalling protection key from the XPK with the KDF of TS 33.220 annex B, FC = 0x51
// (confidentiality) or 0x52 (integrity), P0 = MC service user ID, P1 = XPK-ID; the 128 least significant bits of
// the output.
std::array<std::uint8_t, 16> derive(const Key &key, std::uint8_t fc) {
  require(!key.user.empty() && key.user.size() <= 65535, "XML protection needs the MC service user ID");
  Bytes input{fc};
  input.insert(input.end(), key.user.begin(), key.user.end());
  input.push_back(static_cast<std::uint8_t>(key.user.size() >> 8));
  input.push_back(static_cast<std::uint8_t>(key.user.size()));
  for (int shift = 24; shift >= 0; shift -= 8) input.push_back(static_cast<std::uint8_t>(key.id >> shift));
  input.push_back(0);
  input.push_back(4);
  std::array<std::uint8_t, 32> out{};
  unsigned length = 0;
  require(HMAC(EVP_sha256(), key.xpk.data(), key.xpk.size(), input.data(), input.size(), out.data(), &length) &&
              length == 32,
          "XPK key derivation failed");
  std::array<std::uint8_t, 16> result{};
  std::copy(out.begin() + 16, out.end(), result.begin());
  OPENSSL_cleanse(out.data(), out.size());
  return result;
}

//------------------------------------------------------------------------------
// Helper: base64 encoding (RFC 4648 section 4).
std::string base64(const std::uint8_t *data, std::size_t size) {
  std::string out(4 * ((size + 2) / 3) + 1, '\0');
  const auto length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data, static_cast<int>(size));
  require(length >= 0, "base64 encoding failed");
  out.resize(static_cast<std::size_t>(length));
  return out;
}

//------------------------------------------------------------------------------
// Helper: base64 decoding (RFC 4648 section 4), ignoring white space; at most 1 MiB.
Bytes unbase64(std::string_view text) {
  std::string clean;
  for (const char character : text)
    if (character != ' ' && character != '\n' && character != '\r' && character != '\t') clean.push_back(character);
  require(!clean.empty() && clean.size() % 4 == 0 && clean.size() <= 1 << 20, "invalid base64");
  Bytes out(clean.size() / 4 * 3);
  const auto length = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char *>(clean.data()),
                                      static_cast<int>(clean.size()));
  require(length >= 0, "invalid base64");
  std::size_t padding = clean.ends_with("==") ? 2 : clean.ends_with("=") ? 1 : 0;
  out.resize(static_cast<std::size_t>(length) - padding);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.3.4 step f): the base64 encoding of the 32-bit XPK-ID (the ds:KeyName and "key-id").
std::string key_name(std::uint32_t id) {
  const std::uint8_t bytes[4] = {static_cast<std::uint8_t>(id >> 24), static_cast<std::uint8_t>(id >> 16),
                                 static_cast<std::uint8_t>(id >> 8), static_cast<std::uint8_t>(id)};
  return base64(bytes, 4);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.4.2: AES-128-GCM with a random 96-bit IV: IV (12) || ciphertext || tag (16), as xmlenc 1.1
// lays out a CipherValue.
Bytes seal(const std::array<std::uint8_t, 16> &key, std::string_view plain) {
  Bytes out(12 + plain.size() + 16);
  require(RAND_bytes(out.data(), 12) == 1, "IV generation failed");
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  int length = 0, total = 0;
  require(ctx && EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), out.data()) == 1 &&
              EVP_EncryptUpdate(ctx.get(), out.data() + 12, &length,
                                reinterpret_cast<const unsigned char *>(plain.data()),
                                static_cast<int>(plain.size())) == 1,
          "XML encryption failed");
  total = length;
  require(EVP_EncryptFinal_ex(ctx.get(), out.data() + 12 + total, &length) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, out.data() + 12 + plain.size()) == 1,
          "XML encryption failed");
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.4.2: AES-128-GCM decryption of IV (12) || ciphertext || tag (16); throws if the tag does not
// verify.
std::string open(const std::array<std::uint8_t, 16> &key, const Bytes &data) {
  require(data.size() >= 28, "truncated XML ciphertext");
  std::string plain(data.size() - 28, '\0');
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  int length = 0;
  require(ctx && EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), data.data()) == 1 &&
              EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(plain.data()), &length, data.data() + 12,
                                static_cast<int>(plain.size())) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                                  const_cast<std::uint8_t *>(data.data() + data.size() - 16)) == 1,
          "XML decryption failed");
  const int ok = EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(plain.data()) + length, &length);
  if (ok != 1) {
    OPENSSL_cleanse(plain.data(), plain.size());
    throw std::runtime_error("XML content authentication failed");
  }
  return plain;
}

//------------------------------------------------------------------------------
// Helper: an owned libxml2 document parsed without network access (at most 1 MiB).
struct Doc {
  xmlDocPtr doc = nullptr;

  explicit Doc(std::string_view xml) {
    require(!xml.empty() && xml.size() <= 1 << 20, "empty or oversized XML");
    doc = xmlReadMemory(xml.data(), static_cast<int>(xml.size()), nullptr, nullptr, XML_PARSE_NONET);
    require(doc && xmlDocGetRootElement(doc), "malformed XML");
  }

  ~Doc() {
    if (doc) xmlFreeDoc(doc);
  }

  std::string text() const {
    xmlChar *out = nullptr;
    int size = 0;
    xmlDocDumpMemory(doc, &out, &size);
    require(out != nullptr, "XML serialisation failed");
    std::string result(reinterpret_cast<char *>(out), static_cast<std::size_t>(size));
    xmlFree(out);
    return result;
  }
};

//------------------------------------------------------------------------------
// Helper: the local name of an element.
std::string name_of(xmlNodePtr node) { return reinterpret_cast<const char *>(node->name); }

//------------------------------------------------------------------------------
// Helper: the text content of a node.
std::string content_of(xmlNodePtr node) {
  xmlChar *value = xmlNodeGetContent(node);
  std::string result = value ? reinterpret_cast<char *>(value) : "";
  if (value) xmlFree(value);
  return result;
}

//------------------------------------------------------------------------------
// Helper: whether a node is in the given namespace.
bool in(xmlNodePtr node, const char *ns) {
  return node->ns && node->ns->href && std::strcmp(reinterpret_cast<const char *>(node->ns->href), ns) == 0;
}

//------------------------------------------------------------------------------
// Helper: the first child element with the given name and namespace.
xmlNodePtr child(xmlNodePtr parent, const char *name, const char *ns) {
  for (auto *node = parent->children; node; node = node->next)
    if (node->type == XML_ELEMENT_NODE && name_of(node) == name && in(node, ns)) return node;
  return nullptr;
}

//------------------------------------------------------------------------------
// Helper: calls the visitor on each element of a sibling list and descends into the children of those for which it
// returns false.
template <class Visitor> void each_element(xmlNodePtr node, Visitor &&visitor) {
  for (; node; node = node->next) {
    if (node->type != XML_ELEMENT_NODE) continue;
    auto *next_children = node->children;
    if (!visitor(node)) each_element(next_children, visitor); // an element that was replaced is not descended into
  }
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.4: the signalling plane confidentiality key (FC = 0x51).
std::array<std::uint8_t, 16> confidentiality_key(const Key &key) { return derive(key, 0x51); }

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.4: the signalling plane integrity key (FC = 0x52).
std::array<std::uint8_t, 16> integrity_key(const Key &key) { return derive(key, 0x52); }

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.4.1: a URI in an attribute is confidentiality protected if it has the domain name for
// confidentiality protection (and the ";alg=128-aes-gcm" of clause 6.6.2.3.4).
bool is_encrypted_uri(std::string_view uri) {
  return uri.starts_with("sip:") && uri.ends_with(std::string("@") + encryption_domain) &&
         uri.find(";alg=128-aes-gcm") != std::string_view::npos;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.3.4 and TS 33.180 clause 9.3.4.3: encrypts a URI in an XML attribute: "sip:" base64(ciphertext
// || tag) ";iv=" base64(IV) ";key-id=" base64(XPK-ID) ";alg=128-aes-gcm@" and the confidentiality protection domain.
std::string encrypt_uri(std::string_view uri, const Key &key) {
  auto content_key = confidentiality_key(key);
  const auto sealed = seal(content_key, uri);
  OPENSSL_cleanse(content_key.data(), content_key.size());
  return "sip:" + base64(sealed.data() + 12, sealed.size() - 12) + ";iv=" + base64(sealed.data(), 12) +
         ";key-id=" + key_name(key.id) + ";alg=128-aes-gcm@" + encryption_domain;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.4.3 and TS 33.180 clause 9.3.4.3: decrypts an encrypted URI of an XML attribute; throws if
// it was encrypted under another XPK or does not authenticate.
std::string decrypt_uri(std::string_view uri, const Key &key) {
  require(is_encrypted_uri(uri), "not an encrypted URI");
  const auto body = uri.substr(4, uri.size() - 4 - 1 - std::strlen(encryption_domain));
  const auto first = body.find(';');
  require(first != std::string_view::npos, "encrypted URI without parameters");
  std::string iv, id;
  for (auto rest = body.substr(first + 1); !rest.empty();) {
    const auto end = rest.find(';');
    const auto param = rest.substr(0, end);
    if (param.starts_with("iv="))
      iv = param.substr(3);
    else if (param.starts_with("key-id="))
      id = param.substr(7);
    rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end + 1);
  }
  require(id == key_name(key.id), "URI encrypted under another XPK");
  auto data = unbase64(iv);
  require(data.size() == 12, "invalid URI IV");
  const auto cipher = unbase64(body.substr(0, first));
  data.insert(data.end(), cipher.begin(), cipher.end());
  auto content_key = confidentiality_key(key);
  auto plain = open(content_key, data);
  OPENSSL_cleanse(content_key.data(), content_key.size());
  return plain;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.6.2.3.3 and 6.6.2.3.4, TS 33.180 clause 9.3.4.2: encrypts the URI attributes and the content of
// the elements of the profile whose "type" is "Normal", replacing each content by <EncryptedData> (xmlenc 1.1,
// aes128-gcm, the XPK-ID as ds:KeyName) and setting "type" to "Encrypted".
std::string encrypt(std::string_view xml, const Key &key, const Profile &profile) {
  Doc doc(xml);
  auto content_key = confidentiality_key(key);
  each_element(xmlDocGetRootElement(doc.doc), [&](xmlNodePtr element) {
    for (auto *attribute = element->properties; attribute; attribute = attribute->next) {
      if (!profile.uri_attributes.contains({name_of(element), reinterpret_cast<const char *>(attribute->name)}))
        continue;
      const auto value = content_of(reinterpret_cast<xmlNodePtr>(attribute));
      if (value.empty() || is_encrypted_uri(value)) continue;
      xmlSetProp(element, attribute->name, reinterpret_cast<const xmlChar *>(encrypt_uri(value, key).c_str()));
    }

    if (!profile.elements.contains(name_of(element))) return false;
    xmlChar *type = xmlGetProp(element, reinterpret_cast<const xmlChar *>("type"));
    const bool normal = type && std::strcmp(reinterpret_cast<char *>(type), "Normal") == 0;
    if (type) xmlFree(type);
    if (!normal) return false;

    // The content: every child serialised, then replaced by <EncryptedData>.
    std::string plain;
    for (auto *node = element->children; node; node = node->next) {
      const std::unique_ptr<xmlBuffer, decltype(&xmlBufferFree)> buffer(xmlBufferCreate(), &xmlBufferFree);
      if (!buffer || xmlNodeDump(buffer.get(), doc.doc, node, 0, 0) < 0)
        throw std::runtime_error("XML encryption: cannot serialise the content");
      plain.append(reinterpret_cast<const char *>(xmlBufferContent(buffer.get())), xmlBufferLength(buffer.get()));
    }

    const auto sealed = seal(content_key, plain);
    OPENSSL_cleanse(plain.data(), plain.size());
    while (element->children) {
      auto *node = element->children;
      xmlUnlinkNode(node);
      xmlFreeNode(node);
    }

    auto *encrypted = xmlNewChild(element, nullptr, reinterpret_cast<const xmlChar *>("EncryptedData"), nullptr);
    auto *ns = xmlNewNs(encrypted, reinterpret_cast<const xmlChar *>(xenc), nullptr);
    xmlSetNs(encrypted, ns);
    xmlNewProp(encrypted, reinterpret_cast<const xmlChar *>("Type"),
               reinterpret_cast<const xmlChar *>("http://www.w3.org/2001/04/xmlenc#Content"));
    auto *method = xmlNewChild(encrypted, ns, reinterpret_cast<const xmlChar *>("EncryptionMethod"), nullptr);
    xmlNewProp(method, reinterpret_cast<const xmlChar *>("Algorithm"), reinterpret_cast<const xmlChar *>(gcm));
    auto *info = xmlNewChild(encrypted, nullptr, reinterpret_cast<const xmlChar *>("KeyInfo"), nullptr);
    auto *ds = xmlNewNs(info, reinterpret_cast<const xmlChar *>(dsig), reinterpret_cast<const xmlChar *>("ds"));
    xmlSetNs(info, ds);
    xmlNewTextChild(info, ds, reinterpret_cast<const xmlChar *>("KeyName"),
                    reinterpret_cast<const xmlChar *>(key_name(key.id).c_str()));
    auto *cipher = xmlNewChild(encrypted, ns, reinterpret_cast<const xmlChar *>("CipherData"), nullptr);
    xmlNewTextChild(cipher, ns, reinterpret_cast<const xmlChar *>("CipherValue"),
                    reinterpret_cast<const xmlChar *>(base64(sealed.data(), sealed.size()).c_str()));
    xmlSetProp(element, reinterpret_cast<const xmlChar *>("type"), reinterpret_cast<const xmlChar *>("Encrypted"));
    return true;
  });

  OPENSSL_cleanse(content_key.data(), content_key.size());
  return doc.text();
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.6.2.4.1 to 6.6.2.4.3: decrypts every encrypted URI attribute and every <EncryptedData> element
// content and sets "type" back to "Normal"; throws on the first failure.
std::string decrypt(std::string_view xml, const Key &key) {
  Doc doc(xml);
  auto content_key = confidentiality_key(key);
  std::string failure;
  each_element(xmlDocGetRootElement(doc.doc), [&](xmlNodePtr element) {
    if (!failure.empty()) return true;
    for (auto *attribute = element->properties; attribute; attribute = attribute->next) {
      const auto value = content_of(reinterpret_cast<xmlNodePtr>(attribute));
      if (!is_encrypted_uri(value)) continue;
      try {
        xmlSetProp(element, attribute->name, reinterpret_cast<const xmlChar *>(decrypt_uri(value, key).c_str()));
      } catch (const std::exception &error) {
        failure = error.what();
        return true;
      }
    }

    auto *encrypted = child(element, "EncryptedData", xenc);
    if (!encrypted) return false;
    try {
      auto *info = child(encrypted, "KeyInfo", dsig);
      if (auto *name = info ? child(info, "KeyName", dsig) : nullptr)
        require(content_of(name) == key_name(key.id), "XML content encrypted under another XPK");
      auto *method = child(encrypted, "EncryptionMethod", xenc);
      if (method) {
        xmlChar *algorithm = xmlGetProp(method, reinterpret_cast<const xmlChar *>("Algorithm"));
        const bool known = algorithm && std::strcmp(reinterpret_cast<char *>(algorithm), gcm) == 0;
        if (algorithm) xmlFree(algorithm);
        require(known, "unsupported XML encryption algorithm");
      }

      auto *cipher = child(encrypted, "CipherData", xenc);
      auto *value = cipher ? child(cipher, "CipherValue", xenc) : nullptr;
      require(value != nullptr, "EncryptedData without CipherValue");
      auto plain = open(content_key, unbase64(content_of(value)));
      xmlUnlinkNode(encrypted);
      xmlFreeNode(encrypted);
      xmlNodePtr list = nullptr;
      if (!plain.empty()) {
        const auto result =
            xmlParseInNodeContext(element, plain.data(), static_cast<int>(plain.size()), XML_PARSE_NONET, &list);
        OPENSSL_cleanse(plain.data(), plain.size());
        require(result == XML_ERR_OK, "decrypted XML content is malformed");
        while (list) {
          auto *next = list->next;
          xmlUnlinkNode(list);
          xmlAddChild(element, list);
          list = next;
        }
      }
      xmlSetProp(element, reinterpret_cast<const xmlChar *>("type"), reinterpret_cast<const xmlChar *>("Normal"));
    } catch (const std::exception &error) {
      failure = error.what();
    }
    return true;
  });

  OPENSSL_cleanse(content_key.data(), content_key.size());
  if (!failure.empty()) throw std::runtime_error(failure);
  return doc.text();
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.5 steps 2 and 3: a server copying received XML content re-encrypts each encrypted element
// content and URI attribute from one XPK to another (for example from the CSK to the SPK).
std::string reencrypt(std::string_view xml, const Key &from, const Key &to) {
  Doc doc(xml);
  auto in = confidentiality_key(from), out = confidentiality_key(to);
  std::string failure;
  each_element(xmlDocGetRootElement(doc.doc), [&](xmlNodePtr element) {
    if (!failure.empty()) return true;
    try {
      for (auto *attribute = element->properties; attribute; attribute = attribute->next) {
        const auto value = content_of(reinterpret_cast<xmlNodePtr>(attribute));
        if (is_encrypted_uri(value))
          xmlSetProp(element, attribute->name,
                     reinterpret_cast<const xmlChar *>(encrypt_uri(decrypt_uri(value, from), to).c_str()));
      }

      auto *encrypted = child(element, "EncryptedData", xenc);
      if (!encrypted) return false;
      auto *info = child(encrypted, "KeyInfo", dsig);
      auto *name = info ? child(info, "KeyName", dsig) : nullptr;
      if (name) require(content_of(name) == key_name(from.id), "XML content encrypted under another XPK");
      auto *cipher = child(encrypted, "CipherData", xenc);
      auto *value = cipher ? child(cipher, "CipherValue", xenc) : nullptr;
      require(value != nullptr, "EncryptedData without CipherValue");

      auto plain = open(in, unbase64(content_of(value)));
      const auto sealed = seal(out, plain);
      OPENSSL_cleanse(plain.data(), plain.size());
      xmlNodeSetContent(value, reinterpret_cast<const xmlChar *>(base64(sealed.data(), sealed.size()).c_str()));
      if (name) xmlNodeSetContent(name, reinterpret_cast<const xmlChar *>(key_name(to.id).c_str()));
    } catch (const std::exception &error) {
      failure = error.what();
    }
    return true;
  });

  OPENSSL_cleanse(in.data(), in.size());
  OPENSSL_cleanse(out.data(), out.size());
  if (!failure.empty()) throw std::runtime_error(failure);
  return doc.text();
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.4.1: the XPK-ID of the first confidentiality protected URI or element of a document, if it
// is protected at all.
std::optional<std::uint32_t> key_id(std::string_view xml) {
  if (!is_protected(xml)) return std::nullopt;
  Doc doc(xml);
  std::string name;
  each_element(xmlDocGetRootElement(doc.doc), [&](xmlNodePtr element) {
    if (!name.empty()) return true;
    for (auto *attribute = element->properties; attribute; attribute = attribute->next) {
      const auto value = content_of(reinterpret_cast<xmlNodePtr>(attribute));
      if (!is_encrypted_uri(value)) continue;
      const auto at = value.find(";key-id=");
      if (at != std::string::npos) {
        name = value.substr(at + 8, value.find(';', at + 8) - at - 8);
        return true;
      }
    }
    if (auto *encrypted = child(element, "EncryptedData", xenc)) {
      auto *info = child(encrypted, "KeyInfo", dsig);
      if (auto *key = info ? child(info, "KeyName", dsig) : nullptr) name = content_of(key);
      return true;
    }
    return false;
  });

  if (name.empty()) return std::nullopt;
  const auto bytes = unbase64(name);
  require(bytes.size() == 4, "invalid XPK-ID");
  return std::uint32_t(bytes[0]) << 24 | std::uint32_t(bytes[1]) << 16 | std::uint32_t(bytes[2]) << 8 | bytes[3];
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.4.1: whether a document holds any <EncryptedData> element or encrypted URI.
bool is_protected(std::string_view xml) {
  return xml.find("EncryptedData") != std::string_view::npos ||
         xml.find(std::string("@") + encryption_domain) != std::string_view::npos;
}

// ---- Integrity (TS 33.180 clause 9.3.5; TS 24.379 clause 6.6.3; TS 24.282 clause 6.5.3) ----
namespace {
constexpr const char *exclusive_c14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
constexpr const char *hmac_sha256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
constexpr const char *sha256_digest = "http://www.w3.org/2001/04/xmlenc#sha256";

//------------------------------------------------------------------------------
// Helper: the base64 SHA-256 digest of the data (the DigestValue of a Reference).
std::string sha256_base64(std::string_view data) {
  std::array<std::uint8_t, 32> hash{};
  unsigned length = 0;
  require(EVP_Digest(data.data(), data.size(), hash.data(), &length, EVP_sha256(), nullptr) == 1 && length == 32,
          "SHA-256 failed");
  return base64(hash.data(), hash.size());
}

//------------------------------------------------------------------------------
// Helper: the exclusive canonical form (Exclusive XML Canonicalization 1.0) of an element, taken on its own.
std::string canonical(xmlNodePtr element) {
  xmlDocPtr doc = xmlNewDoc(reinterpret_cast<const xmlChar *>("1.0"));
  require(doc != nullptr, "XML allocation failed");
  auto *copy = xmlDocCopyNode(element, doc, 1);
  if (!copy) {
    xmlFreeDoc(doc);
    throw std::runtime_error("XML copy failed");
  }
  xmlDocSetRootElement(doc, copy);
  xmlReconciliateNs(doc, copy);
  xmlChar *out = nullptr;
  const int size = xmlC14NDocDumpMemory(doc, nullptr, XML_C14N_EXCLUSIVE_1_0, nullptr, 0, &out);
  xmlFreeDoc(doc);
  require(size >= 0 && out != nullptr, "XML canonicalisation failed");
  std::string result(reinterpret_cast<char *>(out), static_cast<std::size_t>(size));
  xmlFree(out);
  return result;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.5: the base64 HMAC-SHA-256 of the data under the integrity key (annex F.1.4).
std::string hmac_base64(const Key &key, std::string_view data) {
  auto integrity = integrity_key(key);
  std::array<std::uint8_t, 32> mac{};
  unsigned length = 0;
  const bool ok = HMAC(EVP_sha256(), integrity.data(), integrity.size(),
                       reinterpret_cast<const unsigned char *>(data.data()), data.size(), mac.data(), &length) &&
                  length == 32;
  OPENSSL_cleanse(integrity.data(), integrity.size());
  require(ok, "HMAC-SHA256 failed");
  return base64(mac.data(), mac.size());
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.3.3 step 2 a): the SignedInfo for one body, with its Reference to the body's Content-ID
// and its SHA-256 digest; with its namespace declaration on its own, and without it inside a Signature that declares
// it. Both have the same exclusive canonical form.
std::string signed_info(const std::string &content_id, std::string_view body, bool declare) {
  return std::string("<ds:SignedInfo") + (declare ? std::string(" xmlns:ds=\"") + dsig + "\"" : std::string{}) +
         "><ds:CanonicalizationMethod Algorithm=\"" + exclusive_c14n + "\"/><ds:SignatureMethod Algorithm=\"" +
         hmac_sha256 + "\"/><ds:Reference URI=\"cid:" + content_id + "\"><ds:DigestMethod Algorithm=\"" +
         sha256_digest + "\"/><ds:DigestValue>" + sha256_base64(body) +
         "</ds:DigestValue></ds:Reference></ds:SignedInfo>";
}

//------------------------------------------------------------------------------
// Helper: the value of an attribute, or empty.
std::string attribute(xmlNodePtr node, const char *name) {
  xmlChar *value = xmlGetProp(node, reinterpret_cast<const xmlChar *>(name));
  std::string result = value ? reinterpret_cast<char *>(value) : "";
  if (value) xmlFree(value);
  return result;
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.3.3 (TS 24.282 clause 6.5.3.3.3) and TS 33.180 clause 9.3.5: the signatures document
// of TS 24.379 annex F.6 with one ds:Signature (HMAC-SHA256 under the XPK, the XPK-ID as ds:KeyName) per signed body.
std::string sign(const std::vector<SignedBody> &bodies, const Key &key, std::string_view root_namespace) {
  require(!bodies.empty() && bodies.size() <= 16, "invalid number of bodies to sign");
  std::string out =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><signatures xmlns=\"" + std::string(root_namespace) + "\">";
  for (const auto &body : bodies) {
    require(!body.content_id.empty() && body.content_id.find_first_of("\"<>&") == std::string::npos,
            "invalid Content-ID");
    Doc doc(signed_info(body.content_id, body.body, true));
    const auto value = hmac_base64(key, canonical(xmlDocGetRootElement(doc.doc)));
    out += std::string("<ds:Signature xmlns:ds=\"") + dsig + "\">" + signed_info(body.content_id, body.body, false) +
           "<ds:SignatureValue>" + value + "</ds:SignatureValue><ds:KeyInfo><ds:KeyName>" + key_name(key.id) +
           "</ds:KeyName></ds:KeyInfo></ds:Signature>";
  }
  return out + "</signatures>";
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.4.2 step 4: the XPK-ID named in a signatures document, if any.
std::optional<std::uint32_t> signature_key_id(std::string_view signatures) {
  Doc doc(signatures);
  std::string name;
  each_element(xmlDocGetRootElement(doc.doc), [&](xmlNodePtr element) {
    if (name.empty() && name_of(element) == "KeyName" && in(element, dsig)) name = content_of(element);
    return false;
  });
  if (name.empty()) return std::nullopt;
  const auto bytes = unbase64(name);
  require(bytes.size() == 4, "invalid XPK-ID");
  return std::uint32_t(bytes[0]) << 24 | std::uint32_t(bytes[1]) << 16 | std::uint32_t(bytes[2]) << 8 | bytes[3];
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.3.4.2 (TS 24.282 clause 6.5.3.4.2): verifies each ds:Signature, reference validation then
// signature validation; returns the Content-IDs of the verified bodies and throws on any failure.
std::set<std::string> verify(std::string_view signatures, const std::vector<SignedBody> &bodies, const Key &key) {
  Doc doc(signatures);
  std::map<std::string, std::string_view> by_id;
  for (const auto &body : bodies) by_id[body.content_id] = body.body;

  std::set<std::string> verified;
  for (auto *signature = xmlDocGetRootElement(doc.doc)->children; signature; signature = signature->next) {
    if (signature->type != XML_ELEMENT_NODE) continue;
    require(name_of(signature) == "Signature" && in(signature, dsig), "unexpected element in the signatures");
    auto *info = child(signature, "SignedInfo", dsig);
    auto *value = child(signature, "SignatureValue", dsig);
    require(info && value, "Signature without SignedInfo or SignatureValue");
    auto *keyinfo = child(signature, "KeyInfo", dsig);
    if (auto *name = keyinfo ? child(keyinfo, "KeyName", dsig) : nullptr)
      require(content_of(name) == key_name(key.id), "signed under another XPK");

    auto *method = child(info, "SignatureMethod", dsig);
    require(!method || attribute(method, "Algorithm") == hmac_sha256, "unsupported signature method");
    auto *reference = child(info, "Reference", dsig);
    require(reference != nullptr, "Signature without Reference");
    const auto uri = attribute(reference, "URI");
    require(uri.starts_with("cid:"), "Reference is not a cid URL");
    const auto target = by_id.find(uri.substr(4));
    require(target != by_id.end(), "Reference to a missing body");
    auto *digest_method = child(reference, "DigestMethod", dsig);
    require(!digest_method || attribute(digest_method, "Algorithm") == sha256_digest, "unsupported digest method");
    auto *digest = child(reference, "DigestValue", dsig);

    // Reference validation (xmldsig clause 3.2.1), then signature validation (clause 3.2.2).
    require(digest && content_of(digest) == sha256_base64(target->second), "reference digest mismatch");
    const auto expected = hmac_base64(key, canonical(info));
    const auto received = content_of(value);
    require(expected.size() == received.size() && CRYPTO_memcmp(expected.data(), received.data(), expected.size()) == 0,
            "signature value mismatch");
    verified.insert(target->first);
  }
  return verified;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.8: the sensitive application data to confidentiality protect, as elements and (element,
// attribute) URIs, for MCPTT and, with the "mcvideo-" element names, for MCVideo.
const Profile &signalling_profile(std::string_view info_prefix) {
  static const Profile mcptt{{"mcptt-access-token", "mcptt-request-uri", "mcptt-calling-user-id",
                              "mcptt-called-party-id", "mcptt-calling-group-id", "mcptt-client-id", "originated-by",
                              "associated-group-id", "location-of-functional-alias-URI", "emergency-ind", "alert-ind",
                              "imminentperil-ind",
                              // TS 24.379 annex F.3: the location reported.
                              "CurrentServingEcgi", "NeighbouringEcgi", "MbmsSaId", "MbsfnArea", "CL_5GMbsfsaArea",
                              "CurrentServingNcgi", "CL_NeighbouringNcgi", "CL_BearingAndSpeed", "longitude",
                              "latitude", "altitude", "horizontalaccuracy", "verticalaccuracy"},
                             {{"entry", "uri"},
                              {"presence", "entity"},
                              {"affiliation", "group"},
                              {"functionalAlias", "functionalAliasID"},
                              {"user", "entity"}}};
  static const Profile mcvideo = [] {
    Profile out{{}, mcptt.uri_attributes};
    for (const auto &element : mcptt.elements)
      out.elements.insert(element.starts_with("mcptt-") ? "mcvideo-" + element.substr(6) : element);
    return out;
  }();
  if (info_prefix == "mcptt") return mcptt;
  if (info_prefix == "mcvideo") return mcvideo;
  throw std::invalid_argument("no signalling protection profile for this service");
}
} // namespace mcx::xmlsec
