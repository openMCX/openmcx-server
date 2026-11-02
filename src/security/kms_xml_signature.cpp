//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Verification and creation of the XML signature of a signed KMS message under a derived integrity key
// (include/mcx/kms_xml_signature.hpp).
//
// Specifications: TS 33.180 V19.5.0 (Rel-19) annexes D.1, D.2.2, D.3.1 and D.3.5.1; W3C XML Signature Syntax and
// Processing (Second Edition, 2008); W3C Canonical XML 1.0 and 1.1; W3C Exclusive XML Canonicalization 1.0.
#include "mcx/kms_xml_signature.hpp"

#include "mcx/xml_security.hpp"

#include <libxml/c14n.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

namespace mcx::kmsxml {
namespace {
constexpr const char *kmsns = "urn:3gpp:ns:mcsecKMSInterface:1.0";
constexpr const char *dsig = "http://www.w3.org/2000/09/xmldsig#";
constexpr const char *xml_namespace = "http://www.w3.org/XML/1998/namespace";
constexpr const char *exclusive_ns = "http://www.w3.org/2001/10/xml-exc-c14n#";
constexpr const char *enveloped_transform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
constexpr const char *hmac_sha256_method = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
constexpr const char *sha256_digest = "http://www.w3.org/2001/04/xmlenc#sha256";

//------------------------------------------------------------------------------
// Helper: throws the given error when a condition fails.
void require(bool condition, const char *what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Helper: an owned document parsed without network access, at most 1 MiB, without a DTD (no DTD-declared IDs,
// defaults or entities).
struct Doc {
  xmlDocPtr doc = nullptr;

  explicit Doc(std::string_view xml) {
    require(!xml.empty() && xml.size() <= 1 << 20, "empty or oversized XML");
    doc = xmlReadMemory(xml.data(), static_cast<int>(xml.size()), nullptr, nullptr,
                        XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    require(doc && xmlDocGetRootElement(doc), "malformed XML");
    require(!doc->intSubset && !doc->extSubset, "forbidden DTD");
  }

  Doc(const Doc &) = delete;
  Doc &operator=(const Doc &) = delete;

  ~Doc() { xmlFreeDoc(doc); }
};

//------------------------------------------------------------------------------
// Helpers: element names, namespaces, attributes and text.
bool named(xmlNodePtr node, const char *name, const char *ns) {
  return node && node->type == XML_ELEMENT_NODE && std::strcmp(reinterpret_cast<const char *>(node->name), name) == 0 &&
         node->ns && node->ns->href && std::strcmp(reinterpret_cast<const char *>(node->ns->href), ns) == 0;
}

std::string attribute(xmlNodePtr node, const char *name) {
  xmlChar *value = xmlGetNoNsProp(node, reinterpret_cast<const xmlChar *>(name));
  std::string out = value ? reinterpret_cast<const char *>(value) : "";
  if (value) xmlFree(value);
  return out;
}

std::string content_of(xmlNodePtr node) {
  xmlChar *value = xmlNodeGetContent(node);
  std::string out = value ? reinterpret_cast<const char *>(value) : "";
  if (value) xmlFree(value);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the element children of a node; any text child other than white space is refused.
std::vector<xmlNodePtr> elements(xmlNodePtr parent) {
  std::vector<xmlNodePtr> out;
  for (auto *node = parent->children; node; node = node->next) {
    if (node->type == XML_ELEMENT_NODE) {
      out.push_back(node);
    } else if (node->type == XML_TEXT_NODE) {
      require(xmlIsBlankNode(node) == 1, "unexpected text");
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: the base64 octets of an element's text (RFC 4648 section 4), white space ignored.
std::vector<std::uint8_t> unbase64(const std::string &text) {
  std::string clean;
  for (const char character : text)
    if (character != ' ' && character != '\n' && character != '\r' && character != '\t') clean.push_back(character);
  require(!clean.empty() && clean.size() % 4 == 0, "invalid base64");
  std::vector<std::uint8_t> out(clean.size() / 4 * 3);
  const int length = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char *>(clean.data()),
                                     static_cast<int>(clean.size()));
  require(length >= 0, "invalid base64");
  out.resize(static_cast<std::size_t>(length) - (clean.ends_with("==") ? 2 : clean.ends_with("=") ? 1 : 0));
  return out;
}

//------------------------------------------------------------------------------
// Helper: the base64 text of octets (RFC 4648 section 4).
std::string base64(std::span<const std::uint8_t> data) {
  std::string out(4 * ((data.size() + 2) / 3) + 1, '\0');
  const int length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data.data(), static_cast<int>(data.size()));
  require(length >= 0, "base64 failed");
  out.resize(static_cast<std::size_t>(length));
  return out;
}

//------------------------------------------------------------------------------
// XMLDSig Second Edition clauses 6.1 and 6.5: a canonicalization algorithm as the libxml2 mode and whether comments are
// kept; nothing for another identifier.
struct Canonicalization {
  int mode = XML_C14N_1_0;
  bool comments = false;
};

std::optional<Canonicalization> canonicalization_of(const std::string &algorithm) {
  if (algorithm == "http://www.w3.org/TR/2001/REC-xml-c14n-20010315") return Canonicalization{XML_C14N_1_0, false};
  if (algorithm == "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments")
    return Canonicalization{XML_C14N_1_0, true};
  if (algorithm == "http://www.w3.org/2006/12/xml-c14n11") return Canonicalization{XML_C14N_1_1, false};
  if (algorithm == "http://www.w3.org/2006/12/xml-c14n11#WithComments") return Canonicalization{XML_C14N_1_1, true};
  if (algorithm == exclusive_ns) return Canonicalization{XML_C14N_EXCLUSIVE_1_0, false};
  if (algorithm == std::string(exclusive_ns) + "WithComments") return Canonicalization{XML_C14N_EXCLUSIVE_1_0, true};
  return std::nullopt;
}

//------------------------------------------------------------------------------
// Exclusive XML Canonicalization 1.0 clause 3: the InclusiveNamespaces PrefixList of a method element; none for the
// inclusive algorithms.
std::vector<std::string> inclusive_prefixes(xmlNodePtr method, const Canonicalization &canonicalization) {
  std::vector<std::string> out;
  if (canonicalization.mode != XML_C14N_EXCLUSIVE_1_0) return out;
  for (auto *node : elements(method)) {
    require(named(node, "InclusiveNamespaces", exclusive_ns), "unexpected canonicalization parameter");
    std::string token;
    for (const char character : attribute(node, "PrefixList") + " ") {
      if (character == ' ' || character == '\t' || character == '\r' || character == '\n') {
        if (!token.empty()) out.push_back(token);
        token.clear();
      } else {
        token.push_back(character);
      }
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// XMLDSig Second Edition clause 4.3.3.3: a node-set of the document: the subtree of apex (the whole document without
// one), less the subtree of excluded (the Signature an enveloped signature transform removes, clause 6.6.4), with or
// without comment nodes. libxml2 passes the owning element as the parent of an attribute or namespace node.
struct NodeSet {
  xmlNodePtr apex = nullptr;
  xmlNodePtr excluded = nullptr;
  bool comments = false;
};

int visible(void *context, xmlNodePtr node, xmlNodePtr parent) {
  const auto *set = static_cast<const NodeSet *>(context);
  const bool attached = node->type == XML_NAMESPACE_DECL || node->type == XML_ATTRIBUTE_NODE;
  if (!set->comments && node->type == XML_COMMENT_NODE) return 0;
  bool inside = set->apex == nullptr;
  for (auto *current = attached ? parent : node; current; current = current->parent) {
    if (current == set->excluded) return 0;
    if (current == set->apex) inside = true;
  }
  return inside ? 1 : 0;
}

//------------------------------------------------------------------------------
// Helper: the canonical form of a node-set by the given algorithm.
std::string c14n(xmlDocPtr doc, const NodeSet &set, const Canonicalization &method,
                 const std::vector<std::string> &prefixes) {
  std::vector<xmlChar *> list;
  for (const auto &prefix : prefixes) list.push_back(reinterpret_cast<xmlChar *>(const_cast<char *>(prefix.c_str())));
  list.push_back(nullptr);
  const std::unique_ptr<xmlOutputBuffer, decltype(&xmlOutputBufferClose)> buffer(xmlAllocOutputBuffer(nullptr),
                                                                                 &xmlOutputBufferClose);
  require(buffer != nullptr, "XML allocation failed");
  NodeSet context = set;
  context.comments = set.comments && method.comments;
  const int size = xmlC14NExecute(doc, visible, &context, method.mode, prefixes.empty() ? nullptr : list.data(),
                                  method.comments ? 1 : 0, buffer.get());
  require(size >= 0, "XML canonicalization failed");
  const auto *content = xmlOutputBufferGetContent(buffer.get());
  return content ? std::string(reinterpret_cast<const char *>(content), xmlOutputBufferGetSize(buffer.get())) : "";
}

//------------------------------------------------------------------------------
// XMLDSig Second Edition clause 4.3.3.3: the element a shortname XPointer names by an ID attribute; exactly one element
// may carry it (each candidate is counted here, also a duplicate the parser did not register as an ID). ID attributes:
// xml:id (W3C xml:id), and the unqualified Id attribute of the KMS schema. TS 33.180 V19.5.0 annex D.3.5.1 types that
// Id xsd:string, not xsd:ID (a schema defect, reported), although the References of annexes D.2.2/D.3.1 point to it;
// resolving it as an ID is the reading of the ETSI test suite for TS 37.579 and of its test system (maintainer
// decision 2026-11-01), not a stated 3GPP rule.
xmlNodePtr by_id(xmlDocPtr doc, const std::string &id) {
  xmlNodePtr found = nullptr;
  int count = 0;
  std::vector<xmlNodePtr> pending{xmlDocGetRootElement(doc)};
  while (!pending.empty()) {
    auto *node = pending.back();
    pending.pop_back();
    for (auto *attr = node->properties; attr; attr = attr->next)
      if (((std::strcmp(reinterpret_cast<const char *>(attr->name), "id") == 0 && attr->ns && attr->ns->href &&
            std::strcmp(reinterpret_cast<const char *>(attr->ns->href), xml_namespace) == 0) ||
           (std::strcmp(reinterpret_cast<const char *>(attr->name), "Id") == 0 && attr->ns == nullptr)) &&
          content_of(reinterpret_cast<xmlNodePtr>(attr)) == id) {
        found = node;
        ++count;
      }
    for (auto *child = node->children; child; child = child->next)
      if (child->type == XML_ELEMENT_NODE) pending.push_back(child);
  }
  require(count == 1, count == 0 ? "Reference to no element" : "Reference to an ambiguous ID");
  return found;
}

//------------------------------------------------------------------------------
// Helper: whether ancestor is node or one of its ancestors.
bool contains(xmlNodePtr ancestor, xmlNodePtr node) {
  for (auto *current = node; current; current = current->parent)
    if (current == ancestor) return true;
  return false;
}

//------------------------------------------------------------------------------
// A validated Reference: the element whose subtree it covers (the root element for the null URI) and the
// canonicalization that turned its node-set into the digested octets.
struct Covered {
  xmlNodePtr apex = nullptr;
  Canonicalization method;
  std::vector<std::string> prefixes;
};

//------------------------------------------------------------------------------
// XMLDSig Second Edition clauses 3.2.1 and 4.3.3.2: reference validation of one Reference of the Signature.
Covered validate_reference(xmlDocPtr doc, xmlNodePtr signature, xmlNodePtr reference) {
  const auto children = elements(reference);
  std::size_t at = 0;
  // clause 4.3.3.1: the null URI or a shortname XPointer; any other form is not supported here.
  require(xmlHasProp(reference, reinterpret_cast<const xmlChar *>("URI")) != nullptr,
          "Reference without URI is not supported");
  const auto uri = attribute(reference, "URI");
  NodeSet set;
  if (!uri.empty()) {
    require(uri.size() > 1 && uri[0] == '#' && uri.find_first_of("()") == std::string::npos,
            "unsupported Reference URI");
    set.apex = by_id(doc, uri.substr(1));
  }
  // clause 4.3.3.4 with 6.6.4 and 6.6.1: the enveloped signature transform, then at most one canonicalization.
  std::optional<Canonicalization> output;
  std::vector<std::string> prefixes;
  if (at < children.size() && named(children[at], "Transforms", dsig)) {
    bool canonicalized = false;
    for (auto *transform : elements(children[at])) {
      require(named(transform, "Transform", dsig), "unexpected element in Transforms");
      require(!canonicalized, "unsupported transform after canonicalization");
      const auto algorithm = attribute(transform, "Algorithm");
      if (algorithm == enveloped_transform) {
        require(set.excluded == nullptr, "repeated enveloped signature transform");
        require(elements(transform).empty(), "unexpected transform parameter");
        set.excluded = signature;
      } else if (const auto method = canonicalization_of(algorithm)) {
        output = method;
        prefixes = inclusive_prefixes(transform, *method);
        canonicalized = true;
      } else {
        throw std::runtime_error("unsupported Reference transform");
      }
    }
    ++at;
  }
  require(at < children.size() && named(children[at], "DigestMethod", dsig) &&
              attribute(children[at], "Algorithm") == sha256_digest && elements(children[at]).empty(),
          "unsupported digest method");
  ++at;
  require(at + 1 == children.size() && named(children[at], "DigestValue", dsig), "invalid Reference");
  // clause 4.3.3.2: a node-set left at the end becomes octets by Canonical XML 1.0 (comments omitted).
  const auto method = output.value_or(Canonicalization{XML_C14N_1_0, false});
  const auto octets = c14n(doc, set, method, prefixes);
  std::uint8_t expected[32];
  unsigned length = 0;
  require(EVP_Digest(octets.data(), octets.size(), expected, &length, EVP_sha256(), nullptr) == 1 && length == 32,
          "SHA-256 failed");
  const auto received = unbase64(content_of(children[at]));
  require(received.size() == 32 && CRYPTO_memcmp(received.data(), expected, 32) == 0, "reference digest mismatch");
  return Covered{set.apex ? set.apex : xmlDocGetRootElement(doc), method, prefixes};
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.180 annexes D.1, D.2.2, D.3.1 and D.3.5.1, XMLDSig Second Edition clause 3.2: the signed KMS message, the
// ds:Signature after its KmsRequest or KmsResponse, every Reference valid and one covering that element, and the
// HMAC-SHA256 of the canonical SignedInfo under the key.
std::string verify_payload(std::string_view signed_xml, std::span<const std::uint8_t> derived_integrity_key) {
  require(derived_integrity_key.size() == 16 || derived_integrity_key.size() == 32,
          "the integrity key is 128 or 256 bits (TS 33.180 annex F.1.4)");
  Doc doc(signed_xml);
  auto *root = xmlDocGetRootElement(doc.doc);
  const char *payload_name = named(root, "SignedKmsResponse", kmsns)  ? "KmsResponse"
                             : named(root, "SignedKmsRequest", kmsns) ? "KmsRequest"
                                                                      : nullptr;
  require(payload_name != nullptr, "not a signed KMS message");
  const auto parts = elements(root);
  require(parts.size() == 2 && named(parts[0], payload_name, kmsns) && named(parts[1], "Signature", dsig),
          "a signed KMS message is its KmsRequest or KmsResponse and one ds:Signature");
  auto *payload = parts[0];
  auto *signature = parts[1];

  // XMLDSig Second Edition clause 4: SignedInfo, SignatureValue, then the optional KeyInfo and Objects, which are not
  // read (the caller selected the key).
  const auto items = elements(signature);
  require(items.size() >= 2 && named(items[0], "SignedInfo", dsig) && named(items[1], "SignatureValue", dsig),
          "invalid Signature");
  for (std::size_t at = 2; at < items.size(); ++at)
    require(named(items[at], at == 2 ? "KeyInfo" : "Object", dsig) || named(items[at], "Object", dsig),
            "invalid Signature");
  const auto info = elements(items[0]);
  require(info.size() >= 3 && named(info[0], "CanonicalizationMethod", dsig) && named(info[1], "SignatureMethod", dsig),
          "invalid SignedInfo");
  const auto canonicalization = canonicalization_of(attribute(info[0], "Algorithm"));
  require(canonicalization.has_value(), "unsupported canonicalization method");
  // TS 33.180 annex D.1: "HMAC-SHA256 with a signature length of 256".
  require(attribute(info[1], "Algorithm") == hmac_sha256_method, "unsupported signature method");
  for (auto *parameter : elements(info[1])) {
    require(named(parameter, "HMACOutputLength", dsig), "unexpected signature method parameter");
    auto text = content_of(parameter);
    const auto first = text.find_first_not_of(" \t\r\n");
    require(first != std::string::npos && text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1) == "256",
            "the HMAC-SHA256 signature length is 256 (TS 33.180 annex D.1)");
  }

  // Reference validation (clause 3.2.1) of every Reference; one must cover the whole KmsRequest or KmsResponse.
  std::optional<Covered> covering;
  for (std::size_t at = 2; at < info.size(); ++at) {
    require(named(info[at], "Reference", dsig), "invalid SignedInfo");
    auto reference = validate_reference(doc.doc, signature, info[at]);
    if (!covering && contains(reference.apex, payload)) covering = std::move(reference);
  }
  require(covering.has_value(), "the signature does not cover the whole KMS message");

  // Signature validation (clause 3.2.2): the SignedInfo canonicalized in this document by its own algorithm.
  const auto canonical = c14n(doc.doc, NodeSet{items[0], nullptr, true}, *canonicalization,
                              inclusive_prefixes(info[0], *canonicalization));
  const auto expected = xmlsec::hmac_sha256(derived_integrity_key, canonical);
  const auto received = unbase64(content_of(items[1]));
  require(received.size() == expected.size() && CRYPTO_memcmp(received.data(), expected.data(), expected.size()) == 0,
          "signature value mismatch");
  // The payload by the canonicalization of the Reference that covers it, so that what is returned carries nothing
  // that Reference left out (an Exclusive XML Canonicalization leaves out namespace declarations the payload does not
  // visibly use, which an inclusive form would bring in from the ancestors).
  return c14n(doc.doc, NodeSet{payload, nullptr, false}, covering->method, covering->prefixes);
}

//------------------------------------------------------------------------------
// XMLDSig Second Edition clause 4.5: the KeyName of the Signature's KeyInfo (the Signature after the payload).
std::string key_name(std::string_view signed_xml) {
  Doc doc(signed_xml);
  const auto parts = elements(xmlDocGetRootElement(doc.doc));
  if (parts.size() != 2 || !named(parts[1], "Signature", dsig)) return {};
  for (auto *item : elements(parts[1]))
    if (named(item, "KeyInfo", dsig))
      for (auto *entry : elements(item))
        if (named(entry, "KeyName", dsig)) return content_of(entry);
  return {};
}

//------------------------------------------------------------------------------
// TS 33.180 annexes D.1, D.2.2 and D.3.1: the signature of a KmsRequest or KmsResponse, in two passes over the same
// document text (the Reference digest, then the SignatureValue over the canonical SignedInfo that holds it).
std::string sign_payload(std::string_view payload_xml, std::span<const std::uint8_t> derived_integrity_key,
                         std::string_view key_name) {
  require(derived_integrity_key.size() == 16 || derived_integrity_key.size() == 32,
          "the integrity key is 128 or 256 bits (TS 33.180 annex F.1.4)");
  const bool request = payload_xml.starts_with("<KmsRequest");
  require(request || payload_xml.starts_with("<KmsResponse"), "not a KmsRequest or KmsResponse element");
  std::string id;
  {
    Doc payload(payload_xml);
    id = attribute(xmlDocGetRootElement(payload.doc), "Id");
  }
  require(!id.empty() && id.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") ==
                             std::string::npos,
          "the payload needs an Id attribute");
  require(!key_name.empty() && key_name.find_first_of("<&\"") == std::string::npos, "invalid KeyName");
  // Placeholders, searched for only after the payload (the Signature text is fixed).
  static constexpr std::string_view digest_mark = "DIGEST", value_mark = "SIGNATUREVALUE";
  const std::string root = request ? "SignedKmsRequest" : "SignedKmsResponse";
  std::string text = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><" + root + " xmlns=\"" + kmsns + "\">" +
                     std::string(payload_xml) + "<ds:Signature xmlns:ds=\"" + dsig +
                     "\"><ds:SignedInfo><ds:CanonicalizationMethod "
                     "Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod Algorithm=\"" +
                     hmac_sha256_method + "\"/><ds:Reference URI=\"#" + id + "\"><ds:DigestMethod Algorithm=\"" +
                     sha256_digest + "\"/><ds:DigestValue>" + std::string(digest_mark) +
                     "</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>" + std::string(value_mark) +
                     "</ds:SignatureValue><ds:KeyInfo><ds:KeyName>" + std::string(key_name) +
                     "</ds:KeyName></ds:KeyInfo></ds:Signature></" + root + ">";
  const auto after_payload = text.find("<ds:Signature ");
  const Canonicalization inclusive{XML_C14N_1_0, false};
  {
    Doc doc(text);
    const auto octets = c14n(doc.doc, NodeSet{by_id(doc.doc, id), nullptr, false}, inclusive, {});
    std::uint8_t digest[32];
    unsigned length = 0;
    require(EVP_Digest(octets.data(), octets.size(), digest, &length, EVP_sha256(), nullptr) == 1 && length == 32,
            "SHA-256 failed");
    text.replace(text.find(digest_mark, after_payload), digest_mark.size(), base64(digest));
  }
  {
    Doc doc(text);
    const auto signature = elements(xmlDocGetRootElement(doc.doc)).at(1);
    const auto canonical = c14n(doc.doc, NodeSet{elements(signature).at(0), nullptr, true}, inclusive, {});
    const auto value = xmlsec::hmac_sha256(derived_integrity_key, canonical);
    text.replace(text.find(value_mark, after_payload), value_mark.size(), base64(value));
  }
  (void)verify_payload(text, derived_integrity_key);
  return text;
}
} // namespace mcx::kmsxml
