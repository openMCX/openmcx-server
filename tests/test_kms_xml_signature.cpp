//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Verification of the XML signature of a signed KMS message (include/mcx/kms_xml_signature.hpp). The fixtures are
// written in canonical form by hand, so each digest and signature value here comes from OpenSSL over text this test
// states, not from the code under test.
//
// Specifications: TS 33.180 V19.5.0 (Rel-19) annexes D.1, D.2.2, D.3.1 and D.3.5.1; W3C XML Signature Syntax and
// Processing (Second Edition, 2008) clauses 3.2, 4.3.3 and 6.

#include "mcx/key_documents.hpp"
#include "mcx/kms_xml_signature.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<std::uint8_t>;
const std::string kmsns = "urn:3gpp:ns:mcsecKMSInterface:1.0";
const std::string dsig = "http://www.w3.org/2000/09/xmldsig#";
const std::string c14n10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const std::string hmac_sha256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
const std::string sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const std::string enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

//------------------------------------------------------------------------------
// Throws the message when the condition does not hold.
void check(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Fails unless verification throws with an error naming the reason.
void refused(const std::string &xml, const Bytes &key, const std::string &what, const std::string &reason) {
  try {
    mcx::kmsxml::verify_payload(xml, key);
  } catch (const std::exception &error) {
    if (std::string(error.what()).find(reason) == std::string::npos)
      throw std::runtime_error(what + ": refused for another reason: " + error.what());
    return;
  }
  throw std::runtime_error("accepted: " + what);
}

//------------------------------------------------------------------------------
// Helpers: base64, SHA-256 and HMAC-SHA256 straight from OpenSSL.
std::string base64(const unsigned char *data, std::size_t size) {
  std::string out(4 * ((size + 2) / 3) + 1, '\0');
  out.resize(static_cast<std::size_t>(
      EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data, static_cast<int>(size))));
  return out;
}

std::string digest(const std::string &octets) {
  unsigned char out[32];
  unsigned length = 0;
  EVP_Digest(octets.data(), octets.size(), out, &length, EVP_sha256(), nullptr);
  return base64(out, length);
}

std::string mac(const Bytes &key, const std::string &octets) {
  unsigned char out[32];
  unsigned length = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char *>(octets.data()),
       octets.size(), out, &length);
  return base64(out, length);
}

//------------------------------------------------------------------------------
// A Reference: its URI, its Transforms (empty for none), its DigestMethod and the octets it digests.
struct Ref {
  std::string uri;
  std::string transforms;
  std::string octets;
  std::string method = sha256;
};

std::string reference(const Ref &ref) {
  return "<Reference URI=\"" + ref.uri + "\">" + ref.transforms + "<DigestMethod Algorithm=\"" + ref.method +
         "\"></DigestMethod><DigestValue>" + digest(ref.octets) + "</DigestValue></Reference>";
}

//------------------------------------------------------------------------------
// A signed KMS message: root (open tag text), payload (as written, in canonical form), the Signature with its
// SignedInfo signed under the key (canonical SignedInfo: the dsig default namespace declared on it and, Canonical XML 1.0
// section 2.4, the xml: attributes of its ancestors, given as inherited).
std::string signed_message(const std::string &root_open, const std::string &root_close, const std::string &payload,
                           const std::vector<Ref> &refs, const Bytes &key, const std::string &method_parameter = "",
                           const std::string &inherited = "", const std::string &signed_info_method = c14n10) {
  std::string body = "<CanonicalizationMethod Algorithm=\"" + signed_info_method +
                     "\"></CanonicalizationMethod><SignatureMethod Algorithm=\"" + hmac_sha256 + "\">" +
                     method_parameter + "</SignatureMethod>";
  for (const auto &ref : refs) body += reference(ref);
  const auto canonical = "<SignedInfo xmlns=\"" + dsig + "\"" + inherited + ">" + body + "</SignedInfo>";
  return root_open + payload + "<Signature xmlns=\"" + dsig + "\"><SignedInfo>" + body +
         "</SignedInfo><SignatureValue>" + mac(key, canonical) +
         "</SignatureValue><KeyInfo><KeyName>AAAAAQ==</KeyName></KeyInfo></Signature>" + root_close;
}

const std::string payload_body =
    "<UserUri>sip:a@example.org</UserUri><KmsUri>https://kms.example.org</KmsUri><Time>2026-10-30T10:00:00</Time>"
    "<ClientReqUrl>https://kms.example.org/keymanagement/identity/v1/init</ClientReqUrl>"
    "<KmsMessage xml:id=\"msg\"><KmsInit Version=\"1.0.0\"></KmsInit></KmsMessage>";
} // namespace

int main() {
  try {
    const Bytes key(32, 0x5a), other_key(32, 0x5b);
    const std::string root_open = "<SignedKmsResponse xmlns=\"" + kmsns + "\">", root_close = "</SignedKmsResponse>";
    // The payload as written inside the root (the default namespace inherited), and its canonical form on its own
    // (Canonical XML 1.0: the in-scope namespace declared on it; attributes without a namespace before xml:id).
    const std::string payload = "<KmsResponse Version=\"1.0.0\" xml:id=\"resp\">" + payload_body + "</KmsResponse>";
    const std::string canonical_payload =
        "<KmsResponse xmlns=\"" + kmsns + "\" Version=\"1.0.0\" xml:id=\"resp\">" + payload_body + "</KmsResponse>";
    const std::string transform = "<Transforms><Transform Algorithm=\"" + enveloped + "\"></Transform></Transforms>";
    const std::string document_minus_signature = root_open + payload + root_close;

    // A shortname XPointer to the KmsResponse (xml:id), no transform: the Signature is its sibling.
    const auto by_id = signed_message(root_open, root_close, payload, {{"#resp", "", canonical_payload}}, key);
    check(mcx::kmsxml::verify_payload(by_id, key) == canonical_payload, "KmsResponse by xml:id");
    // The null URI with the enveloped signature transform: the whole document less the Signature.
    const auto whole = signed_message(root_open, root_close, payload, {{"", transform, document_minus_signature}}, key);
    check(mcx::kmsxml::verify_payload(whole, key) == canonical_payload, "null URI with the enveloped transform");
    // The wrapper by xml:id with the enveloped signature transform.
    const std::string wrapper_open = "<SignedKmsResponse xmlns=\"" + kmsns + "\" xml:id=\"doc\">";
    const auto wrapper =
        signed_message(wrapper_open, root_close, payload, {{"#doc", transform, wrapper_open + payload + root_close}},
                       key, "", " xml:id=\"doc\"");
    check(mcx::kmsxml::verify_payload(wrapper, key) == "<KmsResponse xmlns=\"" + kmsns +
                                                           "\" Version=\"1.0.0\" xml:id=\"resp\">" + payload_body +
                                                           "</KmsResponse>",
          "wrapper by xml:id, enveloped");
    // A 128-bit integrity key (from a 128-bit InK, annex F.1.4) and HMACOutputLength 256.
    const Bytes short_key(16, 0x33);
    check(mcx::kmsxml::verify_payload(signed_message(root_open, root_close, payload, {{"#resp", "", canonical_payload}},
                                                     short_key, "<HMACOutputLength>256</HMACOutputLength>"),
                                      short_key) == canonical_payload,
          "128-bit integrity key, HMACOutputLength 256");
    // A signed KmsRequest.
    const std::string request_open = "<SignedKmsRequest xmlns=\"" + kmsns + "\">";
    const std::string request = "<KmsRequest Version=\"1.1.0\" xml:id=\"req\">" + payload_body + "</KmsRequest>";
    const auto signed_request = signed_message(
        request_open, "</SignedKmsRequest>", request,
        {{"#req", "",
          "<KmsRequest xmlns=\"" + kmsns + "\" Version=\"1.1.0\" xml:id=\"req\">" + payload_body + "</KmsRequest>"}},
        key);
    check(mcx::kmsxml::verify_payload(signed_request, key).starts_with("<KmsRequest xmlns="), "signed KmsRequest");
    // Comments are not part of a null-URI or shortname node-set (clause 4.3.3.3).
    auto commented = by_id;
    commented.insert(commented.find("<UserUri>"), "<!-- note -->");
    check(mcx::kmsxml::verify_payload(commented, key) == canonical_payload, "comments omitted");

    // XMLDSig Second Edition clauses 6.1 and 6.5: the payload under Canonical XML 1.1 and with comments (the
    // shortname node-set has none), and under Exclusive XML Canonicalization.
    for (const auto *method :
         {"http://www.w3.org/2006/12/xml-c14n11", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
          "http://www.w3.org/2001/10/xml-exc-c14n#"}) {
      const auto chain = std::string("<Transforms><Transform Algorithm=\"") + method + "\"></Transform></Transforms>";
      auto variant = signed_message(root_open, root_close, payload, {{"#resp", chain, canonical_payload}}, key);
      variant.insert(variant.find("<UserUri>"), "<!-- note -->");
      check(mcx::kmsxml::verify_payload(variant, key) == canonical_payload, std::string("payload under ") + method);
    }
    // A namespace declaration added to the wrapper after signing: outside an exclusive canonicalization of the payload,
    // so the signature still verifies, and it must not appear in what is returned; under the inclusive default it is
    // part of the payload's canonical form and breaks the digest.
    const auto exclusive =
        std::string("<Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">") +
        "</Transform></Transforms>";
    // SignedInfo under Exclusive XML Canonicalization too (its canonical form here is the same text), else the
    // declaration would enter the canonical SignedInfo and break the signature value.
    auto injected = signed_message(root_open, root_close, payload, {{"#resp", exclusive, canonical_payload}}, key, "",
                                   "", "http://www.w3.org/2001/10/xml-exc-c14n#");
    injected.insert(injected.find('>'), " xmlns:p=\"urn:example:unsigned\"");
    const auto returned = mcx::kmsxml::verify_payload(injected, key);
    check(returned == canonical_payload && returned.find("urn:example:unsigned") == std::string::npos,
          "an unsigned namespace declaration is not returned");
    auto injected_inclusive = by_id;
    injected_inclusive.insert(injected_inclusive.find('>'), " xmlns:p=\"urn:example:unsigned\"");
    refused(injected_inclusive, key, "unsigned namespace under the inclusive default", "reference digest mismatch");

    // Changed payload, wrong key, altered SignatureValue.
    auto changed = by_id;
    changed.replace(changed.find("sip:a@"), 6, "sip:b@");
    refused(changed, key, "changed payload", "reference digest mismatch");
    refused(by_id, other_key, "wrong key", "signature value mismatch");
    auto altered = by_id;
    const auto value = altered.find("<SignatureValue>") + 16;
    altered[value] = altered[value] == 'A' ? 'B' : 'A';
    refused(altered, key, "altered SignatureValue", "signature value mismatch");
    // A wrong digest under a correct HMAC over that SignedInfo.
    refused(signed_message(root_open, root_close, payload, {{"#resp", "", canonical_payload + " "}}, key), key,
            "bad digest", "reference digest mismatch");
    // Valid HMAC over only part of the message: a Reference to the KmsMessage inside the KmsResponse.
    const std::string canonical_message =
        "<KmsMessage xmlns=\"" + kmsns + "\" xml:id=\"msg\"><KmsInit Version=\"1.0.0\"></KmsInit></KmsMessage>";
    refused(signed_message(root_open, root_close, payload, {{"#msg", "", canonical_message}}, key), key,
            "partial coverage (KmsMessage only)", "does not cover the whole KMS message");
    // An invalid additional Reference alongside a valid one to the payload.
    refused(signed_message(root_open, root_close, payload,
                           {{"#resp", "", canonical_payload}, {"#msg", "", canonical_message + "x"}}, key),
            key, "invalid second Reference", "reference digest mismatch");
    // Two elements with the same xml:id: the reference is ambiguous.
    const auto twin = "<KmsResponse Version=\"1.0.0\" xml:id=\"resp\">" + payload_body +
                      "<Extra xmlns=\"urn:example\" xml:id=\"resp\"></Extra></KmsResponse>";
    refused(signed_message(root_open, root_close, twin, {{"#resp", "", canonical_payload}}, key), key,
            "duplicate xml:id", "ambiguous ID");
    // The schema's Id attribute (TS 33.180 D.3.5.1, xsd:string) resolves a shortname XPointer as the ETSI test suite
    // reads it (maintainer decision 2026-11-01).
    const auto by_schema_id = "<KmsResponse Id=\"resp\" Version=\"1.0.0\">" + payload_body + "</KmsResponse>";
    const auto canonical_by_schema_id =
        "<KmsResponse xmlns=\"" + kmsns + "\" Id=\"resp\" Version=\"1.0.0\">" + payload_body + "</KmsResponse>";
    check(mcx::kmsxml::verify_payload(signed_message(root_open, root_close, by_schema_id,
                                                     {{"#resp", "", canonical_by_schema_id}}, key),
                                      key) == canonical_by_schema_id,
          "KmsResponse by the schema's Id");
    // Duplicates across Id and xml:id, or two Id attributes, are ambiguous.
    const auto twin_id = "<KmsResponse Id=\"resp\" Version=\"1.0.0\">" + payload_body +
                         "<Extra xmlns=\"urn:example\" Id=\"resp\"></Extra></KmsResponse>";
    refused(signed_message(root_open, root_close, twin_id, {{"#resp", "", canonical_by_schema_id}}, key), key,
            "duplicate Id", "ambiguous ID");
    const auto mixed_id = "<KmsResponse Id=\"resp\" Version=\"1.0.0\">" + payload_body +
                          "<Extra xmlns=\"urn:example\" xml:id=\"resp\"></Extra></KmsResponse>";
    refused(signed_message(root_open, root_close, mixed_id, {{"#resp", "", canonical_by_schema_id}}, key), key,
            "Id and xml:id with the same value", "ambiguous ID");
    // A namespace-qualified Id is not the schema's attribute.
    const auto prefixed_id =
        "<KmsResponse xmlns:p=\"urn:example\" p:Id=\"resp\" Version=\"1.0.0\">" + payload_body + "</KmsResponse>";
    refused(signed_message(root_open, root_close, prefixed_id,
                           {{"#resp", "",
                             "<KmsResponse xmlns=\"" + kmsns + "\" xmlns:p=\"urn:example\" Version=\"1.0.0\" p:Id=\"resp\">" +
                                 payload_body + "</KmsResponse>"}},
                           key),
            key, "a qualified Id is not an ID", "Reference to no element");
    // The null URI without the enveloped transform would digest the Signature itself.
    refused(signed_message(root_open, root_close, payload, {{"", "", document_minus_signature}}, key), key,
            "null URI without the enveloped transform", "reference digest mismatch");
    // Unsupported transforms, digest, truncation, XPointer forms; no fallback.
    refused(signed_message(root_open, root_close, payload,
                           {{"",
                             "<Transforms><Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\">"
                             "<XPath>not(ancestor-or-self::*[local-name()='KmsMessage'])</XPath></Transform>"
                             "</Transforms>",
                             document_minus_signature}},
                           key),
            key, "XPath transform excluding part of the payload", "unsupported Reference transform");
    refused(signed_message(root_open, root_close, payload,
                           {{"#resp", "", canonical_payload, "http://www.w3.org/2000/09/xmldsig#sha1"}}, key),
            key, "SHA-1 digest", "unsupported digest method");
    refused(signed_message(root_open, root_close, payload, {{"#resp", "", canonical_payload}}, key,
                           "<HMACOutputLength>128</HMACOutputLength>"),
            key, "truncated HMAC", "signature length is 256");
    refused(signed_message(root_open, root_close, payload, {{"#xpointer(id('resp'))", "", canonical_payload}}, key),
            key, "scheme-based XPointer", "unsupported Reference URI");
    // Structure: a DTD, a Signature inside the payload, an unsigned message, a 24-octet key.
    refused("<!DOCTYPE SignedKmsResponse [<!ATTLIST KmsResponse Id ID #IMPLIED>]>" + by_id, key, "DTD",
            "forbidden DTD");
    auto inside = by_id;
    const auto signature = inside.substr(inside.find("<Signature"));
    inside = root_open + "<KmsResponse Version=\"1.0.0\" xml:id=\"resp\">" + payload_body +
             signature.substr(0, signature.size() - root_close.size()) + "</KmsResponse>" + root_close;
    refused(inside, key, "Signature inside the KmsResponse", "one ds:Signature");
    refused(root_open + payload + root_close, key, "no Signature", "one ds:Signature");
    refused(by_id, Bytes(24, 1), "24-octet key", "128 or 256 bits");

    // While the protected KMS exchange is not implemented, the provisioning parser refuses a correctly signed
    // response (TS 33.180 annex D.3.1 handling stays as it is).
    bool held = false;
    try {
      mcx::keying::parse_kms_init(by_id, "sip:a@example.org", "https://kms.example.org",
                                  "https://kms.example.org/keymanagement/identity/v1/init", 0);
    } catch (const std::exception &error) {
      held = std::string(error.what()).find("XML signatures require a verifying profile") != std::string::npos;
    }
    check(held, "a signed KMS response still stops at the provisioning parser");
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << "\n";
    return 1;
  }
  std::cout << "KMS XML signature: ok\n";
  return 0;
}
