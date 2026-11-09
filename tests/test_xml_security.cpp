//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// XML signalling protection: the XPK-derived keys, XML content and URI attribute encryption, re-encryption by an
// IS proxy, and the XML signature of whole bodies (TS 33.180 clause 9.3, TS 24.379 clause 6.6, TS 24.282 clause 4.6,
// TS 24.281 clause 4.8).
//
// Specifications: TS 33.180 V19.5.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19),
// TS 24.281 V19.6.0 (Rel-19), RFC 4231, RFC 2392, W3C XMLDSig Second Edition and 1.1, W3C Canonical XML 1.0,
// W3C Exclusive XML Canonicalization 1.0.
#include "mcx/xml_security.hpp"

#include "../src/security/c14n11.hpp"

#include <libxml/parser.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <set>
#include <stdexcept>

namespace {
//------------------------------------------------------------------------------
// Fails the test with the message what when the condition does not hold.
void check(bool condition, const char *what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Checks that the action throws; the message what names what would have been wrongly accepted.
template <class Action> void rejects(Action action, const char *what) {
  bool failed = false;
  try {
    action();
  } catch (const std::exception &) {
    failed = true;
  }
  check(failed, what);
}

//------------------------------------------------------------------------------
// Encodes a 128-bit key as lower-case hexadecimal.
std::string hex(const std::array<std::uint8_t, 16> &bytes) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  for (auto byte : bytes) {
    out += digits[byte >> 4];
    out += digits[byte & 15];
  }
  return out;
}

//------------------------------------------------------------------------------
// Encodes octets as lower-case hexadecimal.
std::string hex_of(const std::uint8_t *data, std::size_t size) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  for (std::size_t index = 0; index < size; ++index) {
    out += digits[data[index] >> 4];
    out += digits[data[index] & 15];
  }
  return out;
}

//------------------------------------------------------------------------------
// RFC 4648 section 4 base64 of octets.
std::string base64_of(const std::uint8_t *data, std::size_t size) {
  std::string out(4 * ((size + 2) / 3) + 1, '\0');
  const auto length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data, static_cast<int>(size));
  out.resize(static_cast<std::size_t>(length));
  return out;
}

//------------------------------------------------------------------------------
// The base64 SHA-256 digest of a body, as a DigestValue.
std::string digest_of(std::string_view body) {
  std::array<std::uint8_t, 32> hash{};
  unsigned length = 0;
  EVP_Digest(body.data(), body.size(), hash.data(), &length, EVP_sha256(), nullptr);
  return base64_of(hash.data(), hash.size());
}

//------------------------------------------------------------------------------
// A signatures document with one Signature over the given SignedInfo, made as another implementation would: the
// SignedInfo canonicalised in the document by the algorithm given, HMAC-SHA256 under the integrity key, the first
// `octets` of the value kept.
std::string signature_document(const std::string &info, const mcx::xmlsec::Key &key, std::string_view algorithm,
                               std::size_t octets = 32, const std::vector<std::string> &prefixes = {}) {
  const std::string head = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                           "<signatures xmlns=\"urn:3gpp:ns:mcpttSignedDoc:1.0\">"
                           "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
                           info + "<ds:SignatureValue>";
  const std::string tail =
      "</ds:SignatureValue><ds:KeyInfo><ds:KeyName>IAAAAQ==</ds:KeyName></ds:KeyInfo></ds:Signature></signatures>";
  const auto draft = head + "AAAA" + tail;
  const auto canonical = mcx::xmlsec::canonicalize(draft, algorithm, "SignedInfo", prefixes);
  const auto integrity = mcx::xmlsec::integrity_key(key);
  const auto mac = mcx::xmlsec::hmac_sha256(integrity, canonical);
  return head + base64_of(mac.data(), octets) + tail;
}

//------------------------------------------------------------------------------
// A SignedInfo with the given CanonicalizationMethod (none when empty), SignatureMethod content and References.
std::string signed_info_of(std::string_view canonicalization, std::string_view method_content,
                           const std::string &references) {
  std::string out = "<ds:SignedInfo>";
  if (!canonicalization.empty())
    out += "<ds:CanonicalizationMethod Algorithm=\"" + std::string(canonicalization) + "\"/>";
  out += "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\">" +
         std::string(method_content) + "</ds:SignatureMethod>";
  return out + references + "</ds:SignedInfo>";
}

//------------------------------------------------------------------------------
// A Reference to a cid URL with optional Transforms and the SHA-256 digest of the octets given.
std::string reference_of(std::string_view url, std::string_view digested, std::string_view transforms = {}) {
  return "<ds:Reference URI=\"" + std::string(url) + "\">" + std::string(transforms) +
         "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>" +
         digest_of(digested) + "</ds:DigestValue></ds:Reference>";
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3: the confidentiality and integrity keys from the XPK (annex F.1.4), XML content encryption
// (clause 9.3.4.2), URI attribute encryption (clause 9.3.4.3), re-encryption by the IS proxy (clause 11.1.3), the
// XML signature (clause 9.3.5) and the MCVideo signalling profile (TS 24.281 clause 4.8).
int main() {
  try {
    using namespace mcx::xmlsec;
    Key key;
    for (unsigned index = 0; index < 16; ++index) key.xpk[index] = static_cast<std::uint8_t>(index);
    key.id = 0x20000001;
    key.user = "sip:alice@example.org";
    // TS 33.180 annex F.1.4 with TS 33.220 annex B, calculated independently with Python hmac.
    check(hex(confidentiality_key(key)) == "cc31ea68d22862176f98a52e5a80ae68", "confidentiality key known answer");
    check(hex(integrity_key(key)) == "91fdf6756fd52f67659100bbc7cb7bf6", "integrity key known answer");

    // TS 33.180 clause 9.3.4.2, TS 24.282 clause 4.6 EXAMPLE 5 and EXAMPLE 6: an element with type="Normal" becomes type="Encrypted".
    const std::string info =
        "<?xml version=\"1.0\"?><mcdatainfo xmlns=\"urn:3gpp:ns:mcdataInfo:1.0\"><mcdata-Params>"
        "<request-type>group-sds</request-type>"
        "<mcdata-request-uri type=\"Normal\"><mcdataURI>sip:group123@example.org</mcdataURI></mcdata-request-uri>"
        "<mcdata-access-token type=\"Normal\"><mcdataString>secret-token</mcdataString></mcdata-access-token>"
        "</mcdata-Params></mcdatainfo>";
    const Profile profile{{"mcdata-request-uri", "mcdata-access-token"}, {{"entry", "uri"}}};
    const auto encrypted = encrypt(info, key, profile);
    // TS 33.180 clause 11.1.3: the IS proxy re-protects the same content under another key.
    {
      Key other = key;
      other.xpk[0] = 0xff;
      other.id = 0x30000002;
      const auto moved = reencrypt(encrypted, key, other);
      check(moved != encrypted && is_protected(moved) && key_id(moved) == other.id, "re-encrypted under the other key");
      check(decrypt(moved, other) == decrypt(encrypted, key), "re-encryption keeps the content");
      rejects([&] { (void)decrypt(moved, key); }, "the first key no longer opens it");
      rejects([&] { (void)reencrypt(encrypted, other, key); }, "re-encryption needs the key it is under");
    }
    check(encrypted.find("group123") == std::string::npos && encrypted.find("secret-token") == std::string::npos,
          "sensitive content removed");
    check(encrypted.find("type=\"Encrypted\"") != std::string::npos &&
              encrypted.find("http://www.w3.org/2009/xmlenc11#aes128-gcm") != std::string::npos &&
              encrypted.find("<ds:KeyName>IAAAAQ==</ds:KeyName>") != std::string::npos,
          "EncryptedData with the algorithm and the base64 XPK-ID");
    check(encrypted.find("<request-type>group-sds</request-type>") != std::string::npos, "other elements stay clear");
    check(is_protected(encrypted) && !is_protected(info), "protection detected");
    const auto decrypted = decrypt(encrypted, key);
    check(decrypted.find("<mcdataURI>sip:group123@example.org</mcdataURI>") != std::string::npos &&
              decrypted.find("<mcdataString>secret-token</mcdataString>") != std::string::npos &&
              decrypted.find("type=\"Encrypted\"") == std::string::npos,
          "content round trip");
    check(encrypt(info, key, profile) != encrypted, "a fresh IV for every encryption");

    auto other = key;
    other.xpk[0] ^= 1;
    rejects([&] { decrypt(encrypted, other); }, "decryption under another XPK accepted");
    other = key;
    other.id = 0x20000002;
    rejects([&] { decrypt(encrypted, other); }, "decryption under another XPK-ID accepted");
    other = key;
    other.user = "sip:bob@example.org";
    rejects([&] { decrypt(encrypted, other); }, "keys of another MC service user ID accepted");
    auto tampered = encrypted;
    const auto at = tampered.find("<CipherValue>") + 20;
    tampered[at] = tampered[at] == 'A' ? 'B' : 'A';
    rejects([&] { decrypt(tampered, key); }, "altered ciphertext accepted");

    // TS 33.180 clause 9.3.4.3, TS 24.379 clause 6.6.2.3.4: URI attributes, as in a resource-lists body.
    const std::string list =
        "<?xml version=\"1.0\"?><resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\"><list>"
        "<entry uri=\"sip:bob@example.org\"/></list></resource-lists>";
    const auto hidden = encrypt(list, key, profile);
    check(hidden.find("bob@example.org") == std::string::npos &&
              hidden.find("@mc1-encryption.3gppnetwork.org") != std::string::npos,
          "URI attribute encrypted");
    check(decrypt(hidden, key).find("uri=\"sip:bob@example.org\"") != std::string::npos, "URI attribute round trip");
    const auto uri = encrypt_uri("sip:carol@example.org", key);
    check(uri.starts_with("sip:") && uri.find(";iv=") != std::string::npos &&
              uri.find(";key-id=IAAAAQ==") != std::string::npos &&
              uri.find(";alg=128-aes-gcm@mc1-encryption.3gppnetwork.org") != std::string::npos && is_encrypted_uri(uri),
          "encrypted URI format");
    check(decrypt_uri(uri, key) == "sip:carol@example.org", "URI round trip");
    other = key;
    other.id = 7;
    rejects([&] { decrypt_uri(uri, other); }, "URI under another key accepted");
    rejects([&] { decrypt("<a", key); }, "malformed XML accepted");
    {
      // TS 33.180 clause 9.3.5, TS 24.379 clause 6.6.3.3.3: HMAC-SHA256 xmldsig signatures of whole bodies.
      const std::vector<SignedBody> bodies{
          {"info@example.org", "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"/>"},
          {"list@example.org", "<resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\"/>"}};
      const auto signatures = sign(bodies, key, "urn:3gpp:ns:mcpttSignedDoc:1.0");
      check(signatures.find("urn:3gpp:ns:mcpttSignedDoc:1.0") != std::string::npos &&
                signatures.find("URI=\"cid:info@example.org\"") != std::string::npos &&
                signatures.find("xmldsig-more#hmac-sha256") != std::string::npos &&
                signature_key_id(signatures) == key.id,
            "signature document");
      check(verify(signatures, bodies, key) == std::set<std::string>{"info@example.org", "list@example.org"},
            "signatures verify");
      auto tampered = bodies;
      tampered[1].body += " ";
      rejects([&] { verify(signatures, tampered, key); }, "a changed body verified");
      rejects([&] { verify(signatures, {bodies[0]}, key); }, "a signature to a missing body verified");
      auto forged = signatures;
      forged[forged.find("<ds:SignatureValue>") + 19] ^= 1;
      rejects([&] { verify(forged, bodies, key); }, "a changed signature value verified");
      other = key;
      other.xpk[0] ^= 1;
      rejects([&] { verify(signatures, bodies, other); }, "a signature under another XPK verified");
      // Another writer may declare the namespace once on the root: the exclusive
      // canonical SignedInfo is unchanged.
      std::string rewritten = signatures;
      const std::string declaration = " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"";
      for (std::size_t at; (at = rewritten.find(declaration)) != std::string::npos;)
        rewritten.erase(at, declaration.size());
      rewritten.insert(rewritten.find("<signatures ") + 11, declaration);
      check(verify(rewritten, bodies, key).size() == 2, "signatures with the namespace declared on the root verify");
    }
    // RFC 4231 section 4: the HMAC-SHA-256 test cases 1 to 7 (case 5 truncated to 128 bits).
    {
      struct Vector {
        std::vector<std::uint8_t> key;
        std::string data;
        std::string mac;
      };
      std::vector<std::uint8_t> key4;
      for (std::uint8_t octet = 1; octet <= 25; ++octet) key4.push_back(octet);
      const std::vector<Vector> vectors{
          {std::vector<std::uint8_t>(20, 0x0b), "Hi There",
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
          {{'J', 'e', 'f', 'e'}, "what do ya want for nothing?",
           "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
          {std::vector<std::uint8_t>(20, 0xaa), std::string(50, '\xdd'),
           "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"},
          {key4, std::string(50, '\xcd'), "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"},
          {std::vector<std::uint8_t>(20, 0x0c), "Test With Truncation", "a3b6167473100ee06e0c796c2955552b"},
          {std::vector<std::uint8_t>(131, 0xaa), "Test Using Larger Than Block-Size Key - Hash Key First",
           "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
          {std::vector<std::uint8_t>(131, 0xaa),
           "This is a test using a larger than block-size key and a larger than block-size data. The key needs to "
           "be hashed before being used by the HMAC algorithm.",
           "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"}};
      for (const auto &vector : vectors) {
        const auto mac = hmac_sha256(vector.key, vector.data);
        check(hex_of(mac.data(), vector.mac.size() / 2) == vector.mac, "RFC 4231 HMAC-SHA-256 test case");
      }
    }

    // W3C Canonical XML 1.0 section 3 examples (3.1 both forms, 3.2, 3.3, 3.6).
    {
      const std::string c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
      const std::string example31 = "<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   "
                                    "type=\"text/xsl\"   ?>\n\n<!DOCTYPE doc SYSTEM \"doc.dtd\">\n\n<doc>Hello, "
                                    "world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 "
                                    "-->\n\n<!-- Comment 3 -->";
      check(canonicalize(example31, c14n) ==
                "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n"
                "<?pi-without-data?>",
            "Canonical XML 1.0 example 3.1 (uncommented)");
      check(canonicalize(example31, c14n + "#WithComments") ==
                "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 "
                "--></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->",
            "Canonical XML 1.0 example 3.1 (commented)");
      const std::string example32 = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      "
                                    "A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      "
                                    "C\n   </mixed>\n</doc>";
      check(canonicalize(example32, c14n) == example32, "Canonical XML 1.0 example 3.2");
      // Example 3.3, its DTD default attribute written out on e9 (the parser applies no DTD).
      const std::string example33 =
          "<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n   <e4   "
          "name=\"elem4\"   id=\"elem4\"   ></e4>\n   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" "
          "attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      "
          "xmlns=\"http://example.org\"/>\n   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 "
          "xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 "
          "xmlns=\"\" xmlns:a=\"http://www.ietf.org\" attr=\"default\"/>\n         </e8>\n      </e7>\n   "
          "</e6>\n</doc>";
      check(canonicalize(example33, c14n) ==
                "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" "
                "name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" "
                "xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" "
                "a:attr=\"out\"></e5>\n   <e6 xmlns:a=\"http://www.w3.org\">\n      <e7 "
                "xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9 "
                "xmlns:a=\"http://www.ietf.org\" attr=\"default\"></e9>\n         </e8>\n      </e7>\n   "
                "</e6>\n</doc>",
            "Canonical XML 1.0 example 3.3");
      check(canonicalize("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<doc>&#169;</doc>", c14n) ==
                "<doc>\xC2\xA9</doc>",
            "Canonical XML 1.0 example 3.6");
      rejects([&] { (void)canonicalize(example32, "http://www.w3.org/TR/1999/REC-xpath-19991116"); },
              "an unknown canonicalization algorithm");
    }

    // W3C Exclusive XML Canonicalization 1.0 section 2.2: the n1:elem2 subtree of its two documents, inclusive (in its
    // document context) and exclusive.
    {
      const std::string first = "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\">\n  <n1:elem2 "
                                "xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n    <n3:stuff "
                                "xmlns:n3=\"ftp://example.org\"/>\n  </n1:elem2>\n</n0:local>";
      const std::string second = "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\" "
                                 "xml:lang=\"fr\" xml:space=\"retain\">\n  <n1:elem2 xmlns:n1=\"http://example.net\" "
                                 "xml:lang=\"en\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n  "
                                 "</n1:elem2>\n</n2:pdu>";
      const std::string c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
      const std::string exclusive = "http://www.w3.org/2001/10/xml-exc-c14n#";
      check(canonicalize(first, c14n, "elem2") ==
                "<n1:elem2 xmlns:n0=\"foo:bar\" xmlns:n1=\"http://example.net\" xmlns:n3=\"ftp://example.org\" "
                "xml:lang=\"en\">\n    <n3:stuff></n3:stuff>\n  </n1:elem2>",
            "exclusive c14n example 2.2, first document, inclusive");
      check(canonicalize(second, c14n, "elem2") ==
                "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n2=\"http://foo.example\" xml:lang=\"en\" "
                "xml:space=\"retain\">\n    <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>",
            "exclusive c14n example 2.2, second document, inclusive");
      const std::string excl = "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n    <n3:stuff "
                               "xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>";
      check(canonicalize(first, exclusive, "elem2") == excl && canonicalize(second, exclusive, "elem2") == excl,
            "exclusive c14n example 2.2, exclusive");
      check(canonicalize(first, exclusive, "elem2", {"n3"}).find("<n1:elem2 xmlns:n1=\"http://example.net\" "
                                                                 "xmlns:n3=\"ftp://example.org\"") == 0,
            "exclusive c14n InclusiveNamespaces PrefixList");
    }

    // XMLDSig Second Edition clause 4.3.1 / 6.5, TS 24.379 clause 6.6.3.4.2: signatures made with each
    // canonicalisation algorithm verify; the SignedInfo is canonicalised in its document.
    {
      const std::string body = "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"/>";
      const std::vector<SignedBody> bodies{{"info@example.org", body}};
      const auto reference = reference_of("cid:info@example.org", body);
      const std::string base = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
      for (const std::string algorithm :
           {base, base + "#WithComments", std::string("http://www.w3.org/2006/12/xml-c14n11"),
            std::string("http://www.w3.org/2006/12/xml-c14n11#WithComments"),
            std::string("http://www.w3.org/2001/10/xml-exc-c14n#"),
            std::string("http://www.w3.org/2001/10/xml-exc-c14n#WithComments")}) {
        const auto document = signature_document(signed_info_of(algorithm, "", reference), key, algorithm);
        check(verify(document, bodies, key) == std::set<std::string>{"info@example.org"},
              "a signature canonicalised by its own algorithm verifies");
      }
      // A signature computed over the exclusive form but naming Canonical XML 1.0 fails: the verifier uses the
      // named algorithm, and the inclusive SignedInfo carries the root's default namespace.
      {
        const auto exclusive_document = signature_document(
            signed_info_of("http://www.w3.org/2001/10/xml-exc-c14n#", "", reference), key,
            "http://www.w3.org/2001/10/xml-exc-c14n#");
        auto renamed = exclusive_document;
        const std::string from = "http://www.w3.org/2001/10/xml-exc-c14n#";
        renamed.replace(renamed.find(from), from.size(), base);
        rejects([&] { (void)verify(renamed, bodies, key); }, "a SignedInfo canonicalised by another algorithm");
        check(canonicalize(exclusive_document, base, "SignedInfo")
                      .starts_with("<ds:SignedInfo xmlns=\"urn:3gpp:ns:mcpttSignedDoc:1.0\" "
                                   "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"),
              "inclusive SignedInfo in its document context");
      }
      // Exclusive c14n with an InclusiveNamespaces PrefixList.
      {
        const std::string exclusive = "http://www.w3.org/2001/10/xml-exc-c14n#";
        const std::string info =
            "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"" + exclusive +
            "\"><ec:InclusiveNamespaces xmlns:ec=\"" + exclusive +
            "\" PrefixList=\"#default\"/></ds:CanonicalizationMethod><ds:SignatureMethod "
            "Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>" +
            reference + "</ds:SignedInfo>";
        check(verify(signature_document(info, key, exclusive, 32, {"#default"}), bodies, key).size() == 1,
              "exclusive c14n with InclusiveNamespaces verifies");
        rejects([&] { (void)verify(signature_document(info, key, exclusive), bodies, key); },
                "exclusive c14n ignoring the InclusiveNamespaces PrefixList");
      }
      // Maintainer decision M8: a SignedInfo without CanonicalizationMethod fails; so does an unknown algorithm.
      rejects([&] { (void)verify(signature_document(signed_info_of("", "", reference), key, base), bodies, key); },
              "a SignedInfo without CanonicalizationMethod");
      {
        auto unknown = signature_document(signed_info_of(base, "", reference), key, base);
        unknown.replace(unknown.find(base), base.size(), "http://example.org/c14n");
        rejects([&] { (void)verify(unknown, bodies, key); }, "an unknown CanonicalizationMethod");
      }
      // OpenMCX signs with Exclusive XML Canonicalization 1.0 without comments (XMLDSig clause 6.5; Canonical XML
      // 1.0 is mandatory to accept, not to send), as 1.0.0 did, and its own signatures verify.
      const auto own = sign(bodies, key, "urn:3gpp:ns:mcpttSignedDoc:1.0");
      check(own.find("<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>") !=
                std::string::npos,
            "signatures name Exclusive XML Canonicalization 1.0");
      (void)verify(own, bodies, key);

      // XMLDSig 1.1 clauses 4.4.2 and 6.3.1 (maintainer decision M10): HMACOutputLength.
      const auto with_length = [&](const std::string &bits, std::size_t octets) {
        return signature_document(signed_info_of(base, "<ds:HMACOutputLength>" + bits + "</ds:HMACOutputLength>",
                                                 reference),
                                  key, base, octets);
      };
      check(verify(with_length("128", 16), bodies, key).size() == 1, "a 128-bit truncated HMAC verifies");
      check(verify(with_length("256", 32), bodies, key).size() == 1, "an untruncated HMACOutputLength verifies");
      check(verify(with_length(" 160 ", 20), bodies, key).size() == 1, "a 160-bit truncated HMAC verifies");
      rejects([&] { (void)verify(with_length("120", 15), bodies, key); }, "a 120-bit HMAC (below half the hash)");
      rejects([&] { (void)verify(with_length("80", 10), bodies, key); }, "an 80-bit HMAC (below half the hash)");
      rejects([&] { (void)verify(with_length("40", 5), bodies, key); }, "a 40-bit HMAC (CVE-2009-0217)");
      rejects([&] { (void)verify(with_length("0", 0), bodies, key); }, "a zero-length HMAC");
      rejects([&] { (void)verify(with_length("132", 16), bodies, key); }, "an HMACOutputLength not a multiple of 8");
      rejects([&] { (void)verify(with_length("264", 32), bodies, key); }, "an HMACOutputLength above the hash");
      rejects([&] { (void)verify(with_length("-128", 16), bodies, key); }, "a negative HMACOutputLength");
      rejects([&] { (void)verify(with_length("128", 32), bodies, key); }, "a value longer than HMACOutputLength");
      const auto untruncated = signed_info_of(base, "", reference);
      rejects([&] { (void)verify(signature_document(untruncated, key, base, 16), bodies, key); },
              "a truncated value without HMACOutputLength");

      // RFC 2392 section 2: the cid URL is %-decoded before it is matched to a Content-ID.
      const std::vector<SignedBody> escaped{{"a@b@x", body}};
      check(verify(signature_document(signed_info_of(base, "", reference_of("cid:a%40b@x", body)), key, base),
                   escaped, key) == std::set<std::string>{"a@b@x"},
            "a %-encoded cid URL matches its Content-ID");
      rejects([&] {
        (void)verify(signature_document(signed_info_of(base, "", reference_of("cid:a%4", body)), key, base), escaped,
                     key);
      }, "a malformed % escape");
      rejects([&] {
        (void)verify(signature_document(signed_info_of(base, "", reference_of("cid:a%2", body)), key, base), escaped,
                     key);
      }, "a truncated % escape");
      const std::vector<SignedBody> percent{{"50%off@example.org", body}};
      const auto signed_percent = sign(percent, key, "urn:3gpp:ns:mcpttSignedDoc:1.0");
      check(signed_percent.find("URI=\"cid:50%25off@example.org\"") != std::string::npos &&
                verify(signed_percent, percent, key).size() == 1,
            "a Content-ID with % is %-encoded in the cid URL and verifies");

      // XMLDSig Second Edition clause 4.3.3.2: Reference Transforms.
      const std::string loose = "<doc  b=\"2\" a=\"1\" ><e/></doc>";
      const std::vector<SignedBody> loose_bodies{{"doc@example.org", loose}};
      const auto transform = [](std::string_view algorithm) {
        return "<ds:Transforms><ds:Transform Algorithm=\"" + std::string(algorithm) + "\"/></ds:Transforms>";
      };
      const std::string canonical_loose = "<doc a=\"1\" b=\"2\"><e></e></doc>";
      const auto transformed = [&](std::string_view url, std::string_view digested, std::string_view algorithm) {
        return signature_document(signed_info_of(base, "", reference_of(url, digested, transform(algorithm))), key,
                                  base);
      };
      check(verify(transformed("cid:doc@example.org", canonical_loose, base), loose_bodies, key).size() == 1,
            "a Canonical XML 1.0 Reference transform");
      check(verify(transformed("cid:doc@example.org", canonical_loose,
                               "http://www.w3.org/2000/09/xmldsig#enveloped-signature"),
                   loose_bodies, key)
                    .size() == 1,
            "an enveloped-signature transform, then the default Canonical XML 1.0");
      const std::vector<SignedBody> encoded{{"b64@example.org", "PGEvPg=="}};
      check(verify(transformed("cid:b64@example.org", "<a/>", "http://www.w3.org/2000/09/xmldsig#base64"), encoded,
                   key)
                    .size() == 1,
            "a base64 Reference transform");
      rejects([&] {
        (void)verify(transformed("cid:doc@example.org", loose, "http://www.w3.org/TR/1999/REC-xpath-19991116"),
                     loose_bodies, key);
      }, "an unsupported Reference transform");

      // XMLDSig Second Edition clause 3.2.1: every Reference of a SignedInfo is validated.
      const std::vector<SignedBody> two{{"info@example.org", body}, {"doc@example.org", loose}};
      check(verify(signature_document(signed_info_of(base, "", reference + reference_of("cid:doc@example.org", loose)),
                                      key, base),
                   two, key) == std::set<std::string>{"info@example.org", "doc@example.org"},
            "a SignedInfo with two References");
      rejects([&] {
        (void)verify(signature_document(signed_info_of(base, "", reference + reference_of("cid:doc@example.org", body)),
                                        key, base),
                     two, key);
      }, "a SignedInfo whose second Reference fails");
    }

    // TS 33.180 clause 9.3.5 "all XML MIME bodies": the XML MIME types (RFC 7303, RFC 6839).
    check(is_xml_mime("application/vnd.3gpp.mcvideo-location-info+xml") && is_xml_mime("application/xml") &&
              is_xml_mime("text/xml") && is_xml_mime("Application/PIDF+XML; charset=UTF-8") &&
              is_xml_mime("application/vnd.3gpp.mcptt-signed+xml") && !is_xml_mime("application/sdp") &&
              !is_xml_mime("application/mikey") && !is_xml_mime("application/vnd.3gpp.mcdata-signalling") &&
              !is_xml_mime("+xml") && !is_xml_mime("application/xml-dtd"),
          "XML MIME types");
    // TS 24.281 clause 4.8: the MCVideo signalling profile names the MCVideo elements.
    {
      const auto &video = signalling_profile("mcvideo");
      check(video.elements.contains("mcvideo-request-uri") && video.elements.contains("mcvideo-access-token") &&
                !video.elements.contains("mcptt-request-uri") && video.elements.contains("latitude") &&
                video.uri_attributes == signalling_profile().uri_attributes &&
                signalling_profile().elements.contains("mcptt-request-uri"),
            "MCVideo signalling profile");
      const std::string video_info =
          "<?xml version=\"1.0\"?><mcvideoinfo xmlns=\"urn:3gpp:ns:mcvideoInfo:1.0\"><mcvideo-Params>"
          "<mcvideo-request-uri "
          "type=\"Normal\"><mcvideoURI>sip:bob.mcvideo@example.org</mcvideoURI></mcvideo-request-uri>"
          "</mcvideo-Params></mcvideoinfo>";
      const auto sealed = encrypt(video_info, key, video);
      check(sealed.find("bob.mcvideo") == std::string::npos &&
                decrypt(sealed, key).find("bob.mcvideo") != std::string::npos,
            "MCVideo request URI encrypted under the MCVideo profile");
      rejects([] { (void)signalling_profile("mcdata"); }, "a service without a signalling profile");
    }

    // W3C Canonical XML 1.1 clause 2.4: join-URI-References, its examples and RFC 3986 cases with the clause's
    // modifications (the expected values follow the clause; where libxml2 2.9.14 differs, its result is noted).
    {
      const std::vector<std::array<std::string, 3>> joins{
          {"abc/", "../", ""},
          {"../", "../", "../../"},
          {"..", "..", "../../"}, // libxml2: "../.."
          {"http://h/a/b", "c/d", "http://h/a/c/d"},
          {"http://h/a/b/", "../../../x", "http://h/x"},
          {"http://h", "z", "http://h/z"},
          {"/a/b/", "../c", "/a/c"},
          {"x", "../y", "../y"},
          {"../..", "x", "../../x"},
          {"a/./b/", "./c/.", "a/b/c/"},
          {"a//b/", "c", "a/b/c"},
          {"a/b", "", "a/b"},
          {"http://h/a?q", "", "http://h/a?q"},
          {"a/b", "?n", "a/b?n"},
          {"a/b?q", "#f", "a/b?q"},                         // libxml2: "a/b?q#f"
          {"a/b", "../../c#x", "../c"},                     // libxml2: "../c#x"
          {"a/", "http://o/p/./q", "http://o/p/q"},         // libxml2: "http://o/p/./q"
          {"http://h/a", "//o/p/../q", "http://o/q"}};
      for (const auto &[base, reference, joined] : joins)
        check(join_uri_references(base, reference) == joined,
              ("join-URI-References \"" + base + "\" \"" + reference + "\"").c_str());
      // <a xml:base="foo/bar"><b xml:base=".."><c xml:base=".."><d xml:base="x">, b and c omitted: "../../x".
      check(join_uri_references("..", join_uri_references("..", "x")) == "../../x", "clause 2.4 example");
    }

    // W3C Canonical XML 1.1 clause 2.4 on a document subset (the subtree of one element, as a SignedInfo or a
    // referenced element is taken).
    {
      const std::string c14n11 = "http://www.w3.org/2006/12/xml-c14n11";
      const std::string c14n10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
      // Joined values (libxml2 gives the same).
      check(canonicalize("<r xmlns=\"urn:d\" xml:base=\"http://h/a/\"><m xml:base=\"b/\"><e/></m></r>", c14n11, "e") ==
                "<e xmlns=\"urn:d\" xml:base=\"http://h/a/b/\"></e>",
            "xml:base joined over two omitted ancestors");
      check(canonicalize("<a xml:base=\"foo/bar\"><b xml:base=\"..\"><c xml:base=\"..\"><d xml:base=\"x\"/></c></b></a>",
                         c14n11, "d") == "<d xml:base=\"../x\"></d>",
            "xml:base of a, b, c and d joined");
      // A fixed-up value that is empty is not rendered.
      check(canonicalize("<r><m xml:base=\"abc/\"><e xml:base=\"../\"/></m></r>", c14n11, "e") == "<e></e>",
            "empty fixed-up xml:base not rendered");
      // The fragment of a joined value is dropped (libxml2 keeps "#x").
      check(canonicalize("<r xml:base=\"http://h/a?q\"><m xml:base=\"#f\"><e xml:base=\"../../c#x\"/></m></r>", c14n11,
                         "e") == "<e xml:base=\"http://h/c\"></e>",
            "fragment of the joined xml:base dropped");
      // A trailing "..": "../../" (libxml2: "../..").
      check(canonicalize("<r xml:base=\"..\"><e xml:base=\"..\"/></r>", c14n11, "e") == "<e xml:base=\"../../\"></e>",
            "trailing .. of the joined xml:base");
      // No fix-up: the single omitted xml:base as it is; an element's own xml:base, also an empty one, is an
      // ordinary attribute (libxml2 drops the empty one).
      check(canonicalize("<r xml:base=\"http://h/a/\"><e/></r>", c14n11, "e") == "<e xml:base=\"http://h/a/\"></e>",
            "single omitted xml:base");
      check(canonicalize("<r><e xml:base=\"a/../b\"/></r>", c14n11, "e") == "<e xml:base=\"a/../b\"></e>",
            "own xml:base without a fix-up");
      check(canonicalize("<r xml:base=\"\"><e/></r>", c14n11) == "<r xml:base=\"\"><e></e></r>",
            "own empty xml:base without a fix-up (whole document)");
      check(canonicalize("<r><m><e xml:base=\"\"><f xml:base=\"\"/></e></m></r>", c14n11, "e") ==
                "<e xml:base=\"\"><f xml:base=\"\"></f></e>",
            "own empty xml:base without a fix-up (subset)");
      // Inside the subset an element's own xml:base is never fixed up (its parent is rendered).
      check(canonicalize("<r xml:base=\"http://h/\"><e><f xml:base=\"../x\"/></e></r>", c14n11, "e") ==
                "<e xml:base=\"http://h/\"><f xml:base=\"../x\"></f></e>",
            "xml:base of a child of a rendered element");
      // xml:lang and xml:space inherited from the nearest omitted ancestor; xml:id and other xml: attributes not.
      check(canonicalize("<r xml:lang=\"en\" xml:space=\"preserve\" xml:id=\"r\" xml:other=\"o\"><m xml:lang=\"fr\" "
                         "xml:id=\"m\"><e a=\"1\"/></m></r>",
                         c14n11, "e") == "<e a=\"1\" xml:lang=\"fr\" xml:space=\"preserve\"></e>",
            "simple inheritable attributes only");
      check(canonicalize("<r xml:id=\"r\" xml:other=\"o\"><e xml:id=\"e\" xml:other=\"p\"/></r>", c14n11, "e") ==
                "<e xml:id=\"e\" xml:other=\"p\"></e>",
            "own xml:id and other xml: attributes ordinary");
      // With comments.
      check(canonicalize("<r xml:base=\"http://h/a/\"><!--c--><m xml:base=\"b/\" xml:id=\"m\"><!--d--><e/></m></r>",
                         c14n11 + "#WithComments", "m") == "<m xml:base=\"http://h/a/b/\" xml:id=\"m\"><!--d--><e></e></m>",
            "xml:base fixed up with comments");
      // The document is unchanged after the canonicalization (it is read again for the next Reference).
      {
        const std::string xml = "<r xml:base=\"h/\" xml:id=\"r\" xml:o=\"1\"><m xml:base=\"\" xml:lang=\"x\"><e "
                                "xml:base=\"../\" a=\"1\"/><f/></m></r>";
        xmlDocPtr doc = xmlReadMemory(xml.data(), static_cast<int>(xml.size()), nullptr, nullptr, XML_PARSE_NONET);
        check(doc != nullptr, "parse");
        const auto dump = [doc] {
          xmlChar *text = nullptr;
          int size = 0;
          xmlDocDumpMemory(doc, &text, &size);
          std::string out(reinterpret_cast<const char *>(text), static_cast<std::size_t>(size));
          xmlFree(text);
          return out;
        };
        const auto before = dump();
        for (const char *apex : {"e", "f", "m"}) {
          xmlNodePtr top = xmlDocGetRootElement(doc)->children;
          if (std::string(apex) != "m")
            for (top = top->children; std::string(reinterpret_cast<const char *>(top->name)) != apex; top = top->next) {
            }
          const auto in_subtree = [](void *data, xmlNodePtr node, xmlNodePtr parent) -> int {
            for (auto *current = node->type == XML_ATTRIBUTE_NODE || node->type == XML_NAMESPACE_DECL ? parent : node;
                 current; current = current->parent)
              if (current == data) return 1;
            return 0;
          };
          xmlOutputBufferPtr buffer = xmlAllocOutputBuffer(nullptr);
          check(c14n11_execute(doc, in_subtree, top, 0, buffer) >= 0, "canonicalization");
          xmlOutputBufferClose(buffer);
          check(dump() == before, (std::string("document restored after the subset of ") + apex).c_str());
        }
        xmlFreeDoc(doc);
      }
      // Canonical XML 1.1 example 3.8 with the canonical form of erratum E11-01 (W3C, 2008): e3's xml:base joins
      // only e2's, the contiguously omitted ancestor; the Recommendation's "something/bar/foo" was the defect.
      {
        const std::string xml =
            "<!DOCTYPE doc [<!ATTLIST e2 xml:space (default|preserve) 'preserve'><!ATTLIST e3 id ID #IMPLIED>]>"
            "<doc xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"something/else\">\n"
            "   <e1>\n      <e2 xmlns=\"\" xml:id=\"abc\" xml:base=\"bar/\">\n         <e3 id=\"E3\" xml:base=\"foo\"/>\n"
            "      </e2>\n   </e1>\n</doc>";
        xmlDocPtr doc =
            xmlReadMemory(xml.data(), static_cast<int>(xml.size()), nullptr, nullptr, XML_PARSE_NONET | XML_PARSE_DTDATTR);
        check(doc != nullptr, "parse example 3.8");
        // The subset expression: e1, its attributes and namespaces and its children other than text and e2, and every
        // node of e3's subtree.
        const auto in_subset = [](void *, xmlNodePtr node, xmlNodePtr parent) -> int {
          const auto named = [](xmlNodePtr n, const char *name) {
            return n && n->type == XML_ELEMENT_NODE && std::string(reinterpret_cast<const char *>(n->name)) == name;
          };
          const bool owned = node->type == XML_ATTRIBUTE_NODE || node->type == XML_NAMESPACE_DECL;
          xmlNodePtr element = owned ? parent : node;
          for (xmlNodePtr current = element; current; current = current->parent)
            if (named(current, "e3")) return 1;
          if (owned) return named(parent, "e1");
          return named(node, "e1") || (named(node->parent, "e1") && node->type != XML_TEXT_NODE && !named(node, "e2"));
        };
        xmlOutputBufferPtr buffer = xmlAllocOutputBuffer(nullptr);
        check(c14n11_execute(doc, in_subset, nullptr, 0, buffer) >= 0, "canonicalization of example 3.8");
        const auto *content = xmlOutputBufferGetContent(buffer);
        const std::string canonical(reinterpret_cast<const char *>(content), xmlOutputBufferGetSize(buffer));
        xmlOutputBufferClose(buffer);
        xmlFreeDoc(doc);
        check(canonical == "<e1 xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"something/else\">"
                           "<e3 xmlns=\"\" id=\"E3\" xml:base=\"bar/foo\" xml:space=\"preserve\"></e3></e1>",
              ("Canonical XML 1.1 example 3.8 (erratum E11-01): " + canonical).c_str());
      }
      // Node-sets of named elements (with their attributes, namespaces and text): an omitted element between two
      // rendered ones. Refused only where libxml2 would merge a rendered ancestor's xml: attribute into the element.
      {
        const auto subset = [](const std::string &xml, std::vector<std::string> names) {
          xmlDocPtr doc = xmlReadMemory(xml.data(), static_cast<int>(xml.size()), nullptr, nullptr, XML_PARSE_NONET);
          check(doc != nullptr, "parse");
          // Names of elements in the set, and "element@attribute" for an attribute of such an element left out.
          const auto in_set = [](void *data, xmlNodePtr node, xmlNodePtr parent) -> int {
            const auto &set = *static_cast<std::vector<std::string> *>(data);
            if (node->type == XML_ATTRIBUTE_NODE && parent &&
                std::find(set.begin(), set.end(),
                          std::string(reinterpret_cast<const char *>(parent->name)) + "@" +
                              reinterpret_cast<const char *>(node->name)) != set.end())
              return 0;
            xmlNodePtr element =
                node->type == XML_ATTRIBUTE_NODE || node->type == XML_NAMESPACE_DECL || node->type == XML_TEXT_NODE
                    ? parent
                    : node;
            return element && element->type == XML_ELEMENT_NODE &&
                   std::find(set.begin(), set.end(), reinterpret_cast<const char *>(element->name)) != set.end();
          };
          xmlOutputBufferPtr buffer = xmlAllocOutputBuffer(nullptr);
          std::string out;
          try {
            check(c14n11_execute(doc, in_set, &names, 0, buffer) >= 0, "canonicalization");
            out.assign(reinterpret_cast<const char *>(xmlOutputBufferGetContent(buffer)), xmlOutputBufferGetSize(buffer));
          } catch (...) {
            xmlOutputBufferClose(buffer);
            xmlFreeDoc(doc);
            throw;
          }
          xmlOutputBufferClose(buffer);
          xmlFreeDoc(doc);
          return out;
        };
        const auto refused = [&](const std::string &xml, std::vector<std::string> names) {
          try {
            subset(xml, std::move(names));
          } catch (const std::exception &) {
            return true;
          }
          return false;
        };
        check(refused("<r xml:id=\"x\"><m><e/></m></r>", {"r", "e"}), "rendered ancestor's xml:id refused");
        check(refused("<r xml:base=\"http://h/\"><m><e/></m></r>", {"r", "e"}),
              "rendered ancestor's xml:base without a fix-up refused");
        check(subset("<r xml:id=\"x\"><m><e xml:id=\"y\"/></m></r>", {"r", "e"}) ==
                  "<r xml:id=\"x\"><e xml:id=\"y\"></e></r>",
              "element's own xml:id kept");
        check(subset("<r xml:base=\"http://h/a/\"><m xml:base=\"b/\"><e/></m></r>", {"r", "e"}) ==
                  "<r xml:base=\"http://h/a/\"><e xml:base=\"b/\"></e></r>",
              "xml:base joined over the omitted run only");
        // The element's own or fixed-up xml:base outside the node-set: libxml2 would merge the ancestor's.
        check(refused("<r xml:base=\"http://h/\"><m><e xml:base=\"x/\"/></m></r>", {"r", "e", "e@base"}),
              "own xml:base outside the node-set, rendered ancestor's xml:base refused");
        check(refused("<r><m xml:base=\"b/\"><e xml:base=\"x\"/></m></r>", {"r", "e", "e@base"}),
              "fixed-up xml:base outside the node-set refused");
        check(subset("<r><m><e xml:base=\"x\"/></m></r>", {"r", "e", "e@base"}) == "<r><e></e></r>",
              "own xml:base outside the node-set, nothing to merge");
      }
      // Canonical XML 1.0 has no fix-up: every xml: attribute of the omitted ancestors, the nearest one first.
      check(canonicalize("<r xml:base=\"http://h/a/\" xml:id=\"r\"><m xml:base=\"b/\"><e/></m></r>", c14n10, "e") ==
                "<e xml:base=\"b/\" xml:id=\"r\"></e>",
            "Canonical XML 1.0 xml: attributes inherited");
    }
    std::cout << "xml security tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
