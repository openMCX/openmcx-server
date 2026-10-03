// XML signalling protection: the XPK-derived keys, XML content and URI attribute encryption, re-encryption by an
// IS proxy, and the XML signature of whole bodies (TS 33.180 clause 9.3, TS 24.379 clause 6.6, TS 24.282 clause 4.6,
// TS 24.281 clause 4.8).
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19),
// TS 24.281 V19.6.0 (Rel-19).
#include "mcx/xml_security.hpp"

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
    std::cout << "xml security tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
