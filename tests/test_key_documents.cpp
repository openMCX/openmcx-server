//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Key management documents: the KMS XML responses (KMSInit, KMSKeyProv, KMSCertCache), the KMS Redirect Response,
// and the MCS GKTP document with its selector, resource list and XCAP diff.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19); RFC 4826 (resource lists), RFC 5874
// (XCAP diff).

#include "mcx/key_documents.hpp"

#include <iostream>
#include <stdexcept>
using namespace mcx::keying;

//------------------------------------------------------------------------------
// Throws the message when the condition does not hold.
void check(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Fails unless the action throws.
template <class Action> void rejects(Action action) {
  bool bad = false;
  try {
    action();
  } catch (const std::exception &) {
    bad = true;
  }
  check(bad, "invalid document accepted");
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.3: KMSInit (annex D.3.2) and KMSKeyProv (annex D.3.3) responses round trip and are
// refused for another user, another request URI, out of their validity, with a wrong namespace, an altered key,
// a duplicate element or a DTD; TS 24.481 clause 7.7: the MCS GKTP document binds the MIKEY payload to its group
// and time, its selector follows clause 7.7.10, its resource list and XCAP diff bind the group; annex D.3.4.3:
// KMSCertCache; annex D.4: the KMS Redirect Response.
int main() {
  try {
    PublicParameters home_kms{{"https://kms.example.org", 2592000, 0}, Bytes(65, 1), Bytes(257, 2)};
    home_kms.authentication_key[0] = 4;
    home_kms.encryption_key[0] = 4;
    const std::uint64_t now = 4000000000ULL;
    auto init =
        kms_init_xml(home_kms, "sip:a@example.org", "https://kms.example.org/keymanagement/identity/v1/init", now);
    check(init.find("UserIdFormat") != std::string::npos && init.find("PubEncKey") != std::string::npos,
          "Annex D field names");
    auto parsed = parse_kms_init(init, "sip:a@example.org", home_kms.period.kms_uri,
                                 "https://kms.example.org/keymanagement/identity/v1/init", now);
    check(parsed.authentication_key == home_kms.authentication_key && parsed.encryption_key == home_kms.encryption_key,
          "certificate key roundtrip");
    rejects([&] {
      parse_kms_init(init, "sip:b@example.org", home_kms.period.kms_uri,
                     "https://kms.example.org/keymanagement/identity/v1/init", now);
    });
    rejects([&] {
      parse_kms_init(init, "sip:a@example.org", home_kms.period.kms_uri, "https://evil.example.org/init", now);
    });
    rejects([&] {
      parse_kms_init(init, "sip:a@example.org", home_kms.period.kms_uri,
                     "https://kms.example.org/keymanagement/identity/v1/init", now + 1000);
    });
    auto wrong = init;
    auto at = wrong.find("urn:3gpp:ns:mcsecKMSInterface:1.0");
    wrong.replace(at, 31, "urn:evil");
    rejects([&] {
      parse_kms_init(wrong, "sip:a@example.org", home_kms.period.kms_uri,
                     "https://kms.example.org/keymanagement/identity/v1/init", now);
    });
    const Bytes mikey{1, 2, 3, 4, 0xff};
    auto group = gktp_document_xml("sip:g@example.org", "key1", mikey, now);
    check(group.find("01020304ff") != std::string::npos, "GKTP uses hexBinary");
    check(parse_gktp_document(group, "sip:g@example.org") == mikey, "GKTP group binding");
    rejects([&] { parse_gktp_document(group, "sip:h@example.org"); });
    // TS 24.481 clause 7.7.8: a GKTP sent ahead of its activation time is kept (TS 33.180 annex E.6.4).
    check(parse_gktp_document(gktp_document_xml("sip:g@example.org", "key2", mikey, now + 3600), "sip:g@example.org") ==
              mikey,
          "GKTP ahead of its activation time");
    check(gktp_selector("sip:g@example.org").find("org.3gpp.MCPTT-GKTP/global/byGroupID/sip%3Ag%40example.org/~~/") ==
              0,
          "standard GKTP selector");
    check(gktp_resource_list("sip:g@example.org").find("urn:ietf:params:xml:ns:resource-lists") != std::string::npos,
          "SIP resource list");
    auto authority = create_authority(home_kms.period);
    auto keys = issue(authority, "sip:a@example.org", now);
    const auto request = "https://kms.example.org/keymanagement/identity/v1/keyprov";
    auto keydoc = kms_keyprov_xml(authority.public_parameters, keys, request, now);
    auto recovered = parse_kms_keyprov(keydoc, authority.public_parameters, keys.uri, request, now);
    check(recovered.signing_pair == keys.signing_pair && recovered.receiver_secret == keys.receiver_secret,
          "Annex D keyset crypto validation and roundtrip");
    auto wrong_keys = keydoc;
    at = wrong_keys.find("<UserSigningKeySSK");
    at = wrong_keys.find('>', at) + 1;
    wrong_keys[at] = wrong_keys[at] == '0' ? '1' : '0';
    rejects([&] { parse_kms_keyprov(wrong_keys, authority.public_parameters, keys.uri, request, now); });
    auto duplicate = init;
    at = duplicate.find("<UserUri>");
    duplicate.insert(at, "<UserUri>sip:a@example.org</UserUri>");
    rejects([&] {
      parse_kms_init(duplicate, "sip:a@example.org", home_kms.period.kms_uri,
                     "https://kms.example.org/keymanagement/identity/v1/init", now);
    });
    auto dtd = init;
    at = dtd.find("?>") + 2;
    dtd.insert(at, "<!DOCTYPE KmsResponse [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>");
    rejects([&] {
      parse_kms_init(dtd, "sip:a@example.org", home_kms.period.kms_uri,
                     "https://kms.example.org/keymanagement/identity/v1/init", now);
    });
    auto unknown = group;
    at = unknown.find("</list-service>");
    unknown.insert(at, "<unknown xmlns=\"urn:example:extension\" must-understand=\"true\"/>");
    rejects([&] { parse_gktp_document(unknown, "sip:g@example.org"); });
    const auto xroot = "https://gms.example.org/xcap-root/";
    auto diff = gktp_xcap_diff(group, "sip:g@example.org", xroot);
    check(diff.find("urn:ietf:params:xml:ns:xcap-diff") != std::string::npos, "RFC5874 XCAP diff root");
    check(parse_gktp_document(parse_gktp_xcap_diff(diff, "sip:g@example.org", xroot), "sip:g@example.org") == mikey,
          "XCAP element snapshot recovery");
    rejects([&] { parse_gktp_xcap_diff(diff, "sip:g@example.org", "https://evil.example.org/"); });
    rejects([&] { parse_gktp_xcap_diff(diff, "sip:h@example.org", xroot); });
    validate_gktp_resource_list(gktp_resource_list("sip:g@example.org"), "sip:g@example.org");
    rejects([&] { validate_gktp_resource_list(gktp_resource_list("sip:h@example.org"), "sip:g@example.org"); });
    auto dupresource = gktp_resource_list("sip:g@example.org");
    at = dupresource.find("</list>");
    dupresource.insert(at, "<entry uri=\"other\"/>");
    rejects([&] { validate_gktp_resource_list(dupresource, "sip:g@example.org"); });
    {
      // TS 33.180 annexes D.2.5 and D.3.2: a KMS without External KMSs answers a certificate cache without
      // certificates, for the request it answers.
      const std::string url = "https://kms.example.org/keymanagement/identity/v1/certcache";
      const auto cache = kms_certcache_xml(home_kms, "sip:a@example.org", url, now);
      if (cache.find("<KmsCertCache") == std::string::npos || cache.find("KmsCertificate") != std::string::npos)
        throw std::runtime_error("empty certificate cache");
      // TS 33.180 annex D.4: a KMS Redirect Response; an empty list stands for ANY.
      auto krr = parse_krr(krr_xml(
          {"sip:mcptt@mcx.test", "sip:a@x", "https://kms.a", "sip:b@y", "https://kms.a", {}, {"https://kms.b"}}, now));
      if (krr.creator != "sip:mcptt@mcx.test" || krr.receiver != "sip:b@y" || krr.receiver_kms != "https://kms.a" ||
          !krr.initiator_list.empty() || krr.receiver_list != std::vector<std::string>{"https://kms.b"})
        throw std::runtime_error("KRR round trip");
      rejects([&] { parse_krr("<KmsRedirectResponse/>"); });
    }
    std::cout << "key document tests passed\n";
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
