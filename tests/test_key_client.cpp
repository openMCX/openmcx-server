//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The key management client: KMS provisioning of user key material, CSK creation and acceptance, GMK reception
// from GKTP documents.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19).

#include "mcx/key_client.hpp"
#include "mcx/key_documents.hpp"
#include "mcx/security.hpp"

#include <openssl/evp.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

//------------------------------------------------------------------------------
// The current time in NTP seconds (since 1900).
static uint64_t now() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() +
         2208988800ULL;
}

//------------------------------------------------------------------------------
// The home KMS of the test users.
static auto authority = mcx::keying::create_authority({"https://kms.example.org", 2592000, 0});
// Replace only network I/O. Every XML document, identity, signature,
// encapsulation and protected-key payload below is generated and parsed by
// production code.
static std::string substituted_identity;
// The client credentials grants the stub IdMS answered.
static int token_grants = 0;
// The token_type of the stub IdMS's client credentials token response.
static std::string token_type = "Bearer";
// The Request-URI of the last KMS KeyProvision request (TS 33.180 annex D.2.4), and the identity the stub KMS
// provisions in a KeyProvision response when one is set (another of the user's MC service IDs).
static std::string last_keyprov_url, keyprov_identity;

namespace mcx {
//------------------------------------------------------------------------------
// Stub: no connection.
HttpClient::HttpClient(std::string, HttpTimeouts, HttpAddressMap, HttpTrust, std::string) {}

//------------------------------------------------------------------------------
// Stub: the text unchanged.
std::string url_encode(std::string_view text) { return std::string(text); }

//------------------------------------------------------------------------------
// Stub IdMS (https://idms.example.org: its discovery document and the RFC 6749 section 4.4 client credentials grant of
// the client "mcptt-key", whose token is the identity it names) and stub KMS: answers the TS 33.180 annex D.2.3 KMS
// Initialize and D.2.4 KMS KeyProvision requests (HTTP POST without body or basic authentication) for the identity of
// the Authorization header, or for the substituted identity when one is set.
HttpResponse HttpClient::request(std::string_view method, const std::string &url, const std::string &body,
                                 const std::map<std::string, std::string> &headers, const std::string &basic,
                                 const std::string &password) const {
  if (url == "https://idms.example.org/.well-known/openid-configuration" && method == "GET")
    return {200, R"({"issuer": "https://idms.example.org", "token_endpoint": "https://idms.example.org/token"})", {}};
  if (url == "https://idms.example.org/token" && method == "POST") {
    if (basic != "mcptt-key" || password != "mcptt-secret" ||
        body != "grant_type=client_credentials&scope=3gpp:mc:ptt_key_management_service")
      return {401, R"({"error": "invalid_client"})", {}};
    ++token_grants;
    return {200,
            nlohmann::json{{"access_token", "sip:mcptt@example.org"}, {"token_type", token_type}, {"expires_in", 300}}
                .dump(),
            {}};
  }
  if (method != "POST" || !body.empty() || !basic.empty()) throw std::runtime_error("invalid provisioning request");
  const auto identity = substituted_identity.empty() ? headers.at("Authorization").substr(7) : substituted_identity;
  if (!url.ends_with("/init")) last_keyprov_url = url;
  const auto provisioned = keyprov_identity.empty() ? identity : keyprov_identity;
  auto xml = url.ends_with("/init") ? keying::kms_init_xml(authority.public_parameters, identity, url, now())
                                    : keying::kms_keyprov_xml(authority.public_parameters,
                                                              keying::issue(authority, provisioned, now()), url, now());
  return {200, xml, {{"content-type", "application/xml"}}};
}
} // namespace mcx

//------------------------------------------------------------------------------
// Throws the message when the condition does not hold.
static void check(bool good, const char *message) {
  if (!good) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Fails unless the action throws.
template <class Action> static void reject(Action action) {
  try {
    action();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error("accepted prohibited operation");
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.1: only an https KMS URI; clause 9.2.1.3: no CSK before provisioning, key material
// only for the own identity, a CSK accepted once from its sender; clause 5.7.2: a GMK from a GKTP document (TS
// 24.481 clause 7.7) only for its group, while active and not revoked, without rollback to an older or unknown
// GMK; annex E.6.10: an expired CSK refused.
int main() {
  try {
    const nlohmann::json config = {
        {"kms_uri", "https://kms.example.org"},
        {"key_parameter_profile",
         {{"message_type", 10}, {"algorithm", 1}, {"key_parameters_iei", 121}, {"encrypted_payload_iei", 120}}}};
    mcx::HttpClient http("unused");
    mcx::KeyClient alice(http, config, "sip:alice@example.org"), bob(http, config, "sip:bob@example.org");
    reject([&] {
      auto insecure = config;
      insecure["kms_uri"] = "http://kms.example.org";
      mcx::KeyClient denied(http, insecure, "sip:alice@example.org");
    });
    reject([&] {
      auto invalid = config;
      invalid["key_parameter_profile"]["algorithm"] = 2;
      mcx::KeyClient denied(http, invalid, "sip:alice@example.org");
    });
    reject([&] { alice.make_csk("sip:bob@example.org"); });
    substituted_identity = "sip:other@example.org";
    reject([&] { alice.provision("sip:alice@example.org"); });
    substituted_identity.clear();
    alice.provision("sip:alice@example.org");
    check(last_keyprov_url == "https://kms.example.org/keymanagement/identity/v1/keyprov/sip:alice@example.org",
          "KeyProvision names the identity by default");
    bob.provision("sip:bob@example.org");
    // TS 33.180 annex D.2.4: the plain "keyprov" form for the token's identity, the subdirectory for another of the
    // user's MC service IDs; the option must be a boolean.
    {
      auto plain = config;
      plain["kms_keyprov_identity_path"] = false;
      mcx::KeyClient own(http, plain, "sip:alice@example.org");
      own.provision("sip:alice@example.org");
      check(last_keyprov_url == "https://kms.example.org/keymanagement/identity/v1/keyprov",
            "plain KeyProvision Request-URI");
      keyprov_identity = "sip:alice-data@example.org";
      mcx::KeyClient data(http, plain, "sip:alice-data@example.org", "sip:alice@example.org");
      data.provision("sip:alice@example.org");
      keyprov_identity.clear();
      check(last_keyprov_url == "https://kms.example.org/keymanagement/identity/v1/keyprov/sip:alice-data@example.org",
            "another MC service ID named in the subdirectory");
      plain["kms_keyprov_identity_path"] = "no";
      reject([&] { mcx::KeyClient denied(http, plain, "sip:alice@example.org"); });
    }
    // TS 33.180 clauses 5.3.2 and 5.3.3: an MC server's key management client with its own access token from the
    // client credentials grant; a wrong secret gets none; a server client takes no user's token.
    mcx::KeyClient server(http, config, "sip:mcptt@example.org");
    reject([&] {
      server.provision_client("https://idms.example.org", "mcptt-key", "wrong", "3gpp:mc:ptt_key_management_service");
    });
    reject([&] { server.provision_client("http://idms.example.org", "mcptt-key", "mcptt-secret", "scope"); });
    // RFC 6749 section 7.1: a token of a type other than "bearer" is not used; the type is case-insensitive (5.1).
    token_type = "MAC";
    reject([&] {
      server.provision_client("https://idms.example.org/", "mcptt-key", "mcptt-secret",
                              "3gpp:mc:ptt_key_management_service");
    });
    token_type = "bearer";
    token_grants = 0;
    server.provision_client("https://idms.example.org/", "mcptt-key", "mcptt-secret",
                            "3gpp:mc:ptt_key_management_service");
    check(token_grants == 1 && server.knows_kms("https://kms.example.org"), "server provisioned with its own token");
    reject([&] { server.provision("sip:mcptt@example.org"); });
    server.make_csk("sip:bob@example.org");
    check(token_grants == 1, "token reused while valid");
    auto [csk, wire] = alice.make_csk("sip:bob@example.org");
    auto received = bob.accept_csk("sip:alice@example.org", wire);
    check(csk.key == received.key, "CSK changed");
    reject([&] { bob.accept_csk("sip:alice@example.org", wire); });
    reject([&] { bob.accept_csk("sip:other@example.org", wire); });
    reject([&] { bob.accept_csk("sip:alice@example.org", wire + "\n"); });
    auto gms = mcx::keying::issue(authority, "https://gms.example.org", now());
    mcx::keying::KeyMessage key;
    key.key.fill(1);
    key.random.assign(16, 2);
    key.csb_id = mcx::derive_guk_id(key.key, 123, "sip:bob@example.org");
    key.ntp_seconds = now();
    key.properties = mcx::keying::KeyProperties{
        0, 1, now() - 2208988800ULL - 10, now() - 2208988800ULL + 60, "test", {"sip:group@example.org"}};
    const mcx::keying::KeyParameterWireProfile profile{10, 1, 121, 120};
    auto data = mcx::keying::create_mikey(authority.public_parameters, gms, "sip:bob@example.org", key, &profile);
    auto xml = mcx::keying::gktp_document_xml("sip:group@example.org", "123", data, now());
    auto group = bob.open_group(gms.uri, "sip:group@example.org", xml);
    check(group.csb_id == 123 && group.key == key.key, "GMK conversion");
    check(bob.open_group(gms.uri, "sip:group@example.org", xml).key == key.key, "idempotent GKTP");
    reject([&] { bob.open_group(gms.uri, "sip:other@example.org", xml); });
    // The group ID in outer XML cannot override the encrypted group
    // authorization.
    auto wrong_group_xml = mcx::keying::gktp_document_xml("sip:other@example.org", "123", data, now());
    reject([&] { bob.open_group(gms.uri, "sip:other@example.org", wrong_group_xml); });
    auto expired = key;
    expired.properties->activation_unix_seconds = now() - 2208988800ULL - 120;
    expired.properties->expiry_unix_seconds = now() - 2208988800ULL - 1;
    auto expired_data =
        mcx::keying::create_mikey(authority.public_parameters, gms, "sip:bob@example.org", expired, &profile);
    auto expired_xml = mcx::keying::gktp_document_xml("sip:group@example.org", "123", expired_data, now());
    reject([&] { bob.open_group(gms.uri, "sip:group@example.org", expired_xml); });
    auto revoked = key;
    revoked.properties->status = 0;
    auto revoked_data =
        mcx::keying::create_mikey(authority.public_parameters, gms, "sip:bob@example.org", revoked, &profile);
    auto revoked_xml = mcx::keying::gktp_document_xml("sip:group@example.org", "123", revoked_data, now());
    reject([&] { bob.open_group(gms.uri, "sip:group@example.org", revoked_xml); });
    auto changed = key;
    changed.key.fill(3);
    changed.csb_id = mcx::derive_guk_id(changed.key, 123, "sip:bob@example.org");
    auto changed_data =
        mcx::keying::create_mikey(authority.public_parameters, gms, "sip:bob@example.org", changed, &profile);
    auto changed_xml = mcx::keying::gktp_document_xml("sip:group@example.org", "123", changed_data, now());
    reject([&] { bob.open_group(gms.uri, "sip:group@example.org", changed_xml); });
    auto next_epoch = key;
    next_epoch.key.fill(4);
    next_epoch.random.assign(16, 5);
    next_epoch.csb_id = mcx::derive_guk_id(next_epoch.key, 124, "sip:bob@example.org");
    next_epoch.properties->activation_unix_seconds = key.properties->activation_unix_seconds + 5;
    auto next_data =
        mcx::keying::create_mikey(authority.public_parameters, gms, "sip:bob@example.org", next_epoch, &profile);
    auto next_xml = mcx::keying::gktp_document_xml("sip:group@example.org", "124", next_data, now());
    check(bob.open_group(gms.uri, "sip:group@example.org", next_xml).csb_id == 124, "new epoch not selected");
    check(bob.open_group(gms.uri, "sip:group@example.org", next_xml).csb_id == 124,
          "current epoch duplicate not idempotent");
    reject([&] { bob.open_group(gms.uri, "sip:group@example.org", xml); });
    auto unknown_older = key;
    unknown_older.key.fill(6);
    unknown_older.csb_id = mcx::derive_guk_id(unknown_older.key, 125, "sip:bob@example.org");
    auto older_data =
        mcx::keying::create_mikey(authority.public_parameters, gms, "sip:bob@example.org", unknown_older, &profile);
    auto older_xml = mcx::keying::gktp_document_xml("sip:group@example.org", "125", older_data, now());
    reject([&] { bob.open_group(gms.uri, "sip:group@example.org", older_xml); });
    check(bob.open_group(gms.uri, "sip:group@example.org", next_xml).csb_id == 124,
          "rejected rollback changed current epoch");
    // TS 33.180 annex E.6.4, TS 24.481 clause 7.7.8: the next GMK sent ahead of its Activation time is kept, not
    // refused (ProtectedCall uses it from that time).
    auto ahead = key;
    ahead.key.fill(7);
    ahead.random.assign(16, 8);
    ahead.csb_id = mcx::derive_guk_id(ahead.key, 126, "sip:bob@example.org");
    ahead.properties->activation_unix_seconds = now() - 2208988800ULL + 30;
    auto ahead_data =
        mcx::keying::create_mikey(authority.public_parameters, gms, "sip:bob@example.org", ahead, &profile);
    auto ahead_xml = mcx::keying::gktp_document_xml("sip:group@example.org", "126", ahead_data, now() + 30);
    check(bob.open_group(gms.uri, "sip:group@example.org", ahead_xml).csb_id == 126, "GMK ahead of its activation");
    // A current signature cannot make expired CSK properties usable.
    auto alice_identity = mcx::keying::issue(authority, "sip:alice@example.org", now());
    auto expired_csk = csk;
    expired_csk.csb_id ^= 1;
    expired_csk.properties->expiry_unix_seconds = now() - 2208988800ULL - 1;
    auto expired_csk_data = mcx::keying::create_mikey(authority.public_parameters, alice_identity,
                                                      "sip:bob@example.org", expired_csk, &profile);
    std::string expired_csk_b64(4 * ((expired_csk_data.size() + 2) / 3) + 1, '\0');
    expired_csk_b64.resize(EVP_EncodeBlock(reinterpret_cast<unsigned char *>(expired_csk_b64.data()),
                                           expired_csk_data.data(), expired_csk_data.size()));
    reject([&] { bob.accept_csk("sip:alice@example.org", expired_csk_b64); });
    const auto base64 = [](const mcx::keying::Bytes &data) {
      std::string text(4 * ((data.size() + 2) / 3) + 1, '\0');
      text.resize(EVP_EncodeBlock(reinterpret_cast<unsigned char *>(text.data()), data.data(), data.size()));
      return text;
    };
    // TS 33.180 annex E.6.10: an Expiry Time of 0 "shall imply the key shall not expire": the CSK is accepted, once.
    auto lasting_csk = csk;
    lasting_csk.csb_id ^= 2;
    lasting_csk.properties->expiry_unix_seconds = 0;
    const auto lasting = base64(mcx::keying::create_mikey(authority.public_parameters, alice_identity,
                                                          "sip:bob@example.org", lasting_csk, &profile));
    check(bob.accept_csk("sip:alice@example.org", lasting).properties->expiry_unix_seconds == 0, "CSK without expiry");
    reject([&] { bob.accept_csk("sip:alice@example.org", lasting); });
    // TS 33.180 annex E.6.10: a CSK's Expiry Time bounds its use; one after the end of the identity key period is
    // accepted (no clause refuses it).
    auto beyond_csk = csk;
    beyond_csk.csb_id ^= 3;
    beyond_csk.properties->expiry_unix_seconds = now() - 2208988800ULL + 10ULL * 365 * 86400;
    const auto beyond = base64(mcx::keying::create_mikey(authority.public_parameters, alice_identity,
                                                         "sip:bob@example.org", beyond_csk, &profile));
    check(bob.accept_csk("sip:alice@example.org", beyond).key == beyond_csk.key, "CSK beyond the key period");
    // RFC 3830 section 6.11: a RAND shorter than 16 octets is accepted and reported to the warning handler.
    std::vector<std::string> warnings;
    bob.set_warning_handler([&](std::string_view text) { warnings.emplace_back(text); });
    auto short_csk = csk;
    short_csk.csb_id ^= 4;
    // OpenMCX writes 16 octets: the I_MESSAGE is cut to a 15-octet RAND (RAND len at offset 21) and signed again.
    auto short_body = mcx::keying::create_mikey(authority.public_parameters, alice_identity, "sip:bob@example.org",
                                                short_csk, &profile);
    short_body.resize(short_body.size() - 129);
    short_body[21] = 15;
    short_body.erase(short_body.begin() + 22);
    const auto short_signature =
        mcx::keying::sign(authority.public_parameters, alice_identity, short_csk.ntp_seconds, short_body);
    short_body.insert(short_body.end(), short_signature.begin(), short_signature.end());
    const auto short_rand = base64(short_body);
    check(bob.accept_csk("sip:alice@example.org", short_rand).random.size() == 15, "15-octet RAND refused");
    check(warnings.size() == 1 && warnings[0].find("15 octets") != std::string::npos, "short RAND not reported");
    auto full_csk = csk;
    full_csk.csb_id ^= 5;
    const auto full_rand = base64(mcx::keying::create_mikey(authority.public_parameters, alice_identity,
                                                            "sip:bob@example.org", full_csk, &profile));
    check(bob.accept_csk("sip:alice@example.org", full_rand).random.size() == 16 && warnings.size() == 1,
          "16-octet RAND reported");
    // RFC 3830 section 5.4: the clock skew "set by the local policy": security.mikey_clock_skew_s; 300 s without it.
    reject([&] {
      auto invalid = config;
      invalid["mikey_clock_skew_s"] = -1;
      mcx::KeyClient denied(http, invalid, "sip:carol@example.org");
    });
    auto narrow = config;
    narrow["mikey_clock_skew_s"] = 60;
    mcx::KeyClient carol(http, narrow, "sip:carol@example.org");
    carol.provision("sip:carol@example.org");
    auto older_csk = csk;
    older_csk.csb_id ^= 6;
    older_csk.ntp_seconds = now() - 100;
    const auto older_to_carol = base64(mcx::keying::create_mikey(authority.public_parameters, alice_identity,
                                                                 "sip:carol@example.org", older_csk, &profile));
    reject([&] { carol.accept_csk("sip:alice@example.org", older_to_carol); });
    const auto older_to_bob = base64(mcx::keying::create_mikey(authority.public_parameters, alice_identity,
                                                               "sip:bob@example.org", older_csk, &profile));
    check(bob.accept_csk("sip:alice@example.org", older_to_bob).key == older_csk.key, "default skew of 300 s");
    // TS 33.180 annex E.1.2: a PCK I_MESSAGE may carry key parameters (annex E.6): a PCK's are accepted, a revoked
    // PCK is not.
    for (const std::uint8_t status : {1, 0}) {
      mcx::keying::KeyMessage pck;
      pck.key.fill(9);
      pck.csb_id = 0x10000100U | status;
      pck.ntp_seconds = now();
      auto body = mcx::keying::create_mikey(authority.public_parameters, alice_identity, "sip:bob@example.org", pck);
      body.resize(body.size() - 129);
      // TS 33.180 table E.6.1-1: Key Type PCK, Status, Activation and Expiry Time 0, no Text.
      mcx::keying::Bytes parameters{0x79, 0, 17, 1, 0, 0, 0, status};
      parameters.resize(3 + 17);
      const auto sealed = mcx::keying::seal_payload({10, now() - 2208988800ULL, 0, 0, pck.csb_id, parameters}, pck.key,
                                                    profile);
      mcx::keying::Bytes extension{4, 7, static_cast<std::uint8_t>(sealed.size() >> 8),
                                   static_cast<std::uint8_t>(sealed.size())};
      extension.insert(extension.end(), sealed.begin(), sealed.end());
      body[body.size() - 2 - 5 - 273] = 21;
      body.insert(body.end() - 2, extension.begin(), extension.end());
      const auto signature = mcx::keying::sign(authority.public_parameters, alice_identity, pck.ntp_seconds, body);
      body.insert(body.end(), signature.begin(), signature.end());
      if (status) {
        const auto [opened, sender] = bob.accept_pck("sip:alice@example.org", base64(body));
        check(sender == "sip:alice@example.org" && opened.key == pck.key && opened.properties &&
                  opened.properties->type == 1,
              "PCK with key parameters");
      } else
        reject([&] { bob.accept_pck("sip:alice@example.org", base64(body)); });
    }
    std::cout << "KeyClient provisioning, CSK, replay, base64 and group tests passed\n";
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
