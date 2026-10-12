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

namespace mcx {
//------------------------------------------------------------------------------
// Stub: no connection.
HttpClient::HttpClient(std::string, HttpTimeouts, HttpAddressMap) {}

//------------------------------------------------------------------------------
// Stub: the text unchanged.
std::string url_encode(std::string_view text) { return std::string(text); }

//------------------------------------------------------------------------------
// Stub KMS: answers the TS 33.180 annex D.2.3 KMS Initialize and D.2.4 KMS KeyProvision
// requests (HTTP POST without body) for the identity of the Authorization header, or for the
// substituted identity when one is set.
HttpResponse HttpClient::request(std::string_view method, const std::string &url, const std::string &body,
                                 const std::map<std::string, std::string> &headers, const std::string &basic,
                                 const std::string &) const {
  if (method != "POST" || !body.empty() || !basic.empty()) throw std::runtime_error("invalid provisioning request");
  const auto identity = substituted_identity.empty() ? headers.at("Authorization").substr(7) : substituted_identity;
  auto xml = url.ends_with("/init") ? keying::kms_init_xml(authority.public_parameters, identity, url, now())
                                    : keying::kms_keyprov_xml(authority.public_parameters,
                                                              keying::issue(authority, identity, now()), url, now());
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
    bob.provision("sip:bob@example.org");
    auto [csk, wire] = alice.make_csk("sip:bob@example.org");
    auto received = bob.accept_csk("sip:alice@example.org", wire);
    check(csk.key == received.key, "CSK changed");
    reject([&] { bob.accept_csk("sip:alice@example.org", wire); });
    reject([&] { bob.accept_csk("sip:other@example.org", wire); });
    reject([&] { bob.accept_csk("sip:alice@example.org", wire + "\n"); });
    auto gms = mcx::keying::issue(authority, "https://gms.example.org", now());
    mcx::keying::KeyMessage key;
    key.key.fill(1);
    key.random.fill(2);
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
    next_epoch.random.fill(5);
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
    std::cout << "KeyClient provisioning, CSK, replay, base64 and group tests passed\n";
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
