//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// mcx-keytool: key operations on a JSON request from stdin for the KMS and the GMS: KMS authority and user keys, KMS
// responses and GKTP documents.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19),
// TS 24.481 V19.3.0 (Rel-19), RFC 6509.
#include "mcx/key_documents.hpp"
#include "mcx/keying_json.hpp"
#include "mcx/security.hpp"

#include <algorithm>
#include <array>
#include <iostream>
#include <iterator>
#include <map>
#include <string>
using nlohmann::json;
using namespace mcx::keying;

namespace {

//------------------------------------------------------------------------------
// TS 33.180 annex D.2.3 and annex D.2.4: the KMS response to a KMS Initialize ("kms-init") or KMS KeyProvision
// ("kms-keyprov") request.
json kms_response(const std::string &op, const json &request) {
  json result;
  const auto authority = request.at("authority").get<Authority>();
  const auto user = request.at("user_uri").get<std::string>();
  const auto uri = request.at("request_uri").get<std::string>();
  const auto now = request.at("ntp_seconds").get<std::uint64_t>();
  result["xml"] = op == "kms-init"
                      ? kms_init_xml(authority.public_parameters, user, uri, now)
                      : kms_keyprov_xml(authority.public_parameters, issue(authority, user, now), uri, now);
  return result;
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.2.5: the KMS response to a KMS CertCache request ("kms-certcache"): this system has no External
// KMS, so the cache has no certificates.
json kms_certcache(const json &request) {
  json result;
  const auto authority = request.at("authority").get<Authority>();
  result["xml"] = kms_certcache_xml(authority.public_parameters, request.at("user_uri").get<std::string>(),
                                    request.at("request_uri").get<std::string>(),
                                    request.at("ntp_seconds").get<std::uint64_t>());
  return result;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.7.2: writes the GKTP document ("gktp") carrying a GMK to a recipient, MIKEY-SAKKE encrypted to
// the recipient under the Home KMS.
json gktp_create(const json &request, const PublicParameters &pub, const IdentityKeys &identity,
                 const KeyParameterWireProfile &profile, std::uint64_t now) {
  json result;
  KeyMessage message;
  const auto key = unhex(request.at("key_hex").get<std::string>());
  const auto random = unhex(request.at("random_hex").get<std::string>());
  if (key.size() != 16 || random.size() != 16) throw std::invalid_argument("invalid group key material");
  std::copy(key.begin(), key.end(), message.key.begin());
  std::copy(random.begin(), random.end(), message.random.begin());
  const auto recipient = request.at("recipient").get<std::string>();
  const auto group = request.at("group_id").get<std::string>();
  const auto id = request.at("csb_id").get<std::uint32_t>();
  message.csb_id = mcx::derive_guk_id(key, id, recipient);
  message.ntp_seconds = now;
  message.properties = KeyProperties{0, 1, request.at("valid_from"), request.at("valid_to"), "", {group}};
  const auto mikey = create_mikey(pub, pub, identity, recipient, message, &profile);
  result["document"] = gktp_document_xml(group, std::to_string(id), mikey, now);
  return result;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.7.2: the GMS's own KMS key material from the KMS responses, then a GKTP created ("gktp").
json gktp(const json &request) {
  const auto now = request.at("ntp_seconds").get<std::uint64_t>();
  const auto gms = request.at("gms_uri").get<std::string>();
  const auto pub =
      parse_kms_init(request.at("kms_init_xml").get<std::string>(), gms, request.at("kms_uri").get<std::string>(),
                     request.at("init_request_uri").get<std::string>(), now);
  const auto identity = parse_kms_keyprov(request.at("kms_keyprov_xml").get<std::string>(), pub, gms,
                                          request.at("keyprov_request_uri").get<std::string>(), now);
  const auto &profile_json = request.at("key_parameter_profile");
  const KeyParameterWireProfile profile{profile_json.at("message_type"), profile_json.at("algorithm"),
                                        profile_json.at("key_parameters_iei"),
                                        profile_json.at("encrypted_payload_iei")};
  return gktp_create(request, pub, identity, profile, now);
}

//------------------------------------------------------------------------------
// Helper: reads the JSON request from stdin, at most 1 MiB.
std::string read_input() {
  std::string input;
  char character;
  while (std::cin.get(character)) {
    if (input.size() >= 1048576) throw std::invalid_argument("input limit");
    input += character;
  }
  return input;
}

} // namespace

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.3 and 5.7: runs one key operation ("authority-generate", "kms-init", "kms-keyprov",
// "kms-certcache", "gktp" or "issue") and writes its JSON result to stdout.
int main() {
  std::string op;
  try {
    const std::string input = read_input();
    const auto request = json::parse(input);
    op = request.at("op").get<std::string>();
    json result;

    if (op == "authority-generate") {
      result = create_authority(
          {request.at("kms_uri"), request.value("key_period", 2592000u), request.value("key_offset", 0u)});
    } else if (op == "kms-init" || op == "kms-keyprov") {
      result = kms_response(op, request);
    } else if (op == "kms-certcache") {
      result = kms_certcache(request);
    } else if (op == "gktp") {
      result = gktp(request);
    } else if (op == "issue") {
      result = issue(request.at("authority").get<Authority>(), request.at("user_uri").get<std::string>(),
                     request.at("ntp_seconds").get<std::uint64_t>());
    } else
      throw std::invalid_argument("unknown operation");

    std::cout << result.dump() << '\n';
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "key operation failed\n";
    return 1;
  }
}
