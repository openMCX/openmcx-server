//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// What the MC servers read from the common services (common_services.hpp).
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 7519.

#include "parts/common_services.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: GET of a document from the internal interface of a common service.
Json common_document(const HttpClient &http, const Json &common, const std::string &role, const std::string &path) {
  return http
      .request("GET", common.at(role).get<std::string>() + path, {}, {}, common.at("client_id"), common.at("secret"))
      .json();
}

//------------------------------------------------------------------------------
// Helper: the issuer and audience of the configuration's "common" section.
AccessTokens::AccessTokens(const std::string &ca_file, const Json &common)
    : http_(ca_file, {}, {}, HttpTrust::configured_and_system), issuer_(common.value("issuer", common.value("idms", ""))),
      audience_(common.value("token_audience", common.value("client_id", ""))) {}

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.2: the signature, iss and aud where given, times, scope and client_id (verify_access_token),
// then the service's scope and MC service ID.
std::optional<Json> AccessTokens::verify(const std::string &token, const ServiceProfile &svc) {
  const auto now = std::chrono::steady_clock::now();
  if (issuer_.empty() || audience_.empty()) throw std::runtime_error("no IdMS configured (common)");
  if (jwks_.is_null()) {
    jwks_ = oidc_jwks(http_, issuer_);
    fetched_ = now;
  }
  Json claims;
  try {
    claims = verify_access_token(token, jwks_, issuer_, audience_);
  } catch (const oidc_unknown_signing_key &) {
    if (now - fetched_ < std::chrono::minutes(1)) return std::nullopt;
    jwks_ = oidc_jwks(http_, issuer_);
    fetched_ = now;
    try {
      claims = verify_access_token(token, jwks_, issuer_, audience_);
    } catch (const std::exception &) {
      return std::nullopt;
    }
  } catch (const std::exception &) {
    return std::nullopt;
  }
  // TS 33.180 clause 5.1.2: a token scoped for the service, with the user's MC service ID.
  const auto scope = " " + claims.at("scope").get<std::string>() + " ";
  const auto id = claims.find(svc.id_claim);
  if (scope.find(std::string(" ") + svc.scope + " ") == std::string::npos || id == claims.end() || !id->is_string() ||
      id->get_ref<const std::string &>().empty())
    return std::nullopt;
  return claims;
}

//------------------------------------------------------------------------------
// Helper: OpenMCX's IdMS names the user's MC ID.
bool openmcx_token(const Json &claims) { return claims.contains("mc_id"); }

//------------------------------------------------------------------------------
// TS 33.180 clause 5.1.2: the access token's claims bind the MC service ID; an OpenMCX token binds the client and the
// asserted identity as well.
std::optional<Json> service_claims(AccessTokens &tokens, const std::string &token, const ServiceProfile &svc,
                                   const std::string &asserted, const std::string &client_id) {
  auto claims = tokens.verify(token, svc);
  if (claims && openmcx_token(*claims) &&
      (claims->value("sip_uri", "") != asserted || claims->value("mc_client_id", "") != client_id ||
       claims->value("token_type", "") != "access"))
    return std::nullopt;
  return claims;
}

} // namespace mcx
