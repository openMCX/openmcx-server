// The internal interfaces of the OpenMCX common services that the MC servers read (common_services.hpp).
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 7662.

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
// RFC 7662 section 2.1: the introspection request, a form-encoded POST of the token.
Json introspect_token(const HttpClient &http, const Json &common, const std::string &token) {
  return http
      .request("POST", common.at("idms").get<std::string>() + "/introspect", "token=" + url_encode(token),
               {{"Content-Type", "application/x-www-form-urlencoded"}}, common.at("client_id"), common.at("secret"))
      .json();
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.1.2: the access token's claims bind the client and the MC service ID to the asserted identity.
std::optional<Json> introspect_claims(const HttpClient &http, const Json &common, const std::string &token,
                                      const std::string &asserted, const std::string &client_id, const char *id_claim) {
  auto claims = introspect_token(http, common, token);
  if (!claims.value("active", false) || claims.value("sip_uri", "") != asserted ||
      claims.value("client_id", "") != client_id || claims.value(id_claim, std::string{}).empty())
    return std::nullopt;
  return claims;
}

} // namespace mcx
