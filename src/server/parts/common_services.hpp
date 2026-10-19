//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// What the MC servers read from the common services: a document of the GMS or CMS (their OpenMCX internal
// interface), and the check of access tokens against IdMS's keys. Shared by the MCPTT and MCVideo servers (McServer)
// and the MCData server (DataServer).
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 7519.
#pragma once

#include "mcx/http.hpp"
#include "mcx/runtime.hpp"
#include "mcx/service.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace mcx {
//------------------------------------------------------------------------------
// Helper: GET of a document from the internal interface of the common service of the given role ("gms", "cms", ...)
// in the configuration's "common" section, authenticated as this server.
Json common_document(const HttpClient &http, const Json &common, const std::string &role, const std::string &path);

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.2: the MC server's check of access tokens (RFC 7519) against IdMS's JWKS (oidc_jwks), fetched
// at the first token and again for a token of a key it does not hold (IdMS has a new key), at most once a minute.
// The configuration's "common" section names the issuer ("issuer", by default "idms") and the MC servers' audience
// ("token_audience", by default this server's "client_id"). The JWKS comes over HTTPS trusting the configured CA and
// the system's (HttpTrust::configured_and_system), as the clients reach IdMS.
class AccessTokens {
public:
  AccessTokens(const std::string &ca_file, const Json &common);

  // The claims of a valid access token with the scope and the MC service ID claim (TS 33.180 tables B.2.2.2-1 and
  // B.2.2.3-1), or none. Throws when IdMS's JWKS cannot be fetched.
  std::optional<Json> verify(const std::string &token, const ServiceProfile &svc);

private:
  HttpClient http_;
  std::string issuer_, audience_;
  Json jwks_;
  std::chrono::steady_clock::time_point fetched_{};
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.1.2 with TS 24.379 clause 7.3.3 (TS 24.282 clause 7.3.3): the claims of the access token of a
// service authorisation (AccessTokens::verify), or none. A token of OpenMCX's IdMS (it has "mc_id") binds the
// asserted public user identity ("sip_uri") and the client ("mc_client_id") as well.
std::optional<Json> service_claims(AccessTokens &tokens, const std::string &token, const ServiceProfile &svc,
                                   const std::string &asserted, const std::string &client_id);

//------------------------------------------------------------------------------
// Helper: an access token of OpenMCX's IdMS, with its binding claims (service_claims).
bool openmcx_token(const Json &claims);
} // namespace mcx
