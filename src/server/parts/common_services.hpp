// The internal interfaces of the openMCX common services that the MC servers read: a document of the GMS or CMS, and
// the IdMS token introspection. Shared by the MCPTT and MCVideo servers (McServer) and the MCData server
// (DataServer).
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 7662.
#pragma once

#include "mcx/http.hpp"
#include "mcx/runtime.hpp"

#include <optional>
#include <string>

namespace mcx {
//------------------------------------------------------------------------------
// Helper: GET of a document from the internal interface of the common service of the given role ("gms", "cms", ...)
// in the configuration's "common" section, authenticated as this server.
Json common_document(const HttpClient &http, const Json &common, const std::string &role, const std::string &path);

//------------------------------------------------------------------------------
// RFC 7662 section 2: the IdMS introspection of an access token (common.idms): its
// claims, "active" false for a token IdMS does not accept.
Json introspect_token(const HttpClient &http, const Json &common, const std::string &token);

//------------------------------------------------------------------------------
// TS 33.180 clause 5.1.2 with TS 24.379 clause 7.3.3 (TS 24.282 clause 7.3.3): the claims of the access
// token of a service authorisation, introspected at the IdMS, when the token is active, names the asserted public
// user identity and the client, and carries the MC service ID (`id_claim`); none otherwise.
std::optional<Json> introspect_claims(const HttpClient &http, const Json &common, const std::string &token,
                                      const std::string &asserted, const std::string &client_id, const char *id_claim);
} // namespace mcx
