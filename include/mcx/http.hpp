//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// HTTPS client and OpenID Connect user authentication of the IdM client: the authorization code grant, the refresh
// token grant and ID token validation.
//
// Specifications: TS 24.482 V19.1.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 6749, RFC 7636, RFC 3986.
#pragma once
#include <nlohmann/json.hpp>

#include <map>
#include <stdexcept>
#include <string>
#include <string_view>

namespace mcx {
//------------------------------------------------------------------------------
// TS 24.482 annex A.2.1.2: the response to an HTTP request: status code, body and header fields (by lower-case name).
struct HttpResponse {
  long status = 0;
  std::string body;
  std::map<std::string, std::string> headers;
  // The JSON body of a 2xx response; throws on any other status.
  nlohmann::json json() const;
};

//------------------------------------------------------------------------------
// TS 24.482 annex A.2.1.2: the HTTP client in the UE, over TLS, verifying the server against a configured trust anchor.
// The limits of one HTTP request: to connect, and in total (connection, TLS, request and answer).
struct HttpTimeouts {
  long connect_ms = 2000;
  long total_ms = 5000;
};

// The address map of an MCX Admin activation package ("address_map"): "host:port" as the package names a server ->
// "address:port" where this client reaches it (a phone or a dispatcher on another machine, through a host's published
// ports). The connection goes to the address; TLS still checks the certificate against the named host (SNI included).
using HttpAddressMap = std::map<std::string, std::string>;

// The trust anchors of an HTTP client: the configured CA only, or the system's CAs as well (/etc/ssl/certs), for an
// external IdMS (Keycloak, for example) whose certificate a public CA issued; its login page opens in the system
// browser, which trusts them too (TS 33.180 annex B.4.2).
enum class HttpTrust { configured, configured_and_system };

class HttpClient {
public:
  explicit HttpClient(std::string ca_file, HttpTimeouts timeouts = {}, HttpAddressMap address_map = {},
                      HttpTrust trust = HttpTrust::configured);
  // TS 24.482 annex A.2.1.2: sends one HTTP request over TLS, with optional basic authentication and header fields.
  HttpResponse request(std::string_view method, const std::string &url, const std::string &body = {},
                       const std::map<std::string, std::string> &headers = {}, const std::string &user = {},
                       const std::string &password = {}) const;

private:
  std::string ca_;
  HttpTimeouts timeouts_;
  HttpAddressMap address_map_;
  HttpTrust trust_;
};

//------------------------------------------------------------------------------
// MCX Admin activation link (https://...#pin=<base64url SHA-256 of the server certificate, DER>): a GET over TLS that
// trusts only a server presenting that certificate, checked in the TLS handshake before the request is sent; for a
// device that does not trust the system CA yet. The host name is not checked: the pin names the server.
HttpResponse http_get_pinned(const std::string &url, std::string_view pin, HttpTimeouts timeouts = {});

//------------------------------------------------------------------------------
// RFC 3986 section 2.1: percent-encodes every character except the unreserved ones (section 2.3).
std::string url_encode(std::string_view input);

//------------------------------------------------------------------------------
// Helper: 256 random bits, base64url encoded: the OIDC state, nonce and PKCE code verifier (RFC 7636 section 4.1).
std::string random_id();

//------------------------------------------------------------------------------
// Helper: an application/x-www-form-urlencoded body.
std::string form_encode(const std::map<std::string, std::string> &fields);

//------------------------------------------------------------------------------
// TS 33.180 table B.4.2.2-1: the scope of an authorization request whose configuration ("scope") names none.
inline constexpr const char *oidc_default_scope =
    "openid 3gpp:mc:ptt_service 3gpp:mc:ptt_key_management_service 3gpp:mc:data_key_management_service "
    "3gpp:mc:video_key_management_service";

//------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.2: the authorization request of the authorization code grant with PKCE (S256), for the
// user's browser: "url" (the authorization endpoint with the parameters of table B.4.2.2-1) and the "state",
// "nonce" and "code_verifier" the client keeps for the response. cfg holds the issuer, client_id, redirect_uri and
// optionally the scope.
nlohmann::json oidc_authorization_request(const HttpClient &http, const nlohmann::json &cfg);

//------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.4 and B.4.2.5: the token request for the authorization code the browser was redirected
// with; the result holds the tokens, the verified ID token's "claims", the "nonce" and, from an IdMS that issues one,
// the "refresh_token".
nlohmann::json oidc_exchange_code(const HttpClient &http, const nlohmann::json &cfg, const std::string &code,
                                  const std::string &code_verifier, const std::string &nonce);

//------------------------------------------------------------------------------
// TS 24.482 clause 6.2.1 and TS 33.180 annex B.4.2: the authorization code grant with the user's password; the result
// holds the tokens, the verified ID token's "claims", its "nonce" and, from an IdMS that issues one, the
// "refresh_token".
nlohmann::json oidc_login(const HttpClient &http, const nlohmann::json &cfg);

//------------------------------------------------------------------------------
// TS 33.180 annex B.5 (RFC 6749 section 6): the refresh token grant, new tokens without the password. IdMS refusing
// the refresh token itself (RFC 6749 section 5.2 error "invalid_grant": revoked, lapsed, account not active) throws
// oidc_refresh_refused, which ends the sign-in; any other failure (another error code, a server error, a transport
// failure) throws oidc_refresh_failed, after which the refresh token stays valid and the grant may be retried.
nlohmann::json oidc_refresh(const HttpClient &http, const nlohmann::json &cfg, const std::string &refresh_token,
                            const std::string &nonce);

//------------------------------------------------------------------------------
// TS 33.180 annex B.5: the refresh token grant refused by IdMS (RFC 6749 section 5.2 "invalid_grant").
struct oidc_refresh_refused : std::runtime_error {
  using std::runtime_error::runtime_error;
};

//------------------------------------------------------------------------------
// TS 33.180 annex B.5: the refresh token grant failed for a reason other than the refresh token (RFC 6749 section
// 5.2 errors other than "invalid_grant", HTTP errors, transport failures): the refresh token is kept and the grant
// may be retried.
struct oidc_refresh_failed : std::runtime_error {
  using std::runtime_error::runtime_error;
};

//------------------------------------------------------------------------------
// RFC 6749 section 5.2 and TS 33.180 annex B.5: whether a token endpoint response refuses the refresh token itself:
// HTTP 400 (or 401) with the JSON error code "invalid_grant".
bool oidc_refresh_refusal(const HttpResponse &response);

//------------------------------------------------------------------------------
// RFC 7515 section 4.1.4: a token signed with a key ("kid") the JWKS does not hold; IdMS may have a new key.
struct oidc_unknown_signing_key : std::runtime_error {
  using std::runtime_error::runtime_error;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 8.6.1: the IdMS JWKS, from the "jwks_uri" of the issuer's discovery document.
nlohmann::json oidc_jwks(const HttpClient &http, const std::string &issuer);

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.2: validates an access token against the IdMS JWKS, its issuer and audience (alone or among
// others), its times and the scope and client_id claims of table B.2.2.2-1, and returns its claims.
nlohmann::json verify_access_token(std::string_view token, const nlohmann::json &jwks, std::string_view issuer,
                                   std::string_view audience);

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.1: validates an ID token against the IdMS JWKS, its issuer, audience and nonce (which the ID
// token of a refresh may leave out), and returns its claims.
nlohmann::json verify_id_token(std::string_view token, const nlohmann::json &jwks, std::string_view issuer,
                               std::string_view audience, std::string_view nonce, bool refreshed = false);
} // namespace mcx
