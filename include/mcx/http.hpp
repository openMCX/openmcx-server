//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// HTTPS client and OpenID Connect user authentication of the IdM client: the authorization code grant, the refresh
// token grant and ID token validation.
//
// Specifications: TS 24.482 V19.1.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 6749, RFC 7636, RFC 3986.
#pragma once
#include <nlohmann/json.hpp>

#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// TS 24.482 annex A.2.1.2: the response to an HTTP request: status code, body and header fields (by lower-case name;
// the Set-Cookie fields of one response, RFC 6265 section 3, one per line).
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

// TS 33.180 clause 6.1.1 with TS 33.310 clauses 6.1.1 and 6.1a: crl_file, when not empty, is a PEM file of the CRLs
// (version 2, full, not signed with MD2, MD5 or SHA-1) that verify the revocation status of every certificate of the
// server's chain; it is read again for each request. A certificate without a valid CRL of its issuer in the file, or
// listed in one, fails the TLS handshake (TS 33.310 clauses 5.2.2.2 and 7.6).
class HttpClient {
public:
  explicit HttpClient(std::string ca_file, HttpTimeouts timeouts = {}, HttpAddressMap address_map = {},
                      HttpTrust trust = HttpTrust::configured, std::string crl_file = {});
  // TS 24.482 annex A.2.1.2: sends one HTTP request over TLS, with optional basic authentication and header fields.
  HttpResponse request(std::string_view method, const std::string &url, const std::string &body = {},
                       const std::map<std::string, std::string> &headers = {}, const std::string &user = {},
                       const std::string &password = {}) const;

private:
  std::string ca_;
  HttpTimeouts timeouts_;
  HttpAddressMap address_map_;
  HttpTrust trust_;
  std::string crl_file_;
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
// TS 24.484 clause 7.2.2.7 item 4: an IdMS endpoint of the IdM client ("authorization_endpoint", "token_endpoint" or
// "jwks_uri"): the configured <idms-auth-endpoint> (cfg "idms_auth_endpoint"), <idms-token-endpoint>
// ("idms_token_endpoint") or JWKS URI ("jwks_uri", OpenID Connect Core 1.0 section 10 "by other means"), used as given
// (an https URI); otherwise the one of the issuer's discovery document, which discovery returns (fetched only then).
std::string oidc_endpoint(const nlohmann::json &cfg, std::string_view name,
                          const std::function<nlohmann::json()> &discovery);

//------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.2: the authorization request of the authorization code grant with PKCE (S256), for the
// user's browser: "url" (the authorization endpoint with the parameters of table B.4.2.2-1) and the "state",
// "nonce" and "code_verifier" the client keeps for the response. cfg holds the issuer, client_id, redirect_uri and
// optionally the scope and the IdMS endpoints (oidc_endpoint).
nlohmann::json oidc_authorization_request(const HttpClient &http, const nlohmann::json &cfg);

//------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.4 and B.4.2.5: the token request for the authorization code the browser was redirected
// with; the result holds the tokens, the verified ID token's "claims", the "nonce" and, from an IdMS that issues one,
// the "refresh_token".
nlohmann::json oidc_exchange_code(const HttpClient &http, const nlohmann::json &cfg, const std::string &code,
                                  const std::string &code_verifier, const std::string &nonce);

//------------------------------------------------------------------------------
// HTML 4.01 section 17 (TS 37.579-1 table 5.3.2.3.2-5): the controls of the IdMS's user authentication form that are
// submitted: <input> elements of type text, email, password, hidden, checkbox or radio (the last two only when
// checked), with their names and values.
struct HtmlFormInput {
  std::string name, type, value;
};

// HTML 4.01 section 17.3: a form's action (as written, unresolved), its method (lower case) and its inputs.
struct HtmlForm {
  std::string action, method;
  std::vector<HtmlFormInput> inputs;
};

//------------------------------------------------------------------------------
// HTML 4.01 section 17: the one form of an HTML page, or nullopt when the page has none. Strict: a page with more
// than one form, a form with a control this client cannot fill (select, textarea, file and other input types) or an
// unterminated tag is refused (std::runtime_error).
std::optional<HtmlForm> parse_html_form(std::string_view html);

//------------------------------------------------------------------------------
// HTML 4.01 section 17.13.3 and TS 37.579-1 table 5.5.4.3-1 (condition USERAUTH): the fields the user authentication
// form submits: the hidden (and checked) inputs with their values, the user name in the form's one text or email
// input and the password in its one password input. A form without exactly one of each is refused.
std::map<std::string, std::string> html_form_fields(const HtmlForm &form, const std::string &user,
                                                    const std::string &password);

//------------------------------------------------------------------------------
// RFC 3986 section 5.2: the https target URI of a form action relative to the page's URI (an absolute https URI, a
// network-path, absolute-path, query or relative-path reference; the fragment dropped). Refused: another scheme and
// dot segments.
std::string resolve_https_reference(const std::string &base, const std::string &reference);

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
// TS 33.180 annex B.11.2 with OpenID Connect Core 1.0 section 10: the IdMS JWKS, from the "jwks_uri" of the issuer's
// discovery document.
nlohmann::json oidc_jwks(const HttpClient &http, const std::string &issuer);

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.2: validates an access token against the IdMS JWKS, its issuer and audience (alone or among
// others) where the token has them (RFC 7519 sections 4.1.1 and 4.1.3), its times and the scope and client_id claims
// of table B.2.2.2-1, and returns its claims.
nlohmann::json verify_access_token(std::string_view token, const nlohmann::json &jwks, std::string_view issuer,
                                   std::string_view audience);

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.1: validates an ID token against the IdMS JWKS, its issuer, audience and nonce (which the ID
// token of a refresh may leave out), and returns its claims.
nlohmann::json verify_id_token(std::string_view token, const nlohmann::json &jwks, std::string_view issuer,
                               std::string_view audience, std::string_view nonce, bool refreshed = false);
} // namespace mcx
