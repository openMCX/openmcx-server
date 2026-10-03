// HTTPS client and OpenID Connect user authentication of the IdM client: the authorization code grant with PKCE,
// the refresh token grant and ID token validation of the MCX Connect profile.
//
// Specifications: TS 24.482 V19.1.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 6749, RFC 7636, OpenID Connect Core 1.0,
// RFC 7515, RFC 7517, RFC 7518, RFC 7519, RFC 4648, RFC 3986.
#include "mcx/http.hpp"

#include <curl/curl.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <stdexcept>

namespace mcx {
namespace {
using json = nlohmann::json;

// Helper: the largest base64url text decoded (JWT parts, JWK numbers), in characters; it and its decoded size fit
// the int lengths of the OpenSSL calls.
constexpr std::size_t max_base64url = 65536;

// Helper: the largest ID token accepted, in characters.
constexpr std::size_t max_id_token = 16384;

// OpenID Connect Core 1.0 section 3.1.3.7 item 10 (the range is the client's choice): how far ahead of the local clock
// an ID token's iat may lie, in seconds.
constexpr long long id_token_clock_skew_s = 30;

//------------------------------------------------------------------------------
// Helper: the ASCII lower-case form of a header name.
std::string lower(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(),
                 [](unsigned char character) { return std::tolower(character); });
  return text;
}

//------------------------------------------------------------------------------
// Helper: the libcurl write callback; collects the response body up to 1 MiB.
size_t receive(char *data, size_t size, size_t count, void *ctx) {
  auto &body = *static_cast<std::string *>(ctx);
  size_t length = size * count;
  if (length > 1048576 - body.size()) return 0;
  try {
    body.append(data, length);
  } catch (...) {
    return 0;
  }
  return length;
}

//------------------------------------------------------------------------------
// Helper: the libcurl header callback; stores each header field under its lower-case name.
size_t header(char *data, size_t size, size_t count, void *ctx) {
  size_t length = size * count;
  try {
    std::string line(data, length);
    auto colon = line.find(':');
    if (colon != line.npos) {
      auto value = line.substr(colon + 1);
      auto start = value.find_first_not_of(" \t");
      auto end = value.find_last_not_of("\r\n \t");
      if (start != value.npos)
        static_cast<HttpResponse *>(ctx)->headers[lower(line.substr(0, colon))] = value.substr(start, end - start + 1);
    }
  } catch (...) {
    return 0;
  }
  return length;
}

//------------------------------------------------------------------------------
// RFC 4648 section 5: base64url encoding without padding (JWT, PKCE code challenge, random values).
std::string b64(std::string_view raw) {
  if (raw.size() > max_base64url) throw std::runtime_error("base64url input too long");
  std::string result(4 * ((raw.size() + 2) / 3), '\0');
  EVP_EncodeBlock(reinterpret_cast<unsigned char *>(result.data()), reinterpret_cast<const unsigned char *>(raw.data()),
                  static_cast<int>(raw.size()));
  while (!result.empty() && result.back() == '=') result.pop_back();
  std::replace(result.begin(), result.end(), '+', '-');
  std::replace(result.begin(), result.end(), '/', '_');
  return result;
}

//------------------------------------------------------------------------------
// RFC 4648 section 5: base64url decoding of unpadded input (at most 64 KiB).
std::string unb64(std::string_view raw) {
  if (raw.empty() || raw.size() > max_base64url || raw.size() % 4 == 1) throw std::runtime_error("invalid base64url");
  std::string text(raw);
  for (char &character : text) {
    if (character == '-')
      character = '+';
    else if (character == '_')
      character = '/';
    else if (!std::isalnum(static_cast<unsigned char>(character)))
      throw std::runtime_error("invalid base64url");
  }
  const auto padding = static_cast<int>((4 - text.size() % 4) % 4);
  text.append(static_cast<std::size_t>(padding), '=');
  std::string result(text.size() / 4 * 3, '\0');
  // At most max_base64url plus padding characters: the length fits an int.
  const int decoded =
      EVP_DecodeBlock(reinterpret_cast<unsigned char *>(result.data()),
                      reinterpret_cast<const unsigned char *>(text.data()), static_cast<int>(text.size()));
  if (decoded < padding) throw std::runtime_error("invalid base64url");
  result.resize(static_cast<std::size_t>(decoded - padding));
  return result;
}

//------------------------------------------------------------------------------
// Helper: an "application/x-www-form-urlencoded" body or query of name=value pairs.
std::string form(const std::map<std::string, std::string> &fields) {
  std::string out;
  for (auto &[name, value] : fields) {
    if (!out.empty()) out += '&';
    out += url_encode(name) + '=' + url_encode(value);
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: the URL-decoded value of a query parameter of a URI, or empty if absent.
std::string query_value(const std::string &uri, const std::string &key) {
  auto question = uri.find('?');
  if (question == uri.npos) return {};
  std::string query = uri.substr(question + 1);
  size_t start = 0;
  while (start < query.size()) {
    auto end = query.find('&', start);
    auto item = query.substr(start, end - start);
    if (item.starts_with(key + '=')) {
      int length = 0;
      char *result = curl_easy_unescape(nullptr, item.c_str() + key.size() + 1, item.size() - key.size() - 1, &length);
      if (!result) throw std::runtime_error("URL decode failure");
      std::string value(result, length);
      curl_free(result);
      return value;
    }
    if (end == query.npos) break;
    start = end + 1;
  }
  return {};
}
} // namespace

//------------------------------------------------------------------------------
// Helper: the JSON body of a 2xx response; throws on any other status.
nlohmann::json HttpResponse::json() const {
  if (status < 200 || status >= 300) throw std::runtime_error("HTTP request failed: " + std::to_string(status));
  return nlohmann::json::parse(body);
}

//------------------------------------------------------------------------------
// TS 24.482 annex A.2.1.2: an HTTPS client that verifies the server against a configured trust anchor.
HttpClient::HttpClient(std::string ca_file, HttpTimeouts timeouts) : ca_(std::move(ca_file)), timeouts_(timeouts) {
  static const int initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (initialized != CURLE_OK) throw std::runtime_error("curl init failed");
  if (ca_.empty()) throw std::invalid_argument("HTTPS trust anchor required");
}

//------------------------------------------------------------------------------
// TS 24.482 annex A.2.1.2: sends one HTTP request over TLS (server certificate and host name verified, no
// redirects, bounded timeouts), with optional basic authentication and header fields.
HttpResponse HttpClient::request(std::string_view method, const std::string &url, const std::string &body,
                                 const std::map<std::string, std::string> &headers, const std::string &user,
                                 const std::string &password) const {
  if (!url.starts_with("https://")) throw std::invalid_argument("HTTPS required");
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
  if (!handle) throw std::runtime_error("curl allocation");
  auto *easy = handle.get();
  HttpResponse response;
  std::string verb(method);
  curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
  curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, verb.c_str());
  curl_easy_setopt(easy, CURLOPT_CAINFO, ca_.c_str());
  curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "https");
  curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, timeouts_.connect_ms);
  curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, timeouts_.total_ms);
  curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, receive);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &response.body);
  curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, header);
  curl_easy_setopt(easy, CURLOPT_HEADERDATA, &response);
  if (method == "HEAD") {
    // A HEAD response carries no body; without this libcurl waits for one.
    curl_easy_setopt(easy, CURLOPT_NOBODY, 1L);
  } else if (method != "GET") {
    curl_easy_setopt(easy, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
  }
  if (!user.empty()) {
    curl_easy_setopt(easy, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(easy, CURLOPT_USERNAME, user.c_str());
    curl_easy_setopt(easy, CURLOPT_PASSWORD, password.c_str());
  }
  curl_slist *list = nullptr;
  for (auto &[name, value] : headers) {
    if (name.find_first_of("\r\n:") != name.npos || value.find_first_of("\r\n") != value.npos) {
      curl_slist_free_all(list);
      throw std::invalid_argument("invalid HTTP header");
    }
    list = curl_slist_append(list, (name + ": " + value).c_str());
  }
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> holder(list, curl_slist_free_all);
  curl_easy_setopt(easy, CURLOPT_HTTPHEADER, list);
  auto result = curl_easy_perform(easy);
  if (result != CURLE_OK) throw std::runtime_error(std::string("HTTPS transport: ") + curl_easy_strerror(result));
  curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response.status);
  return response;
}

//------------------------------------------------------------------------------
// RFC 3986 section 2.1: percent-encodes every character except the unreserved ones (section 2.3).
std::string url_encode(std::string_view input) {
  static constexpr char hex[] = "0123456789ABCDEF";
  std::string out;
  for (unsigned char character : input) {
    if ((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
        (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' ||
        character == '~')
      out += character;
    else {
      out += '%';
      out += hex[character >> 4];
      out += hex[character & 15];
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: 256 random bits, base64url encoded: the OIDC state, nonce and PKCE code verifier (RFC 7636 section 4.1).
std::string random_id() {
  std::array<unsigned char, 32> bytes{};
  if (RAND_bytes(bytes.data(), bytes.size()) != 1) throw std::runtime_error("random generator failure");
  return b64({reinterpret_cast<char *>(bytes.data()), bytes.size()});
}

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.1 (OpenID Connect Core 1.0 section 3.1.3.7): validates an RS256-signed ID token against the
// IdMS JWKS (RFC 7517, RFC 7518 section 3.3), its iss, aud, nonce, exp, iat and nbf claims, and the MCX claims of
// TS 33.180 table B.2.1.3-1 (the subject must be the mcptt_id).
json verify_id_token(std::string_view token, const json &jwks, std::string_view issuer, std::string_view audience,
                     std::string_view nonce) {
  if (token.size() > max_id_token) throw std::runtime_error("oversized token");
  auto first = token.find('.'), second = token.find('.', first == token.npos ? 0 : first + 1);
  if (first == token.npos || second == token.npos || token.find('.', second + 1) != token.npos)
    throw std::runtime_error("invalid JWT");
  auto head = json::parse(unb64(token.substr(0, first)));
  if (head.value("alg", "") != "RS256") throw std::runtime_error("JWT algorithm refused");
  json key;
  for (const auto &candidate : jwks.at("keys"))
    if (candidate.value("kid", "") == head.value("kid", "") && candidate.value("kty", "") == "RSA" &&
        (!candidate.contains("use") || candidate.value("use", "") == "sig") &&
        (!candidate.contains("alg") || candidate.value("alg", "") == "RS256")) {
      if (!key.is_null()) throw std::runtime_error("duplicate JWKS key");
      key = candidate;
    }
  if (key.is_null()) throw std::runtime_error("unknown signing key");
  auto nbytes = unb64(key.at("n").get<std::string>()), ebytes = unb64(key.at("e").get<std::string>());
  std::unique_ptr<BIGNUM, decltype(&BN_free)> modulus(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(nbytes.data()), static_cast<int>(nbytes.size()), nullptr),
      BN_free),
      exponent(
          BN_bin2bn(reinterpret_cast<const unsigned char *>(ebytes.data()), static_cast<int>(ebytes.size()), nullptr),
          BN_free);
  std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> builder(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
  if (!modulus || !exponent || !builder || BN_num_bits(modulus.get()) < 2048 ||
      !OSSL_PARAM_BLD_push_BN(builder.get(), OSSL_PKEY_PARAM_RSA_N, modulus.get()) ||
      !OSSL_PARAM_BLD_push_BN(builder.get(), OSSL_PKEY_PARAM_RSA_E, exponent.get()))
    throw std::runtime_error("invalid RSA key");
  std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(OSSL_PARAM_BLD_to_param(builder.get()),
                                                                 OSSL_PARAM_free);
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
                                                                  EVP_PKEY_CTX_free);
  EVP_PKEY *raw = nullptr;
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
      EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) != 1)
    throw std::runtime_error("RSA public key import failed");
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pub(raw, EVP_PKEY_free);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  auto signature = unb64(token.substr(second + 1));
  if (!md || EVP_DigestVerifyInit(md.get(), nullptr, EVP_sha256(), nullptr, pub.get()) != 1 ||
      EVP_DigestVerify(md.get(), reinterpret_cast<const unsigned char *>(signature.data()), signature.size(),
                       reinterpret_cast<const unsigned char *>(token.data()), second) != 1)
    throw std::runtime_error("ID token signature rejected");
  auto claims = json::parse(unb64(token.substr(first + 1, second - first - 1)));
  auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  auto identity = [&claims](const char *name) {
    const auto value = claims.find(name);
    if (value == claims.end() || !value->is_string() || value->get_ref<const std::string &>().empty())
      throw std::runtime_error("ID token identity binding rejected");
    return value->get<std::string>();
  };
  const auto subject = identity("sub");
  const auto mcptt_id = identity("mcptt_id");
  (void)identity("client_id");
  (void)identity("sip_uri");
  if (claims.value("iss", "") != issuer || claims.value("aud", "") != audience || claims.value("nonce", "") != nonce ||
      !claims.at("exp").is_number_integer() || !claims.at("iat").is_number_integer() ||
      claims.at("exp").get<long long>() <= now || claims.at("iat").get<long long>() > now + id_token_clock_skew_s ||
      (claims.contains("nbf") && (!claims.at("nbf").is_number_integer() || claims.at("nbf").get<long long>() > now)) ||
      subject != mcptt_id)
    throw std::runtime_error("ID token claims rejected");
  return claims;
}

//------------------------------------------------------------------------------
// Helper: an "application/x-www-form-urlencoded" body.
std::string form_encode(const std::map<std::string, std::string> &fields) { return form(fields); }

//------------------------------------------------------------------------------
// TS 24.482 clause 6.2.1 and TS 33.180 annex B.4.2 (clauses B.4.2.2 to B.4.2.5): OIDC discovery, the authorization
// code grant with PKCE (RFC 7636, S256), the username and password login, and the token request; the result holds
// the tokens, the verified ID token's "claims", its "nonce" and, from an IdMS that issues one, the "refresh_token".
json oidc_login(const HttpClient &http, const json &cfg) {
  const std::string issuer = cfg.at("issuer"), client = cfg.at("client_id"), redirect = cfg.at("redirect_uri");
  auto discovery = http.request("GET", issuer + "/.well-known/openid-configuration").json();
  if (discovery.at("issuer") != issuer) throw std::runtime_error("OIDC issuer mismatch");
  for (auto name : {"authorization_endpoint", "token_endpoint", "jwks_uri"})
    if (!discovery.at(name).get<std::string>().starts_with(issuer + "/"))
      throw std::runtime_error("OIDC endpoint outside issuer");
  auto verifier = random_id(), state = random_id(), nonce = random_id();
  unsigned char digest[32];
  unsigned int len = 0;
  if (EVP_Digest(verifier.data(), verifier.size(), digest, &len, EVP_sha256(), nullptr) != 1)
    throw std::runtime_error("PKCE digest failure");
  auto authorization =
      http.request("GET", discovery.at("authorization_endpoint").get<std::string>() + "?" +
                              form({{"response_type", "code"},
                                    {"client_id", client},
                                    {"redirect_uri", redirect},
                                    {"scope", "openid 3gpp:mc:ptt_service 3gpp:mc:ptt_key_management_service "
                                              "3gpp:mc:data_key_management_service "
                                              "3gpp:mc:video_key_management_service"},
                                    {"state", state},
                                    {"nonce", nonce},
                                    // TS 33.180 table B.4.2.2-1: REQUIRED, the password-based ACR value.
                                    {"acr_values", "3gpp:acr:password"},
                                    {"code_challenge", b64({reinterpret_cast<char *>(digest), len})},
                                    {"code_challenge_method", "S256"}}))
          .json();
  auto login = http.request("POST", issuer + "/login",
                            form({{"request_id", authorization.at("request_id")},
                                  {"username", cfg.at("username")},
                                  {"password", cfg.at("password")}}),
                            {{"Content-Type", "application/x-www-form-urlencoded"}});
  if (login.status != 302) throw std::runtime_error("IdMS user authentication failed");
  auto location = login.headers.at("location");
  if (!location.starts_with(redirect + "?") || query_value(location, "state") != state)
    throw std::runtime_error("OIDC redirect or state mismatch");
  auto code = query_value(location, "code");
  if (code.empty()) throw std::runtime_error("OIDC code absent");
  auto tokens = http.request("POST", discovery.at("token_endpoint"),
                             form({{"grant_type", "authorization_code"},
                                   {"client_id", client},
                                   {"redirect_uri", redirect},
                                   {"code", code},
                                   {"code_verifier", verifier}}),
                             {{"Content-Type", "application/x-www-form-urlencoded"}})
                    .json();
  auto keys = http.request("GET", discovery.at("jwks_uri")).json();
  tokens["claims"] = verify_id_token(tokens.at("id_token").get<std::string>(), keys, issuer, client, nonce);
  tokens["nonce"] = nonce;
  return tokens;
}

//------------------------------------------------------------------------------
// RFC 6749 section 5.2 and TS 33.180 annex B.5: a token endpoint response that refuses the refresh token itself:
// error "invalid_grant", with HTTP 400 (RFC 6749 section 5.2) or 401 (as some servers send it).
bool oidc_refresh_refusal(const HttpResponse &response) {
  constexpr long bad_request = 400;
  constexpr long unauthorized = 401;
  if (response.status != bad_request && response.status != unauthorized) return false;
  const auto error = json::parse(response.body, nullptr, false);
  if (!error.is_object()) return false;
  const auto code = error.find("error");
  return code != error.end() && code->is_string() && code->get_ref<const std::string &>() == "invalid_grant";
}

//------------------------------------------------------------------------------
// TS 33.180 annex B.5 (clauses B.5.2 and B.5.3), RFC 6749 section 6: the refresh token grant, new tokens without
// the password. "invalid_grant" (RFC 6749 section 5.2: revoked, lapsed, account not active) throws
// oidc_refresh_refused; any other failure throws oidc_refresh_failed (retryable: the refresh token is kept).
json oidc_refresh(const HttpClient &http, const json &cfg, const std::string &refresh_token, const std::string &nonce) {
  constexpr long ok = 200;
  const std::string issuer = cfg.at("issuer"), client = cfg.at("client_id");
  // A transport failure or an unreachable IdMS is transient: the refresh token is kept for a later attempt.
  const auto transient = [](const auto &send) {
    try {
      return send();
    } catch (const std::exception &error) {
      throw oidc_refresh_failed(std::string("token refresh failed: ") + error.what());
    }
  };
  const auto discovery =
      transient([&] { return http.request("GET", issuer + "/.well-known/openid-configuration").json(); });
  if (discovery.at("issuer") != issuer) throw std::runtime_error("OIDC issuer mismatch");
  for (const auto *name : {"token_endpoint", "jwks_uri"})
    if (!discovery.at(name).get<std::string>().starts_with(issuer + "/"))
      throw std::runtime_error("OIDC endpoint outside issuer");
  const auto response = transient([&] {
    return http.request(
        "POST", discovery.at("token_endpoint"),
        form({{"grant_type", "refresh_token"}, {"client_id", client}, {"refresh_token", refresh_token}}),
        {{"Content-Type", "application/x-www-form-urlencoded"}});
  });
  if (oidc_refresh_refusal(response)) throw oidc_refresh_refused("IdMS refused the refresh token (invalid_grant)");
  if (response.status != ok) throw oidc_refresh_failed("token refresh failed: HTTP " + std::to_string(response.status));
  auto tokens = response.json();
  auto keys = http.request("GET", discovery.at("jwks_uri")).json();
  // OpenID Connect Core 1.0 section 12.2: the ID token of a refresh names the same user, with the nonce
  // of the authentication.
  tokens["claims"] = verify_id_token(tokens.at("id_token").get<std::string>(), keys, issuer, client, nonce);
  tokens["nonce"] = nonce;
  return tokens;
}
} // namespace mcx
