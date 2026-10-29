//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// HTTPS client and OpenID Connect user authentication of the IdM client: the authorization code grant with PKCE,
// the refresh token grant and ID token validation of the MCX Connect profile.
//
// Specifications: TS 24.482 V19.1.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 37.579-1 V18.1.0 (Rel-18), RFC 6749,
// RFC 7636, OpenID Connect Core 1.0, RFC 7515, RFC 7517, RFC 7518, RFC 7519, RFC 4648, RFC 3986, RFC 6265, HTML 4.01;
// CRLs: TS 33.310 V19.5.0 (Rel-19), RFC 5280.
#include "mcx/http.hpp"
#include "mcx/tls_profile.hpp"

#include <curl/curl.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <functional>
#include <initializer_list>
#include <memory>
#include <optional>
#include <set>
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
      if (start != value.npos) {
        auto &headers = static_cast<HttpResponse *>(ctx)->headers;
        const auto name = lower(line.substr(0, colon));
        auto field = value.substr(start, end - start + 1);
        // RFC 6265 section 3: a response may set several cookies, one Set-Cookie field each.
        if (name == "set-cookie" && headers.contains(name))
          headers[name] += "\n" + field;
        else
          headers[name] = std::move(field);
      }
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

//------------------------------------------------------------------------------
// Helper: TS 33.210 clause 6.2 (TS 33.180 clause 6.1.2): TLS 1.2 or 1.3, TLS 1.2 only with ECDHE and AEAD, no ffdhe
// group (mcx/tls_profile.hpp).
void apply_tls_profile(CURL *easy) {
  curl_easy_setopt(easy, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
  curl_easy_setopt(easy, CURLOPT_SSL_CIPHER_LIST, tls_profile::tls12_ciphers);
  curl_easy_setopt(easy, CURLOPT_SSL_EC_CURVES, tls_profile::groups);
}

// The CRLs of one request, owned.
using CrlSet = std::vector<std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>>;

//------------------------------------------------------------------------------
// Helper: TS 33.310 clause 6.1a: the CRLs of a PEM file, each a version 2 CRL ("Version 2 CRL according to
// RFC5280") whose signature hash is not MD2, MD5 or SHA-1 ("shall not be supported"), and a full CRL (clause 7.6: "The
// use of delta CRLs is not allowed"). A file that cannot be read, holds no CRL or a CRL outside the profile throws.
CrlSet load_crls(const std::string &path) {
  std::unique_ptr<BIO, decltype(&BIO_free)> file(BIO_new_file(path.c_str(), "r"), BIO_free);
  if (!file) throw std::runtime_error("CRL file unreadable: " + path);
  CrlSet crls;
  while (X509_CRL *crl = PEM_read_bio_X509_CRL(file.get(), nullptr, nullptr, nullptr)) {
    crls.emplace_back(crl, X509_CRL_free);
    int digest = NID_undef, key = NID_undef;
    if (X509_CRL_get_version(crl) != X509_CRL_VERSION_2)
      throw std::runtime_error("CRL not version 2 (TS 33.310 clause 6.1a): " + path);
    if (OBJ_find_sigid_algs(X509_CRL_get_signature_nid(crl), &digest, &key) != 1 || digest == NID_md2 ||
        digest == NID_md5 || digest == NID_sha1)
      throw std::runtime_error("CRL signature algorithm refused (TS 33.310 clause 6.1a): " + path);
    if (X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0)
      throw std::runtime_error("delta CRL refused (TS 33.310 clause 7.6): " + path);
  }
  ERR_clear_error();
  if (crls.empty()) throw std::runtime_error("CRL file holds no CRL: " + path);
  return crls;
}

//------------------------------------------------------------------------------
// Helper: libcurl SSL_CTX callback (OpenSSL backend) of a request with CRLs: adds them to the trust store and has the
// whole received chain checked against them (RFC 5280 section 6.3; X509_V_FLAG_CRL_CHECK_ALL: every certificate, not
// only the server's own), on the store and on the context, so the check stays on whatever store the handshake uses.
CURLcode crl_context(CURL *, void *context, void *data) {
  auto *ctx = static_cast<SSL_CTX *>(context);
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  if (!store) return CURLE_SSL_CERTPROBLEM;
  for (const auto &crl : *static_cast<const CrlSet *>(data))
    if (X509_STORE_add_crl(store, crl.get()) != 1) return CURLE_SSL_CERTPROBLEM;
  constexpr unsigned long flags = X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL;
  if (X509_STORE_set_flags(store, flags) != 1 || X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx), flags) != 1)
    return CURLE_SSL_CERTPROBLEM;
  return CURLE_OK;
}

} // namespace

//------------------------------------------------------------------------------
// Helper: the JSON body of a 2xx response; throws on any other status.
nlohmann::json HttpResponse::json() const {
  if (status < 200 || status >= 300) throw std::runtime_error("HTTP request failed: " + std::to_string(status));
  return nlohmann::json::parse(body);
}

//------------------------------------------------------------------------------
// TS 24.482 annex A.2.1.2: an HTTPS client that verifies the server against a configured trust anchor (and the
// system's CAs, with HttpTrust::configured_and_system).
HttpClient::HttpClient(std::string ca_file, HttpTimeouts timeouts, HttpAddressMap address_map, HttpTrust trust,
                       std::string crl_file)
    : ca_(std::move(ca_file)), timeouts_(timeouts), address_map_(std::move(address_map)), trust_(trust),
      crl_file_(std::move(crl_file)) {
  for (const auto &[named, reached] : address_map_)
    if (named.find(':') == named.npos || reached.find(':') == reached.npos ||
        (named + reached).find_first_of(" \r\n") != std::string::npos)
      throw std::invalid_argument("address map entries are host:port -> address:port");
  static const int initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (initialized != CURLE_OK) throw std::runtime_error("curl init failed");
  if (ca_.empty()) throw std::invalid_argument("HTTPS trust anchor required");
}

namespace {
//------------------------------------------------------------------------------
// Helper: RFC 3986 section 3.2: the authority of an http or https URI (without userinfo, which RFC 9110 section
// 4.2.4 forbids a sender to generate); empty when there is none or the URI cannot go on a request line.
std::string uri_authority(std::string_view uri) {
  const auto scheme = uri.starts_with("https://") ? 8 : uri.starts_with("http://") ? 7 : 0;
  if (scheme == 0) return {};
  for (const char c : uri)
    if (static_cast<unsigned char>(c) <= 0x20 || c == 0x7f || c == '#') return {};
  const auto end = uri.find_first_of("/?", scheme);
  const auto authority = uri.substr(scheme, end == uri.npos ? uri.npos : end - scheme);
  if (authority.empty() || authority.find('@') != authority.npos) return {};
  return std::string(authority);
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.482 annex A.2.1.2: the home HTTP proxy, configured as a URI (TS 24.484 clause 7.2.2.7 c), TS 24.483 clause
// 8.2.41B): https (the TLS tunnel), an FQDN and an optional port, nothing else.
void HttpClient::use_proxy(const std::string &proxy_uri) {
  if (proxy_uri.empty()) {
    proxy_.clear();
    return;
  }
  auto origin = proxy_uri;
  if (origin.ends_with('/')) origin.pop_back();
  if (!origin.starts_with("https://") || uri_authority(origin).empty() ||
      origin.size() != 8 + uri_authority(origin).size())
    throw std::invalid_argument("HTTP proxy: an https URI with the proxy's FQDN and port only");
  proxy_ = origin;
}

//------------------------------------------------------------------------------
// TS 24.482 annex A.2.1.2: sends one HTTP request over TLS (server certificate and host name verified, no
// redirects, bounded timeouts), with optional basic authentication and header fields. With a home HTTP proxy, the
// TCP connection and the TLS tunnel go to the proxy ("shall check the home HTTP proxy FQDN against the server's
// identity ... shall not check the portion of dereferenced HTTP URL"), and "all HTTP messages via the TLS tunnel":
// http targets too, which without a proxy are refused. The request target is the target URI in absolute-form (RFC
// 9112 section 3.2.2: "When making a request to a proxy ... a client MUST send the target URI in absolute-form"), with
// the target's authority in Host (RFC 9112 section 3.2); no CONNECT, as the TLS tunnel ends at the proxy (NOTE).
HttpResponse HttpClient::request(std::string_view method, const std::string &url, const std::string &body,
                                 const std::map<std::string, std::string> &headers, const std::string &user,
                                 const std::string &password) const {
  std::string target_host;
  if (proxy_.empty()) {
    if (!url.starts_with("https://")) throw std::invalid_argument("HTTPS required");
  } else {
    target_host = uri_authority(url);
    if (target_host.empty()) throw std::invalid_argument("HTTP request through the proxy: an http or https URI required");
  }
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
  if (!handle) throw std::runtime_error("curl allocation");
  auto *easy = handle.get();
  HttpResponse response;
  std::string verb(method);

  if (proxy_.empty()) {
    curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
  } else {
    // libcurl connects to (and verifies) the URL's host: the proxy; the request line carries the target URI.
    curl_easy_setopt(easy, CURLOPT_URL, (proxy_ + "/").c_str());
    curl_easy_setopt(easy, CURLOPT_REQUEST_TARGET, url.c_str());
    // HTTP/1.1 (TS 24.482 annex A.2.1.1, RFC 9112), whose absolute-form names the target; libcurl would otherwise
    // negotiate HTTP/2 over TLS, which carries the target in :authority instead (RFC 9113 section 8.3.1).
    curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_1_1));
  }
  curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, verb.c_str());
  curl_easy_setopt(easy, CURLOPT_CAINFO, ca_.c_str());
  // libcurl adds the CA directory it was built with (on Ubuntu the system's) unless told otherwise.
  curl_easy_setopt(easy, CURLOPT_CAPATH, trust_ == HttpTrust::configured_and_system ? "/etc/ssl/certs" : nullptr);
  curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
  apply_tls_profile(easy);
  // TS 33.180 clause 6.1.1, TS 33.310 clause 6.1.1: "CRLs as specified in subclause 6.1a shall be supported for
  // certificate revocation verification". The file is read for this request (a CRL replaced in it applies at once);
  // libcurl's CA store cache is off so the CRLs go into this handshake's own store.
  CrlSet crls;
  if (!crl_file_.empty()) {
    crls = load_crls(crl_file_);
    curl_easy_setopt(easy, CURLOPT_CA_CACHE_TIMEOUT, 0L);
    curl_easy_setopt(easy, CURLOPT_SSL_CTX_FUNCTION, crl_context);
    curl_easy_setopt(easy, CURLOPT_SSL_CTX_DATA, &crls);
  }
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
  // RFC 9112 section 3.2: Host carries the target URI's authority (libcurl would send the proxy's).
  if (!target_host.empty()) list = curl_slist_append(list, ("Host: " + target_host).c_str());
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> holder(list, curl_slist_free_all);
  curl_easy_setopt(easy, CURLOPT_HTTPHEADER, list);

  // The address map: connect to the mapped address; libcurl keeps the URL's host for SNI and the name check.
  curl_slist *connect_to = nullptr;
  for (const auto &[named, reached] : address_map_) connect_to = curl_slist_append(connect_to, (named + ":" + reached).c_str());
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> connect_holder(connect_to, curl_slist_free_all);
  if (connect_to) curl_easy_setopt(easy, CURLOPT_CONNECT_TO, connect_to);

  auto result = curl_easy_perform(easy);
  if (result != CURLE_OK) throw std::runtime_error(std::string("HTTPS transport: ") + curl_easy_strerror(result));
  curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &response.status);
  return response;
}

namespace {
//------------------------------------------------------------------------------
// Helper: the pin of http_get_pinned, decoded, reachable from the OpenSSL verify callback through the SSL_CTX.
struct Pin {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
};

//------------------------------------------------------------------------------
// Helper: OpenSSL verify callback of http_get_pinned: the server's own certificate (depth 0) is accepted when its
// SHA-256 (DER) is the pin, whatever its chain or name; the chain above it is not checked (the pin names the server).
int verify_pinned(int, X509_STORE_CTX *store) {
  if (X509_STORE_CTX_get_error_depth(store) != 0) {
    X509_STORE_CTX_set_error(store, X509_V_OK);
    return 1;
  }
  auto *ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
  const auto *pin = ssl ? static_cast<const Pin *>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl))) : nullptr;
  X509 *certificate = X509_STORE_CTX_get_current_cert(store);
  unsigned char *der = nullptr;
  const int length = certificate ? i2d_X509(certificate, &der) : -1;
  if (!pin || length <= 0) return 0;
  std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
  SHA256(der, static_cast<size_t>(length), digest.data());
  OPENSSL_free(der);
  if (CRYPTO_memcmp(digest.data(), pin->digest.data(), digest.size()) != 0) return 0;
  X509_STORE_CTX_set_error(store, X509_V_OK);
  return 1;
}

//------------------------------------------------------------------------------
// Helper: libcurl SSL_CTX callback of http_get_pinned (OpenSSL backend): installs the pin check.
CURLcode pin_context(CURL *, void *context, void *pin) {
  auto *ctx = static_cast<SSL_CTX *>(context);
  SSL_CTX_set_app_data(ctx, pin);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_pinned);
  return CURLE_OK;
}

} // namespace

//------------------------------------------------------------------------------
// MCX Admin activation link: a GET trusting only the server certificate whose SHA-256 is the pin (checked in the TLS
// handshake), without host name check, no redirects, bounded timeouts.
HttpResponse http_get_pinned(const std::string &url, std::string_view pin, HttpTimeouts timeouts) {
  if (!url.starts_with("https://")) throw std::invalid_argument("HTTPS required");
  static const int initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (initialized != CURLE_OK) throw std::runtime_error("curl init failed");

  const auto bytes = unb64(pin);
  Pin expected;
  if (bytes.size() != expected.digest.size()) throw std::invalid_argument("the pin is not a SHA-256");
  std::copy(bytes.begin(), bytes.end(), expected.digest.begin());

  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
  if (!handle) throw std::runtime_error("curl allocation");
  auto *easy = handle.get();
  HttpResponse response;

  curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
  curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(easy, CURLOPT_SSL_CTX_FUNCTION, pin_context);
  curl_easy_setopt(easy, CURLOPT_SSL_CTX_DATA, &expected);
  curl_easy_setopt(easy, CURLOPT_SSL_SESSIONID_CACHE, 0L);
  apply_tls_profile(easy);
  curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "https");
  curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, timeouts.connect_ms);
  curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, timeouts.total_ms);
  curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, receive);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &response.body);
  curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, header);
  curl_easy_setopt(easy, CURLOPT_HEADERDATA, &response);

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

namespace {
//------------------------------------------------------------------------------
// Helper: RFC 7515 section 5.2 with RFC 7518 section 3.3: the claims of an RS256-signed JWT whose signature the IdMS
// JWKS (RFC 7517) key named by its "kid" verifies; a JWT without "kid", the JWKS's only key (OpenID Connect Core 1.0
// section 10.1: "If there are multiple keys in the referenced JWK Set document, a kid value MUST be provided"). A
// token of a key the JWKS does not hold throws oidc_unknown_signing_key. RFC 7515 section 4.1.11: this verifier
// understands no extension, so a JWS with a "crit" header parameter is invalid.
json signed_claims(std::string_view token, const json &jwks) {
  if (token.size() > max_id_token) throw std::runtime_error("oversized token");
  auto first = token.find('.'), second = token.find('.', first == token.npos ? 0 : first + 1);
  if (first == token.npos || second == token.npos || token.find('.', second + 1) != token.npos)
    throw std::runtime_error("invalid JWT");
  auto head = json::parse(unb64(token.substr(0, first)));
  if (head.value("alg", "") != "RS256") throw std::runtime_error("JWT algorithm refused");
  if (head.contains("crit")) throw std::runtime_error("JWT critical header parameter not understood");

  const bool named_key = head.contains("kid");
  json key;
  for (const auto &candidate : jwks.at("keys")) {
    if (candidate.value("kty", "") != "RSA" || (candidate.contains("use") && candidate.value("use", "") != "sig") ||
        (candidate.contains("alg") && candidate.value("alg", "") != "RS256"))
      continue;
    if (named_key && candidate.value("kid", "") != head.value("kid", "")) continue;
    if (!key.is_null())
      throw std::runtime_error(named_key ? "duplicate JWKS key" : "JWT without kid for a JWKS of several keys");
    key = candidate;
  }
  if (key.is_null()) throw oidc_unknown_signing_key("unknown signing key");

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
    throw std::runtime_error("token signature rejected");

  return json::parse(unb64(token.substr(first + 1, second - first - 1)));
}

//------------------------------------------------------------------------------
// Helper: RFC 7519 section 4.1: "exp" ahead (TS 33.180 annex B.12), "iat" a NumericDate where given (section 4.1.6)
// and "nbf" (where given) passed. An ID token must have "iat" (OpenID Connect Core 1.0 section 2), not ahead by more
// than the clock skew (section 3.1.3.7 item 10). An access token's "iat" is not compared with the clock: no rule of
// TS 33.180 annex B.11.2 or RFC 7519 section 7.2 asks for it.
bool times_valid(const json &claims, bool id_token) {
  const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  const auto number = [&claims](const char *name) {
    return claims.contains(name) && claims.at(name).is_number_integer();
  };
  const bool iat_valid = id_token ? number("iat") && claims.at("iat").get<long long>() <= now + id_token_clock_skew_s
                                  : !claims.contains("iat") || number("iat");
  return number("exp") && claims.at("exp").get<long long>() > now && iat_valid &&
         (!claims.contains("nbf") || (number("nbf") && claims.at("nbf").get<long long>() <= now));
}

//------------------------------------------------------------------------------
// Helper: RFC 7519 section 4.1.3: "aud" is the audience, or an array that names it.
bool audience_valid(const json &claims, std::string_view audience) {
  const auto aud = claims.find("aud");
  if (aud == claims.end()) return false;
  if (aud->is_string()) return aud->get_ref<const std::string &>() == audience;
  if (!aud->is_array()) return false;
  for (const auto &item : *aud)
    if (item.is_string() && item.get_ref<const std::string &>() == audience) return true;
  return false;
}

//------------------------------------------------------------------------------
// Helper: OpenID Connect Core 1.0 section 3.1.3.7 step 3: "aud" names the client and no other audience (this client
// trusts no other one): the client_id, or an array of it alone.
bool sole_audience(const json &claims, std::string_view audience) {
  const auto aud = claims.find("aud");
  if (aud == claims.end()) return false;
  if (aud->is_string()) return aud->get_ref<const std::string &>() == audience;
  if (!aud->is_array() || aud->empty()) return false;
  for (const auto &item : *aud)
    if (!item.is_string() || item.get_ref<const std::string &>() != audience) return false;
  return true;
}

//------------------------------------------------------------------------------
// Helper: a claim that is a non-empty string.
bool named(const json &claims, const char *name) {
  const auto value = claims.find(name);
  return value != claims.end() && value->is_string() && !value->get_ref<const std::string &>().empty();
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.1 (OpenID Connect Core 1.0 section 3.1.3.7): validates an RS256-signed ID token against the
// IdMS JWKS (RFC 7517, RFC 7518 section 3.3), its iss, aud, nonce, exp, iat and nbf claims, and the MCX claims of
// TS 33.180 table B.2.1.3-1. The ID token of a refresh may leave the nonce out (OpenID Connect Core 1.0 section 12.2).
json verify_id_token(std::string_view token, const json &jwks, std::string_view issuer, std::string_view audience,
                     std::string_view nonce, bool refreshed) {
  auto claims = signed_claims(token, jwks);
  // TS 33.180 tables B.2.1.2-1 and B.2.1.3-1: sub is any identifier of the user that IdMS never reassigns, and
  // mcptt_id the MCPTT ID; the client checks the IDs against its configuration. client_id and sip_uri (an OpenMCX
  // extension, not in those tables) are checked where an IdMS gives them.
  bool bound = named(claims, "sub") && named(claims, "mcptt_id");
  for (const auto *name : {"client_id", "sip_uri", "mcdata_id", "mcvideo_id"})
    bound = bound && (!claims.contains(name) || named(claims, name));
  if (!bound) throw std::runtime_error("ID token identity binding rejected");

  // OpenID Connect Core 1.0 section 3.1.3.7 step 3: "The ID Token MUST be rejected if the ID Token does not list the
  // Client as a valid audience, or if it contains additional audiences not trusted by the Client".
  if (claims.value("iss", "") != issuer || !sole_audience(claims, audience) ||
      (claims.contains("nonce") || !refreshed ? claims.value("nonce", "") != nonce : false) ||
      !times_valid(claims, true))
    throw std::runtime_error("ID token claims rejected");
  return claims;
}

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.2: validates an access token (RFC 7519 section 7.2): its RS256 signature by a key of the IdMS
// JWKS, exp, nbf and the form of iat, and the claims of tables B.2.2.2-1 and B.2.2.3-1: scope and client_id; the MC
// service ID is the caller's to check. Table B.2.2.2-1 requires neither iss nor aud: RFC 7519 sections 4.1.1 and 4.1.3, iss is
// the IdMS's and aud names the MC servers' audience (alone or among others) "when this claim is present".
json verify_access_token(std::string_view token, const json &jwks, std::string_view issuer, std::string_view audience) {
  auto claims = signed_claims(token, jwks);
  if ((claims.contains("iss") && claims.value("iss", "") != issuer) ||
      (claims.contains("aud") && !audience_valid(claims, audience)) || !times_valid(claims, false) ||
      !named(claims, "scope") || !named(claims, "client_id"))
    throw std::runtime_error("access token claims rejected");
  return claims;
}

//------------------------------------------------------------------------------
// Helper: an "application/x-www-form-urlencoded" body.
std::string form_encode(const std::map<std::string, std::string> &fields) { return form(fields); }

namespace {
//------------------------------------------------------------------------------
// Helper: checks the OpenID Connect Discovery 1.0 document (section 4) of the configured issuer. The endpoints are
// under the issuer, or https URLs elsewhere (section 3: an IdMS may serve them from other hosts).
json checked_discovery(json discovery, const std::string &issuer, std::initializer_list<const char *> endpoints) {
  if (discovery.at("issuer") != issuer) throw std::runtime_error("OIDC issuer mismatch");
  for (const auto *name : endpoints) {
    const auto endpoint = discovery.at(name).get<std::string>();
    if (!endpoint.starts_with(issuer + "/") && !endpoint.starts_with("https://"))
      throw std::runtime_error("OIDC endpoint neither under the issuer nor https");
  }
  return discovery;
}

//------------------------------------------------------------------------------
// Helper: RFC 6749 section 7.1 ("The client MUST NOT use an access token if it does not understand the token type")
// with TS 33.180 annex B.10 and tables B.4.2.5-1 and B.5.3-1: a token response whose access token is of the type
// "bearer" (RFC 6749 section 5.1: "Value is case insensitive").
json bearer_token_response(json tokens) {
  const auto access = tokens.find("access_token"), type = tokens.find("token_type");
  if (access == tokens.end() || !access->is_string() || type == tokens.end() || !type->is_string() ||
      lower(type->get<std::string>()) != "bearer")
    throw std::runtime_error("token response without a bearer access token");
  return tokens;
}

//------------------------------------------------------------------------------
// Helper: fetches and checks the discovery document of the configured issuer.
json oidc_discovery(const HttpClient &http, const std::string &issuer, std::initializer_list<const char *> endpoints) {
  return checked_discovery(http.request("GET", issuer + "/.well-known/openid-configuration").json(), issuer, endpoints);
}

//------------------------------------------------------------------------------
// Helper: a discovery document of the configured issuer fetched once, on first use (oidc_endpoint), through send.
std::function<json()> lazy_discovery(const std::string &issuer, std::function<json()> send) {
  return [issuer, send = std::move(send), document = std::make_shared<std::optional<json>>()] {
    if (!*document) *document = checked_discovery(send(), issuer, {});
    return **document;
  };
}

//------------------------------------------------------------------------------
// Helper: the discovery document of the configured issuer, fetched on first use.
std::function<json()> lazy_discovery(const HttpClient &http, const std::string &issuer) {
  return lazy_discovery(issuer, [&http, issuer] {
    return http.request("GET", issuer + "/.well-known/openid-configuration").json();
  });
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.484 clause 7.2.2.7 item 4: the IdMS endpoints of the initial MC UE configuration, <App-Server-Info>
// <idms-auth-endpoint> ("authorization_endpoint") and <idms-token-endpoint> ("token_endpoint"), configured as
// idms_auth_endpoint and idms_token_endpoint; a JWKS URI ("jwks_uri") configured as jwks_uri (OpenID Connect Core
// 1.0 section 10: keys supplied "by other means"). A configured endpoint is used as given, without the discovery
// document; it is an https URI (TS 33.180 clause 5.1.2.1: "protected using HTTPS"). An endpoint not configured is
// taken from the issuer's discovery document (OpenID Connect Discovery 1.0 section 3), which discovery returns.
std::string oidc_endpoint(const json &cfg, std::string_view name, const std::function<json()> &discovery) {
  static const std::map<std::string_view, const char *> configured{{"authorization_endpoint", "idms_auth_endpoint"},
                                                                   {"token_endpoint", "idms_token_endpoint"},
                                                                   {"jwks_uri", "jwks_uri"}};
  const auto key = configured.find(name);
  if (key == configured.end()) throw std::invalid_argument("unknown IdMS endpoint");
  if (const auto value = cfg.find(key->second); value != cfg.end()) {
    if (!value->is_string() || !value->get_ref<const std::string &>().starts_with("https://"))
      throw std::runtime_error(std::string("configured ") + key->second + " is not an https URI");
    return value->get<std::string>();
  }
  const auto document = discovery();
  const std::string issuer = cfg.at("issuer");
  checked_discovery(document, issuer, {key->first.data()});
  return document.at(std::string(name)).get<std::string>();
}

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.2 (access token validation by RFC 7519) does not say how a resource server gets IdMS's keys;
// OpenID Connect Core 1.0 section 10: "The OP advertises its public keys via its Discovery document or may supply this
// information by other means". Here: the JWKS (RFC 7517) its discovery document names ("jwks_uri").
json oidc_jwks(const HttpClient &http, const std::string &issuer) {
  const auto discovery = oidc_discovery(http, issuer, {"jwks_uri"});
  auto keys = http.request("GET", discovery.at("jwks_uri")).json();
  if (!keys.contains("keys") || !keys.at("keys").is_array()) throw std::runtime_error("invalid JWKS");
  return keys;
}

//------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.2: the authorization request of the authorization code grant with PKCE (RFC 7636, S256):
// "url" (the authorization endpoint with the parameters of table B.4.2.2-1) and the "state", "nonce" and
// "code_verifier" the client keeps for the response.
json oidc_authorization_request(const HttpClient &http, const json &cfg) {
  const std::string issuer = cfg.at("issuer"), client = cfg.at("client_id"), redirect = cfg.at("redirect_uri");
  const auto endpoint = oidc_endpoint(cfg, "authorization_endpoint", lazy_discovery(http, issuer));

  auto verifier = random_id(), state = random_id(), nonce = random_id();
  unsigned char digest[32];
  unsigned int len = 0;
  if (EVP_Digest(verifier.data(), verifier.size(), digest, &len, EVP_sha256(), nullptr) != 1)
    throw std::runtime_error("PKCE digest failure");
  const auto url = endpoint + (endpoint.find('?') == std::string::npos ? "?" : "&") +
                   form({{"response_type", "code"},
                         {"client_id", client},
                         {"redirect_uri", redirect},
                         {"scope", cfg.value("scope", std::string(oidc_default_scope))},
                         {"state", state},
                         {"nonce", nonce},
                         // TS 33.180 table B.4.2.2-1: REQUIRED, the password-based ACR value.
                         {"acr_values", "3gpp:acr:password"},
                         {"code_challenge", b64({reinterpret_cast<char *>(digest), len})},
                         {"code_challenge_method", "S256"}});
  return {{"url", url}, {"state", state}, {"nonce", nonce}, {"code_verifier", verifier}};
}

//------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.4 and B.4.2.5: the token request for an authorization code, and the verified ID token's
// "claims" (annex B.11.1) with the "nonce" of the authorization request.
json oidc_exchange_code(const HttpClient &http, const json &cfg, const std::string &code,
                        const std::string &code_verifier, const std::string &nonce) {
  const std::string issuer = cfg.at("issuer"), client = cfg.at("client_id"), redirect = cfg.at("redirect_uri");
  if (code.empty()) throw std::runtime_error("OIDC code absent");
  const auto discovery = lazy_discovery(http, issuer);
  auto response = http.request("POST", oidc_endpoint(cfg, "token_endpoint", discovery),
                               form({{"grant_type", "authorization_code"},
                                     {"client_id", client},
                                     {"redirect_uri", redirect},
                                     {"code", code},
                                     {"code_verifier", code_verifier}}),
                               {{"Content-Type", "application/x-www-form-urlencoded"}});
  constexpr long ok = 200;
  if (response.status != ok)
    throw std::runtime_error("OIDC token request refused: HTTP " + std::to_string(response.status));
  auto tokens = bearer_token_response(response.json());
  auto keys = http.request("GET", oidc_endpoint(cfg, "jwks_uri", discovery)).json();
  tokens["claims"] = verify_id_token(tokens.at("id_token").get<std::string>(), keys, issuer, client, nonce);
  tokens["nonce"] = nonce;
  return tokens;
}

namespace {
//------------------------------------------------------------------------------
// Helper: whether a character is HTML white space (HTML 4.01 section 9.1).
bool html_space(char character) {
  return character == ' ' || character == '\t' || character == '\n' || character == '\r' || character == '\f';
}

//------------------------------------------------------------------------------
// Helper: an attribute value with its character references decoded (HTML 4.01 section 5.3): the numeric ones and
// &amp; &lt; &gt; &quot; &apos;. Any other "&" stays as it is.
std::string html_unescape(std::string_view text) {
  std::string out;
  for (std::size_t at = 0; at < text.size(); ++at) {
    const auto semicolon = text[at] == '&' ? text.find(';', at) : std::string_view::npos;
    if (semicolon == std::string_view::npos || semicolon - at > 10) {
      out += text[at];
      continue;
    }
    const auto name = text.substr(at + 1, semicolon - at - 1);
    static const std::map<std::string_view, char> named{
        {"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"quot", '"'}, {"apos", '\''}};
    unsigned long code = 0;
    if (const auto found = named.find(name); found != named.end()) {
      out += found->second;
    } else if (name.size() > 1 && name[0] == '#') {
      const bool hex = name[1] == 'x' || name[1] == 'X';
      const auto digits = std::string(name.substr(hex ? 2 : 1));
      if (digits.empty() ||
          digits.find_first_not_of(hex ? "0123456789abcdefABCDEF" : "0123456789") != std::string::npos)
        throw std::runtime_error("invalid HTML character reference");
      code = std::stoul(digits, nullptr, hex ? 16 : 10);
      if (code == 0 || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF))
        throw std::runtime_error("invalid HTML character reference");
      // UTF-8 (RFC 3629 section 3).
      if (code < 0x80) {
        out += static_cast<char>(code);
      } else if (code < 0x800) {
        out += static_cast<char>(0xC0 | (code >> 6));
        out += static_cast<char>(0x80 | (code & 0x3F));
      } else if (code < 0x10000) {
        out += static_cast<char>(0xE0 | (code >> 12));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code & 0x3F));
      } else {
        out += static_cast<char>(0xF0 | (code >> 18));
        out += static_cast<char>(0x80 | ((code >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code & 0x3F));
      }
    } else {
      out += text[at];
      continue;
    }
    at = semicolon;
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: one HTML start tag at `at` (its "<"): the lower-case element name and its attributes (lower-case names,
// decoded values; a repeated attribute keeps its first value, HTML 4.01 section 3.2.2). `at` moves past the ">".
std::pair<std::string, std::map<std::string, std::string>> html_tag(std::string_view html, std::size_t &at) {
  std::size_t index = at + 1;
  const auto word = [&] {
    const auto start = index;
    while (index < html.size() && !html_space(html[index]) && html[index] != '>' && html[index] != '/' &&
           html[index] != '=')
      ++index;
    return lower(std::string(html.substr(start, index - start)));
  };
  const auto skip = [&] {
    while (index < html.size() && (html_space(html[index]) || html[index] == '/')) ++index;
  };
  auto element = word();
  std::map<std::string, std::string> attributes;
  for (skip(); index < html.size() && html[index] != '>'; skip()) {
    auto name = word();
    if (name.empty()) throw std::runtime_error("invalid HTML attribute");
    std::string value;
    while (index < html.size() && html_space(html[index])) ++index;
    if (index < html.size() && html[index] == '=') {
      ++index;
      while (index < html.size() && html_space(html[index])) ++index;
      if (index < html.size() && (html[index] == '"' || html[index] == '\'')) {
        const auto close = html.find(html[index], index + 1);
        if (close == std::string_view::npos) throw std::runtime_error("unterminated HTML attribute value");
        value = html_unescape(html.substr(index + 1, close - index - 1));
        index = close + 1;
      } else {
        const auto start = index;
        while (index < html.size() && !html_space(html[index]) && html[index] != '>') ++index;
        value = html_unescape(html.substr(start, index - start));
      }
    }
    attributes.emplace(std::move(name), std::move(value));
  }
  if (index >= html.size()) throw std::runtime_error("unterminated HTML tag");
  at = index + 1;
  return {std::move(element), std::move(attributes)};
}
} // namespace

//------------------------------------------------------------------------------
// HTML 4.01 section 17: the one form of an IdMS page and the inputs it submits. Comments are skipped; the controls
// this client cannot fill refuse the page.
std::optional<HtmlForm> parse_html_form(std::string_view html) {
  std::optional<HtmlForm> found;
  bool inside = false;
  for (std::size_t at = html.find('<'); at != std::string_view::npos; at = html.find('<', at)) {
    if (html.substr(at, 4) == "<!--") {
      const auto end = html.find("-->", at + 4);
      if (end == std::string_view::npos) throw std::runtime_error("unterminated HTML comment");
      at = end + 3;
      continue;
    }
    if (at + 1 >= html.size() || !(std::isalpha(static_cast<unsigned char>(html[at + 1])) || html[at + 1] == '/')) {
      ++at;
      continue;
    }
    if (html[at + 1] == '/') {
      const auto end = html.find('>', at);
      if (end == std::string_view::npos) throw std::runtime_error("unterminated HTML tag");
      auto name = lower(std::string(html.substr(at + 2, end - at - 2)));
      name.erase(std::find_if(name.begin(), name.end(), [](char character) { return html_space(character); }),
                 name.end());
      if (name == "form") inside = false;
      at = end + 1;
      continue;
    }
    auto [element, attributes] = html_tag(html, at);
    // HTML 4.01 section 6.2: script and style content is not markup.
    if (element == "script" || element == "style") {
      const auto lowered = lower(std::string(html.substr(at)));
      const auto end = lowered.find("</" + element);
      if (end == std::string::npos) throw std::runtime_error("unterminated HTML " + element);
      at += end;
      continue;
    }
    if (element == "form") {
      if (found || inside) throw std::runtime_error("more than one HTML form");
      found = HtmlForm{attributes["action"], lower(attributes.contains("method") ? attributes["method"] : "get"), {}};
      inside = true;
    } else if (inside && (element == "select" || element == "textarea")) {
      throw std::runtime_error("unsupported HTML form control: " + element);
    } else if (inside && element == "input") {
      const auto type = lower(attributes.contains("type") ? attributes["type"] : "text");
      if (type == "submit" || type == "button" || type == "reset" || type == "image") continue;
      static const std::set<std::string> supported{"text", "email", "password", "hidden", "checkbox", "radio"};
      if (!supported.contains(type)) throw std::runtime_error("unsupported HTML input type: " + type);
      // HTML 4.01 section 17.13.2: an unnamed, disabled or unchecked control is not submitted.
      if (attributes["name"].empty() || attributes.contains("disabled")) continue;
      if ((type == "checkbox" || type == "radio") && !attributes.contains("checked")) continue;
      if ((type == "checkbox" || type == "radio") && !attributes.contains("value")) attributes["value"] = "on";
      found->inputs.push_back({attributes["name"], type, attributes["value"]});
    }
  }
  if (inside) throw std::runtime_error("unterminated HTML form");
  return found;
}

//------------------------------------------------------------------------------
// HTML 4.01 section 17.13.3 and TS 37.579-1 table 5.5.4.3-1 (condition USERAUTH): the hidden and checked inputs as
// they are, the user name in the one text or email input, the password in the one password input.
std::map<std::string, std::string> html_form_fields(const HtmlForm &form, const std::string &user,
                                                    const std::string &password) {
  std::map<std::string, std::string> fields;
  int users = 0, passwords = 0;
  for (const auto &input : form.inputs) {
    if (fields.contains(input.name)) throw std::runtime_error("HTML form control name repeated: " + input.name);
    if (input.type == "password") {
      ++passwords;
      fields[input.name] = password;
    } else if (input.type == "text" || input.type == "email") {
      ++users;
      fields[input.name] = user;
    } else {
      fields[input.name] = input.value;
    }
  }
  if (users != 1 || passwords != 1)
    throw std::runtime_error("the IdMS form has no single user name and password input");
  return fields;
}

//------------------------------------------------------------------------------
// RFC 3986 section 5.2.2 (strict parser) for the references a form action uses; the base is an https URI.
std::string resolve_https_reference(const std::string &base, const std::string &reference) {
  if (!base.starts_with("https://")) throw std::invalid_argument("HTTPS base required");
  auto target = reference.substr(0, reference.find('#'));
  const auto authority_end = base.find_first_of("/?#", 8);
  const auto origin = base.substr(0, authority_end);
  auto path_and_query = authority_end == std::string::npos ? std::string("/") : base.substr(authority_end);
  path_and_query = path_and_query.substr(0, path_and_query.find('#'));
  const auto path = path_and_query.substr(0, path_and_query.find('?'));
  std::string resolved;
  if (target.find_first_of(" \t\r\n\\") != std::string::npos) throw std::runtime_error("invalid form action");
  if (target.empty())
    resolved = origin + path_and_query;
  else if (lower(target).starts_with("https://"))
    resolved = target;
  else if (target.starts_with("//"))
    resolved = "https:" + target;
  else if (const auto colon = target.find(':'); colon != std::string::npos && colon < target.find_first_of("/?"))
    throw std::runtime_error("form action of another scheme");
  else if (target.starts_with("/"))
    resolved = origin + target;
  else if (target.starts_with("?"))
    resolved = origin + path + target;
  else
    resolved = origin + path.substr(0, path.rfind('/') + 1) + target;
  // Dot segments (RFC 3986 section 5.2.4) are refused rather than removed.
  const auto resolved_path = resolved.substr(0, resolved.find('?'));
  for (std::size_t at = resolved_path.find("/.", 8); at != std::string::npos; at = resolved_path.find("/.", at + 1)) {
    const auto rest = resolved_path.substr(at + 1);
    if (rest == "." || rest == ".." || rest.starts_with("./") || rest.starts_with("../"))
      throw std::runtime_error("dot segment in form action");
  }
  return resolved;
}

namespace {
//------------------------------------------------------------------------------
// Helper: RFC 6265 section 5.4: the Cookie header field of the next request from the Set-Cookie fields of a response
// (the name=value of each); empty when it set none. The IdMS may keep the authentication request in a cookie.
std::string cookie_header(const HttpResponse &response) {
  const auto found = response.headers.find("set-cookie");
  if (found == response.headers.end()) return {};
  std::string cookies;
  std::size_t start = 0;
  while (start <= found->second.size()) {
    const auto end = std::min(found->second.find('\n', start), found->second.size());
    const auto line = found->second.substr(start, end - start);
    const auto pair = line.substr(0, line.find(';'));
    if (pair.find('=') != std::string::npos && pair.find_first_of("\r\n") == std::string::npos) {
      if (!cookies.empty()) cookies += "; ";
      cookies += pair;
    }
    start = end + 1;
  }
  return cookies;
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.482 clause 6.2.1 and TS 33.180 annex B.4.2 (clauses B.4.2.2 to B.4.2.5), with the test view of TS 37.579-1
// table 5.3.2.3.1-1 steps 3a1 to 9: the OpenID Connect Authentication Request (an HTTP GET), the IdMS's HTML page
// with the user authentication form (table 5.3.2.3.2-5), the form posted to its action with the user name and
// password (table 5.5.4.3-1, condition USERAUTH) and the cookies the page set, the 302 (Found) to the redirect URI
// with the authorization code, and the code exchange. An IdMS that offers no form but the OpenMCX request ID (its
// scripted login of OpenMCX 1.0.0) is answered with POST {issuer}/login.
json oidc_login(const HttpClient &http, const json &cfg) {
  const std::string issuer = cfg.at("issuer"), redirect = cfg.at("redirect_uri");
  const auto request = oidc_authorization_request(http, cfg);
  const std::string state = request.at("state"), url = request.at("url");
  const std::string user = cfg.at("username"), password = cfg.at("password");
  const auto page = http.request("GET", url, {}, {{"Accept", "text/html, application/json;q=0.5"}});
  const auto type = lower(page.headers.contains("content-type") ? page.headers.at("content-type") : "");

  HttpResponse login;
  if (page.status == 200 && type.starts_with("text/html")) {
    const auto found = parse_html_form(page.body);
    if (!found) throw std::runtime_error("the IdMS page has no user authentication form");
    // A GET form would put the password in the URI.
    if (found->method != "post") throw std::runtime_error("the IdMS user authentication form is not a POST");
    std::map<std::string, std::string> headers{{"Content-Type", "application/x-www-form-urlencoded"}};
    if (const auto cookies = cookie_header(page); !cookies.empty()) headers["Cookie"] = cookies;
    login = http.request("POST", resolve_https_reference(url, found->action),
                         form(html_form_fields(*found, user, password)), headers);
  } else {
    const auto authorization = page.json();
    if (!authorization.contains("request_id"))
      throw std::runtime_error("the IdMS offers neither a user authentication form nor a request ID");
    login =
        http.request("POST", issuer + "/login",
                     form({{"request_id", authorization.at("request_id")}, {"username", user}, {"password", password}}),
                     {{"Content-Type", "application/x-www-form-urlencoded"}});
  }
  if (login.status != 302 || !login.headers.contains("location"))
    throw std::runtime_error("IdMS user authentication failed");
  auto location = login.headers.at("location");
  if (!location.starts_with(redirect + "?") || query_value(location, "state") != state)
    throw std::runtime_error("OIDC redirect or state mismatch");
  // RFC 6749 section 4.1.2.1: the IdMS refused the user (access_denied, for example).
  if (!query_value(location, "error").empty())
    throw std::runtime_error("IdMS user authentication failed: " + query_value(location, "error"));
  return oidc_exchange_code(http, cfg, query_value(location, "code"), request.at("code_verifier"), request.at("nonce"));
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

  const auto discovery = lazy_discovery(issuer, [&] {
    return transient([&] { return http.request("GET", issuer + "/.well-known/openid-configuration").json(); });
  });
  const auto token_endpoint = oidc_endpoint(cfg, "token_endpoint", discovery);

  const auto response = transient([&] {
    return http.request(
        "POST", token_endpoint,
        form({{"grant_type", "refresh_token"}, {"client_id", client}, {"refresh_token", refresh_token}}),
        {{"Content-Type", "application/x-www-form-urlencoded"}});
  });
  if (oidc_refresh_refusal(response)) throw oidc_refresh_refused("IdMS refused the refresh token (invalid_grant)");
  if (response.status != ok) throw oidc_refresh_failed("token refresh failed: HTTP " + std::to_string(response.status));

  auto tokens = bearer_token_response(response.json());
  // TS 33.180 table B.5.3-1: the ID token is optional. OpenID Connect Core 1.0 section 12.2: one given names the
  // same user, and its nonce, where given, is the authentication's.
  if (tokens.contains("id_token")) {
    auto keys = http.request("GET", oidc_endpoint(cfg, "jwks_uri", discovery)).json();
    tokens["claims"] = verify_id_token(tokens.at("id_token").get<std::string>(), keys, issuer, client, nonce, true);
  }
  tokens["nonce"] = nonce;
  return tokens;
}
} // namespace mcx
