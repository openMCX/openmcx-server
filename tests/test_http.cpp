//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// HTTP client boundary and OIDC ID token validation: URI escaping, refusal of clear HTTP, and the RS256-signed ID
// token checked for signature, key use and algorithm, issuer, audience, nonce, lifetime and the MCX identity claims
// (TS 33.180 annexes B.2.1 and B.11.1).
//
// Specifications: TS 33.180 V19.4.0 (Rel-19); RFC 7519, RFC 7517, RFC 4648; OpenID Connect Core 1.0.
#include "mcx/http.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <type_traits>
#include <utility>

using nlohmann::json;

namespace {

// An OpenSSL object owned with its free function.
template <typename Object, void (*Free)(Object *)> using OpenSsl = std::unique_ptr<Object, decltype(Free)>;

//------------------------------------------------------------------------------
// RFC 4648 section 5: base64url without padding, as used by JWS and JWK.
std::string base64url(std::string_view bytes) {
  std::string result(4 * ((bytes.size() + 2) / 3), '\0');
  const auto size = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(result.data()),
                                    reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size());
  if (size < 0) throw std::runtime_error("base64 encoding failed");
  result.resize(static_cast<std::size_t>(size));
  while (!result.empty() && result.back() == '=') result.pop_back();
  for (auto &character : result) {
    if (character == '+')
      character = '-';
    else if (character == '/')
      character = '_';
  }
  return result;
}

//------------------------------------------------------------------------------
// RFC 7518 section 6.3.1: an RSA public key number as the base64url of its big-endian bytes.
std::string number(const BIGNUM *value) {
  std::string bytes(static_cast<std::size_t>(BN_num_bytes(value)), '\0');
  if (BN_bn2bin(value, reinterpret_cast<unsigned char *>(bytes.data())) != static_cast<int>(bytes.size()))
    throw std::runtime_error("RSA number encoding failed");
  return base64url(bytes);
}

//------------------------------------------------------------------------------
// A 2048-bit RSA key standing in for the IdM server's token signing key.
class SigningKey {
public:
  //------------------------------------------------------------------------------
  // Generates the RSA key.
  SigningKey() {
    OpenSsl<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
                                                     EVP_PKEY_CTX_free);
    EVP_PKEY *generated = nullptr;
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) != 1 || EVP_PKEY_generate(context.get(), &generated) != 1)
      throw std::runtime_error("RSA test key generation failed");
    key_.reset(generated);
  }

  //------------------------------------------------------------------------------
  // RFC 7517 section 5: the JWK Set with the public key, with the given "use" and "alg".
  json jwks(std::string use = "sig", std::string algorithm = "RS256") const {
    BIGNUM *raw_n = nullptr, *raw_e = nullptr;
    if (EVP_PKEY_get_bn_param(key_.get(), OSSL_PKEY_PARAM_RSA_N, &raw_n) != 1 ||
        EVP_PKEY_get_bn_param(key_.get(), OSSL_PKEY_PARAM_RSA_E, &raw_e) != 1) {
      BN_free(raw_n);
      BN_free(raw_e);
      throw std::runtime_error("RSA public key extraction failed");
    }
    OpenSsl<BIGNUM, BN_free> modulus(raw_n, BN_free), exponent(raw_e, BN_free);
    return {{"keys",
             {{{"kty", "RSA"},
               {"kid", "test-key"},
               {"use", std::move(use)},
               {"alg", std::move(algorithm)},
               {"n", number(modulus.get())},
               {"e", number(exponent.get())}}}}};
  }

  //------------------------------------------------------------------------------
  // RFC 7519: the claims as a JWT signed with RS256.
  std::string token(const json &claims) const {
    const auto header = json{{"alg", "RS256"}, {"typ", "JWT"}, {"kid", "test-key"}}.dump();
    const auto unsigned_token = base64url(header) + "." + base64url(claims.dump());
    OpenSsl<EVP_MD_CTX, EVP_MD_CTX_free> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    std::size_t signature_size = 0;
    if (!context || EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, key_.get()) != 1 ||
        EVP_DigestSign(context.get(), nullptr, &signature_size,
                       reinterpret_cast<const unsigned char *>(unsigned_token.data()), unsigned_token.size()) != 1)
      throw std::runtime_error("JWT test signature sizing failed");
    std::string signature(signature_size, '\0');
    if (EVP_DigestSign(context.get(), reinterpret_cast<unsigned char *>(signature.data()), &signature_size,
                       reinterpret_cast<const unsigned char *>(unsigned_token.data()), unsigned_token.size()) != 1)
      throw std::runtime_error("JWT test signing failed");
    signature.resize(signature_size);
    return unsigned_token + "." + base64url(signature);
  }

private:
  OpenSsl<EVP_PKEY, EVP_PKEY_free> key_{nullptr, EVP_PKEY_free};
};

//------------------------------------------------------------------------------
// TS 33.180 tables B.2.1.2-1 and B.2.1.3-1: the ID token standard claims and the mcptt_id claim, with the nonce.
// The client_id and sip_uri claims are an OpenMCX extension (not in those tables): the identity binding the OpenMCX
// IdMS adds and verify_id_token requires.
json valid_claims() {
  const auto now = std::time(nullptr);
  return {{"iss", "https://idms.example.test"},
          {"aud", "mcptt-client"},
          {"nonce", "test-nonce"},
          {"sub", "sip:alice@mcx.test"},
          {"mcptt_id", "sip:alice@mcx.test"},
          {"client_id", "urn:uuid:alice-device"},
          {"sip_uri", "sip:alice@ims.mcx.test"},
          {"iat", now},
          {"exp", now + 300}};
}

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.1: validates the ID token for the test's issuer, client and nonce.
void verify(const std::string &token, const json &keys) {
  (void)mcx::verify_id_token(token, keys, "https://idms.example.test", "mcptt-client", "test-nonce");
}

//------------------------------------------------------------------------------
// Checks that the function throws; name says what would have been wrongly accepted.
template <typename Function> void expect_rejected(std::string_view name, Function function) {
  try {
    function();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(std::string(name) + " was accepted");
}

} // namespace

//------------------------------------------------------------------------------
// HttpTimeouts: a server that accepts the connection and never answers ends the request after the configured total
// time, not after the default 5 s.
void configured_timeout() {
  const int listener = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t length = sizeof(address);
  if (listener < 0 || bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
      listen(listener, 1) != 0 || getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) != 0)
    throw std::runtime_error("silent server");
  const auto url = "https://127.0.0.1:" + std::to_string(ntohs(address.sin_port)) + "/";
  const auto start = std::chrono::steady_clock::now();
  expect_rejected("an answer after the total timeout",
                  [&] { mcx::HttpClient("unused", {.connect_ms = 300, .total_ms = 300}).request("GET", url); });
  const auto elapsed = std::chrono::steady_clock::now() - start;
  close(listener);
  if (elapsed > std::chrono::seconds(2)) throw std::runtime_error("the configured total timeout was not applied");
}

//------------------------------------------------------------------------------
// The address map and the pinned GET of an MCX Admin activation, against an openssl s_server whose certificate names
// pinned.test: a mapped request reaches 127.0.0.1 and passes the name check; a mapped name the certificate does not
// carry is refused; the certificate's pin is accepted, another pin refused; without a map nothing is mapped.
void address_map_and_pin() {
  const std::string dir = "/tmp/mcx-test-http-" + std::to_string(getpid());
  const std::string make = "mkdir -p " + dir + " && cd " + dir +
                           " && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1"
                           " -subj /CN=pinned.test -addext subjectAltName=DNS:pinned.test -keyout key.pem -out cert.pem"
                           " >/dev/null 2>&1 && openssl x509 -in cert.pem -outform DER | openssl dgst -sha256 -binary"
                           " | openssl base64 -A | tr '+/' '-_' | tr -d '=' > pin";
  if (std::system(make.c_str()) != 0) throw std::runtime_error("test certificate");
  int port = 0;
  {
    const int probe = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    bind(probe, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    getsockname(probe, reinterpret_cast<sockaddr *>(&address), &length);
    port = ntohs(address.sin_port);
    close(probe);
  }
  const std::string serve = "cd " + dir + " && exec openssl s_server -quiet -www -accept 127.0.0.1:" +
                            std::to_string(port) + " -cert cert.pem -key key.pem >/dev/null 2>&1 & echo $! > " + dir +
                            "/server.pid";
  if (std::system(serve.c_str()) != 0) throw std::runtime_error("test server");
  std::this_thread::sleep_for(std::chrono::milliseconds(700));
  std::string pin;
  {
    std::FILE *file = std::fopen((dir + "/pin").c_str(), "r");
    char buffer[128] = {};
    if (!file || !std::fgets(buffer, sizeof buffer, file)) throw std::runtime_error("test pin");
    std::fclose(file);
    pin = buffer;
    while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) pin.pop_back();
  }
  const auto stop = [&] {
    if (std::system(("kill $(cat " + dir + "/server.pid) 2>/dev/null; rm -rf " + dir).c_str()) != 0) std::cerr << "cleanup\n";
  };
  try {
    const std::string here = "127.0.0.1:" + std::to_string(port);
    const mcx::HttpClient mapped(dir + "/cert.pem", {}, {{"pinned.test:8443", here}});
    if (mapped.request("GET", "https://pinned.test:8443/").status != 200)
      throw std::runtime_error("the mapped request did not reach the server");
    expect_rejected("a mapped name the certificate does not carry", [&] {
      mcx::HttpClient(dir + "/cert.pem", {}, {{"other.test:8443", here}}).request("GET", "https://other.test:8443/");
    });
    expect_rejected("an unmapped name", [&] {
      mcx::HttpClient(dir + "/cert.pem", {.connect_ms = 500, .total_ms = 1000}).request("GET", "https://pinned.test:8443/");
    });
    expect_rejected("a malformed address map", [&] { mcx::HttpClient(dir + "/cert.pem", {}, {{"pinned.test", here}}); });
    if (mcx::http_get_pinned("https://" + here + "/", pin).status != 200)
      throw std::runtime_error("the pinned certificate was refused");
    std::string other = pin;
    other[0] = other[0] == 'A' ? 'B' : 'A';
    expect_rejected("another pin", [&] { mcx::http_get_pinned("https://" + here + "/", other); });
    expect_rejected("a pin that is not a SHA-256", [&] { mcx::http_get_pinned("https://" + here + "/", "AAAA"); });
  } catch (...) {
    stop();
    throw;
  }
  stop();
}

//------------------------------------------------------------------------------
// TS 33.180 clause 6.1.2 and annex B.11.1: clear HTTP is refused; a valid ID token returns its claims, and a token
// with another subject, an empty identity binding, a wrong issuer, audience or nonce, an expired or not yet valid
// lifetime, a changed signature, an encryption key or another key algorithm is refused.
int main() {
  if (mcx::url_encode("sip:a+b@example.test") != "sip%3Aa%2Bb%40example.test") throw std::runtime_error("URI escaping");
  expect_rejected("clear HTTP", [] { mcx::HttpClient("unused").request("GET", "http://localhost/"); });
  configured_timeout();
  address_map_and_pin();

  SigningKey key;
  const auto keys = key.jwks();
  const auto claims = valid_claims();
  const auto token = key.token(claims);
  const auto verified = mcx::verify_id_token(token, keys, "https://idms.example.test", "mcptt-client", "test-nonce");
  if (verified.at("mcptt_id") != "sip:alice@mcx.test") throw std::runtime_error("valid signed JWT claims not returned");

  auto changed = claims;
  changed["sub"] = "sip:mallory@mcx.test";
  expect_rejected("mismatched subject binding", [&] { verify(key.token(changed), keys); });

  changed = claims;
  changed["client_id"] = "";
  expect_rejected("empty identity binding", [&] { verify(key.token(changed), keys); });

  changed = claims;
  changed["iss"] = "https://attacker.example.test";
  expect_rejected("wrong issuer", [&] { verify(key.token(changed), keys); });
  changed = claims;
  changed["aud"] = "other-client";
  expect_rejected("wrong audience", [&] { verify(key.token(changed), keys); });
  changed = claims;
  changed["nonce"] = "other-nonce";
  expect_rejected("wrong nonce", [&] { verify(key.token(changed), keys); });
  changed = claims;
  changed["exp"] = std::time(nullptr) - 1;
  expect_rejected("expired token", [&] { verify(key.token(changed), keys); });
  changed = claims;
  changed["nbf"] = std::time(nullptr) + 300;
  expect_rejected("future not-before", [&] { verify(key.token(changed), keys); });

  auto mutated = token;
  const auto signature = mutated.rfind('.') + 1;
  mutated[signature] = mutated[signature] == 'A' ? 'B' : 'A';
  expect_rejected("mutated signature", [&] { verify(mutated, keys); });
  expect_rejected("encryption JWK", [&] { verify(token, key.jwks("enc", "RS256")); });
  expect_rejected("wrong-algorithm JWK", [&] { verify(token, key.jwks("sig", "RS512")); });

  // Refused for its form, not for a missing key: the key set is the valid one.
  expect_rejected("malformed token", [&] { verify("e30.e30.invalid", keys); });
  expect_rejected("token without signature", [&] { verify(token.substr(0, token.rfind('.')), keys); });

  // TS 33.180 annex B.11.1 with a 30 s clock skew allowance: an ID token issued up to 30 s ahead of the local clock
  // is accepted, one issued further ahead is refused.
  changed = claims;
  changed["iat"] = std::time(nullptr) + 20;
  verify(key.token(changed), keys);
  changed["iat"] = std::time(nullptr) + 60;
  expect_rejected("issued-at beyond the clock skew", [&] { verify(key.token(changed), keys); });

  // RFC 6749 section 5.2 and TS 33.180 annex B.5: only "invalid_grant" refuses the refresh token; another error, a
  // server error or an unparsable body leaves it valid (oidc_refresh then throws the retryable oidc_refresh_failed).
  const auto refusal = [](long status, std::string body) {
    mcx::HttpResponse response;
    response.status = status;
    response.body = std::move(body);
    return mcx::oidc_refresh_refusal(response);
  };
  if (!refusal(400, R"({"error":"invalid_grant"})") || !refusal(401, R"({"error":"invalid_grant"})"))
    throw std::runtime_error("invalid_grant not taken as a refusal");
  if (refusal(401, R"({"error":"invalid_client"})") || refusal(400, R"({"error":"invalid_request"})") ||
      refusal(401, "") || refusal(400, "not json") || refusal(503, R"({"error":"invalid_grant"})") ||
      refusal(400, R"({"error":42})"))
    throw std::runtime_error("a transient refresh failure taken as a refusal");
  static_assert(std::is_base_of_v<std::runtime_error, mcx::oidc_refresh_failed> &&
                !std::is_base_of_v<mcx::oidc_refresh_refused, mcx::oidc_refresh_failed>);
  if (mcx::random_id() == mcx::random_id()) throw std::runtime_error("nonce collision");
  std::cout << "HTTPS and signed token boundary tests passed\n";
}
