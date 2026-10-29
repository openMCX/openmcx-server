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
  // RFC 7519: the claims as a JWT signed with RS256, under the given JOSE header (RFC 7515 section 4).
  std::string token(const json &claims,
                    const json &jose = json{{"alg", "RS256"}, {"typ", "JWT"}, {"kid", "test-key"}}) const {
    const auto header = jose.dump();
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
// IdMS adds, which verify_id_token checks where it is given.
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

//------------------------------------------------------------------------------
// TS 33.180 annex B.11.2 with tables B.2.2.2-1 and B.2.2.3-1: an access token of another IdMS (a subject of its own,
// the MC servers among other audiences, no OpenMCX claims) is accepted, and so is one without iss or aud (RFC 7519
// sections 4.1.1 and 4.1.3: checked "when this claim is present"), as the access token of the annex B.4.2.5 example;
// one without scope, client_id or exp, of another issuer or audience, expired or of an unknown key is not.
void access_tokens(const SigningKey &key, const json &keys) {
  const auto now = std::time(nullptr);
  const json claims = {{"iss", "https://idms.example.test"},
                       {"sub", "6f1c2a9e-2b5d-4c1e-9a43-0d7d1f1e2b3c"},
                       {"aud", json::array({"account", "mcx-servers"})},
                       {"azp", "mcptt-client"},
                       {"client_id", "mcptt-client"},
                       {"scope", "openid 3gpp:mc:ptt_service"},
                       {"mcptt_id", "sip:alice@mcx.test"},
                       {"iat", now},
                       {"exp", now + 300}};
  const auto check = [&key, &keys](const json &changed) {
    return mcx::verify_access_token(key.token(changed), keys, "https://idms.example.test", "mcx-servers");
  };
  if (check(claims).at("mcptt_id") != "sip:alice@mcx.test") throw std::runtime_error("access token refused");
  auto changed = claims;
  changed["aud"] = "mcx-servers";
  changed.erase("iat");
  (void)check(changed);
  for (const auto *name : {"scope", "client_id", "exp"}) {
    changed = claims;
    changed.erase(name);
    expect_rejected(std::string("an access token without ") + name, [&] { (void)check(changed); });
  }
  // TS 33.180 annex B.4.2.5: the example access token has mcptt_id, exp, scope and client_id only.
  const json example = {{"mcptt_id", "sip:alice@mcx.test"},
                        {"exp", now + 300},
                        {"scope", "openid 3gpp:mc:ptt_service"},
                        {"client_id", "mcptt_client"}};
  if (check(example).at("mcptt_id") != "sip:alice@mcx.test") throw std::runtime_error("B.4.2.5 access token refused");
  for (const auto *name : {"iss", "aud"}) {
    changed = claims;
    changed.erase(name);
    (void)check(changed);
  }
  changed = claims;
  changed["iss"] = nullptr;
  expect_rejected("an access token with a null issuer", [&] { (void)check(changed); });
  changed = claims;
  changed["iss"] = "https://other.example.test";
  expect_rejected("an access token of another issuer", [&] { (void)check(changed); });
  changed = claims;
  changed["aud"] = json::array({"account"});
  expect_rejected("an access token for another audience", [&] { (void)check(changed); });
  changed = claims;
  changed["exp"] = now - 1;
  expect_rejected("an expired access token", [&] { (void)check(changed); });
  // TS 33.180 annex B.11.2, RFC 7519 section 7.2: no rule compares an access token's iat with the clock; a NumericDate
  // ahead of it is accepted, an iat that is not one (section 4.1.6) is not.
  changed = claims;
  changed["iat"] = now + 3600;
  (void)check(changed);
  changed["iat"] = "now";
  expect_rejected("an access token with a non-numeric iat", [&] { (void)check(changed); });
  auto other = keys;
  other["keys"][0]["kid"] = "rotated";
  try {
    (void)mcx::verify_access_token(key.token(claims), other, "https://idms.example.test", "mcx-servers");
    throw std::runtime_error("a token of an unknown key accepted");
  } catch (const mcx::oidc_unknown_signing_key &) {}
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
// TS 24.482 annex A.2.1.2 with RFC 9112 section 3.2.2: through the home HTTP proxy (an openssl s_server whose
// certificate names proxy.test), the TLS tunnel is checked against the proxy's FQDN and not against the target's,
// https and http targets both go through it, and the request line carries the target URI in absolute-form with the
// target's authority in Host; a proxy URI with more than FQDN and port, and a target that is no http(s) URI, are refused.
void home_http_proxy() {
  const std::string dir = "/tmp/mcx-test-proxy-" + std::to_string(getpid());
  const std::string make = "mkdir -p " + dir + " && cd " + dir +
                           " && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1"
                           " -subj /CN=proxy.test -addext subjectAltName=DNS:proxy.test -keyout key.pem -out cert.pem"
                           " >/dev/null 2>&1";
  if (std::system(make.c_str()) != 0) throw std::runtime_error("test certificate");
  const auto free_port = [] {
    const int probe = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    bind(probe, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    getsockname(probe, reinterpret_cast<sockaddr *>(&address), &length);
    close(probe);
    return std::to_string(ntohs(address.sin_port));
  };
  // One server answers every GET (-www); the other answers nothing and records what it receives.
  const auto answering = free_port(), recording = free_port();
  const std::string serve =
      "cd " + dir + " && (openssl s_server -quiet -www -accept 127.0.0.1:" + answering +
      " -cert cert.pem -key key.pem >/dev/null 2>&1 & echo $! > www.pid) && (sleep 30 | openssl s_server -quiet"
      " -naccept 1 -accept 127.0.0.1:" + recording + " -cert cert.pem -key key.pem > received 2>/dev/null &"
      " echo $! > raw.pid)";
  if (std::system(serve.c_str()) != 0) throw std::runtime_error("test servers");
  std::this_thread::sleep_for(std::chrono::milliseconds(700));
  const auto stop = [&] {
    if (std::system(("kill $(cat " + dir + "/www.pid) $(cat " + dir + "/raw.pid) 2>/dev/null; rm -rf " + dir).c_str()) != 0)
      std::cerr << "cleanup\n";
  };
  try {
    mcx::HttpClient proxied(dir + "/cert.pem", {}, {{"proxy.test:8443", "127.0.0.1:" + answering}});
    proxied.use_proxy("https://proxy.test:8443");
    if (proxied.request("GET", "https://kms.test/keymanagement/identity/v1/init").status != 200)
      throw std::runtime_error("an https target through the proxy refused");
    if (proxied.request("GET", "http://xcap.cms.test/xcap-root/x").status != 200)
      throw std::runtime_error("an http target through the proxy refused");
    expect_rejected("a target that is no http(s) URI", [&] { proxied.request("GET", "ftp://kms.test/"); });
    expect_rejected("a target with a space", [&] { proxied.request("GET", "https://kms.test/a b"); });
    expect_rejected("a target with userinfo", [&] { proxied.request("GET", "https://user@kms.test/"); });
    mcx::HttpClient misnamed(dir + "/cert.pem", {}, {{"other.test:8443", "127.0.0.1:" + answering}});
    misnamed.use_proxy("https://other.test:8443/");
    expect_rejected("a proxy whose certificate does not carry its FQDN",
                    [&] { misnamed.request("GET", "https://proxy.test/"); });
    for (const auto *uri : {"http://proxy.test:8443", "https://proxy.test:8443/path", "https://u@proxy.test", "proxy.test"})
      expect_rejected(std::string("the proxy URI ") + uri, [&] { mcx::HttpClient(dir + "/cert.pem").use_proxy(uri); });

    mcx::HttpClient recorded(dir + "/cert.pem", {.connect_ms = 1000, .total_ms = 1500},
                             {{"proxy.test:443", "127.0.0.1:" + recording}});
    recorded.use_proxy("https://proxy.test");
    expect_rejected("an answer from the recording server",
                    [&] { recorded.request("GET", "https://kms.test:8443/keymanagement/identity/v1/init?x=1"); });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    std::string received;
    {
      std::FILE *file = std::fopen((dir + "/received").c_str(), "r");
      char buffer[4096] = {};
      if (!file) throw std::runtime_error("nothing recorded");
      received.assign(buffer, std::fread(buffer, 1, sizeof buffer - 1, file));
      std::fclose(file);
    }
    if (!received.starts_with("GET https://kms.test:8443/keymanagement/identity/v1/init?x=1 HTTP/1.1\r\n"))
      throw std::runtime_error("request line not in absolute-form: " + received.substr(0, 120));
    if (received.find("\r\nHost: kms.test:8443\r\n") == received.npos || received.find("Host: proxy.test") != received.npos)
      throw std::runtime_error("Host is not the target's authority: " + received.substr(0, 300));
  } catch (...) {
    stop();
    throw;
  }
  stop();
}

//------------------------------------------------------------------------------
// TS 37.579-1 table 5.3.2.3.2-5 and HTML 4.01 section 17: the IdMS's user authentication form is read, its fields
// filled and its action resolved: the form of the test view, the OpenMCX IdMS's form (hidden inputs, relative
// action) and a third-party form (character references, cookies, an unchecked box, script); malformed or unfillable
// forms are refused.
void html_forms() {
  const auto form = mcx::parse_html_form(
      "<!DOCTYPE html>\n<html>\n<body>\n<form action=\"/idms/userauth\" method=\"post\">\nUsername: <input "
      "type=\"text\" name=\"user\"><br>\nPassword: <input type=\"password\" name=\"password\"><button "
      "type=\"submit\">Login</button>\n</form>\n\n</body>\n</html>");
  if (!form || form->action != "/idms/userauth" || form->method != "post" || form->inputs.size() != 2)
    throw std::runtime_error("the test view's form not read");
  const auto fields = mcx::html_form_fields(*form, "alice", "s3cret&=");
  if (fields != std::map<std::string, std::string>{{"user", "alice"}, {"password", "s3cret&="}})
    throw std::runtime_error("the test view's form fields");
  if (mcx::resolve_https_reference("https://idms.example.test:8443/authorize?client_id=x", form->action) !=
      "https://idms.example.test:8443/idms/userauth")
    throw std::runtime_error("absolute-path action");

  const auto openmcx = mcx::parse_html_form(
      "<form method=\"post\" action=\"login\"><input type=\"hidden\" name=\"request_id\" value=\"r&amp;1\"><input "
      "type=\"hidden\" name=\"html\" value=\"1\"><label>User name<input name=\"username\" required autofocus>"
      "</label><label>Password<input type=\"password\" name=\"password\" required></label><button "
      "type=\"submit\">Sign in</button></form>");
  if (!openmcx || mcx::html_form_fields(*openmcx, "bob", "pw") !=
                      std::map<std::string, std::string>{
                          {"request_id", "r&1"}, {"html", "1"}, {"username", "bob"}, {"password", "pw"}})
    throw std::runtime_error("the OpenMCX IdMS form fields");
  if (mcx::resolve_https_reference("https://idms.test/idms/authorize?x=1#f", "login") != "https://idms.test/idms/login")
    throw std::runtime_error("relative-path action");

  const auto third = mcx::parse_html_form(
      "<html><head><script>if (a < b) { document.write('<form>'); }</script></head><body><!-- <form> -->"
      "<FORM id=kc onsubmit=\"x()\" ACTION=\"https://kc.test/realms/mcx/login-actions/authenticate?session_code=a"
      "&amp;execution=b\" METHOD=POST><input id=username name=username type=email value=\"\"/><input "
      "id=password name=password type=password /><input type=checkbox name=rememberMe><input type=hidden "
      "id=id-hidden-input name=credentialId value='c&#x41;&#66;'><input type=submit name=login value=Sign></FORM>");
  if (!third || third->method != "post" ||
      third->action != "https://kc.test/realms/mcx/login-actions/authenticate?session_code=a&execution=b" ||
      mcx::html_form_fields(*third, "carol", "pw") !=
          std::map<std::string, std::string>{{"username", "carol"}, {"password", "pw"}, {"credentialId", "cAB"}})
    throw std::runtime_error("a third-party form");
  if (mcx::parse_html_form("<html><body><p>no form</p></body></html>"))
    throw std::runtime_error("a form found in a page without one");
  if (mcx::resolve_https_reference("https://a.test/x/y", "") != "https://a.test/x/y" ||
      mcx::resolve_https_reference("https://a.test/x/y", "?s=1") != "https://a.test/x/y?s=1" ||
      mcx::resolve_https_reference("https://a.test/x/y", "//b.test/z") != "https://b.test/z" ||
      mcx::resolve_https_reference("https://a.test", "z") != "https://a.test/z")
    throw std::runtime_error("reference resolution");

  expect_rejected("two forms", [] { mcx::parse_html_form("<form></form><form></form>"); });
  expect_rejected("an unterminated form", [] { mcx::parse_html_form("<form action=x><input name=a>"); });
  expect_rejected("an unterminated tag", [] { mcx::parse_html_form("<form action=\"x"); });
  expect_rejected("a select control", [] { mcx::parse_html_form("<form><select name=s></select></form>"); });
  expect_rejected("a file input", [] { mcx::parse_html_form("<form><input type=file name=f></form>"); });
  expect_rejected("an invalid character reference", [] { mcx::parse_html_form("<form action=\"&#xZZ;\"></form>"); });
  const auto two = mcx::parse_html_form("<form><input name=a><input name=b><input type=password name=p></form>");
  expect_rejected("two user name inputs", [&] { mcx::html_form_fields(*two, "u", "p"); });
  const auto none = mcx::parse_html_form("<form><input name=a></form>");
  expect_rejected("no password input", [&] { mcx::html_form_fields(*none, "u", "p"); });
  const auto twice =
      mcx::parse_html_form("<form><input type=hidden name=a><input name=a><input type=password name=p></form>");
  expect_rejected("a repeated control name", [&] { mcx::html_form_fields(*twice, "u", "p"); });
  expect_rejected("an action of another scheme", [] { mcx::resolve_https_reference("https://a.test/", "http://b/"); });
  expect_rejected("a javascript action", [] { mcx::resolve_https_reference("https://a.test/", "javascript:x()"); });
  expect_rejected("a dot segment", [] { mcx::resolve_https_reference("https://a.test/x/", "../login"); });
}

//------------------------------------------------------------------------------
// TS 33.180 clause 6.1.2 and annex B.11.1: clear HTTP is refused; a valid ID token returns its claims, and a token
// without a subject or MCPTT ID, an empty identity binding, a wrong issuer, audience or nonce, an expired or not yet valid
// lifetime, a changed signature, an encryption key or another key algorithm is refused.
//------------------------------------------------------------------------------
// TS 24.484 clause 7.2.2.7 item 4: the configured <idms-auth-endpoint> and <idms-token-endpoint> (and a configured
// JWKS URI) are used as given, without the discovery document; one not configured comes from the issuer's discovery
// document; a configured endpoint that is not https, or a discovery document of another issuer, is refused.
void configured_idms_endpoints() {
  int fetched = 0;
  const auto discovery = [&] {
    ++fetched;
    return json{{"issuer", "https://idms.test"},
                {"authorization_endpoint", "https://idms.test/authorize"},
                {"token_endpoint", "https://idms.test/token"},
                {"jwks_uri", "https://idms.test/jwks"}};
  };
  const json cfg{{"issuer", "https://idms.test"},
                 {"idms_auth_endpoint", "https://idms-auth.test:8443/idms/auth"},
                 {"idms_token_endpoint", "https://idms-token.test:8443/idms/token"}};
  if (mcx::oidc_endpoint(cfg, "authorization_endpoint", discovery) != "https://idms-auth.test:8443/idms/auth" ||
      mcx::oidc_endpoint(cfg, "token_endpoint", discovery) != "https://idms-token.test:8443/idms/token" || fetched != 0)
    throw std::runtime_error("configured IdMS endpoints not used as given");
  if (mcx::oidc_endpoint(cfg, "jwks_uri", discovery) != "https://idms.test/jwks" || fetched != 1)
    throw std::runtime_error("JWKS URI not taken from discovery");
  auto with_jwks = cfg;
  with_jwks["jwks_uri"] = "https://idms.test/keys";
  if (mcx::oidc_endpoint(with_jwks, "jwks_uri", discovery) != "https://idms.test/keys" || fetched != 1)
    throw std::runtime_error("configured JWKS URI not used");
  if (mcx::oidc_endpoint(json{{"issuer", "https://idms.test"}}, "token_endpoint", discovery) !=
      "https://idms.test/token")
    throw std::runtime_error("token endpoint not taken from discovery");
  auto clear = cfg;
  clear["idms_token_endpoint"] = "http://idms.test/token";
  expect_rejected("a configured clear HTTP token endpoint",
                  [&] { mcx::oidc_endpoint(clear, "token_endpoint", discovery); });
  expect_rejected("a discovery document of another issuer", [&] {
    mcx::oidc_endpoint(json{{"issuer", "https://other.test"}}, "token_endpoint", discovery);
  });
}

int main() {
  configured_idms_endpoints();
  if (mcx::url_encode("sip:a+b@example.test") != "sip%3Aa%2Bb%40example.test") throw std::runtime_error("URI escaping");
  expect_rejected("clear HTTP", [] { mcx::HttpClient("unused").request("GET", "http://localhost/"); });
  configured_timeout();
  address_map_and_pin();
  home_http_proxy();
  html_forms();

  SigningKey key;
  const auto keys = key.jwks();
  const auto claims = valid_claims();
  const auto token = key.token(claims);
  const auto verified = mcx::verify_id_token(token, keys, "https://idms.example.test", "mcptt-client", "test-nonce");
  if (verified.at("mcptt_id") != "sip:alice@mcx.test") throw std::runtime_error("valid signed JWT claims not returned");

  // TS 33.180 table B.2.1.2-1: sub is any identifier IdMS never reassigns (a third-party IdMS gives a UUID), and
  // an IdMS other than OpenMCX's names no client_id or sip_uri.
  auto changed = claims;
  changed["sub"] = "6f1c2a9e-2b5d-4c1e-9a43-0d7d1f1e2b3c";
  changed.erase("client_id");
  changed.erase("sip_uri");
  if (mcx::verify_id_token(key.token(changed), keys, "https://idms.example.test", "mcptt-client", "test-nonce")
          .at("mcptt_id") != "sip:alice@mcx.test")
    throw std::runtime_error("third-party ID token refused");

  changed = claims;
  changed.erase("sub");
  expect_rejected("no subject", [&] { verify(key.token(changed), keys); });
  changed = claims;
  changed.erase("mcptt_id");
  expect_rejected("no MCPTT ID", [&] { verify(key.token(changed), keys); });

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

  // OpenID Connect Core 1.0 section 3.1.3.7 step 3: an audience list of the client alone is accepted; one with an
  // additional audience is refused, azp or not (this client trusts no other audience), and so is one without the
  // client.
  changed = claims;
  changed["aud"] = json::array({"mcptt-client"});
  verify(key.token(changed), keys);
  changed["aud"] = json::array({"mcptt-client", "account"});
  changed["azp"] = "mcptt-client";
  expect_rejected("an additional audience", [&] { verify(key.token(changed), keys); });
  changed["aud"] = json::array({"account"});
  expect_rejected("an audience list without the client", [&] { verify(key.token(changed), keys); });

  // RFC 7515 section 4.1.11: a "crit" header parameter names an extension this verifier does not understand.
  expect_rejected("a critical header parameter", [&] {
    verify(key.token(claims, {{"alg", "RS256"}, {"kid", "test-key"}, {"crit", {"exp"}}, {"exp", 1}}), keys);
  });
  // OpenID Connect Core 1.0 section 10.1: without kid, the JWK Set's only key verifies the token; with several keys
  // the token must name one.
  const auto unnamed = key.token(claims, {{"alg", "RS256"}, {"typ", "JWT"}});
  verify(unnamed, keys);
  auto two = keys;
  two["keys"].push_back(keys.at("keys").at(0));
  two["keys"][1]["kid"] = "second-key";
  expect_rejected("a token without kid for two keys", [&] { verify(unnamed, two); });
  verify(token, two);

  access_tokens(key, keys);

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
