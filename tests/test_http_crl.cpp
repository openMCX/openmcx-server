//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// CRL revocation verification of the HTTPS client (HttpClient with a CRL file), against an openssl s_server whose
// certificate a test CA issued: a valid CRL that does not list the server passes; a CRL listing it, an expired CRL,
// only another CA's CRL, and CRLs outside the TS 33.310 clause 6.1a profile (version 1, SHA-1, delta) fail.
//
// Specifications: TS 33.180 V19.5.0 (Rel-19) clause 6.1.1; TS 33.310 V19.5.0 (Rel-19) clauses 6.1.1, 6.1a, 7.6;
// RFC 5280 sections 5 and 6.3.
#include "mcx/http.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <vector>

namespace {

// An OpenSSL object owned with its free function.
template <typename Object, void (*Free)(Object *)> using OpenSsl = std::unique_ptr<Object, decltype(Free)>;

//------------------------------------------------------------------------------
// Helper: the call throws.
void expect_rejected(const char *what, const std::function<void()> &call) {
  try {
    call();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(std::string("accepted: ") + what);
}

//------------------------------------------------------------------------------
// Helper: a certificate or key read from a PEM file.
OpenSsl<X509, X509_free> read_certificate(const std::string &path) {
  std::FILE *file = std::fopen(path.c_str(), "r");
  if (!file) throw std::runtime_error("test certificate " + path);
  OpenSsl<X509, X509_free> certificate(PEM_read_X509(file, nullptr, nullptr, nullptr), X509_free);
  std::fclose(file);
  if (!certificate) throw std::runtime_error("test certificate " + path);
  return certificate;
}

OpenSsl<EVP_PKEY, EVP_PKEY_free> read_key(const std::string &path) {
  std::FILE *file = std::fopen(path.c_str(), "r");
  if (!file) throw std::runtime_error("test key " + path);
  OpenSsl<EVP_PKEY, EVP_PKEY_free> key(PEM_read_PrivateKey(file, nullptr, nullptr, nullptr), EVP_PKEY_free);
  std::fclose(file);
  if (!key) throw std::runtime_error("test key " + path);
  return key;
}

//------------------------------------------------------------------------------
// The CRL variants of the tests.
struct CrlSpec {
  long this_update_s = -60; // relative to now
  long next_update_s = 3600;
  const ASN1_INTEGER *revoked = nullptr;
  long version = X509_CRL_VERSION_2;
  const EVP_MD *(*digest)() = EVP_sha256;
  bool delta = false;
};

//------------------------------------------------------------------------------
// Helper: RFC 5280 section 5: a CRL of the issuer, in PEM.
std::string make_crl(X509 *issuer, EVP_PKEY *key, const CrlSpec &spec) {
  OpenSsl<X509_CRL, X509_CRL_free> crl(X509_CRL_new(), X509_CRL_free);
  OpenSsl<ASN1_TIME, ASN1_TIME_free> this_update(X509_time_adj_ex(nullptr, 0, spec.this_update_s, nullptr),
                                                  ASN1_TIME_free);
  OpenSsl<ASN1_TIME, ASN1_TIME_free> next_update(X509_time_adj_ex(nullptr, 0, spec.next_update_s, nullptr),
                                                  ASN1_TIME_free);
  bool ok = crl && this_update && next_update && X509_CRL_set_version(crl.get(), spec.version) == 1 &&
            X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer)) == 1 &&
            X509_CRL_set1_lastUpdate(crl.get(), this_update.get()) == 1 &&
            X509_CRL_set1_nextUpdate(crl.get(), next_update.get()) == 1;
  if (ok && spec.revoked) {
    X509_REVOKED *entry = X509_REVOKED_new();
    // X509_REVOKED_set_serialNumber copies the serial; its parameter is not const.
    ok = entry && X509_REVOKED_set_serialNumber(entry, const_cast<ASN1_INTEGER *>(spec.revoked)) == 1 &&
         X509_REVOKED_set_revocationDate(entry, this_update.get()) == 1 && X509_CRL_add0_revoked(crl.get(), entry) == 1;
    if (!ok) X509_REVOKED_free(entry);
  }
  if (ok && spec.version == X509_CRL_VERSION_2) {
    OpenSsl<ASN1_INTEGER, ASN1_INTEGER_free> number(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    ok = number && ASN1_INTEGER_set(number.get(), 2) == 1 &&
         X509_CRL_add1_ext_i2d(crl.get(), NID_crl_number, number.get(), 0, 0) == 1;
    if (ok && spec.delta) {
      ASN1_INTEGER_set(number.get(), 1);
      ok = X509_CRL_add1_ext_i2d(crl.get(), NID_delta_crl, number.get(), 1, 0) == 1;
    }
  }
  ok = ok && X509_CRL_sort(crl.get()) == 1 && X509_CRL_sign(crl.get(), key, spec.digest()) > 0;
  std::unique_ptr<BIO, decltype(&BIO_free)> out(BIO_new(BIO_s_mem()), BIO_free);
  ok = ok && out && PEM_write_bio_X509_CRL(out.get(), crl.get()) == 1;
  if (!ok) throw std::runtime_error("test CRL");
  char *data = nullptr;
  const long length = BIO_get_mem_data(out.get(), &data);
  return std::string(data, static_cast<std::size_t>(length));
}

//------------------------------------------------------------------------------
// Helper: writes a file.
void write(const std::string &path, const std::string &text) {
  std::FILE *file = std::fopen(path.c_str(), "w");
  if (!file || std::fwrite(text.data(), 1, text.size(), file) != text.size()) throw std::runtime_error("test file");
  std::fclose(file);
}

//------------------------------------------------------------------------------
// Helper: a free loopback TCP port.
int free_port() {
  const int probe = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t length = sizeof(address);
  if (probe < 0 || bind(probe, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
      getsockname(probe, reinterpret_cast<sockaddr *>(&address), &length) != 0)
    throw std::runtime_error("test port");
  close(probe);
  return ntohs(address.sin_port);
}

} // namespace

//------------------------------------------------------------------------------
int main() {
  const std::string dir = "/tmp/mcx-test-http-crl-" + std::to_string(getpid());
  // TS 33.310 clauses 6.1.4a and 6.1.3a: a CA (critical basic constraints CA, path length 0; critical keyCertSign and
  // cRLSign) and the server's certificate (critical digitalSignature, serverAuth, CRL distribution point); another CA.
  const std::string ca = " -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -addext"
                         " basicConstraints=critical,CA:TRUE,pathlen:0 -addext keyUsage=critical,keyCertSign,cRLSign";
  const std::string make =
      "mkdir -p " + dir + " && cd " + dir + " && openssl req -x509" + ca +
      " -subj '/O=OpenMCX test/CN=CRL test CA' -keyout ca.key -out ca.crt >/dev/null 2>&1 && openssl req -x509" + ca +
      " -subj '/O=OpenMCX test/CN=other CA' -keyout other.key -out other.crt >/dev/null 2>&1"
      " && openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj '/O=OpenMCX test/CN=crl.test'"
      " -keyout key.pem -out server.csr >/dev/null 2>&1 && printf '%s\\n' 'subjectAltName=DNS:crl.test'"
      " 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth'"
      " 'crlDistributionPoints=URI:http://crl.test/ca.crl' > server.ext && openssl x509 -req -in server.csr -CA ca.crt"
      " -CAkey ca.key -CAcreateserial -days 1 -extfile server.ext -out cert.pem >/dev/null 2>&1";
  if (std::system(make.c_str()) != 0) throw std::runtime_error("test certificates");
  const int port = free_port();
  const std::string serve = "cd " + dir + " && exec openssl s_server -quiet -www -accept 127.0.0.1:" +
                            std::to_string(port) + " -cert cert.pem -key key.pem >/dev/null 2>&1 & echo $! > " + dir +
                            "/server.pid";
  if (std::system(serve.c_str()) != 0) throw std::runtime_error("test server");
  std::this_thread::sleep_for(std::chrono::milliseconds(700));
  const auto stop = [&] {
    if (std::system(("kill $(cat " + dir + "/server.pid) 2>/dev/null; rm -rf " + dir).c_str()) != 0)
      std::cerr << "cleanup\n";
  };

  try {
    auto ca_cert = read_certificate(dir + "/ca.crt");
    auto ca_key = read_key(dir + "/ca.key");
    auto other_cert = read_certificate(dir + "/other.crt");
    auto other_key = read_key(dir + "/other.key");
    auto server = read_certificate(dir + "/cert.pem");
    const ASN1_INTEGER *serial = X509_get0_serialNumber(server.get());

    const std::string url = "https://crl.test:8443/", crl_file = dir + "/crl.pem";
    const mcx::HttpAddressMap map{{"crl.test:8443", "127.0.0.1:" + std::to_string(port)}};
    const auto get = [&](const std::string &crls) {
      return mcx::HttpClient(dir + "/ca.crt", {}, map, mcx::HttpTrust::configured, crls).request("GET", url).status;
    };
    if (get({}) != 200) throw std::runtime_error("the server was not reached without a CRL file");

    // RFC 5280 section 6.3.3: a current CRL of the issuer that does not list the certificate: unrevoked. The file
    // may hold several CRLs (here another CA's too).
    const auto valid = make_crl(ca_cert.get(), ca_key.get(), {});
    write(crl_file, make_crl(other_cert.get(), other_key.get(), {}) + valid);
    if (get(crl_file) != 200) throw std::runtime_error("a valid CRL not listing the server was refused");

    // TS 33.310 clause 5.2.12: the revoked certificate is listed in the CRL; the file is read again per request.
    write(crl_file, make_crl(ca_cert.get(), ca_key.get(), {.revoked = serial}));
    expect_rejected("a revoked server certificate", [&] { get(crl_file); });

    // TS 33.310 clause 7.6: "If no valid CRL can be fetched, the NE, SEG or TLS entity shall treat this as an error";
    // RFC 5280 section 6.3.3 (a)(1): a CRL past its next update is not current.
    write(crl_file, make_crl(ca_cert.get(), ca_key.get(), {.this_update_s = -7200, .next_update_s = -3600}));
    expect_rejected("an expired CRL", [&] { get(crl_file); });
    write(crl_file, make_crl(other_cert.get(), other_key.get(), {}));
    expect_rejected("no CRL of the server's CA", [&] { get(crl_file); });

    // TS 33.310 clause 6.1a: version 2 only, no SHA-1; clause 7.6: no delta CRL.
    write(crl_file, make_crl(ca_cert.get(), ca_key.get(), {.version = X509_CRL_VERSION_1}) + valid);
    expect_rejected("a version 1 CRL", [&] { get(crl_file); });
    write(crl_file, make_crl(ca_cert.get(), ca_key.get(), {.digest = EVP_sha1}) + valid);
    expect_rejected("a CRL signed with SHA-1", [&] { get(crl_file); });
    write(crl_file, make_crl(ca_cert.get(), ca_key.get(), {.delta = true}) + valid);
    expect_rejected("a delta CRL", [&] { get(crl_file); });
    write(crl_file, "");
    expect_rejected("a CRL file without a CRL", [&] { get(crl_file); });
    expect_rejected("a missing CRL file", [&] { get(dir + "/none.pem"); });

    write(crl_file, valid);
    if (get(crl_file) != 200) throw std::runtime_error("the valid CRL was refused after the refusals");
  } catch (...) {
    stop();
    throw;
  }
  stop();
  std::cout << "HTTPS CRL revocation tests passed\n";
  return 0;
}
