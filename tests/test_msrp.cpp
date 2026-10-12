//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MSRP framing (RFC 4975) as TS 24.582 uses it: URIs, SEND and responses, chunking, multipart MCData
// bodies, endpoints over TCP and TLS, and the MSRP SDP of the MCData media plane.
//
// Specifications: TS 24.582 V19.0.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 4975, RFC 6135, RFC 4567.

#include "mcx/msrp.hpp"
#include "mcx/protocol.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>

namespace {
int failures = 0;

//------------------------------------------------------------------------------
// Counts a failure, printing what, when condition is false.
void check(bool condition, const char *what) {
  if (!condition) {
    std::cerr << "FAILED: " << what << '\n';
    ++failures;
  }
}

//------------------------------------------------------------------------------
// Counts a failure when fn does not throw: the input it builds or parses must be refused.
template <typename Action> void rejects(Action &&fn, const char *what) {
  try {
    fn();
    std::cerr << "FAILED to reject: " << what << '\n';
    ++failures;
  } catch (const std::exception &) {
    // The expected refusal.
  }
}

//------------------------------------------------------------------------------
// A throwaway PKI for the TLS tests: a CA, and certificates it issues with one
// DNS subject alternative name, written as PEM files to a temporary directory.
struct Pki {
  std::string dir;
  EVP_PKEY *ca_key = nullptr;
  X509 *ca = nullptr;

  //------------------------------------------------------------------------------
  // Issues a certificate for name signed by issuer (self-signed CA when issuer is null).
  static X509 *issue(EVP_PKEY *key, const std::string &name, X509 *issuer, EVP_PKEY *issuer_key) {
    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), std::rand() + 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert), 86400);
    X509_set_pubkey(cert, key);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(name.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert, issuer ? X509_get_subject_name(issuer) : X509_get_subject_name(cert));
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer ? issuer : cert, cert, nullptr, nullptr, 0);
    const auto add = [&](int nid, const std::string &value) {
      X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
      X509_add_ext(cert, ext, -1);
      X509_EXTENSION_free(ext);
    };
    add(NID_basic_constraints, issuer ? "CA:FALSE" : "critical,CA:TRUE");
    if (issuer) add(NID_subject_alt_name, "DNS:" + name);
    X509_sign(cert, issuer_key ? issuer_key : key, EVP_sha256());
    return cert;
  }

  //------------------------------------------------------------------------------
  // Writes cert, and key when given, as PEM files <file>.crt and <file>.key in dir.
  void write(const std::string &file, X509 *cert, EVP_PKEY *key) {
    const auto pem = [&](const std::string &name, const auto &print) {
      struct Close {
        void operator()(FILE *file) const { std::fclose(file); }
      };
      const std::unique_ptr<FILE, Close> out(std::fopen((dir + "/" + name).c_str(), "w"));
      if (!out || print(out.get()) != 1) throw std::runtime_error("cannot write test PEM file " + name);
    };
    pem(file + ".crt", [&](FILE *out) { return PEM_write_X509(out, cert); });
    if (!key) return;
    pem(file + ".key",
        [&](FILE *out) { return PEM_write_PrivateKey(out, key, nullptr, nullptr, 0, nullptr, nullptr); });
  }

  //------------------------------------------------------------------------------
  // Creates the temporary directory and the CA, written as ca.crt.
  explicit Pki(const std::string &prefix) {
    char path[] = "/tmp/msrp-tls-XXXXXX";
    if (mkdtemp(path) == nullptr) throw std::runtime_error("cannot create the test PKI directory");
    dir = path;
    ca_key = EVP_EC_gen("P-256");
    ca = issue(ca_key, prefix + " test CA", nullptr, nullptr);
    write("ca", ca, nullptr);
  }

  //------------------------------------------------------------------------------
  // Frees the CA and removes the temporary directory with its files.
  ~Pki() {
    X509_free(ca);
    EVP_PKEY_free(ca_key);
    std::error_code ignored;
    std::filesystem::remove_all(dir, ignored);
  }

  Pki(const Pki &) = delete;
  Pki &operator=(const Pki &) = delete;

  //------------------------------------------------------------------------------
  // Issues a key and certificate for name and returns the TLS configuration using them, expecting the peer
  // name expected.
  mcx::msrp::TlsConfig entity(const std::string &name, const std::string &expected = {}) {
    EVP_PKEY *key = EVP_EC_gen("P-256");
    X509 *cert = issue(key, name, ca, ca_key);
    write(name, cert, key);
    X509_free(cert);
    EVP_PKEY_free(key);
    return {dir + "/ca.crt", dir + "/" + name + ".crt", dir + "/" + name + ".key", expected};
  }
};
} // namespace

//------------------------------------------------------------------------------
// RFC 4975 framing and TS 24.582 clause 6.1.1.2 MSRP handling, and TS 24.282 clause 9.2.3.2 MSRP SDP.
int main() {
  using namespace mcx::msrp;
  // MSRP URIs (RFC 4975 section 6).
  const auto uri = parse_uri("msrp://mcdata-server:2855/kjhd37s2s20w2a;tcp");
  check(uri.host == "mcdata-server" && uri.port == 2855 && uri.session == "kjhd37s2s20w2a" && !uri.secure,
        "MSRP URI parsing");
  check(uri.text() == "msrp://mcdata-server:2855/kjhd37s2s20w2a;tcp", "MSRP URI round trip");
  check(parse_uri("msrps://host/abc;tcp").secure, "MSRP over TLS scheme");
  rejects([] { (void)parse_uri("sip:alice@mcx.test"); }, "a URI that is not MSRP");
  rejects([] { (void)parse_uri("msrp://host/abc"); }, "an MSRP URI without a transport");

  // A SEND request with one body, and its 200 response.
  Message send;
  send.transaction = "a786hjs2";
  send.method = "SEND";
  send.message_id = "87652491";
  send.to_path = {parse_uri("msrp://mcdata-server:2855/abcd;tcp")};
  send.from_path = {parse_uri("msrp://client-a:7654/efgh;tcp")};
  send.content_type = "application/vnd.3gpp.mcdata-signalling";
  send.body = std::string("\x01\x02\x03", 3);
  send.range_start = 1;
  send.range_end = 3;
  send.total = 3;
  const auto wire = encode(send);
  check(wire.rfind("MSRP a786hjs2 SEND\r\n", 0) == 0 && wire.find("\r\nByte-Range: 1-3/3\r\n") != std::string::npos &&
            wire.find("\r\n-------a786hjs2$\r\n") != std::string::npos,
        "SEND encoding with the end-line and continuation flag");
  Message decoded;
  check(decode(wire, decoded) == wire.size() && decoded.method == "SEND" && decoded.body == send.body &&
            decoded.complete && decoded.to_path.front().session == "abcd" && decoded.message_id == "87652491",
        "SEND decoding");

  Message response;
  response.transaction = send.transaction;
  response.status = 200;
  response.comment = "OK";
  response.to_path = send.from_path;
  response.from_path = send.to_path;
  const auto answer = encode(response);
  check(answer.rfind("MSRP a786hjs2 200 OK\r\n", 0) == 0 && answer.find("Content-Type") == std::string::npos,
        "response encoding without a body");
  Message answered;
  check(decode(answer, answered) == answer.size() && answered.status == 200 && answered.method.empty(),
        "response decoding");

  // A partial frame yields nothing until the rest arrives.
  check(decode(wire.substr(0, wire.size() - 4), decoded) == 0, "an incomplete frame is not decoded");
  const auto pair = wire + answer;
  const auto used = decode(pair, decoded);
  check(used == wire.size() && decode(pair.substr(used), decoded) == answer.size(), "two messages in one buffer");

  // Chunking: the continuation flag is "+" on every chunk but the last.
  Message chunk = send;
  chunk.complete = false;
  check(encode(chunk).find("\r\n-------a786hjs2+\r\n") != std::string::npos, "a continued chunk ends with +");
  chunk.complete = true;
  chunk.aborted = true;
  check(encode(chunk).find("\r\n-------a786hjs2#\r\n") != std::string::npos, "an aborted chunk ends with #");

  rejects(
      [&] {
        Message message;
        (void)decode("HTTP/1.1 200 OK\r\n\r\n", message);
      },
      "a frame that is not MSRP");
  rejects(
      [&] {
        Message message;
        (void)decode("MSRP a786hjs2 SEND\r\nTo-Path: msrp://h/s;tcp\r\n"
                     "\r\n-------a786hjs2$\r\n",
                     message);
      },
      "a SEND without From-Path");
  rejects(
      [&] {
        Message message;
        (void)decode("MSRP a7 SEND\r\nTo-Path: msrp://h/s;tcp\r\nFrom-Path: msrp://g/t;tcp\r\n"
                     "Byte-Range: x-3/3\r\n\r\n-------a7$\r\n",
                     message);
      },
      "a malformed Byte-Range");
  rejects(
      [&] {
        Message message;
        (void)decode("MSRP a7 FETCH\r\nTo-Path: msrp://h/s;tcp\r\nFrom-Path: msrp://g/t;tcp\r\n"
                     "\r\n-------a7$\r\n",
                     message);
      },
      "an unsupported method");

  // TS 24.582 clause 6.1.1.2.4 and clause 6.4.1: the two MCData bodies travel as multipart/mixed.
  Message multipart;
  multipart.content_type = "multipart/mixed; boundary=msrp-xyz";
  multipart.body = "--msrp-xyz\r\nContent-Type: application/vnd.3gpp.mcdata-signalling\r\n\r\nSIG\r\n"
                   "--msrp-xyz\r\nContent-Type: application/vnd.3gpp.mcdata-payload\r\n\r\nDATA\r\n--msrp-xyz--\r\n";
  const auto parts = multipart.parts();
  check(parts.size() == 2 && parts.at("application/vnd.3gpp.mcdata-signalling") == "SIG" &&
            parts.at("application/vnd.3gpp.mcdata-payload") == "DATA",
        "multipart MCData bodies");

  // Two endpoints over TCP: the passive side listens, the active side connects and
  // binds the connection with an empty SEND (TS 24.582 clause 6.1.1.2.1 step 4, RFC 6135), then sends both
  // MCData bodies of TS 24.582 clause 6.1.1.2.4 in one multipart body.
  {
    Endpoint passive, active;
    std::vector<Message> received;
    std::string trouble;
    const auto local = passive.listen("127.0.0.1", {[&](const Message &message) { received.push_back(message); },
                                                    [&](std::string_view reason) { trouble = reason; }});
    check(local.port != 0 && !local.session.empty(), "the passive endpoint listens and names a session");
    Endpoint::Callbacks none{{}, [&](std::string_view reason) { trouble = reason; }};
    const auto mine = Uri{"127.0.0.1", random_ident(), "tcp", 0, false};
    active.connect(local, mine, none);
    active.send_parts({{"application/vnd.3gpp.mcdata-signalling", std::string("\x01SIG", 4)},
                       {"application/vnd.3gpp.mcdata-payload", std::string("\x03"
                                                                           "DATA",
                                                                           5)}});
    for (int attempt = 0; attempt < 400 && received.empty() && trouble.empty(); ++attempt) {
      active.poll();
      passive.poll();
    }
    check(trouble.empty(), trouble.empty() ? "the MSRP connection carried the message" : trouble.c_str());
    check(received.size() == 1 && received.front().method == "SEND", "one SEND arrived, the binding SEND excluded");
    if (received.size() == 1) {
      const auto bodies = received.front().parts();
      check(bodies.size() == 2 && bodies.at("application/vnd.3gpp.mcdata-signalling") == std::string("\x01SIG", 4) &&
                bodies.at("application/vnd.3gpp.mcdata-payload") == std::string("\x03"
                                                                                "DATA",
                                                                                5),
            "both MCData bodies arrived unchanged");
      check(received.front().to_path.front().session == local.session, "the SEND names the peer's session");
    }
    // A message larger than the chunk size is reassembled from its chunks.
    received.clear();
    const std::string large(5000, 'x');
    active.send("application/vnd.3gpp.mcdata-payload", large);
    for (int attempt = 0; attempt < 400 && received.empty() && trouble.empty(); ++attempt) {
      active.poll();
      passive.poll();
    }
    check(received.size() == 1 && received.front().body == large && received.front().complete,
          "a chunked message is reassembled");
  }

  // RFC 4975 section 7.1.2: a REPORT is not answered and is no message for the application; a SEND is answered
  // unless its Failure-Report is "no". A raw TCP peer sends them to a listening endpoint.
  {
    Endpoint passive;
    std::vector<Message> received;
    const auto local = passive.listen("127.0.0.1", {[&](const Message &message) { received.push_back(message); }, {}});
    const int peer = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(local.port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check(peer >= 0 && ::connect(peer, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0,
          "a raw MSRP peer connects");
    const auto mine = Uri{"127.0.0.1", random_ident(), "tcp", 9, false};
    Message bind;
    bind.transaction = random_ident();
    bind.method = "SEND";
    bind.message_id = random_ident();
    bind.to_path = {local};
    bind.from_path = {mine};
    bind.failure_report = "no";
    Message report;
    report.transaction = random_ident();
    report.method = "REPORT";
    report.message_id = "earlier";
    report.to_path = {local};
    report.from_path = {mine};
    const auto exchange = [&](const std::string &bytes) {
      check(::send(peer, bytes.data(), bytes.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(bytes.size()),
            "the raw peer sends");
      std::string answer;
      for (int attempt = 0; attempt < 50; ++attempt) {
        passive.poll();
        char buffer[4096];
        const auto got = ::recv(peer, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (got > 0) answer.append(buffer, static_cast<std::size_t>(got));
      }
      return answer;
    };
    // RFC 6135: an accepted connection is not ready to send before its binding SEND names the peer.
    for (int attempt = 0; attempt < 50; ++attempt) passive.poll();
    check(!passive.connected(), "an accepted connection without its binding SEND cannot be sent to");
    check(exchange(encode(bind) + encode(report)).empty() && received.empty(),
          "neither the binding SEND (Failure-Report: no) nor a REPORT is answered or delivered");
    check(passive.connected(), "the binding SEND names the peer, which can then be sent to");
    Message data = bind;
    data.transaction = random_ident();
    data.failure_report.clear();
    data.content_type = "application/vnd.3gpp.mcdata-payload";
    data.body = "x";
    const auto answer = exchange(encode(data));
    check(answer.rfind("MSRP " + data.transaction + " 200", 0) == 0 && received.size() == 1,
          "a SEND is answered 200 and delivered");
    if (peer >= 0) ::close(peer);
  }

  // MSRP over TLS (RFC 4975 section 14) between two MCData servers: the listener
  // requires a certificate from the connector, the connector checks the listener's name.
  {
    Pki pki("lab");
    const auto server = pki.entity("mcdata-server.a.test");
    const auto client = pki.entity("mcdata-server.b.test", "mcdata-server.a.test");
    const auto run = [](Endpoint &passive, Endpoint &active, std::vector<Message> &received, std::string &trouble) {
      for (int attempt = 0; attempt < 2000 && received.empty() && trouble.empty(); ++attempt) {
        active.poll();
        passive.poll();
      }
    };
    {
      Endpoint passive, active;
      std::vector<Message> received;
      std::string trouble;
      const auto local = passive.listen("127.0.0.1",
                                        {[&](const Message &message) { received.push_back(message); },
                                         [&](std::string_view reason) { trouble = reason; }},
                                        &server);
      check(local.secure && local.text().starts_with("msrps://"), "a TLS listener names an msrps URI");
      active.connect(local, Uri{"127.0.0.1", random_ident(), "tcp", 0, false},
                     {{}, [&](std::string_view reason) { trouble = reason; }}, &client);
      active.send("application/vnd.3gpp.mcdata-payload", std::string("\x43secret", 7));
      run(passive, active, received, trouble);
      check(trouble.empty(), trouble.empty() ? "an MSRP message crossed a TLS connection" : trouble.c_str());
      check(received.size() == 1 && received.front().body == std::string("\x43secret", 7) && active.secure() &&
                passive.secure(),
            "the message arrived over TLS on both sides");
      // A peer that goes away mid-relay ends the connection, not the process (SIGPIPE).
      passive.close();
      const std::string bulk(64 * 1024, 'x');
      for (int attempt = 0; attempt < 20 && trouble.empty(); ++attempt) {
        active.send("application/vnd.3gpp.mcdata-payload", bulk);
        active.poll();
      }
      check(!trouble.empty(), "writing to a closed TLS peer reports the connection closed");
      // The library guards its own writes; it leaves the process's SIGPIPE disposition alone.
      struct sigaction pipe_action{};
      check(sigaction(SIGPIPE, nullptr, &pipe_action) == 0 && pipe_action.sa_handler == SIG_DFL,
            "SIGPIPE keeps its default disposition");
    }
    {
      // The listener's certificate does not name the expected peer.
      Endpoint passive, active;
      std::vector<Message> received;
      std::string trouble;
      auto wrong = client;
      wrong.expected_name = "mcdata-server.c.test";
      const auto local =
          passive.listen("127.0.0.1", {[&](const Message &message) { received.push_back(message); }, {}}, &server);
      active.connect(local, Uri{"127.0.0.1", random_ident(), "tcp", 0, false},
                     {{}, [&](std::string_view reason) { trouble = reason; }}, &wrong);
      active.send("application/vnd.3gpp.mcdata-payload", "x");
      run(passive, active, received, trouble);
      check(received.empty() && trouble.find("TLS handshake failed") != std::string::npos,
            "a listener without the expected name is refused");
    }
    {
      // A connector whose certificate comes from another CA is refused by the listener.
      Pki other("other");
      auto stranger = other.entity("mcdata-server.b.test", "mcdata-server.a.test");
      stranger.ca_file = server.ca_file; // it trusts the listener, but is not trusted back
      Endpoint passive, active;
      std::vector<Message> received;
      std::string refused;
      const auto local = passive.listen("127.0.0.1",
                                        {[&](const Message &message) { received.push_back(message); },
                                         [&](std::string_view reason) { refused = reason; }},
                                        &server);
      active.connect(local, Uri{"127.0.0.1", random_ident(), "tcp", 0, false}, {}, &stranger);
      active.send("application/vnd.3gpp.mcdata-payload", "x");
      for (int attempt = 0; attempt < 2000 && received.empty() && refused.empty(); ++attempt) {
        active.poll();
        passive.poll();
      }
      check(received.empty() && refused.find("TLS handshake failed") != std::string::npos,
            "a connector with an untrusted certificate is refused");
    }
    rejects(
        [&] {
          Endpoint active;
          active.connect(parse_uri("msrps://127.0.0.1:1/abc;tcp"), Uri{"127.0.0.1", "x", "tcp", 0, false}, {});
        },
        "an msrps peer without TLS configuration");
  }

  // TS 24.282 clause 9.2.3.2.1 and clause 9.2.3.2.2: the SDP offer and answer of the MCData media plane.
  {
    mcx::MsrpMedia offer;
    offer.address = "10.0.0.5";
    offer.port = 2855;
    offer.path = "msrp://10.0.0.5:2855/abcd;tcp";
    offer.accept_types = {"application/vnd.3gpp.mcdata-signalling", "application/vnd.3gpp.mcdata-payload"};
    const auto sdp = mcx::msrp_sdp(offer, 42);
    check(
        sdp.find("m=message 2855 TCP/MSRP *\r\n") != std::string::npos &&
            sdp.find("a=path:msrp://10.0.0.5:2855/abcd;tcp\r\n") != std::string::npos &&
            sdp.find("a=setup:actpass\r\n") != std::string::npos && sdp.find("a=sendonly\r\n") != std::string::npos &&
            sdp.find("a=accept-types:application/vnd.3gpp.mcdata-signalling application/vnd.3gpp.mcdata-payload\r\n") !=
                std::string::npos,
        "MSRP SDP offer");
    const auto parsed = mcx::parse_msrp_sdp(sdp);
    check(parsed.port == 2855 && parsed.path == offer.path && parsed.setup == "actpass" &&
              parsed.accept_types.size() == 2 && parsed.address == "10.0.0.5" && !parsed.secure,
          "MSRP SDP round trip");
    mcx::MsrpMedia answer = offer;
    answer.setup = "passive";
    answer.direction = "recvonly";
    answer.secure = true;
    answer.file_selector = "name:\"report.txt\" type:text/plain size:12";
    const auto answered = mcx::parse_msrp_sdp(mcx::msrp_sdp(answer, 43));
    check(answered.setup == "passive" && answered.direction == "recvonly" && answered.secure &&
              answered.file_selector == answer.file_selector,
          "MSRP SDP answer with the file selector");
    // TS 24.282 clause 9.2.3.2.1 step 2: the PCK of a one-to-one offer in a=key-mgmt (RFC 4567).
    mcx::MsrpMedia keyed = offer;
    keyed.key_mgmt = "AQIDBAUG";
    const auto keyed_sdp = mcx::msrp_sdp(keyed, 44);
    check(keyed_sdp.find("a=key-mgmt:mikey AQIDBAUG\r\n") < keyed_sdp.find("m=message"), "session-level key-mgmt");
    check(mcx::parse_msrp_sdp(keyed_sdp).key_mgmt == "AQIDBAUG" && parsed.key_mgmt.empty(),
          "MSRP SDP key-mgmt round trip");
    rejects(
        [&] {
          (void)mcx::parse_msrp_sdp(
              "v=0\r\na=key-mgmt:mikey A*B=\r\nc=IN IP4 10.0.0.5\r\nm=message 2855 TCP/MSRP *\r\n");
        },
        "malformed key management data");
    rejects([&] { (void)mcx::parse_msrp_sdp("v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 5000 RTP/AVP 96\r\n"); },
            "SDP without an MSRP stream");
    rejects([&] { (void)mcx::parse_msrp_sdp("v=0\r\nc=IN IP4 10.0.0.5\r\nm=message 2855 TCP/FOO *\r\n"); },
            "an unsupported MSRP transport");
    rejects(
        [&] {
          mcx::MsrpMedia bad = offer;
          bad.setup = "sideways";
          (void)mcx::msrp_sdp(bad, 1);
        },
        "an invalid setup attribute");
  }

  const auto ident = random_ident();
  check(ident.size() >= 4 && ident.size() <= 32 && ident != random_ident(), "random identifiers");
  if (!failures) std::cout << "msrp tests passed\n";
  return failures ? 1 : 0;
}
