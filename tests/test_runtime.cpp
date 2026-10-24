//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Runtime boundaries: the --disable-tls debug flag, the SIP transport it selects, and the P-Asserted-Identity check.
//
// Specifications: RFC 3325 section 9.1 (P-Asserted-Identity), TS 24.229.

#include "mcx/runtime.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <iterator>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <vector>

//------------------------------------------------------------------------------
// Checks that the operation throws; what names what would have been wrongly accepted.
static void rejects(const std::function<void()> &operation, const std::string &what) {
  try {
    operation();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(what + " accepted");
}

//------------------------------------------------------------------------------
// Helper: the number of open file descriptors of this process.
static std::size_t open_descriptors() {
  return static_cast<std::size_t>(std::distance(std::filesystem::directory_iterator("/proc/self/fd"), {}));
}

//------------------------------------------------------------------------------
// TS 24.582 clause 13.4 item 1: the GRE-in-UDP tunnel of MCData IP connectivity uses the UDP checksum. UdpSocket
// leaves the kernel's UDP checksum on (SO_NO_CHECK is 0), and a datagram it sends to itself arrives.
static void udp_checksum_kept() {
  mcx::UdpSocket udp("127.0.0.1", 0);
  int descriptor = -1;
  for (const auto &entry : std::filesystem::directory_iterator("/proc/self/fd")) {
    const int candidate = std::stoi(entry.path().filename().string());
    sockaddr_in local{};
    socklen_t length = sizeof(local);
    if (getsockname(candidate, reinterpret_cast<sockaddr *>(&local), &length) == 0 && local.sin_family == AF_INET &&
        ntohs(local.sin_port) == udp.port())
      descriptor = candidate;
  }
  int no_check = -1;
  socklen_t size = sizeof(no_check);
  if (descriptor < 0 || getsockopt(descriptor, SOL_SOCKET, SO_NO_CHECK, &no_check, &size) != 0 || no_check != 0)
    throw std::runtime_error("the UDP socket does not keep the UDP checksum (TS 24.582 clause 13.4 item 1)");
  const std::vector<std::uint8_t> payload{0x00, 0x00, 0x08, 0x00, 0x45};
  udp.send(payload, "127.0.0.1", udp.port());
  for (int attempt = 0; attempt < 100; ++attempt) {
    if (const auto datagram = udp.receive()) {
      if (datagram->bytes != payload) throw std::runtime_error("UDP datagram changed");
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  throw std::runtime_error("UDP datagram to self lost");
}

//------------------------------------------------------------------------------
// The debug flag is off unless given and selects SIP over TCP on port 5060; RFC 3325 section 9.1: a request with
// more than one P-Asserted-Identity URI, or a malformed or empty identity, is refused.
int main() {
  char exe[] = "mcx-client", option[] = "--config", file[] = "lab.json", flag[] = "--disable-tls";
  char *argv[] = {exe, option, file, flag};
  if (mcx::arguments(3, argv).disable_tls || !mcx::arguments(4, argv).disable_tls)
    throw std::runtime_error("explicit debug flag lost or enabled by default");
  mcx::Json cfg = {{"sip",
                    {{"listen", "127.0.0.1"},
                     {"advertise", "client"},
                     {"port", 5061},
                     {"core_uri", "sip:core:5061;transport=tls"},
                     {"identity", "sip:a@example.test"}}},
                   {"trusted_core", "core"},
                   {"tls", {{"ca_file", "ca"}, {"cert_file", "cert"}, {"key_file", "key"}}}};
  const auto normal = mcx::sip_config(cfg), debug = mcx::sip_config(cfg, true);
  if (!normal.tls.enabled || debug.tls.enabled || debug.listen_port != 5060 ||
      debug.core_uri != "sip:core:5060;transport=tcp")
    throw std::runtime_error("SIP debug transport selection failed");
  cfg["sip"]["debug_port"] = 70000;
  rejects([&] { mcx::sip_config(cfg, true); }, "a debug port above 65535");
  // TS 33.203 (sip.auth "aka"): the ISIM and P-CSCF settings, no TLS, names resolved; the engine accepts it.
  mcx::Json aka = cfg;
  aka["sip"]["auth"] = "aka";
  aka["sip"]["advertise"] = "127.0.0.1";
  aka["sip"]["port"] = 31900;
  aka["sip"]["isim"] = {{"impi", "a@example.test"},
                        {"k", "465b5ce8b199b49faa5f0a2ee238a6bc"},
                        {"opc", "cd63cb71954a9f4e48a5994e37a02baf"},
                        {"amf", "8000"}};
  aka["sip"]["pcscf"] = {{"address", "localhost"}, {"port", 5060}};
  const auto ims = mcx::sip_config(aka);
  if (!ims.aka.enabled || ims.tls.enabled || ims.aka.pcscf_address != "127.0.0.1" || ims.aka.pcscf_port != 5060 ||
      ims.aka.impi != "a@example.test" || ims.aka.unprotected_port != 5060)
    throw std::runtime_error("IMS AKA configuration not taken");
  { mcx::SipEngine accepted(ims); }
  // TS 34.108 clause 8.1.2: the test algorithm needs no OPc; a RES length outside 4 to 16 bytes is refused.
  mcx::Json test_isim = aka;
  test_isim["sip"]["isim"] = {
      {"impi", "a@example.test"}, {"k", "000102030405060708090a0b0c0d0e0f"}, {"algorithm", "test"}, {"res_length", 8}};
  const auto test_config = mcx::sip_config(test_isim);
  if (test_config.aka.algorithm != "test" || test_config.aka.res_length != 8 || !test_config.aka.opc.empty())
    throw std::runtime_error("IMS AKA test algorithm configuration not taken");
  { mcx::SipEngine accepted(test_config); }
  test_isim["sip"]["isim"]["res_length"] = 17;
  rejects([&] { mcx::sip_config(test_isim); }, "a RES of 17 bytes");
  test_isim["sip"]["isim"]["algorithm"] = "comp128";
  rejects([&] { mcx::sip_config(test_isim); }, "an unknown ISIM algorithm");
  aka["sip"]["port"] = 5060;
  rejects([&] { mcx::SipEngine engine(mcx::sip_config(aka)); }, "an IMS AKA protected server port 5060");
  aka["sip"]["port"] = 31900;
  aka["sip"]["isim"]["k"] = "465b";
  rejects([&] { mcx::SipEngine engine(mcx::sip_config(aka)); }, "a short ISIM key");
  mcx::SipMessage message;
  message.headers = {{"P-Asserted-Identity", "<sip:alpha@example.test>"}};
  if (mcx::asserted_identity(message) != "sip:alpha@example.test") throw std::runtime_error("trusted identity lost");
  message.headers.push_back({"p-asserted-identity", "<sip:beta@example.test>"});
  rejects([&] { mcx::asserted_identity(message); }, "two P-Asserted-Identity header fields");
  message.headers = {{"P-Asserted-Identity", "<sip:alpha@example.test>, <sip:beta@example.test>"}};
  rejects([&] { mcx::asserted_identity(message); }, "two P-Asserted-Identity URIs in one header field");
  rejects([] { mcx::canonical_identity("<sip:alpha@example.test>;unexpected=1"); }, "an identity with parameters");
  rejects([] { mcx::canonical_identity("sip:alpha@example.test\r\nInjected: true"); }, "an identity with CR/LF");
  rejects([] { mcx::canonical_identity(""); }, "an empty identity");
  // A UDP socket whose address cannot be resolved is refused and leaves no descriptor open.
  const auto descriptors = open_descriptors();
  rejects([] { mcx::UdpSocket udp("", 0); }, "a UDP socket on an unresolvable address");
  if (open_descriptors() != descriptors) throw std::runtime_error("a refused UDP socket left a descriptor open");
  if (mcx::resolve_ipv4("127.0.0.1") != "127.0.0.1") throw std::runtime_error("numeric IPv4 address not resolved");
  udp_checksum_kept();
  std::cout << "Runtime identity boundary tests passed\n";
}
