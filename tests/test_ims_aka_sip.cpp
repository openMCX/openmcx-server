//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The IMS AKA UE of the SIP engine against the raw P-CSCF of tests/run_ims_aka.py: the roles of this program are the
// UE ("ue"), and for the P-CSCF's authentication vectors the network side of MILENAGE ("vector", "auts").
//
//   test_ims_aka_sip vector K OPC RAND SQN AMF  -> "AUTN RES CK IK" (TS 33.102 clause 6.3.2)
//   test_ims_aka_sip auts K OPC RAND AUTS       -> "SQN_MS" or "invalid" (TS 33.102 clause 6.3.5)
//   test_ims_aka_sip ue SQN_FILE K OPC          -> registers, sends a MESSAGE once registered, answers MESSAGEs;
//                                                 a MESSAGE with the body "deregister" deregisters; exits 0 after
//                                                 the deregistration, 3 on a refused registration (printing it).
//
// Specifications: TS 24.229 V19.7.0 (Rel-19) clause 5.1.1, TS 33.203 V19.1.0 (Rel-19) clause 7, TS 33.102
// V19.1.0 (Rel-19) clause 6.3, TS 35.206 V19.0.0 (Rel-19).
#include "mcx/ims_aka.hpp"
#include "mcx/runtime.hpp"
#include "mcx/sip.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>

using namespace mcx;

//------------------------------------------------------------------------------
// Helper: bytes of hexadecimal text.
template <std::size_t N> std::array<std::uint8_t, N> bytes(const std::string &text) {
  if (text.size() != 2 * N) throw std::invalid_argument("hex length");
  std::array<std::uint8_t, N> out{};
  for (std::size_t index = 0; index < N; ++index)
    out[index] = static_cast<std::uint8_t>(std::stoul(text.substr(2 * index, 2), nullptr, 16));
  return out;
}

//------------------------------------------------------------------------------
// The network side: AUTN = (SQN XOR AK) || AMF || MAC and XRES, CK, IK of a vector; or SQN_MS from AUTS.
int network(int argc, char **argv) {
  const std::string role = argv[1];
  const aka::Milenage milenage(bytes<16>(argv[2]), bytes<16>(argv[3]));
  const auto rand = bytes<16>(argv[4]);
  const auto outputs = milenage.f2345(rand);
  if (role == "vector" && argc == 7) {
    const auto sqn = bytes<6>(argv[5]);
    const auto amf = bytes<2>(argv[6]);
    const auto mac = milenage.f1(rand, sqn, amf);
    std::array<std::uint8_t, 16> autn{};
    for (int index = 0; index < 6; ++index) autn[index] = sqn[index] ^ outputs.ak[index];
    autn[6] = amf[0];
    autn[7] = amf[1];
    std::copy(mac.begin(), mac.end(), autn.begin() + 8);
    std::cout << aka::hex(autn) << ' ' << aka::hex(outputs.res) << ' ' << aka::hex(outputs.ck) << ' '
              << aka::hex(outputs.ik) << '\n';
    return 0;
  }
  if (role == "auts" && argc == 6) {
    const auto auts = bytes<14>(argv[5]);
    aka::Sqn sqn_ms{};
    for (int index = 0; index < 6; ++index) sqn_ms[index] = auts[index] ^ outputs.ak_star[index];
    const auto mac_s = milenage.f1_star(rand, sqn_ms, aka::Amf{0, 0});
    std::cout << (std::equal(mac_s.begin(), mac_s.end(), auts.begin() + 6) ? aka::hex(sqn_ms) : "invalid") << '\n';
    return 0;
  }
  return 2;
}

//------------------------------------------------------------------------------
// The UE: alice@example.org at 127.0.0.1, protected server port 31900, P-CSCF 127.0.0.2:5060.
int ue(const std::string &sqn_file, const std::string &k, const std::string &opc) {
  // MCX_LOG=debug: the SIP message log and the ESP keys on stderr.
  if (const char *level = std::getenv("MCX_LOG"); level != nullptr) set_log_level(parse_log_level(level));
  SipConfig config;
  config.listen_address = "127.0.0.1";
  config.advertise_address = "127.0.0.1";
  config.listen_port = 31900;
  config.core_uri = "sip:unused";
  config.identity = "sip:alice@example.org";
  config.tls.enabled = false;
  config.aka.enabled = true;
  config.aka.impi = "alice@example.org";
  config.aka.k = k;
  config.aka.opc = opc;
  config.aka.sqn_file = sqn_file;
  config.aka.pcscf_address = "127.0.0.2";
  bool deregister = false, done = false;
  int exit_code = 1;
  SipCallbacks callbacks;
  callbacks.on_request = [&](const SipMessage &message) {
    SipResponse response;
    response.status_code = 200;
    response.reason = "OK";
    std::cout << "request " << message.method << ' ' << message.body << std::endl;
    if (message.body == "deregister") deregister = true;
    return response;
  };
  callbacks.on_error = [](std::string_view error) { std::cout << "error " << error << std::endl; };
  SipEngine engine(config, callbacks);
  engine.start();
  engine.register_account(3600, [&](const SipResponse &response) {
    std::cout << "registered " << response.status_code << ' ' << response.reason << std::endl;
    if (response.status_code != 200) {
      exit_code = 3;
      done = true;
      return;
    }
    const auto status = engine.security_status();
    std::cout << "sa "
              << (status ? status->alg + " " + status->ealg + " uc " + std::to_string(status->port_uc) + " ps " +
                               std::to_string(status->port_ps)
                         : std::string("none"))
              << std::endl;
    engine.request("MESSAGE", "sip:bob@example.org", "text/plain", "hello", {}, [](const SipResponse &answer) {
      std::cout << "message answered " << answer.status_code << std::endl;
    });
  });
  const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(40);
  while (!done && std::chrono::steady_clock::now() < end) {
    engine.poll(std::chrono::milliseconds(20));
    if (deregister) {
      deregister = false;
      engine.unregister_account([&](const SipResponse &response) {
        std::cout << "deregistered " << response.status_code << std::endl;
        exit_code = response.status_code == 200 && !engine.security_status() ? 0 : 4;
        done = true;
      });
    }
  }
  engine.stop();
  return exit_code;
}

//------------------------------------------------------------------------------
// Selects the role.
int main(int argc, char **argv) {
  try {
    if (argc >= 2 && std::string(argv[1]) == "ue" && argc == 5) return ue(argv[2], argv[3], argv[4]);
    if (argc >= 6) return network(argc, argv);
  } catch (const std::exception &error) {
    std::cout << "error " << error.what() << std::endl;
    return 1;
  }
  std::cerr << "usage: test_ims_aka_sip vector|auts|ue ...\n";
  return 2;
}
