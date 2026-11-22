//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Prototype (not part of any program): IMS AKA registration over reSIProcate 1.14, against the lab's P-CSCF
// (Kamailio with ims_ipsec_pcscf) and HSS, TCP case of TS 33.203 clause 7.1. The REGISTERs are written as text and
// sent through reSIProcate's transaction layer (as src/sip/ims_aka.cpp sends them through pjsip's); the ISIM, the
// digest, the sec-agree mechanisms and the ESP keys are OpenMCX's (include/mcx/ims_aka.hpp), the SAs its XFRM code
// (include/mcx/xfrm.hpp). What reSIProcate has to provide is the transport behaviour of the pjproject patch
// dependencies/pjproject/0001: the protected REGISTER on a TCP connection from port_uc to port_ps, here a TCP
// transport on port_uc in reSIProcate's "symmetric connections" mode, chosen through the top Via's sent-by.
//
//   aka_probe --config aka-probe.json [--pcscf pcscf] [--pcscf-port 5060]
//
// Needs CAP_NET_ADMIN (the SAs) and the lab network. The config is the lab's aka-probe ISIM:
// {"identity": "sip:user@domain", "isim": {"impi": ..., "k": ..., "opc": ..., "amf": ...}}.
//
// Specifications: TS 24.229 V19.7.0 (Rel-19) clauses 5.1.1.2, 5.1.1.5 and 5.1.1.6, TS 33.203 V19.1.0 (Rel-19)
// clauses 6.1, 7.1 and 7.2 and annexes H and I, RFC 3310, RFC 3329.

#include "mcx/ims_aka.hpp"
#include "mcx/xfrm.hpp"
#include "resip/stack/SipMessage.hxx"
#include "resip/stack/SipStack.hxx"
#include "resip/stack/TransactionUser.hxx"
#include "resip/stack/Tuple.hxx"
#include "rutil/FdPoll.hxx"
#include "rutil/Log.hxx"

#include <netdb.h>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

// TS 24.229 clause 5.1.1.2.1 and the lab: the UE's unprotected port (the initial REGISTER) and its protected server
// port port_us (the Contact of the protected REGISTER; the client's sip.port).
constexpr std::uint16_t unprotected_port = 5060;
constexpr std::uint16_t protected_server_port = 5064;
// The registration time asked for, and the time allowed for each response.
constexpr unsigned register_expires_s = 600;
constexpr auto response_timeout = std::chrono::seconds(10);

int failures = 0;

//------------------------------------------------------------------------------
// Records a check: a failure is counted and printed, a success printed.
void check(bool condition, const std::string &text) {
  std::cout << (condition ? "  ok   " : "  FAIL ") << text << '\n';
  if (!condition) ++failures;
}

//------------------------------------------------------------------------------
// Helper: a random 32-bit value from OpenSSL's generator.
std::uint32_t random_u32() {
  std::uint32_t value = 0;
  if (RAND_bytes(reinterpret_cast<unsigned char *>(&value), sizeof value) != 1) throw std::runtime_error("random");
  return value;
}

//------------------------------------------------------------------------------
// Helper: random lower-case hexadecimal text of the given number of bytes (tags, Call-ID, branch).
std::string random_hex(std::size_t bytes) {
  std::vector<std::uint8_t> value(bytes);
  if (RAND_bytes(value.data(), static_cast<int>(value.size())) != 1) throw std::runtime_error("random");
  return mcx::aka::hex(value);
}

//------------------------------------------------------------------------------
// Helper: the numeric IPv4 address of a host name.
std::string resolve(const std::string &host) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  addrinfo *found = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &found) != 0 || found == nullptr)
    throw std::runtime_error("cannot resolve " + host);
  char text[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(found->ai_addr)->sin_addr, text, sizeof text);
  freeaddrinfo(found);
  return text;
}

//------------------------------------------------------------------------------
// Helper: this host's address towards a destination (the source address the kernel picks for it).
std::string local_address_towards(const std::string &destination) {
  const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  sockaddr_in remote{};
  remote.sin_family = AF_INET;
  remote.sin_port = htons(9);
  inet_pton(AF_INET, destination.c_str(), &remote.sin_addr);
  sockaddr_in local{};
  socklen_t length = sizeof local;
  if (fd < 0 || connect(fd, reinterpret_cast<sockaddr *>(&remote), sizeof remote) != 0 ||
      getsockname(fd, reinterpret_cast<sockaddr *>(&local), &length) != 0)
    throw std::runtime_error("no route to " + destination);
  close(fd);
  char text[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &local.sin_addr, text, sizeof text);
  return text;
}

//------------------------------------------------------------------------------
// Helper: a free TCP port on the address for port_uc (TS 33.203 clause 7.1: chosen by the UE).
std::uint16_t free_tcp_port(const std::string &address) {
  for (int attempt = 0; attempt < 200; ++attempt) {
    const auto port = static_cast<std::uint16_t>(20000 + random_u32() % 40000);
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    inet_pton(AF_INET, address.c_str(), &local.sin_addr);
    const bool is_free = bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof local) == 0;
    close(fd);
    if (is_free) return port;
  }
  throw std::runtime_error("no free port for port_uc");
}

// The probe's transaction user: every response of its REGISTERs comes to its queue.
class ProbeUser : public resip::TransactionUser {
public:
  const resip::Data &name() const override {
    static const resip::Data probe_name("openmcx-aka-probe");
    return probe_name;
  }

  //------------------------------------------------------------------------------
  // The next SIP response in the queue, if any (other messages, such as transaction terminations, are dropped).
  std::unique_ptr<resip::SipMessage> next_response() {
    while (mFifo.messageAvailable()) {
      std::unique_ptr<resip::Message> message(mFifo.getNext());
      auto *sip = dynamic_cast<resip::SipMessage *>(message.get());
      if (sip != nullptr && sip->isResponse()) {
        message.release();
        return std::unique_ptr<resip::SipMessage>(sip);
      }
    }
    return nullptr;
  }
};

// The probe's settings: the ISIM, the identity and the addresses.
struct Settings {
  std::string identity; // sip:user@domain, From and To
  std::string impi;     // the private user identity, Authorization username
  std::string domain;   // the home domain, Request-URI and realm of the initial REGISTER
  std::string user;     // the user part of the identity, the Contact's
  mcx::aka::Key k{}, opc{};
  std::string pcscf_address;
  std::uint16_t pcscf_port = 5060;
  std::string ue_address;
};

//------------------------------------------------------------------------------
// Reads the lab's aka-probe configuration and resolves the P-CSCF.
Settings load_settings(int argc, char **argv) {
  std::string config_path, pcscf = "pcscf";
  Settings settings;
  for (int index = 1; index + 1 < argc; index += 2) {
    const std::string option = argv[index];
    if (option == "--config")
      config_path = argv[index + 1];
    else if (option == "--pcscf")
      pcscf = argv[index + 1];
    else if (option == "--pcscf-port")
      settings.pcscf_port = static_cast<std::uint16_t>(std::stoi(argv[index + 1]));
    else
      throw std::invalid_argument("unknown option " + option);
  }
  if (config_path.empty())
    throw std::invalid_argument("usage: aka_probe --config FILE [--pcscf HOST] [--pcscf-port N]");
  std::ifstream file(config_path);
  const auto config = nlohmann::json::parse(file);
  settings.identity = config.at("identity").get<std::string>();
  const auto &isim = config.at("isim");
  settings.impi = isim.at("impi").get<std::string>();
  settings.k = mcx::aka::key_from_hex(isim.at("k").get<std::string>());
  settings.opc = mcx::aka::key_from_hex(isim.at("opc").get<std::string>());
  const auto at = settings.identity.find('@');
  settings.user = settings.identity.substr(4, at - 4);
  settings.domain = settings.identity.substr(at + 1);
  settings.pcscf_address = resolve(pcscf);
  settings.ue_address = local_address_towards(settings.pcscf_address);
  return settings;
}

// One registration procedure's dialog-like state (TS 24.229 clause 5.1.1.2.1: one Call-ID and From tag, CSeq
// increasing).
struct Procedure {
  std::string call_id = random_hex(12);
  std::string from_tag = random_hex(6);
  unsigned cseq = 0;
  std::string security_client;
};

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.2.1 and 5.1.1.5.1 (as src/sip/ims_aka.cpp aka_send_register): one REGISTER of the procedure,
// as text: Via with our sent-by (the source the transport layer sends from), Request-URI the home domain, From and To
// the identity, Contact, Expires, Authorization, Security-Client, Security-Verify when protected, Require and
// Proxy-Require "sec-agree", Supported "path".
std::unique_ptr<resip::SipMessage> make_register(const Settings &settings, Procedure &procedure, std::uint16_t via_port,
                                                 std::uint16_t contact_port, unsigned expires,
                                                 const std::string &authorization, const std::string &security_verify) {
  std::ostringstream text;
  text << "REGISTER sip:" << settings.domain << " SIP/2.0\r\n"
       << "Via: SIP/2.0/TCP " << settings.ue_address << ':' << via_port << ";branch=z9hG4bK" << random_hex(10)
       << ";rport\r\n"
       << "Max-Forwards: 70\r\n"
       << "From: <" << settings.identity << ">;tag=" << procedure.from_tag << "\r\n"
       << "To: <" << settings.identity << ">\r\n"
       << "Call-ID: " << procedure.call_id << "\r\n"
       << "CSeq: " << ++procedure.cseq << " REGISTER\r\n"
       << "Contact: <sip:" << settings.user << '@' << settings.ue_address << ':' << contact_port
       << ";transport=tcp>\r\n"
       << "Expires: " << expires << "\r\n"
       << "Authorization: " << authorization << "\r\n"
       << "Security-Client: " << procedure.security_client << "\r\n";
  if (!security_verify.empty()) text << "Security-Verify: " << security_verify << "\r\n";
  text << "Require: sec-agree\r\nProxy-Require: sec-agree\r\nSupported: path\r\nContent-Length: 0\r\n\r\n";
  const resip::Data wire(text.str());
  return std::unique_ptr<resip::SipMessage>(resip::SipMessage::make(wire, false));
}

// The stack, its transports in one epoll poll group, and the probe's transaction user.
struct Stack {
  std::unique_ptr<resip::FdPollGrp> group{resip::FdPollGrp::create("epoll")};
  resip::SipStack stack;
  ProbeUser user;

  //------------------------------------------------------------------------------
  // TS 33.203 clause 7.1, TCP case: the unprotected port (initial REGISTER), the protected server port port_us
  // (requests of the P-CSCF), and the protected client port port_uc in "symmetric connections" mode: a connection it
  // sets up comes from port_uc, as the protected requests must ("from the protected client port port_uc ... to the
  // protected server port port_ps").
  Stack(const Settings &settings, std::uint16_t port_uc) : stack(options(*group)) {
    const resip::Data interface(settings.ue_address);
    stack.addTransport(resip::TCP, unprotected_port, resip::V4, resip::StunDisabled, interface);
    stack.addTransport(resip::TCP, protected_server_port, resip::V4, resip::StunDisabled, interface);
    stack.addTransport(resip::TCP, port_uc, resip::V4, resip::StunDisabled, interface, resip::Data::Empty,
                       resip::Data::Empty, resip::SecurityTypes::SSLv23, RESIP_TRANSPORT_FLAG_SYMMETRIC_CONNECTIONS);
    stack.registerTransactionUser(user);
  }

  static resip::SipStackOptions options(resip::FdPollGrp &poll_group) {
    resip::SipStackOptions result;
    result.mPollGrp = &poll_group;
    return result;
  }

  //------------------------------------------------------------------------------
  // Sends a REGISTER to the P-CSCF's port and waits for its final response (a provisional one is skipped).
  std::unique_ptr<resip::SipMessage> transact(std::unique_ptr<resip::SipMessage> request, const Settings &settings,
                                              std::uint16_t pcscf_port) {
    // The next hop is the P-CSCF's address and port (TS 37.579-1 table 5.5.2.13-1: no Route, straight to the
    // P-CSCF), not the Request-URI's domain: a forced target (SipStack::sendTo with a Tuple does not override the
    // target the transaction resolves). The source transport is the top Via's sent-by (make_register).
    request->setForceTarget(
        resip::Uri(resip::Data("sip:" + settings.pcscf_address + ":" + std::to_string(pcscf_port) + ";transport=tcp")));
    stack.send(std::move(request), &user);
    const auto deadline = Clock::now() + response_timeout;
    while (Clock::now() < deadline) {
      stack.process(50);
      while (auto response = user.next_response()) {
        if (response->header(resip::h_StatusLine).statusCode() >= 200) return response;
      }
    }
    return nullptr;
  }
};

//------------------------------------------------------------------------------
// Helper: the values of a header field of a response as sent (all of its values, comma-separated).
std::string header_text(const resip::SipMessage &message, const char *name) {
  std::string out;
  const auto *values = message.getRawHeader(resip::Headers::getType(name, static_cast<int>(std::strlen(name))));
  if (values == nullptr) return out;
  for (const auto &value : *values) {
    out += (out.empty() ? "" : ", ") + std::string(value.getBuffer(), value.getLength());
  }
  return out;
}

// What the 401 gave the UE: the authorization for the protected REGISTER, the Security-Server and the set's ports.
struct Challenge {
  std::string authorization;
  std::string security_server;
  mcx::aka::SecMechanism mechanism;
  mcx::aka::AuthResult result;
};

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.5.1 (as aka_challenge): the AKA challenge of the 401: the ISIM authenticates RAND and AUTN,
// the UE takes a mechanism from the Security-Server (TS 33.203 clause 7.2) and computes the Authorization (RFC 3310
// section 3.3).
std::optional<Challenge> answer_challenge(const resip::SipMessage &challenge, const Settings &settings,
                                          mcx::aka::SoftIsim &isim) {
  if (!challenge.exists(resip::h_WWWAuthenticates)) return std::nullopt;
  const auto &digest = challenge.header(resip::h_WWWAuthenticates).front();
  const std::string algorithm_text = digest.exists(resip::p_algorithm) ? digest.param(resip::p_algorithm).c_str() : "";
  const auto algorithm = mcx::aka::aka_algorithm(algorithm_text);
  const std::string nonce = digest.param(resip::p_nonce).c_str();
  const std::string realm = digest.param(resip::p_realm).c_str();
  const auto parsed = mcx::aka::parse_nonce(nonce);
  check(algorithm.has_value() && parsed.has_value(),
        "RFC 3310: the 401 carries an AKA challenge (" + algorithm_text + ")");
  if (!algorithm || !parsed) return std::nullopt;

  Challenge answer;
  answer.result = isim.authenticate(parsed->rand, parsed->autn);
  check(answer.result.status == mcx::aka::AuthStatus::success,
        "TS 33.102 clause 6.3.3: the ISIM accepts the challenge");
  if (answer.result.status != mcx::aka::AuthStatus::success) return std::nullopt;

  answer.security_server = header_text(challenge, "Security-Server");
  const auto mechanism = mcx::aka::select_mechanism(mcx::aka::parse_sec_mechanisms(answer.security_server));
  check(mechanism.has_value(), "TS 33.203 clause 7.2: the Security-Server offers a mechanism the UE supports");
  if (!mechanism) return std::nullopt;
  answer.mechanism = *mechanism;

  const auto uri = "sip:" + settings.domain;
  const auto password = mcx::aka::digest_password(*algorithm, answer.result);
  const bool qop_auth = digest.exists(resip::p_qopOptions) &&
                        std::string(digest.param(resip::p_qopOptions).c_str()).find("auth") != std::string::npos;
  const std::string cnonce = qop_auth ? random_hex(16) : "", nc = qop_auth ? "00000001" : "",
                    qop = qop_auth ? "auth" : "";
  const auto response =
      mcx::aka::digest_response(*algorithm, settings.impi, realm, password, "REGISTER", uri, nonce, nc, cnonce, qop);
  answer.authorization = "Digest username=\"" + settings.impi + "\", realm=\"" + realm + "\", nonce=\"" + nonce +
                         "\", uri=\"" + uri + "\", response=\"" + response +
                         "\", algorithm=" + std::string(mcx::aka::algorithm_name(*algorithm));
  if (qop_auth) answer.authorization += ", qop=auth, nc=" + nc + ", cnonce=\"" + cnonce + "\"";
  if (digest.exists(resip::p_opaque))
    answer.authorization += ", opaque=\"" + std::string(digest.param(resip::p_opaque).c_str()) + "\"";
  return answer;
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 and annex I (as aka_install): the four SAs of the set: UE port_uc to P-CSCF port_ps and UE
// port_us to P-CSCF port_pc outbound, and the reverse inbound, with IK_ESP, CK_ESP and the salt of annex I.
std::vector<mcx::xfrm::SecurityAssociation> security_associations(const Settings &settings, const Challenge &answer,
                                                                  const mcx::aka::SecMechanism &offer) {
  const auto &mechanism = answer.mechanism;
  const auto integrity = mcx::aka::integrity_key_esp(mechanism.alg, answer.result.ck, answer.result.ik);
  const auto encryption = mcx::aka::encryption_key_esp(*mechanism.ealg, answer.result.ck);
  const auto salt = mcx::aka::esp_salt(mechanism.alg, *mechanism.ealg, answer.result.ck, answer.result.ik);
  const auto port_uc = *offer.port_c, port_us = *offer.port_s, port_pc = *mechanism.port_c, port_ps = *mechanism.port_s;
  const auto make = [&](bool outbound, std::uint16_t ue_port, std::uint16_t pcscf_port, std::uint32_t spi) {
    mcx::xfrm::SecurityAssociation sa;
    sa.source = outbound ? settings.ue_address : settings.pcscf_address;
    sa.destination = outbound ? settings.pcscf_address : settings.ue_address;
    sa.source_port = outbound ? ue_port : pcscf_port;
    sa.destination_port = outbound ? pcscf_port : ue_port;
    sa.spi = spi;
    sa.alg = mechanism.alg;
    sa.ealg = *mechanism.ealg;
    sa.outbound = outbound;
    sa.integrity_key = integrity;
    sa.encryption_key = encryption;
    const bool to_ue = !outbound;
    const bool from_server = to_ue ? sa.source_port == port_ps : sa.source_port == port_us;
    sa.salt = mcx::aka::sa_salt(salt, mechanism.alg, *mechanism.ealg, to_ue, from_server);
    return sa;
  };
  return {make(true, port_uc, port_ps, *mechanism.spi_s), make(true, port_us, port_pc, *mechanism.spi_c),
          make(false, port_uc, port_ps, *offer.spi_c), make(false, port_us, port_pc, *offer.spi_s)};
}

} // namespace

int main(int argc, char **argv) {
  const char *log_level = std::getenv("PROBE_LOG");
  resip::Log::initialize(resip::Log::Cout, log_level ? resip::Log::toLevel(log_level) : resip::Log::Warning, argv[0]);
  std::vector<mcx::xfrm::SecurityAssociation> installed;
  std::unique_ptr<mcx::xfrm::Xfrm> xfrm;
  try {
    const auto settings = load_settings(argc, argv);
    std::cout << "UE " << settings.ue_address << ", P-CSCF " << settings.pcscf_address << ':' << settings.pcscf_port
              << ", identity " << settings.identity << '\n';
    xfrm = std::make_unique<mcx::xfrm::Xfrm>();
    mcx::aka::SoftIsim isim(settings.k, settings.opc, "/tmp/aka-probe-sqn.json");

    // TS 33.203 clause 7.2 (as aka_new_offer): the offer: new SPIs, port_uc free, port_us the protected server port.
    mcx::aka::SecMechanism offer;
    offer.name = "ipsec-3gpp";
    offer.alg = std::string(mcx::aka::supported_esp_algorithms().front().alg);
    offer.ealg = std::string(mcx::aka::supported_esp_algorithms().front().ealg);
    offer.prot = "esp";
    offer.mod = "trans";
    offer.spi_c = 4096 + random_u32() % 1000000;
    offer.spi_s = *offer.spi_c + 1;
    offer.port_c = free_tcp_port(settings.ue_address);
    offer.port_s = protected_server_port;
    Stack sip(settings, *offer.port_c);
    Procedure procedure;
    procedure.security_client = mcx::aka::format_sec_mechanisms(mcx::aka::esp_offers(offer));

    std::cout << "Initial REGISTER, unprotected, from port " << unprotected_port << '\n';
    const auto initial_authorization = "Digest username=\"" + settings.impi + "\", realm=\"" + settings.domain +
                                       "\", uri=\"sip:" + settings.domain + "\", nonce=\"\", response=\"\"";
    const auto challenge = sip.transact(make_register(settings, procedure, unprotected_port, unprotected_port,
                                                      register_expires_s, initial_authorization, ""),
                                        settings, settings.pcscf_port);
    check(challenge && challenge->header(resip::h_StatusLine).statusCode() == 401,
          "TS 24.229 clause 5.1.1.2.2: 401 (Unauthorized) to the initial REGISTER");
    if (!challenge || challenge->header(resip::h_StatusLine).statusCode() != 401) throw std::runtime_error("no 401");
    const auto answer = answer_challenge(*challenge, settings, isim);
    if (!answer) throw std::runtime_error("cannot answer the challenge");
    const auto port_ps = *answer->mechanism.port_s;
    std::cout << "  set: alg " << answer->mechanism.alg << ", ealg " << *answer->mechanism.ealg << ", port_uc "
              << *offer.port_c << ", port_us " << *offer.port_s << ", port_pc " << *answer->mechanism.port_c
              << ", port_ps " << port_ps << '\n';

    for (const auto &sa : security_associations(settings, *answer, offer)) {
      xfrm->add(sa);
      installed.push_back(sa);
    }
    check(installed.size() == 4, "TS 33.203 clause 7.1: the four SAs of the set are installed");

    std::cout << "Protected REGISTER, TCP from port_uc " << *offer.port_c << " to port_ps " << port_ps << '\n';
    const auto registered =
        sip.transact(make_register(settings, procedure, *offer.port_c, *offer.port_s, register_expires_s,
                                   answer->authorization, answer->security_server),
                     settings, port_ps);
    const int status = registered ? registered->header(resip::h_StatusLine).statusCode() : 0;
    check(status == 200,
          "TS 24.229 clause 5.1.1.5.1: 200 (OK) to the protected REGISTER (status " + std::to_string(status) + ")");
    if (registered && status == 200) {
      const auto local = registered->getReceivedTransportTuple();
      check(local.getPort() == *offer.port_c,
            "TS 33.203 clause 7.1: the 200 came on the connection from port_uc (local port " +
                std::to_string(local.getPort()) + ")");
      std::cout << "  P-Associated-URI: " << header_text(*registered, "P-Associated-URI") << '\n'
                << "  Service-Route: " << header_text(*registered, "Service-Route") << '\n';
    }

    // TS 24.229 clause 5.1.1.6.2 and TS 33.203 clause 7.4 (as aka_register with a set in use): the deregistration goes
    // over the set in use with a new offer, new SPIs and a new port_uc, in its Security-Client (the P-CSCF refuses
    // a REGISTER that offers the set's port_uc again: "protected client port already in use").
    std::cout << "Deregistration (Expires 0), protected, with a new Security-Client offer\n";
    auto next_offer = offer;
    next_offer.spi_c = *offer.spi_c + 2;
    next_offer.spi_s = *offer.spi_c + 3;
    next_offer.port_c = free_tcp_port(settings.ue_address);
    procedure.security_client = mcx::aka::format_sec_mechanisms(mcx::aka::esp_offers(next_offer));
    const auto removed = sip.transact(make_register(settings, procedure, *offer.port_c, *offer.port_s, 0,
                                                    answer->authorization, answer->security_server),
                                      settings, port_ps);
    const int removed_status = removed ? removed->header(resip::h_StatusLine).statusCode() : 0;
    check(removed_status == 200,
          "TS 24.229 clause 5.1.1.6.2: 200 (OK) to the deregistration (status " + std::to_string(removed_status) + ")");
    if (removed && removed_status != 200) std::cout << "  response: " << removed->brief() << '\n';
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    ++failures;
  }
  for (const auto &sa : installed) xfrm->remove(sa);
  std::cout << (failures == 0 ? "PASS" : "FAIL") << ": IMS AKA over reSIProcate, " << failures << " failed checks\n";
  return failures == 0 ? 0 : 1;
}
