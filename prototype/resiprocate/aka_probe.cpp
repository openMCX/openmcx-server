//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Prototype (not part of any program): IMS AKA over reSIProcate 1.14, against the lab's P-CSCF (Kamailio with
// ims_ipsec_pcscf) and HSS, in the TCP and UDP cases of TS 33.203 clause 7.1. The requests are written as text and
// sent through reSIProcate's transaction layer (as src/sip/ims_aka.cpp sends them through pjsip's); the ISIM, the
// digest, the sec-agree mechanisms and the ESP keys are OpenMCX's (include/mcx/ims_aka.hpp), the SAs its XFRM code
// (include/mcx/xfrm.hpp). What reSIProcate has to provide is the transport behaviour of the pjproject patches
// (dependencies/pjproject):
//   - TCP (0001): requests on a TCP connection from port_uc to port_ps: a TCP transport on port_uc in reSIProcate's
//     "symmetric connections" mode, chosen through the top Via's sent-by;
//   - UDP (0002 and the engine's send override): everything sent from port_uc to port_ps, everything received on
//     port_us (the Via names port_us): a UDP transport on port_us whose sends leave from a socket on port_uc
//     (ProtectedUdpTransport); requests of 1300 bytes or more over TCP from port_uc (RFC 3261 section 18.1.1).
//
//   aka_probe --config aka-probe.json [--transport tcp|udp] [--pcscf pcscf] [--pcscf-port 5060]
//
// The steps: the initial registration (unprotected REGISTER, 401, SAs, protected REGISTER, 200); a subscription to
// the own reg event, whose NOTIFY the P-CSCF sends to port_us; with UDP, a MESSAGE of more than 1300 bytes to the own
// identity (over TCP both ways); with UDP, a reregistration that creates a new set and deletes the old one; the
// deregistration. Needs CAP_NET_ADMIN (the SAs) and the lab network. The config is the lab's aka-probe ISIM:
// {"identity": "sip:user@domain", "isim": {"impi": ..., "k": ..., "opc": ..., "amf": ...}}.
//
// Specifications: TS 24.229 V19.7.0 (Rel-19) clauses 4.2A, 5.1.1.2, 5.1.1.3, 5.1.1.4, 5.1.1.5 and 5.1.1.6,
// TS 33.203 V19.1.0 (Rel-19) clauses 6.1, 7.1, 7.2 and 7.4 and annexes H and I, RFC 3261, RFC 3310, RFC 3329,
// RFC 3680.

#include "mcx/ims_aka.hpp"
#include "mcx/xfrm.hpp"
#include "resip/stack/Helper.hxx"
#include "resip/stack/SendData.hxx"
#include "resip/stack/SipMessage.hxx"
#include "resip/stack/SipStack.hxx"
#include "resip/stack/TransactionUser.hxx"
#include "resip/stack/Tuple.hxx"
#include "resip/stack/UdpTransport.hxx"
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
#include <map>
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
// port port_us (the client's sip.port).
constexpr std::uint16_t unprotected_port = 5060;
constexpr std::uint16_t protected_server_port = 5064;
// The registration and subscription times asked for, and the time allowed for each response.
constexpr unsigned register_expires_s = 600;
constexpr unsigned subscription_expires_s = 600;
constexpr auto response_timeout = std::chrono::seconds(10);
// RFC 3261 section 18.1.1 and TS 24.229 clause 4.2A: a request "within 200 bytes of the path MTU, or ... larger than
// 1300 bytes" goes over a congestion-controlled transport: 1300 here, as src/sip/ims_aka.cpp.
constexpr std::size_t udp_size_limit = 1300;
// The size of the MESSAGE body that makes the request too large for UDP.
constexpr std::size_t large_body_bytes = 1500;
// How long the probe waits for the NOTIFY of the reg event and for a retransmission of it (RFC 3261 section 17.1.2.2:
// a UDP NOTIFY is retransmitted after T1 = 500 ms when no response arrived).
constexpr auto notify_wait = std::chrono::seconds(4);

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
// Helper: an IPv4 socket address.
sockaddr_in socket_address(const std::string &address, std::uint16_t port) {
  sockaddr_in result{};
  result.sin_family = AF_INET;
  result.sin_port = htons(port);
  if (inet_pton(AF_INET, address.c_str(), &result.sin_addr) != 1) throw std::runtime_error("bad address " + address);
  return result;
}

//------------------------------------------------------------------------------
// Helper: this host's address towards a destination (the source address the kernel picks for it).
std::string local_address_towards(const std::string &destination) {
  const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  const auto remote = socket_address(destination, 9);
  sockaddr_in local{};
  socklen_t length = sizeof local;
  if (fd < 0 || connect(fd, reinterpret_cast<const sockaddr *>(&remote), sizeof remote) != 0 ||
      getsockname(fd, reinterpret_cast<sockaddr *>(&local), &length) != 0)
    throw std::runtime_error("no route to " + destination);
  close(fd);
  char text[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &local.sin_addr, text, sizeof text);
  return text;
}

//------------------------------------------------------------------------------
// Helper: a port free for both TCP and UDP on the address, for port_uc (TS 33.203 clause 7.1: chosen by the UE).
std::uint16_t free_port(const std::string &address) {
  for (int attempt = 0; attempt < 200; ++attempt) {
    const auto port = static_cast<std::uint16_t>(20000 + random_u32() % 40000);
    bool is_free = true;
    for (const int type : {SOCK_STREAM, SOCK_DGRAM}) {
      const int fd = socket(AF_INET, type | SOCK_CLOEXEC, 0);
      const auto local = socket_address(address, port);
      is_free = is_free && bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof local) == 0;
      close(fd);
    }
    if (is_free) return port;
  }
  throw std::runtime_error("no free port for port_uc");
}

// TS 33.203 clause 7.1, UDP case (as the engine's aka_udp_send): the UDP transport on the protected server port
// port_us. It receives everything the P-CSCF sends; what the stack sends on it (requests, whose Via names port_us, and
// the responses to the P-CSCF's requests) leaves from a socket on port_uc of the set in use, to port_ps. Without a set
// nothing is sent (no unprotected messages on these ports).
class ProtectedUdpTransport : public resip::UdpTransport {
public:
  ProtectedUdpTransport(resip::Fifo<resip::TransactionMessage> &fifo, const std::string &address, std::uint16_t port_us)
      : UdpTransport(fifo, port_us, resip::V4, resip::StunDisabled, resip::Data(address)), address_(address) {}

  ~ProtectedUdpTransport() override {
    if (egress_ >= 0) ::close(egress_);
  }

  //------------------------------------------------------------------------------
  // TS 33.203 clause 7.1: the set in use: its port_uc (the socket sends leave from) and the P-CSCF's port_ps.
  void use_set(std::uint16_t port_uc, const std::string &pcscf, std::uint16_t port_ps) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    const auto local = socket_address(address_, port_uc);
    if (fd < 0 || ::bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof local) != 0)
      throw std::runtime_error("cannot bind the UDP port_uc " + std::to_string(port_uc));
    if (egress_ >= 0) ::close(egress_);
    egress_ = fd;
    egress_port_ = port_uc;
    destination_ = socket_address(pcscf, port_ps);
  }

  //------------------------------------------------------------------------------
  // The stack's send on port_us: out from port_uc to port_ps instead.
  void send(std::unique_ptr<resip::SendData> data) override {
    if (data->command != resip::SendData::NoCommand) return;
    if (egress_ < 0) {
      ++dropped;
      return;
    }
    const auto sent = ::sendto(egress_, data->data.data(), data->data.size(), 0,
                               reinterpret_cast<const sockaddr *>(&destination_), sizeof destination_);
    if (sent == static_cast<ssize_t>(data->data.size())) ++redirected;
  }

  std::uint16_t egress_port() const { return egress_port_; }

  unsigned redirected = 0; // messages sent from port_uc to port_ps
  unsigned dropped = 0;    // messages without a set

private:
  std::string address_;
  int egress_ = -1;
  std::uint16_t egress_port_ = 0;
  sockaddr_in destination_{};
};

// A request the probe received (and answered with 200), with the transport it came on.
struct Received {
  std::string method;
  unsigned cseq = 0;
  std::string call_id;
  resip::TransportType transport = resip::UNKNOWN_TRANSPORT;
  int local_port = 0;
  std::size_t bytes = 0;
};

// The probe's transaction user: every response of its requests comes to its queue; every request to it is answered
// with 200 (OK) and recorded.
class ProbeUser : public resip::TransactionUser {
public:
  const resip::Data &name() const override {
    static const resip::Data probe_name("openmcx-aka-probe");
    return probe_name;
  }

  //------------------------------------------------------------------------------
  // The next SIP response in the queue, if any; requests are answered and recorded on the way.
  std::unique_ptr<resip::SipMessage> next_response(resip::SipStack &stack) {
    while (mFifo.messageAvailable()) {
      std::unique_ptr<resip::Message> message(mFifo.getNext());
      auto *sip = dynamic_cast<resip::SipMessage *>(message.get());
      if (sip == nullptr) continue;
      if (sip->isResponse()) {
        message.release();
        return std::unique_ptr<resip::SipMessage>(sip);
      }
      answer(stack, *sip);
    }
    return nullptr;
  }

  std::vector<Received> received;

private:
  //------------------------------------------------------------------------------
  // RFC 3261 section 8.2.6 (RFC 3265 section 3.2.2 for a NOTIFY): 200 (OK) to a request, recorded with its transport.
  void answer(resip::SipStack &stack, const resip::SipMessage &request) {
    Received entry;
    entry.method = request.methodStr().c_str();
    entry.cseq = request.header(resip::h_CSeq).sequence();
    entry.call_id = request.header(resip::h_CallId).value().c_str();
    entry.transport = request.getReceivedTransportTuple().getType();
    entry.local_port = request.getReceivedTransportTuple().getPort();
    entry.bytes = request.getContents() ? request.getContents()->getBodyData().size() : 0;
    received.push_back(entry);
    if (request.method() == resip::ACK) return;
    std::unique_ptr<resip::SipMessage> response(resip::Helper::makeResponse(request, 200));
    stack.send(std::move(response), this);
  }
};

// The probe's settings: the ISIM, the identity, the addresses and the transport.
struct Settings {
  std::string identity; // sip:user@domain, From and To
  std::string impi;     // the private user identity, Authorization username
  std::string domain;   // the home domain, Request-URI and realm of the initial REGISTER
  std::string user;     // the user part of the identity, the Contact's
  mcx::aka::Key k{}, opc{};
  std::string pcscf_address;
  std::uint16_t pcscf_port = 5060;
  std::string ue_address;
  bool udp = false;
};

//------------------------------------------------------------------------------
// Reads the lab's aka-probe configuration and resolves the P-CSCF.
Settings load_settings(int argc, char **argv) {
  std::string config_path, pcscf = "pcscf";
  Settings settings;
  for (int index = 1; index + 1 < argc; index += 2) {
    const std::string option = argv[index], value = argv[index + 1];
    if (option == "--config")
      config_path = value;
    else if (option == "--pcscf")
      pcscf = value;
    else if (option == "--pcscf-port")
      settings.pcscf_port = static_cast<std::uint16_t>(std::stoi(value));
    else if (option == "--transport" && (value == "tcp" || value == "udp"))
      settings.udp = value == "udp";
    else
      throw std::invalid_argument("unknown option " + option + " " + value);
  }
  if (config_path.empty())
    throw std::invalid_argument("usage: aka_probe --config FILE [--transport tcp|udp] [--pcscf HOST] [--pcscf-port N]");
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
// increasing), and the set of SAs in use.
struct Procedure {
  std::string call_id = random_hex(12);
  std::string from_tag = random_hex(6);
  unsigned cseq = 0;
  std::string security_client;
  std::string authorization;
  std::string security_server;
  mcx::aka::SecMechanism offer;
  mcx::aka::SecMechanism mechanism;
  std::vector<mcx::xfrm::SecurityAssociation> sas;
  std::string service_route;
};

// Where a request goes: the transport, the sent-by port of the top Via (which picks reSIProcate's transport) and the
// P-CSCF's port.
struct Hop {
  bool tcp = true;
  std::uint16_t via_port = 0;
  std::uint16_t pcscf_port = 0;
};

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.2.1 and 5.1.1.5.1 (as src/sip/ims_aka.cpp aka_send_register): one REGISTER of the procedure,
// as text: Via with our sent-by, Request-URI the home domain, From and To the identity, Contact, Expires,
// Authorization, Security-Client, Security-Verify when protected, Require and Proxy-Require "sec-agree", Supported
// "path".
std::string register_text(const Settings &settings, Procedure &procedure, const Hop &hop, std::uint16_t contact_port,
                          unsigned expires, bool is_protected) {
  const char *transport = hop.tcp ? "TCP" : "UDP";
  std::ostringstream text;
  text << "REGISTER sip:" << settings.domain << " SIP/2.0\r\n"
       << "Via: SIP/2.0/" << transport << ' ' << settings.ue_address << ':' << hop.via_port << ";branch=z9hG4bK"
       << random_hex(10) << "\r\n"
       << "Max-Forwards: 70\r\n"
       << "From: <" << settings.identity << ">;tag=" << procedure.from_tag << "\r\n"
       << "To: <" << settings.identity << ">\r\n"
       << "Call-ID: " << procedure.call_id << "\r\n"
       << "CSeq: " << ++procedure.cseq << " REGISTER\r\n"
       << "Contact: <sip:" << settings.user << '@' << settings.ue_address << ':' << contact_port
       << (settings.udp ? ";transport=udp" : ";transport=tcp") << ">\r\n"
       << "Expires: " << expires << "\r\n"
       << "Authorization: " << procedure.authorization << "\r\n"
       << "Security-Client: " << procedure.security_client << "\r\n";
  if (is_protected) text << "Security-Verify: " << procedure.security_server << "\r\n";
  text << "Require: sec-agree\r\nProxy-Require: sec-agree\r\nSupported: path\r\nContent-Length: 0\r\n\r\n";
  return text.str();
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.2A.1.1 (requests after registration): a request to the own identity with the Service-Route of
// the registration as its Route, the Contact on port_us, other header fields and the body as given.
std::string request_text(const Settings &settings, const Procedure &procedure, const std::string &method,
                         const Hop &hop, const std::string &extra_headers, const std::string &body) {
  std::ostringstream text;
  text << method << ' ' << settings.identity << " SIP/2.0\r\n"
       << "Via: SIP/2.0/" << (hop.tcp ? "TCP" : "UDP") << ' ' << settings.ue_address << ':' << hop.via_port
       << ";branch=z9hG4bK" << random_hex(10) << "\r\n"
       << "Max-Forwards: 70\r\n"
       << "Route: " << procedure.service_route << "\r\n"
       << "From: <" << settings.identity << ">;tag=" << random_hex(6) << "\r\n"
       << "To: <" << settings.identity << ">\r\n"
       << "Call-ID: " << random_hex(12) << "\r\n"
       << "CSeq: 1 " << method << "\r\n"
       << "Contact: <sip:" << settings.user << '@' << settings.ue_address << ':' << protected_server_port
       << (settings.udp ? ";transport=udp" : ";transport=tcp")
       << ">\r\n"
       // TS 24.229 clause 5.1.2A.1.1 (as aka_sec_agree): every request over the set carries Security-Verify with
       // Require and Proxy-Require "sec-agree" (the P-CSCF answers 494 otherwise).
       << "Security-Verify: " << procedure.security_server << "\r\n"
       << "Require: sec-agree\r\nProxy-Require: sec-agree\r\n"
       << extra_headers << "Content-Length: " << body.size() << "\r\n\r\n"
       << body;
  return text.str();
}

// The stack, its transports in one epoll poll group, and the probe's transaction user.
struct Stack {
  std::unique_ptr<resip::FdPollGrp> group{resip::FdPollGrp::create("epoll")};
  resip::SipStack stack;
  ProbeUser user;
  ProtectedUdpTransport *protected_udp = nullptr;

  //------------------------------------------------------------------------------
  // TS 33.203 clause 7.1: TCP on the unprotected port, on the protected server port port_us and on the protected
  // client port port_uc in "symmetric connections" mode (its connections come from port_uc); with UDP also the
  // unprotected UDP port and ProtectedUdpTransport on port_us.
  Stack(const Settings &settings, std::uint16_t port_uc) : stack(options(*group)) {
    const resip::Data interface(settings.ue_address);
    stack.addTransport(resip::TCP, unprotected_port, resip::V4, resip::StunDisabled, interface);
    stack.addTransport(resip::TCP, protected_server_port, resip::V4, resip::StunDisabled, interface);
    stack.addTransport(resip::TCP, port_uc, resip::V4, resip::StunDisabled, interface, resip::Data::Empty,
                       resip::Data::Empty, resip::SecurityTypes::SSLv23, RESIP_TRANSPORT_FLAG_SYMMETRIC_CONNECTIONS);
    if (settings.udp) {
      stack.addTransport(resip::UDP, unprotected_port, resip::V4, resip::StunDisabled, interface);
      auto transport =
          std::make_unique<ProtectedUdpTransport>(stack.stateMacFifo(), settings.ue_address, protected_server_port);
      protected_udp = transport.get();
      stack.addTransport(std::move(transport));
    }
    stack.registerTransactionUser(user);
  }

  static resip::SipStackOptions options(resip::FdPollGrp &poll_group) {
    resip::SipStackOptions result;
    result.mPollGrp = &poll_group;
    return result;
  }

  //------------------------------------------------------------------------------
  // Runs the stack for a while, answering requests (responses that come are dropped).
  void run_for(std::chrono::milliseconds duration) {
    const auto deadline = Clock::now() + duration;
    while (Clock::now() < deadline) {
      stack.process(50);
      while (user.next_response(stack)) {}
    }
  }

  //------------------------------------------------------------------------------
  // Sends a request to the P-CSCF's port and waits for its final response (provisional ones are skipped). The next
  // hop is a forced target (SipStack::sendTo with a Tuple does not override the target the transaction resolves); the
  // source transport is the top Via's sent-by.
  std::unique_ptr<resip::SipMessage> transact(const std::string &text, const Settings &settings, const Hop &hop) {
    const resip::Data wire(text);
    std::unique_ptr<resip::SipMessage> request(resip::SipMessage::make(wire, false));
    request->setForceTarget(
        resip::Uri(resip::Data("sip:" + settings.pcscf_address + ":" + std::to_string(hop.pcscf_port) +
                               (hop.tcp ? ";transport=tcp" : ";transport=udp"))));
    stack.send(std::move(request), &user);
    const auto deadline = Clock::now() + response_timeout;
    while (Clock::now() < deadline) {
      stack.process(50);
      while (auto response = user.next_response(stack)) {
        if (response->header(resip::h_StatusLine).statusCode() >= 200) return response;
      }
    }
    return nullptr;
  }
};

//------------------------------------------------------------------------------
// Helper: the values of a header field of a message as received (all of its values, comma-separated).
std::string header_text(const resip::SipMessage &message, const char *name) {
  std::string out;
  const auto *values = message.getRawHeader(resip::Headers::getType(name, static_cast<int>(std::strlen(name))));
  if (values == nullptr) return out;
  for (const auto &value : *values)
    out += (out.empty() ? "" : ", ") + std::string(value.getBuffer(), value.getLength());
  return out;
}

//------------------------------------------------------------------------------
// Helper: the status code of a response, 0 for none.
int status_of(const std::unique_ptr<resip::SipMessage> &response) {
  return response ? response->header(resip::h_StatusLine).statusCode() : 0;
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.2 (as aka_new_offer): an offer with new SPIs and a new port_uc, port_us the protected server
// port.
mcx::aka::SecMechanism new_offer(const Settings &settings) {
  mcx::aka::SecMechanism offer;
  offer.name = "ipsec-3gpp";
  offer.alg = std::string(mcx::aka::supported_esp_algorithms().front().alg);
  offer.ealg = std::string(mcx::aka::supported_esp_algorithms().front().ealg);
  offer.prot = "esp";
  offer.mod = "trans";
  offer.spi_c = 4096 + random_u32() % 1000000;
  offer.spi_s = *offer.spi_c + 1;
  offer.port_c = free_port(settings.ue_address);
  offer.port_s = protected_server_port;
  return offer;
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.5.1 (as aka_challenge): the AKA challenge of a 401: the ISIM authenticates RAND and AUTN, the
// UE takes a mechanism from the Security-Server (TS 33.203 clause 7.2) and computes the Authorization (RFC 3310
// section 3.3). Fills the procedure's authorization, Security-Server and mechanism; false when it cannot.
bool answer_challenge(const resip::SipMessage &challenge, const Settings &settings, mcx::aka::SoftIsim &isim,
                      Procedure &procedure, mcx::aka::AuthResult &result) {
  if (!challenge.exists(resip::h_WWWAuthenticates)) return false;
  const auto &digest = challenge.header(resip::h_WWWAuthenticates).front();
  const std::string algorithm_text = digest.exists(resip::p_algorithm) ? digest.param(resip::p_algorithm).c_str() : "";
  const auto algorithm = mcx::aka::aka_algorithm(algorithm_text);
  const std::string nonce = digest.param(resip::p_nonce).c_str();
  const std::string realm = digest.param(resip::p_realm).c_str();
  const auto parsed = mcx::aka::parse_nonce(nonce);
  check(algorithm.has_value() && parsed.has_value(),
        "RFC 3310: the 401 carries an AKA challenge (" + algorithm_text + ")");
  if (!algorithm || !parsed) return false;
  result = isim.authenticate(parsed->rand, parsed->autn);
  check(result.status == mcx::aka::AuthStatus::success, "TS 33.102 clause 6.3.3: the ISIM accepts the challenge");
  if (result.status != mcx::aka::AuthStatus::success) return false;

  procedure.security_server = header_text(challenge, "Security-Server");
  const auto mechanism = mcx::aka::select_mechanism(mcx::aka::parse_sec_mechanisms(procedure.security_server));
  check(mechanism.has_value(), "TS 33.203 clause 7.2: the Security-Server offers a mechanism the UE supports");
  if (!mechanism) return false;
  procedure.mechanism = *mechanism;

  const auto uri = "sip:" + settings.domain;
  const auto password = mcx::aka::digest_password(*algorithm, result);
  const bool qop_auth = digest.exists(resip::p_qopOptions) &&
                        std::string(digest.param(resip::p_qopOptions).c_str()).find("auth") != std::string::npos;
  const std::string cnonce = qop_auth ? random_hex(16) : "", nc = qop_auth ? "00000001" : "",
                    qop = qop_auth ? "auth" : "";
  const auto response =
      mcx::aka::digest_response(*algorithm, settings.impi, realm, password, "REGISTER", uri, nonce, nc, cnonce, qop);
  procedure.authorization = "Digest username=\"" + settings.impi + "\", realm=\"" + realm + "\", nonce=\"" + nonce +
                            "\", uri=\"" + uri + "\", response=\"" + response +
                            "\", algorithm=" + std::string(mcx::aka::algorithm_name(*algorithm));
  if (qop_auth) procedure.authorization += ", qop=auth, nc=" + nc + ", cnonce=\"" + cnonce + "\"";
  if (digest.exists(resip::p_opaque))
    procedure.authorization += ", opaque=\"" + std::string(digest.param(resip::p_opaque).c_str()) + "\"";
  return true;
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 and annex I (as aka_install): the four SAs of a set: UE port_uc to P-CSCF port_ps and UE
// port_us to P-CSCF port_pc outbound, and the reverse inbound, with IK_ESP, CK_ESP and the salt of annex I.
std::vector<mcx::xfrm::SecurityAssociation> security_associations(const Settings &settings, const Procedure &procedure,
                                                                  const mcx::aka::AuthResult &result) {
  const auto &mechanism = procedure.mechanism;
  const auto &offer = procedure.offer;
  const auto integrity = mcx::aka::integrity_key_esp(mechanism.alg, result.ck, result.ik);
  const auto encryption = mcx::aka::encryption_key_esp(*mechanism.ealg, result.ck);
  const auto salt = mcx::aka::esp_salt(mechanism.alg, *mechanism.ealg, result.ck, result.ik);
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

// The probe: the stack, the ISIM, XFRM and the set in use, and the steps.
class Probe {
public:
  explicit Probe(const Settings &settings)
      : settings_(settings), isim_(settings.k, settings.opc, "/tmp/aka-probe-sqn.json") {
    procedure_.offer = new_offer(settings_);
    stack_ = std::make_unique<Stack>(settings_, *procedure_.offer.port_c);
  }

  ~Probe() {
    for (const auto &sa : procedure_.sas) xfrm_.remove(sa);
  }

  //------------------------------------------------------------------------------
  // TS 24.229 clauses 5.1.1.2 and 5.1.1.5.1: the initial registration: the unprotected REGISTER, its 401, the SAs of
  // the challenge, the protected REGISTER and its 200.
  bool register_initially() {
    std::cout << "Initial REGISTER, unprotected " << (settings_.udp ? "UDP" : "TCP") << ", from port "
              << unprotected_port << '\n';
    procedure_.security_client = mcx::aka::format_sec_mechanisms(mcx::aka::esp_offers(procedure_.offer));
    procedure_.authorization = "Digest username=\"" + settings_.impi + "\", realm=\"" + settings_.domain +
                               "\", uri=\"sip:" + settings_.domain + "\", nonce=\"\", response=\"\"";
    const Hop unprotected{!settings_.udp, unprotected_port, settings_.pcscf_port};
    const auto challenge =
        stack_->transact(register_text(settings_, procedure_, unprotected, unprotected_port, register_expires_s, false),
                         settings_, unprotected);
    check(status_of(challenge) == 401, "TS 24.229 clause 5.1.1.2.2: 401 (Unauthorized) to the initial REGISTER");
    if (status_of(challenge) != 401) return false;
    mcx::aka::AuthResult result;
    if (!answer_challenge(*challenge, settings_, isim_, procedure_, result)) return false;
    install(result);
    return register_protected("Protected REGISTER");
  }

  //------------------------------------------------------------------------------
  // TS 24.229 clause 5.1.1.3 and RFC 3680: a subscription to the own reg event over the set; the network's NOTIFY comes
  // to port_us (TCP: on a connection from port_pc; UDP: on port_us, and the probe's 200 leaves from port_uc). With UDP,
  // the P-CSCF must have had the 200: it does not retransmit the NOTIFY.
  void subscribe_reg_event() {
    std::cout << "SUBSCRIBE to the own reg event, protected\n";
    const auto before = stack_->user.received.size();
    const auto response = stack_->transact(request_text(settings_, procedure_, "SUBSCRIBE", request_hop(0),
                                                        "Event: reg\r\nAccept: application/reginfo+xml\r\nExpires: " +
                                                            std::to_string(subscription_expires_s) + "\r\n",
                                                        ""),
                                           settings_, request_hop(0));
    check(status_of(response) >= 200 && status_of(response) < 300,
          "TS 24.229 clause 5.1.1.3: 2xx to the SUBSCRIBE (status " + std::to_string(status_of(response)) + ")");
    stack_->run_for(std::chrono::duration_cast<std::chrono::milliseconds>(notify_wait));
    std::map<unsigned, int> by_cseq;
    const Received *first = nullptr;
    for (auto index = before; index < stack_->user.received.size(); ++index) {
      const auto &entry = stack_->user.received[index];
      if (entry.method != "NOTIFY") continue;
      ++by_cseq[entry.cseq];
      if (first == nullptr) first = &entry;
    }
    check(first != nullptr, "RFC 3680: the NOTIFY of the reg event arrives");
    if (first == nullptr) return;
    check(first->local_port == protected_server_port, "TS 33.203 clause 7.1: the NOTIFY came to port_us (" +
                                                          std::string(resip::toData(first->transport).c_str()) +
                                                          " port " + std::to_string(first->local_port) + ")");
    bool retransmitted = false;
    for (const auto &[cseq, count] : by_cseq) retransmitted = retransmitted || count > 1;
    check(!retransmitted, "RFC 3261 section 17.1.2.2: no NOTIFY retransmitted: the P-CSCF had the probe's 200");
  }

  //------------------------------------------------------------------------------
  // RFC 3261 section 18.1.1 and TS 24.229 clause 4.2A (UDP case): a MESSAGE of more than 1300 bytes to the own
  // identity goes over TCP from port_uc to port_ps; the network delivers it back to port_us.
  void send_large_message() {
    const std::string body(large_body_bytes, 'x');
    const auto udp_text =
        request_text(settings_, procedure_, "MESSAGE", request_hop(body.size()), "Content-Type: text/plain\r\n", body);
    const bool is_large = udp_text.size() >= udp_size_limit;
    std::cout << "MESSAGE of " << udp_text.size() << " bytes, protected, over "
              << (request_hop(body.size()).tcp ? "TCP" : "UDP") << '\n';
    const auto before = stack_->user.received.size();
    const auto response = stack_->transact(udp_text, settings_, request_hop(body.size()));
    check(is_large && request_hop(body.size()).tcp,
          "RFC 3261 section 18.1.1: a request of 1300 bytes or more goes over TCP from port_uc");
    // The response came back on that connection. The lab's SIP core relays requests between users only through an
    // application server, and answers this one 403 "Route forbidden" (generated/kamailio.cfg): a final response from
    // the core shows the request crossed the P-CSCF; a delivery back to the probe needs an application server.
    const bool on_connection = response && response->getReceivedTransportTuple().getType() == resip::TCP &&
                               response->getReceivedTransportTuple().getPort() == *procedure_.offer.port_c;
    check(on_connection, "TS 33.203 clause 7.1: its final response (" + std::to_string(status_of(response)) +
                             ") came on the TCP connection from port_uc");
    stack_->run_for(std::chrono::seconds(2));
    for (auto index = before; index < stack_->user.received.size(); ++index) {
      const auto &entry = stack_->user.received[index];
      if (entry.method != "MESSAGE") continue;
      check(entry.local_port == protected_server_port && entry.transport == resip::TCP && entry.bytes == body.size(),
            "TS 33.203 clause 7.1: the MESSAGE came back on port_us over TCP, whole (" + std::to_string(entry.bytes) +
                " bytes)");
      return;
    }
    std::cout << "  (not delivered back to the probe: the lab's core relays user to user only through an AS)\n";
  }

  //------------------------------------------------------------------------------
  // TS 24.229 clause 5.1.1.4 and TS 33.203 clause 7.4: a reregistration over the set in use with a new offer; on a 401
  // a new set, the REGISTER over it, its 200: the new set is used and the old one deleted.
  void reregister() {
    std::cout << "Reregistration over the set in use, new Security-Client offer\n";
    auto next = procedure_;
    next.offer = new_offer(settings_);
    next.security_client = mcx::aka::format_sec_mechanisms(mcx::aka::esp_offers(next.offer));
    const auto challenge = stack_->transact(
        register_text(settings_, next, register_hop(), protected_server_port, register_expires_s, true), settings_,
        register_hop());
    procedure_.cseq = next.cseq;
    if (status_of(challenge) == 200) {
      check(true, "TS 24.229 clause 5.1.1.4.1: 200 (OK) to the reregistration, no new challenge");
      return;
    }
    check(status_of(challenge) == 401, "TS 24.229 clause 5.1.1.5.1: 401 to the reregistration, a new challenge");
    if (status_of(challenge) != 401) return;
    mcx::aka::AuthResult result;
    if (!answer_challenge(*challenge, settings_, isim_, next, result)) return;
    const auto old_sas = procedure_.sas;
    next.sas.clear();
    procedure_ = next;
    install(result);
    if (!register_protected("REGISTER over the new set")) return;
    for (const auto &sa : old_sas) xfrm_.remove(sa);
    check(true, "TS 33.203 clause 7.4: the old set's SAs are deleted after the new set's 200");
  }

  //------------------------------------------------------------------------------
  // TS 24.229 clause 5.1.1.6.2 (as aka_register with a set in use): the deregistration over the set in use, with a new
  // offer in its Security-Client (the P-CSCF refuses one that offers the set's port_uc again).
  void deregister() {
    std::cout << "Deregistration (Expires 0), protected, new Security-Client offer\n";
    auto request = procedure_;
    request.security_client = mcx::aka::format_sec_mechanisms(mcx::aka::esp_offers(new_offer(settings_)));
    const auto removed = stack_->transact(
        register_text(settings_, request, register_hop(), protected_server_port, 0, true), settings_, register_hop());
    check(status_of(removed) == 200, "TS 24.229 clause 5.1.1.6.2: 200 (OK) to the deregistration (status " +
                                         std::to_string(status_of(removed)) + ")");
  }

  //------------------------------------------------------------------------------
  // With UDP, what ProtectedUdpTransport did: every message on port_us left from port_uc, none without a set.
  void report_udp() const {
    if (stack_->protected_udp == nullptr) return;
    check(stack_->protected_udp->redirected > 0 && stack_->protected_udp->dropped == 0,
          "TS 33.203 clause 7.1 (UDP): " + std::to_string(stack_->protected_udp->redirected) +
              " messages sent from port_uc to port_ps, " + std::to_string(stack_->protected_udp->dropped) +
              " without a set");
  }

private:
  //------------------------------------------------------------------------------
  // TS 33.203 clause 7.1: the set's SAs, and with UDP its port_uc for what ProtectedUdpTransport sends.
  void install(const mcx::aka::AuthResult &result) {
    std::cout << "  set: alg " << procedure_.mechanism.alg << ", ealg " << *procedure_.mechanism.ealg << ", port_uc "
              << *procedure_.offer.port_c << ", port_us " << *procedure_.offer.port_s << ", port_pc "
              << *procedure_.mechanism.port_c << ", port_ps " << *procedure_.mechanism.port_s << '\n';
    for (const auto &sa : security_associations(settings_, procedure_, result)) {
      xfrm_.add(sa);
      procedure_.sas.push_back(sa);
    }
    check(procedure_.sas.size() == 4, "TS 33.203 clause 7.1: the four SAs of the set are installed");
    if (stack_->protected_udp != nullptr)
      stack_->protected_udp->use_set(*procedure_.offer.port_c, settings_.pcscf_address, *procedure_.mechanism.port_s);
  }

  //------------------------------------------------------------------------------
  // TS 24.229 clause 5.1.1.5.1 step 4: the REGISTER over the set just installed; on its 200 the Service-Route is kept.
  bool register_protected(const char *what) {
    std::cout << what << ", " << (settings_.udp ? "UDP" : "TCP") << " from port_uc " << *procedure_.offer.port_c
              << " to port_ps " << *procedure_.mechanism.port_s << '\n';
    const auto registered = stack_->transact(
        register_text(settings_, procedure_, register_hop(), protected_server_port, register_expires_s, true),
        settings_, register_hop());
    check(status_of(registered) == 200,
          "TS 24.229 clause 5.1.1.5.1: 200 (OK) (status " + std::to_string(status_of(registered)) + ")");
    if (status_of(registered) != 200) return false;
    const auto local = registered->getReceivedTransportTuple();
    const int expected = settings_.udp ? protected_server_port : *procedure_.offer.port_c;
    check(local.getPort() == expected, std::string("TS 33.203 clause 7.1: the 200 came ") +
                                           (settings_.udp ? "to port_us" : "on the connection from port_uc") +
                                           " (local port " + std::to_string(local.getPort()) + ")");
    procedure_.service_route = header_text(*registered, "Service-Route");
    std::cout << "  P-Associated-URI: " << header_text(*registered, "P-Associated-URI")
              << "\n  Service-Route: " << procedure_.service_route << '\n';
    return true;
  }

  //------------------------------------------------------------------------------
  // TS 33.203 clause 7.1: where a REGISTER of the set in use goes: TCP, Via port_uc (the symmetric transport); UDP,
  // Via port_us (ProtectedUdpTransport, which sends from port_uc); to port_ps.
  Hop register_hop() const {
    return {!settings_.udp, settings_.udp ? protected_server_port : *procedure_.offer.port_c,
            *procedure_.mechanism.port_s};
  }

  //------------------------------------------------------------------------------
  // The hop of a request after registration of the given body size: as a REGISTER, but over TCP from port_uc when the
  // request would be 1300 bytes or more (RFC 3261 section 18.1.1).
  Hop request_hop(std::size_t body_bytes) const {
    auto hop = register_hop();
    if (settings_.udp && body_bytes + 600 >= udp_size_limit) hop = {true, *procedure_.offer.port_c, hop.pcscf_port};
    return hop;
  }

  Settings settings_;
  mcx::aka::SoftIsim isim_;
  mcx::xfrm::Xfrm xfrm_;
  Procedure procedure_;
  std::unique_ptr<Stack> stack_;
};

} // namespace

int main(int argc, char **argv) {
  const char *log_level = std::getenv("PROBE_LOG");
  resip::Log::initialize(resip::Log::Cout, log_level ? resip::Log::toLevel(log_level) : resip::Log::Warning, argv[0]);
  try {
    const auto settings = load_settings(argc, argv);
    std::cout << "UE " << settings.ue_address << ", P-CSCF " << settings.pcscf_address << ':' << settings.pcscf_port
              << ", identity " << settings.identity << ", " << (settings.udp ? "UDP" : "TCP") << '\n';
    Probe probe(settings);
    if (probe.register_initially()) {
      probe.subscribe_reg_event();
      if (settings.udp) {
        probe.send_large_message();
        probe.reregister();
      }
      probe.deregister();
    }
    probe.report_udp();
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    ++failures;
  }
  std::cout << (failures == 0 ? "PASS" : "FAIL") << ": IMS AKA over reSIProcate, " << failures << " failed checks\n";
  return failures == 0 ? 0 : 1;
}
