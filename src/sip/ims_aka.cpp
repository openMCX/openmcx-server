//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IMS AKA registration of SipEngine::Impl on reSIProcate (SipConfig::aka), the port of src/sip/ims_aka.cpp: the UE's
// own REGISTER transactions with sec-agree (RFC 3329), the authentication by the software ISIM (include/mcx/
// ims_aka.hpp), its sets of IPsec security associations over XFRM (include/mcx/xfrm.hpp) and the SIP signalling
// inside them, over TCP (requests from the protected client port port_uc to the P-CSCF's protected server port
// port_ps, requests of the P-CSCF accepted on the protected server port port_us) or over UDP (requests and responses
// from port_uc to port_ps, everything received on port_us; requests of 1300 bytes or more over TCP), TS 33.203 clause
// 7.1, TS 24.229 clause 4.2A, on the transports of aka_transports.hpp: the receive filter, the symmetric TCP transports of port_uc and of the unprotected port, and
// the UDP transport of port_us that sends from port_uc of the set in use.
//
// Specifications: TS 24.229 V19.7.0 (Rel-19) clauses 5.1.1.2, 5.1.1.4, 5.1.1.5, 5.1.1.6 and 5.1.2A.1,
// TS 33.203 V19.1.0 (Rel-19) clauses 6.1, 6.3, 7.1 to 7.4 and annexes H and I, TS 33.102 V19.1.0 (Rel-19),
// RFC 3261 (clause 18), RFC 3310, RFC 3329, RFC 4169.

#include "resip_impl.hpp"

#include "resip/stack/Helper.hxx"
#include "resip/stack/Transport.hxx"

#include <openssl/rand.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <stdexcept>

namespace mcx {
namespace {
// TS 24.229 table 7.7.1: reg-await-auth, the SIP level lifetime of the temporary set (clause 5.1.1.5.1 step 2).
constexpr std::chrono::minutes reg_await_auth{4};
// TS 33.203 clause 7.4.1a: how often the old set's pending transactions are looked at until none is left (a polling
// interval, not a protocol timer).
constexpr std::chrono::seconds old_set_poll{1};
// TS 24.229 clauses 5.1.1.2.2 and 5.1.1.4.2: the SA lifetime is the registration's plus 30 seconds.
constexpr std::chrono::seconds sa_lifetime_margin{30};
// RFC 3261 section 17.2.2 (Timer J) and 17.1.2.2 (Timer K): how long a transaction over UDP lasts after its final
// response (64*T1), during which it is still a pending transaction of its set; over TCP it ends with the response.
constexpr std::chrono::seconds udp_transaction_linger{32};
// RFC 3261 section 18.1.1 and TS 24.229 clause 4.2A: a request of 1300 bytes or more goes over TCP.
constexpr std::size_t udp_size_limit = 1300;

using sip_detail::ascii_equal;

//------------------------------------------------------------------------------
// Helper: a random 32-bit value from OpenSSL's generator.
std::uint32_t random_u32() {
  std::uint32_t value = 0;
  if (RAND_bytes(reinterpret_cast<unsigned char *>(&value), sizeof(value)) != 1)
    throw std::runtime_error("could not draw a random value");
  return value;
}

//------------------------------------------------------------------------------
// Helper: whether a TCP (or UDP) port of the address can be bound now.
bool port_free(const std::string &address, std::uint16_t port, int type = SOCK_STREAM) {
  const bool v6 = address.find(':') != std::string::npos;
  const int fd = ::socket(v6 ? AF_INET6 : AF_INET, type, 0);
  if (fd < 0) return false;
  int enabled = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
  bool bound = false;
  if (v6) {
    sockaddr_in6 local{};
    local.sin6_family = AF_INET6;
    local.sin6_port = htons(port);
    bound = inet_pton(AF_INET6, address.c_str(), &local.sin6_addr) == 1 &&
            ::bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0;
  } else {
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    bound = inet_pton(AF_INET, address.c_str(), &local.sin_addr) == 1 &&
            ::bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == 0;
  }
  ::close(fd);
  return bound;
}

//------------------------------------------------------------------------------
// Helper: whether two numeric IP addresses are the same address (IPv4 or IPv6, any spelling).
bool same_address(std::string_view left, std::string_view right) {
  const std::string a(left), b(right);
  unsigned char x[16]{}, y[16]{};
  const int family = a.find(':') != std::string::npos ? AF_INET6 : AF_INET;
  return inet_pton(family, a.c_str(), x) == 1 && inet_pton(family, b.c_str(), y) == 1 &&
         std::memcmp(x, y, family == AF_INET6 ? 16 : 4) == 0;
}

//------------------------------------------------------------------------------
// Helper: a host for a SIP URI: an IPv6 address in brackets (RFC 3261 section 25.1).
std::string uri_host(const std::string &address) {
  return address.find(':') != std::string::npos ? "[" + address + "]" : address;
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.3.1: the entries of header field values that may be comma-separated lists of name-addr values
// (Service-Route, P-Associated-URI), each as sent; commas inside <...> or quotes do not separate.
std::vector<std::string> header_list(const std::vector<SipHeader> &headers, std::string_view name) {
  std::vector<std::string> out;
  for (const auto &header : headers) {
    if (!ascii_equal(header.name, name)) continue;
    std::string current;
    bool angle = false, quoted = false;
    for (const char c : header.value) {
      if (c == '"' && !angle) quoted = !quoted;
      if (c == '<' && !quoted) angle = true;
      if (c == '>' && !quoted) angle = false;
      if (c == ',' && !angle && !quoted) {
        out.push_back(current);
        current.clear();
        continue;
      }
      current.push_back(c);
    }
    out.push_back(current);
  }
  for (auto &entry : out) {
    const auto first = entry.find_first_not_of(" \t");
    entry = first == std::string::npos ? std::string{} : entry.substr(first, entry.find_last_not_of(" \t") - first + 1);
  }
  std::erase_if(out, [](const std::string &entry) { return entry.empty(); });
  return out;
}

//------------------------------------------------------------------------------
// Helper: a P-CSCF target URI for reSIProcate's forced next hop.
std::string pcscf_target(const SipConfig &config, int port, resip::TransportType type) {
  return "sip:" + uri_host(config.aka.pcscf_address) + ":" + std::to_string(port) +
         (type == resip::UDP ? ";transport=udp" : ";transport=tcp");
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.203 clauses 7.1 and 7.2: starts IMS AKA: the XFRM access (CAP_NET_ADMIN), the ISIM, the TCP transport of the
// protected server port port_us (the P-CSCF connects to it from port_pc), the unprotected TCP transport of the initial
// REGISTER (its connections from the unprotected port), over UDP also the UDP transports of port_us and of the
// unprotected port; every one of them with the receive filter of rules 4 and 7 (aka_accept).
void SipEngine::Impl::aka_start() {
  aka = std::make_unique<Aka>();
  aka->xfrm = std::make_unique<xfrm::Xfrm>();
  const bool test = config.aka.algorithm == "test";
  aka->isim = std::make_unique<aka::SoftIsim>(
      aka::key_from_hex(config.aka.k), test && config.aka.opc.empty() ? aka::Key{} : aka::key_from_hex(config.aka.opc),
      config.aka.sqn_file, test ? aka::IsimAlgorithm::test : aka::IsimAlgorithm::milenage, config.aka.res_length);
  const resip_engine::ReceiveFilter filter = [this](const resip::SipMessage &message, int local_port) {
    return aka_accept(message, local_port);
  };
  auto &fifo = stack->stateMacFifo();
  stack->addTransport(std::make_unique<resip_engine::FilteredTcpTransport>(fifo, config.listen_port,
                                                                           config.listen_address, 0, filter));
  stack->addTransport(std::make_unique<resip_engine::FilteredTcpTransport>(
      fifo, config.aka.unprotected_port, config.listen_address, RESIP_TRANSPORT_FLAG_SYMMETRIC_CONNECTIONS, filter));
  if (config.aka.udp) {
    auto port_us = std::make_unique<resip_engine::ProtectedUdpTransport>(fifo, config.listen_port,
                                                                          config.listen_address, filter);
    aka->udp_us = port_us.get();
    stack->addTransport(std::move(port_us));
    stack->addTransport(std::make_unique<resip_engine::FilteredUdpTransport>(fifo, config.aka.unprotected_port,
                                                                             config.listen_address, filter));
  }
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4.1a: on stop, every security association goes, with its transports; the timers end.
void SipEngine::Impl::aka_stop() noexcept {
  if (!aka) return;
  for (const auto timer : {Timer::aka_refresh, Timer::aka_pending, Timer::aka_old, Timer::aka_expiry}) cancel(timer);
  aka_delete(aka->pending);
  aka_delete(aka->old);
  aka_delete(aka->current);
  aka.reset();
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 rules 6 and SPI: a new Security-Client proposal: "ipsec-3gpp", the mechanisms of
// aka::esp_offers, ESP in transport mode, two fresh SPIs (at least 256, RFC 4303 section 2.1), a fresh protected client
// port (NOTE 16: random) and the fixed protected server port (NOTE 10).
aka::SecMechanism SipEngine::Impl::aka_new_offer() const {
  std::set<std::uint32_t> spis;
  std::set<std::uint16_t> ports{5060, 5061, config.listen_port, config.aka.unprotected_port};
  for (const auto *set : {aka->current.get(), aka->pending.get(), aka->old.get()}) {
    if (set == nullptr) continue;
    spis.insert({set->spi_uc, set->spi_us, set->spi_pc, set->spi_ps});
    ports.insert({set->port_uc, set->port_us});
  }
  aka::SecMechanism offer;
  offer.name = "ipsec-3gpp";
  offer.alg = std::string(aka::supported_esp_algorithms().front().alg);
  offer.ealg = std::string(aka::supported_esp_algorithms().front().ealg);
  offer.prot = "esp";
  offer.mod = "trans";
  for (auto *spi : {&offer.spi_c, &offer.spi_s}) {
    std::uint32_t value = 0;
    while (value < 256 || spis.contains(value)) value = random_u32();
    spis.insert(value);
    *spi = value;
  }
  for (int attempt = 0; attempt < 200 && !offer.port_c; ++attempt) {
    const auto port = static_cast<std::uint16_t>(20000 + random_u32() % 40000);
    if (!ports.contains(port) && port_free(config.listen_address, port) &&
        (!config.aka.udp || port_free(config.listen_address, port, SOCK_DGRAM)))
      offer.port_c = port;
  }
  if (!offer.port_c) throw std::runtime_error("IMS AKA: no free protected client port");
  offer.port_s = config.listen_port;
  return offer;
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.2.2 a: the Authorization of an unprotected REGISTER: username, realm and uri, with an empty
// nonce and response.
std::string SipEngine::Impl::aka_unprotected_authorization() const {
  return "Digest username=\"" + config.aka.impi + "\", realm=\"" + aka->realm + "\", uri=\"sip:" + aka->realm +
         "\", nonce=\"\", response=\"\"";
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.2.1: one registration procedure at a time. A UE with a set of security associations sends
// the REGISTER protected by it (clause 5.1.1.4.2, TS 33.203 clause 7.4.1a); otherwise an unprotected initial
// REGISTER with a new Call-ID (clause 5.1.1.2.2). Expires 0 deregisters (clause 5.1.1.6.2).
void SipEngine::Impl::aka_register(unsigned expires, std::string_view content_type, std::string_view body,
                                   SipResponseHandler handler) {
  ensure_started();
  if (aka->busy) throw std::logic_error("IMS AKA: a REGISTER is in progress (TS 24.229 clause 5.1.1.2.1)");
  if (expires == 0 && !aka->current) throw std::logic_error("no IMS AKA registration to remove");
  aka->expires = expires;
  aka->content_type = std::string(content_type);
  aka->body = std::string(body);
  aka->handler = std::move(handler);
  aka->resyncs = 0;
  aka->restarts = 0;
  aka->busy = true;
  aka->reregistration = aka->current && expires != 0;
  try {
    if (aka->current) {
      aka_send_register(AkaRoute::current, true, aka->authorization);
    } else {
      aka->call_id.clear();
      aka->realm = sip_detail::identity_domain(config.identity);
      aka_send_register(AkaRoute::unprotected, true, aka_unprotected_authorization());
    }
  } catch (...) {
    aka->busy = false;
    throw;
  }
}

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.2.1, 5.1.1.2.2, 5.1.1.4.2, 5.1.1.5.1 and 5.1.1.6.2: one REGISTER of the procedure: From
// and To the public user identity (the ISIM's, sip.isim.impu, when configured), the Request-URI the home domain, no
// Route (TS 37.579-1 table 5.5.2.13-1: it goes to the P-CSCF directly), Expires, the Contact with the protected server
// port (or the unprotected port for an unprotected REGISTER), Authorization, Security-Client, Security-Verify when
// protected, Require and Proxy-Require "sec-agree" (RFC 3329 section 2.3.1) and Supported "path"; the Call-ID of the
// procedure, the next CSeq; to the P-CSCF's unprotected port, or from port_uc of the set to its port_ps.
void SipEngine::Impl::aka_send_register(AkaRoute route, bool new_offer, const std::string &authorization) {
  if (new_offer) {
    aka->offer = aka_new_offer();
    aka->security_client = aka::format_sec_mechanisms(aka::esp_offers(aka->offer));
  }
  AkaSet *set = route == AkaRoute::current   ? aka->current.get()
                : route == AkaRoute::pending ? aka->pending.get()
                                             : nullptr;
  if (route != AkaRoute::unprotected && set == nullptr) throw std::logic_error("IMS AKA: no security association set");
  aka->register_route = route;

  const auto &instance = config.outbound_instance;
  if (instance.find_first_of("\"<>\r\n") != std::string::npos)
    throw std::invalid_argument("invalid SIP outbound instance");
  const auto target_uri = route == AkaRoute::unprotected
                              ? "sip:" + sip_detail::identity_user(config.identity) + "@" +
                                    uri_host(config.advertise_address) + ":" +
                                    std::to_string(config.aka.unprotected_port) +
                                    (config.aka.udp ? ";transport=udp" : ";transport=tcp") +
                                    (instance.empty() ? "" : ";ob")
                              : sip_detail::contact_target(config);
  const auto contact = "<" + target_uri + ">" +
                       (config.registration_features.empty() ? sip_detail::service_tags(config)
                                                             : config.registration_features) +
                       config.media_feature_tags +
                       (instance.empty() ? "" : ";+sip.instance=\"<" + instance + ">\";reg-id=1");
  if (aka->call_id.empty()) {
    aka->call_id = resip_engine::random_hex(16);
    aka->from_tag = resip_engine::random_hex(8);
  }
  // From and To: the ISIM's public user identity when it is configured (TS 24.229 clause 5.1.1.2.1 a) and b)).
  const auto &identity = config.aka.impu.empty() ? config.identity : config.aka.impu;
  OutgoingRequest request;
  request.method = "REGISTER";
  request.request_uri = "sip:" + sip_detail::identity_domain(config.identity);
  request.from = identity;
  request.from_tag = aka->from_tag;
  request.to = sip_detail::name_addr(identity);
  request.call_id = aka->call_id;
  request.cseq = ++aka->cseq;
  request.contact = contact;
  request.headers = {{"Expires", std::to_string(aka->expires)},
                     {"Authorization", authorization},
                     {"Security-Client", aka->security_client}};
  if (set != nullptr) request.headers.push_back({"Security-Verify", set->security_server});
  request.headers.push_back({"Require", "sec-agree"});
  request.headers.push_back({"Proxy-Require", "sec-agree"});
  request.headers.push_back({"Supported", "path"});
  for (const auto &header : request.headers) resip_engine::check_header(header);
  request.content_type = aka->content_type;
  request.body = aka->body;

  const auto hop = set != nullptr ? aka_hop(*set) : aka_unprotected_hop();
  aka->route = route;
  Pending entry;
  entry.purpose = Purpose::aka_register;
  dispatch(write_request(request, hop), hop, std::move(entry));
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1: the hop of a request over a set: from port_uc (its TCP or UDP transport, picked by the Via's
// sent-by port) to the P-CSCF's port_ps; the Via then names port_us (TS 24.229 clause 5.1.2A.1.1 b).
SipEngine::Impl::Hop SipEngine::Impl::aka_hop(const AkaSet &set) const {
  Hop hop;
  hop.type = config.aka.udp ? resip::UDP : resip::TCP;
  hop.via_port = set.port_uc;
  hop.force_target = pcscf_target(config, set.port_ps, hop.type);
  hop.advertised_port = set.port_us;
  return hop;
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.2.1: the hop of an unprotected REGISTER: from the unprotected port to the P-CSCF's port.
SipEngine::Impl::Hop SipEngine::Impl::aka_unprotected_hop() const {
  Hop hop;
  hop.type = config.aka.udp ? resip::UDP : resip::TCP;
  hop.via_port = config.aka.unprotected_port;
  hop.force_target = pcscf_target(config, config.aka.pcscf_port, hop.type);
  hop.advertised_port = config.aka.unprotected_port;
  return hop;
}

//------------------------------------------------------------------------------
// RFC 3261 section 18.1.1 and TS 24.229 clause 4.2A: over UDP, a request of 1300 bytes or more goes over TCP from the
// same port (port_uc of its set, or the unprotected port) to the same port of the P-CSCF.
void SipEngine::Impl::aka_size_hop(resip::SipMessage &request, Hop &hop) const {
  if (!config.aka.udp || hop.type != resip::UDP || resip_engine::text_of(request).size() < udp_size_limit) return;
  hop.type = resip::TCP;
  const resip::Uri target{resip::Data(hop.force_target)};
  hop.force_target = pcscf_target(config, target.port(), resip::TCP);
  request.header(resip::h_Vias).front().transport() = "TCP";
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 and annex I: the four SAs of a set, ESP in transport mode: UE port_uc to P-CSCF port_ps
// (SPI spi_ps) and UE port_us to P-CSCF port_pc (spi_pc) outbound, P-CSCF port_ps to UE port_uc (spi_uc) and P-CSCF
// port_pc to UE port_us (spi_us) inbound; IK_ESP and CK_ESP of annex I; then the transports of port_uc (TCP, and UDP
// over UDP). Installed all or none.
void SipEngine::Impl::aka_install(AkaSet &set) {
  const auto &ue = config.advertise_address;
  const auto &pcscf = config.aka.pcscf_address;
  const auto make = [&](bool outbound, std::uint16_t ue_port, std::uint16_t pcscf_port, std::uint32_t spi) {
    xfrm::SecurityAssociation sa;
    sa.source = outbound ? ue : pcscf;
    sa.destination = outbound ? pcscf : ue;
    sa.source_port = outbound ? ue_port : pcscf_port;
    sa.destination_port = outbound ? pcscf_port : ue_port;
    sa.spi = spi;
    sa.alg = set.alg;
    sa.ealg = set.ealg;
    sa.outbound = outbound;
    return sa;
  };
  std::vector<xfrm::SecurityAssociation> sas{
      make(true, set.port_uc, set.port_ps, set.spi_ps), make(true, set.port_us, set.port_pc, set.spi_pc),
      make(false, set.port_uc, set.port_ps, set.spi_uc), make(false, set.port_us, set.port_pc, set.spi_us)};
  for (auto &sa : sas) {
    sa.integrity_key = set.integrity_key;
    sa.encryption_key = set.encryption_key;
    // Annex I unique salt: the direction (to the UE) and the role of the source port (a protected server port).
    const bool to_ue = !sa.outbound;
    const bool from_server = to_ue ? sa.source_port == set.port_ps : sa.source_port == set.port_us;
    sa.salt = aka::sa_salt(set.salt, set.alg, set.ealg, to_ue, from_server);
  }
  set.sas.clear();
  try {
    for (const auto &sa : sas) {
      aka->xfrm->add(sa);
      set.sas.push_back(sa);
    }
    const resip_engine::ReceiveFilter filter = [this](const resip::SipMessage &message, int local_port) {
      return aka_accept(message, local_port);
    };
    auto &fifo = stack->stateMacFifo();
    // TS 33.203 clause 7.1, TCP case: "the UE ... shall set up a TCP connection to the port port_ps of the P-CSCF
    // before sending a request": reSIProcate's symmetric connections open it from port_uc.
    auto tcp = std::make_unique<resip_engine::FilteredTcpTransport>(
        fifo, set.port_uc, config.listen_address, RESIP_TRANSPORT_FLAG_SYMMETRIC_CONNECTIONS, filter);
    auto *tcp_transport = tcp.get();
    stack->addTransport(std::move(tcp));
    set.tcp_key = tcp_transport->getKey();
    if (config.aka.udp) {
      auto udp = std::make_unique<resip_engine::FilteredUdpTransport>(fifo, set.port_uc, config.listen_address, filter);
      set.udp = udp.get();
      stack->addTransport(std::move(udp));
      set.udp_key = set.udp->getKey();
    }
  } catch (...) {
    for (const auto &sa : set.sas) aka->xfrm->remove(sa);
    set.sas.clear();
    if (set.tcp_key != 0) stack->removeTransport(set.tcp_key);
    set.tcp_key = 0;
    set.udp = nullptr;
    throw;
  }
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4: deleting an SA deletes it "from both the application and IPsec layer": the XFRM SAs and
// policies, and the set's transports with their connections.
void SipEngine::Impl::aka_delete(std::unique_ptr<AkaSet> &set) noexcept {
  if (!set) return;
  if (aka && aka->xfrm)
    for (const auto &sa : set->sas) aka->xfrm->remove(sa);
  try {
    if (aka && aka->udp_us != nullptr && set->udp != nullptr && aka->current.get() == set.get()) aka->udp_us->use(-1, {}, 0);
    if (stack) {
      if (set->tcp_key != 0) stack->removeTransport(set->tcp_key);
      if (set->udp_key != 0) stack->removeTransport(set->udp_key);
    }
  } catch (...) {
    // The transports go with the stack in any case.
  }
  set.reset();
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1, UDP case: what the transport of port_us sends leaves from port_uc of the set in use.
void SipEngine::Impl::aka_use(AkaSet *set) {
  if (aka->udp_us == nullptr) return;
  if (set == nullptr || set->udp == nullptr)
    aka->udp_us->use(-1, {}, 0);
  else
    aka->udp_us->use(set->udp->socket(), config.aka.pcscf_address, set->port_ps);
}

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.2.1, 5.1.1.4.1, 5.1.1.5.1 and 5.1.1.5.3: a 401 is a challenge, a 2xx the registration, a 423
// a new REGISTER with at least Min-Expires, a 403, 408, 500 or 504 to a reregistration an initial registration; any
// other result ends the procedure. A response the stack made itself (a timeout, a transport failure) is no answer.
void SipEngine::Impl::aka_registration_result(const resip::SipMessage &message) {
  if (!aka) return;
  const int status = message.header(resip::h_StatusLine).statusCode();
  const bool answered = message.isFromWire();
  if (status == 401 && answered) return aka_challenge(message);
  if (status >= 200 && status < 300 && answered) return aka_registered(message);
  SipResponse response;
  try {
    response = response_from(message);
  } catch (const std::exception &) {
    response.status_code = status;
    response.reason = message.header(resip::h_StatusLine).reason().c_str();
  }
  if (status == 423 && answered) {
    const auto min_expires = get_header(response.headers, "Min-Expires");
    unsigned value = 0;
    const auto [end, error] = std::from_chars(min_expires.data(), min_expires.data() + min_expires.size(), value);
    if (error == std::errc{} && value > aka->expires && aka->restarts++ < 2) {
      aka->expires = value;
      aka_delete(aka->pending);
      if (aka->current) return aka_send_register(AkaRoute::current, true, aka->authorization);
      return aka_send_register(AkaRoute::unprotected, true, aka_unprotected_authorization());
    }
  }
  // TS 24.229 V19.7.0 clause 5.1.1.4.1: "On receiving a 408 (Request Timeout) response or 500 (Server Internal Error)
  // response or 504 (Server Time-Out) response or 403 (Forbidden) response for a reregistration, the UE shall perform
  // the procedures for initial registration as described in subclause 5.1.1.2"; once per reregistration.
  if (answered && aka->reregistration && (status == 403 || status == 408 || status == 500 || status == 504)) {
    aka->reregistration = false;
    aka_forget_registration();
    report_error("IMS AKA: reregistration answered " + std::to_string(status) +
                 "; initial registration (TS 24.229 clause 5.1.1.4.1)");
    return aka_send_register(AkaRoute::unprotected, true, aka_unprotected_authorization());
  }
  // TS 24.229 clause 5.1.1.2.1: a REGISTER protected by the set in use that gets no answer: the SAs are no longer
  // active; the next registration is an initial one.
  if (!answered && aka->route == AkaRoute::current) {
    aka_delete(aka->old);
    aka_delete(aka->current);
    aka_use(nullptr);
  }
  aka_failed(response);
}

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.4.1 and 5.1.1.7: the registration and its security associations are given up (timers,
// sets, the last authorization); the next REGISTER is an initial one, unprotected with a new Call-ID.
void SipEngine::Impl::aka_forget_registration() {
  for (const auto timer : {Timer::aka_refresh, Timer::aka_pending, Timer::aka_old, Timer::aka_expiry}) cancel(timer);
  aka_delete(aka->pending);
  aka_delete(aka->old);
  aka_delete(aka->current);
  aka_use(nullptr);
  aka->authorization.clear();
  aka->resyncs = 0;
  aka->restarts = 0;
  aka->call_id.clear();
  aka->realm = sip_detail::identity_domain(config.identity);
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.7: a reg event NOTIFY ended the
// registration: the set in use becomes the old set, deleted once none of its transactions (the NOTIFY's among them)
// is left; the other sets, the timers and the authorization go now. A REGISTER procedure under way keeps its sets.
void SipEngine::Impl::aka_registration_ended() {
  if (aka->busy) return;
  auto ending = std::move(aka->current);
  aka_forget_registration();
  if (ending) {
    aka->old = std::move(ending);
    aka->old_release_scheduled = true;
    schedule(Timer::aka_old, old_set_poll);
  }
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.5.1 and TS 33.203 clauses 7.3 and 7.4.1a: the procedure failed: the temporary set goes and the
// application hears the response; the unprotected connection is closed.
void SipEngine::Impl::aka_failed(const SipResponse &response) {
  cancel(Timer::aka_pending);
  aka_delete(aka->pending);
  if (aka->unprotected_flow) {
    stack->terminateFlow(*aka->unprotected_flow);
    aka->unprotected_flow.reset();
  }
  aka->busy = false;
  dispatch_response(response, aka->handler);
}

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.5.1 and 5.1.1.5.3, TS 33.203 clauses 6.1.1, 7.2 and 7.3: the 401: the topmost Digest WWW-Authenticate with an algorithm the UE supports (AKAv2-SHA-256 or
// AKAv1-MD5); RAND and AUTN to the ISIM; on success the temporary set from the Security-Server and the protected
// REGISTER with the response; on a MAC failure a REGISTER with an empty response, on an SQN failure one with auts (no
// temporary set either way); a missing Security-Server restarts with a new Call-ID.
void SipEngine::Impl::aka_challenge(const resip::SipMessage &message) {
  SipResponse challenge;
  try {
    challenge = response_from(message);
  } catch (const std::exception &error) {
    challenge.status_code = 401;
    challenge.reason = error.what();
  }
  const auto fail = [&](std::string_view why) {
    report_error(std::string("IMS AKA: ") + std::string(why));
    SipResponse response = challenge;
    response.reason = std::string(why);
    aka_failed(response);
  };
  if (aka->register_route == AkaRoute::unprotected) aka->unprotected_flow = message.getSource();

  const resip::Auth *chosen = nullptr;
  std::optional<aka::AkaAlgorithm> algorithm;
  if (message.exists(resip::h_WWWAuthenticates)) {
    for (const auto &header : message.header(resip::h_WWWAuthenticates)) {
      if (!ascii_equal(header.scheme().c_str(), "Digest") || !header.exists(resip::p_algorithm)) continue;
      algorithm = aka::aka_algorithm(header.param(resip::p_algorithm).c_str());
      if (algorithm) {
        chosen = &header;
        break;
      }
    }
  }
  if (chosen == nullptr) return fail("401 without an AKAv2-SHA-256 or AKAv1-MD5 challenge");
  const std::string nonce = chosen->exists(resip::p_nonce) ? chosen->param(resip::p_nonce).c_str() : "";
  const auto parsed = aka::parse_nonce(nonce);
  if (!parsed) return fail("the AKA nonce is not base64(RAND || AUTN)");
  aka->realm = chosen->exists(resip::p_realm) ? chosen->param(resip::p_realm).c_str() : "";
  const std::string opaque = chosen->exists(resip::p_opaque) ? chosen->param(resip::p_opaque).c_str() : "";
  const auto qop_offered =
      sip_detail::ascii_lower(chosen->exists(resip::p_qopOptions) ? chosen->param(resip::p_qopOptions).c_str() : "");
  bool qop_auth = false;
  for (std::size_t at = 0; at < qop_offered.size();) {
    const auto end = std::min(qop_offered.find(',', at), qop_offered.size());
    auto token = qop_offered.substr(at, end - at);
    token.erase(0, token.find_first_not_of(" \t"));
    token.erase(token.find_last_not_of(" \t") + 1);
    qop_auth = qop_auth || token == "auth";
    at = end + 1;
  }
  const auto uri = "sip:" + sip_detail::identity_domain(config.identity);
  const auto name = std::string(aka::algorithm_name(*algorithm));
  const auto base = "Digest username=\"" + config.aka.impi + "\", realm=\"" + aka->realm + "\", nonce=\"" + nonce +
                    "\", uri=\"" + uri + "\"";
  const auto opaque_part = opaque.empty() ? std::string{} : ", opaque=\"" + opaque + "\"";
  // TS 24.229 clause 5.1.1.5.3: the REGISTER that says the challenge is invalid goes over the set in use, if any,
  // with new spi_uc, spi_us and port_uc; no temporary set is created.
  const auto invalid_route = aka->current ? AkaRoute::current : AkaRoute::unprotected;

  const auto result = aka->isim->authenticate(parsed->rand, parsed->autn);
  if (result.status == aka::AuthStatus::mac_failure) {
    report_error("IMS AKA: the network failed authentication (MAC), TS 33.102 clause 6.3.3");
    return aka_send_register(invalid_route, true, base + ", response=\"\", algorithm=" + name + opaque_part);
  }
  if (result.status == aka::AuthStatus::sync_failure) {
    // TS 33.102 clause 6.3.5 and RFC 3310 section 3.4: AUTS in the auts parameter (at most twice here).
    if (++aka->resyncs > 2) return fail("SQN still out of range after resynchronisation");
    return aka_send_register(invalid_route, true,
                             base + ", response=\"\", algorithm=" + name + ", auts=\"" + aka::base64(result.auts) +
                                 "\"" + opaque_part);
  }

  // RFC 3329 section 2.3.1 and TS 24.229 clause 5.1.1.5.1 step 3: the Security-Server, as sent, and the mechanism the
  // UE takes from it.
  const auto security_server = resip_engine::joined_header(challenge.headers, "Security-Server");
  if (security_server.empty()) {
    if (aka->restarts++ > 0) return fail("401 without Security-Server");
    aka->call_id.clear();
    return aka_send_register(AkaRoute::unprotected, true,
                             "Digest username=\"" + config.aka.impi + "\", realm=\"" + aka->realm + "\", uri=\"" + uri +
                                 "\", nonce=\"\", response=\"\"");
  }
  std::optional<aka::SecMechanism> mechanism;
  try {
    mechanism = aka::select_mechanism(aka::parse_sec_mechanisms(security_server));
  } catch (const std::invalid_argument &) {
    mechanism.reset();
  }
  // TS 33.203 clause 7.3.2.2: "the UE shall abandon the registration procedure".
  if (!mechanism) return fail("the Security-Server proposes nothing the UE supports (TS 33.203 clause 7.3.2.2)");

  // RFC 3310 section 3.3, RFC 4169 section 3 and RFC 2617 section 3.2.2: the response, with qop "auth" when offered.
  const auto password = aka::digest_password(*algorithm, result);
  std::string cnonce, nc, qop;
  if (qop_auth) {
    cnonce = resip_engine::random_hex(16);
    nc = "00000001";
    qop = "auth";
  }
  const auto response =
      aka::digest_response(*algorithm, config.aka.impi, aka->realm, password, "REGISTER", uri, nonce, nc, cnonce, qop);
  auto authorization = base + ", response=\"" + response + "\", algorithm=" + name;
  if (qop_auth) authorization += ", qop=auth, nc=" + nc + ", cnonce=\"" + cnonce + "\"";
  authorization += opaque_part;

  // TS 33.203 clause 7.4.1a: one registration at a time: an earlier temporary set goes.
  cancel(Timer::aka_pending);
  aka_delete(aka->pending);
  auto set = std::make_unique<AkaSet>();
  set->port_uc = *aka->offer.port_c;
  set->port_us = *aka->offer.port_s;
  set->spi_uc = *aka->offer.spi_c;
  set->spi_us = *aka->offer.spi_s;
  set->port_pc = *mechanism->port_c;
  set->port_ps = *mechanism->port_s;
  set->spi_pc = *mechanism->spi_c;
  set->spi_ps = *mechanism->spi_s;
  set->alg = mechanism->alg;
  set->ealg = *mechanism->ealg;
  set->security_server = security_server;
  set->integrity_key = aka::integrity_key_esp(set->alg, result.ck, result.ik);
  set->encryption_key = aka::encryption_key_esp(set->ealg, result.ck);
  set->salt = aka::esp_salt(set->alg, set->ealg, result.ck, result.ik);
  try {
    aka_install(*set);
  } catch (const std::exception &error) {
    return fail(error.what());
  }
  set->expires = Clock::now() + reg_await_auth;
  aka->pending = std::move(set);
  schedule(Timer::aka_pending, reg_await_auth);
  aka->pending_authorization = authorization;
  aka->pending_algorithm = name;
  // TS 24.229 clause 5.1.1.5.1 step 4: same Call-ID, the same Security-Client, Security-Verify mirroring the
  // Security-Server, protected by the temporary set towards port_ps.
  aka_send_register(AkaRoute::pending, false, authorization);
}

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.2.1, 5.1.1.2.2, 5.1.1.4.2, 5.1.1.5.1 and 5.1.1.6.2: the 200 (OK): the temporary set becomes the set in use (the one before it is old, deleted after the first
// message from the P-CSCF on the new set, TS 33.203 clause 7.4.1a), the SA lifetime is the longest of the previous one
// and the registration's plus 30 s, P-Associated-URI and Service-Route are kept; a deregistration deletes every SA.
void SipEngine::Impl::aka_registered(const resip::SipMessage &message) {
  SipResponse response;
  try {
    response = response_from(message);
  } catch (const std::exception &error) {
    response.status_code = 500;
    response.reason = error.what();
    return aka_failed(response);
  }
  if (aka->expires == 0) {
    for (const auto timer : {Timer::aka_refresh, Timer::aka_pending, Timer::aka_old, Timer::aka_expiry}) cancel(timer);
    aka_delete(aka->pending);
    aka_delete(aka->old);
    aka_delete(aka->current);
    aka_use(nullptr);
    aka->service_routes.clear();
    aka->associated_uris.clear();
    aka->busy = false;
    return dispatch_response(response, aka->handler);
  }
  if (aka->route == AkaRoute::unprotected) {
    SipResponse refused = response;
    refused.status_code = 500;
    refused.reason = "IMS AKA: 200 (OK) to an unprotected REGISTER without authentication";
    report_error(refused.reason);
    return aka_failed(refused);
  }
  if (aka->route == AkaRoute::pending) {
    cancel(Timer::aka_pending);
    cancel(Timer::aka_old);
    aka_delete(aka->old);
    const auto previous_expiry = aka->current ? aka->current->expires : Clock::time_point{};
    aka->old = std::move(aka->current);
    aka->current = std::move(aka->pending);
    aka->current->expires = previous_expiry;
    aka->old_release_scheduled = false;
    aka->authorization = aka->pending_authorization;
    aka->algorithm = aka->pending_algorithm;
    aka_use(aka->current.get());
    if (aka->unprotected_flow) {
      stack->terminateFlow(*aka->unprotected_flow);
      aka->unprotected_flow.reset();
    }
  }
  // RFC 3261 section 10.2.4: the expiry granted to our Contact (its expires parameter, or Expires).
  unsigned granted = aka->expires;
  bool contact_found = false;
  if (message.exists(resip::h_Contacts)) {
    for (const auto &contact : message.header(resip::h_Contacts)) {
      if (contact.isAllContacts() || !contact.exists(resip::p_expires)) continue;
      const auto &uri = contact.uri();
      if (uri.port() == config.listen_port && same_address(uri.host().c_str(), config.advertise_address)) {
        granted = contact.param(resip::p_expires);
        contact_found = true;
        break;
      }
    }
  }
  if (!contact_found && message.exists(resip::h_Expires) && message.header(resip::h_Expires).value() > 0)
    granted = std::min<unsigned>(granted, message.header(resip::h_Expires).value());
  const auto now = Clock::now();
  aka->current->expires = std::max(aka->current->expires, now + std::chrono::seconds(granted) + sa_lifetime_margin);
  schedule(Timer::aka_expiry, std::chrono::duration_cast<std::chrono::milliseconds>(aka->current->expires - now));
  aka->service_routes = header_list(response.headers, "Service-Route");
  aka->associated_uris = header_list(response.headers, "P-Associated-URI");
  // TS 24.229 clause 5.1.1.4.1: a registration of more than 1200 s is refreshed 600 s before it expires, a shorter one
  // half way.
  const unsigned refresh_s = granted > 1200 ? granted - 600 : std::max(1U, granted / 2);
  schedule(Timer::aka_refresh, std::chrono::seconds(refresh_s));
  aka->busy = false;
  dispatch_response(response, aka->handler);
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4.1a and RFC 3329 section 2.3.1: a
// request outside a dialog goes over the set in use (without one the UE "is not allowed to use IMS service"), with
// Security-Verify mirroring its Security-Server and Require "sec-agree", Proxy-Require "sec-agree" in INVITE and
// OPTIONS; not REGISTER, ACK, CANCEL or PRACK, and not a request that has its Security-Verify already.
void SipEngine::Impl::aka_prepare(OutgoingRequest &request) const {
  if (!aka->current) throw std::runtime_error("IMS AKA: not registered, no security associations (TS 33.203 7.4.1a)");
  const auto &method = request.method;
  if (ascii_equal(method, "REGISTER") || ascii_equal(method, "ACK") || ascii_equal(method, "CANCEL") ||
      ascii_equal(method, "PRACK") || !get_header(request.headers, "Security-Verify").empty())
    return;
  request.headers.push_back({"Security-Verify", aka->current->security_server});
  request.headers.push_back({"Require", "sec-agree"});
  if (ascii_equal(method, "INVITE") || ascii_equal(method, "OPTIONS"))
    request.headers.push_back({"Proxy-Require", "sec-agree"});
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.2A.1.1: the preloaded Route of new dialogs and standalone requests: the P-CSCF URI with its
// protected server port, then the Service-Route values of the last registration.
std::vector<std::string> SipEngine::Impl::aka_routes() const {
  std::vector<std::string> routes;
  if (aka->current)
    routes.push_back("<sip:" + uri_host(config.aka.pcscf_address) + ":" + std::to_string(aka->current->port_ps) +
                     (config.aka.udp ? ";lr;transport=udp>" : ";lr;transport=tcp>"));
  routes.insert(routes.end(), aka->service_routes.begin(), aka->service_routes.end());
  return routes;
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 rules 4 and 7, clause 7.4.1a: a received message is
// taken only on the inbound SA it belongs to: from the P-CSCF on (port_uc, port_ps) or (port_us, port_pc) of a set; on
// the temporary set only the answer to the protected REGISTER; on an unprotected port only responses to an
// unprotected REGISTER. The first message on the set in use starts the end of the old set. Runs in the transport, before
// the transaction layer (aka_transports.hpp).
bool SipEngine::Impl::aka_accept(const resip::SipMessage &message, int local_port) {
  if (!aka) return false;
  const bool response = message.isResponse();
  const bool register_response = response && message.header(resip::h_CSeq).method() == resip::REGISTER;
  const auto &source = message.getSource();
  const auto remote_port = source.getPort();
  const bool from_pcscf = same_address(resip::Tuple::inet_ntop(source).c_str(), config.aka.pcscf_address);
  const auto on = [&](const AkaSet *set) {
    return set != nullptr && from_pcscf &&
           ((local_port == set->port_uc && remote_port == set->port_ps) ||
            (local_port == set->port_us && remote_port == set->port_pc));
  };
  const auto track = [&](AkaSet &set) {
    if (response || message.method() == resip::ACK) return;
    const std::string transaction = message.getTransactionId().c_str();
    set.transactions.insert(transaction);
    transactions[transaction] = {std::nullopt, source.getType() == resip::UDP};
  };
  if (register_response && aka->register_route == AkaRoute::pending && !on(aka->pending.get())) return false;
  if (on(aka->current.get())) {
    if (register_response && aka->register_route != AkaRoute::current) return false;
    track(*aka->current);
    if (aka->old && !aka->old_release_scheduled) {
      aka->old_release_scheduled = true;
      schedule(Timer::aka_old, old_set_poll);
    }
    return true;
  }
  if (on(aka->pending.get())) return register_response;
  if (on(aka->old.get())) {
    track(*aka->old);
    return true;
  }
  bool protected_port = local_port == config.listen_port;
  for (const auto *set : {aka->current.get(), aka->pending.get(), aka->old.get()})
    protected_port = protected_port || (set != nullptr && local_port == set->port_uc);
  return register_response && !protected_port && aka->register_route == AkaRoute::unprotected;
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4.1a: a request sent from port_uc of a set starts a client transaction on that set.
void SipEngine::Impl::aka_track_sent(const std::string &transaction, const Hop &hop) {
  for (auto *set : {aka->current.get(), aka->pending.get(), aka->old.get()}) {
    if (set == nullptr || hop.via_port != set->port_uc) continue;
    set->transactions.insert(transaction);
    transactions[transaction] = {std::nullopt, hop.type == resip::UDP};
    return;
  }
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4.1a: whether a transaction of a set is still pending: running, or over UDP within Timer J or K
// of its final response.
bool SipEngine::Impl::transaction_alive(const std::string &transaction) const {
  const auto found = transactions.find(transaction);
  if (found == transactions.end()) return false;
  if (!found->second.at) return true;
  return found->second.udp && Clock::now() < *found->second.at + udp_transaction_linger;
}

//------------------------------------------------------------------------------
// Helper: a transaction's final response was received or sent.
void SipEngine::Impl::transaction_ended(const std::string &transaction) {
  if (const auto found = transactions.find(transaction); found != transactions.end() && !found->second.at)
    found->second.at = Clock::now();
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4.1a: "the old SAs shall be deleted as soon as either all pending SIP transactions have been
// completed, or have timed out": looked at every second until none of the old set's transactions is pending (the SA
// lifetime deletes it in any case). Transactions that ended long ago are forgotten.
void SipEngine::Impl::aka_old_check() {
  const auto now = Clock::now();
  std::erase_if(transactions, [now](const auto &entry) {
    return entry.second.at && now > *entry.second.at + 2 * udp_transaction_linger;
  });
  if (!aka->old) return;
  if (std::any_of(aka->old->transactions.begin(), aka->old->transactions.end(),
                  [this](const std::string &transaction) { return transaction_alive(transaction); }))
    schedule(Timer::aka_old, old_set_poll);
  else
    aka_delete(aka->old);
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 rule 5: the UE's SA_table of the set in use.
std::optional<SipSecurityStatus> SipEngine::security_status() const {
  if (!impl_->aka || !impl_->aka->current) return std::nullopt;
  const auto &set = *impl_->aka->current;
  SipSecurityStatus status;
  status.mechanism = "ipsec-3gpp";
  status.alg = set.alg;
  status.ealg = set.ealg;
  status.port_uc = set.port_uc;
  status.port_us = set.port_us;
  status.port_pc = set.port_pc;
  status.port_ps = set.port_ps;
  status.spi_uc = set.spi_uc;
  status.spi_us = set.spi_us;
  status.spi_pc = set.spi_pc;
  status.spi_ps = set.spi_ps;
  status.associated_uris = impl_->aka->associated_uris;
  status.service_routes = impl_->aka->service_routes;
  status.algorithm = impl_->aka->algorithm;
  return status;
}

} // namespace mcx
