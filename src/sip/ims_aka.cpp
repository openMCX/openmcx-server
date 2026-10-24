//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IMS AKA registration of SipEngine::Impl (SipConfig::aka): the UE's own REGISTER transactions with sec-agree
// (RFC 3329), the authentication by the software ISIM (include/mcx/ims_aka.hpp), its sets of IPsec security
// associations over XFRM (include/mcx/xfrm.hpp) and the SIP signalling inside them, over TCP (requests from the
// protected client port port_uc to the P-CSCF's protected server port port_ps, requests of the P-CSCF accepted on the
// protected server port port_us) or over UDP (requests and responses from port_uc to port_ps, everything received on
// port_us; requests of 1300 bytes or more, and the requests of a dialog whose route set names TCP, over TCP), TS 33.203
// clause 7.1, TS 24.229 clause 4.2A.
//
// Specifications: TS 24.229 V19.7.0 (Rel-19) clauses 5.1.1.2, 5.1.1.4, 5.1.1.5, 5.1.1.6 and 5.1.2A.1,
// TS 33.203 V19.1.0 (Rel-19) clauses 6.1, 6.3, 7.1 to 7.4 and annexes H and I, TS 33.102 V19.1.0 (Rel-19),
// RFC 3261 (clause 18), RFC 3310, RFC 3329, RFC 4169.

#include "mcx/runtime.hpp"
#include "sip_impl.hpp"

#include <unistd.h>

#include <arpa/inet.h>
#include <charconv>
#include <netinet/in.h>
#include <set>
#include <sys/socket.h>

namespace mcx {
namespace {
// TS 24.229 table 7.7.1: reg-await-auth, the SIP level lifetime of the temporary set of security associations
// (clause 5.1.1.5.1 step 2).
constexpr std::uint64_t reg_await_auth_ms = 4 * 60 * 1000;
// TS 33.203 clause 7.4.1a: the old set goes once the transactions started on it are over; RFC 3261 section 17.1.2.2
// Timer F (64*T1) bounds a non-INVITE client transaction.
constexpr std::uint64_t old_set_release_ms = 64 * 500;
// TS 24.229 clauses 5.1.1.2.2 and 5.1.1.4.2: the SA lifetime is the registration's plus 30 seconds.
constexpr std::uint64_t sa_lifetime_margin_ms = 30 * 1000;

enum TimerId { refresh_timer_id = 1, pending_timer_id, old_timer_id, expiry_timer_id };

//------------------------------------------------------------------------------
// Helper: a random 32-bit value from OpenSSL's generator.
std::uint32_t random_u32() {
  std::uint32_t value = 0;
  if (RAND_bytes(reinterpret_cast<unsigned char *>(&value), sizeof(value)) != 1)
    throw std::runtime_error("could not draw a random value");
  return value;
}

//------------------------------------------------------------------------------
// Helper: whether a TCP (or UDP) port of the address can be bound now (a port the system or another program uses
// cannot be a protected client port).
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
// Helper: a header field added as given, without being parsed and printed again by pjsip (the Authorization of
// IMS AKA keeps its empty nonce and response, and its auts, exactly as TS 24.229 clause 5.1.1.5.3 has them).
void add_raw_header(pjsip_tx_data *data, std::string_view name, std::string_view value) {
  if (value.find_first_of("\r\n") != std::string_view::npos) throw std::invalid_argument("invalid SIP header");
  pj_str_t header_name{}, header_value{};
  pj_strdup2_with_null(data->pool, &header_name, std::string(name).c_str());
  pj_strdup2_with_null(data->pool, &header_value, std::string(value).c_str());
  pjsip_msg_add_hdr(data->msg, reinterpret_cast<pjsip_hdr *>(
                                   pjsip_generic_string_hdr_create(data->pool, &header_name, &header_value)));
}

//------------------------------------------------------------------------------
// Helper: the transport selector naming one transport.
pjsip_tpselector transport_selector(pjsip_transport *transport) {
  pjsip_tpselector selector{};
  selector.type = PJSIP_TPSELECTOR_TRANSPORT;
  selector.u.transport = transport;
  return selector;
}

//------------------------------------------------------------------------------
// Helper: a UDP transport bound to the address and port, published with the advertised address and a port for Via.
pjsip_transport *start_udp(pjsip_endpoint *endpoint, const pj_sockaddr &local, std::uint16_t port,
                           const pjsip_host_port &advertised, std::uint16_t published_port, const char *what) {
  pj_sockaddr bound = local;
  pj_sockaddr_set_port(&bound, port);
  pjsip_host_port name = advertised;
  name.port = published_port;
  pjsip_transport *transport = nullptr;
  require_success(pjsip_udp_transport_start(endpoint, &bound.ipv4, &name, 1, &transport), what);
  return transport;
}

//------------------------------------------------------------------------------
// Helper: the numeric address and port as a pjlib socket address.
pj_sockaddr socket_address(const std::string &address, std::uint16_t port) {
  pj_sockaddr out{};
  auto host = pj_view(address);
  require_success(
      pj_sockaddr_init(address.find(':') != std::string::npos ? pj_AF_INET6() : pj_AF_INET(), &out, &host, port),
      "parse P-CSCF address");
  return out;
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.203 clauses 7.1 and 7.2: starts IMS AKA: the XFRM access (CAP_NET_ADMIN), the ISIM, the TCP listener on the
// protected server port port_us (it also originates the connections from port_uc, with the pjproject patch of
// dependencies/pjproject), the unprotected TCP listener of the initial REGISTER, and the receive filter of rules 4
// and 7.
void SipEngine::Impl::aka_start(const pj_sockaddr &local, const pjsip_host_port &advertised) {
#ifndef PJSIP_TCP_TRANSPORT_HAS_CLIENT_PORT
  (void)local;
  (void)advertised;
  throw std::runtime_error("IMS AKA needs pjproject with dependencies/pjproject/0001-tcp-client-port.patch (a newer "
                           "development image)");
#else
  aka = std::make_unique<Aka>();
  aka->xfrm = std::make_unique<xfrm::Xfrm>();
  const bool test = config.aka.algorithm == "test";
  aka->isim = std::make_unique<aka::SoftIsim>(
      aka::key_from_hex(config.aka.k), test && config.aka.opc.empty() ? aka::Key{} : aka::key_from_hex(config.aka.opc),
      config.aka.sqn_file, test ? aka::IsimAlgorithm::test : aka::IsimAlgorithm::milenage, config.aka.res_length);
  require_success(pjsip_tcp_transport_start2(endpoint, &local.ipv4, &advertised, 1, &tls_factory),
                  "start the IMS AKA protected SIP TCP transport");
  pj_sockaddr unprotected = local;
  pj_sockaddr_set_port(&unprotected, config.aka.unprotected_port);
  pjsip_host_port unprotected_name = advertised;
  unprotected_name.port = config.aka.unprotected_port;
  require_success(
      pjsip_tcp_transport_start2(endpoint, &unprotected.ipv4, &unprotected_name, 1, &aka->unprotected_factory),
      "start the IMS AKA unprotected SIP TCP transport");
  if (config.aka.udp) {
#ifndef PJSIP_HAS_UDP_TO_TCP_CALLBACK
    throw std::runtime_error("IMS AKA over UDP needs pjproject with dependencies/pjproject/0002-udp-to-tcp.patch "
                             "(development image 0.3)");
#else
    // TS 33.203 clause 7.1, UDP case: port_us receives; what pjsip sends on it (responses to the P-CSCF's requests)
    // leaves from port_uc of the set in use (aka_udp_send). RFC 3261 section 18.1.1: large requests over TCP.
    aka->udp_us = start_udp(endpoint, local, config.listen_port, advertised, config.listen_port,
                            "start the IMS AKA protected SIP UDP transport");
    aka->udp_us_send = aka->udp_us->send_msg;
    aka->udp_us->send_msg = &Impl::aka_udp_send;
    aka->udp_unprotected = start_udp(endpoint, local, config.aka.unprotected_port, advertised,
                                     config.aka.unprotected_port, "start the IMS AKA unprotected SIP UDP transport");
    pjsip_set_udp_to_tcp_callback(&Impl::aka_udp_to_tcp);
#endif
  }
  aka_module.name = pj_view("mod-openmcx-ims-aka");
  aka_module.id = -1;
  // After the SIP message log, before the transaction layer.
  aka_module.priority = PJSIP_MOD_PRIORITY_TSX_LAYER - 1;
  aka_module.on_rx_request = &Impl::aka_filter;
  aka_module.on_rx_response = &Impl::aka_filter;
  require_success(pjsip_endpt_register_module(endpoint, &aka_module), "register the IMS AKA receive filter");
  pj_timer_entry_init(&aka->refresh_timer, refresh_timer_id, this, &Impl::aka_timer);
  pj_timer_entry_init(&aka->pending_timer, pending_timer_id, this, &Impl::aka_timer);
  pj_timer_entry_init(&aka->old_timer, old_timer_id, this, &Impl::aka_timer);
  pj_timer_entry_init(&aka->expiry_timer, expiry_timer_id, this, &Impl::aka_timer);
#endif
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4.1a: on stop, every security association goes, with its connection; the timers end.
void SipEngine::Impl::aka_stop() noexcept {
  if (!aka) return;
  if (endpoint != nullptr)
    for (auto *entry : {&aka->refresh_timer, &aka->pending_timer, &aka->old_timer, &aka->expiry_timer})
      if (pj_timer_entry_running(entry)) (void)pjsip_endpt_cancel_timer(endpoint, entry);
  aka_delete(aka->pending);
  aka_delete(aka->old);
  aka_delete(aka->current);
  if (aka->unprotected_connection != nullptr) (void)pjsip_transport_dec_ref(aka->unprotected_connection);
#ifdef PJSIP_HAS_UDP_TO_TCP_CALLBACK
  if (aka->udp_us != nullptr) {
    pjsip_set_udp_to_tcp_callback(nullptr);
    aka->udp_us->send_msg = aka->udp_us_send;
  }
#endif
  aka.reset();
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 rules 6 and SPI: a new Security-Client proposal: "ipsec-3gpp" with hmac-sha-1-96 and aes-cbc
// (TS 37.579-1 table 5.5.2.13-1), ESP in transport mode, two fresh SPIs (not those of any existing SA, at least 256:
// RFC 4303 section 2.1 reserves 1 to 255), a fresh protected client port (not in the SA_table, NOTE 16: random) and
// the fixed protected server port (NOTE 10).
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
  offer.alg = "hmac-sha-1-96";
  offer.ealg = "aes-cbc";
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
  try {
    if (aka->current) {
      aka_send_register(AkaRoute::current, true, aka->authorization);
    } else {
      aka->call_id.clear();
      aka->realm = identity_domain(config.identity);
      // TS 24.229 clause 5.1.1.2.2 a: username, realm and uri, with an empty nonce and response.
      aka_send_register(AkaRoute::unprotected, true,
                        "Digest username=\"" + config.aka.impi + "\", realm=\"" + aka->realm +
                            "\", uri=\"sip:" + aka->realm + "\", nonce=\"\", response=\"\"");
    }
  } catch (...) {
    aka->busy = false;
    throw;
  }
}

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.2.1, 5.1.1.2.2, 5.1.1.4.2, 5.1.1.5.1 and 5.1.1.6.2: one REGISTER of the procedure: From
// and To the public user identity, the Request-URI the home domain, no Route (TS 37.579-1 table 5.5.2.13-1: it goes
// to the P-CSCF directly), Expires, the Contact with the protected server port (or the unprotected port for an
// unprotected REGISTER), Authorization, Security-Client, Security-Verify when protected, Require and Proxy-Require
// "sec-agree" (RFC 3329 section 2.3.1) and Supported "path"; the Call-ID of the procedure, the next CSeq.
void SipEngine::Impl::aka_send_register(AkaRoute route, bool new_offer, const std::string &authorization) {
  if (new_offer) {
    aka->offer = aka_new_offer();
    aka->security_client = aka::format_sec_mechanism(aka->offer);
  }
  AkaSet *set = route == AkaRoute::current   ? aka->current.get()
                : route == AkaRoute::pending ? aka->pending.get()
                                             : nullptr;
  if (route != AkaRoute::unprotected && set == nullptr) throw std::logic_error("IMS AKA: no security association set");

  const auto registrar = "sip:" + identity_domain(config.identity);
  const auto &instance = config.outbound_instance;
  if (instance.find_first_of("\"<>\r\n") != std::string::npos)
    throw std::invalid_argument("invalid SIP outbound instance");
  const auto target_uri = route == AkaRoute::unprotected
                              ? "sip:" + identity_user(config.identity) + "@" + uri_host(config.advertise_address) +
                                    ":" + std::to_string(config.aka.unprotected_port) +
                                    (config.aka.udp ? ";transport=udp" : ";transport=tcp") +
                                    (instance.empty() ? "" : ";ob")
                              : contact_target();
  const auto contact_text = "<" + target_uri + ">" +
                            (config.registration_features.empty() ? service_tags() : config.registration_features) +
                            (instance.empty() ? "" : ";+sip.instance=\"<" + instance + ">\";reg-id=1");
  auto target = pj_view(registrar);
  auto identity = pj_view(config.identity);
  auto contact = pj_view(contact_text);
  auto call_id = pj_view(aka->call_id);
  pjsip_tx_data *created = nullptr;
  require_success(pjsip_endpt_create_request(endpoint, &pjsip_register_method, &target, &identity, &identity, &contact,
                                             aka->call_id.empty() ? nullptr : &call_id, static_cast<int>(++aka->cseq),
                                             nullptr, &created),
                  "create REGISTER request");
  TxData data(created);
  auto *from = static_cast<pjsip_fromto_hdr *>(pjsip_msg_find_hdr(data->msg, PJSIP_H_FROM, nullptr));
  if (aka->call_id.empty()) {
    aka->call_id = call_id_from(data->msg);
    aka->from_tag = string_from(from->tag);
  } else {
    pj_strdup2(data->pool, &from->tag, aka->from_tag.c_str());
  }
  add_raw_header(data.get(), "Expires", std::to_string(aka->expires));
  add_raw_header(data.get(), "Authorization", authorization);
  add_raw_header(data.get(), "Security-Client", aka->security_client);
  if (set != nullptr) add_raw_header(data.get(), "Security-Verify", set->security_server);
  add_raw_header(data.get(), "Require", "sec-agree");
  add_raw_header(data.get(), "Proxy-Require", "sec-agree");
  add_raw_header(data.get(), "Supported", "path");
  if (!aka->content_type.empty()) data->msg->body = make_text_body(data->pool, aka->content_type, aka->body);

  // The P-CSCF's unprotected port, or its protected server port port_ps from port_uc: over the set's connection, or
  // its UDP transport (a large REGISTER still goes over the connection, RFC 3261 section 18.1.1, aka_udp_to_tcp).
  pjsip_transport *connection = nullptr;
  std::uint16_t port = config.aka.pcscf_port;
  if (set != nullptr) {
    connection = aka_request_transport(*set);
    port = set->port_ps;
  } else {
    connection = config.aka.udp ? aka->udp_unprotected : aka_unprotected_connection();
  }
  const auto destination = socket_address(config.aka.pcscf_address, port);
  data->dest_info.addr.count = 1;
  data->dest_info.cur_addr = 0;
  data->dest_info.addr.entry[0].type = config.aka.udp ? PJSIP_TRANSPORT_UDP : PJSIP_TRANSPORT_TCP;
  data->dest_info.addr.entry[0].priority = 0;
  data->dest_info.addr.entry[0].weight = 0;
  pj_memcpy(&data->dest_info.addr.entry[0].addr, &destination, sizeof(destination));
  data->dest_info.addr.entry[0].addr_len = pj_sockaddr_get_len(&destination);
  pj_strdup2(data->pool, &data->dest_info.name, config.aka.pcscf_address.c_str());
  const auto selector = transport_selector(connection);
  require_success(pjsip_tx_data_set_transport(data.get(), &selector), "select the REGISTER connection");
  aka->route = route;
  require_success(pjsip_endpt_send_request(endpoint, data.release(), -1, nullptr, &Impl::aka_register_complete),
                  "send REGISTER request");
}

//------------------------------------------------------------------------------
// Helper: the connection of a set from port_uc to port_ps, set up when it is missing or closed (TS 33.203 clause 7.1,
// TCP case: "the UE ... shall set up a TCP connection to the port port_ps of the P-CSCF before sending a request").
pjsip_transport *SipEngine::Impl::aka_connection(AkaSet &set) {
  if (set.connection != nullptr && !set.connection->is_shutdown && !set.connection->is_destroying)
    return set.connection;
  if (set.connection != nullptr) (void)pjsip_transport_dec_ref(set.connection);
  set.connection = nullptr;
#ifdef PJSIP_TCP_TRANSPORT_HAS_CLIENT_PORT
  const auto destination = socket_address(config.aka.pcscf_address, set.port_ps);
  pjsip_tpselector selector{};
  selector.type = PJSIP_TPSELECTOR_LISTENER;
  selector.u.listener = tls_factory;
  // A new connection: the one of another set to the same port_ps must not be reused.
  selector.disable_connection_reuse = PJ_TRUE;
  require_success(pjsip_tcp_transport_set_client_port(tls_factory, set.port_uc), "set the protected client port");
  const auto status =
      pjsip_endpt_acquire_transport2(endpoint, PJSIP_TRANSPORT_TCP, &destination, pj_sockaddr_get_len(&destination),
                                     &selector, nullptr, &set.connection);
  (void)pjsip_tcp_transport_set_client_port(tls_factory, 0);
  require_success(status, "connect from the protected client port to the P-CSCF");
#endif
  return set.connection;
}

//------------------------------------------------------------------------------
// Helper: the TCP connection to the P-CSCF's unprotected port, from the unprotected port (TS 24.229 clause 5.1.1.2.1),
// set up when it is missing or closed.
pjsip_transport *SipEngine::Impl::aka_unprotected_connection() {
  if (aka->unprotected_connection != nullptr && !aka->unprotected_connection->is_shutdown &&
      !aka->unprotected_connection->is_destroying)
    return aka->unprotected_connection;
  if (aka->unprotected_connection != nullptr) (void)pjsip_transport_dec_ref(aka->unprotected_connection);
  aka->unprotected_connection = nullptr;
  const auto destination = socket_address(config.aka.pcscf_address, config.aka.pcscf_port);
  pjsip_tpselector selector{};
  selector.type = PJSIP_TPSELECTOR_LISTENER;
  selector.u.listener = aka->unprotected_factory;
  selector.disable_connection_reuse = PJ_TRUE;
  require_success(pjsip_endpt_acquire_transport2(endpoint, PJSIP_TRANSPORT_TCP, &destination,
                                                 pj_sockaddr_get_len(&destination), &selector, nullptr,
                                                 &aka->unprotected_connection),
                  "connect to the P-CSCF");
  return aka->unprotected_connection;
}

//------------------------------------------------------------------------------
// Helper: the transport the requests of a set are pinned to: its UDP transport on port_uc, or its TCP connection.
pjsip_transport *SipEngine::Impl::aka_request_transport(AkaSet &set) {
  return config.aka.udp ? set.udp : aka_connection(set);
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1, UDP case: "The UE sends requests and responses protected with ESP on the port port_uc": a
// message pjsip sends on port_us (a response to a request of the P-CSCF) goes out on the UDP transport of port_uc of
// the set in use, to port_ps. Without a set nothing is sent there (rule 4: no unprotected messages on these ports).
pj_status_t SipEngine::Impl::aka_udp_send(pjsip_transport * /*transport*/, pjsip_tx_data *data,
                                          const pj_sockaddr_t * /*remote*/, int /*remote_length*/, void *token,
                                          pjsip_transport_callback callback) {
  auto *owner = active.load();
  if (owner == nullptr || !owner->aka || !owner->aka->current || owner->aka->current->udp == nullptr)
    return PJSIP_ETPNOTAVAIL;
  auto *udp = owner->aka->current->udp;
  pj_sockaddr destination{};
  try {
    destination = socket_address(owner->config.aka.pcscf_address, owner->aka->current->port_ps);
  } catch (const std::exception &) {
    return PJ_EINVAL;
  }
  return udp->send_msg(udp, data, &destination, pj_sockaddr_get_len(&destination), token, callback);
}

//------------------------------------------------------------------------------
// A request pinned to the UDP transport of a set that goes over TCP, because it has 1300 bytes or more (RFC 3261
// section 18.1.1, TS 24.229 clause 4.2A) or because its dialog's route set names TCP (the P-CSCF's Record-Route of an
// INVITE that went over TCP): over the set's TCP connection from port_uc to port_ps; one pinned to the unprotected UDP
// transport over the unprotected connection (pjsip_set_udp_to_tcp_callback, dependencies/pjproject/0002).
pjsip_transport *SipEngine::Impl::aka_udp_to_tcp(pjsip_tx_data *data) {
  auto *owner = active.load();
  if (owner == nullptr || !owner->aka || data == nullptr) return nullptr;
  const auto *pinned = data->tp_sel.u.transport;
  pjsip_transport *reliable = nullptr;
  guarded(owner, [&] {
    if (pinned == owner->aka->udp_unprotected) {
      reliable = owner->aka_unprotected_connection();
      return;
    }
    for (auto *set : {owner->aka->current.get(), owner->aka->pending.get(), owner->aka->old.get()})
      if (set != nullptr && set->udp == pinned) reliable = owner->aka_connection(*set);
  });
  return reliable;
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 and annex I: the four SAs of a set, ESP in transport mode: UE port_uc to P-CSCF port_ps
// (SPI spi_ps) and UE port_us to P-CSCF port_pc (spi_pc) outbound, P-CSCF port_ps to UE port_uc (spi_uc) and P-CSCF
// port_pc to UE port_us (spi_us) inbound; IK_ESP and CK_ESP of annex I. Installed all or none.
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
  }
  set.sas.clear();
  try {
    for (const auto &sa : sas) {
      aka->xfrm->add(sa);
      set.sas.push_back(sa);
    }
    if (config.aka.udp) {
      pj_sockaddr local{};
      auto listen = pj_view(config.listen_address);
      require_success(pj_sockaddr_init(pj_AF_INET(), &local, &listen, 0), "parse SIP listen address");
      pjsip_host_port advertised{};
      advertised.host = pj_view(config.advertise_address);
      set.udp = start_udp(endpoint, local, set.port_uc, advertised, set.port_us,
                          "start the UDP transport of the protected client port");
    }
  } catch (...) {
    for (const auto &sa : set.sas) aka->xfrm->remove(sa);
    set.sas.clear();
    throw;
  }
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4: deleting an SA deletes it "from both the application and IPsec layer": the XFRM SAs and
// policies, and the set's connection.
void SipEngine::Impl::aka_delete(std::unique_ptr<AkaSet> &set) noexcept {
  if (!set) return;
  if (aka && aka->xfrm)
    for (const auto &sa : set->sas) aka->xfrm->remove(sa);
  if (set->connection != nullptr) (void)pjsip_transport_dec_ref(set->connection);
  if (set->udp != nullptr) (void)pjsip_transport_shutdown(set->udp);
  set.reset();
}

//------------------------------------------------------------------------------
// Helper: the outcome of a REGISTER transaction of the procedure (pjsip_endpt_send_request callback).
void SipEngine::Impl::aka_register_complete(void * /*token*/, pjsip_event *event) {
  auto *owner = active.load();
  if (owner == nullptr || !owner->aka || event == nullptr || event->type != PJSIP_EVENT_TSX_STATE) return;
  auto *transaction = event->body.tsx_state.tsx;
  pjsip_rx_data *received =
      event->body.tsx_state.type == PJSIP_EVENT_RX_MSG ? event->body.tsx_state.src.rdata : nullptr;
  const int status = transaction != nullptr ? transaction->status_code : 500;
  const auto reason = transaction != nullptr ? string_from(transaction->status_text) : std::string("REGISTER failed");
  guarded(owner, [&] { owner->aka_registration_result(received, status, reason); });
}

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.2.1, 5.1.1.5.1 and 5.1.1.5.3: a 401 is a challenge, a 2xx the registration, a 423 a new
// REGISTER with at least Min-Expires; any other result ends the procedure.
void SipEngine::Impl::aka_registration_result(pjsip_rx_data *data, int status, std::string_view reason) {
  if (status == 401 && data != nullptr) return aka_challenge(data);
  if (status >= 200 && status < 300 && data != nullptr) return aka_registered(data);
  SipResponse response = response_from(data);
  if (data == nullptr) {
    response.status_code = status;
    response.reason = std::string(reason);
  }
  if (status == 423 && data != nullptr) {
    const auto min_expires = get_header(response.headers, "Min-Expires");
    unsigned value = 0;
    const auto [end, error] = std::from_chars(min_expires.data(), min_expires.data() + min_expires.size(), value);
    if (error == std::errc{} && value > aka->expires && aka->restarts++ < 2) {
      aka->expires = value;
      aka_delete(aka->pending);
      if (aka->current) return aka_send_register(AkaRoute::current, true, aka->authorization);
      return aka_send_register(AkaRoute::unprotected, true,
                               "Digest username=\"" + config.aka.impi + "\", realm=\"" + aka->realm +
                                   "\", uri=\"sip:" + aka->realm + "\", nonce=\"\", response=\"\"");
    }
  }
  // TS 24.229 clause 5.1.1.2.1: a REGISTER protected by the set in use that gets no answer: the SAs are no longer
  // active; the public user identities are deregistered and the next registration is an initial one.
  if (data == nullptr && aka->route == AkaRoute::current) {
    aka_delete(aka->old);
    aka_delete(aka->current);
  }
  aka_failed(response);
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.5.1 and TS 33.203 clauses 7.3 and 7.4.1a: the procedure failed: the temporary set goes
// ("the UE shall delete the temporary set of security associations it was trying to establish, and use the old set")
// and the application hears the response.
void SipEngine::Impl::aka_failed(const SipResponse &response) {
  if (pj_timer_entry_running(&aka->pending_timer)) (void)pjsip_endpt_cancel_timer(endpoint, &aka->pending_timer);
  aka_delete(aka->pending);
  if (aka->unprotected_connection != nullptr) {
    (void)pjsip_transport_dec_ref(aka->unprotected_connection);
    aka->unprotected_connection = nullptr;
  }
  aka->busy = false;
  aka_finish(response);
}

//------------------------------------------------------------------------------
// Helper: reports a registration result to the handler of register_account (kept for the refreshes, as pjsip_regc
// keeps its callback).
void SipEngine::Impl::aka_finish(const SipResponse &response) {
  auto handler = aka->handler;
  dispatch_response(response, handler);
}

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.5.1 and 5.1.1.5.3, TS 33.203 clauses 6.1.1, 7.2 and 7.3: the 401: the topmost
// WWW-Authenticate with an algorithm the UE supports (AKAv2-SHA-256 or AKAv1-MD5); RAND and AUTN to the ISIM; on
// success the temporary set of SAs from the Security-Server and the protected REGISTER with the response; on a MAC
// failure a REGISTER with an empty response, on an SQN failure one with auts (no temporary set either way); a missing
// Security-Server restarts with a new Call-ID.
void SipEngine::Impl::aka_challenge(pjsip_rx_data *data) {
  auto *message = data->msg_info.msg;
  const SipResponse challenge = response_from(data);
  const auto fail = [&](std::string_view why) {
    report_error(std::string("IMS AKA: ") + std::string(why));
    SipResponse response = challenge;
    response.reason = std::string(why);
    aka_failed(response);
  };
  const pjsip_www_authenticate_hdr *chosen = nullptr;
  std::optional<aka::AkaAlgorithm> algorithm;
  for (auto *header =
           static_cast<pjsip_www_authenticate_hdr *>(pjsip_msg_find_hdr(message, PJSIP_H_WWW_AUTHENTICATE, nullptr));
       header != nullptr; header = static_cast<pjsip_www_authenticate_hdr *>(
                              pjsip_msg_find_hdr(message, PJSIP_H_WWW_AUTHENTICATE, header->next))) {
    if (pj_stricmp2(&header->scheme, "Digest") != 0) continue;
    algorithm = aka::aka_algorithm(string_from(header->challenge.digest.algorithm));
    if (algorithm) {
      chosen = header;
      break;
    }
  }
  if (chosen == nullptr) return fail("401 without an AKAv2-SHA-256 or AKAv1-MD5 challenge");
  const auto &digest = chosen->challenge.digest;
  const auto nonce = string_from(digest.nonce);
  const auto parsed = aka::parse_nonce(nonce);
  if (!parsed) return fail("the AKA nonce is not base64(RAND || AUTN)");
  aka->realm = string_from(digest.realm);
  const auto opaque = string_from(digest.opaque);
  const auto qop_offered = ascii_lower(string_from(digest.qop));
  bool qop_auth = false;
  for (std::size_t at = 0; at < qop_offered.size();) {
    const auto end = std::min(qop_offered.find(',', at), qop_offered.size());
    auto token = qop_offered.substr(at, end - at);
    token.erase(0, token.find_first_not_of(" \t"));
    token.erase(token.find_last_not_of(" \t") + 1);
    qop_auth = qop_auth || token == "auth";
    at = end + 1;
  }
  const auto uri = "sip:" + identity_domain(config.identity);
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
    // TS 33.102 clause 6.3.5 and RFC 3310 section 3.4: AUTS in the auts parameter; the network resynchronises and
    // challenges again (at most twice here).
    if (++aka->resyncs > 2) return fail("SQN still out of range after resynchronisation");
    return aka_send_register(invalid_route, true,
                             base + ", response=\"\", algorithm=" + name + ", auts=\"" + aka::base64(result.auts) +
                                 "\"" + opaque_part);
  }

  // RFC 3329 section 2.3.1 and TS 24.229 clause 5.1.1.5.1 step 3: the Security-Server, as sent, and the mechanism the
  // UE takes from it.
  std::string security_server;
  for (const auto &header : challenge.headers)
    if (ascii_equal(header.name, "Security-Server"))
      security_server += (security_server.empty() ? "" : ", ") + header.value;
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
    std::array<std::uint8_t, 16> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) throw std::runtime_error("random cnonce");
    cnonce = aka::hex(random);
    nc = "00000001";
    qop = "auth";
  }
  const auto response =
      aka::digest_response(*algorithm, config.aka.impi, aka->realm, password, "REGISTER", uri, nonce, nc, cnonce, qop);
  auto authorization = base + ", response=\"" + response + "\", algorithm=" + name;
  if (qop_auth) authorization += ", qop=auth, nc=" + nc + ", cnonce=\"" + cnonce + "\"";
  authorization += opaque_part;

  // TS 33.203 clause 7.4.1a: one registration at a time: an earlier temporary set goes.
  if (pj_timer_entry_running(&aka->pending_timer)) (void)pjsip_endpt_cancel_timer(endpoint, &aka->pending_timer);
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
  set->integrity_key = aka::integrity_key_esp(set->alg, result.ik);
  set->encryption_key = aka::encryption_key_esp(set->ealg, result.ck);
  try {
    aka_install(*set);
  } catch (const std::exception &error) {
    return fail(error.what());
  }
  set->expires_ms = monotonic_ms() + reg_await_auth_ms;
  aka->pending = std::move(set);
  aka_schedule(aka->pending_timer, reg_await_auth_ms, pending_timer_id);
  aka->pending_authorization = authorization;
  aka->pending_algorithm = name;
  // TS 24.229 clause 5.1.1.5.1 step 4: same Call-ID, the same Security-Client, Security-Verify mirroring the
  // Security-Server, protected by the temporary set towards port_ps.
  aka_send_register(AkaRoute::pending, false, authorization);
}

//------------------------------------------------------------------------------
// TS 24.229 clauses 5.1.1.2.1, 5.1.1.2.2, 5.1.1.4.2, 5.1.1.5.1 and 5.1.1.6.2: the 200 (OK): the temporary set
// becomes the set in use (the one before it is old, deleted after the first message from the P-CSCF on the new set,
// TS 33.203 clause 7.4.1a), the SA lifetime is the longest of the previous one and the registration's plus 30 s,
// P-Associated-URI and Service-Route are kept; a deregistration deletes every SA.
void SipEngine::Impl::aka_registered(pjsip_rx_data *data) {
  const SipResponse response = response_from(data);
  if (aka->expires == 0) {
    for (auto *entry : {&aka->refresh_timer, &aka->pending_timer, &aka->old_timer, &aka->expiry_timer})
      if (pj_timer_entry_running(entry)) (void)pjsip_endpt_cancel_timer(endpoint, entry);
    aka_delete(aka->pending);
    aka_delete(aka->old);
    aka_delete(aka->current);
    aka->service_routes.clear();
    aka->associated_uris.clear();
    aka->busy = false;
    return aka_finish(response);
  }
  if (aka->route == AkaRoute::unprotected) {
    SipResponse refused = response;
    refused.status_code = 500;
    refused.reason = "IMS AKA: 200 (OK) to an unprotected REGISTER without authentication";
    report_error(refused.reason);
    return aka_failed(refused);
  }
  if (aka->route == AkaRoute::pending) {
    if (pj_timer_entry_running(&aka->pending_timer)) (void)pjsip_endpt_cancel_timer(endpoint, &aka->pending_timer);
    if (pj_timer_entry_running(&aka->old_timer)) (void)pjsip_endpt_cancel_timer(endpoint, &aka->old_timer);
    aka_delete(aka->old);
    const auto previous_expiry = aka->current ? aka->current->expires_ms : 0;
    aka->old = std::move(aka->current);
    aka->current = std::move(aka->pending);
    aka->current->expires_ms = previous_expiry;
    aka->old_release_scheduled = false;
    aka->authorization = aka->pending_authorization;
    aka->algorithm = aka->pending_algorithm;
    aka_use_current();
    if (aka->unprotected_connection != nullptr) {
      (void)pjsip_transport_dec_ref(aka->unprotected_connection);
      aka->unprotected_connection = nullptr;
    }
  }
  // RFC 3261 section 10.2.4: the expiry granted to our Contact (its expires parameter, or Expires).
  unsigned granted = aka->expires;
  bool contact_found = false;
  for (auto *contact =
           static_cast<pjsip_contact_hdr *>(pjsip_msg_find_hdr(data->msg_info.msg, PJSIP_H_CONTACT, nullptr));
       contact != nullptr; contact = static_cast<pjsip_contact_hdr *>(
                               pjsip_msg_find_hdr(data->msg_info.msg, PJSIP_H_CONTACT, contact->next))) {
    if (contact->uri == nullptr || contact->expires == PJSIP_EXPIRES_NOT_SPECIFIED) continue;
    const auto *sip = static_cast<const pjsip_sip_uri *>(pjsip_uri_get_uri(contact->uri));
    if (sip != nullptr && sip->port == config.listen_port &&
        same_address(string_from(sip->host), config.advertise_address)) {
      granted = static_cast<unsigned>(contact->expires);
      contact_found = true;
      break;
    }
  }
  if (!contact_found) {
    if (const auto *expires =
            static_cast<const pjsip_expires_hdr *>(pjsip_msg_find_hdr(data->msg_info.msg, PJSIP_H_EXPIRES, nullptr));
        expires != nullptr && expires->ivalue > 0)
      granted = std::min<unsigned>(granted, static_cast<unsigned>(expires->ivalue));
  }
  const auto now = monotonic_ms();
  aka->current->expires_ms =
      std::max<std::uint64_t>(aka->current->expires_ms, now + granted * 1000ULL + sa_lifetime_margin_ms);
  aka_schedule(aka->expiry_timer, aka->current->expires_ms - now, expiry_timer_id);
  aka->service_routes = header_list(response.headers, "Service-Route");
  aka->associated_uris = header_list(response.headers, "P-Associated-URI");
  // TS 24.229 clause 5.1.1.4.1: a registration of more than 1200 s is refreshed 600 s before it expires, a shorter one
  // half way.
  const std::uint64_t refresh_s = granted > 1200 ? granted - 600 : std::max(1U, granted / 2);
  aka_schedule(aka->refresh_timer, refresh_s * 1000, refresh_timer_id);
  aka->busy = false;
  aka_finish(response);
}

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.5.1: "use the newly established set of security associations for further messages sent
// towards the P-CSCF": every dialog moves to the new set's connection.
void SipEngine::Impl::aka_use_current() {
  for (auto &[id, entry] : dialogs) {
    (void)id;
    if (entry->dialog != nullptr) aka_apply(entry->dialog);
  }
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4.1a: a request outside a dialog goes from port_uc of the set in use; without one the UE "is not
// allowed to use IMS service".
void SipEngine::Impl::aka_apply(pjsip_tx_data *data) {
  if (!aka) return;
  if (!aka->current) throw std::runtime_error("IMS AKA: not registered, no security associations (TS 33.203 7.4.1a)");
  const auto selector = transport_selector(aka_request_transport(*aka->current));
  require_success(pjsip_tx_data_set_transport(data, &selector), "select the protected connection");
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4.1a: the requests of a dialog go from port_uc of the set in use.
void SipEngine::Impl::aka_apply(pjsip_dialog *dialog) {
  if (!aka) return;
  if (!aka->current) throw std::runtime_error("IMS AKA: not registered, no security associations (TS 33.203 7.4.1a)");
  const auto selector = transport_selector(aka_request_transport(*aka->current));
  require_success(pjsip_dlg_set_transport(dialog, &selector), "select the dialog's protected connection");
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
// TS 33.203 clause 7.1 rules 4 and 7, clause 7.4.1a: a received message is taken only on the inbound SA it belongs
// to: from the P-CSCF on (port_uc, port_ps) or (port_us, port_pc) of a set; on the temporary set only the answer to
// the protected REGISTER; on an unprotected port only responses to an unprotected REGISTER. The first message on the
// set in use starts the end of the old set.
bool SipEngine::Impl::aka_accept(pjsip_rx_data *data) {
  auto *message = data->msg_info.msg;
  const bool response = message->type == PJSIP_RESPONSE_MSG;
  const bool register_response =
      response && data->msg_info.cseq != nullptr && data->msg_info.cseq->method.id == PJSIP_REGISTER_METHOD;
  const auto *transport = data->tp_info.transport;
  const auto local_port =
      transport != nullptr ? pj_sockaddr_get_port(&transport->local_addr) : static_cast<pj_uint16_t>(0);
  const auto remote_port = static_cast<std::uint16_t>(data->pkt_info.src_port);
  const bool from_pcscf = same_address(data->pkt_info.src_name, config.aka.pcscf_address);
  const auto on = [&](const AkaSet *set) {
    return set != nullptr && from_pcscf &&
           ((local_port == set->port_uc && remote_port == set->port_ps) ||
            (local_port == set->port_us && remote_port == set->port_pc));
  };
  if (on(aka->current.get())) {
    if (aka->old && !aka->old_release_scheduled) {
      aka->old_release_scheduled = true;
      aka_schedule(aka->old_timer, old_set_release_ms, old_timer_id);
    }
    return true;
  }
  if (on(aka->pending.get())) return register_response;
  if (on(aka->old.get())) return true;
  bool protected_port = local_port == config.listen_port;
  for (const auto *set : {aka->current.get(), aka->pending.get(), aka->old.get()})
    protected_port = protected_port || (set != nullptr && local_port == set->port_uc);
  return register_response && !protected_port;
}

//------------------------------------------------------------------------------
// The receive filter module: a message that aka_accept refuses is discarded silently (TS 33.203 clause 7.1 rule 4:
// "rejected or silently discarded").
pj_bool_t SipEngine::Impl::aka_filter(pjsip_rx_data *data) {
  auto *owner = active.load();
  if (owner == nullptr || !owner->aka || data == nullptr || data->msg_info.msg == nullptr) return PJ_FALSE;
  bool accepted = true;
  guarded(owner, [&] { accepted = owner->aka_accept(data); });
  if (accepted) return PJ_FALSE;
  if (log_level() == LogLevel::debug)
    debug_line("SIP dropped (IMS AKA: not on its security association, TS 33.203 clause 7.1) from " +
               std::string(data->pkt_info.src_name) + ":" + std::to_string(data->pkt_info.src_port));
  return PJ_TRUE;
}

//------------------------------------------------------------------------------
// Helper: (re)starts one of the IMS AKA timers.
void SipEngine::Impl::aka_schedule(pj_timer_entry &entry, std::uint64_t delay_ms, int id) {
  if (pj_timer_entry_running(&entry)) (void)pjsip_endpt_cancel_timer(endpoint, &entry);
  entry.id = id;
  pj_time_val delay{};
  delay.sec = static_cast<long>(delay_ms / 1000);
  delay.msec = static_cast<long>(delay_ms % 1000);
  require_success(pjsip_endpt_schedule_timer(endpoint, &entry, &delay), "schedule an IMS AKA timer");
}

//------------------------------------------------------------------------------
// The IMS AKA timers: the refresh of the registration (TS 24.229 clause 5.1.1.4.1), the end of the temporary set
// (reg-await-auth, clause 5.1.1.5.1), the end of the old set (TS 33.203 clause 7.4.1a) and the end of the set in use
// at its lifetime ("The UE shall delete any SA whose lifetime is exceeded").
void SipEngine::Impl::aka_timer(pj_timer_heap_t * /*heap*/, pj_timer_entry *entry) {
  auto *owner = static_cast<Impl *>(entry->user_data);
  if (owner == nullptr || owner != active.load() || !owner->aka) return;
  guarded(owner, [&] {
    auto &state = *owner->aka;
    if (entry == &state.refresh_timer) {
      if (!state.busy && state.current) owner->aka_register(state.expires, {}, {}, state.handler);
    } else if (entry == &state.pending_timer) {
      owner->aka_delete(state.pending);
    } else if (entry == &state.old_timer) {
      owner->aka_delete(state.old);
    } else if (entry == &state.expiry_timer) {
      owner->aka_delete(state.old);
      owner->aka_delete(state.current);
      owner->report_error("IMS AKA: the security associations expired; the registration has ended");
    }
  });
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
