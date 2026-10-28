//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The IPsec ESP security associations and security policies of an IMS AKA UE in the Linux kernel (XFRM), written as
// netlink messages on a raw NETLINK_XFRM socket (include/mcx/xfrm.hpp).
//
// Specifications: TS 33.203 V19.1.0 (Rel-19) clauses 6.2, 6.3, 7.1, 7.4 and annexes H, I; RFC 4301, RFC 4303.

#include "mcx/xfrm.hpp"

#include "mcx/runtime.hpp"

#include <unistd.h>

#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>

namespace mcx::xfrm {
namespace {
// Helper: the Linux capability that the XFRM requests need (include/uapi/linux/capability.h).
constexpr unsigned cap_net_admin = 12;
// Helper: the room for one request: the header, the largest fixed part, two algorithms and one template.
constexpr std::size_t request_bytes = 2048;
// TS 33.203 clause 6.3: "The anti-replay service shall be enabled ... on all established SAs": a window of 32
// packets (RFC 4303 section 3.4.3, the minimum window size it requires).
constexpr std::uint8_t replay_window = 32;

//------------------------------------------------------------------------------
// Helper: the error text of a missing CAP_NET_ADMIN.
std::string privilege_error(std::string_view what) {
  return "IMS AKA needs CAP_NET_ADMIN to " + std::string(what) +
         " (XFRM security associations; give the client container cap_add NET_ADMIN)";
}

//------------------------------------------------------------------------------
// Helper: whether this process has CAP_NET_ADMIN in its effective set (the CapEff line of /proc/self/status).
bool has_net_admin() {
  std::ifstream status("/proc/self/status");
  std::string line;
  while (std::getline(status, line)) {
    if (!line.starts_with("CapEff:")) continue;
    std::istringstream value(line.substr(7));
    unsigned long long capabilities = 0;
    value >> std::hex >> capabilities;
    return (capabilities >> cap_net_admin) & 1U;
  }
  return false;
}

//------------------------------------------------------------------------------
// Helper: a numeric IPv4 or IPv6 address as the kernel's xfrm_address_t, and its address family.
struct Address {
  xfrm_address_t value{};
  unsigned short family = 0;
};

Address parse_address(const std::string &text) {
  Address address;
  if (inet_pton(AF_INET, text.c_str(), &address.value.a4) == 1) {
    address.family = AF_INET;
  } else if (inet_pton(AF_INET6, text.c_str(), &address.value.a6) == 1) {
    address.family = AF_INET6;
  } else {
    throw XfrmError("XFRM: not a numeric IP address: " + text);
  }
  return address;
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 (Selectors): the source and destination address (full length), the two ports (exact) and any
// transport protocol ("The transport protocol selector shall allow UDP and TCP") of an SA and its policy.
xfrm_selector selector_of(const SecurityAssociation &sa, const Address &source, const Address &destination) {
  if (source.family != destination.family) throw XfrmError("XFRM: source and destination of different families");
  xfrm_selector selector{};
  selector.family = destination.family;
  selector.saddr = source.value;
  selector.daddr = destination.value;
  selector.prefixlen_s = selector.prefixlen_d = destination.family == AF_INET ? 32 : 128;
  selector.sport = htons(sa.source_port);
  selector.dport = htons(sa.destination_port);
  selector.sport_mask = selector.dport_mask = 0xffff;
  selector.proto = 0;
  return selector;
}

//------------------------------------------------------------------------------
// Helper: a netlink request being built in a fixed buffer: the header, the fixed part and its attributes.
class Request {
public:
  Request(std::uint16_t type, std::uint16_t flags) {
    header()->nlmsg_type = type;
    header()->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    header()->nlmsg_len = NLMSG_LENGTH(0);
  }

  nlmsghdr *header() { return reinterpret_cast<nlmsghdr *>(buffer_.data()); }

  // The fixed part (xfrm_usersa_info and the like) right after the header.
  template <class Body> Body *body() {
    header()->nlmsg_len = NLMSG_LENGTH(sizeof(Body));
    return reinterpret_cast<Body *>(NLMSG_DATA(header()));
  }

  // One attribute (struct nlattr) at the aligned end of the message.
  void attribute(std::uint16_t type, const void *data, std::size_t length) {
    const std::size_t at = NLMSG_ALIGN(header()->nlmsg_len);
    const std::size_t total = NLA_HDRLEN + length;
    if (at + NLA_ALIGN(total) > buffer_.size()) throw XfrmError("XFRM: request too long");
    auto *entry = reinterpret_cast<nlattr *>(buffer_.data() + at);
    entry->nla_type = type;
    entry->nla_len = static_cast<std::uint16_t>(total);
    std::memcpy(buffer_.data() + at + NLA_HDRLEN, data, length);
    header()->nlmsg_len = static_cast<std::uint32_t>(at + NLA_ALIGN(total));
  }

  std::size_t length() { return header()->nlmsg_len; }

private:
  alignas(nlmsghdr) std::array<unsigned char, request_bytes> buffer_{};
};

//------------------------------------------------------------------------------
// Helper: hexadecimal text of bytes, for the debug log line.
std::string hex(const std::vector<std::uint8_t> &bytes) {
  std::string text;
  char digits[3];
  for (const auto byte : bytes) {
    std::snprintf(digits, sizeof(digits), "%02x", byte);
    text += digits;
  }
  return text.empty() ? "-" : text;
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.203 clause 6.3: opens the NETLINK_XFRM socket for this network namespace's SAD and SPD; without CAP_NET_ADMIN
// the kernel refuses every change, so the engine stops at once with that reason.
Xfrm::Xfrm() {
  if (!has_net_admin()) throw XfrmError(privilege_error("set up IPsec"));
  socket_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
  if (socket_ < 0) throw XfrmError(std::string("XFRM: cannot open the netlink socket: ") + std::strerror(errno));
  sockaddr_nl local{};
  local.nl_family = AF_NETLINK;
  if (::bind(socket_, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
    const int error = errno;
    ::close(socket_);
    throw XfrmError(std::string("XFRM: cannot bind the netlink socket: ") + std::strerror(error));
  }
}

//------------------------------------------------------------------------------
// Helper: closes the netlink socket; the SAs stay until removed (the engine removes them, TS 33.203 clause 7.4.1a).
Xfrm::~Xfrm() {
  if (socket_ >= 0) ::close(socket_);
}

//------------------------------------------------------------------------------
// Helper: sends one request to the kernel and reads its acknowledgement (NLMSG_ERROR with error 0); a refusal throws
// XfrmError, except "no such SA or policy" when missing_ok.
void Xfrm::transact(void *message, std::size_t length, bool missing_ok) {
  auto *header = static_cast<nlmsghdr *>(message);
  header->nlmsg_seq = ++sequence_;
  sockaddr_nl kernel{};
  kernel.nl_family = AF_NETLINK;
  if (::sendto(socket_, message, length, 0, reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) < 0)
    throw XfrmError(std::string("XFRM: cannot send to the kernel: ") + std::strerror(errno));
  alignas(nlmsghdr) std::array<unsigned char, 8192> reply{};
  for (;;) {
    const ssize_t received = ::recv(socket_, reply.data(), reply.size(), 0);
    if (received < 0) {
      if (errno == EINTR) continue;
      throw XfrmError(std::string("XFRM: cannot read the kernel's answer: ") + std::strerror(errno));
    }
    auto remaining = static_cast<int>(received);
    for (auto *answer = reinterpret_cast<nlmsghdr *>(reply.data()); NLMSG_OK(answer, remaining);
         answer = NLMSG_NEXT(answer, remaining)) {
      if (answer->nlmsg_seq != sequence_ || answer->nlmsg_type != NLMSG_ERROR) continue;
      const auto *error = static_cast<const nlmsgerr *>(NLMSG_DATA(answer));
      if (error->error == 0) return;
      const int code = -error->error;
      if (missing_ok && (code == ENOENT || code == ESRCH)) return;
      if (code == EPERM) throw XfrmError(privilege_error("change the SA and policy databases"));
      throw XfrmError(std::string("XFRM: the kernel refused the request: ") + std::strerror(code));
    }
  }
}

//------------------------------------------------------------------------------
// TS 33.203 clauses 6.2, 6.3 and 7.1: adds one unidirectional SA (ESP in transport mode, anti-replay on, the SA
// duration unlimited at the network layer, clause 7.1 NOTE 4; the integrity algorithm of annex H with IK_ESP and the
// encryption algorithm with CK_ESP of annex I) and then its security policy, OUT for an outbound SA and IN for an
// inbound one, whose template names this SA (reqid = SPI); a policy that cannot be added takes the SA with it.
void Xfrm::add(const SecurityAssociation &sa) {
  const auto source = parse_address(sa.source);
  const auto destination = parse_address(sa.destination);
  const auto selector = selector_of(sa, source, destination);
  if (sa.spi < 256) throw XfrmError("XFRM: SPI values 0 to 255 are reserved (RFC 4303 section 2.1)");

  // Annex H with annex I: the kernel transforms and their keys. AES-GCM (RFC 4106, 16-octet ICV) and AES-GMAC
  // (RFC 4543) are AEAD transforms keyed with CK_ESP or IK_ESP followed by the salt; HMAC-SHA-1-96 (RFC 2404) and
  // HMAC-SHA2-256-128 (RFC 4868) authenticate, with AES-CBC (RFC 3602) or the NULL algorithm (RFC 2410).
  const bool gcm = (sa.ealg == "aes-gcm" || sa.ealg == "aes-gcm-us") && sa.alg == "null";
  const bool gmac = (sa.alg == "aes-gmac" || sa.alg == "aes-gmac-us") && sa.ealg == "null";
  const char *auth_name = sa.alg == "hmac-sha-1-96"       ? "hmac(sha1)"
                          : sa.alg == "hmac-sha2-256-128" ? "hmac(sha256)"
                                                          : nullptr;
  const unsigned auth_trunc = sa.alg == "hmac-sha-1-96" ? 96 : 128;
  const std::size_t auth_key = sa.alg == "hmac-sha-1-96" ? 20 : 32;
  const bool null_encryption = sa.ealg == "null";
  if (gcm || gmac) {
    const auto &key = gcm ? sa.encryption_key : sa.integrity_key;
    if (key.size() != 16 || sa.salt.size() != 4)
      throw XfrmError("XFRM: unsupported AEAD key or salt: " + sa.alg + "/" + sa.ealg);
  } else {
    if (auth_name == nullptr || sa.integrity_key.size() != auth_key)
      throw XfrmError("XFRM: unsupported integrity algorithm or key: " + sa.alg);
    if (!null_encryption && (sa.ealg != "aes-cbc" || sa.encryption_key.size() != 16))
      throw XfrmError("XFRM: unsupported encryption algorithm or key: " + sa.ealg);
  }

  Request request(XFRM_MSG_NEWSA, NLM_F_CREATE | NLM_F_EXCL);
  auto *info = request.body<xfrm_usersa_info>();
  info->sel = selector;
  info->id.daddr = destination.value;
  info->id.spi = htonl(sa.spi);
  info->id.proto = IPPROTO_ESP;
  info->saddr = source.value;
  info->family = destination.family;
  info->mode = XFRM_MODE_TRANSPORT;
  info->reqid = sa.spi;
  info->replay_window = replay_window;
  info->lft.soft_byte_limit = info->lft.hard_byte_limit = XFRM_INF;
  info->lft.soft_packet_limit = info->lft.hard_packet_limit = XFRM_INF;

  if (gcm || gmac) {
    const auto &key = gcm ? sa.encryption_key : sa.integrity_key;
    std::array<unsigned char, sizeof(xfrm_algo_aead) + 64> aead_buffer{};
    auto *aead = reinterpret_cast<xfrm_algo_aead *>(aead_buffer.data());
    std::strncpy(aead->alg_name, gcm ? "rfc4106(gcm(aes))" : "rfc4543(gcm(aes))", sizeof(aead->alg_name) - 1);
    aead->alg_key_len = static_cast<unsigned>((key.size() + sa.salt.size()) * 8);
    aead->alg_icv_len = 128;
    std::memcpy(aead->alg_key, key.data(), key.size());
    std::memcpy(aead->alg_key + key.size(), sa.salt.data(), sa.salt.size());
    request.attribute(XFRMA_ALG_AEAD, aead, sizeof(xfrm_algo_aead) + key.size() + sa.salt.size());
  } else {
    std::array<unsigned char, sizeof(xfrm_algo_auth) + 64> auth_buffer{};
    auto *auth = reinterpret_cast<xfrm_algo_auth *>(auth_buffer.data());
    std::strncpy(auth->alg_name, auth_name, sizeof(auth->alg_name) - 1);
    auth->alg_key_len = static_cast<unsigned>(sa.integrity_key.size() * 8);
    auth->alg_trunc_len = auth_trunc;
    std::memcpy(auth->alg_key, sa.integrity_key.data(), sa.integrity_key.size());
    request.attribute(XFRMA_ALG_AUTH_TRUNC, auth, sizeof(xfrm_algo_auth) + sa.integrity_key.size());

    std::array<unsigned char, sizeof(xfrm_algo) + 64> crypt_buffer{};
    auto *crypt = reinterpret_cast<xfrm_algo *>(crypt_buffer.data());
    std::strncpy(crypt->alg_name, null_encryption ? "ecb(cipher_null)" : "cbc(aes)", sizeof(crypt->alg_name) - 1);
    const std::size_t crypt_key = null_encryption ? 0 : sa.encryption_key.size();
    crypt->alg_key_len = static_cast<unsigned>(crypt_key * 8);
    if (crypt_key != 0) std::memcpy(crypt->alg_key, sa.encryption_key.data(), crypt_key);
    request.attribute(XFRMA_ALG_CRYPT, crypt, sizeof(xfrm_algo) + crypt_key);
  }
  transact(request.header(), request.length(), false);

  try {
    Request policy(XFRM_MSG_NEWPOLICY, NLM_F_CREATE | NLM_F_EXCL);
    auto *policy_info = policy.body<xfrm_userpolicy_info>();
    policy_info->sel = selector;
    policy_info->dir = sa.outbound ? XFRM_POLICY_OUT : XFRM_POLICY_IN;
    policy_info->action = XFRM_POLICY_ALLOW;
    policy_info->share = XFRM_SHARE_ANY;
    policy_info->lft.soft_byte_limit = policy_info->lft.hard_byte_limit = XFRM_INF;
    policy_info->lft.soft_packet_limit = policy_info->lft.hard_packet_limit = XFRM_INF;
    xfrm_user_tmpl tmpl{};
    tmpl.id.daddr = destination.value;
    tmpl.id.spi = htonl(sa.spi);
    tmpl.id.proto = IPPROTO_ESP;
    tmpl.family = destination.family;
    tmpl.saddr = source.value;
    tmpl.reqid = sa.spi;
    tmpl.mode = XFRM_MODE_TRANSPORT;
    tmpl.aalgos = tmpl.ealgos = tmpl.calgos = ~0U;
    policy.attribute(XFRMA_TMPL, &tmpl, sizeof(tmpl));
    transact(policy.header(), policy.length(), false);
  } catch (...) {
    Request undo(XFRM_MSG_DELSA, 0);
    auto *id = undo.body<xfrm_usersa_id>();
    id->daddr = destination.value;
    id->spi = htonl(sa.spi);
    id->family = destination.family;
    id->proto = IPPROTO_ESP;
    undo.attribute(XFRMA_SRCADDR, &source.value, sizeof(source.value));
    try {
      transact(undo.header(), undo.length(), true);
    } catch (const XfrmError &) {
      // The SA could not be taken back either; the policy error is the one reported.
    }
    throw;
  }

  // OpenMCX, not TS 33.203: the SA and its keys at log level debug, so that a capture of the protected SIP signalling
  // can be decrypted (Wireshark's ESP SA table), like the TLS key log of the digest clients.
  if (log_level() == LogLevel::debug) {
    char spi[16];
    std::snprintf(spi, sizeof(spi), "0x%08x", sa.spi);
    debug_line("ESP SA " + sa.source + ":" + std::to_string(sa.source_port) + " -> " + sa.destination + ":" +
               std::to_string(sa.destination_port) + " spi " + spi + " auth " + sa.alg + " key " +
               (sa.integrity_key.empty() ? std::string("-") : hex(sa.integrity_key)) + " enc " + sa.ealg + " key " +
               (sa.encryption_key.empty() ? std::string("-") : hex(sa.encryption_key)) +
               (sa.salt.empty() ? std::string() : " salt " + hex(sa.salt)));
  }
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.4.1a: deletes an SA and its policy ("deleting an SA means deleting the SA from both the
// application and IPsec layer"); one already gone, or any failure, is not reported, since a removal must not stop
// the engine.
void Xfrm::remove(const SecurityAssociation &sa) noexcept {
  try {
    const auto source = parse_address(sa.source);
    const auto destination = parse_address(sa.destination);
    Request policy(XFRM_MSG_DELPOLICY, 0);
    auto *policy_id = policy.body<xfrm_userpolicy_id>();
    policy_id->sel = selector_of(sa, source, destination);
    policy_id->dir = sa.outbound ? XFRM_POLICY_OUT : XFRM_POLICY_IN;
    try {
      transact(policy.header(), policy.length(), true);
    } catch (const XfrmError &) {
      // The SA is removed all the same.
    }
    Request request(XFRM_MSG_DELSA, 0);
    auto *id = request.body<xfrm_usersa_id>();
    id->daddr = destination.value;
    id->spi = htonl(sa.spi);
    id->family = destination.family;
    id->proto = IPPROTO_ESP;
    request.attribute(XFRMA_SRCADDR, &source.value, sizeof(source.value));
    transact(request.header(), request.length(), true);
  } catch (...) {
    // Nothing to report from here (see above).
  }
}

} // namespace mcx::xfrm
