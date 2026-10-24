//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The IPsec ESP security associations of an IMS AKA UE in the kernel (mcx::xfrm): without CAP_NET_ADMIN the clear
// refusal; with it (a scratch network namespace), the two pairs of SAs of one registration added, read back from
// the kernel, refused when added twice, removed, and the NULL encryption and unknown algorithm cases.
//
// Specifications: TS 33.203 V19.1.0 (Rel-19) clauses 6.3, 7.1, 7.2, annexes H and I; RFC 4303.
#include "mcx/xfrm.hpp"

#include <unistd.h>

#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <iostream>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <vector>

using mcx::xfrm::SecurityAssociation;
using mcx::xfrm::Xfrm;
using mcx::xfrm::XfrmError;

//------------------------------------------------------------------------------
// Fails the test with the message why when the condition yes does not hold.
void check(bool yes, const char *why) {
  if (!yes) throw std::runtime_error(why);
}

//------------------------------------------------------------------------------
// Checks that the action throws XfrmError.
template <class Action> void rejects(Action action, const char *why) {
  bool threw = false;
  try {
    action();
  } catch (const XfrmError &) {
    threw = true;
  }
  check(threw, why);
}

//------------------------------------------------------------------------------
// Whether the kernel has the SA (XFRM_MSG_GETSA by destination, SPI and ESP), read on a netlink socket of the test's
// own; the SA found must have the SPI, transport mode and the replay window of 32.
bool kernel_has(const SecurityAssociation &sa) {
  const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
  check(fd >= 0, "test netlink socket");

  struct {
    nlmsghdr header;
    xfrm_usersa_id id;
  } request{};

  request.header.nlmsg_len = NLMSG_LENGTH(sizeof(xfrm_usersa_id));
  request.header.nlmsg_type = XFRM_MSG_GETSA;
  request.header.nlmsg_flags = NLM_F_REQUEST;
  request.header.nlmsg_seq = 1;
  check(inet_pton(AF_INET, sa.destination.c_str(), &request.id.daddr.a4) == 1, "test address");
  request.id.spi = htonl(sa.spi);
  request.id.family = AF_INET;
  request.id.proto = IPPROTO_ESP;
  sockaddr_nl kernel{};
  kernel.nl_family = AF_NETLINK;
  check(::sendto(fd, &request, request.header.nlmsg_len, 0, reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel)) > 0,
        "test GETSA send");
  alignas(nlmsghdr) std::array<unsigned char, 8192> reply{};
  const ssize_t received = ::recv(fd, reply.data(), reply.size(), 0);
  ::close(fd);
  check(received > 0, "test GETSA answer");
  const auto *answer = reinterpret_cast<const nlmsghdr *>(reply.data());
  if (answer->nlmsg_type == NLMSG_ERROR) return false;
  check(answer->nlmsg_type == XFRM_MSG_NEWSA, "GETSA answer type");
  const auto *info = static_cast<const xfrm_usersa_info *>(NLMSG_DATA(answer));
  check(ntohl(info->id.spi) == sa.spi && info->mode == XFRM_MODE_TRANSPORT && info->replay_window == 32,
        "SA parameters as added");
  check(ntohs(info->sel.sport) == sa.source_port && ntohs(info->sel.dport) == sa.destination_port, "SA selectors");
  return true;
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1: the four SAs of one registration between UE 10.250.0.1 (port_uc 31001, port_us 31002) and
// P-CSCF 10.250.0.2 (port_pc 5101, port_ps 6101): UE -> P-CSCF from port_uc to port_ps (spi_ps) and from port_us to
// port_pc (spi_pc), and the inbound SAs back (spi_uc, spi_us).
int main() {
  try {
    bool privileged = true;
    try {
      Xfrm probe;
    } catch (const XfrmError &error) {
      check(std::string(error.what()).find("IMS AKA needs CAP_NET_ADMIN") != std::string::npos,
            "the refusal names CAP_NET_ADMIN");
      privileged = false;
    }
    if (!privileged) {
      std::cout << "xfrm: no CAP_NET_ADMIN, refusal checked, SA tests skipped\n";
      return 0;
    }

    Xfrm xfrm;
    const std::vector<std::uint8_t> ik_esp = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                              0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x00, 0x00, 0x00, 0x00};
    const std::vector<std::uint8_t> ck_esp = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                                              0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
    const auto make = [&](const char *source, std::uint16_t sport, const char *destination, std::uint16_t dport,
                          std::uint32_t spi, bool outbound) {
      SecurityAssociation sa;
      sa.source = source;
      sa.destination = destination;
      sa.source_port = sport;
      sa.destination_port = dport;
      sa.spi = spi;
      sa.alg = "hmac-sha-1-96";
      sa.ealg = "aes-cbc";
      sa.integrity_key = ik_esp;
      sa.encryption_key = ck_esp;
      sa.outbound = outbound;
      return sa;
    };
    const std::array set = {
        make("10.250.0.1", 31001, "10.250.0.2", 6101, 0x10001001U, true),   // port_uc -> port_ps, spi_ps
        make("10.250.0.1", 31002, "10.250.0.2", 5101, 0x10001002U, true),   // port_us -> port_pc, spi_pc
        make("10.250.0.2", 6101, "10.250.0.1", 31001, 0x20002001U, false),  // port_ps -> port_uc, spi_uc
        make("10.250.0.2", 5101, "10.250.0.1", 31002, 0x20002002U, false)}; // port_pc -> port_us, spi_us
    for (const auto &sa : set) xfrm.add(sa);
    for (const auto &sa : set) check(kernel_has(sa), "added SA in the kernel");
    rejects([&] { xfrm.add(set[0]); }, "an SA added twice is refused");
    for (const auto &sa : set) xfrm.remove(sa);
    for (const auto &sa : set) check(!kernel_has(sa), "removed SA gone");
    xfrm.remove(set[0]); // gone already: no error

    // TS 33.203 clause 7.2: the NULL encryption algorithm when the P-CSCF names no ealg.
    auto plain = make("10.250.0.1", 31003, "10.250.0.2", 6101, 0x10001003U, true);
    plain.ealg = "null";
    plain.encryption_key.clear();
    xfrm.add(plain);
    check(kernel_has(plain), "NULL encryption SA in the kernel");
    xfrm.remove(plain);
    check(!kernel_has(plain), "NULL encryption SA removed");

    // Annex H algorithms this UE does not offer, a wrong key length and a reserved SPI.
    auto md5 = make("10.250.0.1", 31004, "10.250.0.2", 6101, 0x10001004U, true);
    md5.alg = "hmac-md5-96";
    rejects([&] { xfrm.add(md5); }, "hmac-md5-96 refused");
    auto des = make("10.250.0.1", 31004, "10.250.0.2", 6101, 0x10001004U, true);
    des.ealg = "des-ede3-cbc";
    rejects([&] { xfrm.add(des); }, "des-ede3-cbc refused");
    auto short_key = make("10.250.0.1", 31004, "10.250.0.2", 6101, 0x10001004U, true);
    short_key.integrity_key.resize(16);
    rejects([&] { xfrm.add(short_key); }, "a 128-bit IK_ESP for hmac-sha-1-96 refused");
    auto reserved = make("10.250.0.1", 31004, "10.250.0.2", 6101, 200, true);
    rejects([&] { xfrm.add(reserved); }, "a reserved SPI refused");
    check(!kernel_has(md5), "no SA left by a refused request");
    std::cout << "xfrm: SA and policy tests passed\n";
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
  return 0;
}
