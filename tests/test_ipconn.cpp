//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData IP connectivity media plane (TS 24.582 clause 13): SDP, GRE-in-UDP
// encapsulation (IETF RFC 8086, RFC 2784) and the IPv4/ICMP endpoint.
//
// Specifications: TS 24.582 V19.0.0 (Rel-19); RFC 8086, RFC 2784, RFC 791, RFC 792, RFC 1071.
#include "mcx/ipconn.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {
int failures = 0;

//------------------------------------------------------------------------------
// Counts a failure, with the message what, when the condition does not hold.
void check(bool condition, const char *what) {
  if (!condition) {
    std::cerr << "FAILED: " << what << '\n';
    ++failures;
  }
}

//------------------------------------------------------------------------------
// Counts a failure, with the message what, when the action does not throw.
template <typename Action> void rejects(Action &&action, const char *what) {
  try {
    action();
    std::cerr << "FAILED to reject: " << what << '\n';
    ++failures;
  } catch (const std::exception &) {}
}

//------------------------------------------------------------------------------
// The values as bytes.
std::vector<std::uint8_t> bytes(std::initializer_list<int> values) {
  std::vector<std::uint8_t> out;
  for (auto value : values) out.push_back(static_cast<std::uint8_t>(value));
  return out;
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.582 clauses 13.4, 13.5.2.1 and 13.6.2.3: the GRE-in-UDP tunnel SDP, the IPv4 and ICMP echo codec of the
// tunnel endpoint, and GRE encapsulation and decapsulation (no GRE key, protocol type from the packet).
int main() {
  using namespace mcx::ipconn;

  // SDP (TS 24.582 table 13.5.2.1-1 and table 13.6.2.3-1).
  const auto text = tunnel_sdp({"10.1.2.3", 20032, 20032}, 7);
  check(text == "v=0\r\no=- 7 1 IN IP4 10.1.2.3\r\ns=MCData\r\nc=IN IP4 10.1.2.3\r\nt=0 0\r\n"
                "m=application 20032 udp MCDATA\r\na=fmtp:MCDATA mcdata-ipconn-s-port=20032\r\n",
        "tunnel SDP");
  const auto parsed = parse_tunnel_sdp(text);
  check(parsed.address == "10.1.2.3" && parsed.port == 20032 && parsed.source_port == 20032, "tunnel SDP round trip");
  const auto example = parse_tunnel_sdp("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 96\r\nc=IN IP4 192.0.2.9\r\n"
                                        "m=application 20032 udp MCDATA\r\na=fmtp:MCDATA mcdata-ipconn\r\n");
  check(example.address == "192.0.2.1" && example.port == 20032 && !example.source_port,
        "the 13.5.2.1 example: session-level address, other sections skipped, fmtp without a port");
  check(parse_tunnel_sdp("v=0\r\nc=IN IP4 192.0.2.1\r\nm=application 9 udp MCDATA\r\nc=IN IP4 192.0.2.7\r\n").address ==
            "192.0.2.7",
        "a media-level connection address wins");
  rejects([] { (void)parse_tunnel_sdp("v=0\r\nc=IN IP4 192.0.2.1\r\nm=message 9 TCP/MSRP *\r\n"); },
          "an SDP without the IP connectivity section");
  rejects([] { (void)parse_tunnel_sdp("v=0\r\nc=IN IP4 192.0.2.1\r\nm=application 0 udp MCDATA\r\n"); }, "port 0");
  rejects([] { (void)parse_tunnel_sdp("v=0\r\nm=application 9 udp MCDATA\r\n"); }, "no connection address");
  rejects([] { (void)tunnel_sdp({"mcdata-server", 9, {}}, 1); }, "a host name instead of an address");

  // IPv4 header (RFC 791 section 3.1), checksum (RFC 1071) with the well-known IPv4 header whose checksum is 0xb861.
  const auto header = bytes({0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
                             0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7});
  check(internet_checksum(header) == 0xb861, "internet checksum");
  Ipv4Packet ip;
  ip.source = "192.168.0.1";
  ip.destination = "192.168.0.199";
  ip.protocol = 17;
  ip.payload.assign(0x73 - 20, 0);
  const auto encoded = encode_ipv4(ip);
  check(std::vector(encoded.begin(), encoded.begin() + 20) ==
            bytes({0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
                   0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7}),
        "IPv4 header byte-exact");
  const auto decoded = decode_ipv4(encoded);
  check(decoded.source == "192.168.0.1" && decoded.destination == "192.168.0.199" && decoded.protocol == 17 &&
            decoded.payload.size() == 0x73 - 20,
        "IPv4 round trip");
  auto corrupt = encoded;
  corrupt[15] ^= 1;
  rejects([&] { (void)decode_ipv4(corrupt); }, "an IPv4 header checksum mismatch");
  auto truncated = encoded;
  truncated.resize(60);
  rejects([&] { (void)decode_ipv4(truncated); }, "a total length beyond the packet");

  // ICMP echo (RFC 792), checksum worked by hand: 0x0800+1+1+0x6162+0x6364 = 0xccc8.
  const auto echo = encode_icmp_echo({false, 1, 1, bytes({'a', 'b', 'c', 'd'})});
  check(echo == bytes({0x08, 0x00, 0x33, 0x37, 0x00, 0x01, 0x00, 0x01, 'a', 'b', 'c', 'd'}), "ICMP echo byte-exact");
  const auto reply = decode_icmp_echo(encode_icmp_echo({true, 0x1234, 9, bytes({1, 2, 3})}));
  check(reply.reply && reply.identifier == 0x1234 && reply.sequence == 9 && reply.data == bytes({1, 2, 3}),
        "ICMP echo reply round trip");
  auto bad_echo = echo;
  bad_echo.back() ^= 0xff;
  rejects([&] { (void)decode_icmp_echo(bad_echo); }, "an ICMP checksum mismatch");
  rejects([] { (void)decode_icmp_echo(bytes({3, 1, 0xfc, 0xfe, 0, 0, 0, 0})); }, "an ICMP message other than echo");

  // GRE-in-UDP (TS 24.582 clause 13.4, RFC 8086, RFC 2784): no checksum, no key, protocol type from the packet.
  const auto packet = encode_ipv4({"10.77.0.1", "10.77.0.2", 1, 64, 7, echo});
  const auto tunnelled = encapsulate(packet);
  check(tunnelled.size() == packet.size() + 4 && tunnelled[0] == 0 && tunnelled[1] == 0 && tunnelled[2] == 0x08 &&
            tunnelled[3] == 0x00,
        "GRE header for IPv4");
  const auto opened = decapsulate(tunnelled);
  check(opened.protocol == ipv4 && opened.packet == packet, "GRE round trip");
  check(encapsulate(bytes({0x60, 0, 0, 0}))[2] == 0x86 && encapsulate(bytes({0x60, 0, 0, 0}))[3] == 0xdd,
        "GRE protocol type for IPv6");
  // A GRE checksum (C bit, RFC 2784) is accepted when it verifies.
  auto with_checksum = bytes({0x80, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00});
  with_checksum.insert(with_checksum.end(), packet.begin(), packet.end());
  const auto sum = internet_checksum(with_checksum);
  with_checksum[4] = static_cast<std::uint8_t>(sum >> 8);
  with_checksum[5] = static_cast<std::uint8_t>(sum);
  check(decapsulate(with_checksum).packet == packet, "GRE with a valid checksum");
  with_checksum[5] ^= 1;
  rejects([&] { (void)decapsulate(with_checksum); }, "a GRE checksum mismatch");
  auto keyed = tunnelled;
  keyed[0] = 0x20;
  rejects([&] { (void)decapsulate(keyed); }, "a GRE key (TS 24.582 13.4 step 3)");
  auto version1 = tunnelled;
  version1[1] = 0x01;
  rejects([&] { (void)decapsulate(version1); }, "GRE version 1");
  auto ethernet = tunnelled;
  ethernet[2] = 0x65;
  ethernet[3] = 0x58;
  rejects([&] { (void)decapsulate(ethernet); }, "a protocol type other than IP");
  auto mismatch = tunnelled;
  mismatch[2] = 0x86;
  mismatch[3] = 0xdd;
  rejects([&] { (void)decapsulate(mismatch); }, "a protocol type that does not match the packet");
  rejects([] { (void)decapsulate(bytes({0, 0, 8})); }, "a short GRE header");
  rejects([] { (void)encapsulate(bytes({0x12, 0x34})); }, "encapsulating something that is not IP");

  if (failures) return 1;
  std::cout << "ipconn tests passed\n";
  return 0;
}
