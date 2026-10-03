// MCData IP connectivity and its media plane: a GRE-in-UDP tunnel (RFC 8086 over RFC 2784) negotiated with an
// "m=application <port> udp MCDATA" SDP section (TS 24.282 clause 20, TS 24.582 clause 13), and a minimal IPv4/ICMP
// endpoint.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), RFC 8086, RFC 2784, RFC 1071, RFC 791,
// RFC 792.
#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcx::ipconn {

//------------------------------------------------------------------------------
// TS 24.582 clauses 13.5.2.1 and 13.6.2: the tunnel end of one party. The fmtp "mcdata-ipconn-s-port" names the UDP
// source port the tunnel is sent from.
struct TunnelMedia {
  std::string address;
  std::uint16_t port = 0;
  std::optional<std::uint16_t> source_port;
};

//------------------------------------------------------------------------------
// TS 24.582 clause 13.5.2.1 (table 13.5.2.1-1) and clause 13.6.2.3, used by TS 24.282 clauses 20.2.0a and 20.2.0b:
// the SDP of the tunnel end, an "m=application <port> udp MCDATA" section.
std::string tunnel_sdp(const TunnelMedia &media, std::uint64_t session_id);

//------------------------------------------------------------------------------
// TS 24.582 clauses 13.5.2.1 and 13.6.2.3: reads the first "m=application ... udp MCDATA" section; throws if there is
// none.
TunnelMedia parse_tunnel_sdp(std::string_view sdp);

//------------------------------------------------------------------------------
// RFC 2784: the GRE protocol type of an encapsulated IPv4 packet.
inline constexpr std::uint16_t ipv4 = 0x0800;
//------------------------------------------------------------------------------
// RFC 2784: the GRE protocol type of an encapsulated IPv6 packet.
inline constexpr std::uint16_t ipv6 = 0x86dd;

//------------------------------------------------------------------------------
// TS 24.582 clause 13.4: a GRE header (RFC 2784) without key (item 3) and without checksum in front of an IP packet;
// the UDP checksum (item 1) is left to the socket.
std::vector<std::uint8_t> encapsulate(std::span<const std::uint8_t> ip_packet);

//------------------------------------------------------------------------------
// TS 24.582 clause 13.4: an IP packet taken out of the tunnel, with its GRE protocol type.
struct Decapsulated {
  std::uint16_t protocol = 0;
  std::vector<std::uint8_t> packet;
};

//------------------------------------------------------------------------------
// TS 24.582 clause 13.4 and RFC 2784: removes the GRE header. Rejects a GRE version other than 0, a key or sequence
// number, reserved bits, a protocol other than IPv4 or IPv6, and a checksum (C bit) that does not verify.
Decapsulated decapsulate(std::span<const std::uint8_t> datagram);

//------------------------------------------------------------------------------
// RFC 1071: the Internet checksum.
std::uint16_t internet_checksum(std::span<const std::uint8_t> bytes);

//------------------------------------------------------------------------------
// RFC 791 section 3.1: a packet of a minimal IPv4 endpoint, the IP application of TS 24.582 clause 13.1.1 that these
// clients run themselves. It builds and reads ICMP echo (RFC 792).
struct Ipv4Packet {
  std::string source, destination;
  std::uint8_t protocol = 0, ttl = 64;
  std::uint16_t identification = 0;
  std::vector<std::uint8_t> payload;
};

//------------------------------------------------------------------------------
// RFC 791 section 3.1: encodes an unfragmented IPv4 packet with its header checksum.
std::vector<std::uint8_t> encode_ipv4(const Ipv4Packet &packet);

//------------------------------------------------------------------------------
// RFC 791 section 3.1: decodes an IPv4 packet; verifies the version, header length, total length and header checksum.
Ipv4Packet decode_ipv4(std::span<const std::uint8_t> bytes);

//------------------------------------------------------------------------------
// RFC 792: an ICMP Echo or Echo Reply message.
struct IcmpEcho {
  bool reply = false;
  std::uint16_t identifier = 0, sequence = 0;
  std::vector<std::uint8_t> data;
};

//------------------------------------------------------------------------------
// RFC 792: encodes an ICMP Echo or Echo Reply message with its checksum.
std::vector<std::uint8_t> encode_icmp_echo(const IcmpEcho &echo);

//------------------------------------------------------------------------------
// RFC 792: verifies the checksum; throws for any ICMP message other than echo and echo reply.
IcmpEcho decode_icmp_echo(std::span<const std::uint8_t> bytes);

} // namespace mcx::ipconn
