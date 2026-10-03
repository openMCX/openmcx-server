// MCData IP connectivity: the SDP of the GRE-in-UDP tunnel, GRE encapsulation and a minimal IPv4/ICMP endpoint.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), RFC 8086, RFC 2784, RFC 1071, RFC 791,
// RFC 792.
#include "mcx/ipconn.hpp"

#include <arpa/inet.h>
#include <charconv>
#include <sstream>
#include <stdexcept>

namespace mcx::ipconn {
namespace {

//------------------------------------------------------------------------------
// Helper: throws the error of a malformed or unsupported IP connectivity input.
[[noreturn]] void invalid(const char *reason) { throw std::runtime_error(std::string("IP connectivity: ") + reason); }

constexpr std::size_t max_sdp = 16 * 1024;

//------------------------------------------------------------------------------
// Helper: splits text at a separator, dropping a trailing CR and empty pieces.
std::vector<std::string_view> split(std::string_view text, char separator) {
  std::vector<std::string_view> out;
  std::size_t start = 0;
  while (start <= text.size()) {
    auto end = text.find(separator, start);
    if (end == std::string_view::npos) end = text.size();
    auto piece = text.substr(start, end - start);
    if (!piece.empty() && piece.back() == '\r') piece.remove_suffix(1);
    if (!piece.empty()) out.push_back(piece);
    start = end + 1;
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: parses a UDP port number (1 to 65535).
std::uint16_t port_number(std::string_view text) {
  unsigned value = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || end != text.data() + text.size() || value == 0 || value > 65535) invalid("invalid port");
  return static_cast<std::uint16_t>(value);
}

//------------------------------------------------------------------------------
// Helper: parses a dotted IPv4 address into its host-order value.
std::uint32_t address_value(const std::string &text) {
  in_addr address{};
  if (inet_pton(AF_INET, text.c_str(), &address) != 1) invalid("an IPv4 address is required");
  return ntohl(address.s_addr);
}

//------------------------------------------------------------------------------
// Helper: formats a host-order IPv4 address as dotted text.
std::string address_text(std::uint32_t value) {
  in_addr address{htonl(value)};
  char text[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &address, text, sizeof(text));
  return text;
}

//------------------------------------------------------------------------------
// Helper: appends a 16-bit value in network byte order.
void put16(std::vector<std::uint8_t> &out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value));
}

//------------------------------------------------------------------------------
// Helper: appends a 32-bit value in network byte order.
void put32(std::vector<std::uint8_t> &out, std::uint32_t value) {
  put16(out, static_cast<std::uint16_t>(value >> 16));
  put16(out, static_cast<std::uint16_t>(value));
}

//------------------------------------------------------------------------------
// Helper: reads a 16-bit network-order value at an offset.
std::uint16_t get16(std::span<const std::uint8_t> in, std::size_t at) {
  return static_cast<std::uint16_t>(in[at] << 8 | in[at + 1]);
}

//------------------------------------------------------------------------------
// Helper: reads a 32-bit network-order value at an offset.
std::uint32_t get32(std::span<const std::uint8_t> in, std::size_t at) {
  return static_cast<std::uint32_t>(get16(in, at)) << 16 | get16(in, at + 2);
}

} // namespace

//------------------------------------------------------------------------------
// TS 24.582 clause 13.5.2.1 (table 13.5.2.1-1) and clause 13.6.2.3 (table 13.6.2.3-1), used by TS 24.282
// clauses 20.2.0a and 20.2.0b: builds the SDP of the tunnel end, an "m=application <port> udp MCDATA" section with
// the optional "mcdata-ipconn-s-port" fmtp parameter.
std::string tunnel_sdp(const TunnelMedia &media, std::uint64_t session_id) {
  (void)address_value(media.address);
  if (!media.port) invalid("the tunnel needs a UDP port");
  std::ostringstream out;
  // TS 24.582 clause 13.5.2.1 (table 13.5.2.1-1) and clause 13.6.2.3.
  out << "v=0\r\no=- " << session_id << " 1 IN IP4 " << media.address << "\r\ns=MCData\r\nc=IN IP4 " << media.address
      << "\r\nt=0 0\r\nm=application " << media.port << " udp MCDATA\r\n";
  if (media.source_port) out << "a=fmtp:MCDATA mcdata-ipconn-s-port=" << *media.source_port << "\r\n";
  return out.str();
}

//------------------------------------------------------------------------------
// TS 24.582 clauses 13.5.2.1 and 13.6.2.3: reads the first "m=application ... udp MCDATA" section of the peer's
// SDP (its address, port and "mcdata-ipconn-s-port"); throws if there is none.
TunnelMedia parse_tunnel_sdp(std::string_view sdp) {
  if (sdp.size() > max_sdp) invalid("SDP too large");
  TunnelMedia out;
  std::string session_address;
  bool tunnel = false, found = false, version = false, media = false;
  for (const auto line : split(sdp, '\n')) {
    if (line.size() < 2 || line[1] != '=') invalid("malformed SDP line");
    const auto value = line.substr(2);
    if (line[0] == 'v') {
      if (value != "0") invalid("unsupported SDP version");
      version = true;
    } else if (line[0] == 'c') {
      const auto parts = split(value, ' ');
      if (parts.size() != 3 || parts[0] != "IN" || parts[1] != "IP4") invalid("unsupported SDP connection");
      const std::string address(parts[2]);
      (void)address_value(address);
      if (tunnel)
        out.address = address; // a media-level connection wins
      else if (!media)
        session_address = address;
    } else if (line[0] == 'm') {
      const auto parts = split(value, ' ');
      media = true;
      tunnel = !found && parts.size() == 4 && parts[0] == "application" && parts[2] == "udp" && parts[3] == "MCDATA";
      if (tunnel) {
        out.port = port_number(parts[1]);
        found = true;
      }
    } else if (line[0] == 'a' && tunnel && value.starts_with("fmtp:MCDATA ")) {
      // "a=fmtp:MCDATA mcdata-ipconn-s-port=<port>"; the example of TS 24.582 clause 13.5.2.1 also
      // shows a bare "mcdata-ipconn", which names no port.
      for (const auto parameter : split(value.substr(12), ';')) {
        auto trimmed = parameter;
        while (!trimmed.empty() && trimmed.front() == ' ') trimmed.remove_prefix(1);
        if (trimmed.starts_with("mcdata-ipconn-s-port=")) out.source_port = port_number(trimmed.substr(21));
      }
    }
  }
  if (!version) invalid("SDP without version");
  if (!found) invalid("no IP connectivity media section");
  if (out.address.empty()) out.address = session_address;
  if (out.address.empty()) invalid("no connection address for the tunnel");
  return out;
}

//------------------------------------------------------------------------------
// RFC 1071: the Internet checksum (one's complement of the one's complement sum of 16-bit words).
std::uint16_t internet_checksum(std::span<const std::uint8_t> bytes) {
  std::uint32_t sum = 0;
  for (std::size_t index = 0; index + 1 < bytes.size(); index += 2) sum += get16(bytes, index);
  if (bytes.size() % 2) sum += static_cast<std::uint32_t>(bytes.back()) << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<std::uint16_t>(~sum);
}

//------------------------------------------------------------------------------
// TS 24.582 clause 13.4: puts a GRE header (RFC 2784) without key (item 3) and without checksum in front of an IP
// packet; the UDP checksum (item 1) is left to the socket.
std::vector<std::uint8_t> encapsulate(std::span<const std::uint8_t> ip_packet) {
  if (ip_packet.empty()) invalid("empty IP packet");
  const auto version = ip_packet[0] >> 4;
  if (version != 4 && version != 6) invalid("not an IP packet");
  std::vector<std::uint8_t> out;
  out.reserve(4 + ip_packet.size());
  put16(out, 0); // C=0, no key or sequence number, version 0 (RFC 2784 section 2.1)
  put16(out, version == 4 ? ipv4 : ipv6);
  out.insert(out.end(), ip_packet.begin(), ip_packet.end());
  return out;
}

//------------------------------------------------------------------------------
// TS 24.582 clause 13.4 and RFC 2784: removes the GRE header; rejects a GRE version other than 0, a key or sequence
// number, reserved bits, a protocol other than IPv4 or IPv6, and a checksum (C bit) that does not verify.
Decapsulated decapsulate(std::span<const std::uint8_t> datagram) {
  if (datagram.size() < 4) invalid("short GRE header");
  const auto flags = get16(datagram, 0);
  const bool checksum = flags & 0x8000;
  if (flags & 0x0007) invalid("unsupported GRE version");
  if (flags & 0x2000) invalid("a GRE key is not used (TS 24.582 13.4)");
  if (flags & 0x7ff8) invalid("reserved GRE bits set");
  Decapsulated out;
  out.protocol = get16(datagram, 2);
  if (out.protocol != ipv4 && out.protocol != ipv6) invalid("unsupported GRE protocol type");
  std::size_t header = 4;
  if (checksum) {
    if (datagram.size() < 8) invalid("short GRE checksum field");
    if (internet_checksum(datagram) != 0) invalid("GRE checksum mismatch");
    header = 8;
  }
  out.packet.assign(datagram.begin() + static_cast<std::ptrdiff_t>(header), datagram.end());
  if (out.packet.empty() || (out.packet[0] >> 4) != (out.protocol == ipv4 ? 4 : 6))
    invalid("GRE protocol type does not match the packet");
  return out;
}

//------------------------------------------------------------------------------
// RFC 791 section 3.1: encodes an unfragmented IPv4 packet with a 20-byte header and its header checksum, for the
// IP application of TS 24.582 clause 13.1.1 that these clients run themselves.
std::vector<std::uint8_t> encode_ipv4(const Ipv4Packet &packet) {
  const auto length = 20 + packet.payload.size();
  if (length > 65535) invalid("IPv4 packet too large");
  std::vector<std::uint8_t> out;
  out.reserve(length);
  out.push_back(0x45); // version 4, IHL 5
  out.push_back(0);
  put16(out, static_cast<std::uint16_t>(length));
  put16(out, packet.identification);
  put16(out, 0x4000); // don't fragment
  out.push_back(packet.ttl);
  out.push_back(packet.protocol);
  put16(out, 0);
  put32(out, address_value(packet.source));
  put32(out, address_value(packet.destination));
  const auto sum = internet_checksum(std::span(out).first(20));
  out[10] = static_cast<std::uint8_t>(sum >> 8);
  out[11] = static_cast<std::uint8_t>(sum);
  out.insert(out.end(), packet.payload.begin(), packet.payload.end());
  return out;
}

//------------------------------------------------------------------------------
// RFC 791 section 3.1: decodes an IPv4 packet; verifies the version, header length, total length and header
// checksum, and rejects fragments.
Ipv4Packet decode_ipv4(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < 20) invalid("short IPv4 header");
  if ((bytes[0] >> 4) != 4) invalid("not IPv4");
  const std::size_t header = (bytes[0] & 0x0f) * 4u;
  if (header < 20 || bytes.size() < header) invalid("invalid IPv4 header length");
  const auto total = get16(bytes, 2);
  if (total < header || total > bytes.size()) invalid("invalid IPv4 total length");
  if (internet_checksum(bytes.first(header)) != 0) invalid("IPv4 header checksum mismatch");
  if (get16(bytes, 6) & 0x3fff) invalid("IPv4 fragments are not reassembled");
  Ipv4Packet out;
  out.identification = get16(bytes, 4);
  out.ttl = bytes[8];
  out.protocol = bytes[9];
  out.source = address_text(get32(bytes, 12));
  out.destination = address_text(get32(bytes, 16));
  out.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(header), bytes.begin() + total);
  return out;
}

//------------------------------------------------------------------------------
// RFC 792: encodes an ICMP Echo (type 8) or Echo Reply (type 0) message with its checksum.
std::vector<std::uint8_t> encode_icmp_echo(const IcmpEcho &echo) {
  std::vector<std::uint8_t> out;
  out.push_back(echo.reply ? 0 : 8);
  out.push_back(0);
  put16(out, 0);
  put16(out, echo.identifier);
  put16(out, echo.sequence);
  out.insert(out.end(), echo.data.begin(), echo.data.end());
  const auto sum = internet_checksum(out);
  out[2] = static_cast<std::uint8_t>(sum >> 8);
  out[3] = static_cast<std::uint8_t>(sum);
  return out;
}

//------------------------------------------------------------------------------
// RFC 792: decodes an ICMP Echo or Echo Reply message and verifies its checksum.
IcmpEcho decode_icmp_echo(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < 8) invalid("short ICMP message");
  if ((bytes[0] != 0 && bytes[0] != 8) || bytes[1] != 0) invalid("not an ICMP echo");
  if (internet_checksum(bytes) != 0) invalid("ICMP checksum mismatch");
  IcmpEcho out;
  out.reply = bytes[0] == 0;
  out.identifier = get16(bytes, 4);
  out.sequence = get16(bytes, 6);
  out.data.assign(bytes.begin() + 8, bytes.end());
  return out;
}

} // namespace mcx::ipconn
