//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Process runtime of the clients and servers: the configuration, UDP sockets, the control FIFO, the status file and
// JSON events, command-line arguments, and the MCPTT information and asserted identity of SIP messages.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.229, RFC 3325, RFC 3550.
#pragma once
#include "mcx/banner.hpp"
#include "mcx/sip.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <netinet/in.h>
#include <span>

namespace mcx {
using Json = nlohmann::json;

//------------------------------------------------------------------------------
// Helper: loads and checks the configuration (at most 1 MiB).
Json load_config(const std::string &path, bool disable_tls = false);

//------------------------------------------------------------------------------
// Helper: the SIP stack settings of the configuration; with TLS disabled, the debug port and core URI over TCP.
SipConfig sip_config(const Json &cfg, bool disable_tls = false);

//------------------------------------------------------------------------------
// Helper: the first IPv4 address of a host name.
std::string resolve_ipv4(const std::string &host);

//------------------------------------------------------------------------------
// Helper: milliseconds of the monotonic clock.
std::uint64_t monotonic_ms();

//------------------------------------------------------------------------------
// RFC 3550 section 8.1: a random, non-zero SSRC.
std::uint32_t random_ssrc();

//------------------------------------------------------------------------------
// Helper: the local media description (address, RTP, RTCP and floor control ports shifted by the offset, and random
// SSRCs).
MediaDescription local_media(const Json &cfg, unsigned offset = 0);

//------------------------------------------------------------------------------
// RFC 1112 section 4: whether a numeric IPv4 address is a host group address (class D, 224.0.0.0/4).
bool is_ipv4_multicast(const std::string &address);

//------------------------------------------------------------------------------
// RFC 791 section 3.1: the largest time-to-live.
inline constexpr int max_multicast_ttl = 255;

//------------------------------------------------------------------------------
// Helper: one received UDP datagram and its source address.
struct Datagram {
  std::vector<std::uint8_t> bytes;
  sockaddr_in source{};
};

//------------------------------------------------------------------------------
// Helper: a non-blocking UDP socket bound to an address and port.
class UdpSocket {
public:
  UdpSocket(const std::string &address, std::uint16_t port);
  ~UdpSocket();
  UdpSocket(const UdpSocket &) = delete;
  UdpSocket &operator=(const UdpSocket &) = delete;
  // One received datagram, or none when nothing is waiting.
  std::optional<Datagram> receive();
  // Sends a datagram to a numeric IPv4 address and port.
  void send(std::span<const std::uint8_t> data, const std::string &host, std::uint16_t port);
  // Whether a source address is the given IPv4 address and port.
  static bool matches(const sockaddr_in &source, const std::string &ip, std::uint16_t port);
  // RFC 1112 section 7.1: datagrams sent to a host group leave through the interface with the given IPv4 address
  // ("0.0.0.0": the routing table's choice), with the time-to-live, and are looped back to this host only when asked.
  void multicast_sending(const std::string &interface, int ttl, bool loop = false);
  // RFC 1112 section 7.2: joins the host group on the interface with the given IPv4 address ("0.0.0.0": the routing
  // table's choice); the membership ends when the socket is closed.
  void join(const std::string &group, const std::string &interface);
  // The bound port, which the system chose when the socket was bound to port 0.
  std::uint16_t port() const;

private:
  int fd_ = -1;
};

//------------------------------------------------------------------------------
// Helper: the control FIFO of a process, read as complete command lines.
class Control {
public:
  explicit Control(const std::string &fifo);
  ~Control();
  std::vector<std::string> read();

private:
  int fd_ = -1;
  std::string path_, buffer_;
};

//------------------------------------------------------------------------------
// Helper: replaces the status file atomically with the status JSON.
void write_status(const Json &cfg, const Json &status);

//------------------------------------------------------------------------------
// Helper: writes one JSON event line to stdout with its kind and monotonic time.
void event(std::string_view kind, const Json &detail = Json::object());

//------------------------------------------------------------------------------
// The log level of the process (OpenMCX, no 3GPP specification): "info" (the default) writes the events only;
// "debug" adds a text line on stderr per SIP message sent and received (debug_line), without its body. Set from the configuration's
// "log_level" by load_config(); the environment variable MCX_LOG overrides it.
enum class LogLevel { info, debug };
void set_log_level(LogLevel level);
LogLevel log_level();
// Helper: the level a name stands for ("info" or "debug"); throws for any other name.
LogLevel parse_log_level(std::string_view name);

//------------------------------------------------------------------------------
// Helper: one human-readable debug log line on stderr, "YYYY/MM/DD HH:MM:SS OpenMCX DEBUG [<program>] <text>" in
// local time; stdout stays the JSON event stream.
void debug_line(std::string_view text);

//------------------------------------------------------------------------------
// Helper: the command-line arguments of a process.
struct Arguments {
  std::string config, command;
  // MCX Admin activation (a client): the one-time activation URL, and a file with the account's password, which the
  // user set on IdMS's page.
  std::string activate, password_file;
  // A sign-in in the user's browser (a client): print the authorization request (TS 33.180 annex B.4.2.2) and end.
  bool authorization_request = false;
  bool status = false;
  bool disable_tls = false;
};

//------------------------------------------------------------------------------
// Helper: parses the command line.
Arguments arguments(int argc, char **argv);

//------------------------------------------------------------------------------
// Helper: runs a --status or --command invocation against a running process; false if the invocation is neither.
bool dispatch_control(const Arguments &args, const Json &cfg);

//------------------------------------------------------------------------------
// TS 24.379 annex F.1: the MCPTT information body part (or that of the service) of a SIP message.
std::vector<BodyPart> info_parts(const McpttInfo &info, const ServiceProfile &service = mcptt_service);

//------------------------------------------------------------------------------
// TS 24.379 annex F.1: the one MCPTT information body (or that of the service) of a SIP message; throws if it is
// missing or repeated.
McpttInfo message_info(const SipMessage &message, const ServiceProfile &service = mcptt_service);

//------------------------------------------------------------------------------
// RFC 3325 section 9.1: the SIP URI of a P-Asserted-Identity header value; throws unless it is a single SIP URI with a
// domain.
std::string canonical_identity(std::string_view header);

//------------------------------------------------------------------------------
// TS 24.229 and RFC 3325 section 9.1: the one P-Asserted-Identity of a SIP message, as a SIP URI; throws unless there
// is exactly one.
std::string asserted_identity(const SipMessage &message);
} // namespace mcx
