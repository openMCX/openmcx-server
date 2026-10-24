//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Process runtime of the clients and servers: the configuration, UDP sockets, the control FIFO, the status file
// and JSON events, command-line arguments, and the MCPTT information and asserted identity of SIP messages.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.229, RFC 3325, RFC 3550.
#include "mcx/runtime.hpp"

#include "mcx/banner.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <sys/stat.h>

namespace mcx {
namespace {
//------------------------------------------------------------------------------
// Helper: a configuration field must be a non-empty single-line string of at most 8192 characters.
void required(const Json &config, const char *name) {
  auto value = config.at(name).get<std::string>();
  if (value.empty() || value.size() > 8192 || value.find_first_of("\r\n\0", 0, 3) != value.npos)
    throw std::runtime_error(std::string("invalid configuration field: ") + name);
}
} // namespace

//------------------------------------------------------------------------------
// Helper: loads and checks the configuration (at most 1 MiB): the control and status paths, the SIP settings over
// TLS, the TLS files and, if present, the media ports and AMR-WB mode.
Json load_config(const std::string &path, bool disable_tls) {
  if (std::filesystem::file_size(path) > 1024 * 1024) throw std::runtime_error("configuration exceeds limit");
  std::ifstream file(path);
  Json cfg;
  file >> cfg;
  const char *environment = std::getenv("MCX_LOG");
  set_log_level(parse_log_level(environment && *environment ? environment : cfg.value("log_level", "info")));
  for (auto field : {"control_fifo", "status_file"}) required(cfg, field);
  auto &sip = cfg.at("sip");
  // TS 33.203 (sip.auth "aka"): IPsec instead of TLS on the SIP hop, so no SIP core URI over TLS and no client
  // certificate; the CA file stays, for HTTPS to the common services.
  const bool aka = sip.value("auth", "digest") == "aka";
  for (auto field : {"listen", "advertise", "identity"}) required(sip, field);
  if (!aka) required(sip, "core_uri");
  auto &tls = cfg.at("tls");
  for (auto field : {"ca_file", "cert_file", "key_file"}) {
    if ((disable_tls || aka) && std::string_view(field) != "ca_file") continue;
    required(tls, field);
    if (!std::filesystem::is_regular_file(tls.at(field).get<std::string>()))
      throw std::runtime_error("TLS file unavailable");
  }
  if (!aka && !sip.at("core_uri").get<std::string>().ends_with(";transport=tls"))
    throw std::runtime_error("TLS SIP core URI required");
  unsigned sipport = sip.at("port");
  if (!sipport || sipport > 65535) throw std::runtime_error("invalid SIP port");

  // The MCData server has no RTP media plane in its signalling-plane profile.
  if (!cfg.contains("media")) return cfg;
  auto &media = cfg.at("media");
  unsigned audio = media.at("rtp_port"), floor = media.at("floor_port");
  if (!audio || audio >= 65400 || !floor || floor >= 65400 || floor == audio || floor == audio + 1)
    throw std::runtime_error("invalid media port allocation");
  if (media.value("mode", 0) < 0 || media.value("mode", 0) > 8) throw std::runtime_error("unsupported AMR-WB mode");

  return cfg;
}

//------------------------------------------------------------------------------
// Helper: the SIP stack settings of the configuration; with TLS disabled, the debug port and core URI over TCP.
SipConfig sip_config(const Json &cfg, bool disable_tls) {
  auto &sip = cfg.at("sip");
  auto &tls = cfg.at("tls");
  SipConfig config;
  config.listen_address = sip.at("listen");
  config.advertise_address = sip.at("advertise");
  config.listen_port = sip.at("port");
  config.identity = sip.at("identity");
  config.session_expires = sip.value("session_expires", 1800u);
  // TS 33.203 and TS 24.229 clause 5.1.1.2.2: sip.auth "aka": the ISIM (sip.isim: impi, k, opc, amf, and optionally
  // sqn_file) and the preconfigured P-CSCF (sip.pcscf: address, port); sip.port is the protected server port port_us.
  // The SAs bind IP addresses, so names are resolved here.
  if (sip.value("auth", "digest") == "aka") {
    const auto &isim = sip.at("isim");
    const auto &pcscf = sip.at("pcscf");
    config.tls.enabled = false;
    config.tls.ca_file = tls.at("ca_file");
    config.aka.enabled = true;
    config.aka.impi = isim.at("impi");
    config.aka.k = isim.at("k");
    config.aka.opc = isim.at("opc");
    config.aka.amf = isim.value("amf", "8000");
    config.aka.sqn_file = isim.value("sqn_file", "");
    const auto numeric = [](const std::string &host) {
      unsigned char address[16];
      return inet_pton(host.find(':') != std::string::npos ? AF_INET6 : AF_INET, host.c_str(), address) == 1
                 ? host
                 : resolve_ipv4(host);
    };
    config.aka.pcscf_address = numeric(pcscf.at("address").get<std::string>());
    const unsigned pcscf_port = pcscf.value("port", 5060u), unprotected = sip.value("unprotected_port", 5060u);
    if (!pcscf_port || pcscf_port > 65535 || !unprotected || unprotected > 65535)
      throw std::invalid_argument("invalid P-CSCF or unprotected SIP port");
    config.aka.pcscf_port = static_cast<std::uint16_t>(pcscf_port);
    config.aka.unprotected_port = static_cast<std::uint16_t>(unprotected);
    config.advertise_address = numeric(config.advertise_address);
    return config;
  }
  config.core_uri = sip.at("core_uri");
  config.username = sip.value("username", "");
  config.password = sip.value("password", "");
  config.tls.ca_file = tls.at("ca_file");
  config.tls.enabled = !disable_tls;
  if (disable_tls) {
    unsigned port = sip.value("debug_port", 5060u);
    if (!port || port > 65535) throw std::invalid_argument("invalid debug SIP port");
    config.listen_port = port;
    config.core_uri = sip.contains("debug_core_uri")
                          ? sip.at("debug_core_uri").get<std::string>()
                          : "sip:" + cfg.at("trusted_core").get<std::string>() + ":5060;transport=tcp";
  } else {
    config.tls.cert_file = tls.at("cert_file");
    config.tls.key_file = tls.at("key_file");
  }

  return config;
}

//------------------------------------------------------------------------------
// Helper: the first IPv4 address of a host name.
std::string resolve_ipv4(const std::string &host) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo *found = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &found) != 0) throw std::runtime_error("cannot resolve " + host);
  const std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> result(found, &freeaddrinfo);
  // The first entry with an IPv4 socket address (AF_INET was asked for, but the entry is checked, not assumed).
  for (const auto *entry = result.get(); entry != nullptr; entry = entry->ai_next) {
    if (entry->ai_family != AF_INET || entry->ai_addr == nullptr || entry->ai_addrlen < sizeof(sockaddr_in)) continue;
    char address[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in *>(entry->ai_addr)->sin_addr, address,
                  sizeof(address)) == nullptr)
      continue;
    return address;
  }
  throw std::runtime_error("no IPv4 address for " + host);
}

//------------------------------------------------------------------------------
// Helper: milliseconds of the monotonic clock.
std::uint64_t monotonic_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

//------------------------------------------------------------------------------
// RFC 3550 section 8.1: a random, non-zero SSRC.
std::uint32_t random_ssrc() {
  std::uint32_t ssrc = 0;
  do {
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&ssrc), sizeof(ssrc)) != 1)
      throw std::runtime_error("SSRC random generation failed");
  } while (!ssrc);
  return ssrc;
}

//------------------------------------------------------------------------------
// Helper: the local media description (address, RTP, RTCP and floor control ports shifted by the offset, and random
// SSRCs).
MediaDescription local_media(const Json &cfg, unsigned offset) {
  auto &media = cfg.at("media");
  MediaDescription result;
  result.address = resolve_ipv4(media.at("advertise"));
  result.floor_address = result.address;
  result.audio_port = media.at("rtp_port").get<unsigned>() + offset;
  result.rtcp_port = result.audio_port + 1;
  result.floor_port = media.at("floor_port").get<unsigned>() + offset;
  result.floor_ssrc = random_ssrc();
  result.audio_ssrc = random_ssrc();
  return result;
}

//------------------------------------------------------------------------------
// Helper: a non-blocking UDP socket bound to the address and port.
UdpSocket::UdpSocket(const std::string &address, std::uint16_t port) {
  // The address first: a failure then leaves no socket behind.
  sockaddr_in local{};
  local.sin_family = AF_INET;
  local.sin_port = htons(port);
  const auto ip = resolve_ipv4(address);
  if (inet_pton(AF_INET, ip.c_str(), &local.sin_addr) != 1) throw std::runtime_error("UDP bind: invalid address " + ip);
  fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd_ < 0) throw std::runtime_error("UDP socket failure");
  if (bind(fd_, reinterpret_cast<sockaddr *>(&local), sizeof(local)) < 0) {
    auto reason = std::string(std::strerror(errno));
    close(fd_);
    fd_ = -1;
    throw std::runtime_error("UDP bind: " + reason);
  }
}

//------------------------------------------------------------------------------
// Helper: closes the socket.
UdpSocket::~UdpSocket() {
  if (fd_ >= 0) close(fd_);
}

//------------------------------------------------------------------------------
// Helper: one received datagram, or none when nothing is waiting.
std::optional<Datagram> UdpSocket::receive() {
  Datagram datagram;
  datagram.bytes.resize(65536);
  socklen_t len = sizeof(datagram.source);
  auto received = recvfrom(fd_, datagram.bytes.data(), datagram.bytes.size(), 0,
                           reinterpret_cast<sockaddr *>(&datagram.source), &len);
  if (received < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return {};
    throw std::runtime_error("UDP receive failed");
  }
  datagram.bytes.resize(received);
  return datagram;
}

//------------------------------------------------------------------------------
// Helper: sends a datagram to a numeric IPv4 address and port.
void UdpSocket::send(std::span<const std::uint8_t> data, const std::string &host, std::uint16_t port) {
  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(port);
  if (inet_pton(AF_INET, host.c_str(), &dst.sin_addr) != 1)
    throw std::runtime_error("numeric negotiated IPv4 required");
  if (sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) !=
      static_cast<ssize_t>(data.size()))
    throw std::runtime_error("UDP send failed");
}

//------------------------------------------------------------------------------
// Helper: the bound port, which the system chose when the socket was bound to port 0.
std::uint16_t UdpSocket::port() const {
  sockaddr_in local{};
  socklen_t len = sizeof(local);
  if (getsockname(fd_, reinterpret_cast<sockaddr *>(&local), &len) < 0)
    throw std::runtime_error("UDP getsockname failed");
  return ntohs(local.sin_port);
}

//------------------------------------------------------------------------------
// Helper: whether a source address is the given IPv4 address and port.
bool UdpSocket::matches(const sockaddr_in &source, const std::string &ip, std::uint16_t port) {
  in_addr addr{};
  return inet_pton(AF_INET, ip.c_str(), &addr) == 1 && source.sin_port == htons(port) &&
         source.sin_addr.s_addr == addr.s_addr;
}

//------------------------------------------------------------------------------
// Helper: creates (or reopens a safe, own) control FIFO.
Control::Control(const std::string &fifo) : path_(fifo) {
  std::filesystem::create_directories(std::filesystem::path(fifo).parent_path());
  struct stat st{};
  if (lstat(fifo.c_str(), &st) == 0) {
    if (!S_ISFIFO(st.st_mode) || st.st_uid != getuid()) throw std::runtime_error("unsafe control path");
  } else if (mkfifo(fifo.c_str(), 0600) != 0)
    throw std::runtime_error("control FIFO create failed");
  fd_ = open(fifo.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd_ < 0) throw std::runtime_error("control FIFO open failed");
}

//------------------------------------------------------------------------------
// Helper: closes and removes the control FIFO.
Control::~Control() {
  if (fd_ >= 0) close(fd_);
  unlink(path_.c_str());
}

//------------------------------------------------------------------------------
// Helper: the complete command lines read from the control FIFO (at most 16 KiB buffered).
std::vector<std::string> Control::read() {
  char data[4096];
  auto count = ::read(fd_, data, sizeof(data));
  if (count > 0) buffer_.append(data, count);
  if (buffer_.size() > 16384) {
    buffer_.clear();
    throw std::runtime_error("command too large");
  }
  std::vector<std::string> result;
  size_t pos;
  while ((pos = buffer_.find('\n')) != buffer_.npos) {
    result.push_back(buffer_.substr(0, pos));
    buffer_.erase(0, pos + 1);
  }
  return result;
}

//------------------------------------------------------------------------------
// Helper: replaces the status file atomically with the status JSON.
void write_status(const Json &cfg, const Json &status) {
  auto path = std::filesystem::path(cfg.at("status_file").get<std::string>());
  std::filesystem::create_directories(path.parent_path());
  auto temp = path.string() + ".tmp";
  std::ofstream out(temp);
  out << status.dump(2) << '\n';
  out.close();
  if (!out) throw std::runtime_error("status write failed");
  std::filesystem::rename(temp, path);
}

//------------------------------------------------------------------------------
// Helper: writes one JSON event line to stdout with its kind and monotonic time.
namespace {
std::atomic<LogLevel> process_log_level{LogLevel::info};
} // namespace

void set_log_level(LogLevel level) { process_log_level = level; }

LogLevel log_level() { return process_log_level; }

LogLevel parse_log_level(std::string_view name) {
  if (name == "info") return LogLevel::info;
  if (name == "debug") return LogLevel::debug;
  throw std::runtime_error("invalid log level: " + std::string(name) + " (info or debug)");
}

void debug_line(std::string_view text) {
  const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::tm local{};
  localtime_r(&now, &local);
  char stamp[32];
  std::strftime(stamp, sizeof(stamp), "%Y/%m/%d %H:%M:%S", &local);
  std::string line = std::string(stamp) + " OpenMCX DEBUG [" + log_program() + "] " + std::string(text) + "\n";
  std::cerr << line << std::flush;
}

void event(std::string_view kind, const Json &detail) {
  Json out = detail;
  out["event"] = kind;
  out["monotonic_ms"] = monotonic_ms();
  std::cout << out.dump() << std::endl;
}

//------------------------------------------------------------------------------
// Helper: parses the command line.
Arguments arguments(int argc, char **argv) {
  Arguments parsed;
  for (int index = 1; index < argc; index++) {
    std::string arg = argv[index];
    if (arg == "--config" && index + 1 < argc)
      parsed.config = argv[++index];
    else if (arg == "--command" && index + 1 < argc)
      parsed.command = argv[++index];
    else if (arg == "--disable-tls")
      parsed.disable_tls = true;
    else if (arg == "--status")
      parsed.status = true;
    else if (arg == "--activate" && index + 1 < argc)
      parsed.activate = argv[++index];
    else if (arg == "--password-file" && index + 1 < argc)
      parsed.password_file = argv[++index];
    else if (arg == "--authorization-request")
      parsed.authorization_request = true;
    else
      throw std::invalid_argument("usage: --config FILE [--disable-tls] [--command TEXT | --status] [--activate URL "
                                  "--password-file FILE] [--authorization-request]");
  }
  if (parsed.config.empty()) throw std::invalid_argument("--config required");
  return parsed;
}

//------------------------------------------------------------------------------
// Helper: runs a --status or --command invocation against a running process; false if the invocation is neither.
bool dispatch_control(const Arguments &args, const Json &cfg) {
  if (args.status) {
    std::ifstream file(cfg.at("status_file").get<std::string>());
    if (!file) throw std::runtime_error("status unavailable");
    std::cout << file.rdbuf();
    return true;
  }
  if (!args.command.empty()) {
    if (args.command.size() > 4094 || args.command.find('\n') != args.command.npos)
      throw std::runtime_error("invalid command");
    int fd = open(cfg.at("control_fifo").get<std::string>().c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) throw std::runtime_error("client is not running");
    std::string command = args.command + '\n';
    auto written = write(fd, command.data(), command.size());
    close(fd);
    if (written != static_cast<ssize_t>(command.size())) throw std::runtime_error("control write failed");
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1: the MCPTT information body part (or that of the service) of a SIP message.
std::vector<BodyPart> info_parts(const McpttInfo &info, const ServiceProfile &service) {
  return {{service.info_mime, service_info_xml(info, service)}};
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1: the one MCPTT information body (or that of the service) of a SIP message; throws if it is
// missing or repeated.
McpttInfo message_info(const SipMessage &message, const ServiceProfile &service) {
  std::optional<McpttInfo> result;
  auto parts = message.parts.empty() ? parse_body_parts(message.content_type, message.body) : message.parts;
  for (auto &part : parts)
    if (part.content_type == service.info_mime) {
      if (result) throw std::runtime_error("duplicate MCPTT info");
      result = parse_service_info(part.body, service);
    }
  if (!result) throw std::runtime_error("MCPTT information missing");
  return *result;
}

//------------------------------------------------------------------------------
// Helper: the SIP URI of a P-Asserted-Identity header value (RFC 3325); throws unless it is a single SIP URI with a
// domain.
std::string canonical_identity(std::string_view header) {
  if (header.empty() || header.find_first_of(",\r\n") != header.npos)
    throw std::runtime_error("missing or ambiguous asserted identity");
  if (header.front() == '<' && header.back() == '>') header = header.substr(1, header.size() - 2);
  if (!header.starts_with("sip:") || header.find_first_of(" <>;\t") != header.npos || header.find('@') == header.npos)
    throw std::runtime_error("asserted identity must be a provisioned SIP URI");
  return std::string(header);
}

//------------------------------------------------------------------------------
// TS 24.229 and RFC 3325 section 9.1: the one P-Asserted-Identity of a SIP message, as a SIP URI; throws unless there
// is exactly one.
std::string asserted_identity(const SipMessage &message) {
  unsigned count = 0;
  std::string value;
  for (auto &header : message.headers) {
    std::string name = header.name;
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char character) { return std::tolower(character); });
    if (name == "p-asserted-identity") {
      ++count;
      value = header.value;
    }
  }
  if (count != 1) throw std::runtime_error("exactly one asserted identity required");
  return canonical_identity(value);
}
} // namespace mcx
