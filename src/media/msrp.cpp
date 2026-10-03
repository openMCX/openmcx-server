// MSRP endpoint for the MCData media plane: message framing and chunking, MSRP URIs, multipart bodies, and
// one TCP or TLS connection bound with an empty SEND.
//
// Specifications: TS 24.582 V19.0.0 (Rel-19), RFC 4975, RFC 6135, RFC 2046.

#include "mcx/msrp.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <ctime>
#include <deque>
#include <memory>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <set>
#include <stdexcept>
#include <sys/socket.h>

namespace mcx::msrp {
namespace {

//------------------------------------------------------------------------------
// Helper: refuses a malformed MSRP message or URI.
[[noreturn]] void invalid(const char *reason) { throw std::runtime_error(std::string("MSRP: ") + reason); }

constexpr std::size_t max_message = 8 * 1024 * 1024; // refuse anything larger than a lab file
constexpr std::size_t chunk_size = 2048;             // RFC 4975 section 5.1 leaves this to the sender

//------------------------------------------------------------------------------
// Helper: the media plane connects by address, as the SDP carries one; a host name in a
// lab configuration is resolved once here so that msrp.cpp keeps no runtime
// dependency (mcx::resolve_ipv4 lives in the runtime library).
std::string resolve(const std::string &host) {
  in_addr parsed{};
  if (inet_pton(AF_INET, host.c_str(), &parsed) == 1) return host;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *found = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &found) != 0 || !found)
    throw std::runtime_error("MSRP: cannot resolve " + host);
  char text[INET_ADDRSTRLEN]{};
  const auto *address = reinterpret_cast<sockaddr_in *>(found->ai_addr);
  inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text));
  freeaddrinfo(found);
  return text;
}

//------------------------------------------------------------------------------
// Helper: the text without leading blanks and trailing blanks and CR.
std::string_view trim(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
  while (!text.empty() && (text.back() == '\r' || text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
  return text;
}

//------------------------------------------------------------------------------
// Helper: the non-empty lines of a header block.
std::vector<std::string_view> lines(std::string_view text) {
  std::vector<std::string_view> out;
  while (!text.empty()) {
    const auto end = text.find('\n');
    auto line = text.substr(0, end);
    if (!trim(line).empty()) out.push_back(line);
    if (end == std::string_view::npos) break;
    text.remove_prefix(end + 1);
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: case-insensitive ASCII comparison, for header field names.
bool ascii_equal(std::string_view left, std::string_view right) {
  if (left.size() != right.size()) return false;
  for (std::size_t index = 0; index < left.size(); ++index)
    if (std::tolower(static_cast<unsigned char>(left[index])) != std::tolower(static_cast<unsigned char>(right[index])))
      return false;
  return true;
}

//------------------------------------------------------------------------------
// RFC 4975 section 9: a To-Path or From-Path header field value, MSRP URIs separated by spaces.
std::vector<Uri> parse_path(std::string_view value) {
  std::vector<Uri> out;
  while (!value.empty()) {
    const auto space = value.find(' ');
    out.push_back(parse_uri(trim(value.substr(0, space))));
    if (space == std::string_view::npos) break;
    value.remove_prefix(space + 1);
  }
  if (out.empty()) invalid("empty path header field");
  return out;
}

//------------------------------------------------------------------------------
// RFC 4975 section 9: writes a To-Path or From-Path header field value.
std::string path_text(const std::vector<Uri> &path) {
  std::string out;
  for (const auto &uri : path) {
    if (!out.empty()) out += ' ';
    out += uri.text();
  }
  return out;
}

//------------------------------------------------------------------------------
// RFC 4975 section 9: a decimal number of a Byte-Range (or a port or status code); "*" (unknown) is empty.
// Values beyond the accepted message size are refused.
std::optional<std::uint64_t> number(std::string_view text) {
  if (text == "*") return std::nullopt;
  std::uint64_t value = 0;
  if (text.empty()) invalid("empty Byte-Range field");
  for (const char digit : text) {
    if (!std::isdigit(static_cast<unsigned char>(digit))) invalid("invalid Byte-Range field");
    value = value * 10 + static_cast<std::uint64_t>(digit - '0');
    if (value > max_message) invalid("Byte-Range beyond the accepted size");
  }
  return value;
}

} // namespace

//------------------------------------------------------------------------------
// RFC 4975 section 6: writes the MSRP URI "msrp[s]://host[:port]/session;transport".
std::string Uri::text() const {
  std::string out = (secure ? "msrps://" : "msrp://") + host;
  if (port) out += ":" + std::to_string(port);
  if (!session.empty()) out += "/" + session;
  return out + ";" + transport;
}

//------------------------------------------------------------------------------
// RFC 4975 section 6: parses an msrp or msrps URI (host, optional port and session, transport).
Uri parse_uri(std::string_view text) {
  Uri uri;
  if (text.starts_with("msrps://")) {
    uri.secure = true;
    text.remove_prefix(8);
  } else if (text.starts_with("msrp://")) {
    text.remove_prefix(7);
  } else {
    invalid("unsupported MSRP URI scheme");
  }
  const auto semicolon = text.rfind(';');
  if (semicolon == std::string_view::npos) invalid("MSRP URI without a transport");
  uri.transport = std::string(text.substr(semicolon + 1));
  if (uri.transport.empty()) invalid("MSRP URI without a transport");
  text = text.substr(0, semicolon);
  const auto slash = text.find('/');
  if (slash != std::string_view::npos) {
    uri.session = std::string(text.substr(slash + 1));
    text = text.substr(0, slash);
  }
  const auto colon = text.rfind(':');
  if (colon != std::string_view::npos) {
    const auto port = number(text.substr(colon + 1));
    if (!port || *port > 65535) invalid("invalid MSRP URI port");
    uri.port = static_cast<std::uint16_t>(*port);
    text = text.substr(0, colon);
  }
  uri.host = std::string(text);
  if (uri.host.empty()) invalid("MSRP URI without a host");
  return uri;
}

//------------------------------------------------------------------------------
// TS 24.582 clause 6.4.1: the bodies of a multipart/mixed body (RFC 2046 section 5.1.1) by content type, or
// the single body under its own content type.
std::map<std::string, std::string> Message::parts() const {
  std::map<std::string, std::string> out;
  const auto at = content_type.find("boundary=");
  if (content_type.rfind("multipart/", 0) != 0 || at == std::string::npos) {
    if (!content_type.empty()) out[content_type] = body;
    return out;
  }
  auto boundary = content_type.substr(at + 9);
  if (!boundary.empty() && boundary.front() == '"') boundary = boundary.substr(1, boundary.find('"', 1) - 1);
  const std::string marker = "--" + boundary;
  std::size_t position = body.find(marker);
  while (position != std::string::npos) {
    position += marker.size();
    if (body.compare(position, 2, "--") == 0) break;
    const auto head = body.find("\r\n\r\n", position);
    if (head == std::string::npos) break;
    const auto next = body.find(marker, head);
    if (next == std::string::npos) break;
    std::string type;
    for (const auto line : lines(std::string_view(body).substr(position, head - position))) {
      const auto colon = line.find(':');
      if (colon != std::string_view::npos && ascii_equal(trim(line.substr(0, colon)), "content-type"))
        type = std::string(trim(line.substr(colon + 1)));
    }
    // The CRLF before the next boundary belongs to the framing, not the body.
    const auto end = next >= 2 ? next - 2 : next;
    if (!type.empty()) out[type] = body.substr(head + 4, end - head - 4);
    position = next;
  }
  return out;
}

//------------------------------------------------------------------------------
// RFC 4975 section 9: encodes a request or response: start line, To-Path, From-Path, the optional header fields,
// the body and the end-line with its continuation flag ('$' complete, '+' more chunks, '#' aborted).
std::string encode(const Message &message) {
  if (message.transaction.empty()) invalid("a message needs a transaction identifier");
  std::string out = "MSRP " + message.transaction + ' ';
  out += message.method.empty()
             ? std::to_string(message.status) + (message.comment.empty() ? "" : " " + message.comment)
             : message.method;
  out += "\r\nTo-Path: " + path_text(message.to_path) + "\r\nFrom-Path: " + path_text(message.from_path) + "\r\n";
  if (!message.message_id.empty()) out += "Message-ID: " + message.message_id + "\r\n";
  if (message.range_start)
    out += "Byte-Range: " + std::to_string(*message.range_start) + "-" +
           (message.range_end ? std::to_string(*message.range_end) : "*") + "/" +
           (message.total ? std::to_string(*message.total) : "*") + "\r\n";
  if (!message.success_report.empty()) out += "Success-Report: " + message.success_report + "\r\n";
  if (!message.failure_report.empty()) out += "Failure-Report: " + message.failure_report + "\r\n";
  if (!message.body.empty()) {
    if (message.content_type.empty()) invalid("a body needs a content type");
    out += "Content-Type: " + message.content_type + "\r\n\r\n" + message.body + "\r\n";
  }
  out += "-------" + message.transaction + (message.aborted ? '#' : message.complete ? '$' : '+');
  return out + "\r\n";
}

//------------------------------------------------------------------------------
// RFC 4975 section 9: decodes one complete message at the front of the buffer and returns the bytes it used, or
// 0 when the end-line has not arrived yet; only SEND and REPORT requests and responses are accepted.
std::size_t decode(std::string_view buffer, Message &out) {
  const auto start = buffer.find("\r\n");
  if (start == std::string_view::npos) return 0;
  auto first = buffer.substr(0, start);
  if (!first.starts_with("MSRP ")) invalid("not an MSRP message");
  first.remove_prefix(5);
  const auto space = first.find(' ');
  if (space == std::string_view::npos) invalid("malformed start line");
  Message message;
  message.transaction = std::string(first.substr(0, space));
  if (message.transaction.empty() || message.transaction.size() > 32) invalid("invalid transaction identifier");
  auto rest = first.substr(space + 1);
  if (!rest.empty() && std::isdigit(static_cast<unsigned char>(rest.front()))) {
    const auto comment = rest.find(' ');
    const auto code = number(rest.substr(0, comment));
    if (!code || *code < 100 || *code > 699) invalid("invalid status code");
    message.status = static_cast<unsigned>(*code);
    if (comment != std::string_view::npos) message.comment = std::string(rest.substr(comment + 1));
  } else {
    message.method = std::string(rest);
    if (message.method != "SEND" && message.method != "REPORT") invalid("unsupported MSRP method");
  }
  // The end-line closes the message; its position also bounds the body.
  const std::string end_line = "\r\n-------" + message.transaction;
  const auto end = buffer.find(end_line, start);
  if (end == std::string_view::npos) {
    if (buffer.size() > max_message) invalid("message exceeds the accepted size");
    return 0;
  }
  const auto flag = end + end_line.size();
  if (buffer.size() < flag + 1) return 0;
  const char continuation = buffer[flag];
  if (continuation != '$' && continuation != '+' && continuation != '#') invalid("invalid continuation flag");
  message.complete = continuation == '$';
  message.aborted = continuation == '#';
  auto head = buffer.substr(start + 2, end - start - 2);
  const auto blank = head.find("\r\n\r\n");
  std::string_view headers = blank == std::string_view::npos ? head : head.substr(0, blank + 2);
  if (blank != std::string_view::npos) message.body = std::string(head.substr(blank + 4));
  for (const auto line : lines(headers)) {
    const auto colon = line.find(':');
    if (colon == std::string_view::npos) continue;
    const auto name = trim(line.substr(0, colon));
    const auto value = trim(line.substr(colon + 1));
    if (ascii_equal(name, "to-path"))
      message.to_path = parse_path(value);
    else if (ascii_equal(name, "from-path"))
      message.from_path = parse_path(value);
    else if (ascii_equal(name, "message-id"))
      message.message_id = std::string(value);
    else if (ascii_equal(name, "content-type"))
      message.content_type = std::string(value);
    else if (ascii_equal(name, "success-report"))
      message.success_report = std::string(value);
    else if (ascii_equal(name, "failure-report"))
      message.failure_report = std::string(value);
    else if (ascii_equal(name, "byte-range")) {
      const auto hyphen = value.find('-'), slash = value.find('/');
      if (hyphen == std::string_view::npos || slash == std::string_view::npos || slash < hyphen)
        invalid("malformed Byte-Range");
      message.range_start = number(value.substr(0, hyphen));
      message.range_end = number(value.substr(hyphen + 1, slash - hyphen - 1));
      message.total = number(value.substr(slash + 1));
    }
  }
  if (message.to_path.empty() || message.from_path.empty()) invalid("a message needs To-Path and From-Path");
  out = std::move(message);
  // The end-line is followed by CRLF when more data may follow on the connection.
  auto used = flag + 1;
  if (buffer.size() >= used + 2 && buffer.compare(used, 2, "\r\n") == 0) used += 2;
  return used;
}

//------------------------------------------------------------------------------
// RFC 4975 section 9: a random ident of 12 lower-case letters and digits (transaction, message and session identifiers).
std::string random_ident() {
  unsigned char bytes[12];
  if (RAND_bytes(bytes, sizeof(bytes)) != 1) throw std::runtime_error("MSRP identifier generation failed");
  static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  std::string out;
  for (const auto byte : bytes) out += alphabet[byte % (sizeof(alphabet) - 1)];
  return out;
}

namespace {
//------------------------------------------------------------------------------
// Helper: runs an OpenSSL call that may write on the socket with SIGPIPE blocked in this thread, and discards the
// SIGPIPE it raised. OpenSSL writes with write(), not send(MSG_NOSIGNAL): a peer that has closed its end would
// otherwise stop the process instead of failing the call with EPIPE. The signal disposition of the process is left
// alone.
template <typename Call> auto without_sigpipe(Call &&call) {
  sigset_t pipe_signal{};
  sigemptyset(&pipe_signal);
  sigaddset(&pipe_signal, SIGPIPE);
  sigset_t pending{};
  sigpending(&pending);
  const bool already_pending = sigismember(&pending, SIGPIPE) == 1;
  sigset_t previous{};
  pthread_sigmask(SIG_BLOCK, &pipe_signal, &previous);
  const auto result = call();
  const int saved_errno = errno;
  if (!already_pending) {
    sigpending(&pending);
    if (sigismember(&pending, SIGPIPE) == 1) {
      const timespec no_wait{};
      (void)sigtimedwait(&pipe_signal, nullptr, &no_wait);
    }
  }
  pthread_sigmask(SIG_SETMASK, &previous, nullptr);
  errno = saved_errno;
  return result;
}
} // namespace

//------------------------------------------------------------------------------
// The state of one MSRP endpoint: listener, connection, TLS session (RFC 4975 section 14), buffers, and the
// reassembly of chunked messages (RFC 4975 section 5.1).
struct Endpoint::State {
  int listener = -1, connection = -1;
  // TLS (RFC 4975 section 14): the context, the connection's session, and whether
  // its handshake has completed. Nothing is written or read before it has.
  SSL_CTX *tls = nullptr;
  SSL *session = nullptr;
  bool handshaken = false;
  std::string expected_name;

  void configure(const TlsConfig &config) {
    tls = SSL_CTX_new(TLS_method());
    if (!tls || SSL_CTX_set_min_proto_version(tls, TLS1_2_VERSION) != 1 ||
        SSL_CTX_use_certificate_chain_file(tls, config.cert_file.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(tls, config.key_file.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(tls) != 1 || SSL_CTX_load_verify_locations(tls, config.ca_file.c_str(), nullptr) != 1)
      throw std::runtime_error("MSRP TLS configuration failed");
    SSL_CTX_set_verify(tls, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    expected_name = config.expected_name;
  }

  void start_tls(bool server) {
    session = SSL_new(tls);
    if (!session || SSL_set_fd(session, connection) != 1) throw std::runtime_error("MSRP TLS session failed");
    if (server)
      SSL_set_accept_state(session);
    else {
      if (expected_name.empty()) throw std::runtime_error("MSRP TLS needs the peer's expected name");
      SSL_set_tlsext_host_name(session, expected_name.c_str());
      if (SSL_set1_host(session, expected_name.c_str()) != 1) throw std::runtime_error("MSRP TLS host check failed");
      SSL_set_connect_state(session);
    }
  }

  // Drives the handshake; true once it has completed.
  bool handshake() {
    if (!session || handshaken) return true;
    const auto result = without_sigpipe([&] { return SSL_do_handshake(session); });
    if (result == 1) {
      handshaken = true;
      return true;
    }
    const auto error = SSL_get_error(session, result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return false;
    char reason[256] = {};
    ERR_error_string_n(ERR_get_error(), reason, sizeof(reason));
    fail(std::string("MSRP TLS handshake failed: ") + reason);
    return false;
  }

  Uri local, peer;
  Callbacks callbacks;
  std::string incoming, outgoing;
  // Reassembly of a chunked message (RFC 4975 section 5.1), by Message-ID.
  std::map<std::string, Message> partial;
  std::set<std::string> outstanding; // SENDs of ours that are not answered yet

  ~State() {
    shutdown();
    if (tls) SSL_CTX_free(tls);
  }

  void shutdown() {
    if (session) {
      SSL_free(session);
      session = nullptr;
    }
    handshaken = false;
    if (connection >= 0) ::close(connection);
    if (listener >= 0) ::close(listener);
    connection = listener = -1;
  }

  void fail(const std::string &reason) {
    shutdown();
    if (callbacks.failure) callbacks.failure(reason);
  }

  void queue(const Message &message) { outgoing += encode(message); }

  void flush() {
    if (session && !handshake()) return;
    while (connection >= 0 && !outgoing.empty()) {
      if (session) {
        const auto sent =
            without_sigpipe([&] { return SSL_write(session, outgoing.data(), static_cast<int>(outgoing.size())); });
        if (sent > 0) {
          outgoing.erase(0, static_cast<std::size_t>(sent));
          continue;
        }
        const auto error = SSL_get_error(session, sent);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return;
        fail("MSRP TLS connection lost while sending");
        return;
      }
      const auto sent = ::send(connection, outgoing.data(), outgoing.size(), MSG_NOSIGNAL);
      if (sent > 0) {
        outgoing.erase(0, static_cast<std::size_t>(sent));
        continue;
      }
      if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
      fail("MSRP connection lost while sending");
      return;
    }
  }

  void deliver(Message &message) {
    if (message.aborted) {
      partial.erase(message.message_id);
      return;
    }
    if (!message.complete) {
      auto &held = partial[message.message_id];
      if (held.body.empty()) {
        held = message;
      } else {
        held.body += message.body;
      }
      return;
    }
    const auto held = partial.find(message.message_id);
    if (held != partial.end()) {
      held->second.body += message.body;
      held->second.complete = true;
      message = held->second;
      partial.erase(held);
    }
    if (callbacks.message) callbacks.message(message);
  }

  void read() {
    char buffer[8192];
    if (session && !handshake()) return;
    while (connection >= 0 && session) {
      // A read may write too (TLS 1.3 key update, alerts).
      const auto received = without_sigpipe([&] { return SSL_read(session, buffer, sizeof(buffer)); });
      if (received > 0) {
        incoming.append(buffer, static_cast<std::size_t>(received));
        if (incoming.size() > max_message) {
          fail("MSRP message exceeds the accepted size");
          return;
        }
        continue;
      }
      const auto error = SSL_get_error(session, received);
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) break;
      fail(error == SSL_ERROR_ZERO_RETURN ? "MSRP connection closed by the peer"
                                          : "MSRP TLS connection lost while reading");
      return;
    }
    while (connection >= 0 && !session) {
      const auto received = ::recv(connection, buffer, sizeof(buffer), 0);
      if (received == 0) {
        fail("MSRP connection closed by the peer");
        return;
      }
      if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        fail("MSRP connection lost while reading");
        return;
      }
      incoming.append(buffer, static_cast<std::size_t>(received));
      if (incoming.size() > max_message) {
        fail("MSRP message exceeds the accepted size");
        return;
      }
    }
    while (!incoming.empty()) {
      Message message;
      std::size_t used = 0;
      try {
        used = decode(incoming, message);
      } catch (const std::exception &error) {
        fail(error.what());
        return;
      }
      if (!used) return;
      incoming.erase(0, used);
      if (message.method.empty()) {
        // A response to one of our SENDs; the last one completes the transfer.
        if (outstanding.erase(message.transaction) && outstanding.empty() && callbacks.sent) callbacks.sent();
        continue;
      }
      // A listening endpoint learns the peer from the path of the first request,
      // which for an active peer is the empty SEND that binds the connection.
      if (peer.host.empty() && !message.from_path.empty()) peer = message.from_path.front();
      // RFC 4975 section 7.1.2: a REPORT is never answered; it reports on a SEND of ours and is no message for the
      // application.
      if (message.method == "REPORT") continue;
      // RFC 4975 section 7.1.2: answer a SEND unless the sender declined reports.
      if (message.failure_report != "no") {
        Message response;
        response.transaction = message.transaction;
        response.status = 200;
        response.comment = "OK";
        response.to_path = message.from_path;
        response.from_path = std::vector<Uri>{local};
        queue(response);
      }
      // RFC 6135: the empty SEND that binds the connection carries nothing to deliver.
      if (message.body.empty()) continue;
      deliver(message);
    }
  }
};

//------------------------------------------------------------------------------
// Helper: a new endpoint, neither listening nor connected.
Endpoint::Endpoint() : state_(std::make_unique<State>()) {}

//------------------------------------------------------------------------------
// Helper: closes the connection and listener and frees the TLS context (State).
Endpoint::~Endpoint() = default;

//------------------------------------------------------------------------------
// RFC 6135: the passive endpoint listens on an ephemeral TCP port and returns its MSRP URI (msrps with TLS) for
// the SDP; the peer connects and binds the connection.
Uri Endpoint::listen(const std::string &advertise, Callbacks callbacks, const TlsConfig *tls) {
  state_->callbacks = std::move(callbacks);
  if (tls) state_->configure(*tls);
  state_->listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (state_->listener < 0) throw std::runtime_error("MSRP socket failure");
  sockaddr_in local{};
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  if (::bind(state_->listener, reinterpret_cast<sockaddr *>(&local), sizeof(local)) < 0 ||
      ::listen(state_->listener, 1) < 0)
    throw std::runtime_error("MSRP listen failed: " + std::string(std::strerror(errno)));
  socklen_t length = sizeof(local);
  if (getsockname(state_->listener, reinterpret_cast<sockaddr *>(&local), &length) < 0)
    throw std::runtime_error("MSRP port lookup failed");
  state_->local = Uri{advertise, random_ident(), "tcp", ntohs(local.sin_port), tls != nullptr};
  return state_->local;
}

//------------------------------------------------------------------------------
// RFC 6135: the active endpoint connects to the peer's MSRP URI (with TLS for msrps, RFC 4975 section 14) and
// binds the connection with an empty SEND.
void Endpoint::connect(const Uri &peer, const Uri &local, Callbacks callbacks, const TlsConfig *tls) {
  state_->callbacks = std::move(callbacks);
  if (peer.secure && !tls) throw std::runtime_error("an msrps peer needs TLS");
  if (peer.secure && !state_->tls) state_->configure(*tls);
  state_->peer = peer;
  state_->local = local;
  if (state_->listener >= 0) {
    ::close(state_->listener); // the active endpoint does not accept
    state_->listener = -1;
  }
  state_->connection = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (state_->connection < 0) throw std::runtime_error("MSRP socket failure");
  int flag = 1;
  setsockopt(state_->connection, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
  sockaddr_in remote{};
  remote.sin_family = AF_INET;
  remote.sin_port = htons(peer.port);
  const auto host = resolve(peer.host);
  if (inet_pton(AF_INET, host.c_str(), &remote.sin_addr) != 1) throw std::runtime_error("MSRP peer address");
  if (::connect(state_->connection, reinterpret_cast<sockaddr *>(&remote), sizeof(remote)) < 0 && errno != EINPROGRESS)
    throw std::runtime_error("MSRP connect: " + std::string(std::strerror(errno)));
  if (peer.secure) {
    state_->local.secure = true;
    state_->start_tls(false);
  }
  // RFC 6135: the active endpoint binds the connection with an empty SEND.
  Message bind;
  bind.transaction = random_ident();
  bind.method = "SEND";
  bind.message_id = random_ident();
  bind.to_path = std::vector<Uri>{peer};
  bind.from_path = std::vector<Uri>{state_->local};
  bind.failure_report = "no";
  state_->queue(bind);
}

//------------------------------------------------------------------------------
// RFC 4975 sections 7.1.1 and 5.1: sends a body as one message in SEND chunks of 2048 bytes with Byte-Range; an
// empty body is one empty chunk.
void Endpoint::send(const std::string &content_type, const std::string &body) {
  if (state_->peer.host.empty()) throw std::runtime_error("MSRP peer is not known yet");
  const auto id = random_ident();
  const auto total = body.size();
  for (std::size_t at = 0; at < total || at == 0; at += chunk_size) {
    Message message;
    message.transaction = random_ident();
    message.method = "SEND";
    message.message_id = id;
    message.to_path = std::vector<Uri>{state_->peer};
    message.from_path = std::vector<Uri>{state_->local};
    message.content_type = content_type;
    message.body = body.substr(at, chunk_size);
    message.range_start = at + 1;
    message.range_end = at + message.body.size();
    message.total = total;
    message.complete = at + chunk_size >= total;
    state_->outstanding.insert(message.transaction);
    state_->queue(message);
    if (total == 0) break;
  }
  state_->flush();
}

//------------------------------------------------------------------------------
// TS 24.582 clause 6.4.1: several MCData bodies travel in one multipart/mixed body.
void Endpoint::send_parts(const std::vector<std::pair<std::string, std::string>> &parts) {
  if (parts.size() == 1) return send(parts.front().first, parts.front().second);
  const auto boundary = "msrp-" + random_ident();
  std::string body;
  for (const auto &[type, content] : parts)
    body += "--" + boundary + "\r\nContent-Type: " + type + "\r\n\r\n" + content + "\r\n";
  body += "--" + boundary + "--\r\n";
  send("multipart/mixed; boundary=" + boundary, body);
}

//------------------------------------------------------------------------------
// Helper: accepts a waiting connection (starting TLS as server), then sends what is queued and reads and answers
// what has arrived; call it from the event loop.
void Endpoint::poll() {
  auto &state = *state_;
  if (state.listener >= 0 && state.connection < 0) {
    const auto accepted = accept4(state.listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (accepted >= 0) {
      state.connection = accepted;
      int flag = 1;
      setsockopt(state.connection, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
      if (state.tls) {
        try {
          state.start_tls(true);
        } catch (const std::exception &error) {
          state.fail(error.what());
          return;
        }
      }
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
      state.fail("MSRP accept failed");
      return;
    }
  }
  if (state.connection < 0) return;
  state.flush();
  state.read();
}

//------------------------------------------------------------------------------
// Helper: closes the connection and the listener.
void Endpoint::close() { state_->shutdown(); }

//------------------------------------------------------------------------------
// Helper: whether the connection is up (and its TLS handshake complete).
bool Endpoint::connected() const { return state_->connection >= 0 && (!state_->session || state_->handshaken); }

//------------------------------------------------------------------------------
// Helper: whether the connection runs over TLS with a completed handshake.
bool Endpoint::secure() const { return state_->session && state_->handshaken; }

//------------------------------------------------------------------------------
// Helper: the local port of this endpoint.
std::uint16_t Endpoint::port() const { return state_->local.port; }

//------------------------------------------------------------------------------
// Helper: the local MSRP URI of this endpoint.
const Uri &Endpoint::local() const { return state_->local; }

} // namespace mcx::msrp
