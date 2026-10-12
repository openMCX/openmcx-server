//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// HTTP/2 over cleartext with prior knowledge (RFC 9113 3.3), the server side of one
// connection: what the SBI uses (TS 29.500 5.2.2.1). nghttp2 does the framing.
#pragma once
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mcx::h2 {
// The client connection preface (RFC 9113 3.4).
inline constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

struct Request {
  std::string method, path, body;
};
struct Response {
  int status = 204;
  std::vector<std::pair<std::string, std::string>> headers;  // lower-case names
  std::string body;
};
using Handler = std::function<Response(const Request &)>;

// Serves the requests of one connection on `fd` until the peer closes it, it
// stays idle for `idle_ms` (then GOAWAY) or `stopping` returns true. `received`
// holds what was already read from the connection (starting with the preface).
// Returns false if the peer did not speak HTTP/2.
bool serve(int fd, std::string_view received, const Handler &, const std::function<bool()> &stopping,
           int idle_ms = 5000);
}  // namespace mcx::h2
