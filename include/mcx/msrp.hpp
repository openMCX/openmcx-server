// MSRP (RFC 4975) as the MCData media plane uses it (TS 24.582): SEND requests carrying the MCData bodies of TS 24.282
// clause 15, their responses, chunking and the connection binding of RFC 6135. Only the subset TS 24.582 needs is
// here: SEND and REPORT, no relays (RFC 4976) and no CEMA (RFC 6714). The MCData client and the controlling function
// are the MSRP endpoints (TS 24.582 clause 5.1.1), so a relay is never in the path in this deployment.
//
// Specifications: TS 24.582 V19.0.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 4975, RFC 6135, RFC 2046.
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx::msrp {

//------------------------------------------------------------------------------
// RFC 4975 section 6: an MSRP URI, "msrp://host:port/session;tcp" (the grammar of RFC 4975 section 9).
struct Uri {
  std::string host, session, transport = "tcp";
  std::uint16_t port = 0;
  bool secure = false; // "msrps"
  // RFC 4975 section 6: writes the MSRP URI.
  std::string text() const;
};

//------------------------------------------------------------------------------
// RFC 4975 section 6: parses an msrp or msrps URI.
Uri parse_uri(std::string_view text);

//------------------------------------------------------------------------------
// RFC 4975 section 9: one MSRP request or response. Bodies are kept as they arrive: the MCData bodies are binary
// (TS 24.282 clause 15), so nothing is interpreted here.
struct Message {
  std::string transaction, method; // method is empty in a response
  unsigned status = 0;             // nonzero in a response
  std::string comment;
  std::vector<Uri> to_path, from_path;
  std::string message_id, content_type, body;
  std::optional<std::uint64_t> range_start, range_end, total;
  bool complete = true; // the "$" continuation flag; "+" when more chunks follow
  bool aborted = false; // the "#" continuation flag
  std::string success_report, failure_report;
  // TS 24.582 clause 6.4.1: bodies of a multipart/mixed body, decoded on request.
  std::map<std::string, std::string> parts() const;
};

//------------------------------------------------------------------------------
// RFC 4975 section 9: encodes a request or response.
std::string encode(const Message &message);

//------------------------------------------------------------------------------
// RFC 4975 section 9: decodes one message from the head of the buffer. Returns how many octets it used, or 0 when the
// buffer does not yet hold a complete message. Throws on a malformed frame, which the caller answers with 400 and a
// closed connection.
std::size_t decode(std::string_view buffer, Message &out);

//------------------------------------------------------------------------------
// RFC 4975 section 9: a random ident (transaction identifiers, message identifiers, sessions).
std::string random_ident();

//------------------------------------------------------------------------------
// RFC 4975 section 14: MSRP over TLS ("msrps"): certificates from a trusted CA on both sides. The connecting side
// checks that the listener's certificate names expected_name; the listening side requires a certificate from the
// connector.
struct TlsConfig {
  std::string ca_file, cert_file, key_file, expected_name;
};

//------------------------------------------------------------------------------
// RFC 6135 and TS 24.582 clause 6.1.1.2.1: one MSRP connection over TCP. The endpoint either listens (the "passive"
// side of the SDP setup attribute) or connects (the "active" side), and drives its socket from the application's own
// poll loop.
class Endpoint {
public:
  struct Callbacks {
    std::function<void(const Message &)> message;  // a complete SEND, reassembled
    std::function<void(std::string_view)> failure; // the connection failed or was refused
    // Every SEND this endpoint issued has been answered; TS 24.582 clause 6.1.1.2.1 then releases the SIP session of a
    // standalone transfer.
    std::function<void()> sent;
  };

  Endpoint();
  ~Endpoint();
  Endpoint(const Endpoint &) = delete;
  Endpoint &operator=(const Endpoint &) = delete;

  // RFC 6135: listens on any free port of the given address and returns the local MSRP URI.
  Uri listen(const std::string &advertise, Callbacks callbacks, const TlsConfig *tls = nullptr);
  // RFC 6135: connects to the peer named in the SDP answer, from an already listening or a fresh endpoint, and binds
  // the connection with an empty SEND. A peer with an "msrps" URI is connected over TLS, which needs tls.
  void connect(const Uri &peer, const Uri &local, Callbacks callbacks, const TlsConfig *tls = nullptr);
  // RFC 4975 sections 7.1.1 and 5.1: sends one message to the peer, chunked when it is larger than the chunk size.
  void send(const std::string &content_type, const std::string &body);
  // TS 24.582 clauses 6.1.1.2.4 and 6.4.1: sends the two MCData bodies as one multipart/mixed body.
  void send_parts(const std::vector<std::pair<std::string, std::string>> &parts);
  void poll(); // accepts, reads and writes without blocking
  void close();
  bool connected() const; // ready to send: connected, TLS handshake done, peer known
  bool secure() const; // the connection runs over TLS and its handshake completed
  std::uint16_t port() const;
  const Uri &local() const;

private:
  struct State;
  std::unique_ptr<State> state_;
};

} // namespace mcx::msrp
