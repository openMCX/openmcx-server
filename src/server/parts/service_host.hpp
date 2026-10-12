//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// What every service part needs from its server (McServer for MCPTT and MCVideo, DataServer for MCData): the protection
// of the bodies it sends, the peers (the other participating and controlling functions of the system; MCData has none),
// the common services and the SIP requests, called per request. Each part's own host interface derives from it.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
#pragma once

#include "mcx/protocol.hpp"
#include "mcx/runtime.hpp"
#include "mcx/sip.hpp"

#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// The server as every service part sees it.
class ServiceHost {
public:
  virtual ~ServiceHost() = default;
  // The bodies sent to a client served here, or to a peer, as the server protects them (TS 33.180 clauses 9.3, 9.5
  // and 11.1.3); the core protects in its SIP engine's body filter and passes them as they are.
  virtual std::vector<BodyPart> seal_for_client(const std::string &sip, std::vector<BodyPart> parts) = 0;
  // The peers: configured, their PSI and the route to them. A server without peers (MCData) keeps these defaults.
  virtual std::vector<BodyPart> seal_for_peer(const std::string &peer, std::vector<BodyPart> /*parts*/) {
    throw std::logic_error("no peer server " + peer);
  }
  [[nodiscard]] virtual bool peer_known(const std::string & /*peer*/) const { return false; }
  [[nodiscard]] virtual std::string peer_uri(const std::string &peer) const {
    throw std::logic_error("no peer server " + peer);
  }
  [[nodiscard]] virtual std::vector<SipHeader> route_to(const std::string &peer,
                                                        std::vector<SipHeader> /*headers*/) const {
    throw std::logic_error("no peer server " + peer);
  }
  // This server's PSI.
  [[nodiscard]] virtual std::string service_uri() const = 0;
  // A document of a common service's internal interface ("cms", "gms"), and the IdMS token introspection
  // (parts/common_services.hpp); both throw on failure.
  virtual Json common_document(const std::string &role, const std::string &path) = 0;
  virtual Json introspect(const std::string &token) = 0;
  // SIP: a MESSAGE request, a PUBLISH request, and the final response to a request answered later.
  virtual void send_message(const std::string &uri, const std::string &type, const std::string &body,
                            const std::vector<SipHeader> &headers, SipResponseHandler handler) = 0;
  virtual void publish(const std::string &uri, const std::string &type, const std::string &body,
                       const std::vector<SipHeader> &headers, SipResponseHandler handler) = 0;
  virtual void respond(const std::string &transaction, const SipResponse &response) = 0;
  // A task for the run loop, after the current request is answered.
  virtual void schedule(std::function<void()> task) = 0;
};
} // namespace mcx
