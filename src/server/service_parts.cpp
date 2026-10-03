// The host of the shared service parts (src/server/parts) in the MCPTT and MCVideo core: what every part needs
// (ServiceHost); the location hooks are in location.cpp and the peer registration hooks in split.cpp (member functions
// of McServer::PartsGlue).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the core passes the bodies to a client as they are; its SIP engine's outgoing body filter protects them
// (protect_outgoing, TS 33.180 clause 9.3).
std::vector<BodyPart> McServer::PartsGlue::seal_for_client(const std::string & /*sip*/, std::vector<BodyPart> parts) {
  return parts;
}

//------------------------------------------------------------------------------
// Helper: the core passes the bodies to a peer as they are; its SIP engine's outgoing body filter protects them
// (protect_outgoing, TS 33.180 clause 11.1.3).
std::vector<BodyPart> McServer::PartsGlue::seal_for_peer(const std::string & /*peer*/, std::vector<BodyPart> parts) {
  return parts;
}

//------------------------------------------------------------------------------
// Helper: whether the peer is configured.
bool McServer::PartsGlue::peer_known(const std::string &peer) const { return server_.peers_.contains(peer); }

//------------------------------------------------------------------------------
// Helper: the PSI of the peer.
std::string McServer::PartsGlue::peer_uri(const std::string &peer) const { return server_.peers_.at(peer).service_uri; }

//------------------------------------------------------------------------------
// Helper: the header fields of a request to the peer, with its route.
std::vector<SipHeader> McServer::PartsGlue::route_to(const std::string &peer, std::vector<SipHeader> headers) const {
  return server_.route_to(peer, std::move(headers));
}

//------------------------------------------------------------------------------
// Helper: this server's PSI.
std::string McServer::PartsGlue::service_uri() const { return server_.own_service_uri(); }

//------------------------------------------------------------------------------
// Helper: a document of a common service's internal interface.
Json McServer::PartsGlue::common_document(const std::string &role, const std::string &path) {
  return server_.internal(role, path);
}

//------------------------------------------------------------------------------
// Helper: the IdMS introspection of an access token.
Json McServer::PartsGlue::introspect(const std::string &token) { return server_.introspect(token); }

//------------------------------------------------------------------------------
// Helper: a SIP MESSAGE request.
void McServer::PartsGlue::send_message(const std::string &uri, const std::string &type, const std::string &body,
                                       const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  server_.sip_.request("MESSAGE", uri, type, body, headers, std::move(handler));
}

//------------------------------------------------------------------------------
// Helper: a SIP PUBLISH request.
void McServer::PartsGlue::publish(const std::string &uri, const std::string &type, const std::string &body,
                                  const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  server_.sip_.publish(uri, type, body, headers, std::move(handler));
}

//------------------------------------------------------------------------------
// Helper: the final response to a request answered later.
void McServer::PartsGlue::respond(const std::string &transaction, const SipResponse &response) {
  server_.sip_.respond(transaction, response);
}

//------------------------------------------------------------------------------
// Helper: a task for the run loop.
void McServer::PartsGlue::schedule(std::function<void()> task) { server_.schedule(std::move(task)); }

} // namespace mcx
