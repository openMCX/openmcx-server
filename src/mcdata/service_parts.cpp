// The host of the shared service parts (src/server/parts) in the MCData server: what every part needs
// (ServiceHost); the location hooks are in location.cpp (member functions of
// DataServer::PartsGlue, declared in data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 33.180 clause 9.5 and TS 24.282 clause 6.5.2: the bodies to a client protected as any other sent to it.
std::vector<BodyPart> DataServer::PartsGlue::seal_for_client(const std::string &sip, std::vector<BodyPart> parts) {
  return server_.seal_for(sip, std::move(parts));
}

//------------------------------------------------------------------------------
// Helper: this server's PSI.
std::string DataServer::PartsGlue::service_uri() const { return server_.service_uri_; }

//------------------------------------------------------------------------------
// Helper: a document of a common service's internal interface.
Json DataServer::PartsGlue::common_document(const std::string &role, const std::string &path) {
  return server_.internal(role, path);
}

//------------------------------------------------------------------------------
// Helper: the IdMS introspection of an access token.
Json DataServer::PartsGlue::introspect(const std::string &token) {
  return introspect_token(server_.http_, server_.cfg_.at("common"), token);
}

//------------------------------------------------------------------------------
// Helper: a SIP MESSAGE request.
void DataServer::PartsGlue::send_message(const std::string &uri, const std::string &type, const std::string &body,
                                         const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  server_.sip_.request("MESSAGE", uri, type, body, headers, std::move(handler));
}

//------------------------------------------------------------------------------
// Helper: a SIP PUBLISH request.
void DataServer::PartsGlue::publish(const std::string &uri, const std::string &type, const std::string &body,
                                    const std::vector<SipHeader> &headers, SipResponseHandler handler) {
  server_.sip_.publish(uri, type, body, headers, std::move(handler));
}

//------------------------------------------------------------------------------
// Helper: the final response to a request answered later.
void DataServer::PartsGlue::respond(const std::string &transaction, const SipResponse &response) {
  server_.sip_.respond(transaction, response);
}

//------------------------------------------------------------------------------
// Helper: a task for the run loop.
void DataServer::PartsGlue::schedule(std::function<void()> task) { server_.pending_.push_back(std::move(task)); }

} // namespace mcx
