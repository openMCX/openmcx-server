//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCPTT server: its construction and the MCPTT-only rules of the shared core's service hooks: the SDP of an
// MCPTT call, the direction of an ambient listening call and the subject of an access token (members of McpttServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 29.283.

#include "mcptt_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379: construct the MCPTT server on the shared core with the MCPTT service profile; it reads user profiles
// over MCPTT-2 (TS 23.379 clause 7.5.2.3, TS 29.283), so it needs "diameter_config".
McpttServer::McpttServer(Json cfg, bool disable_tls) : McServer(mcptt_service, std::move(cfg), disable_tls) {
  if (!diameter_) throw std::runtime_error("an MCPTT server needs diameter_config (MCPTT-2)");
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.2.1 and 11.1.2: an MCPTT call has floor control and no video; a private call may have no
// floor control (uncontrolled_allowed). TS 24.379 clause 11.1.6.2.1.1 steps 12 and 13: an implicit floor request
// (mc_implicit_request) is accepted only in an ambient listening call (implicit_allowed).
void McpttServer::check_service_media(const MediaDescription &media, bool implicit_allowed,
                                      bool uncontrolled_allowed) const {
  if (media.video.has_value() || media.control == MediaControl::transmission)
    throw std::runtime_error("media of another MC service");
  if (media.control == MediaControl::none && !uncontrolled_allowed)
    throw std::runtime_error("call requires floor control");
  if (media.implicit_request && !implicit_allowed) throw std::runtime_error("unsupported negotiated profile");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.6.3.1.1 step 9 and clause 6.2.1 step 2c: the speech of an ambient listening call is
// offered recvonly (remote-init) or sendonly (local-init).
std::optional<std::string> McpttServer::ambient_direction_refusal(const MediaDescription &media,
                                                                  const std::string &type) const {
  if (media.direction != (type == "remote-init" ? "recvonly" : "sendonly"))
    return "ambient listening SDP direction does not match the ambient listening type";
  return std::nullopt;
}

//------------------------------------------------------------------------------
// OpenMCX: the subject of an access token of OpenMCX's IdMS is the MCPTT ID.
bool McpttServer::token_subject_valid(const Json &claims) const {
  return claims.value("sub", "") == claims.value(svc_.id_claim, "");
}

} // namespace mcx
