//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCPTT server: its construction and the MCPTT-only rules of the shared core's service hooks: the SDP of an
// MCPTT call, its implicit floor request, the direction of an ambient listening call and the subject of an access
// token (members of McpttServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19),
// TS 33.180 V19.4.0 (Rel-19), TS 29.283.

#include "mcptt_server.hpp"

#include "implicit_floor.hpp"

#include <set>
#include <utility>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379: construct the MCPTT server on the shared core with the MCPTT service profile; it reads user profiles
// over MCPTT-2 (TS 23.379 clause 7.5.2.3, TS 29.283), so it needs "diameter_config".
McpttServer::McpttServer(Json cfg, bool disable_tls) : McServer(mcptt_service, std::move(cfg), disable_tls) {
  if (!diameter_) throw std::runtime_error("an MCPTT server needs diameter_config (MCPTT-2)");
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.2.1 and 11.1.2: an MCPTT call has floor control and no video; a private call may have no
// floor control (uncontrolled_allowed). An "mc_implicit_request" is no reason to refuse an offer: where it is no
// implicit floor request, the INVITE "shall be regarded as received without an implicit floor request" (TS 24.379
// clause 6.4; accept_implicit_floor_request).
void McpttServer::check_service_media(const MediaDescription &media, bool uncontrolled_allowed) const {
  if (media.video.has_value() || media.control == MediaControl::transmission)
    throw std::runtime_error("media of another MC service");
  if (media.control == MediaControl::none && !uncontrolled_allowed)
    throw std::runtime_error("call requires floor control");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.4 with TS 24.380 clauses 14.3.5 and 14.3.6: the answer to the initial INVITE of a client
// that initiates the call (initiates) accepts its implicit floor request and returns the SSRC of its speech in
// "mc_ssrc" (initial_answer_media). TS 24.380 clause 14.3.4: "mc_granted" is optional for the controlling function
// and is not used; the floor is granted with Floor Granted (initial_service_state).
void McpttServer::accept_implicit_floor_request(Leg &leg, const MediaDescription &remote, bool initiates) {
  leg.implicit_floor =
      implicit_floor_accepted(remote.implicit_request, initiates, leg.local.control == MediaControl::floor);
  leg.implicit_audio_ssrc = 0;
  if (!leg.implicit_floor) return;
  std::set<std::uint32_t> in_use;
  for (const auto &[dialog, other] : legs_) {
    in_use.insert(other->audio_ssrc);
    if (other->implicit_audio_ssrc) in_use.insert(other->implicit_audio_ssrc);
  }
  leg.implicit_audio_ssrc = implicit_audio_ssrc(remote.audio_ssrc, in_use, random_ssrc);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5.2.2 items 1 and 3 (clause 6.3.4.2.2 step 3a-i for a new call): once the leg of a client
// whose implicit floor request was accepted is active, the request is processed as a Floor Request (clause
// 6.3.4.3.3); with another participant sending media it is queued (queueing negotiated) or answered with Floor
// Taken by the core (not negotiated). Returns true when the leg has been told its state. The request is processed
// once: the flag is cleared.
bool McpttServer::initial_service_state(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session) {
  if (session->no_media_control || !leg->remote || !std::exchange(leg->implicit_floor, false)) return false;
  auto &arbitrator = *session->arbitrator;
  const auto owner = arbitrator.owner();
  const bool queueing = leg->local.queueing && leg->remote->queueing;
  const auto outcome = implicit_floor_outcome(owner && *owner != leg->user, queueing);
  if (outcome == ImplicitFloorOutcome::taken) return false; // item 3c: Floor Taken (initial_floor_state)

  // Item 3b i: the negotiated maximum priority (floor_request takes the lowest of the given one, the negotiated
  // "mc_priority" and the member's <user-priority>); a Floor Request without a Floor Priority field otherwise.
  constexpr std::uint8_t negotiated_maximum = 255;
  floor_request(*leg, session, arbitrator, outcome == ImplicitFloorOutcome::queue ? negotiated_maximum : 0, true);
  return true;
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
