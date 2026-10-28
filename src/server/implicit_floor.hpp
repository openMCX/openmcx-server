//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The implicit floor request of an MCPTT call at the controlling MCPTT function (TS 24.379 clause 6.4): whether
// the answer to an initial INVITE accepts it (TS 24.380 clause 14.3.5), the RTP SSRC that answer returns in
// "mc_ssrc" (TS 24.380 clause 14.3.6), and how the floor control server processes the request once the
// participant's leg is active (TS 24.380 clause 6.3.5.2.2). Used by the MCPTT server (McpttServer); free of server
// state, so that the unit tests reach them.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
#pragma once

#include <cstdint>
#include <functional>
#include <set>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.380 clause 14.3.5: "the MCPTT server shall accept the initial INVITE request to be an implicit request for
// floor unless the MCPTT client is joining a chat group call or an ongoing pre-arranged call or adhoc group call".
// offered: the SDP offer has "mc_implicit_request". initiates: the INVITE initiates the call, a new one or (clause
// 6.3.5.2.2 item 3) "an already existing MCPTT call"; false for a join of a chat group call that exists (clause
// 6.3.2.2) and a rejoin of an ongoing call by its session identity (clause 6.2.1 item 2: "shall not be regarded as
// an implicit floor request in case of a rejoin to an already on-going group call"). floor_control: the call has
// a media plane control channel (without floor control the floor control parameters are discarded, clause
// 14.3.7).
constexpr bool implicit_floor_accepted(bool offered, bool initiates, bool floor_control) {
  return offered && initiates && floor_control;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 14.3.6: with an accepted implicit floor request and an "a=ssrc" in the SDP offer, the answer's
// "mc_ssrc" returns "the value included in the SDP offer or a new ssrc value if a collision is detected"; nothing
// (0) when the offer has no "a=ssrc" (the clause leaves that value to the server: "can determine", not used here).
// in_use: the audio SSRCs of the server's other legs; fresh: a new random SSRC.
inline std::uint32_t implicit_audio_ssrc(std::uint32_t offered, const std::set<std::uint32_t> &in_use,
                                         const std::function<std::uint32_t()> &fresh) {
  if (!offered) return 0;
  auto ssrc = offered;
  while (!ssrc || in_use.contains(ssrc)) ssrc = fresh();
  return ssrc;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5.2.2 items 1 and 3: the floor control server's processing of an accepted implicit floor
// request when the participant's leg is active.
enum class ImplicitFloorOutcome {
  // Item 1 (the call did not exist) and item 3a (nobody has the permission to send media): "as if a Floor Request
  // message was received" (clause 6.3.4.3.3), 'U: permitted'.
  request,
  // Item 3b: another participant sends media and queueing is negotiated: queued at "the negotiated maximum
  // priority level [...] except for pre-emptive priority" (NOTE 5: "will not result in pre-emption"), with a Floor
  // Queue Position Info.
  queue,
  // Item 3c: another participant sends media and queueing is not negotiated: Floor Taken.
  taken,
};

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5.2.2 items 1 and 3: the outcome for a participant whose call has (other_talker) or has not
// another participant with the permission to send media, and has (queueing) or has not negotiated "mc_queueing".
constexpr ImplicitFloorOutcome implicit_floor_outcome(bool other_talker, bool queueing) {
  if (!other_talker) return ImplicitFloorOutcome::request;
  return queueing ? ImplicitFloorOutcome::queue : ImplicitFloorOutcome::taken;
}

} // namespace mcx
