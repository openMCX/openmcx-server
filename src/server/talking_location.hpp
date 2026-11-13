//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

#pragma once

// The user's location in a call request the originating participating MCPTT function sends to the controlling
// function (TS 24.379 V19.8.0), governed by <allow-location-info-when-talking> of the user profile (TS 24.484 V19.6.0
// clause 8.3.2.7: "false" = "not authorised to be sent to the MCPTT server performing the controlling MCPTT function
// for the call").

#include <string_view>

namespace mcx {

//------------------------------------------------------------------------------
// What happens to the location: the client's body passed on or withheld, the function's own added, or none.
enum class TalkingLocation { pass, withhold, add_own, none };

//------------------------------------------------------------------------------
// Helper: a call type whose location steps all depend on the element: private calls (clauses 11.1.1.3.1.1 step 21,
// 11.1.1.3.1.2 step 19b, with clauses 6.3.2.1.3 step 9 and 6.3.2.1.4 step 14), ambient listening calls (clauses
// 11.1.6.3.1.1 step 15, 11.1.6.3.1.4 step 18a) and ad hoc group calls (clauses 17.3.2.1.1 step 17, 17.3.2.2.1 step
// 16). On-demand group and chat calls also copy the body with no condition (clauses 10.1.1.3.1.1 step 7, 10.1.2.3.1.1
// step 6 b)): a conflict of the specification (Known limitations, "Location in call requests"), where the body is
// passed on as before.
constexpr bool talking_location_gated(std::string_view session_type, std::string_view ambient) {
  return session_type == "private" || session_type == "first-to-answer" || session_type == ambient ||
         session_type == "adhoc";
}

//------------------------------------------------------------------------------
// Helper: a call type whose implicit floor request step adds the function's own location of the user when the
// request carries none ("otherwise" of clauses 10.1.1.3.1.1 step 9, 10.1.2.3.1.1 step 8, 11.1.1.3.1.1 step 21,
// 11.1.6.3.1.1 step 15 and their REFER twins); the ad hoc steps have no such branch.
constexpr bool talking_location_own(std::string_view session_type, std::string_view ambient) {
  return session_type == "prearranged" || session_type == "chat" || session_type == "private" ||
         session_type == "first-to-answer" || session_type == ambient;
}

//------------------------------------------------------------------------------
// The decision for an initial INVITE towards the controlling function. implicit: the request is regarded as received
// with an implicit floor request (clause 6.4); allowed: the element is "true"; client_body: the request carries a
// location body; kept: that body is the emergency alert's location (clause 6.2.9.1) or a location information report
// of clause 13.3.4.2 (it has TriggerIds), which the text does not say the element covers (Known limitations): passed
// on as before; own_known: the function has the user's location available.
constexpr TalkingLocation talking_location(bool gated, bool own_branch, bool implicit, bool allowed, bool client_body,
                                           bool kept, bool own_known) {
  if (client_body) return !gated || kept || allowed ? TalkingLocation::pass : TalkingLocation::withhold;
  return own_branch && implicit && allowed && own_known ? TalkingLocation::add_own : TalkingLocation::none;
}

} // namespace mcx
