//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Whether a group call at the controlling MCPTT function is still ongoing for a new request (TS 24.379 clause
// 10.1.1.4.2 step 9, clause 10.1.2.4.1 for a chat group call), and who of a released call's participants a new call
// waits for before it invites them. Used by the MCPTT and MCVideo servers (McServer); free of server state, so that
// the unit tests reach them.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19).
#pragma once

#include <algorithm>
#include <set>
#include <string>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.2 step 9: the controlling function "shall determine if an MCPTT group call for the group
// identity is already ongoing by determining if an MCPTT session identity has already been allocated for the group
// call and the MCPTT session is active". A session whose remaining dialogs (dialogs) have all been ended by this
// server's own BYE (ended_here: the release of clause 6.3.8.1, or of T4, TNG3 or a broadcast's end, whose answers are
// still outstanding) is being released and no longer active: a new request for the group creates a new session (step
// 14) instead of joining it (step 15), which would end with the release. A session without dialogs is gone already.
inline bool group_session_releasing(const std::set<std::string> &dialogs, const std::set<std::string> &ended_here) {
  return !dialogs.empty() &&
         std::all_of(dialogs.begin(), dialogs.end(), [&](const std::string &id) { return ended_here.contains(id); });
}

//------------------------------------------------------------------------------
// The members of a new group call that are still in the released call of the same group (in_released: the users of
// its remaining legs): the new call invites them once they are out of it (as a broadcast waits for the users of
// the calls it preempted), not while their BYE is outstanding. The caller, who has left that call, is not waited for.
inline std::set<std::string> members_to_await(const std::set<std::string> &in_released, const std::string &caller) {
  auto waiting = in_released;
  waiting.erase(caller);
  return waiting;
}

} // namespace mcx
