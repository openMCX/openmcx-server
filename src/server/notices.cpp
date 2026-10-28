//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Disconnection of users and the media plane control server's notices to participants (TS 24.380 clause 6.3,
// TS 24.581 clause 6.3).
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19),
// TS 23.379 V19.11.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: a user leaves every call (or only the given one): forwarding stops, the floor is released
// (floor arbitration may grant a waiting survivor) and each of the user's legs receives a SIP BYE.
void McServer::disconnect_user(const std::string &id, const std::shared_ptr<Session> &only) {
  for (const auto &[group, session] : sessions_) {
    if (only && session != only) continue;
    // Stop forwarding first; floor arbitration may grant a waiting survivor.
    for (const auto &leg : session_legs(*session))
      if (leg->user == id) leg->active = false;
    notices(*session, session->arbitrator->release(id, monotonic_ms()));
    for (const auto &leg : session_legs(*session))
      if (leg->user == id) sip_.bye(leg->dialog);
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5, TS 24.581 clause 6.3.5: a floor arbitration outcome goes to a participant as the
// service's media plane control message (media_control_notice): floor control for MCPTT, transmission control for
// MCVideo.
void McServer::send_notice(Leg &leg, const FloorNotice &notice) {
  // A call without media plane control has no channel to send on (TS 24.379 clause 11.1.2).
  if (!leg.remote || !leg.active || leg.session->no_media_control) return;
  media_control_notice(leg, notice);
}

//------------------------------------------------------------------------------
// Helper: each floor arbitration outcome goes to the recipient's legs in the session.
void McServer::notices(const Session &session, const std::vector<FloorNotice> &floor_notices) {
  // TS 24.380 clause 10.2.2.2: a granted floor may start the conversation's MBMS subchannel (src/server/mbms.cpp).
  if (std::ranges::any_of(floor_notices, [](const auto &notice) { return notice.kind == FloorNoticeKind::Granted; }))
    (void)mbms_conversation_start(session);
  for (auto &notice : floor_notices)
    for (auto &[dialog, leg] : legs_)
      if (leg->session.get() == &session && leg->user == notice.recipient) send_notice(*leg, notice);
}

//------------------------------------------------------------------------------
// Helper: a broadcast hierarchy reaches users affiliated to a subordinate group
// (group-broadcast) or to any group (user-broadcast members).
bool McServer::reachable_via_hierarchy(const Session &session, const User &user) {
  if (session.hierarchy == "group-broadcast")
    return std::any_of(session.subordinate_groups.begin(), session.subordinate_groups.end(),
                       [&](const std::string &group) { return user.groups.contains(group); });
  return session.hierarchy == "user-broadcast" && !user.groups.empty();
}

//------------------------------------------------------------------------------
// Helper: whether the user is affiliated with a regroup: told of it (TS 24.379 clauses 16.2.2.4 step 3 h) and
// 16.3.2.4 step 3 h)), or affiliated to one of its constituent groups, from which a call on it is placed
// (TS 24.379 clause 10.1.2.4.1 NOTE 4).
bool McServer::regroup_affiliated(const User &user, const std::string &group) const {
  const auto found = regroups_.find(group);
  if (found == regroups_.end()) return false;
  return found->second.affiliated.contains(user.id) ||
         std::any_of(found->second.groups.begin(), found->second.groups.end(),
                     [&](const std::string &constituent) { return user.groups.contains(constituent); });
}

//------------------------------------------------------------------------------
// Helper: whether a leg takes part in media and floor control now: active, not held, its user registered
// and still a member of the call (affiliated to its group or regroup, or reached by the broadcast hierarchy), and
// its floor key ready.
bool McServer::eligible(const Leg &leg) {
  auto *user = by_id(leg.user);
  return leg.active && !leg.held && leg.remote && user && user->expires > std::time(nullptr) &&
         current_session(leg.session) &&
         (leg.session->private_call || leg.session->adhoc || user->groups.contains(leg.session->group) ||
          regroup_affiliated(*user, leg.session->group) || reachable_via_hierarchy(*leg.session, *user)) &&
         floor_key_ready(leg);
}

} // namespace mcx
