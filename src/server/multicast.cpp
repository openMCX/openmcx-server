//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The participating function's handling of the MBMS listening status reports (TS 24.379 clauses 14.2.3 and 14.2.4,
// TS 24.281 clauses 16.3.3 and 16.3.4): a client that reported "listening" for a session whose conversation has an
// MBMS subchannel (src/server/mbms.cpp) receives the session's media there, and by unicast again once it reports
// "not-listening" (TS 24.380 clause 6.4.3 step 3 a, clause 10.2.3.5 NOTE).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), RFC 3428.

#include "server.hpp"

#include "mcx/mbms_usage.hpp"

#include <algorithm>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.380 clause 10.2.3.5 and its NOTE: whether a participant receives the media over the MBMS subchannel of its
// session's conversation: it is served over MBMS, its latest report for the session is "listening" (TS 24.379
// clause 14.2.3 step 1 a i), and its SDP agreed the subchannel's RTP payload type and AMR-WB payload format (RFC 4867
// section 4). Any other participant keeps unicast.
bool McServer::multicast_leg(const Leg &leg) const {
  return mbms_ && leg.remote && mbms_->serves(leg.user) && mbms_conversations_.contains(leg.session->uri) &&
         multicast_listening_.contains({leg.user, leg.session->uri}) &&
         leg.remote->payload_type == mbms_->payload_type && leg.remote->octet_aligned == mbms_->octet_aligned;
}

//------------------------------------------------------------------------------
// Helper: the application/vnd.3gpp.mcptt-mbms-usage-info+xml body of a SIP MESSAGE, or none.
const std::string *McServer::mbms_usage_part(const SipMessage &message) const {
  const std::string mime = mbms_usage_type(mbms_service()).mime;
  for (const auto &part : message.parts)
    if (part.content_type == mime) return &part.body;
  return message.content_type == mime ? &message.body : nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 14.2.3 and 14.2.4: a "SIP MESSAGE request for an MBMS listening status update" from a served
// user. A body with an <announcement>, or an mcptt-info naming another MCPTT ID than the asserted user's, is refused
// with 403 (clause 14.2.4, clause 14.2.3 step 1). A suspension status is accepted without action until the
// suspension procedures are in place.
SipResponse McServer::mbms_usage_message(const SipMessage &message, const User &user, const std::string &body) {
  SipResponse response;
  response.status_code = 403;
  MbmsUsageInfo usage;
  try {
    usage = parse_mbms_usage_info(body, mbms_service());
  } catch (const std::exception &error) {
    response.status_code = 400;
    event("multicast_status_refused", {{"user_id", user.id}, {"reason", error.what()}});
    return response;
  }
  const auto info = message_info(message, svc_);
  if (!usage.announcements.empty() || info.request_uri != user.id) {
    event("multicast_status_refused", {{"user_id", user.id}, {"reason", "TS 24.379 clause 14.2.4"}});
    return response;
  }
  // TS 24.379 clause 14.2.3 step 1 a ii and step 1 b ii: the general purpose subchannel of announced bearers
  // (src/server/mbms.cpp); the same report may also name a session.
  if (usage.listening_status && usage.listening_status->general_purpose) {
    if (const auto refusal = mbms_general_purpose_status(user, *usage.listening_status); !refusal.empty()) {
      event("multicast_status_refused", {{"user_id", user.id}, {"reason", refusal}});
      return response;
    }
  }
  if (!usage.listening_status || usage.listening_status->session_id.empty()) {
    response.status_code = 200;
    return response;
  }
  const auto &status = *usage.listening_status;
  if (!status.listening) {
    // A report for a session that has ended, or that never used multicast, changes nothing.
    multicast_listening_.erase({user.id, status.session_id});
    response.status_code = 200;
  } else if (const auto refusal = multicast_listening_refusal(user, status); !refusal.empty()) {
    event("multicast_status_refused", {{"user_id", user.id}, {"reason", refusal}});
    return response;
  } else {
    multicast_listening_.emplace(user.id, status.session_id);
    response.status_code = 200;
  }
  publish_multicast_listening();
  event("multicast_listening",
        {{"user_id", user.id}, {"session_uri", status.session_id}, {"listening", status.listening}});
  return response;
}

//------------------------------------------------------------------------------
// Helper: why a "listening" report for a session cannot be taken, or empty: MBMS is not configured, the user is not
// served over MBMS, the session has no conversation with an MBMS subchannel (no Map Group To Bearer was sent), the
// report does not name its bearer's TMGI, or the user takes no part in the session.
std::string McServer::multicast_listening_refusal(const User &user, const MbmsListeningStatus &status) const {
  if (!mbms_) return "MBMS not configured";
  if (!mbms_->serves(user.id)) return "user not served over MBMS";
  const auto conversation = mbms_conversations_.find(status.session_id);
  if (conversation == mbms_conversations_.end()) return "session without an MBMS subchannel";
  if (std::ranges::find(status.tmgis, conversation->second.channel.tmgi) == status.tmgis.end())
    return "TMGI of another bearer";
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [&](const auto &entry) { return entry.second->uri == status.session_id; });
  if (found == sessions_.end()) return "no such session";
  const auto legs = session_legs(*found->second);
  if (std::none_of(legs.begin(), legs.end(), [&](const auto &leg) { return leg->user == user.id; }))
    return "user not in the session";
  return {};
}

//------------------------------------------------------------------------------
// Helper: the status shows who listens to which session; reports of sessions that have ended are dropped first.
void McServer::publish_multicast_listening() {
  std::erase_if(multicast_listening_, [&](const auto &entry) {
    return std::none_of(sessions_.begin(), sessions_.end(),
                        [&](const auto &session) { return session.second->uri == entry.second; });
  });
  auto listening = Json::array();
  for (const auto &[user, session] : multicast_listening_)
    listening.push_back({{"user_id", user}, {"session_uri", session}});
  status_["multicast_listening"] = std::move(listening);
}

} // namespace mcx
