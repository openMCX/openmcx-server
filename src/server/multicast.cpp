//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IP multicast delivery of MCPTT group call speech, an OpenMCX profile (include/mcx/multicast.hpp): the configured
// host groups, the participants that receive a session's speech by multicast, and the participating function's part
// of TS 24.379 clause 14 that the profile uses: the client's listening status report (clauses 14.2.3 and 14.2.4).
// A participant on the opt-in list receives the speech by unicast until it reports "listening" for the session, and
// again once it reports "not-listening" (TS 24.380 clause 6.4.3 step 3 a).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), RFC 1112, RFC 3428.

#include "server.hpp"

#include "mcx/mbms_usage.hpp"

#include <algorithm>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: reads the "multicast" block of the mcptt configuration and opens the socket the speech is sent from, on the
// media address. The profile serves MCPTT group calls of a server in the "both" role only: MCVideo and the separate
// participating and controlling servers keep unicast media.
void McServer::multicast_setup() {
  const auto &service = cfg_.at(svc_.name);
  if (!service.contains("multicast")) return;
  if (std::string_view(svc_.name) != "mcptt") throw std::runtime_error("multicast: MCPTT only");
  if (role_ != "both") throw std::runtime_error("multicast: needs mcptt.role both");
  multicast_ = multicast_config(service.at("multicast"));
  multicast_socket_ = std::make_unique<UdpSocket>(cfg_.at("media").at("bind").get<std::string>(), 0);
  multicast_socket_->multicast_sending(multicast_->interface, multicast_->ttl);
  status_["multicast_groups"] = multicast_->groups.size();
  status_["multicast_forwarded"] = 0;
  status_["multicast_listening"] = Json::array();
}

//------------------------------------------------------------------------------
// Helper: the host group of a session's speech: a prearranged, chat or broadcast group call (or a regroup) whose group
// is configured, with floor control. Private, ad hoc and ambient listening calls and calls without floor control
// (TS 24.379 clause 11.1.2, where a receiver follows the first SSRC it hears, its own included) stay unicast.
const MulticastDestination *McServer::multicast_destination(const Session &session) const {
  if (!multicast_ || session.private_call || session.adhoc || session.no_media_control || !session.ambient.empty())
    return nullptr;
  return multicast_->group(session.group);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.4.3 step 3 a): whether a participant receives the speech by multicast: its user is on the
// opt-in list, its latest report for the session is "listening" (TS 24.379 clause 14.2.3 step 1 a), and its SDP
// agreed the multicast speech's RTP payload type and AMR-WB payload format (RFC 4867 section 4). Any other
// participant keeps unicast.
bool McServer::multicast_leg(const Leg &leg) const {
  return multicast_ && leg.remote && multicast_->serves(leg.user) &&
         multicast_listening_.contains({leg.user, leg.session->uri}) &&
         leg.remote->payload_type == multicast_->payload_type && leg.remote->octet_aligned == multicast_->octet_aligned;
}

//------------------------------------------------------------------------------
// Helper: sends one RTP packet of a session's speech to its host group.
void McServer::send_multicast(std::span<const std::uint8_t> packet, const MulticastDestination &destination) {
  multicast_socket_->send(packet, destination.address, destination.port);
  status_["multicast_forwarded"] = status_.value("multicast_forwarded", 0u) + 1;
}

//------------------------------------------------------------------------------
// Helper: the application/vnd.3gpp.mcptt-mbms-usage-info+xml body of a SIP MESSAGE, or none.
const std::string *McServer::mbms_usage_part(const SipMessage &message) {
  for (const auto &part : message.parts)
    if (part.content_type == mbms_usage_mime) return &part.body;
  return message.content_type == mbms_usage_mime ? &message.body : nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 14.2.3 and 14.2.4: a "SIP MESSAGE request for an MBMS listening status update" from a served
// user. A body with an <announcement>, or an mcptt-info naming another MCPTT ID than the asserted user's, is refused
// with 403 (clause 14.2.4, clause 14.2.3 step 1). A suspension status is accepted without action (clause 14.2.3: the
// action is implementation specific; the profile has no bearer to suspend), and so is a report on the general
// purpose subchannel only (the profile has none).
SipResponse McServer::mbms_usage_message(const SipMessage &message, const User &user, const std::string &body) {
  SipResponse response;
  response.status_code = 403;
  MbmsUsageInfo usage;
  try {
    usage = parse_mbms_usage_info(body);
  } catch (const std::exception &error) {
    response.status_code = 400;
    event("multicast_status_refused", {{"user_id", user.id}, {"reason", error.what()}});
    return response;
  }
  const auto info = message_info(message, svc_);
  if (usage.announcement || info.request_uri != user.id) {
    event("multicast_status_refused", {{"user_id", user.id}, {"reason", "TS 24.379 clause 14.2.4"}});
    return response;
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
// Helper: why a "listening" report cannot be taken, or empty: the profile is not configured, the user is not on the
// opt-in list, the session is not a current one with a host group, the user takes no part in it, or the report does
// not name the session's TMGI.
std::string McServer::multicast_listening_refusal(const User &user, const MbmsListeningStatus &status) const {
  if (!multicast_) return "multicast not configured";
  if (!multicast_->serves(user.id)) return "user not on the multicast opt-in list";
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [&](const auto &entry) { return entry.second->uri == status.session_id; });
  if (found == sessions_.end()) return "no such session";
  const auto *destination = multicast_destination(*found->second);
  if (!destination) return "session without a host group";
  if (std::find(status.tmgis.begin(), status.tmgis.end(), destination->tmgi) == status.tmgis.end())
    return "TMGI of another host group";
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
