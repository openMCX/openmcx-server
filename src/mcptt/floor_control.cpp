// Floor control server of the MCPTT server, the interface towards the floor participant: the floor control
// messages from a client and the floor arbitration outcomes sent to it (members of McpttServer).
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19).

#include "mcptt_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5 (floor control interface towards the floor participant): a floor control packet from a
// client: Floor Ack (clause 8.2.13), Floor Request (clauses 6.3.5.3.4 and 6.3.5.4.4), Floor Release (clauses
// 6.3.5.4.5 and 6.3.5.5.3) and Floor Queue Position Request (clause 6.3.5.4.7).
void McpttServer::floor_packet(Leg &leg, const Datagram &datagram) {
  if (!eligible(leg) || !UdpSocket::matches(datagram.source, leg.remote->floor_address, leg.remote->floor_port)) return;
  if (wire_ssrc(datagram.bytes, true) != leg.local.floor_ssrc) return;
  auto *user = by_id(leg.user);
  auto *keys = user ? floor_keys(*user) : nullptr;
  if (floor_protected(leg) && !keys) throw std::runtime_error("floor key unavailable");
  auto bytes = floor_protected(leg) ? keys->unprotect_floor(datagram.bytes) : datagram.bytes;
  auto packet = decode_floor(bytes);
  if (packet.ssrc != leg.local.floor_ssrc) return;
  validate_on_network_floor(packet);
  const auto session = leg.session;
  auto &arbitrator = *session->arbitrator;
  std::string id;
  std::uint8_t priority = 0;
  for (auto &field : packet.fields) {
    if (field.id == static_cast<unsigned>(FloorFieldId::UserId)) id = read_user_id(field);
    if (field.id == static_cast<unsigned>(FloorFieldId::FloorPriority)) priority = read_priority(field);
  }
  if (packet.type == FloorType::Ack) {
    if (leg.floor_retries) leg.floor_retries->receive(packet);
    return;
  }
  if (packet.ack_required) {
    FloorPacket ack{FloorType::Ack, false, leg.remote->floor_ssrc, {source_field(2), message_type_field(packet.type)}};
    transmit_floor(leg, ack);
  }
  if (!id.empty() && id != leg.user) throw std::runtime_error("floor identity mismatch");
  if (packet.type == FloorType::Request) {
    floor_request(leg, session, arbitrator, priority);
  } else if (packet.type == FloorType::Release) {
    if (leg.floor_retries) leg.floor_retries->cancel(FloorType::Granted);
    // TS 24.380 clause 6.3.5.7.4: a Floor Release leaves 'U: not permitted but sends media' with Floor Idle or
    // Floor Taken (below); from 'U: permitted' it is the release clause 6.3.5.3.8 looks back to.
    leg.released_floor = arbitrator.owner() == leg.user;
    leg.sends_without_permission = false;
    const auto released = arbitrator.release(leg.user, monotonic_ms());
    if (released.empty()) {
      const auto owner = arbitrator.owner();
      send_notice(leg, {owner ? FloorNoticeKind::Taken : FloorNoticeKind::Idle, leg.user, owner.value_or(""), 0});
    } else
      notices(*session, released);
  } else if (packet.type == FloorType::QueuePositionRequest) {
    send_notice(leg, arbitrator.queue_position(leg.user));
  } else
    throw std::runtime_error("unsupported floor request");
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 6.3.5.3.4 and 6.3.5.4.4: a Floor Request from a participant: a member no longer in the group is
// disconnected; a request in an ambient listening call (TS 23.379 clause 10.14.1), from a broadcast receiver
// (clause 6.3.5.3.4 steps 1 and 2) or a receive-only user is denied; otherwise it is arbitrated with its effective
// floor priority and preemption level.
void McpttServer::floor_request(Leg &leg, const std::shared_ptr<Session> &session, MediaPlaneController &arbitrator,
                                std::uint8_t priority) {
  // Private-call authorization is revalidated periodically in tick().
  const bool unprovisioned = session->private_call || session->adhoc;
  const auto policy = unprovisioned ? Json::object() : group_profile(session->group);
  // A broadcast hierarchy reaches users through other groups; its membership
  // was resolved at setup.
  const bool member_now =
      unprovisioned || (session->hierarchy.empty() ? member(policy, leg.user)
                                                   : std::find(session->members.begin(), session->members.end(),
                                                               leg.user) != session->members.end());
  if (!member_now) {
    if (auto *requester = by_id(leg.user)) requester->groups.erase(session->group);
    disconnect_user(leg.user, session);
    return;
  }
  // TS 23.379 clause 10.14.1: only the listened-to user transmits in an ambient listening call.
  if (!session->ambient.empty() && leg.user != session->listened_to) {
    send_notice(leg, {FloorNoticeKind::Denied, leg.user, "", 5});
    event("floor_denied_ambient_listening", {{"user_id", leg.user}, {"session_uri", session->uri}});
    return;
  }
  const auto priority_policy = policy.value("priority_policy", Json::object());
  // TS 24.380 clause 6.3.5.3.4 steps 1 and 2: only the broadcast initiator reaches arbitration,
  // unless call_policy.broadcast_overriders authorises an override.
  const bool overrider = session->broadcast && leg.user != session->initiator &&
                         policy_allows_listed(session->policy, "broadcast_overriders", leg.user);
  if (session->broadcast && leg.user != session->initiator && !overrider) {
    send_notice(leg, {FloorNoticeKind::Denied, leg.user, "", 5});
    event("floor_denied_receive_only", {{"user_id", leg.user}, {"session_uri", session->uri}});
    return;
  }
  if (priority_allowed(priority_policy, "receive_only_users", leg.user)) {
    send_notice(leg, {FloorNoticeKind::Denied, leg.user, "", 5});
    return;
  }
  const auto caps = priority_policy.value("floor_priority_caps", policy.value("floor_priority_caps", Json::object()));
  // TS 24.380 clause 4.1.1.4: the configured cap, or the member's <user-priority> of the group document.
  const unsigned cap = caps.contains(leg.user) ? caps.value(leg.user, 0u)
                                               : policy.value("user_priorities", Json::object()).value(leg.user, 0u);
  if (cap > 99) throw std::runtime_error("invalid floor priority cap");
  priority = leg.local.floor_priority
                 ? static_cast<std::uint8_t>(std::min({unsigned(priority), unsigned(*leg.local.floor_priority), cap}))
                 : 0;
  const auto &current_priority = call_priority(*session);
  const bool emergency_request = current_priority.emergency_users.contains(leg.user);
  const bool imminent_request = !current_priority.emergency && current_priority.imminent_users.contains(leg.user);
  const std::uint8_t preemptive =
      emergency_request  ? 3
      : imminent_request ? 2
      : (overrider || (priority_allowed(priority_policy, "floor_preemptive_users", leg.user) &&
                       priority >= priority_policy.value("preemptive_priority", 99u)))
          ? 1
          : 0;
  if (overrider) {
    session->broadcast_overriders.insert(leg.user);
    event("broadcast_override_requested", {{"user_id", leg.user}, {"session_uri", session->uri}});
  }
  if (arbitrator.owner() == leg.user) {
    if (arbitrator.state() == FloorState::PendingRevoke)
      send_notice(leg, {FloorNoticeKind::Revoke, leg.user, leg.user, arbitrator.revoke_cause()});
    else
      // TS 24.380 clause 6.3.4.4.8: Floor Granted again, with the T2 still running for the participant.
      send_notice(leg, {FloorNoticeKind::Granted, leg.user, leg.user, 0, leg.granted_priority, 254,
                        arbitrator.talk_time_remaining(monotonic_ms())});
  } else
    notices(*session, arbitrator.request(leg.user, monotonic_ms(), priority, leg.local.queueing && leg.remote->queueing,
                                         preemptive));
  event("floor_request",
        {{"user_id", leg.user}, {"session_uri", session->uri}, {"owner", arbitrator.owner().value_or("")}});
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5: the floor control interface towards the MCPTT client sends a floor arbitration
// outcome as Floor Granted (clause 8.2.5), Floor Taken (clause 8.2.9), Floor Queue Position Info
// (clause 8.2.12), Floor Deny (clause 8.2.6), Floor Revoke (clause 8.2.10) or Floor Idle (clause 8.2.8),
// with the Floor Indicator (clause 8.2.3.15).
void McpttServer::send_floor_notice(Leg &leg, const FloorNotice &notice) {
  if (!leg.remote) return; // no SDP answer yet: no floor control channel (send_notice checks it too)
  FloorPacket packet;
  packet.ssrc = leg.remote->floor_ssrc;
  if (!leg.floor_retries)
    leg.floor_retries = std::make_unique<FloorAckRetry>(leg.remote->floor_ssrc, leg.local.floor_ssrc, 0);
  const auto &state = call_priority(*leg.session);
  const auto indicator = floor_call_type_bits(leg.session->broadcast, state.emergency, state.imminent);
  packet.fields.push_back(floor_indicator_field(indicator | (leg.local.queueing && leg.remote->queueing ? 0x0400 : 0)));
  switch (notice.kind) {
  case FloorNoticeKind::Granted:
    if (!leg.floor_granted) {
      std::uint32_t candidate;
      bool collision;
      do {
        candidate = random_ssrc();
        collision = false;
        for (const auto &[id, other] : legs_)
          if (other->audio_ssrc == candidate) collision = true;
      } while (collision);
      leg.audio_ssrc = candidate;
      leg.floor_granted = true;
    }
    packet.type = FloorType::Granted;
    leg.granted_priority = notice.priority;
    leg.sends_without_permission = leg.released_floor = false;
    if (leg.session->broadcast && leg.user == leg.session->initiator) leg.session->broadcast_transmitted = true;
    // TS 24.380 clauses 6.3.4.4.2 step 1a and 6.3.4.4.8 step 1a: the T2 (Stop talking) the arbitrator applies.
    packet.fields.push_back(duration_field_ms(notice.duration_ms));
    packet.fields.push_back(audio_ssrc_field(leg.audio_ssrc));
    packet.fields.push_back(priority_field(notice.priority));
    break;
  case FloorNoticeKind::Taken:
    leg.floor_granted = false;
    leg.released_floor = false; // now 'U: not permitted and Floor Taken' (clause 6.3.5.4.2)
    packet.type = FloorType::Taken;
    packet.fields.push_back(message_sequence_field(++leg.floor_sequence));
    packet.fields.push_back(granted_party_identity_field(notice.participant));
    // TS 24.380 clause 6.3.4.4.2: Permission to Request the floor is '0' in a broadcast group call.
    // Nor may the listening user request it in an ambient listening call (TS 23.379 clause 10.14.1).
    packet.fields.push_back(permission_to_request_field(!leg.session->broadcast && leg.session->ambient.empty()));
    packet.fields.push_back(location_not_provided_field());
    for (auto &[dialog, granted] : legs_)
      if (granted->session == leg.session && granted->user == notice.participant)
        packet.fields.push_back(audio_ssrc_field(granted->audio_ssrc));
    break;
  case FloorNoticeKind::QueuePosition:
    packet.type = FloorType::QueuePositionInfo;
    packet.fields.push_back(queue_info_field(notice.queue_position, notice.priority));
    break;
  case FloorNoticeKind::Denied:
    packet.type = FloorType::Deny;
    packet.fields.push_back(reject_cause_field(notice.reject_cause));
    break;
  case FloorNoticeKind::Revoke:
    packet.type = FloorType::Revoke;
    packet.fields.push_back(reject_cause_field(notice.reject_cause));
    break;
  case FloorNoticeKind::Idle:
    leg.floor_granted = false;
    packet.type = FloorType::Idle;
    packet.fields.push_back(message_sequence_field(++leg.floor_sequence));
    break;
  }
  packet.ack_required = packet.type != FloorType::Revoke && cfg_.at(svc_.name).value("floor_ack", true);
  if (packet.type == FloorType::Taken || packet.type == FloorType::Idle || packet.type == FloorType::Granted) {
    leg.floor_retries->cancel(FloorType::Taken);
    leg.floor_retries->cancel(FloorType::Idle);
  }
  if (packet.type == FloorType::Idle || packet.type == FloorType::Revoke || packet.type == FloorType::Taken)
    leg.floor_retries->cancel(FloorType::Granted);
  validate_on_network_floor(packet);
  leg.floor_retries->send(packet, monotonic_ms());
  transmit_floor(leg, packet);
}

} // namespace mcx
