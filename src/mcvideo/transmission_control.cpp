// MCVideo transmission control server: the transmission control messages it sends and receives, and the check of
// those the participating function relays (member functions of McvideoServer).
//
// Specifications: TS 24.581 V19.2.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19),
// TS 23.281 V19.10.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).

#include "mcvideo_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.581 clauses 9.2.5 to 9.2.10 and 9.2.30: send an arbitration notice to a participant as its transmission
// control message. The arbitration is that of the floor arbitrator behind MediaPlaneController; its notices
// become the MCV1 messages of those clauses. Messages are sent without acknowledgement; in a group with
// protect_floor they are SRTCP under the user's CSK with the MCVideo CS-ID 8 (TS 24.281 clause 4.7.1,
// TS 33.180 clause 9.4).
void McvideoServer::send_transmission_notice(Leg &leg, const FloorNotice &notice) {
  using namespace mcx::transmission;
  if (!leg.remote) return; // no SDP answer yet: no transmission control channel (send_notice checks it too)
  Packet packet;
  packet.ssrc = leg.remote->floor_ssrc;
  switch (notice.kind) {
  case FloorNoticeKind::Granted:
    if (!leg.floor_granted) {
      // SSRCs for the granted user's audio and video, unique in this server.
      const auto fresh = [this]() {
        std::uint32_t candidate;
        bool collision;
        do {
          candidate = random_ssrc();
          collision = false;
          for (const auto &[id, other] : legs_)
            if (other->audio_ssrc == candidate || other->video_ssrc == candidate) collision = true;
        } while (collision);
        return candidate;
      };
      leg.audio_ssrc = fresh();
      leg.video_ssrc = fresh();
      leg.floor_granted = true;
    }
    packet.type = Type::Granted;
    leg.granted_priority = notice.priority;
    packet.fields = {duration_field(cfg_.at(svc_.name).value("max_talk_ms", 30000) / 1000),
                     audio_ssrc_field(leg.audio_ssrc), video_ssrc_field(leg.video_ssrc),
                     priority_field(notice.priority)};
    break;
  case FloorNoticeKind::Taken:
    leg.floor_granted = false;
    packet.type = Type::ArbitrationTaken;
    packet.fields = {message_sequence_field(++leg.floor_sequence), transmitting_user_field(notice.participant),
                     permission_to_request_field(!leg.session->broadcast)};
    for (auto &[dialog, other] : legs_)
      if (other->session == leg.session && other->user == notice.participant) {
        packet.fields.push_back(audio_ssrc_field(other->audio_ssrc));
        packet.fields.push_back(video_ssrc_field(other->video_ssrc));
        // TS 24.581 clauses 4.1.1.2 and 9.2.16: with reception control, a member is told of the new
        // transmission and receives it once it accepts (Receive Media Request).
        if (reception_control()) {
          leg.receiving = false;
          send_transmission({Type::MediaReceptionNotification,
                             false,
                             leg.remote->floor_ssrc,
                             {user_id_field(notice.participant), audio_ssrc_field(other->audio_ssrc),
                              video_ssrc_field(other->video_ssrc)}},
                            leg);
        }
      }
    break;
  case FloorNoticeKind::QueuePosition:
    packet.type = Type::QueuePositionInfo;
    packet.fields = {queue_info_field(notice.queue_position, notice.priority)};
    break;
  case FloorNoticeKind::Denied:
    packet.type = Type::Rejected;
    packet.fields = {reject_cause_field(notice.reject_cause)};
    break;
  case FloorNoticeKind::Revoke:
    packet.type = Type::Revoked;
    packet.fields = {reject_cause_field(notice.reject_cause)};
    break;
  case FloorNoticeKind::Idle:
    // TS 24.581 clause 6.3.4.3.2: nobody transmits; every participant may request.
    leg.floor_granted = false;
    packet.type = Type::Idle;
    packet.fields = {message_sequence_field(++leg.floor_sequence)};
    break;
  }
  send_transmission(packet, leg);
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2 with TS 33.180 clause 9.4: encode a transmission control message and send it to the
// participant, as SRTCP when the call's transmission control is protected.
void McvideoServer::send_transmission(const mcx::transmission::Packet &packet, Leg &leg) {
  auto bytes = mcx::transmission::encode(packet);
  if (floor_protected(leg)) {
    auto *user = by_id(leg.user);
    auto *keys = user ? floor_keys(*user) : nullptr;
    if (!keys || !keys->floor_ready()) {
      stop_unkeyed_leg(leg, "transmission control security unavailable or expired");
      return;
    }
    try {
      bytes = keys->protect_floor(bytes);
    } catch (const std::exception &error) {
      stop_unkeyed_leg(leg, error.what());
      return;
    }
  }
  leg.floor->send(bytes, leg.remote->floor_address, leg.remote->floor_port);
  event("transmission_control_sent", {{"user_id", leg.user}, {"subtype", bytes[0] & 0x1f}});
}

//------------------------------------------------------------------------------
// Helper: the leg of the session's transmitting participant, or nullptr.
McvideoServer::Leg *McvideoServer::transmitter_leg(const std::shared_ptr<Session> &session) {
  const auto owner = session->arbitrator->owner();
  for (auto &[dialog, other] : legs_)
    if (owner && other->session == session && other->user == *owner) return other.get();
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.581 table 9.2.3.1-1: the User ID and SSRC fields naming the session's transmitter (none when idle).
std::vector<FloorField> McvideoServer::transmitter_fields(const std::shared_ptr<Session> &session) {
  using namespace mcx::transmission;
  const auto *transmitter = transmitter_leg(session);
  if (!transmitter) return {};
  return {transmitting_user_field(transmitter->user), audio_ssrc_field(transmitter->audio_ssrc),
          video_ssrc_field(transmitter->video_ssrc)};
}

//------------------------------------------------------------------------------
// TS 24.581 clauses 6.3.4 and 6.3.5: a transmission control message from a participant (Transmission Request,
// Transmission Release, Transmission End Request, Receive Media Request, ...).
void McvideoServer::transmission_packet(Leg &leg, const Datagram &datagram) {
  using namespace mcx::transmission;
  if (!eligible(leg) || !UdpSocket::matches(datagram.source, leg.remote->floor_address, leg.remote->floor_port)) return;
  if (wire_ssrc(datagram.bytes, true) != leg.local.floor_ssrc) return;
  auto *keys = [&]() -> ProtectedCall * {
    auto *served = by_id(leg.user);
    return served ? floor_keys(*served) : nullptr;
  }();
  if (floor_protected(leg) && !keys) throw std::runtime_error("transmission control key unavailable");
  const auto packet = decode(floor_protected(leg) ? keys->unprotect_floor(datagram.bytes) : datagram.bytes);
  if (packet.ssrc != leg.local.floor_ssrc) return;
  if (!from_participant(packet.type)) throw std::runtime_error("transmission control message not sent by participants");
  // The User ID names the sender, except in a remote request (TS 24.581 clauses 9.2.22 and 9.2.24),
  // where it names the user whose transmission is asked for.
  const bool remote = packet.type == Type::RemoteRequest || packet.type == Type::RemoteCancelRequest;
  if (const auto *user = find(packet, Field::UserId); user && !remote && read_user_id(*user) != leg.user)
    throw std::runtime_error("transmission control identity mismatch");
  const auto session = leg.session;
  auto &arbitrator = *session->arbitrator;
  switch (packet.type) {
  case Type::Request: {
    if (!session->private_call && !session->adhoc && !member(group_profile(session->group), leg.user)) {
      disconnect_user(leg.user, session);
      return;
    }
    std::uint8_t priority = 0;
    if (const auto *field = find(packet, Field::Priority))
      priority = leg.local.floor_priority ? std::min(read_priority(*field), *leg.local.floor_priority) : 0;
    // TS 24.581 clause 4.1.1.2: a request of a user in the emergency (or imminent peril)
    // state of the call pre-empts a normal transmission, as for floor control.
    const auto &current_priority = call_priority(*session);
    const bool emergency_request = current_priority.emergency_users.contains(leg.user);
    const bool imminent_request = !current_priority.emergency && current_priority.imminent_users.contains(leg.user);
    const std::uint8_t preemptive = emergency_request ? 3 : imminent_request ? 2 : 0;
    if (arbitrator.owner() == leg.user)
      send_notice(leg, {FloorNoticeKind::Granted, leg.user, leg.user, 0, leg.granted_priority});
    else
      notices(*session, arbitrator.request(leg.user, monotonic_ms(), priority,
                                           leg.local.queueing && leg.remote->queueing, preemptive));
    event("transmission_requested",
          {{"user_id", leg.user}, {"owner", arbitrator.owner().value_or("")}, {"preemptive", preemptive}});
    break;
  }
  case Type::Release:
    notices(*session, arbitrator.release(leg.user, monotonic_ms()));
    event("transmission_released", {{"user_id", leg.user}});
    break;
  case Type::EndRequest:
    // TS 24.581 clauses 9.2.20 and 9.2.21: the transmitter ends its transmission.
    send_transmission({Type::EndResponse, false, leg.remote->floor_ssrc, transmitter_fields(session)}, leg);
    if (arbitrator.owner() == leg.user) notices(*session, arbitrator.release(leg.user, monotonic_ms()));
    event("transmission_ended", {{"user_id", leg.user}});
    break;
  case Type::ReceiveMediaRequest: {
    // TS 24.581 clauses 9.2.14 and 9.2.15: a member accepts the current transmission, or is told why not.
    auto fields = transmitter_fields(session);
    if (fields.empty() || arbitrator.owner() == leg.user) {
      fields.insert(fields.begin(), reject_cause_field(fields.empty() ? 3 : 255));
    } else {
      leg.receiving = true;
    }
    send_transmission({Type::ReceiveMediaResponse, false, leg.remote->floor_ssrc, std::move(fields)}, leg);
    event("reception_requested", {{"user_id", leg.user}, {"accepted", leg.receiving}});
    break;
  }
  case Type::ReceptionEndRequest:
    // TS 24.581 clauses 9.2.26 and 9.2.27: the member stops receiving the transmission.
    leg.receiving = false;
    send_transmission({Type::ReceptionEndResponse, false, leg.remote->floor_ssrc, transmitter_fields(session)}, leg);
    event("reception_ended", {{"user_id", leg.user}});
    break;
  case Type::QueuePositionRequest: send_notice(leg, arbitrator.queue_position(leg.user)); break;
  case Type::RemoteRequest:
  case Type::RemoteCancelRequest: remote_transmission(leg, packet); break;
  case Type::Ack: break;
  default:
    event("transmission_control_ignored", {{"user_id", leg.user}, {"type", static_cast<int>(packet.type)}});
    break;
  }
}

//------------------------------------------------------------------------------
// TS 23.281 clauses 7.7.1.3.7 and 7.7.1.3.6.3 with TS 24.581 clauses 9.2.22 to 9.2.25: an authorised
// user asks the transmission control server to start, or to end, another
// participant's transmission. A start is arbitrated as that participant's own
// request would be (grant, deny or queue); an end revokes its grant with cause #5.
// The requester is the sender of the request: the Remote ID field has no field ID
// in TS 24.581 table 9.2.3.1-1. The response carries a Result field (TS 24.581 clause 9.2.3.17).
void McvideoServer::remote_transmission(Leg &leg, const mcx::transmission::Packet &packet) {
  using namespace mcx::transmission;
  const bool start = packet.type == Type::RemoteRequest;
  const auto session = leg.session;
  auto &arbitrator = *session->arbitrator;
  const auto *field = find(packet, Field::UserId);
  const auto target = field ? read_user_id(*field) : std::string{};
  Leg *target_leg = nullptr;
  for (auto &[dialog, other] : legs_)
    if (other->session == session && other->user == target && other.get() != &leg && eligible(*other))
      target_leg = other.get();
  // TS 24.484: <allow-revoke-transmit> authorises ending another user's transmission;
  // the MCVideo profile has no element for starting one, so the project profile's
  // "allow_remote_transmit" does (tests/mcvideo/MCVIDEO_PULL_PUSH_TEST.md).
  bool authorised = false;
  try {
    authorised = user_profile(leg.user).value(start ? "allow_remote_transmit" : "allow_revoke_transmit", false);
  } catch (const std::exception &) {
    authorised = false; // no profile: the right is not granted
  }
  bool done = false;
  std::string reason;
  if (!authorised)
    reason = "not authorised";
  else if (!target_leg)
    reason = "no such participant";
  else if (start) {
    if (arbitrator.owner() != target)
      notices(*session, arbitrator.request(target, monotonic_ms(), 0,
                                           target_leg->local.queueing && target_leg->remote->queueing, 0));
    done = arbitrator.owner() == target;
    if (!done) reason = "not granted";
  } else if (arbitrator.owner() != target) {
    reason = "not transmitting";
  } else {
    // Cause #5 (TS 24.581 clause 9.2.10.2): the participant's permission to send is revoked.
    send_notice(*target_leg, {FloorNoticeKind::Revoke, target, target, 5});
    notices(*session, arbitrator.release(target, monotonic_ms()));
    done = true;
  }
  send_transmission(
      {start ? Type::RemoteResponse : Type::RemoteCancelResponse, false, leg.remote->floor_ssrc, {result_field(done)}},
      leg);
  event(start ? "remote_transmission_requested" : "remote_transmission_cancelled",
        {{"user_id", leg.user}, {"target", target}, {"result", done}, {"reason", reason}});
}

//------------------------------------------------------------------------------
// TS 24.581 clause 6.4.2: the participating function passes transmission control on
// unchanged. A Remote Transmission (cancel) request from its user is checked first:
// the requester's right is checked here, at its participating function, so an
// unauthorised request is answered with Result 0 (TS 23.281 clause 7.7.1.3.7 leaves the check to "the MCVideo
// server").
bool McvideoServer::refuse_remote_request(Relay &relay, UdpSocket &socket, std::span<const std::uint8_t> plain,
                                          ProtectedCall *csk) {
  using namespace mcx::transmission;
  Packet packet;
  try {
    packet = decode(plain);
  } catch (const std::exception &) {
    return false;
  }
  if (packet.type != Type::RemoteRequest && packet.type != Type::RemoteCancelRequest) return false;
  const bool start = packet.type == Type::RemoteRequest;
  bool authorised = false;
  try {
    authorised = user_profile(relay.user).value(start ? "allow_remote_transmit" : "allow_revoke_transmit", false);
  } catch (const std::exception &) {
    // No user profile: not authorised.
  }
  // Without the client's media (relay_packets checks it too) there is nowhere to answer: the request is dropped.
  if (!relay.client_remote) return true;
  if (authorised) return false;
  const auto &client = *relay.client_remote;
  const auto reply = encode(
      {start ? Type::RemoteResponse : Type::RemoteCancelResponse, false, client.floor_ssrc, {result_field(false)}});
  socket.send(csk ? csk->protect_floor(reply) : reply, client.floor_address, client.floor_port);
  event(start ? "remote_transmission_requested" : "remote_transmission_cancelled",
        {{"user_id", relay.user}, {"result", false}, {"reason", "not authorised"}, {"relayed", false}});
  return true;
}

} // namespace mcx
