//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCVideo transmission control message coding: the RTCP APP packets MCV0, MCV1 and MCV2 of TS 24.581
// clause 9.2 and their specific fields (clause 9.2.3).
//
// Specifications: TS 24.581 V19.2.0 (Rel-19), RFC 3550.

#include "mcx/transmission.hpp"

#include <array>
#include <stdexcept>
#include <string>
#include <utility>

namespace mcx::transmission {
namespace {
constexpr std::array<std::uint8_t, 4> mcv0{'M', 'C', 'V', '0'}, mcv1{'M', 'C', 'V', '1'}, mcv2{'M', 'C', 'V', '2'};

struct Code {
  Type type;
  int name;             // 0, 1 or 2 for MCV0, MCV1, MCV2
  std::uint8_t subtype; // the four bits after x (TS 24.581 tables 9.2.2.1-1 to 9.2.2.1-3)
};

// TS 24.581 tables 9.2.2.1-1 to 9.2.2.1-3: void entries (MCV0 x0101, MCV1 x1001) are absent and refused.
constexpr Code codes[] = {
    {Type::Request, 0, 0},
    {Type::Release, 0, 2},
    {Type::QueuePositionRequest, 0, 3},
    {Type::ReceiveMediaRequest, 0, 4},
    {Type::RemoteRequest, 0, 7},
    {Type::RemoteCancelRequest, 0, 8},
    {Type::Granted, 1, 0},
    {Type::Rejected, 1, 1},
    {Type::ArbitrationTaken, 1, 2},
    {Type::ArbitrationRelease, 1, 3},
    {Type::Revoked, 1, 4},
    {Type::QueuePositionInfo, 1, 5},
    {Type::MediaTransmissionNotification, 1, 6},
    {Type::ReceiveMediaResponse, 1, 7},
    {Type::MediaReceptionNotification, 1, 8},
    {Type::CancelRequestNotify, 1, 10},
    {Type::RemoteResponse, 1, 11},
    {Type::RemoteCancelResponse, 1, 12},
    {Type::ReceptionOverrideNotification, 1, 13},
    {Type::EndNotify, 1, 14},
    {Type::Idle, 1, 15},
    {Type::EndRequest, 2, 0},
    {Type::EndResponse, 2, 1},
    {Type::ReceptionEndRequest, 2, 2},
    {Type::ReceptionEndResponse, 2, 3},
    {Type::Ack, 2, 4},
};

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.2.1: the message name and subtype of a transmission control message.
const Code &code_of(Type type) {
  for (const auto &code : codes)
    if (code.type == type) return code;
  throw std::runtime_error("unknown transmission control message");
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.2.1: the RTCP APP name (MCV0, MCV1 or MCV2) of a message table.
const std::array<std::uint8_t, 4> &name_of(int name) { return name == 0 ? mcv0 : name == 1 ? mcv1 : mcv2; }

//------------------------------------------------------------------------------
// Helper: refuses a field whose value is not exactly `size` octets long.
void require_length(const FloorField &field, std::size_t size, const char *what) {
  if (field.value.size() != size) throw std::runtime_error(std::string("invalid ") + what + " field");
}

//------------------------------------------------------------------------------
// TS 24.581 clauses 9.2.3.16 and 9.2.3.23: reads an SSRC field (length 6: the RFC 3550 SSRC and 16 spare bits
// set to zero).
std::uint32_t ssrc_value(const FloorField &field, Field id) {
  if (field.id != static_cast<std::uint8_t>(id) || field.value.size() != 6 || field.value[4] || field.value[5])
    throw std::runtime_error("invalid SSRC field");
  return (std::uint32_t(field.value[0]) << 24) | (std::uint32_t(field.value[1]) << 16) |
         (std::uint32_t(field.value[2]) << 8) | field.value[3];
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3: checks the coding of the fields whose size is fixed or which must not be empty.
void validate(const FloorField &field) {
  switch (static_cast<Field>(field.id)) {
  case Field::Priority:
  case Field::ReceptionPriority:
    require_length(field, 2, "priority");
    if (field.value[1]) throw std::runtime_error("invalid priority spare bits");
    break;
  case Field::Duration:
  case Field::QueueInfo:
  case Field::QueueSize:
  case Field::MessageSequence:
  case Field::Source:
  case Field::Indicator: require_length(field, 2, "two-octet"); break;
  case Field::PermissionToRequest:
    require_length(field, 2, "permission");
    if (field.value[0] || field.value[1] > 1) throw std::runtime_error("invalid permission field");
    break;
  case Field::ReceptionMode:
    require_length(field, 2, "reception mode");
    if (field.value[0] || field.value[1] > 1) throw std::runtime_error("invalid reception mode field");
    break;
  case Field::RejectCause:
    if (field.value.size() < 2) throw std::runtime_error("invalid reject cause field");
    break;
  case Field::Result:
    // TS 24.581 clause 9.2.3.17: an 8-bit value (0 rejected, 1 granted) and 8 spare bits, as for the priority.
    require_length(field, 2, "result");
    if (field.value[0] > 1 || field.value[1]) throw std::runtime_error("invalid result field");
    break;
  case Field::TransmittingUserId:
  case Field::UserId:
  case Field::QueuedUserId:
  case Field::OverridingId:
  case Field::OverriddenId:
  case Field::GroupIdentity:
  case Field::FunctionalAlias:
    if (field.value.empty()) throw std::runtime_error("empty identity field");
    break;
  case Field::AudioSsrc:
  case Field::VideoSsrc: (void)ssrc_value(field, static_cast<Field>(field.id)); break;
  default: break; // other and unknown fields are carried as they are (TS 24.581 clause 9.1.4)
  }
}

//------------------------------------------------------------------------------
// TS 24.581 clauses 9.2.3.16 and 9.2.3.23: builds an SSRC field (the RFC 3550 SSRC and 16 spare bits).
FloorField ssrc_field(Field id, std::uint32_t ssrc) {
  return {static_cast<std::uint8_t>(id),
          {std::uint8_t(ssrc >> 24), std::uint8_t(ssrc >> 16), std::uint8_t(ssrc >> 8), std::uint8_t(ssrc), 0, 0}};
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.581 tables 9.2.2.1-1 and 9.2.2.1-3: whether the transmission participant sends this message.
bool from_participant(Type type) { return code_of(type).name == 0 || code_of(type).name == 2; }

//------------------------------------------------------------------------------
// TS 24.581 tables 9.2.2.1-2 and 9.2.2.1-3: whether the transmission control server sends this message.
bool from_server(Type type) { return code_of(type).name == 1 || code_of(type).name == 2; }

//------------------------------------------------------------------------------
// TS 24.581 clauses 9.1.2 and 9.2.2.1: encodes a transmission control message as an RTCP APP packet, the x bit
// of the subtype asking for a Transmission control ack.
std::vector<std::uint8_t> encode(const Packet &packet) {
  const auto &code = code_of(packet.type);
  // TS 24.581 table 9.2.2.1-3 gives the Transmission control ack a fixed subtype without x.
  if (packet.ack_required && packet.type == Type::Ack) throw std::runtime_error("an ack cannot ask for an ack");
  for (const auto &field : packet.fields) validate(field);
  return encode_app({static_cast<std::uint8_t>(code.subtype | (packet.ack_required ? 0x10 : 0)), packet.ssrc,
                     name_of(code.name), packet.fields});
}

//------------------------------------------------------------------------------
// TS 24.581 clauses 9.1.2 and 9.2.2.1: decodes an RTCP APP packet as a transmission control message; unknown
// and void subtypes are refused (clause 9.1.4 step 1: the whole message is ignored), fields are checked (clause
// 9.2.3). Clause 9.1.4 steps 2 and 3: unspecified fields are kept for the caller to ignore, and a syntactically
// incorrect field is ignored (left out), the rest of the message being processed.
Packet decode(std::span<const std::uint8_t> bytes) {
  auto app = decode_app(bytes);
  int name = -1;
  for (int candidate = 0; candidate < 3; ++candidate)
    if (app.name == name_of(candidate)) name = candidate;
  if (name < 0) throw std::runtime_error("RTCP APP packet is not MCVideo transmission control");
  Packet packet;
  packet.ack_required = (app.subtype & 0x10) != 0;
  const std::uint8_t subtype = app.subtype & 0x0f;
  bool known = false;
  for (const auto &code : codes)
    if (code.name == name && code.subtype == subtype) {
      packet.type = code.type;
      known = true;
    }
  if (!known) throw std::runtime_error("unknown or void transmission control subtype");
  if (packet.type == Type::Ack && packet.ack_required) throw std::runtime_error("an ack cannot ask for an ack");
  packet.ssrc = app.ssrc;
  for (auto &field : app.fields) {
    try {
      validate(field);
    } catch (const std::runtime_error &) {
      continue; // clause 9.1.4 step 3: "ignore the syntactically incorrect optional fields"
    }
    packet.fields.push_back(std::move(field));
  }
  return packet;
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.23: builds the Video SSRC of the Transmitting User field.
FloorField video_ssrc_field(std::uint32_t ssrc) { return ssrc_field(Field::VideoSsrc, ssrc); }

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.23: reads the Video SSRC of the Transmitting User field.
std::uint32_t read_video_ssrc(const FloorField &field) { return ssrc_value(field, Field::VideoSsrc); }

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.6: builds the User Id of the Transmitting User field (the MCVideo ID).
FloorField transmitting_user_field(std::string_view mcvideo_id) {
  if (mcvideo_id.empty()) throw std::runtime_error("empty identity field");
  return {static_cast<std::uint8_t>(Field::TransmittingUserId), {mcvideo_id.begin(), mcvideo_id.end()}};
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.22: builds the Reception Mode field, '0' (automatic) or '1' (not automatic).
FloorField reception_mode_field(bool automatic) {
  return {static_cast<std::uint8_t>(Field::ReceptionMode), {0, static_cast<std::uint8_t>(automatic ? 0 : 1)}};
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.22: reads the Reception Mode field.
bool read_reception_mode(const FloorField &field) {
  if (field.id != static_cast<std::uint8_t>(Field::ReceptionMode)) throw std::runtime_error("not a reception mode");
  validate(field);
  return field.value[1] == 0;
}

//------------------------------------------------------------------------------
// TS 24.581 clause 6.3.6.3.3 step 1: automatic reception in a broadcast group call, a system call, an emergency call
// or an imminent peril call (step 1a), manual reception otherwise (step 1b). The server has no system call.
bool automatic_reception(bool reception_control, bool broadcast, bool emergency, bool imminent) {
  return !reception_control || broadcast || emergency || imminent;
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.13: the Media Transmission Notification, with the fields of table 9.2.13-1 that the
// transmission control server fills in on-network (no Track Info: no non-controlling function; the Functional Alias
// is not sent).
Packet media_transmission_notification(std::uint32_t ssrc, std::string_view transmitter, std::uint32_t audio_ssrc,
                                       std::uint32_t video_ssrc, bool permission_to_request,
                                       std::optional<std::uint16_t> indicator, bool automatic) {
  Packet packet{Type::MediaTransmissionNotification,
                false,
                ssrc,
                {transmitting_user_field(transmitter), audio_ssrc_field(audio_ssrc), video_ssrc_field(video_ssrc),
                 permission_to_request_field(permission_to_request)}};
  if (indicator) packet.fields.push_back(floor_indicator_field(*indicator));
  packet.fields.push_back(reception_mode_field(automatic));
  return packet;
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.6: reads the User Id of the Transmitting User field.
std::string read_transmitting_user(const FloorField &field) {
  if (field.id != static_cast<std::uint8_t>(Field::TransmittingUserId) || field.value.empty())
    throw std::runtime_error("invalid transmitting user field");
  return {field.value.begin(), field.value.end()};
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.17: builds the Result field (1 granted, 0 rejected).
FloorField result_field(bool success) {
  return {static_cast<std::uint8_t>(Field::Result), {std::uint8_t(success ? 1 : 0), 0}};
}

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.17: reads the Result field; true when granted.
bool read_result(const FloorField &field) {
  if (field.id != static_cast<std::uint8_t>(Field::Result)) throw std::runtime_error("invalid result field");
  validate(field);
  return field.value[0] == 1;
}

//------------------------------------------------------------------------------
// Helper: the first field of the packet with this field ID, or null.
const FloorField *find(const Packet &packet, Field id) {
  for (const auto &field : packet.fields)
    if (field.id == static_cast<std::uint8_t>(id)) return &field;
  return nullptr;
}


//------------------------------------------------------------------------------
// TS 24.581 clauses 11.1.1 and 11.2.1: the on-network transmission participant timers T100 to T104 and counters
// C100 to C104; a zero interval or limit is refused.
ParticipantTimers::ParticipantTimers(ParticipantTimerOptions options) : options_(options) {
  const auto &o = options_;
  if (!o.t100_request_ms || !o.t101_end_request_ms || !o.t102_queue_position_ms || !o.t103_receive_request_ms ||
      !o.t104_receive_release_ms || !o.c100_request || !o.c101_end_request || !o.c102_queue_position ||
      !o.c103_receive_request || !o.c104_receive_release)
    throw std::runtime_error("invalid transmission participant timer configuration");
}

//------------------------------------------------------------------------------
// Helper: (re)starts a timer for the request just sent with its counter initialised to 1.
void ParticipantTimers::start(std::optional<Pending> &slot, const Packet &packet, std::uint64_t now_ms) {
  slot = Pending{packet, now_ms, 1};
}

//------------------------------------------------------------------------------
// TS 24.581 clause 6.2.4: Transmission Request in 'U: has no permission to transmit' starts T100 and enters 'U:
// pending request to transmit' (clause 6.2.4.3.2); Transmission end request in 'U: pending request to transmit'
// (clause 6.2.4.4.7, T100 stopped), 'U: has permission to transmit' (clauses 6.2.4.5.3 and 6.2.4.5.5 step 4a) or
// 'U: queued transmission' (clause 6.2.4.9.4) starts T101 and enters 'U: pending end of transmission'; Queue
// Position Request in 'U: queued transmission' (clause 6.2.4.9.3), or in 'U: has permission to transmit' after a
// Transmission Revoked queueing the transmission (clause 6.2.4.5.5 step 4b), starts T102 in 'U: queued
// transmission'. TS 24.581 clause 6.2.5: Receive Media Request in 'U: reception controller' creates the basic
// reception instance and starts T103 (clause 6.2.5.3.3); Media reception end request in 'U: pending request to
// receive' (clause 6.2.5.4.6, T103 stopped) or 'U: has permission to receive' (clause 6.2.5.5.3) starts T104 and
// enters 'U: pending reception release'.
void ParticipantTimers::send(const Packet &packet, std::uint64_t now_ms) {
  if (!from_participant(packet.type)) throw std::runtime_error("not a transmission participant message");
  (void)encode(packet);
  if (state_ == ParticipantState::CallReleasing) return; // clause 6.2.4.7.2 step 1: no more control messages
  switch (packet.type) {
  case Type::Request:
    if (state_ != ParticipantState::NoPermission)
      throw std::runtime_error("transmission request is not valid in participant state");
    start(transmission_, packet, now_ms);
    state_ = ParticipantState::PendingRequest;
    break;
  case Type::EndRequest:
    if (state_ != ParticipantState::PendingRequest && state_ != ParticipantState::HasPermission &&
        state_ != ParticipantState::Queued)
      throw std::runtime_error("transmission end request is not valid in participant state");
    start(transmission_, packet, now_ms);
    state_ = ParticipantState::PendingEnd;
    break;
  case Type::QueuePositionRequest:
    if (state_ != ParticipantState::Queued && state_ != ParticipantState::HasPermission)
      throw std::runtime_error("queue position request is not valid in participant state");
    start(transmission_, packet, now_ms);
    state_ = ParticipantState::Queued;
    break;
  case Type::ReceiveMediaRequest:
    if (reception_ != ReceptionState::Idle && reception_ != ReceptionState::Terminated)
      throw std::runtime_error("receive media request is not valid in reception state");
    start(reception_timer_, packet, now_ms);
    reception_ = ReceptionState::PendingRequest;
    break;
  case Type::ReceptionEndRequest:
    if (reception_ != ReceptionState::PendingRequest && reception_ != ReceptionState::HasPermission)
      throw std::runtime_error("media reception end request is not valid in reception state");
    start(reception_timer_, packet, now_ms);
    reception_ = ReceptionState::PendingRelease;
    break;
  default: break; // acks and responses run no participant timer
  }
}

//------------------------------------------------------------------------------
// TS 24.581 clause 6.2.4.2.2 step 4: "a. shall start timer T100 (Transmission Request) and initialise counter C100
// (Transmission Request) to 1; b. shall enter the 'U: pending request to transmit' state", nothing being sent.
void ParticipantTimers::expect_implicit_request(const Packet &request, std::uint64_t now_ms) {
  if (request.type != Type::Request) throw std::runtime_error("implicit request needs a Transmission Request");
  if (state_ != ParticipantState::NoPermission)
    throw std::runtime_error("implicit transmission request is not valid in participant state");
  (void)encode(request);
  start(transmission_, request, now_ms);
  state_ = ParticipantState::PendingRequest;
}

//------------------------------------------------------------------------------
// TS 24.581 clauses 6.2.4 and 6.2.5: the received messages that stop a participant timer or change state (table
// 11.1.1-1 "Normal stop"). Messages with no procedure in the current state are discarded (clauses 6.2.4.1 and
// 6.2.5.1).
void ParticipantTimers::receive(const Packet &packet, std::uint64_t) {
  if (state_ == ParticipantState::CallReleasing) return;
  switch (packet.type) {
  case Type::Granted:
    // Clause 6.2.4.4.6 step 4 (stop T100) and clause 6.2.4.9.9 step 4 (stop T102): 'U: has permission to transmit'.
    if (state_ == ParticipantState::PendingRequest || state_ == ParticipantState::Queued) {
      transmission_.reset();
      state_ = ParticipantState::HasPermission;
    }
    break;
  case Type::Rejected:
    // Clause 6.2.4.4.2 steps 4 and 5: stop T100, 'U: has no permission to transmit'.
    if (state_ == ParticipantState::PendingRequest) {
      transmission_.reset();
      state_ = ParticipantState::NoPermission;
    }
    break;
  case Type::QueuePositionInfo:
    // Clause 6.2.4.4.5 step 4 with table 11.1.1-1 (T100 normal stop): 'U: queued transmission'; clause 6.2.4.9.2
    // step 3: stop T102, if running.
    if (state_ == ParticipantState::PendingRequest || state_ == ParticipantState::Queued) {
      transmission_.reset();
      state_ = ParticipantState::Queued;
    }
    break;
  case Type::CancelRequestNotify:
    // Clause 6.2.4.9.6 step 2: 'U: has no permission to transmit' (T102 no longer applies).
    if (state_ == ParticipantState::Queued) {
      transmission_.reset();
      state_ = ParticipantState::NoPermission;
    }
    break;
  case Type::EndResponse:
    // Clause 6.2.4.6.4 steps 4 and 5: stop T101, 'U: has no permission to transmit'.
    if (state_ == ParticipantState::PendingEnd) {
      transmission_.reset();
      state_ = ParticipantState::NoPermission;
    }
    break;
  case Type::EndRequest:
    // Clause 6.2.4.5.7 step 5: the server ends the permission; the caller sends the Transmission End Response.
    if (state_ == ParticipantState::HasPermission) state_ = ParticipantState::NoPermission;
    break;
  case Type::ReceiveMediaResponse:
    // Clause 6.2.5.4.5 (granted: stop T103, 'U: has permission to receive') and clause 6.2.5.4.2 (rejected: stop
    // T103, 'terminated'). The Result field (clause 9.2.15.1) decides; without one a Reject Cause means rejected.
    if (reception_ == ReceptionState::PendingRequest) {
      const auto *result = find(packet, Field::Result);
      const bool granted = result ? read_result(*result) : !find(packet, Field::RejectCause);
      reception_timer_.reset();
      reception_ = granted ? ReceptionState::HasPermission : ReceptionState::Terminated;
    }
    break;
  case Type::ReceptionEndResponse:
    // Clause 6.2.5.6.4 steps 4 and 5: stop T104, 'terminated'.
    if (reception_ == ReceptionState::PendingRelease) {
      reception_timer_.reset();
      reception_ = ReceptionState::Terminated;
    }
    break;
  case Type::ReceptionEndRequest:
    // Clause 6.2.5.5.5 step 8: the server ends the reception; the caller sends the Media reception end response.
    if (reception_ == ReceptionState::HasPermission) reception_ = ReceptionState::Terminated;
    break;
  default: break;
  }
}

//------------------------------------------------------------------------------
// TS 24.581 clauses 6.2.4.4.3, 6.2.4.6.2, 6.2.4.9.7, 6.2.5.4.3 and 6.2.5.6.2: on expiry less than the upper limit
// of its counter, a request is sent again, its timer restarted and its counter incremented. Clauses 6.2.4.4.4 and
// 6.2.4.6.3 (T100, T101 expired N times): 'U: has no permission to transmit'; clause 6.2.4.9.8 (T102 expired N
// times): a Transmission End Request is sent, T101 started and 'U: pending end of transmission' entered; clauses
// 6.2.5.4.4 and 6.2.5.6.3 (T103, T104 expired N times): 'terminated'.
std::vector<Packet> ParticipantTimers::tick(std::uint64_t now_ms) {
  std::vector<Packet> out;
  const auto expired = [now_ms](const Pending &pending, std::uint64_t interval) {
    return now_ms >= pending.sent_ms && now_ms - pending.sent_ms >= interval;
  };
  const auto retry = [&](Pending &pending) {
    ++pending.count;
    pending.sent_ms = now_ms;
    out.push_back(pending.packet);
  };

  if (transmission_) {
    const auto type = transmission_->packet.type;
    const auto interval = type == Type::Request      ? options_.t100_request_ms
                          : type == Type::EndRequest ? options_.t101_end_request_ms
                                                     : options_.t102_queue_position_ms;
    const auto limit = type == Type::Request      ? options_.c100_request
                       : type == Type::EndRequest ? options_.c101_end_request
                                                  : options_.c102_queue_position;
    if (expired(*transmission_, interval)) {
      if (transmission_->count < limit) {
        retry(*transmission_);
      } else {
        failed_.push_back(type);
        if (type == Type::QueuePositionRequest) {
          // Clause 6.2.4.9.8: no field is required of this Transmission end request (the Transmission Indicator of
          // clause 6.2.4.9.4 applies only to a broadcast call established as a normal call).
          const Packet end{Type::EndRequest, false, transmission_->packet.ssrc, {}};
          start(transmission_, end, now_ms);
          state_ = ParticipantState::PendingEnd;
          out.push_back(end);
        } else {
          transmission_.reset();
          state_ = ParticipantState::NoPermission;
        }
      }
    }
  }

  if (reception_timer_) {
    const auto type = reception_timer_->packet.type;
    const auto interval = type == Type::ReceiveMediaRequest ? options_.t103_receive_request_ms
                                                            : options_.t104_receive_release_ms;
    const auto limit =
        type == Type::ReceiveMediaRequest ? options_.c103_receive_request : options_.c104_receive_release;
    if (expired(*reception_timer_, interval)) {
      if (reception_timer_->count < limit) {
        retry(*reception_timer_);
      } else {
        failed_.push_back(type);
        reception_timer_.reset();
        reception_ = ReceptionState::Terminated;
      }
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: the request types whose counters reached their upper limit.
std::vector<Type> ParticipantTimers::take_failed() { return std::exchange(failed_, {}); }

//------------------------------------------------------------------------------
// TS 24.581 clause 6.2.4.7.2 ("shall stop sending transmission control messages ... shall enter the 'Call
// releasing' state") and clause 6.2.5.3.5 ("shall stop receiving reception control messages ... shall enter the
// 'Call releasing' state").
void ParticipantTimers::release() {
  transmission_.reset();
  reception_timer_.reset();
  state_ = ParticipantState::CallReleasing;
  reception_ = ReceptionState::CallReleasing;
}

} // namespace mcx::transmission
