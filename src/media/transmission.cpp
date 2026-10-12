// MCVideo transmission control message coding: the RTCP APP packets MCV0, MCV1 and MCV2 of TS 24.581
// clause 9.2 and their specific fields (clause 9.2.3).
//
// Specifications: TS 24.581 V19.2.0 (Rel-19), RFC 3550.

#include "mcx/transmission.hpp"

#include <array>
#include <stdexcept>
#include <string>

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
// and void subtypes are refused, fields are checked (clause 9.2.3).
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
  for (const auto &field : app.fields) validate(field);
  packet.fields = std::move(app.fields);
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

} // namespace mcx::transmission
