//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCPTT floor control: the RTCP APP packet coding shared with MCVideo transmission control, the floor control
// messages and fields of TS 24.380 clause 8.2, the Floor Ack retransmission, the on-network floor participant
// timers and states (TS 24.380 clause 6.2.4) and the floor control server arbitration (TS 24.380 clause 6.3.4).
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), RFC 3550.

#include "mcx/floor.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace mcx {
namespace {

constexpr std::uint8_t kRtcpVersion = 2;
constexpr std::uint8_t kRtcpApp = 204;
constexpr std::size_t kHeaderSize = 12;
constexpr std::size_t kMaximumPacketSize =
    (static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()) + 1) * 4;
constexpr std::array<std::uint8_t, 4> kName{'M', 'C', 'P', 'T'};

// TS 24.380 clause 8.2.10.2: Floor Revoke cause #2 (Media burst too long).
constexpr std::uint16_t revoke_cause_media_burst_too_long = 2;

//------------------------------------------------------------------------------
// Helper: reads a 16-bit value in network byte order.
std::uint16_t read_u16(std::span<const std::uint8_t> bytes) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) | bytes[1]);
}

//------------------------------------------------------------------------------
// Helper: reads a 32-bit value in network byte order.
std::uint32_t read_u32(std::span<const std::uint8_t> bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24) | (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]);
}

//------------------------------------------------------------------------------
// Helper: appends a 16-bit value in network byte order.
void append_u16(std::vector<std::uint8_t> &bytes, std::uint16_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 8));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

//------------------------------------------------------------------------------
// Helper: appends a 32-bit value in network byte order.
void append_u32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 24));
  bytes.push_back(static_cast<std::uint8_t>(value >> 16));
  bytes.push_back(static_cast<std::uint8_t>(value >> 8));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.2.2.1-1: the subtype of a floor control message, without the acknowledgement bit x.
std::uint8_t subtype(FloorType type) {
  switch (type) {
  case FloorType::Request:
  case FloorType::Granted:
  case FloorType::Taken:
  case FloorType::Deny:
  case FloorType::Release:
  case FloorType::Idle:
  case FloorType::Revoke:
  case FloorType::QueuePositionRequest:
  case FloorType::QueuePositionInfo:
  case FloorType::Ack: return static_cast<std::uint8_t>(type);
  }
  throw std::runtime_error("unsupported floor message type");
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.2.2.1-1: whether the message has the x bit to ask for a Floor Ack (Floor Granted, Floor Deny,
// Floor Release, Floor Idle, Floor Taken, Floor Queue Position Info).
bool may_request_ack(FloorType type) {
  switch (type) {
  case FloorType::Granted:
  case FloorType::Taken:
  case FloorType::Deny:
  case FloorType::Release:
  case FloorType::Idle:
  case FloorType::QueuePositionInfo: return true;
  default: return false;
  }
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.2.2.1-1: the floor control message of a received subtype, and its acknowledgement bit;
// unsupported subtypes and an x bit on a message without one are refused.
FloorType floor_type(std::uint8_t raw_subtype, bool &ack_required) {
  ack_required = (raw_subtype & 0x10) != 0;
  const auto base = static_cast<std::uint8_t>(raw_subtype & 0x0f);
  FloorType type;
  switch (base) {
  case 0: type = FloorType::Request; break;
  case 1: type = FloorType::Granted; break;
  case 2: type = FloorType::Taken; break;
  case 3: type = FloorType::Deny; break;
  case 4: type = FloorType::Release; break;
  case 5: type = FloorType::Idle; break;
  case 6: type = FloorType::Revoke; break;
  case 8: type = FloorType::QueuePositionRequest; break;
  case 9: type = FloorType::QueuePositionInfo; break;
  case 10: type = FloorType::Ack; break;
  default: throw std::runtime_error("unsupported floor message subtype");
  }
  if (ack_required && !may_request_ack(type)) {
    throw std::runtime_error("acknowledgement bit is invalid for floor message");
  }
  return type;
}

//------------------------------------------------------------------------------
// Helper: refuses a field whose ID or length differs from the expected ones.
void require_field(const FloorField &field, FloorFieldId id, std::size_t size) {
  if (field.id != static_cast<std::uint8_t>(id) || field.value.size() != size) {
    throw std::runtime_error("invalid floor field");
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3: checks the coding of the floor control specific fields by their field ID
// (table 8.2.3.1-2); other fields are carried as they are (clause 8.1.4).
void validate_field(const FloorField &field) {
  switch (field.id) {
  case 0:
    require_field(field, FloorFieldId::FloorPriority, 2);
    if (field.value[1] != 0) throw std::runtime_error("invalid priority spare bits");
    break;
  case 1: require_field(field, FloorFieldId::Duration, 2); break;
  case 2:
    if (field.value.size() < 2) throw std::runtime_error("invalid reject cause field");
    break;
  case 3:
    if (field.value.size() != 2) throw std::runtime_error("invalid queue info field");
    break;
  case 4:
  case 6:
  case 9:
    if (field.value.empty()) throw std::runtime_error("empty floor user identity");
    break;
  case 5:
    if (field.value.size() != 2 || read_u16(field.value) > 1) {
      throw std::runtime_error("invalid permission field");
    }
    break;
  case 7:
  case 8:
    if (field.value.size() != 2) throw std::runtime_error("invalid two-octet floor field");
    break;
  case 10: (void)read_source(field); break;
  case 12: (void)read_message_type(field); break;
  case 13: (void)read_floor_indicator(field); break;
  case 14: (void)read_audio_ssrc(field); break;
  default: break;
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.13: a Floor Ack carries one Source and one Message Type field, naming a message that can
// ask for an acknowledgement.
void validate_packet(const FloorPacket &packet) {
  if (packet.type != FloorType::Ack) return;
  const auto source_count =
      std::count_if(packet.fields.begin(), packet.fields.end(), [](const auto &field) { return field.id == 10; });
  const auto message_type_count =
      std::count_if(packet.fields.begin(), packet.fields.end(), [](const auto &field) { return field.id == 12; });
  if (source_count != 1 || message_type_count != 1) {
    throw std::runtime_error("Floor Ack requires one Source and one Message Type field");
  }
  const auto message_type =
      std::find_if(packet.fields.begin(), packet.fields.end(), [](const auto &field) { return field.id == 12; });
  if (!may_request_ack(read_message_type(*message_type))) {
    throw std::runtime_error("Floor Ack names a message that cannot request acknowledgement");
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.1.3: a field with its padding to a multiple of four octets.
std::size_t padded_size(std::size_t size) { return (size + 3) & ~std::size_t{3}; }

} // namespace

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.1.2 and 8.1.3 (TS 24.581 clauses 9.1.2 and 9.1.3, RFC 3550 section 6.7): encodes an RTCP
// APP packet whose application-dependent data are fields of ID, length (one octet below field ID 192, two
// octets from 192) and value, each padded to four octets.
std::vector<std::uint8_t> encode_app(const AppPacket &packet) {
  if (packet.subtype > 0x1f) throw std::runtime_error("RTCP APP subtype exceeds five bits");
  std::vector<std::uint8_t> bytes;
  bytes.reserve(kHeaderSize + packet.fields.size() * 4);
  bytes.push_back(static_cast<std::uint8_t>((kRtcpVersion << 6) | packet.subtype));
  bytes.push_back(kRtcpApp);
  bytes.push_back(0);
  bytes.push_back(0);
  append_u32(bytes, packet.ssrc);
  bytes.insert(bytes.end(), packet.name.begin(), packet.name.end());

  for (const auto &field : packet.fields) {
    const auto header_size = field.id < 192 ? std::size_t{2} : std::size_t{3};
    if ((field.id < 192 && field.value.size() > 255) ||
        field.value.size() > std::numeric_limits<std::uint16_t>::max()) {
      throw std::runtime_error("floor field is too large");
    }
    const auto encoded_size = padded_size(header_size + field.value.size());
    if (encoded_size > kMaximumPacketSize - bytes.size()) {
      throw std::runtime_error("floor packet is too large");
    }
    bytes.push_back(field.id);
    if (field.id < 192) {
      bytes.push_back(static_cast<std::uint8_t>(field.value.size()));
    } else {
      append_u16(bytes, static_cast<std::uint16_t>(field.value.size()));
    }
    bytes.insert(bytes.end(), field.value.begin(), field.value.end());
    while (bytes.size() % 4 != 0) bytes.push_back(0);
  }

  if (bytes.size() > kMaximumPacketSize) {
    throw std::runtime_error("floor packet is too large");
  }
  const auto words_minus_one = static_cast<std::uint16_t>(bytes.size() / 4 - 1);
  bytes[2] = static_cast<std::uint8_t>(words_minus_one >> 8);
  bytes[3] = static_cast<std::uint8_t>(words_minus_one);
  return bytes;
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.1.2 and 8.1.3 (TS 24.581 clauses 9.1.2 and 9.1.3, RFC 3550 section 6.7): decodes an RTCP
// APP packet (version 2, no padding bit, length matching) into its fields.
AppPacket decode_app(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < kHeaderSize || bytes.size() > kMaximumPacketSize || bytes.size() % 4 != 0) {
    throw std::runtime_error("invalid floor packet size");
  }
  if ((bytes[0] >> 6) != kRtcpVersion || (bytes[0] & 0x20) != 0) {
    throw std::runtime_error("invalid RTCP header");
  }
  if (bytes[1] != kRtcpApp) throw std::runtime_error("floor packet is not RTCP APP");
  const auto declared_size = (static_cast<std::size_t>(read_u16(bytes.subspan(2, 2))) + 1) * 4;
  if (declared_size != bytes.size()) throw std::runtime_error("RTCP length mismatch");

  AppPacket packet;
  packet.subtype = static_cast<std::uint8_t>(bytes[0] & 0x1f);
  packet.ssrc = read_u32(bytes.subspan(4, 4));
  std::copy(bytes.begin() + 8, bytes.begin() + 12, packet.name.begin());

  std::size_t offset = kHeaderSize;
  while (offset < bytes.size()) {
    const auto id = bytes[offset];
    const auto header_size = id < 192 ? std::size_t{2} : std::size_t{3};
    if (bytes.size() - offset < header_size) {
      throw std::runtime_error("truncated floor field header");
    }
    const auto length = id < 192 ? static_cast<std::size_t>(bytes[offset + 1])
                                 : static_cast<std::size_t>(read_u16(bytes.subspan(offset + 1, 2)));
    if (length > kMaximumPacketSize - header_size) {
      throw std::runtime_error("floor field is too large");
    }
    const auto field_size = padded_size(header_size + length);
    if (field_size > bytes.size() - offset) {
      throw std::runtime_error("truncated floor field value");
    }
    packet.fields.push_back({id,
                             {bytes.begin() + static_cast<std::ptrdiff_t>(offset + header_size),
                              bytes.begin() + static_cast<std::ptrdiff_t>(offset + header_size + length)}});
    offset += field_size;
  }
  return packet;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.2.1: encodes a floor control message as an RTCP APP packet named "MCPT".
std::vector<std::uint8_t> encode_floor(const FloorPacket &packet) {
  const auto base_subtype = subtype(packet.type);
  if (packet.ack_required && !may_request_ack(packet.type)) {
    throw std::runtime_error("acknowledgement bit is invalid for floor message");
  }
  validate_packet(packet);
  for (const auto &field : packet.fields) validate_field(field);
  return encode_app(
      {static_cast<std::uint8_t>(base_subtype | (packet.ack_required ? 0x10 : 0)), packet.ssrc, kName, packet.fields});
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.2.1: decodes an RTCP APP packet named "MCPT" as a floor control message.
FloorPacket decode_floor(std::span<const std::uint8_t> bytes) {
  auto app = decode_app(bytes);
  if (app.name != kName) {
    throw std::runtime_error("RTCP APP packet is not MCPT");
  }
  FloorPacket packet;
  packet.type = floor_type(app.subtype, packet.ack_required);
  packet.ssrc = app.ssrc;
  for (auto &field : app.fields) validate_field(field);
  packet.fields = std::move(app.fields);
  validate_packet(packet);
  return packet;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.8: builds the User ID field (an MCPTT ID).
FloorField user_id_field(std::string_view user_id) {
  if (user_id.empty()) throw std::runtime_error("empty floor user identity");
  return {static_cast<std::uint8_t>(FloorFieldId::UserId), {user_id.begin(), user_id.end()}};
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.8: reads the User ID field.
std::string read_user_id(const FloorField &field) {
  if (field.id != static_cast<std::uint8_t>(FloorFieldId::UserId) || field.value.empty()) {
    throw std::runtime_error("invalid user identity field");
  }
  return {field.value.begin(), field.value.end()};
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.2: builds the Floor Priority field (priority and a spare octet).
FloorField priority_field(std::uint8_t priority) {
  return {static_cast<std::uint8_t>(FloorFieldId::FloorPriority), {priority, 0}};
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.2: reads the Floor Priority field.
std::uint8_t read_priority(const FloorField &field) {
  require_field(field, FloorFieldId::FloorPriority, 2);
  if (field.value[1] != 0) throw std::runtime_error("invalid priority spare bits");
  return field.value[0];
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.3: builds the Duration field, in seconds.
FloorField duration_field(std::uint16_t seconds) {
  FloorField field{static_cast<std::uint8_t>(FloorFieldId::Duration), {}};
  append_u16(field.value, seconds);
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.3: the Duration field in seconds for a timer value in milliseconds, rounded up so that a
// running T2 is never announced as already expired, at most 65535.
FloorField duration_field_ms(std::uint64_t milliseconds) {
  return duration_field(static_cast<std::uint16_t>(std::min<std::uint64_t>((milliseconds + 999) / 1000, 65535)));
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.3: reads the Duration field.
std::uint16_t read_duration(const FloorField &field) {
  require_field(field, FloorFieldId::Duration, 2);
  return read_u16(field.value);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.4: builds the Reject Cause field: the cause code and the optional reject phrase.
FloorField reject_cause_field(std::uint16_t cause, std::string_view phrase) {
  FloorField field{static_cast<std::uint8_t>(FloorFieldId::RejectCause), {}};
  append_u16(field.value, cause);
  field.value.insert(field.value.end(), phrase.begin(), phrase.end());
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.4: reads the Reject Cause field.
RejectCause read_reject_cause(const FloorField &field) {
  if (field.id != static_cast<std::uint8_t>(FloorFieldId::RejectCause) || field.value.size() < 2) {
    throw std::runtime_error("invalid reject cause field");
  }
  return {read_u16(field.value), {field.value.begin() + 2, field.value.end()}};
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.16: builds the Audio SSRC of Granted Participant field.
FloorField audio_ssrc_field(std::uint32_t ssrc) {
  FloorField field{static_cast<std::uint8_t>(FloorFieldId::AudioSsrc), {}};
  append_u32(field.value, ssrc);
  // TS 24.380 clause 8.2.3.16 includes the two spare octets in field length 6.
  append_u16(field.value, 0);
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.16: reads the Audio SSRC of Granted Participant field (spare octets zero).
std::uint32_t read_audio_ssrc(const FloorField &field) {
  require_field(field, FloorFieldId::AudioSsrc, 6);
  if (field.value[4] != 0 || field.value[5] != 0) throw std::runtime_error("invalid audio SSRC spare bits");
  return read_u32(field.value);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.10: builds the Message Sequence Number field.
FloorField message_sequence_field(std::uint16_t sequence) {
  FloorField field{static_cast<std::uint8_t>(FloorFieldId::MessageSequence), {}};
  append_u16(field.value, sequence);
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.10: reads the Message Sequence Number field.
std::uint16_t read_message_sequence(const FloorField &field) {
  require_field(field, FloorFieldId::MessageSequence, 2);
  return read_u16(field.value);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.12: builds the Source field (0 floor participant, 1 participating, 2 controlling, 3
// non-controlling MCPTT function).
FloorField source_field(std::uint16_t source) {
  if (source > 3) throw std::runtime_error("invalid floor message source");
  FloorField field{static_cast<std::uint8_t>(FloorFieldId::Source), {}};
  append_u16(field.value, source);
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.12: reads the Source field; reserved values are refused.
std::uint16_t read_source(const FloorField &field) {
  require_field(field, FloorFieldId::Source, 2);
  const auto source = read_u16(field.value);
  if (source > 3) throw std::runtime_error("invalid floor message source");
  return source;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.14: builds the Message Type field naming the acknowledged message.
FloorField message_type_field(FloorType type) {
  return {static_cast<std::uint8_t>(FloorFieldId::MessageType), {subtype(type), 0}};
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.14: reads the Message Type field of a Floor Ack.
FloorType read_message_type(const FloorField &field) {
  require_field(field, FloorFieldId::MessageType, 2);
  if (field.value[1] != 0 || (field.value[0] & 0xe0) != 0 || (field.value[0] & 0x10) != 0) {
    throw std::runtime_error("invalid acknowledged message type");
  }
  bool ack_required = false;
  return floor_type(field.value[0], ack_required);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.21: the Location field with location type 0 (Not provided, table 8.2.3.21-3).
FloorField location_not_provided_field() { return {19, {0}}; }

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.6: builds the Granted Party's Identity field.
FloorField granted_party_identity_field(std::string_view identity) {
  auto field = user_id_field(identity);
  field.id = 4;
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.6: reads the Granted Party's Identity field.
std::string read_granted_party_identity(const FloorField &field) {
  if (field.id != 4 || field.value.empty()) throw std::runtime_error("invalid granted party identity");
  return {field.value.begin(), field.value.end()};
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.7: builds the Permission to Request the Floor field.
FloorField permission_to_request_field(bool permitted) { return {5, {0, static_cast<std::uint8_t>(permitted)}}; }

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.7: reads the Permission to Request the Floor field.
bool read_permission_to_request(const FloorField &field) {
  require_field(field, FloorFieldId::PermissionToRequest, 2);
  const auto value = read_u16(field.value);
  if (value > 1) throw std::runtime_error("invalid permission to request");
  return value == 1;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.15: builds the Floor Indicator field; bits J to P are reserved.
FloorField floor_indicator_field(std::uint16_t bitmap) {
  // J-P reserved. The floor control server's local policy decides which call
  // type bits combine (TS 24.380 clause 8.2.3.15): one of A-E, or B with D or E for an
  // emergency or imminent-peril broadcast group call.
  if ((bitmap & 0x7f) != 0) throw std::runtime_error("reserved floor indicator bits");
  const auto types = bitmap & 0xf800;
  if (types && (types & (types - 1)) && types != (0x4000 | 0x1000) && types != (0x4000 | 0x0800))
    throw std::runtime_error("conflicting floor call types");
  FloorField field{13, {}};
  append_u16(field.value, bitmap);
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.15: the call type bits of the Floor Indicator: A (normal), B (broadcast group call),
// D (emergency) or E (imminent peril).
std::uint16_t floor_call_type_bits(bool broadcast, bool emergency, bool imminent) {
  // Emergency takes precedence over imminent peril.
  const std::uint16_t priority = emergency ? 0x1000 : imminent ? 0x0800 : 0;
  if (broadcast) return 0x4000 | priority;
  return priority ? priority : 0x8000;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.15: reads the Floor Indicator field.
std::uint16_t read_floor_indicator(const FloorField &field) {
  require_field(field, FloorFieldId::FloorIndicator, 2);
  // Preserve reserved bits received for forward compatibility.
  return read_u16(field.value);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.5: builds the Queue Info field (queue position and queue priority).
FloorField queue_info_field(std::uint8_t position, std::uint8_t priority) { return {3, {position, priority}}; }

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.5: reads the Queue Info field.
QueueInfo read_queue_info(const FloorField &field) {
  require_field(field, FloorFieldId::QueueInfo, 2);
  return {field.value[0], field.value[1]};
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.9: builds the Queue Size field.
FloorField queue_size_field(std::uint16_t size) {
  FloorField field{7, {}};
  append_u16(field.value, size);
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.9: reads the Queue Size field.
std::uint16_t read_queue_size(const FloorField &field) {
  require_field(field, FloorFieldId::QueueSize, 2);
  return read_u16(field.value);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.11: builds the Queued User ID field.
FloorField queued_user_id_field(std::string_view identity) {
  auto field = user_id_field(identity);
  field.id = 9;
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.11: reads the Queued User ID field.
std::string read_queued_user_id(const FloorField &field) {
  if (field.id != 9 || field.value.empty()) throw std::runtime_error("invalid queued user identity");
  return {field.value.begin(), field.value.end()};
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.2.5 to 8.2.12: checks an on-network single-talker floor message: fields not repeated, the
// fields the procedures of clause 6.3.4 always include present (Floor Granted: Duration, Floor Priority, Audio
// SSRC; Floor Taken: Audio SSRC, Message Sequence Number; Floor Idle: Message Sequence Number; Floor Deny and
// Floor Revoke: Reject Cause; Floor Queue Position Info: Queue Info), and no User ID in Floor Granted or Taken.
void validate_on_network_floor(const FloorPacket &packet) {
  (void)encode_floor(packet);
  std::array<unsigned, 256> counts{};
  for (const auto &field : packet.fields) {
    if (++counts[field.id] > 1 && field.id <= 14) throw std::runtime_error("duplicate single-talker floor field");
  }
  const auto require = [&](FloorFieldId id) {
    if (counts[static_cast<std::uint8_t>(id)] != 1) throw std::runtime_error("missing on-network floor field");
  };
  switch (packet.type) {
  case FloorType::Granted:
    require(FloorFieldId::Duration);
    require(FloorFieldId::FloorPriority);
    require(FloorFieldId::AudioSsrc);
    break;
  case FloorType::Taken:
    require(FloorFieldId::AudioSsrc);
    require(FloorFieldId::MessageSequence);
    break;
  case FloorType::Idle: require(FloorFieldId::MessageSequence); break;
  case FloorType::Deny:
  case FloorType::Revoke: require(FloorFieldId::RejectCause); break;
  case FloorType::QueuePositionInfo: require(FloorFieldId::QueueInfo); break;
  default: break;
  }
  if ((packet.type == FloorType::Granted || packet.type == FloorType::Taken) && counts[6])
    throw std::runtime_error("User ID in Granted/Taken is off-network only");
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.10: accepts a Floor Taken or Floor Idle only when its Message Sequence Number is newer
// (modulo 65536) than the last one; a repeated or older one is discarded.
bool FloorSequenceTracker::accept(const FloorPacket &packet) {
  if (packet.type != FloorType::Taken && packet.type != FloorType::Idle) return true;
  const auto field =
      std::find_if(packet.fields.begin(), packet.fields.end(), [](const auto &candidate) { return candidate.id == 8; });
  if (field == packet.fields.end()) throw std::runtime_error("missing floor sequence");
  const auto current = read_message_sequence(*field);
  if (last_) {
    const auto delta = static_cast<std::uint16_t>(current - *last_);
    if (delta == 0 || delta >= 0x8000) return false;
  }
  last_ = current;
  return true;
}

//------------------------------------------------------------------------------
// Helper: a bounded retransmission of floor messages that asked for a Floor Ack (TS 24.380 clause 8.2.13), not
// the complete state machine.
FloorAckRetry::FloorAckRetry(std::uint32_t local_ssrc, std::uint32_t peer_ssrc, std::uint16_t peer_source,
                             std::uint64_t retry_ms, unsigned max_transmissions)
    : local_ssrc_(local_ssrc), peer_ssrc_(peer_ssrc), peer_source_(peer_source), retry_ms_(retry_ms),
      max_transmissions_(max_transmissions) {
  if (peer_source > 3 || retry_ms == 0 || max_transmissions == 0)
    throw std::runtime_error("invalid floor retry configuration");
}

//------------------------------------------------------------------------------
// Helper: records a sent message; one asking for a Floor Ack is kept until it is acknowledged.
void FloorAckRetry::send(const FloorPacket &packet, std::uint64_t now_ms) {
  (void)encode_floor(packet);
  if (packet.ssrc != local_ssrc_) throw std::runtime_error("unexpected local floor SSRC");
  std::erase_if(pending_, [&](const auto &entry) { return entry.packet.type == packet.type; });
  if (packet.ack_required) pending_.push_back({packet, now_ms, 1});
}

//------------------------------------------------------------------------------
// Helper: stops retransmitting messages of this type.
void FloorAckRetry::cancel(FloorType type) {
  std::erase_if(pending_, [&](const auto &entry) { return entry.packet.type == type; });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.13: a Floor Ack from the peer (its SSRC and Source) acknowledges the pending message
// named by its Message Type field.
bool FloorAckRetry::receive(const FloorPacket &ack) {
  if (ack.type != FloorType::Ack || ack.ssrc != peer_ssrc_) return false;
  validate_on_network_floor(ack);
  const auto source =
      std::find_if(ack.fields.begin(), ack.fields.end(), [](const auto &candidate) { return candidate.id == 10; });
  const auto type =
      std::find_if(ack.fields.begin(), ack.fields.end(), [](const auto &candidate) { return candidate.id == 12; });
  if (read_source(*source) != peer_source_) return false;
  const auto size = pending_.size();
  std::erase_if(pending_, [&](const auto &entry) { return entry.packet.type == read_message_type(*type); });
  return size != pending_.size();
}

//------------------------------------------------------------------------------
// Helper: retransmits the unacknowledged messages due; after the last transmission the type is reported failed.
std::vector<FloorPacket> FloorAckRetry::tick(std::uint64_t now_ms) {
  std::vector<FloorPacket> packets;
  for (auto it = pending_.begin(); it != pending_.end();) {
    if (now_ms < it->sent_at || now_ms - it->sent_at < retry_ms_) {
      ++it;
      continue;
    }
    if (it->count >= max_transmissions_) {
      failed_.push_back(it->packet.type);
      it = pending_.erase(it);
    } else {
      packets.push_back(it->packet);
      it->sent_at = now_ms;
      ++it->count;
      ++it;
    }
  }
  return packets;
}

//------------------------------------------------------------------------------
// Helper: the message types whose transmissions all went unacknowledged.
std::vector<FloorType> FloorAckRetry::take_failed() { return std::exchange(failed_, {}); }

//------------------------------------------------------------------------------
// TS 24.380 clauses 11.1.1 and 11.2.1: the on-network floor participant timers T100, T101, T103, T104 and T132
// and their counters.
FloorParticipantTimers::FloorParticipantTimers(FloorParticipantTimerOptions options) : options_(options) {
  if (!options_.request_retry_ms || !options_.release_retry_ms || !options_.queue_retry_ms ||
      !options_.queued_grant_action_ms || !options_.max_transmissions)
    throw std::runtime_error("invalid participant floor timer configuration");
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4.3.5: in 'U: has no permission', a Floor Request starts T101 and enters 'U: pending
// Request'; clauses 6.2.4.4.8, 6.2.4.5.3 and 6.2.4.9.6: a Floor Release starts T100 and enters 'U: pending
// Release'; clause 6.2.4.9.9: in 'U: queued' with T132 not running, a Floor Queue Position Request starts T104.
void FloorParticipantTimers::send(const FloorPacket &packet, std::uint64_t now_ms) {
  (void)encode_floor(packet);
  switch (packet.type) {
  case FloorType::Request:
    if (state_ != FloorParticipantState::NoPermission)
      throw std::runtime_error("floor request is not valid in participant state");
    state_ = FloorParticipantState::PendingRequest;
    break;
  case FloorType::Release:
    state_ = FloorParticipantState::PendingRelease;
    queued_granted_at_.reset();
    break;
  case FloorType::QueuePositionRequest:
    if (state_ != FloorParticipantState::Queued || queued_granted_at_)
      throw std::runtime_error("queue position request is not valid in participant state");
    break;
  default: throw std::runtime_error("unsupported participant timer message");
  }
  local_ssrc_ = packet.ssrc;
  pending_ = packet;
  transmissions_ = 1;
  last_sent_ms_ = now_ms;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.4: the terminating client of a remotely initiated ambient listening call, which the
// originator's implicit request asks the floor to be granted to, waits for Floor Granted in 'U: pending Request'
// (TS 24.380 clause 6.2.4.4.2 step 1c). It sent no Floor Request, so no T101 runs.
void FloorParticipantTimers::expect_implicit_grant() {
  if (state_ != FloorParticipantState::NoPermission)
    throw std::runtime_error("implicit floor request is not valid in participant state");
  state_ = FloorParticipantState::PendingRequest;
  pending_.reset();
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4.2.2 step 4: an MCPTT call initiated with an implicit floor request that the 200 (OK)
// accepted: "a. shall start timer T101 (Floor Request) and initialise counter C101 (Floor Request) to 1; b. shall
// enter the 'U: pending Request' state". Nothing is sent now; on T101 expiry tick() sends `request`, the Floor
// Request of clause 6.2.4.4.5, and after C101 expiries enters 'U: has no permission' (clause 6.2.4.4.6).
void FloorParticipantTimers::expect_implicit_grant(const FloorPacket &request, std::uint64_t now_ms) {
  if (request.type != FloorType::Request) throw std::runtime_error("implicit floor request needs a Floor Request");
  (void)encode_floor(request);
  expect_implicit_grant();
  local_ssrc_ = request.ssrc;
  pending_ = request;
  transmissions_ = 1;
  last_sent_ms_ = now_ms;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4: the participant's handling of received floor messages: Floor Granted in 'U: pending
// Request' (clause 6.2.4.4.2) and in 'U: queued' (clause 6.2.4.9.4, start T132); Floor Deny (clauses 6.2.4.4.4
// and 6.2.4.9.5); Floor Queue Position Info (clauses 6.2.4.4.9 and 6.2.4.9.7); Floor Taken (clauses 6.2.4.4.11
// and 6.2.4.6.5); Floor Idle (clauses 6.2.4.6.4 and 6.2.4.9.8).
void FloorParticipantTimers::receive(const FloorPacket &packet, std::uint64_t now_ms) {
  validate_on_network_floor(packet);
  switch (packet.type) {
  case FloorType::Granted:
    if (state_ == FloorParticipantState::PendingRequest) {
      state_ = FloorParticipantState::HasPermission;
      pending_.reset();
      last_remote_media_.reset();
    } else if (state_ == FloorParticipantState::Queued) {
      pending_.reset();
      // Retransmitted grants must not postpone the user action deadline.
      if (!queued_granted_at_) queued_granted_at_ = now_ms;
      last_remote_media_.reset();
    }
    break;
  case FloorType::Deny:
    if (state_ == FloorParticipantState::PendingRequest || state_ == FloorParticipantState::Queued) {
      state_ = FloorParticipantState::NoPermission;
      pending_.reset();
      queued_granted_at_.reset();
    }
    break;
  case FloorType::QueuePositionInfo:
    if (state_ == FloorParticipantState::PendingRequest || state_ == FloorParticipantState::Queued) {
      const auto field = std::find_if(packet.fields.begin(), packet.fields.end(),
                                      [](const auto &candidate) { return candidate.id == 3; });
      const bool queued = read_queue_info(*field).position != 254;
      if (state_ == FloorParticipantState::PendingRequest)
        state_ = queued ? FloorParticipantState::Queued : FloorParticipantState::NoPermission;
      pending_.reset();
    }
    break;
  case FloorType::Taken:
    media_received(now_ms);
    if (state_ == FloorParticipantState::PendingRequest || state_ == FloorParticipantState::PendingRelease) {
      state_ = FloorParticipantState::NoPermission;
      pending_.reset();
    }
    break;
  case FloorType::Idle:
    last_remote_media_.reset();
    if (state_ == FloorParticipantState::PendingRelease || state_ == FloorParticipantState::Queued) {
      state_ = FloorParticipantState::NoPermission;
      queued_granted_at_.reset();
      pending_.reset();
    }
    break;
  default: break;
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4.3.4: received RTP media (re)starts T103 (End of RTP media), when it is used.
void FloorParticipantTimers::media_received(std::uint64_t now_ms) {
  if (options_.media_idle_ms) last_remote_media_ = now_ms;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4.9.12: in 'U: queued' with T132 running, the user accepts the granted floor: stop T132
// and enter 'U: has permission'.
bool FloorParticipantTimers::confirm_queued_grant() {
  if (!queued_granted_at_ || state_ != FloorParticipantState::Queued) return false;
  queued_granted_at_.reset();
  state_ = FloorParticipantState::HasPermission;
  return true;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4: the participant timers: T103 expiry (clause 6.2.4.3.6), T132 expiry (clause
// 6.2.4.9.13), T101 expiry (clauses 6.2.4.4.5 and 6.2.4.4.6), T100 expiry (clauses 6.2.4.6.2 and 6.2.4.6.3) and
// T104 expiry (clauses 6.2.4.9.10 and 6.2.4.9.11).
std::vector<FloorPacket> FloorParticipantTimers::tick(std::uint64_t now_ms) {
  const auto elapsed = [now_ms](std::uint64_t start, std::uint64_t interval) {
    return now_ms >= start && now_ms - start >= interval;
  };
  if (last_remote_media_ && elapsed(*last_remote_media_, options_.media_idle_ms)) last_remote_media_.reset();
  if (queued_granted_at_ && elapsed(*queued_granted_at_, options_.queued_grant_action_ms)) {
    FloorPacket release{FloorType::Release, true, local_ssrc_, {}};
    // T132 expiry sends one Release then enters has-no-permission (TS 24.380 clause 6.2.4.9.13).
    queued_granted_at_.reset();
    pending_.reset();
    state_ = FloorParticipantState::NoPermission;
    return {release};
  }
  if (!pending_) return {};
  const auto interval = pending_->type == FloorType::Request   ? options_.request_retry_ms
                        : pending_->type == FloorType::Release ? options_.release_retry_ms
                                                               : options_.queue_retry_ms;
  if (!elapsed(last_sent_ms_, interval)) return {};
  if (transmissions_ >= options_.max_transmissions) {
    failed_.push_back(pending_->type);
    if (pending_->type == FloorType::QueuePositionRequest) {
      // T104 exhaustion cancels the queued request using T100 (TS 24.380 clause 6.2.4.9.11).
      FloorPacket release{FloorType::Release, true, local_ssrc_, {}};
      send(release, now_ms);
      return {release};
    }
    state_ = FloorParticipantState::NoPermission;
    pending_.reset();
    return {};
  }
  ++transmissions_;
  last_sent_ms_ = now_ms;

  return {*pending_};
}

//------------------------------------------------------------------------------
// Helper: the message types whose retransmissions were exhausted.
std::vector<FloorType> FloorParticipantTimers::take_failed() { return std::exchange(failed_, {}); }

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4: an arbitrator with only T2 (Stop talking) of max_talk_ms: no T1 (End of RTP media), no
// T3 grace, no queue. T2 runs from the first RTP packet (clause 6.3.4.4.5) and its expiry revokes with cause #2
// (clause 6.3.4.4.4), as with full options.
FloorArbitrator::FloorArbitrator(std::vector<std::string> authorized, std::uint64_t max_talk_ms)
    : FloorArbitrator(std::move(authorized), FloorArbitratorOptions{max_talk_ms, 0, 0, 1000, false}) {}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4: the floor control server arbitration for the authorized participants, with the timers
// of clause 11.1.3 (T1, T2, T3, T7, T20) and their counters.
FloorArbitrator::FloorArbitrator(std::vector<std::string> authorized, FloorArbitratorOptions options)
    : options_(options), authorized_(std::move(authorized)), max_talk_ms_(options.max_talk_ms) {
  if (options_.max_idle_transmissions == 0) throw std::runtime_error("invalid idle retry count");
  if (options_.grant_retry_ms == 0 || options_.max_grant_transmissions == 0)
    throw std::runtime_error("invalid queued grant retry configuration");
  if (options_.revoke_retry_ms == 0) throw std::runtime_error("revoke retry must be positive");
  if (max_talk_ms_ == 0) throw std::runtime_error("maximum talk time must be positive");
  if (std::any_of(authorized_.begin(), authorized_.end(), [](const auto &id) { return id.empty(); })) {
    throw std::runtime_error("empty authorized participant identity");
  }
  std::sort(authorized_.begin(), authorized_.end());
  authorized_.erase(std::unique(authorized_.begin(), authorized_.end()), authorized_.end());
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.3.3: in 'G: Floor Idle', a Floor Request is granted and 'G: Floor Taken' entered
// (clause 6.3.4.4.2: Floor Granted to the requester, Floor Taken to the others); clause 6.3.4.4.7: in 'G: Floor
// Taken', a request with pre-emptive priority revokes the floor (cause #4) and is queued; clause 6.3.5.4.4:
// otherwise it is queued (Floor Queue Position Info, Floor Deny cause #7 when the queue is full) or denied
// (cause #1); an unauthorized participant is denied (cause #255).
std::vector<FloorNotice> FloorArbitrator::request(std::string_view participant, std::uint64_t now_ms,
                                                  std::uint8_t priority, bool queue_capable, std::uint8_t preemptive) {
  const std::string id(participant);
  if (!is_authorized(participant)) {
    return {{FloorNoticeKind::Denied, id, owner_.value_or(""), 255}};
  }
  if (owner_) {
    if (*owner_ == participant) return {};
    if (preemptive > owner_preemptive_) {
      const auto found = std::find_if(queue_.begin(), queue_.end(),
                                      [&](const auto &entry) { return entry.participant == participant; });
      if (found == queue_.end())
        queue_.push_back({id, priority, preemptive});
      else {
        found->priority = priority;
        found->preemptive = preemptive;
      }
      std::stable_sort(queue_.begin(), queue_.end(), [](const auto &left, const auto &right) {
        if (left.preemptive != right.preemptive) return left.preemptive > right.preemptive;
        return !left.preemptive && left.priority > right.priority;
      });
      std::vector<FloorNotice> notices;
      if (!revoked_at_ms_) {
        media_supervised_ = false; // Stop T1 and T20 while revoke is pending.
        queued_grant_ = false;
        revoked_at_ms_ = now_ms;
        last_revoke_ms_ = now_ms;
        revoke_cause_ = 4;
        notices.push_back({FloorNoticeKind::Revoke, *owner_, *owner_, 4, owner_priority_});
      }
      if (queue_capable) notices.push_back(queue_position(participant));
      if (options_.revoke_grace_ms == 0) {
        auto next = finish_owner(now_ms);
        notices.insert(notices.end(), next.begin(), next.end());
      }
      return notices;
    }
    if (options_.queue_enabled && queue_capable) {
      const auto found = std::find_if(queue_.begin(), queue_.end(),
                                      [&](const auto &entry) { return entry.participant == participant; });
      if (found == queue_.end()) {
        if (queue_.size() >= std::clamp(options_.queue_depth, 1u, 253u))
          return {{FloorNoticeKind::Denied, id, *owner_, 7}}; // cause #7 (Queue full)
        queue_.push_back({id, priority, preemptive});
      } else {
        found->priority = priority;
        found->preemptive = preemptive;
      }
      std::stable_sort(queue_.begin(), queue_.end(), [](const auto &left, const auto &right) {
        if (left.preemptive != right.preemptive) return left.preemptive > right.preemptive;
        return !left.preemptive && left.priority > right.priority;
      });
      return {queue_position(participant)};
    }
    return {{FloorNoticeKind::Denied, id, *owner_, 1}};
  }

  idle_sent_ms_.reset();
  owner_ = id;
  last_media_ms_ = now_ms;
  media_supervised_ = true;
  first_media_ms_.reset();
  revoked_at_ms_.reset();
  owner_priority_ = priority;
  owner_preemptive_ = preemptive;
  revoke_cause_ = revoke_cause_media_burst_too_long;
  queued_grant_ = false;
  grant_transmissions_ = 1;
  last_grant_ms_ = now_ms;

  // TS 24.380 clause 6.3.4.4.2 step 1a: the Duration field carries T2 (Stop talking).
  std::vector<FloorNotice> notices{{FloorNoticeKind::Granted, id, id, 0, priority, 254, max_talk_ms_}};
  for (const auto &recipient : authorized_) {
    if (recipient != id) {
      notices.push_back({FloorNoticeKind::Taken, recipient, id, 0, priority});
    }
  }

  return notices;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.3.2: enter 'G: Floor Idle': with an empty queue send Floor Idle and start T7; otherwise
// grant the floor to the request at the top of the queue.
std::vector<FloorNotice> FloorArbitrator::finish_owner(std::uint64_t now_ms) {
  owner_.reset();
  queued_grant_ = false;
  first_media_ms_.reset();
  revoked_at_ms_.reset();
  if (queue_.empty()) {
    start_idle(now_ms);
    return idle_notices();
  }
  const auto next = queue_.front();
  queue_.erase(queue_.begin());
  auto notices = request(next.participant, now_ms, next.priority, true, next.preemptive);
  queued_grant_ = true;
  return notices;
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 6.3.4.4.6 and 6.3.4.5.4: a Floor Release from the permitted participant enters 'G: Floor
// Idle'; from a queued participant it removes its queued request.
std::vector<FloorNotice> FloorArbitrator::release(std::string_view participant, std::uint64_t now_ms) {
  std::erase_if(queue_, [&](const auto &entry) { return entry.participant == participant; });
  if (!owner_ || *owner_ != participant) return {};
  return finish_owner(now_ms);
}

//------------------------------------------------------------------------------
// Helper: a participant joins the call and is told the floor state (Floor Taken or Floor Idle), as on entering
// the basic state machine of TS 24.380 clause 6.3.5.
std::vector<FloorNotice> FloorArbitrator::add(std::string_view participant) {
  if (participant.empty()) throw std::runtime_error("empty authorized participant identity");
  const auto found = std::lower_bound(authorized_.begin(), authorized_.end(), participant);
  if (found != authorized_.end() && *found == participant) return {};
  authorized_.insert(found, std::string(participant));
  if (owner_) return {{FloorNoticeKind::Taken, std::string(participant), *owner_, 0, owner_priority_}};
  return {{FloorNoticeKind::Idle, std::string(participant), "", 0}};
}

//------------------------------------------------------------------------------
// Helper: a participant leaves the call; the floor is released if it held it.
std::vector<FloorNotice> FloorArbitrator::remove(std::string_view participant, std::uint64_t now_ms) {
  const auto found = std::lower_bound(authorized_.begin(), authorized_.end(), participant);
  if (found == authorized_.end() || *found != participant) return {};
  authorized_.erase(found);
  return release(participant, now_ms);
}

//------------------------------------------------------------------------------
// Helper: the floor priority admitted for the owner or a queued participant.
std::optional<std::uint8_t> FloorArbitrator::admitted_priority(std::string_view participant) const {
  if (owner_ == participant) return owner_priority_;
  for (const auto &entry : queue_)
    if (entry.participant == participant) return entry.priority;
  return std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: changes a participant's pre-emptive priority class and reorders the queue.
void FloorArbitrator::set_priority_class(std::string_view participant, std::uint8_t priority_class) {
  if (owner_ == participant) owner_preemptive_ = priority_class;
  for (auto &entry : queue_)
    if (entry.participant == participant) entry.preemptive = priority_class;
  std::stable_sort(queue_.begin(), queue_.end(), [](const auto &left, const auto &right) {
    if (left.preemptive != right.preemptive) return left.preemptive > right.preemptive;
    return !left.preemptive && left.priority > right.priority;
  });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.4.5: RTP media from the permitted participant starts T2 (Stop talking) if not running,
// restarts T1 (End of RTP media) and stops T20 (Floor Granted).
void FloorArbitrator::media_received(std::string_view participant, std::uint64_t now_ms) {
  if (!owner_ || *owner_ != participant) return;
  media_supervised_ = true;
  if (!first_media_ms_) first_media_ms_ = now_ms;
  last_media_ms_ = now_ms;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.4.8 step 1a: the value of T2 (Stop talking) running for the permitted participant. T2
// starts with its first RTP packet (clause 6.3.4.4.5), so before that it is the whole maximum talk time.
std::uint64_t FloorArbitrator::talk_time_remaining(std::uint64_t now_ms) const {
  if (!owner_ || !first_media_ms_) return max_talk_ms_;
  const auto talked = now_ms >= *first_media_ms_ ? now_ms - *first_media_ms_ : 0;
  return talked >= max_talk_ms_ ? 0 : max_talk_ms_ - talked;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.5: the Queue Info of a participant: its position in the queue, or 254 when it is not
// queued.
FloorNotice FloorArbitrator::queue_position(std::string_view participant) const {
  for (std::size_t index = 0; index < queue_.size(); ++index) {
    if (queue_[index].participant == participant)
      return {FloorNoticeKind::QueuePosition, std::string(participant),
              std::string(participant),       0,
              queue_[index].priority,         static_cast<std::uint8_t>(index + 1)};
  }
  return {FloorNoticeKind::QueuePosition, std::string(participant), std::string(participant), 0, 0, 254};
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.3.2: starts T7 (Floor Idle) and counter C7 when the floor becomes idle.
void FloorArbitrator::start_idle(std::uint64_t now_ms) {
  if (!owner_ && !idle_sent_ms_) {
    idle_sent_ms_ = now_ms;
    idle_transmissions_ = 1;
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4: the general state: 'G: Floor Idle', 'G: Floor Taken' or 'G: pending Floor Revoke'.
FloorState FloorArbitrator::state() const {
  if (!owner_) return FloorState::Idle;
  return revoked_at_ms_ ? FloorState::PendingRevoke : FloorState::Taken;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4: the server timers: T7 expiry resends Floor Idle (clause 6.3.4.3.4); in 'G: pending
// Floor Revoke', T3 expiry (clause 6.3.4.5.5) and T1 expiry (clause 6.3.4.5.6) end the floor, and Floor Revoke is
// resent as on T8 expiry (clause 6.3.5.6.3); in 'G: Floor Taken', T1 expiry (clause 6.3.4.4.3) ends the floor, T20 expiry resends Floor Granted
// (clauses 6.3.4.4.9 and 6.3.4.4.10), and T2 expiry revokes the floor with cause #2 (clause 6.3.4.4.4).
std::vector<FloorNotice> FloorArbitrator::tick(std::uint64_t now_ms) {
  const auto elapsed = [now_ms](std::uint64_t start, std::uint64_t interval) {
    return now_ms >= start && now_ms - start >= interval;
  };
  if (!owner_) {
    if (idle_sent_ms_ && options_.idle_retry_ms && idle_transmissions_ < options_.max_idle_transmissions &&
        elapsed(*idle_sent_ms_, options_.idle_retry_ms)) {
      idle_sent_ms_ = now_ms;
      ++idle_transmissions_;
      return idle_notices();
    }
    return {};
  }
  if (revoked_at_ms_) {
    if (elapsed(*revoked_at_ms_, options_.revoke_grace_ms)) return finish_owner(now_ms);
    if (media_supervised_ && options_.media_idle_ms && elapsed(last_media_ms_, options_.media_idle_ms))
      return finish_owner(now_ms);
    if (elapsed(last_revoke_ms_, options_.revoke_retry_ms)) {
      last_revoke_ms_ = now_ms;
      return {{FloorNoticeKind::Revoke, *owner_, *owner_, revoke_cause_, owner_priority_}};
    }
    return {};
  }
  if (options_.media_idle_ms && elapsed(last_media_ms_, options_.media_idle_ms)) return finish_owner(now_ms);
  if (awaiting_grant_media() && grant_transmissions_ < options_.max_grant_transmissions &&
      elapsed(last_grant_ms_, options_.grant_retry_ms)) {
    ++grant_transmissions_;
    last_grant_ms_ = now_ms;
    return {{FloorNoticeKind::Granted, *owner_, *owner_, 0, owner_priority_, 254, max_talk_ms_}};
  }

  // TS 24.380 clause 6.3.4.4.5: T2 runs from the first RTP packet of the permitted participant.
  if (!first_media_ms_ || !elapsed(*first_media_ms_, max_talk_ms_)) return {};
  media_supervised_ = false; // T2 expiry stops T1; subsequent RTP restarts T1.
  revoked_at_ms_ = now_ms;
  last_revoke_ms_ = now_ms;
  revoke_cause_ = revoke_cause_media_burst_too_long;
  std::vector<FloorNotice> notices{
      {FloorNoticeKind::Revoke, *owner_, *owner_, revoke_cause_media_burst_too_long, owner_priority_}};
  if (options_.revoke_grace_ms == 0) {
    auto next = finish_owner(now_ms);
    notices.insert(notices.end(), next.begin(), next.end());
  }

  return notices;
}

//------------------------------------------------------------------------------
// Helper: the participant with permission to send media, if any.
std::optional<std::string> FloorArbitrator::owner() const { return owner_; }

//------------------------------------------------------------------------------
// Helper: whether the participant may request the floor.
bool FloorArbitrator::is_authorized(std::string_view participant) const {
  return std::binary_search(authorized_.begin(), authorized_.end(), participant);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.3.2: a Floor Idle to every participant.
std::vector<FloorNotice> FloorArbitrator::idle_notices() const {
  std::vector<FloorNotice> notices;
  notices.reserve(authorized_.size());
  for (const auto &recipient : authorized_) {
    notices.push_back({FloorNoticeKind::Idle, recipient, "", 0});
  }
  return notices;
}

} // namespace mcx
