// MCVideo transmission control messages (TS 24.581 clause 9.2): RTCP APP packets named MCV0 (sent by the transmission
// participant), MCV1 (sent by the transmission control server) and MCV2 (sent by either), with the fields of clause
// 9.2.3 in the TS 24.380 field syntax. MCV3 to MCV5 (MBMS, MBS) are out of scope.
//
// Specifications: TS 24.581 V19.2.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), RFC 3550.
#pragma once
#include "mcx/floor.hpp"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace mcx::transmission {

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.2.1: the transmission control specific messages.
enum class Type {
  // MCV0, TS 24.581 table 9.2.2.1-1
  Request,
  Release,
  QueuePositionRequest,
  ReceiveMediaRequest,
  RemoteRequest,
  RemoteCancelRequest,
  // MCV1, TS 24.581 table 9.2.2.1-2
  Granted,
  Rejected,
  ArbitrationTaken,
  ArbitrationRelease,
  Revoked,
  QueuePositionInfo,
  MediaTransmissionNotification,
  ReceiveMediaResponse,
  MediaReceptionNotification,
  CancelRequestNotify,
  RemoteResponse,
  RemoteCancelResponse,
  ReceptionOverrideNotification,
  EndNotify,
  Idle,
  // MCV2, TS 24.581 table 9.2.2.1-3
  EndRequest,
  EndResponse,
  ReceptionEndRequest,
  ReceptionEndResponse,
  Ack,
};

//------------------------------------------------------------------------------
// TS 24.581 table 9.2.3.1-1: the field IDs (the same numbers as TS 24.380 where the fields are shared). The table gives
// Video SSRC as decimal 024 but binary 00010111; the binary value, 23, follows Reception Mode (22) and is used here.
enum class Field : std::uint8_t {
  Priority = 0,
  Duration = 1,
  RejectCause = 2,
  QueueInfo = 3,
  TransmittingUserId = 4,
  PermissionToRequest = 5,
  UserId = 6,
  QueueSize = 7,
  MessageSequence = 8,
  QueuedUserId = 9,
  Source = 10,
  TrackInfo = 11,
  MessageType = 12,
  Indicator = 13,
  AudioSsrc = 14,
  Result = 15,
  MessageName = 16,
  OverridingId = 17,
  OverriddenId = 18,
  ReceptionPriority = 19,
  GroupIdentity = 20,
  FunctionalAlias = 21,
  ReceptionMode = 22,
  VideoSsrc = 23,
};

//------------------------------------------------------------------------------
// TS 24.581 clauses 9.1.2 and 9.2.2.1: one transmission control message, an RTCP APP packet.
struct Packet {
  Type type = Type::Request;
  bool ack_required = false; // the x bit of the subtype (TS 24.581 clause 9.2.2.1)
  std::uint32_t ssrc = 0;
  std::vector<FloorField> fields;
  bool operator==(const Packet &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.581 clauses 9.1.2 and 9.2.2.1: encodes a transmission control message as an RTCP APP packet.
std::vector<std::uint8_t> encode(const Packet &packet);

//------------------------------------------------------------------------------
// TS 24.581 clauses 9.1.2 and 9.2.2.1: decodes an RTCP APP packet as a transmission control message. Refuses another
// name (an MCPTT floor packet), an unknown subtype, a void subtype and malformed fields of known IDs (clause 9.2.3).
Packet decode(std::span<const std::uint8_t> bytes);

//------------------------------------------------------------------------------
// TS 24.581 tables 9.2.2.1-1 and 9.2.2.1-3: whether the transmission participant sends this message (MCV0 or MCV2).
[[nodiscard]] bool from_participant(Type type);

//------------------------------------------------------------------------------
// TS 24.581 tables 9.2.2.1-2 and 9.2.2.1-3: whether the transmission control server sends this message (MCV1 or
// MCV2).
[[nodiscard]] bool from_server(Type type);

// Field constructors and readers specific to MCVideo follow; the others are the floor field helpers of floor.hpp with
// the IDs above.

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.23: builds the Video SSRC of the Transmitting User field.
FloorField video_ssrc_field(std::uint32_t ssrc);

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.23: reads the Video SSRC of the Transmitting User field.
std::uint32_t read_video_ssrc(const FloorField &field);

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.6: builds the User Id of the Transmitting User field (the MCVideo ID).
FloorField transmitting_user_field(std::string_view mcvideo_id);

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.6: reads the User Id of the Transmitting User field.
std::string read_transmitting_user(const FloorField &field);

//------------------------------------------------------------------------------
// Helper: the first field of the packet with this field ID, or null.
const FloorField *find(const Packet &packet, Field id);

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.17: builds the Result of a Remote Transmission (cancel) request, carried in the responses
// (clauses 9.2.23 and 9.2.25), whose tables list no field for it; see tests/mcvideo/MCVIDEO_PULL_PUSH_TEST.md.
FloorField result_field(bool success);

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.17: reads the Result field; true when granted.
bool read_result(const FloorField &field);

} // namespace mcx::transmission
