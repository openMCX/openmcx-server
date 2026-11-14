//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCVideo transmission control messages (TS 24.581 clause 9.2): RTCP APP packets named MCV0 (sent by the transmission
// participant), MCV1 (sent by the transmission control server) and MCV2 (sent by either), with the fields of clause
// 9.2.3 in the TS 24.380 field syntax. MCV3 to MCV5 (MBMS, MBS) are out of scope.
//
// Specifications: TS 24.581 V19.2.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), RFC 3550.
#pragma once
#include "mcx/floor.hpp"

#include <cstdint>
#include <optional>
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
// TS 24.581 clause 9.2.3.22: builds the Reception Mode field: 0 when the receiver is granted permission to receive
// the media automatically, 1 when it is not.
FloorField reception_mode_field(bool automatic);

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.3.22: reads the Reception Mode field; true for automatic reception.
bool read_reception_mode(const FloorField &field);

//------------------------------------------------------------------------------
// TS 24.581 clause 6.3.6.3.3 step 1: the Reception Mode of a Media Transmission Notification, automatic ('0') in a
// broadcast, emergency or imminent peril call, manual ('1') otherwise; without the server's reception control every
// member receives every transmission, which is automatic reception.
bool automatic_reception(bool reception_control, bool broadcast, bool emergency, bool imminent);

//------------------------------------------------------------------------------
// TS 24.581 clause 9.2.13: a Media Transmission Notification to the participant whose RTCP SSRC is ssrc, of the
// transmission by transmitter with these audio and video SSRCs: the Permission to Request the Transmission field,
// the Transmission Indicator field when indicator is set, and the Reception Mode field.
Packet media_transmission_notification(std::uint32_t ssrc, std::string_view transmitter, std::uint32_t audio_ssrc,
                                       std::uint32_t video_ssrc, bool permission_to_request,
                                       std::optional<std::uint16_t> indicator, bool automatic);

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


//------------------------------------------------------------------------------
// TS 24.581 clause 6.2.4: the states of the 'Transmission participant state transition diagram for basic
// transmission control operation': 'U: has no permission to transmit', 'U: pending request to transmit', 'U: has
// permission to transmit', 'U: pending end of transmission', 'U: queued transmission' and 'Call releasing'.
enum class ParticipantState { NoPermission, PendingRequest, HasPermission, PendingEnd, Queued, CallReleasing };

//------------------------------------------------------------------------------
// TS 24.581 clause 6.2.5: the states of the reception control machines: 'U: reception controller' of the general
// machine with no basic instance (Idle), the basic machine states 'U: pending request to receive', 'U: has
// permission to receive', 'U: pending reception release' and 'U: terminated', and 'Call releasing'.
enum class ReceptionState { Idle, PendingRequest, HasPermission, PendingRelease, Terminated, CallReleasing };

//------------------------------------------------------------------------------
// TS 24.581 clauses 11.1.1 and 11.2.1: the on-network transmission participant timers and counters. The timer
// values come from the MCVideo service configuration document (TS 24.484 clause 9.4.2.7, in seconds) and have no
// default in TS 24.581; one second each keeps the C = 3 transmissions within the 6 seconds of table 11.1.1-1
// NOTEs 1 to 4. The counter limits are the defaults of table 11.2.1-1.
struct ParticipantTimerOptions {
  std::uint64_t t100_request_ms{1000};         // T100 (Transmission Request)
  std::uint64_t t101_end_request_ms{1000};     // T101 (Transmission End Request)
  std::uint64_t t102_queue_position_ms{1000};  // T102 (Transmission Queue Position Request)
  std::uint64_t t103_receive_request_ms{1000}; // T103 (Receive Media Request)
  std::uint64_t t104_receive_release_ms{1000}; // T104 (Receive Media Release)
  unsigned c100_request{3};                    // C100 (Transmission Request)
  unsigned c101_end_request{3};                // C101 (Transmission End Request)
  unsigned c102_queue_position{3};             // C102 (Transmission Queue Position Request)
  unsigned c103_receive_request{3};            // C103 (Receive Media Request)
  unsigned c104_receive_release{3};            // C104 (Receive Media Release)
};

//------------------------------------------------------------------------------
// TS 24.581 clauses 6.2.4 and 6.2.5 with clauses 11.1.1 and 11.2.1: the on-network transmission participant's
// timers T100 to T104 and counters C100 to C104 with the state transitions they drive, for the basic transmission
// control machine and one basic reception control instance. Pure logic: the caller sends what send() registers
// and what tick() returns, sends the Transmission control Acks, end responses and user notifications, and binds
// incoming packets to the session. Broadcast group call endings ('Call releasing' in clauses 6.2.4.5.7 and
// 6.2.4.6.4 step 6) are left to the caller, which calls release().
class ParticipantTimers {
public:
  explicit ParticipantTimers(ParticipantTimerOptions options = {});
  // A request the caller has just sent: Transmission Request (T100), Transmission end request (T101), Queue
  // Position Request (T102), Receive Media Request (T103) or Media reception end request (T104). Throws when the
  // message is not valid in the current state; other participant messages are accepted and start no timer.
  void send(const Packet &packet, std::uint64_t now_ms);
  // TS 24.581 clause 6.2.4.2.2 step 4: a call whose SIP INVITE request was an implicit Transmission request: T100
  // starts with C100 at 1 and 'U: pending request to transmit' is entered without sending; T100 expiry sends
  // `request` (clause 6.2.4.4.3).
  void expect_implicit_request(const Packet &request, std::uint64_t now_ms);
  // A transmission control message received from the transmission control server.
  void receive(const Packet &packet, std::uint64_t now_ms);
  // The requests to send again on timer expiry, and the Transmission end request of clause 6.2.4.9.8.
  std::vector<Packet> tick(std::uint64_t now_ms);
  // The request types that expired the upper limit of their counter since the last call (clauses 6.2.4.4.4,
  // 6.2.4.6.3, 6.2.4.9.8, 6.2.5.4.4 and 6.2.5.6.3).
  std::vector<Type> take_failed();
  // TS 24.581 clauses 6.2.4.7.2 and 6.2.5.3.5: MCVideo call release step 1 stops every timer and enters 'Call
  // releasing' in both machines; step 2 (clauses 6.2.4.8.2 and 6.2.5.9.2) is destroying this object.
  void release();

  ParticipantState state() const { return state_; }

  ReceptionState reception_state() const { return reception_; }

private:
  struct Pending {
    Packet packet;
    std::uint64_t sent_ms{};
    unsigned count{}; // the counter C10x, 1 after the first transmission
  };
  void start(std::optional<Pending> &slot, const Packet &packet, std::uint64_t now_ms);

  ParticipantTimerOptions options_;
  ParticipantState state_{ParticipantState::NoPermission};
  ReceptionState reception_{ReceptionState::Idle};
  std::optional<Pending> transmission_;    // T100, T101 or T102 (one runs at a time in the basic machine)
  std::optional<Pending> reception_timer_; // T103 or T104
  std::vector<Type> failed_;
};

} // namespace mcx::transmission
