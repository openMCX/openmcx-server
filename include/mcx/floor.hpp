// MCPTT floor control: the RTCP APP packet coding shared with MCVideo transmission control (TS 24.380 clause 8.1,
// TS 24.581 clause 9.1), the floor control messages and fields of TS 24.380 clause 8.2, the Floor Ack
// retransmission, the on-network floor participant timers and states (TS 24.380 clause 6.2.4) and the floor control
// server arbitration (TS 24.380 clause 6.3.4).
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19),
// TS 24.483 V19.2.0 (Rel-19), RFC 3550.

#pragma once

#include "mcx/media_control.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.380 table 8.2.2.1-1: the floor control specific messages, by subtype.
enum class FloorType : std::uint8_t {
  Request = 0,
  Granted = 1,
  Taken = 2,
  Deny = 3,
  Release = 4,
  Idle = 5,
  Revoke = 6,
  QueuePositionRequest = 8,
  QueuePositionInfo = 9,
  Ack = 10,
};

//------------------------------------------------------------------------------
// TS 24.380 table 8.2.3.1-2: the floor control specific data fields, by field ID.
enum class FloorFieldId : std::uint8_t {
  FloorPriority = 0,
  Duration = 1,
  RejectCause = 2,
  QueueInfo = 3,
  GrantedPartyIdentity = 4,
  PermissionToRequest = 5,
  UserId = 6,
  QueueSize = 7,
  MessageSequence = 8,
  QueuedUserId = 9,
  Source = 10,
  MessageType = 12,
  FloorIndicator = 13,
  AudioSsrc = 14,
  Location = 19,
};

//------------------------------------------------------------------------------
// TS 24.380 clause 8.1.3: one field of the application-dependent data: field ID and value.
struct FloorField {
  std::uint8_t id{};
  std::vector<std::uint8_t> value;

  bool operator==(const FloorField &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.2.1: a floor control message: subtype, acknowledgement bit, SSRC and fields.
struct FloorPacket {
  FloorType type{FloorType::Request};
  bool ack_required{false};
  std::uint32_t ssrc{};
  std::vector<FloorField> fields;

  bool operator==(const FloorPacket &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.4: the Reject Cause field: cause code and reject phrase.
struct RejectCause {
  std::uint16_t cause{};
  std::string phrase;

  bool operator==(const RejectCause &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 8.1.2 and clause 8.1.3, TS 24.581 clause 9.1.3: an RTCP APP packet (RFC 3550 section 6.7) whose
// application-dependent data are the field-ID/length/value fields: the
// framing floor control ("MCPT") and MCVideo transmission control ("MCV0" to
// "MCV2") share. Neither the name nor the field contents are checked here.
struct AppPacket {
  std::uint8_t subtype{}; // the five low bits of the first octet
  std::uint32_t ssrc{};
  std::array<std::uint8_t, 4> name{};
  std::vector<FloorField> fields;
  bool operator==(const AppPacket &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.1.2 and 8.1.3 (TS 24.581 clauses 9.1.2 and 9.1.3, RFC 3550 section 6.7): encodes an RTCP
// APP packet, each field padded to four octets.
std::vector<std::uint8_t> encode_app(const AppPacket &packet);
//------------------------------------------------------------------------------
// TS 24.380 clauses 8.1.2 and 8.1.3 (TS 24.581 clauses 9.1.2 and 9.1.3, RFC 3550 section 6.7): decodes an RTCP
// APP packet into its fields.
AppPacket decode_app(std::span<const std::uint8_t> bytes);

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.2.1: encodes a floor control message as an RTCP APP packet named "MCPT".
std::vector<std::uint8_t> encode_floor(const FloorPacket &packet);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.2.1: decodes an RTCP APP packet named "MCPT" as a floor control message.
FloorPacket decode_floor(std::span<const std::uint8_t> bytes);

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.8: builds the User ID field (an MCPTT ID).
FloorField user_id_field(std::string_view user_id);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.8: reads the User ID field.
std::string read_user_id(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.2: builds the Floor Priority field.
FloorField priority_field(std::uint8_t priority);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.2: reads the Floor Priority field.
std::uint8_t read_priority(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.3: builds the Duration field, in seconds.
FloorField duration_field(std::uint16_t seconds);
// The Duration field (clause 8.2.3.3) for a T2 value in milliseconds: whole seconds, rounded up.
FloorField duration_field_ms(std::uint64_t milliseconds);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.3: reads the Duration field.
std::uint16_t read_duration(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.4: builds the Reject Cause field: the cause code and the optional reject phrase.
FloorField reject_cause_field(std::uint16_t cause, std::string_view phrase = {});
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.4: reads the Reject Cause field.
RejectCause read_reject_cause(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.16: builds the Audio SSRC of Granted Participant field.
FloorField audio_ssrc_field(std::uint32_t ssrc);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.16: reads the Audio SSRC of Granted Participant field.
std::uint32_t read_audio_ssrc(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.10: builds the Message Sequence Number field.
FloorField message_sequence_field(std::uint16_t sequence);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.10: reads the Message Sequence Number field.
std::uint16_t read_message_sequence(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.12: builds the Source field.
FloorField source_field(std::uint16_t source);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.12: reads the Source field; reserved values are refused.
std::uint16_t read_source(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.14: builds the Message Type field naming the acknowledged message.
FloorField message_type_field(FloorType type);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.14: reads the Message Type field of a Floor Ack.
FloorType read_message_type(const FloorField &field);

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.21: the Location field with location type 0 (Not provided, table 8.2.3.21-3).
FloorField location_not_provided_field();
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.6: builds the Granted Party's Identity field.
FloorField granted_party_identity_field(std::string_view identity);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.6: reads the Granted Party's Identity field.
std::string read_granted_party_identity(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.7: builds the Permission to Request the Floor field.
FloorField permission_to_request_field(bool permitted);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.7: reads the Permission to Request the Floor field.
bool read_permission_to_request(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.15: builds the Floor Indicator field; bits J to P are reserved.
FloorField floor_indicator_field(std::uint16_t bitmap);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.15: call-type bits of the Floor Indicator: D (emergency) or
// E (imminent peril), each optionally with B (broadcast); B alone; otherwise A.
std::uint16_t floor_call_type_bits(bool broadcast, bool emergency, bool imminent);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.15: reads the Floor Indicator field.
std::uint16_t read_floor_indicator(const FloorField &field);

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.5: the Queue Info field: queue position and queue priority.
struct QueueInfo {
  std::uint8_t position{};
  std::uint8_t priority{};
  bool operator==(const QueueInfo &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.5: builds the Queue Info field (queue position and queue priority).
FloorField queue_info_field(std::uint8_t position, std::uint8_t priority);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.5: reads the Queue Info field.
QueueInfo read_queue_info(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.9: builds the Queue Size field.
FloorField queue_size_field(std::uint16_t size);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.9: reads the Queue Size field.
std::uint16_t read_queue_size(const FloorField &field);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.11: builds the Queued User ID field.
FloorField queued_user_id_field(std::string_view identity);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.11: reads the Queued User ID field.
std::string read_queued_user_id(const FloorField &field);

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.2.5 to 8.2.12: additional schema checks for the single-talker on-network profile. Identity
// may be omitted for privacy; extensions remain accepted by the generic codec.
void validate_on_network_floor(const FloorPacket &packet);

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.3.10: accepts a Floor Taken or Floor Idle only when its Message Sequence Number is newer than
// the last one. One instance per receiving peer and session; Idle and Taken share a sequence.
class FloorSequenceTracker {
public:
  bool accept(const FloorPacket &packet);

  void reset() { last_.reset(); }

private:
  std::optional<std::uint16_t> last_;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 8.2.13: bounded ACK delivery primitive (Floor Ack), not the complete TS 24.380 state machine.
// Caller authenticates/binds the datagram endpoint. ACK has no transaction ID:
// only one outstanding message per type is supported; send supersedes it.
// A delayed ACK for a previous same-type message is indistinguishable on wire.
// Cancel obsolete state messages at the application transition; this primitive
// does not provide transaction correlation or exactly-once delivery.
class FloorAckRetry {
public:
  FloorAckRetry(std::uint32_t local_ssrc, std::uint32_t peer_ssrc, std::uint16_t peer_source,
                std::uint64_t retry_ms = 1000, unsigned max_transmissions = 3);
  // Caller transmits the initial packet; this method schedules repeats.
  void send(const FloorPacket &packet, std::uint64_t now_ms);
  bool receive(const FloorPacket &ack);
  void cancel(FloorType type);
  std::vector<FloorPacket> tick(std::uint64_t now_ms);

  std::size_t pending() const { return pending_.size(); }

  std::vector<FloorType> take_failed();

private:
  struct Pending {
    FloorPacket packet;
    std::uint64_t sent_at;
    unsigned count;
  };

  std::uint32_t local_ssrc_, peer_ssrc_;
  std::uint16_t peer_source_;
  std::uint64_t retry_ms_;
  unsigned max_transmissions_;
  std::vector<Pending> pending_;
  std::vector<FloorType> failed_;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4: the floor participant states 'U: has no permission', 'U: pending Request',
// 'U: has permission', 'U: pending Release' and 'U: queued'.
enum class FloorParticipantState { NoPermission, PendingRequest, HasPermission, PendingRelease, Queued };

//------------------------------------------------------------------------------
// TS 24.380 clause 11.1.1 and clause 11.2.1: the on-network floor participant timers and counters.
struct FloorParticipantTimerOptions {
  // T100/T101/T104 intervals are deployment policy, provisioned by TS 24.483 (clauses 8.2.11 to 8.2.15).
  std::uint64_t request_retry_ms{1000};
  std::uint64_t release_retry_ms{1000};
  std::uint64_t queue_retry_ms{1000};
  std::uint64_t media_idle_ms{4000};          // T103; zero disables optional supervision
  std::uint64_t queued_grant_action_ms{2000}; // T132 default
  unsigned max_transmissions{3};              // C100/C101/C104 defaults
};

//------------------------------------------------------------------------------
// TS 24.380 clause 6.2.4 with clauses 11.1.1 and 11.2.1: single-talker participant timer/state subset:
// T100/101/103/104/132.
// Caller validates/binds incoming peers, filters duplicate/stale state packets,
// acknowledges messages and reacts to Revoke by sending Release. Does not
// implement broadcast, dual-floor, implicit request, or user-interface policy.
// Granted has no sequence/transaction field: a delayed old grant arriving during
// a new PendingRequest cannot be distinguished here. The server must cancel
// obsolete grant retries and enforce current floor ownership for every RTP packet.
class FloorParticipantTimers {
public:
  explicit FloorParticipantTimers(FloorParticipantTimerOptions options = {});
  // Caller sends the initial packet; send registers timer/state only.
  void send(const FloorPacket &packet, std::uint64_t now_ms);
  // A session set up with an implicit floor request, or with an implicit
  // request to grant the floor to this client (TS 24.379 clause 6.4, TS 24.380 clause 6.2.4.2.2 step 4; ambient
  // listening): wait for Floor Granted without sending or retrying a request.
  void expect_implicit_grant();
  void receive(const FloorPacket &packet, std::uint64_t now_ms);
  void media_received(std::uint64_t now_ms);
  std::vector<FloorPacket> tick(std::uint64_t now_ms);
  std::vector<FloorType> take_failed();
  bool confirm_queued_grant();

  bool awaiting_user_confirmation() const { return queued_granted_at_.has_value(); }

  bool remote_media_active() const { return last_remote_media_.has_value(); }

  FloorParticipantState state() const { return state_; }

private:
  FloorParticipantTimerOptions options_;
  FloorParticipantState state_{FloorParticipantState::NoPermission};
  std::optional<FloorPacket> pending_;
  std::uint64_t last_sent_ms_{};
  unsigned transmissions_{};
  std::uint32_t local_ssrc_{};
  std::optional<std::uint64_t> last_remote_media_;
  std::optional<std::uint64_t> queued_granted_at_;
  std::vector<FloorType> failed_;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 11.1.3 and clause 11.2.3: the floor control server timers (T1, T2, T3, T7, T20) and counters.
struct FloorArbitratorOptions {
  std::uint64_t max_talk_ms{30000};
  std::uint64_t media_idle_ms{4000};
  std::uint64_t revoke_grace_ms{3000};
  std::uint64_t revoke_retry_ms{1000};
  bool queue_enabled{false};
  // TS 24.380 clause 6.3.5.4.4: the maximum queue length (<floor-control-queue>/<depth>, TS 24.484 clause 8.4.2.7);
  // at most 253, as Queue Position Info 254 and 255 have their own meanings (TS 24.380 clause 8.2.3.5).
  unsigned queue_depth{253};
  std::uint64_t grant_retry_ms{1000};
  unsigned max_grant_transmissions{3};
  std::uint64_t idle_retry_ms{0}; // T7: deployment supplies radio-dependent interval
  unsigned max_idle_transmissions{10};
};

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4: deterministic single-talker policy. Effective priority/preemption policy and
// call-level inactivity/hang timers remain the caller's responsibility. The
// MCPTT floor control server of TS 24.380 behind the MediaPlaneController interface.
class FloorArbitrator final : public MediaPlaneController {
public:
  // Only T2 (Stop talking) of max_talk_ms, from the first RTP packet: no T1, no T3 grace, no queue.
  FloorArbitrator(std::vector<std::string> authorized, std::uint64_t max_talk_ms);

  FloorArbitrator(std::vector<std::string> authorized, FloorArbitratorOptions options);
  std::vector<FloorNotice> request(std::string_view participant, std::uint64_t now_ms, std::uint8_t priority = 0,
                                   bool queue_capable = false, std::uint8_t preemptive = 0) override;
  void media_received(std::string_view participant, std::uint64_t now_ms) override;
  void set_priority_class(std::string_view participant, std::uint8_t priority_class) override;
  [[nodiscard]] std::optional<std::uint8_t> admitted_priority(std::string_view participant) const override;
  // Call after initial Idle is sent. Release/T1/T3 arm this automatically.
  void start_idle(std::uint64_t now_ms) override;
  [[nodiscard]] FloorNotice queue_position(std::string_view participant) const override;
  [[nodiscard]] FloorState state() const override;

  [[nodiscard]] std::uint16_t revoke_cause() const override { return revoke_cause_; }

  [[nodiscard]] bool awaiting_grant_media() const override { return queued_grant_ && !first_media_ms_; }

  [[nodiscard]] std::uint64_t talk_time_remaining(std::uint64_t now_ms) const override;

  std::vector<FloorNotice> release(std::string_view participant, std::uint64_t now_ms) override;
  // Adds authorization without changing ownership, queue ordering, or timers.
  std::vector<FloorNotice> add(std::string_view participant) override;
  std::vector<FloorNotice> remove(std::string_view participant, std::uint64_t now_ms) override;
  std::vector<FloorNotice> tick(std::uint64_t now_ms) override;

  [[nodiscard]] std::optional<std::string> owner() const override;
  [[nodiscard]] bool is_authorized(std::string_view participant) const override;

private:
  std::vector<FloorNotice> idle_notices() const;
  std::vector<FloorNotice> finish_owner(std::uint64_t now_ms);

  struct Queued {
    std::string participant;
    std::uint8_t priority;
    std::uint8_t preemptive{0};
  };

  std::vector<Queued> queue_;
  FloorArbitratorOptions options_;
  std::optional<std::uint64_t> first_media_ms_;
  std::uint64_t last_media_ms_{};
  bool media_supervised_{true};
  std::optional<std::uint64_t> revoked_at_ms_;
  std::uint64_t last_revoke_ms_{};
  std::uint8_t owner_priority_{};
  std::uint8_t owner_preemptive_{0};
  std::uint16_t revoke_cause_{2};
  bool queued_grant_{false};
  unsigned grant_transmissions_{};
  std::uint64_t last_grant_ms_{};
  std::optional<std::uint64_t> idle_sent_ms_;
  unsigned idle_transmissions_{};

  std::vector<std::string> authorized_;
  std::optional<std::string> owner_;
  std::uint64_t max_talk_ms_{};
};

} // namespace mcx
