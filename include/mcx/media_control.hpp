//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The media plane control server interface of a call: MCPTT floor control or MCVideo transmission control, with the
// notices it returns.
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// TS 24.380 clause 6.3 and TS 24.581 clause 6.3: the kind of a notice of the media plane control server of a call:
// MCPTT floor control or MCVideo transmission control. The call-handling core drives it through MediaPlaneController
// and turns the notices it returns into the protocol's messages (Floor Granted or Transmission Granted, and so on).
// The notice kinds are those of floor control; transmission control maps its messages onto them.
enum class FloorNoticeKind {
  Granted,
  Taken,
  Denied,
  Idle,
  Revoke,
  QueuePosition,
};

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4: a floor control message the server sends to one recipient, about one participant.
struct FloorNotice {
  FloorNoticeKind kind{FloorNoticeKind::Idle};
  std::string recipient;
  std::string participant;
  std::uint16_t reject_cause{};     // TS 24.380 clause 8.2.3.4: the Reject Cause field
  std::uint8_t priority{};          // TS 24.380 clause 8.2.3.2: the Floor Priority field
  std::uint8_t queue_position{254}; // TS 24.380 clause 8.2.3.5: the Queue Position Info, 254 when not queued
  // TS 24.380 clauses 6.3.4.4.2 and 6.3.4.4.8: in a Floor Granted, the value of T2 (Stop talking) for the Duration
  // field (clause 8.2.3.3), in milliseconds.
  std::uint64_t duration_ms{};

  bool operator==(const FloorNotice &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.380 clauses 6.3.4.3, 6.3.4.4 and 6.3.4.5: the general states 'G: Floor Idle', 'G: Floor Taken' and
// 'G: pending Floor Revoke' of the floor control server.
enum class FloorState { Idle, Taken, PendingRevoke };

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4 and TS 24.581 clause 6.3.4: the floor (or transmission) control server arbitration of a call,
// as the call-handling core drives it.
class MediaPlaneController {
public:
  virtual ~MediaPlaneController() = default;
  // TS 24.380 clauses 6.3.4.3.3 and 6.3.4.4.7: a Floor Request from a participant.
  virtual std::vector<FloorNotice> request(std::string_view participant, std::uint64_t now_ms,
                                           std::uint8_t priority = 0, bool queue_capable = false,
                                           std::uint8_t preemptive = 0) = 0;
  // TS 24.380 clause 6.3.4.4.5: RTP media received from a participant.
  virtual void media_received(std::string_view participant, std::uint64_t now_ms) = 0;
  virtual void set_priority_class(std::string_view participant, std::uint8_t priority_class) = 0;
  [[nodiscard]] virtual std::optional<std::uint8_t> admitted_priority(std::string_view participant) const = 0;
  // TS 24.380 clause 6.3.4.3.2: the floor becomes idle (T7 started).
  virtual void start_idle(std::uint64_t now_ms) = 0;
  // TS 24.380 clause 8.2.3.5: the Queue Info of a participant.
  [[nodiscard]] virtual FloorNotice queue_position(std::string_view participant) const = 0;
  [[nodiscard]] virtual FloorState state() const = 0;
  [[nodiscard]] virtual std::uint16_t revoke_cause() const = 0;
  [[nodiscard]] virtual bool awaiting_grant_media() const = 0;
  // TS 24.380 clause 6.3.4.4.8: the value of T2 (Stop talking) running for the participant granted the floor, in
  // milliseconds: all of it before its first RTP packet starts T2 (clause 6.3.4.4.5).
  [[nodiscard]] virtual std::uint64_t talk_time_remaining(std::uint64_t now_ms) const = 0;
  // TS 24.380 clauses 6.3.4.4.6 and 6.3.4.5.4: a Floor Release from a participant.
  virtual std::vector<FloorNotice> release(std::string_view participant, std::uint64_t now_ms) = 0;
  virtual std::vector<FloorNotice> add(std::string_view participant) = 0;
  virtual std::vector<FloorNotice> remove(std::string_view participant, std::uint64_t now_ms) = 0;
  // TS 24.380 clause 6.3.4: runs the server timers.
  virtual std::vector<FloorNotice> tick(std::uint64_t now_ms) = 0;
  [[nodiscard]] virtual std::optional<std::string> owner() const = 0;
  [[nodiscard]] virtual bool is_authorized(std::string_view participant) const = 0;
};
} // namespace mcx
