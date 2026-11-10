//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Call setup control over a pre-established session (include/mcx/pre_established.hpp): the "MCPC" messages of
// TS 24.380 clause 8.3 on the RTCP APP framing of clause 8.1, and the state machines of clauses 9.2.2 and 9.3.2.
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), RFC 3550.

#include "mcx/pre_established.hpp"

#include "mcx/floor.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>
#include <utility>

namespace mcx {
namespace {

constexpr std::uint8_t kRtcpApp = 204;
constexpr std::size_t kNameOffset = 8, kHeaderSize = 12;

// TS 24.380 clause 8.3.1: the RTCP APP name of the pre-established session call control protocol.
constexpr std::array<std::uint8_t, 4> kMcpc{'M', 'C', 'P', 'C'};

// TS 24.380 clause 8.3.2: the first bit of the five-bit subtype, "Acknowledgment is required".
constexpr std::uint8_t kAckRequiredBit = 0x10;

// TS 24.380 table 8.3.3.1-2: the field IDs.
enum Field : std::uint8_t {
  kMediaStreams = 0,
  kSessionIdentity = 1,
  kWarningText = 2,
  kGroupIdentity = 3,
  kAnswerState = 4,
  kInvitingUser = 5,
  kReasonCode = 6,
  kReasonCause = 7,
  kInvitedUser = 8,
  kPckIMessage = 192,
};

// TS 24.380 clauses 8.3.3.6, 8.3.3.8 and 8.3.3.11: the 16-bit values have length 2; clause 8.3.3.2: Media Streams
// has its two octets.
constexpr std::size_t kU16Length = 2, kMediaStreamsLength = 2;

// TS 24.380 table 11.1.4-1: the maximum value of T55 and T56.
constexpr std::uint64_t kTimerMaximumMs = 4000;

//------------------------------------------------------------------------------
// Helper: a 16-bit field in network byte order.
FloorField u16_field(std::uint8_t id, std::uint16_t value) {
  return {id, {static_cast<std::uint8_t>(value >> 8), static_cast<std::uint8_t>(value)}};
}

//------------------------------------------------------------------------------
// Helper: reads a 16-bit field; nothing when its length is not 2 (a malformed field, clause 8.3.3.9 step 3).
std::optional<std::uint16_t> read_u16(const FloorField &field) {
  if (field.value.size() != kU16Length) return std::nullopt;
  return static_cast<std::uint16_t>((field.value[0] << 8) | field.value[1]);
}

//------------------------------------------------------------------------------
// Helper: a text field (TS 24.380 clauses 8.3.3.4, 8.3.3.5, 8.3.3.7 and 8.3.3.12).
FloorField text_field(std::uint8_t id, std::string_view text) { return {id, {text.begin(), text.end()}}; }

std::string read_text(const FloorField &field) { return {field.value.begin(), field.value.end()}; }

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.3: the MCPTT Session Identity field: the <Session Type> octet, then the SIP URI.
FloorField session_identity_field(PreEstablishedSessionType type, std::string_view identity) {
  FloorField field{kSessionIdentity, {static_cast<std::uint8_t>(type)}};
  field.value.insert(field.value.end(), identity.begin(), identity.end());
  return field;
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.3.4 and 8.3.5: the fields of a Connect or Disconnect beyond the MCPTT Session Identity.
void append_connect_fields(const PreEstablishedMessage &message, std::vector<FloorField> &fields) {
  if (!message.group_identity.empty()) fields.push_back(text_field(kGroupIdentity, message.group_identity));
  if (message.media_streams)
    fields.push_back({kMediaStreams, {message.media_streams->media_stream, message.media_streams->control_channel}});
  if (!message.warning_text.empty()) fields.push_back(text_field(kWarningText, message.warning_text));
  if (message.answer_state)
    fields.push_back(u16_field(kAnswerState, static_cast<std::uint16_t>(*message.answer_state)));
  if (!message.inviting_user.empty()) fields.push_back(text_field(kInvitingUser, message.inviting_user));
  if (!message.invited_user.empty()) fields.push_back(text_field(kInvitedUser, message.invited_user));
  if (!message.pck_i_message.empty()) fields.push_back({kPckIMessage, message.pck_i_message});
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.3.4 to 8.3.6: the fields of a message, mandatory ones first, in the order of its table.
std::vector<FloorField> message_fields(const PreEstablishedMessage &message) {
  std::vector<FloorField> fields;
  if (message.type == PreEstablishedMessageType::Acknowledge) {
    if (!message.reason_code) throw std::runtime_error("Acknowledge without Reason Code: TS 24.380 clause 8.3.6");
    fields.push_back(u16_field(kReasonCode, static_cast<std::uint16_t>(*message.reason_code)));
    return fields;
  }
  if (message.session_identity.empty())
    throw std::runtime_error("Connect or Disconnect without MCPTT Session Identity: TS 24.380 clauses 8.3.4, 8.3.5");
  fields.push_back(session_identity_field(message.session_type, message.session_identity));
  if (message.type == PreEstablishedMessageType::Connect) {
    append_connect_fields(message, fields);
  } else if (message.reason_cause) {
    fields.push_back(u16_field(kReasonCause, static_cast<std::uint16_t>(*message.reason_cause)));
  }
  return fields;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.9 steps 2 and 3: reads one field into the message; unknown fields and malformed optional
// ones are skipped. Sets has_mandatory when the field is the message's well-formed mandatory one.
void read_field(const FloorField &field, PreEstablishedMessage &message, bool &has_mandatory) {
  const bool acknowledge = message.type == PreEstablishedMessageType::Acknowledge;
  switch (field.id) {
  case kSessionIdentity:
    if (acknowledge || field.value.size() < 2) return;
    message.session_type = static_cast<PreEstablishedSessionType>(field.value[0]);
    message.session_identity.assign(field.value.begin() + 1, field.value.end());
    has_mandatory = true;
    return;
  case kReasonCode:
    if (const auto value = read_u16(field); acknowledge && value) {
      message.reason_code = static_cast<PreEstablishedReasonCode>(*value);
      has_mandatory = true;
    }
    return;
  case kReasonCause:
    if (const auto value = read_u16(field); message.type == PreEstablishedMessageType::Disconnect && value)
      message.reason_cause = static_cast<PreEstablishedReasonCause>(*value);
    return;
  default:
    break;
  }
  if (message.type != PreEstablishedMessageType::Connect) return;
  switch (field.id) {
  case kMediaStreams:
    if (field.value.size() == kMediaStreamsLength)
      message.media_streams = PreEstablishedMediaStreams{field.value[0], field.value[1]};
    return;
  case kAnswerState:
    if (const auto value = read_u16(field)) message.answer_state = static_cast<PreEstablishedAnswerState>(*value);
    return;
  case kGroupIdentity:
    message.group_identity = read_text(field);
    return;
  case kWarningText:
    message.warning_text = read_text(field);
    return;
  case kInvitingUser:
    message.inviting_user = read_text(field);
    return;
  case kInvitedUser:
    message.invited_user = read_text(field);
    return;
  case kPckIMessage:
    message.pck_i_message = field.value;
    return;
  default:
    return; // clause 8.3.3.9 step 2: a field of a later version
  }
}

} // namespace

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.3.2 to 8.3.6: encodes the message on the RTCP APP framing of clause 8.1.2, with the first
// subtype bit for a Connect or Disconnect that asks for an acknowledgement.
std::vector<std::uint8_t> encode_pre_established(const PreEstablishedMessage &message) {
  if (message.type == PreEstablishedMessageType::Acknowledge && message.ack_required)
    throw std::runtime_error("an Acknowledge cannot ask for an acknowledgement: TS 24.380 table 8.3.2-1");
  AppPacket packet;
  packet.subtype = static_cast<std::uint8_t>(message.type);
  if (message.ack_required) packet.subtype |= kAckRequiredBit;
  packet.ssrc = message.ssrc;
  packet.name = kMcpc;
  packet.fields = message_fields(message);
  return encode_app(packet);
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.3.2 to 8.3.6 with clause 8.3.3.9: decodes an "MCPC" packet.
std::optional<PreEstablishedMessage> decode_pre_established(std::span<const std::uint8_t> bytes) {
  if (!is_pre_established_message(bytes)) throw std::runtime_error("not an MCPC packet: TS 24.380 clause 8.3.1");
  const auto packet = decode_app(bytes);
  PreEstablishedMessage message;
  message.ssrc = packet.ssrc;
  const auto subtype = packet.subtype;
  if (subtype == static_cast<std::uint8_t>(PreEstablishedMessageType::Acknowledge)) {
    message.type = PreEstablishedMessageType::Acknowledge;
  } else if ((subtype & ~kAckRequiredBit) <= static_cast<std::uint8_t>(PreEstablishedMessageType::Disconnect)) {
    message.type = static_cast<PreEstablishedMessageType>(subtype & ~kAckRequiredBit);
    message.ack_required = (subtype & kAckRequiredBit) != 0;
  } else {
    return std::nullopt; // clause 8.3.3.9 step 1: an unknown subtype
  }

  bool has_mandatory = false;
  for (const auto &field : packet.fields) read_field(field, message, has_mandatory);
  if (!has_mandatory) throw std::runtime_error("MCPC message lacks its mandatory field: TS 24.380 clauses 8.3.4 to 8.3.6");
  return message;
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.1.2 and 8.3.1: an RTCP APP packet (version 2) named "MCPC".
bool is_pre_established_message(std::span<const std::uint8_t> bytes) noexcept {
  return bytes.size() >= kHeaderSize && (bytes[0] >> 6) == 2 && bytes[1] == kRtcpApp &&
         std::ranges::equal(bytes.subspan(kNameOffset, kMcpc.size()), kMcpc);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.3 (see the header for "adhoc").
PreEstablishedSessionType pre_established_session_type(std::string_view session_type) noexcept {
  if (session_type == "private") return PreEstablishedSessionType::Private;
  if (session_type == "prearranged") return PreEstablishedSessionType::Prearranged;
  if (session_type == "chat") return PreEstablishedSessionType::Chat;
  return PreEstablishedSessionType::None;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.4.7 step 2 a iii with tables 8.3.3.8 and 8.3.3.11.
std::optional<PreEstablishedReasonCause> reason_cause_of(PreEstablishedReasonCode code) noexcept {
  switch (code) {
  case PreEstablishedReasonCode::Busy:
    return PreEstablishedReasonCause::Busy;
  case PreEstablishedReasonCode::MikeyAuthenticationFailed:
    return PreEstablishedReasonCause::MikeyAuthenticationFailed;
  case PreEstablishedReasonCode::IntegrityCheckFailed:
    return PreEstablishedReasonCause::IntegrityCheckFailed;
  case PreEstablishedReasonCode::DecryptionFailed:
    return PreEstablishedReasonCause::DecryptionFailed;
  default:
    return std::nullopt; // 'Accepted', and 'Not Accepted', which no Reason Cause matches
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.3.3 steps 1 a to d and 9.3.2.3.5 steps 1 a to d: the Connect to a terminating client.
PreEstablishedMessage make_terminating_connect(std::string_view contact_uri, std::string_view session_type,
                                               std::string_view calling_group, std::string_view calling_user,
                                               bool privacy, std::span<const std::uint8_t> pck_i_message,
                                               std::optional<PreEstablishedMediaStreams> media_streams) {
  PreEstablishedMessage connect;
  connect.type = PreEstablishedMessageType::Connect;
  connect.session_identity = std::string(contact_uri);
  connect.session_type = pre_established_session_type(session_type);
  const bool group = session_type == "prearranged" || session_type == "chat" || session_type == "adhoc";
  if (group) connect.group_identity = std::string(calling_group);
  if (group || session_type == "private")
    connect.inviting_user =
        privacy || calling_user.empty() ? std::string(pre_established_anonymous_user) : std::string(calling_user);
  if (session_type == "private") connect.pck_i_message.assign(pck_i_message.begin(), pck_i_message.end());
  connect.media_streams = media_streams;
  return connect;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.4.10 steps 1 a to e and g: the Connect to the originating client.
PreEstablishedMessage make_originating_connect(std::string_view contact_uri, std::string_view session_type,
                                               std::string_view warning_text, std::string_view answer_state,
                                               std::string_view called_party) {
  PreEstablishedMessage connect;
  connect.type = PreEstablishedMessageType::Connect;
  connect.session_identity = std::string(contact_uri);
  connect.session_type = pre_established_session_type(session_type);
  connect.warning_text = std::string(warning_text);
  // RFC 4964 section 4: the answer-type of P-Answer-State, "Confirmed" or "Unconfirmed", case-insensitive.
  auto lower = std::string(answer_state.substr(0, answer_state.find(';')));
  std::ranges::transform(lower, lower.begin(), [](unsigned char letter) { return std::tolower(letter); });
  if (lower == "unconfirmed") connect.answer_state = PreEstablishedAnswerState::Unconfirmed;
  if (lower == "confirmed") connect.answer_state = PreEstablishedAnswerState::Confirmed;
  connect.invited_user = std::string(called_party);
  return connect;
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.2.2.3.2 and 9.2.2.4.2: the Acknowledge of this floor participant.
PreEstablishedMessage PreEstablishedClient::acknowledge(PreEstablishedReasonCode code) const {
  PreEstablishedMessage ack;
  ack.type = PreEstablishedMessageType::Acknowledge;
  ack.ssrc = local_ssrc_;
  ack.reason_code = code;
  return ack;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2.2.2: enter 'U: Pre-established session not in use'.
void PreEstablishedClient::started() { state_ = PreEstablishedClientState::NotInUse; }

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2.3.3: enter 'Start-stop'.
void PreEstablishedClient::stopped() { state_ = PreEstablishedClientState::StartStop; }

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2.3.2 (not in use: acknowledge with the client's answer and, if accepted, start the call) and
// clause 9.2.2.4.2 (in use: acknowledge only if asked).
PreEstablishedClientOutcome PreEstablishedClient::receive_connect(const PreEstablishedMessage &connect,
                                                                  PreEstablishedReasonCode answer) {
  PreEstablishedClientOutcome outcome;
  if (state_ == PreEstablishedClientState::NotInUse) {
    outcome.acknowledge = acknowledge(answer);
    if (answer == PreEstablishedReasonCode::Accepted) {
      outcome.call_started = true;
      state_ = PreEstablishedClientState::InUse;
    }
  } else if (state_ == PreEstablishedClientState::InUse && connect.ack_required) {
    outcome.acknowledge = acknowledge(PreEstablishedReasonCode::Accepted);
  }
  return outcome;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2.3.4 (not in use: acknowledge if asked) and clause 9.2.2.4.5 (in use: acknowledge if asked,
// end the call, enter 'U: Pre-established session not in use').
PreEstablishedClientOutcome PreEstablishedClient::receive_disconnect(const PreEstablishedMessage &disconnect) {
  PreEstablishedClientOutcome outcome;
  if (state_ == PreEstablishedClientState::StartStop) return outcome;
  if (disconnect.ack_required) outcome.acknowledge = acknowledge(PreEstablishedReasonCode::Accepted);
  if (state_ == PreEstablishedClientState::InUse) {
    outcome.call_ended = true;
    state_ = PreEstablishedClientState::NotInUse;
  }
  return outcome;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2.3.5: enter 'U: Pre-established session in use'.
void PreEstablishedClient::call_refer_accepted() {
  if (state_ == PreEstablishedClientState::NotInUse) state_ = PreEstablishedClientState::InUse;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2.3.6: enter 'U: Pre-established session in use'.
void PreEstablishedClient::call_reinvite_answered() { call_refer_accepted(); }

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2.4.6: enter 'U: Pre-established session not in use'.
void PreEstablishedClient::leave_refer_accepted() {
  if (state_ == PreEstablishedClientState::InUse) state_ = PreEstablishedClientState::NotInUse;
}

//------------------------------------------------------------------------------
// TS 24.380 tables 11.1.4-1 and 11.2.4-1: checks the timers and counters.
PreEstablishedServer::PreEstablishedServer(std::uint32_t local_ssrc, PreEstablishedTimerOptions options)
    : local_ssrc_(local_ssrc), options_(options) {
  if (options.t55_ms == 0 || options.t55_ms > kTimerMaximumMs || options.t56_ms == 0 ||
      options.t56_ms > kTimerMaximumMs)
    throw std::invalid_argument("T55 and T56 are at most 4 s: TS 24.380 table 11.1.4-1");
  if (options.c55 == 0 || options.c56 == 0) throw std::invalid_argument("C55 and C56 are at least 1");
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.2.2: enter 'G: Pre-established session not in use'.
void PreEstablishedServer::started() { state_ = PreEstablishedServerState::NotInUse; }

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.3.4 and 9.3.2.4.6: release the timers and enter 'Start-stop'.
void PreEstablishedServer::stopped() {
  t55_.reset();
  t56_.reset();
  session_identity_.clear();
  state_ = PreEstablishedServerState::StartStop;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.3.2: enter 'G: Pre-established session in use'.
void PreEstablishedServer::refer_received() {
  if (state_ == PreEstablishedServerState::NotInUse) state_ = PreEstablishedServerState::InUse;
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.3.3 steps 1 e to 5, 9.3.2.3.5 steps 1 e to 5 and 9.3.2.4.10 steps 1 f to 4.
PreEstablishedMessage PreEstablishedServer::connect(PreEstablishedMessage connect, std::uint64_t now_ms) {
  if (state_ == PreEstablishedServerState::StartStop)
    throw std::logic_error("Connect without a pre-established session: TS 24.380 clause 9.3.2.2");
  connect.type = PreEstablishedMessageType::Connect;
  connect.ssrc = local_ssrc_;
  connect.ack_required = true;
  session_identity_ = connect.session_identity;
  session_type_ = connect.session_type;
  t56_.reset();
  t55_ = Pending{connect, now_ms, 1};
  state_ = PreEstablishedServerState::InUse;
  return connect;
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.4.5 steps 1 to 5 and 9.3.2.4.11 steps 1 to 5.
PreEstablishedMessage PreEstablishedServer::disconnect(std::uint64_t now_ms,
                                                       std::optional<PreEstablishedReasonCause> cause,
                                                       std::string_view session_identity) {
  PreEstablishedMessage message;
  message.type = PreEstablishedMessageType::Disconnect;
  message.ssrc = local_ssrc_;
  message.ack_required = true;
  message.session_type = session_identity_.empty() ? PreEstablishedSessionType::None : session_type_;
  message.session_identity = session_identity_.empty() ? std::string(session_identity) : session_identity_;
  message.reason_cause = cause;
  t55_.reset();
  t56_ = Pending{message, now_ms, 1};
  state_ = PreEstablishedServerState::CallReleasing;
  return message;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.4.4 steps 3 and 4.
void PreEstablishedServer::client_released() {
  if (state_ != PreEstablishedServerState::InUse) return;
  t55_.reset();
  session_identity_.clear();
  state_ = PreEstablishedServerState::NotInUse;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.4.7 (in use: accepted, or a refusal answered with a Disconnect) and clause 9.3.2.5.2
// (releasing: the Disconnect is acknowledged).
std::optional<PreEstablishedMessage> PreEstablishedServer::receive_acknowledge(const PreEstablishedMessage &acknowledge,
                                                                               std::uint64_t now_ms) {
  if (acknowledge.type != PreEstablishedMessageType::Acknowledge) return std::nullopt;
  if (state_ == PreEstablishedServerState::CallReleasing) {
    t55_.reset();
    t56_.reset();
    session_identity_.clear();
    state_ = PreEstablishedServerState::NotInUse;
    events_.push_back(PreEstablishedServerEvent::DisconnectAcknowledged);
    return std::nullopt;
  }
  if (state_ != PreEstablishedServerState::InUse || !t55_) return std::nullopt;
  t55_.reset();
  const auto code = acknowledge.reason_code.value_or(PreEstablishedReasonCode::Accepted);
  if (code == PreEstablishedReasonCode::Accepted) {
    events_.push_back(PreEstablishedServerEvent::ConnectAccepted);
    return std::nullopt;
  }
  events_.push_back(PreEstablishedServerEvent::ConnectRefused);
  return disconnect(now_ms, reason_cause_of(code));
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.4.8 and 9.3.2.4.9 (T55: retransmit the Connect until C55 is reached, then release the call
// and enter 'not in use'), 9.3.2.5.3 and 9.3.2.5.4 (T56: the same for the Disconnect).
std::vector<PreEstablishedMessage> PreEstablishedServer::tick(std::uint64_t now_ms) {
  std::vector<PreEstablishedMessage> out;
  if (t55_ && now_ms >= t55_->sent_ms + options_.t55_ms) {
    if (t55_->count >= options_.c55) {
      t55_.reset();
      session_identity_.clear();
      state_ = PreEstablishedServerState::NotInUse;
      events_.push_back(PreEstablishedServerEvent::ConnectExpired);
    } else {
      ++t55_->count;
      t55_->sent_ms = now_ms;
      out.push_back(t55_->message);
    }
  }
  if (t56_ && now_ms >= t56_->sent_ms + options_.t56_ms) {
    if (t56_->count >= options_.c56) {
      t56_.reset();
      session_identity_.clear();
      state_ = PreEstablishedServerState::NotInUse;
      events_.push_back(PreEstablishedServerEvent::DisconnectExpired);
    } else {
      ++t56_->count;
      t56_->sent_ms = now_ms;
      out.push_back(t56_->message);
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: the events since the last call.
std::vector<PreEstablishedServerEvent> PreEstablishedServer::take_events() { return std::exchange(events_, {}); }

} // namespace mcx
