//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Call setup control over a pre-established session, media plane: the pre-established session call control messages
// of TS 24.380 clause 8.3 ("MCPC": Connect, Disconnect, Acknowledge) and the two state machines of TS 24.380 clause 9:
// the MCPTT client's (clause 9.2.2) and the participating MCPTT function's (clause 9.3.2) with timers T55 (Connect)
// and T56 (Disconnect) and counters C55 and C56 (clause 11.1.4 and clause 11.2.4). The messages are RTCP APP packets
// coded as in TS 24.380 clause 8.1 (include/mcx/floor.hpp) and travel on the media plane control channel of the
// pre-established session, protected like floor control (TS 24.380 clause 13.3.2 step 6, clause 13.3.3).
//
// Where the specification is unclear, this code takes (see docs/3GPP_CORRECTION_CANDIDATES.md, S01 to S05):
//   - the privacy identity of the Inviting MCPTT User Identity field is "sip:anonymous@anonymous.invalid"
//     (RFC 3323 section 4.1.1.3), where clause 8.3.4 gives <sip:anonymous@invalid.invalid> and clause 9.3.2.3.3
//     'anonymous@anonymous.invalid';
//   - an ad hoc group call's Connect carries Session Type 'no session type' (0): clause 9.3.2.3.3 b ii asks for
//     'adhoc', which table 8.3.3.3 does not code;
//   - a Connect sent on a SIP 200 (OK) from the controlling function (clause 9.3.2.4.10) initialises C55 to 1, where
//     step 3 says "increment";
//   - an Acknowledge with Reason Code 'Not Accepted' leads to a Disconnect without a Reason Cause field: table
//     8.3.3.11 has no value corresponding to it (clause 9.3.2.4.7 step 2 a iii);
//   - the participating function always asks for an Acknowledge (the first subtype bit), where clauses 9.3.2.3.5,
//     9.3.2.4.5, 9.3.2.4.10 and 9.3.2.4.11 make it optional, so that T55 and T56, which those clauses start in every
//     case, can stop.
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), RFC 3550,
// RFC 3323.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.380 table 8.3.2-1: the pre-established session call control messages, by subtype (without the first bit).
enum class PreEstablishedMessageType : std::uint8_t { Connect = 0, Disconnect = 1, Acknowledge = 2 };

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.3: the <Session Type> value of the MCPTT Session Identity field. Other values are reserved;
// a received one is kept as its number.
enum class PreEstablishedSessionType : std::uint8_t { None = 0, Private = 1, Prearranged = 3, Chat = 4 };

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.6: the <Answer State> value.
enum class PreEstablishedAnswerState : std::uint16_t { Unconfirmed = 0, Confirmed = 1 };

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.8: the <Reason Code> value of an Acknowledge.
enum class PreEstablishedReasonCode : std::uint16_t {
  Accepted = 0,
  Busy = 1,
  NotAccepted = 2,
  MikeyAuthenticationFailed = 3,
  IntegrityCheckFailed = 4,
  DecryptionFailed = 5,
};

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.11: the <Reason Cause> value of a Disconnect.
enum class PreEstablishedReasonCause : std::uint16_t {
  Busy = 0,
  MikeyAuthenticationFailed = 1,
  IntegrityCheckFailed = 2,
  DecryptionFailed = 3,
  InactivityTimerExpired = 4,
  OneOrNoParticipants = 5,
  MinimumAffiliatedMembersAbsent = 6,
  GroupCallTimerExpired = 7,
  PrivateCallMaximumDuration = 8,
  BearerFailedCallEnded = 9,
  BearerFailedCallContinues = 10,
};

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.2: the Media Streams field: the numbers of the "m=audio" and "m=application" m-lines
// negotiated in the pre-established session; control channel 0 when the call has no floor control.
struct PreEstablishedMediaStreams {
  std::uint8_t media_stream = 1;
  std::uint8_t control_channel = 2;

  bool operator==(const PreEstablishedMediaStreams &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.3.4 to 8.3.6: a pre-established session call control message. Which fields a message has:
//   Connect: MCPTT Session Identity (mandatory), MCPTT Group Identity, Media Streams, Warning Text, Answer State,
//   Inviting and Invited MCPTT User Identity, PCK I_MESSAGE;
//   Disconnect: MCPTT Session Identity (mandatory), Reason Cause;
//   Acknowledge: Reason Code (mandatory); never asks for an acknowledgement.
// Empty strings and unset optionals are fields not sent. ssrc is the participating function's (Connect,
// Disconnect) or the floor participant's (Acknowledge).
struct PreEstablishedMessage {
  PreEstablishedMessageType type = PreEstablishedMessageType::Connect;
  bool ack_required = false;
  std::uint32_t ssrc = 0;
  PreEstablishedSessionType session_type = PreEstablishedSessionType::None;
  std::string session_identity;
  std::string group_identity;
  std::optional<PreEstablishedMediaStreams> media_streams;
  std::string warning_text;
  std::optional<PreEstablishedAnswerState> answer_state;
  std::string inviting_user;
  std::string invited_user;
  std::vector<std::uint8_t> pck_i_message; // the MIKEY-SAKKE I_MESSAGE as received in the SIP INVITE
  std::optional<PreEstablishedReasonCause> reason_cause;
  std::optional<PreEstablishedReasonCode> reason_code;

  bool operator==(const PreEstablishedMessage &) const = default;
};

// TS 24.380 clause 9.3.2.3.3 b iv and c ii, clause 8.3.4: the Inviting MCPTT User Identity of a user who asked for
// privacy, or whose MCPTT ID the INVITE does not give (see the file header).
inline constexpr std::string_view pre_established_anonymous_user = "sip:anonymous@anonymous.invalid";

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.3.2 to 8.3.6: encodes a pre-established session call control message as an RTCP APP packet
// named "MCPC"; throws when a mandatory field is missing or a field does not fit.
std::vector<std::uint8_t> encode_pre_established(const PreEstablishedMessage &message);
//------------------------------------------------------------------------------
// TS 24.380 clauses 8.3.2 to 8.3.6 with clause 8.3.3.9: decodes an "MCPC" packet. An unknown subtype gives no message
// (step 1: the whole message is ignored); unknown fields and malformed optional fields are skipped (steps 2 and 3).
// Throws when the packet is not an "MCPC" APP packet or lacks a mandatory field.
std::optional<PreEstablishedMessage> decode_pre_established(std::span<const std::uint8_t> bytes);
//------------------------------------------------------------------------------
// Whether a packet is an RTCP APP packet named "MCPC", to tell it from floor control ("MCPT") on the same channel.
[[nodiscard]] bool is_pre_established_message(std::span<const std::uint8_t> bytes) noexcept;

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2: the states of the MCPTT client's call setup control over pre-established session state
// machine, one instance per pre-established session.
enum class PreEstablishedClientState { StartStop, NotInUse, InUse };

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2: what the MCPTT client does with a received Connect or Disconnect: the Acknowledge to send,
// and whether a call started on the session (create the floor participant of clause 6.2.4) or ended (terminate it).
struct PreEstablishedClientOutcome {
  std::optional<PreEstablishedMessage> acknowledge;
  bool call_started = false;
  bool call_ended = false;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2: the MCPTT client's call setup control over pre-established session state machine. The
// caller passes the session call control messages of this session's control channel and the SIP events of TS 24.379,
// and runs the floor participant (clause 6.2.4) while the state is 'U: Pre-established session in use'. Messages
// with no procedure in the current state are discarded (clause 9.2.2.1).
class PreEstablishedClient {
public:
  explicit PreEstablishedClient(std::uint32_t local_ssrc) : local_ssrc_(local_ssrc) {}

  // TS 24.380 clause 4.3 (TS 24.379 clause 6.3.2.1.2.2 NOTE): the Acknowledge carries the SSRC the participating
  // function gave in its SDP answer ("mc_floor_ssrc"), known once the session's media are negotiated.
  void set_ssrc(std::uint32_t ssrc) noexcept { local_ssrc_ = ssrc; }

  // TS 24.380 clause 9.2.2.2.2: the pre-established session is created (TS 24.379 clause 8.2.1).
  void started();
  // TS 24.380 clause 9.2.2.3.3: the pre-established session is released (TS 24.379 clause 8.4).
  void stopped();
  // TS 24.380 clauses 9.2.2.3.2 and 9.2.2.4.2: a Connect. In 'U: Pre-established session not in use', `answer` is
  // the client's decision (Accepted, or why not); in use, the Connect is only acknowledged if asked.
  PreEstablishedClientOutcome receive_connect(const PreEstablishedMessage &connect,
                                              PreEstablishedReasonCode answer = PreEstablishedReasonCode::Accepted);
  // TS 24.380 clauses 9.2.2.3.4 and 9.2.2.4.5: a Disconnect.
  PreEstablishedClientOutcome receive_disconnect(const PreEstablishedMessage &disconnect);
  // TS 24.380 clause 9.2.2.3.5: a 2xx to the SIP REFER that starts a call on the session.
  void call_refer_accepted();
  // TS 24.380 clause 9.2.2.3.6: the 200 (OK) to the SIP re-INVITE that starts a call on the session is sent.
  void call_reinvite_answered();
  // TS 24.380 clause 9.2.2.4.6: a 2xx to the SIP REFER that leaves the call and keeps the session.
  void leave_refer_accepted();

  [[nodiscard]] PreEstablishedClientState state() const noexcept { return state_; }

private:
  PreEstablishedMessage acknowledge(PreEstablishedReasonCode code) const;

  std::uint32_t local_ssrc_;
  PreEstablishedClientState state_ = PreEstablishedClientState::StartStop;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2: the states of the participating MCPTT function's call setup control over pre-established
// session state machine, one instance per pre-established session.
enum class PreEstablishedServerState { StartStop, NotInUse, InUse, CallReleasing };

//------------------------------------------------------------------------------
// TS 24.380 table 11.1.4-1 and table 11.2.4-1: T55 (Connect) and T56 (Disconnect), default 2 s, at most 4 s; C55 and
// C56, default 3. Provisioned by the <T55-connect>, <T56-disconnect>, <C55-connect> and <C56-disconnect> elements of
// <fc-timers-counters> (TS 24.484 clause 8.3.2).
struct PreEstablishedTimerOptions {
  std::uint64_t t55_ms = 2000;
  std::uint64_t t56_ms = 2000;
  unsigned c55 = 3;
  unsigned c56 = 3;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2: what the participating function learns, for the call control of TS 24.379.
enum class PreEstablishedServerEvent {
  // Clause 9.3.2.4.7 step 3: the client accepted the call; send the 200 (OK) to the controlling function's INVITE
  // if not yet sent.
  ConnectAccepted,
  // Clause 9.3.2.4.7 step 2 d: the client refused it; send the call release to the controlling function.
  ConnectRefused,
  // Clause 9.3.2.4.9: no Acknowledge after C55 Connects; send the call release to the controlling function.
  ConnectExpired,
  // Clause 9.3.2.5.2: the Disconnect was acknowledged; the session is free again.
  DisconnectAcknowledged,
  // Clause 9.3.2.5.4: no Acknowledge after C56 Disconnects; the session is free again.
  DisconnectExpired,
};

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2: the participating MCPTT function's call setup control over pre-established session state
// machine with T55 and T56. The caller transmits every message the methods return, passes received Acknowledge
// messages, calls tick on its clock, and acts on the events of take_events.
class PreEstablishedServer {
public:
  // Throws when a timer exceeds its 4 s maximum or a counter is 0 (table 11.1.4-1, table 11.2.4-1).
  explicit PreEstablishedServer(std::uint32_t local_ssrc, PreEstablishedTimerOptions options = {});

  // TS 24.380 clause 9.3.2.2.2: the pre-established session is created (TS 24.379 clause 8.2.2).
  void started();
  // TS 24.380 clauses 9.3.2.3.4 and 9.3.2.4.6: the pre-established session is released; timers stop.
  void stopped();
  // TS 24.380 clause 9.3.2.3.2: a SIP REFER from the client starts a call on the session.
  void refer_received();
  // TS 24.380 clauses 9.3.2.3.3, 9.3.2.3.5 and 9.3.2.4.10: send a Connect (built by the caller from the SIP
  // request or response, see make_connect), start T55 and set C55 to 1; enter 'G: Pre-established session in use'.
  // Returns the Connect to transmit, with this function's SSRC and the acknowledgement bit set.
  PreEstablishedMessage connect(PreEstablishedMessage connect, std::uint64_t now_ms);
  // TS 24.380 clauses 9.3.2.4.5 and 9.3.2.4.11: the controlling function released the call or refused it: stop T55,
  // send a Disconnect with the MCPTT Session Identity of the Connect (or `session_identity` when no Connect was
  // sent), start T56, set C56 to 1 and enter 'G: Call releasing'.
  PreEstablishedMessage disconnect(std::uint64_t now_ms, std::optional<PreEstablishedReasonCause> cause = {},
                                   std::string_view session_identity = {});
  // TS 24.380 clause 9.3.2.4.4: the client left the call keeping the session (SIP REFER "BYE"): stop T55 and enter
  // 'G: Pre-established session not in use'.
  void client_released();
  // TS 24.380 clauses 9.3.2.4.7 and 9.3.2.5.2: an Acknowledge from the client. Returns the Disconnect to transmit
  // when the client refused the call.
  std::optional<PreEstablishedMessage> receive_acknowledge(const PreEstablishedMessage &acknowledge,
                                                           std::uint64_t now_ms);
  // TS 24.380 clauses 9.3.2.4.8, 9.3.2.4.9, 9.3.2.5.3 and 9.3.2.5.4: the retransmissions due by now.
  std::vector<PreEstablishedMessage> tick(std::uint64_t now_ms);
  std::vector<PreEstablishedServerEvent> take_events();

  [[nodiscard]] PreEstablishedServerState state() const noexcept { return state_; }

  // The MCPTT Session Identity of the call on the session (the last Connect's), empty when none.
  [[nodiscard]] const std::string &session_identity() const noexcept { return session_identity_; }

private:
  struct Pending {
    PreEstablishedMessage message;
    std::uint64_t sent_ms = 0;
    unsigned count = 0;
  };

  std::uint32_t local_ssrc_;
  PreEstablishedTimerOptions options_;
  PreEstablishedServerState state_ = PreEstablishedServerState::StartStop;
  std::optional<Pending> t55_, t56_;
  PreEstablishedSessionType session_type_ = PreEstablishedSessionType::None;
  std::string session_identity_;
  std::vector<PreEstablishedServerEvent> events_;
};

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.3.3 and 9.3.2.3.5: the Connect to a terminating client, from the controlling function's
// SIP INVITE (or re-INVITE): its Contact URI, the <session-type>, <mcptt-calling-group-id> and
// <mcptt-calling-user-id> of its MCPTT-Info (an empty calling user, or `privacy`, gives the anonymous identity), its
// MIKEY-SAKKE I_MESSAGE for a private call, and the Media Streams field when the call does not use every stream of
// the session (`floor_control` false: control channel 0). `session_type` is the <session-type> text ("prearranged",
// "chat", "adhoc", "private").
//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.10 with RFC 4567 section 3.1: the PCK I_MESSAGE field holds the MIKEY-SAKKE I_MESSAGE as
// received in the SIP INVITE, whose "a=key-mgmt:mikey" carries it base64 encoded: the octets of that text, and back.
// pck_i_message_of throws on text that is not base64.
std::vector<std::uint8_t> pck_i_message_of(std::string_view key_mgmt);
std::string key_mgmt_of(std::span<const std::uint8_t> pck_i_message);

PreEstablishedMessage make_terminating_connect(std::string_view contact_uri, std::string_view session_type,
                                               std::string_view calling_group, std::string_view calling_user,
                                               bool privacy, std::span<const std::uint8_t> pck_i_message = {},
                                               std::optional<PreEstablishedMediaStreams> media_streams = {});
//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.4.10: the Connect to the originating client, from the controlling function's SIP 200 (OK):
// its Contact URI, the <session-type> of its MCPTT-Info (empty: 'no session type'), the warn-text of a Warning 399,
// the answer-type of its P-Answer-State ("Unconfirmed" or "Confirmed"; empty: no field) and its
// <mcptt-called-party-id> (empty: no field).
PreEstablishedMessage make_originating_connect(std::string_view contact_uri, std::string_view session_type,
                                               std::string_view warning_text, std::string_view answer_state,
                                               std::string_view called_party);
//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.3: the <Session Type> value of a <session-type> element of TS 24.379 annex F.1 ("private",
// "prearranged", "chat"; anything else, "adhoc" included, is 'no session type': see the file header).
PreEstablishedSessionType pre_established_session_type(std::string_view session_type) noexcept;
//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.4.7 step 2 a iii: the Reason Cause corresponding to a Reason Code other than 'Accepted';
// none for 'Not Accepted' (see the file header).
std::optional<PreEstablishedReasonCause> reason_cause_of(PreEstablishedReasonCode code) noexcept;

} // namespace mcx
