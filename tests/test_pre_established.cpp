//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Call setup control over a pre-established session, media plane (include/mcx/pre_established.hpp): byte-exact
// "MCPC" messages worked out from the tables of TS 24.380 clause 8.3, the handling of unknown and malformed content
// of clause 8.3.3.9, and the state machines of clauses 9.2.2 and 9.3.2 with T55 and T56.
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19).

#include "mcx/floor.hpp"
#include "mcx/pre_established.hpp"

#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<std::uint8_t>;
using mcx::PreEstablishedMessage;
using mcx::PreEstablishedMessageType;
using mcx::PreEstablishedReasonCode;
using mcx::PreEstablishedServerEvent;
using mcx::PreEstablishedServerState;

//------------------------------------------------------------------------------
// Checks that the operation throws; what names what would have been wrongly accepted.
static void rejects(const std::function<void()> &operation, const std::string &what) {
  try {
    operation();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(what + " accepted");
}

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Helper: a Connect of a prearranged group call.
static PreEstablishedMessage group_connect() {
  PreEstablishedMessage connect;
  connect.type = PreEstablishedMessageType::Connect;
  connect.ack_required = true;
  connect.ssrc = 0x01020304;
  connect.session_type = mcx::PreEstablishedSessionType::Prearranged;
  connect.session_identity = "sip:s@x";
  connect.group_identity = "sip:g@x";
  connect.media_streams = mcx::PreEstablishedMediaStreams{1, 2};
  connect.answer_state = mcx::PreEstablishedAnswerState::Unconfirmed;
  return connect;
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.3.4-1 with clauses 8.3.3.2, 8.3.3.3, 8.3.3.5 and 8.3.3.6: a Connect asking for an
// acknowledgement, octet by octet. The MCPTT Session Identity is padded to (1 + a multiple of 4) octets after its
// Session Type octet, the Group Identity to (2 + a multiple of 4).
static void Clause_8_3_4_ConnectOctets() {
  const Bytes expected = {
      0x90, 0xcc, 0x00, 0x0a, 0x01, 0x02, 0x03, 0x04, 'M', 'C', 'P', 'C',  // x=1 subtype 0, 11 words, SSRC, name
      0x01, 0x08, 0x03, 's',  'i',  'p',  ':',  's',  '@', 'x', 0x00, 0x00, // Session Identity, prearranged
      0x03, 0x07, 's',  'i',  'p',  ':',  'g',  '@',  'x', 0x00, 0x00, 0x00, // Group Identity
      0x00, 0x02, 0x01, 0x02,                                                // Media Streams: m-lines 1 and 2
      0x04, 0x02, 0x00, 0x00,                                                // Answer State: Unconfirmed
  };
  expect(mcx::encode_pre_established(group_connect()) == expected, "Connect octets");
  const auto decoded = mcx::decode_pre_established(expected);
  expect(decoded && *decoded == group_connect(), "Connect round trip");
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.3.6-1 with clause 8.3.3.8: an Acknowledge 'Busy', octet by octet (subtype 00010).
static void Clause_8_3_6_AcknowledgeOctets() {
  PreEstablishedMessage ack;
  ack.type = PreEstablishedMessageType::Acknowledge;
  ack.ssrc = 0xaabbccdd;
  ack.reason_code = PreEstablishedReasonCode::Busy;
  const Bytes expected = {0x82, 0xcc, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0xdd, 'M', 'C', 'P', 'C', 0x06, 0x02, 0x00, 0x01};
  expect(mcx::encode_pre_established(ack) == expected, "Acknowledge octets");
  const auto decoded = mcx::decode_pre_established(expected);
  expect(decoded && *decoded == ack, "Acknowledge round trip");
  ack.ack_required = true;
  rejects([&] { (void)mcx::encode_pre_established(ack); }, "Acknowledge asking for an acknowledgement");
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.3.5-1 with clause 8.3.3.11: a Disconnect with a Reason Cause; and one without acknowledgement.
static void Clause_8_3_5_DisconnectRoundTrip() {
  PreEstablishedMessage disconnect;
  disconnect.type = PreEstablishedMessageType::Disconnect;
  disconnect.ack_required = true;
  disconnect.ssrc = 7;
  disconnect.session_type = mcx::PreEstablishedSessionType::Chat;
  disconnect.session_identity = "sip:call-17@mcptt.example";
  disconnect.reason_cause = mcx::PreEstablishedReasonCause::GroupCallTimerExpired;
  const auto bytes = mcx::encode_pre_established(disconnect);
  expect(bytes[0] == 0x91, "Disconnect subtype x0001 with x=1");
  expect(mcx::decode_pre_established(bytes) == disconnect, "Disconnect round trip");
  disconnect.ack_required = false;
  disconnect.reason_cause.reset();
  const auto plain = mcx::encode_pre_established(disconnect);
  expect(plain[0] == 0x81, "Disconnect subtype 00001");
  expect(mcx::decode_pre_established(plain) == disconnect, "Disconnect without Reason Cause");
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.10 with clause 8.1.3: the PCK I_MESSAGE field (ID 192) has a two-octet length, so an
// I_MESSAGE longer than 255 octets fits; the Inviting and Invited MCPTT User Identity fields of a private call.
static void Clause_8_3_3_10_PckIMessage() {
  PreEstablishedMessage connect;
  connect.ssrc = 1;
  connect.session_type = mcx::PreEstablishedSessionType::Private;
  connect.session_identity = "sip:private-1@mcptt.example";
  connect.inviting_user = "sip:alice@mcptt.example";
  connect.invited_user = "sip:bob@mcptt.example";
  connect.warning_text = "107 User not authorised to make private calls";
  for (int octet = 0; octet < 400; ++octet) connect.pck_i_message.push_back(static_cast<std::uint8_t>(octet));
  const auto bytes = mcx::encode_pre_established(connect);
  expect(bytes.size() % 4 == 0, "Connect is whole words");
  expect(mcx::decode_pre_established(bytes) == connect, "private call Connect round trip");
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.9: an unknown subtype ignores the whole message (an Acknowledge with the first bit set is
// one); unknown fields and malformed optional fields are skipped; a missing mandatory field is refused.
static void Clause_8_3_3_9_UnknownAndMalformed() {
  Bytes unknown_subtype = {0x83, 0xcc, 0x00, 0x03, 0, 0, 0, 1, 'M', 'C', 'P', 'C', 0x06, 0x02, 0x00, 0x00};
  expect(!mcx::decode_pre_established(unknown_subtype), "subtype 00011 ignored");
  unknown_subtype[0] = 0x92;
  expect(!mcx::decode_pre_established(unknown_subtype), "Acknowledge with x=1 ignored");

  mcx::AppPacket packet;
  packet.subtype = 0;
  packet.ssrc = 9;
  packet.name = {'M', 'C', 'P', 'C'};
  packet.fields = {{1, {0x01, 's', ':', 'x'}}, {42, {1, 2, 3}}, {4, {0x01}}, {0, {1}}};
  const auto connect = mcx::decode_pre_established(mcx::encode_app(packet));
  expect(connect && connect->session_identity == "s:x", "Connect with unknown field");
  expect(!connect->answer_state && !connect->media_streams, "malformed Answer State and Media Streams skipped");

  packet.fields = {{7, {0, 1}}};
  rejects([&] { (void)mcx::decode_pre_established(mcx::encode_app(packet)); }, "Connect without Session Identity");
  packet.subtype = 2;
  packet.fields = {{6, {0}}};
  rejects([&] { (void)mcx::decode_pre_established(mcx::encode_app(packet)); }, "Acknowledge with a short Reason Code");
  packet.name = {'M', 'C', 'P', 'T'};
  expect(!mcx::is_pre_established_message(mcx::encode_app(packet)), "MCPT is not MCPC");
  rejects([&] { (void)mcx::decode_pre_established(mcx::encode_app(packet)); }, "MCPT decoded as MCPC");

  PreEstablishedMessage no_identity;
  rejects([&] { (void)mcx::encode_pre_established(no_identity); }, "Connect encoded without Session Identity");
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.2.2.3.2: in 'U: Pre-established session not in use' the client acknowledges a Connect with its
// answer; an accepted one starts the call, a refused one leaves the session not in use.
static void Clause_9_2_2_3_2_ClientReceivesConnect() {
  mcx::PreEstablishedClient client(0x55);
  expect(!client.receive_connect(group_connect()).acknowledge, "Connect discarded in 'Start-stop' (clause 9.2.2.1)");
  client.started();
  auto refused = client.receive_connect(group_connect(), PreEstablishedReasonCode::Busy);
  expect(refused.acknowledge && refused.acknowledge->reason_code == PreEstablishedReasonCode::Busy, "Busy answer");
  expect(!refused.call_started && client.state() == mcx::PreEstablishedClientState::NotInUse, "refused: not in use");
  auto accepted = client.receive_connect(group_connect());
  expect(accepted.call_started && accepted.acknowledge->ssrc == 0x55, "accepted: Acknowledge with own SSRC");
  expect(accepted.acknowledge->reason_code == PreEstablishedReasonCode::Accepted, "Accepted reason");
  expect(client.state() == mcx::PreEstablishedClientState::InUse, "in use");
  // Clause 9.2.2.4.2: a repeated Connect in use is acknowledged only.
  auto repeated = client.receive_connect(group_connect());
  expect(repeated.acknowledge && !repeated.call_started, "repeated Connect acknowledged");
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.2.2.3.4 and 9.2.2.4.5: a Disconnect is acknowledged when asked, and in use ends the call.
static void Clause_9_2_2_4_5_ClientReceivesDisconnect() {
  mcx::PreEstablishedClient client(0x55);
  client.started();
  PreEstablishedMessage disconnect;
  disconnect.type = PreEstablishedMessageType::Disconnect;
  disconnect.session_identity = "sip:s@x";
  auto idle = client.receive_disconnect(disconnect);
  expect(!idle.acknowledge && !idle.call_ended, "not in use, no acknowledgement asked");
  client.call_refer_accepted();
  expect(client.state() == mcx::PreEstablishedClientState::InUse, "2xx to the REFER: in use (clause 9.2.2.3.5)");
  disconnect.ack_required = true;
  auto ended = client.receive_disconnect(disconnect);
  expect(ended.acknowledge && ended.call_ended, "in use: acknowledged and ended");
  expect(client.state() == mcx::PreEstablishedClientState::NotInUse, "back to not in use");
  client.call_reinvite_answered();
  client.leave_refer_accepted();
  expect(client.state() == mcx::PreEstablishedClientState::NotInUse, "2xx to REFER BYE (clause 9.2.2.4.6)");
  client.stopped();
  expect(client.state() == mcx::PreEstablishedClientState::StartStop, "stopped (clause 9.2.2.3.3)");
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.3.3, 9.3.2.4.8 and 9.3.2.4.9: the Connect asks for an acknowledgement and is resent on T55
// until C55 transmissions; then the call is released and the session is not in use.
static void Clause_9_3_2_4_9_ConnectExpires() {
  mcx::PreEstablishedServer server(0x99);
  server.started();
  const auto sent = server.connect(group_connect(), 1000);
  expect(sent.ack_required && sent.ssrc == 0x99, "Connect with the x bit and the function's SSRC");
  expect(server.state() == PreEstablishedServerState::InUse, "in use");
  expect(server.tick(2999).empty(), "T55 not yet expired");
  expect(server.tick(3000).size() == 1, "second Connect at T55");
  expect(server.tick(5000).size() == 1, "third Connect");
  expect(server.tick(7000).empty(), "no fourth Connect");
  expect(server.take_events() == std::vector{PreEstablishedServerEvent::ConnectExpired}, "ConnectExpired");
  expect(server.state() == PreEstablishedServerState::NotInUse, "not in use after C55");
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.4.7, 9.3.2.5.2 to 9.3.2.5.4: an accepted Connect stops T55; a refused one is answered by a
// Disconnect with the corresponding Reason Cause, resent on T56 until acknowledged or C56.
static void Clause_9_3_2_4_7_Acknowledge() {
  mcx::PreEstablishedServer server(0x99);
  server.started();
  (void)server.connect(group_connect(), 0);
  PreEstablishedMessage ack;
  ack.type = PreEstablishedMessageType::Acknowledge;
  ack.reason_code = PreEstablishedReasonCode::Accepted;
  expect(!server.receive_acknowledge(ack, 100), "accepted: no Disconnect");
  expect(server.take_events() == std::vector{PreEstablishedServerEvent::ConnectAccepted}, "ConnectAccepted");
  expect(server.tick(10000).empty(), "T55 stopped");

  (void)server.connect(group_connect(), 20000);
  ack.reason_code = PreEstablishedReasonCode::Busy;
  const auto disconnect = server.receive_acknowledge(ack, 20100);
  expect(disconnect && disconnect->type == PreEstablishedMessageType::Disconnect, "refused: Disconnect");
  expect(disconnect->session_identity == "sip:s@x" && disconnect->ack_required, "Session Identity of the Connect");
  expect(disconnect->reason_cause == mcx::PreEstablishedReasonCause::Busy, "Reason Cause Busy");
  expect(server.take_events() == std::vector{PreEstablishedServerEvent::ConnectRefused}, "ConnectRefused");
  expect(server.state() == PreEstablishedServerState::CallReleasing, "call releasing");
  expect(server.tick(22100).size() == 1, "Disconnect resent at T56");
  ack.reason_code = PreEstablishedReasonCode::Accepted;
  (void)server.receive_acknowledge(ack, 22200);
  expect(server.take_events() == std::vector{PreEstablishedServerEvent::DisconnectAcknowledged}, "acknowledged");
  expect(server.state() == PreEstablishedServerState::NotInUse, "not in use");

  (void)server.connect(group_connect(), 30000);
  ack.reason_code = PreEstablishedReasonCode::NotAccepted;
  expect(!server.receive_acknowledge(ack, 30100)->reason_cause, "Not Accepted: no Reason Cause");
  (void)server.tick(32100);
  (void)server.tick(34100);
  (void)server.tick(36100);
  expect(server.take_events().back() == PreEstablishedServerEvent::DisconnectExpired, "DisconnectExpired after C56");
  expect(server.state() == PreEstablishedServerState::NotInUse, "not in use after C56");
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.3.2, 9.3.2.4.4, 9.3.2.4.11 and table 11.1.4-1: a REFER puts the session in use, the
// client's leave frees it, a refused call setup is a Disconnect with the given identity, and T55 is at most 4 s.
static void Clause_9_3_2_4_11_ReferAndRelease() {
  mcx::PreEstablishedServer server(1);
  server.started();
  server.refer_received();
  expect(server.state() == PreEstablishedServerState::InUse, "REFER: in use");
  server.client_released();
  expect(server.state() == PreEstablishedServerState::NotInUse, "REFER BYE: not in use");
  server.refer_received();
  const auto refusal = server.disconnect(0, std::nullopt, "sip:pre-1@mcptt.example");
  expect(refusal.session_identity == "sip:pre-1@mcptt.example", "Disconnect before any Connect");
  server.stopped();
  expect(server.state() == PreEstablishedServerState::StartStop && server.tick(100000).empty(), "stopped");
  rejects([] { mcx::PreEstablishedServer late(1, {.t55_ms = 5000}); }, "T55 of 5 s");
  rejects([] { mcx::PreEstablishedServer none(1, {.c56 = 0}); }, "C56 of 0");
  rejects([&] { (void)server.connect(group_connect(), 0); }, "Connect in 'Start-stop'");
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.3.3 b to d and 9.3.2.4.10 a to g: the Connect contents taken from the SIP messages.
static void Clause_9_3_2_3_3_ConnectContents() {
  const Bytes pck = {1, 2, 3};
  auto connect = mcx::make_terminating_connect("sip:c@x", "private", "", "sip:alice@x", true, pck,
                                               mcx::PreEstablishedMediaStreams{1, 0});
  expect(connect.session_type == mcx::PreEstablishedSessionType::Private, "private");
  expect(connect.inviting_user == mcx::pre_established_anonymous_user, "privacy: anonymous");
  expect(connect.pck_i_message == pck && connect.media_streams->control_channel == 0, "PCK, no floor control");
  connect = mcx::make_terminating_connect("sip:c@x", "adhoc", "sip:g@x", "", false);
  expect(connect.session_type == mcx::PreEstablishedSessionType::None && connect.group_identity == "sip:g@x",
         "ad hoc: no session type, group identity");
  expect(connect.inviting_user == mcx::pre_established_anonymous_user, "unknown inviting user: anonymous");
  connect = mcx::make_terminating_connect("sip:c@x", "chat", "sip:g@x", "sip:alice@x", false, pck);
  expect(connect.inviting_user == "sip:alice@x" && connect.pck_i_message.empty(), "chat: no PCK");

  connect = mcx::make_originating_connect("sip:c@x", "prearranged", "", "Unconfirmed;reason=x", "");
  expect(connect.answer_state == mcx::PreEstablishedAnswerState::Unconfirmed, "P-Answer-State Unconfirmed");
  connect = mcx::make_originating_connect("sip:c@x", "", "107 text", "", "sip:bob@x");
  expect(connect.session_type == mcx::PreEstablishedSessionType::None && !connect.answer_state, "no type, no state");
  expect(connect.warning_text == "107 text" && connect.invited_user == "sip:bob@x", "warning and invited user");
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.10 with RFC 4567 section 3.1: the PCK I_MESSAGE field is the octets of the I_MESSAGE whose
// base64 text an "a=key-mgmt:mikey" carries.
static void Clause_8_3_3_10_KeyMgmtText() {
  const std::vector<std::uint8_t> octets = {0x01, 0x1a, 0x05, 0x00, 0xff, 0x7e, 0x10};
  const auto text = mcx::key_mgmt_of(octets);
  expect(text == "ARoFAP9+EA==", "base64 text");
  expect(mcx::pck_i_message_of(text) == octets, "octets back");
  expect(mcx::pck_i_message_of(mcx::key_mgmt_of(std::vector<std::uint8_t>{1, 2, 3})).size() == 3, "no padding");
  bool refused = false;
  try {
    (void)mcx::pck_i_message_of("ARo");
  } catch (const std::exception &) {
    refused = true;
  }
  expect(refused, "text that is not base64 refused");
}

int main() {
  const std::vector<std::pair<const char *, void (*)()>> tests = {
      {"Clause_8_3_4_ConnectOctets", Clause_8_3_4_ConnectOctets},
      {"Clause_8_3_6_AcknowledgeOctets", Clause_8_3_6_AcknowledgeOctets},
      {"Clause_8_3_5_DisconnectRoundTrip", Clause_8_3_5_DisconnectRoundTrip},
      {"Clause_8_3_3_10_PckIMessage", Clause_8_3_3_10_PckIMessage},
      {"Clause_8_3_3_10_KeyMgmtText", Clause_8_3_3_10_KeyMgmtText},
      {"Clause_8_3_3_9_UnknownAndMalformed", Clause_8_3_3_9_UnknownAndMalformed},
      {"Clause_9_2_2_3_2_ClientReceivesConnect", Clause_9_2_2_3_2_ClientReceivesConnect},
      {"Clause_9_2_2_4_5_ClientReceivesDisconnect", Clause_9_2_2_4_5_ClientReceivesDisconnect},
      {"Clause_9_3_2_4_9_ConnectExpires", Clause_9_3_2_4_9_ConnectExpires},
      {"Clause_9_3_2_4_7_Acknowledge", Clause_9_3_2_4_7_Acknowledge},
      {"Clause_9_3_2_4_11_ReferAndRelease", Clause_9_3_2_4_11_ReferAndRelease},
      {"Clause_9_3_2_3_3_ConnectContents", Clause_9_3_2_3_3_ConnectContents},
  };
  int failures = 0;
  for (const auto &[name, test] : tests) {
    try {
      test();
    } catch (const std::exception &error) {
      std::cerr << name << ": " << error.what() << '\n';
      ++failures;
    }
  }
  if (failures == 0) std::cout << tests.size() << " pre-established session tests passed\n";
  return failures == 0 ? 0 : 1;
}
