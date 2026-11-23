//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// ICE for a pre-established session (include/mcx/ice.hpp): two agents on real UDP sockets on the loopback address,
// as an MCPTT client (controlling: the offerer) and its participating function, run the connectivity checks of the
// speech RTP and RTCP and the control channel to completion; checks that arrive before the peer's description, lost
// datagrams and a peer-reflexive remote candidate are handled; a role conflict is repaired; a wrong password fails;
// RTP and floor control are told from STUN (RFC 7983).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 8445, RFC 8839, RFC 5389, RFC 7983.

#include "stun.hpp"
#include "support/ice_side.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using Side = IceSide<mcx::IceAgent>;

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// RFC 7983 section 7 with RFC 5389 section 6: STUN against RTP (first octet 128 to 191) and RTCP APP floor control.
static void Rfc7983_7_Demultiplexing() {
  std::vector<std::uint8_t> binding(20, 0);
  binding[1] = 0x01; // Binding request
  binding[4] = 0x21;
  binding[5] = 0x12;
  binding[6] = 0xa4;
  binding[7] = 0x42;
  expect(mcx::is_stun_packet(binding), "Binding request is STUN");
  auto rtp = binding;
  rtp[0] = 0x80;
  expect(!mcx::is_stun_packet(rtp), "RTP is not STUN");
  auto no_cookie = binding;
  no_cookie[4] = 0;
  expect(!mcx::is_stun_packet(no_cookie), "no magic cookie, no STUN");
  expect(!mcx::is_stun_packet(std::vector<std::uint8_t>(12, 0)), "short datagram");
}

//------------------------------------------------------------------------------
// RFC 8445 sections 5.1.1.1, 5.3 and 6 to 8, TS 24.379 clauses 8.2.1 and 8.2.2: the client (offerer, controlling)
// and the participating function (controlled) complete on all three components, each nominated pair naming the
// other's socket; host candidates are the defaults, so no updated offer is due.
static void Rfc8445_8_CompletesOnAllComponents() {
  Side client(true), server(false);
  const auto &offer = client.agent->local_description();
  expect(offer.ufrag.size() == 8 && offer.pwd.size() == 24, "credentials of RFC 8445 section 5.3");
  expect(offer.audio.size() == 2 && offer.control.size() == 1 && offer.audio[1].component == 2, "host candidates");
  expect(offer.audio[0].priority > offer.audio[1].priority, "RTP above RTCP (RFC 8445 section 5.1.2.1)");
  expect(offer.audio[0].foundation == offer.control[0].foundation, "one foundation per type and base address");
  server.agent->start(offer);
  client.agent->start(server.agent->local_description());
  const auto took = run_ice(client, server, std::chrono::seconds(5));
  expect(client.agent->state() == mcx::IceState::Completed, "client completed");
  expect(server.agent->state() == mcx::IceState::Completed, "server completed");
  expect(took < std::chrono::seconds(1), "completed within a second on the loopback address");
  const auto rtcp = client.agent->selected(mcx::IceStream::Audio, 2);
  expect(rtcp && rtcp->second == server.sockets[1]->port(), "RTCP pair names the server's RTCP socket");
  const auto control = server.agent->selected(mcx::IceStream::Control, 1);
  expect(control && control->second == client.sockets[2]->port(), "control pair names the client's socket");
  expect(!client.agent->needs_updated_offer(), "host candidates are the defaults (RFC 8445 section 8.1.2)");
  expect(client.media_seen == 0 && server.media_seen == 0, "all traffic was STUN");
}

//------------------------------------------------------------------------------
// RFC 8445 section 7.3 (TS 24.379 clause 8.2.2: the participating function checks as soon as it answers): the
// client answers the checks that arrive before the answer reaches it, and pairs them when it starts.
static void Rfc8445_7_3_ChecksBeforeTheAnswer() {
  Side client(true), server(false);
  server.agent->start(client.agent->local_description());
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
  while (std::chrono::steady_clock::now() < end) {
    client.pump();
    server.pump();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  expect(client.agent->state() == mcx::IceState::Gathered, "the client has not started");
  expect(client.sent > 0, "the client answered the early checks");
  client.agent->start(server.agent->local_description());
  run_ice(client, server, std::chrono::seconds(5));
  expect(client.agent->state() == mcx::IceState::Completed && server.agent->state() == mcx::IceState::Completed,
         "both completed after the early checks");
}

//------------------------------------------------------------------------------
// RFC 5389 section 7.2.1: the first datagrams of each side are lost; the retransmissions complete the checks.
static void Rfc5389_7_2_1_LostChecksRetransmitted() {
  Side client(true, false), server(false, false);
  client.drop = 3;
  server.drop = 3;
  server.agent->start(client.agent->local_description());
  client.agent->start(server.agent->local_description());
  run_ice(client, server, std::chrono::seconds(10));
  expect(client.agent->state() == mcx::IceState::Completed && server.agent->state() == mcx::IceState::Completed,
         "completed despite the lost datagrams");
}

//------------------------------------------------------------------------------
// RFC 8445 sections 7.3.1.3 and 7.3.1.4: the server is told a wrong RTP port for the client; the client's check
// from its real socket makes a peer-reflexive remote candidate, whose triggered check is the one nominated.
static void Rfc8445_7_3_1_3_PeerReflexiveRemote() {
  Side client(true, false), server(false, false);
  mcx::UdpSocket silent("127.0.0.1", 0); // a port no agent answers on
  auto offer = client.agent->local_description();
  offer.audio[0].port = silent.port();
  server.agent->start(offer);
  client.agent->start(server.agent->local_description());
  run_ice(client, server, std::chrono::seconds(10));
  expect(client.agent->state() == mcx::IceState::Completed && server.agent->state() == mcx::IceState::Completed,
         "completed over the peer-reflexive candidate");
  const auto rtp = server.agent->selected(mcx::IceStream::Audio, 1);
  expect(rtp && rtp->second == client.sockets[0]->port(), "the server's RTP pair names the client's real socket");
}

//------------------------------------------------------------------------------
// RFC 8445 section 8.1.1: the peer never sees a check carrying USE-CANDIDATE; the nomination times out, its pair is
// no longer valid and the controlling agent fails instead of nominating it again and again.
static void Rfc8445_8_1_1_NominationNeverAnswered() {
  Side client(true, false), server(false, false);
  server.lose_received = [](std::span<const std::uint8_t> bytes) {
    const auto message = mcx::stun::decode(bytes);
    return message && message->use_candidate;
  };
  server.agent->start(client.agent->local_description());
  client.agent->start(server.agent->local_description());
  const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  while (std::chrono::steady_clock::now() < end && client.agent->state() == mcx::IceState::Checking) {
    client.pump();
    server.pump();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  expect(client.agent->state() == mcx::IceState::Failed, "the client failed once its nominations timed out");
}

//------------------------------------------------------------------------------
// RFC 8445 section 7.3.1.1: both agents controlling; the conflict is repaired and the checks complete.
static void Rfc8445_7_3_1_1_RoleConflict() {
  Side first(true, false), second(true, false);
  second.agent->start(first.agent->local_description());
  first.agent->start(second.agent->local_description());
  run_ice(first, second, std::chrono::seconds(5));
  expect(first.agent->state() == mcx::IceState::Completed && second.agent->state() == mcx::IceState::Completed,
         "role conflict repaired, session without control channel completed");
}

//------------------------------------------------------------------------------
// RFC 8445 section 7.3.1.1: both agents controlled; the conflict is repaired too.
static void Rfc8445_7_3_1_1_BothControlled() {
  Side first(false, false), second(false, false);
  second.agent->start(first.agent->local_description());
  first.agent->start(second.agent->local_description());
  run_ice(first, second, std::chrono::seconds(5));
  expect(first.agent->state() == mcx::IceState::Completed && second.agent->state() == mcx::IceState::Completed,
         "both controlled: one became controlling and nominated");
}

//------------------------------------------------------------------------------
// RFC 8445 section 7.2.5.1 (with RFC 5389 section 10.1.2): checks under a wrong password are refused; the agent fails.
static void Rfc8445_7_2_5_1_WrongPasswordFails() {
  Side client(true, false), server(false, false);
  auto wrong = server.agent->local_description();
  wrong.pwd = "WRONGWRONGWRONGWRONGWRONG";
  server.agent->start(client.agent->local_description());
  client.agent->start(wrong);
  const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(15);
  while (std::chrono::steady_clock::now() < end && client.agent->state() == mcx::IceState::Checking) {
    client.pump();
    server.pump();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  expect(client.agent->state() == mcx::IceState::Failed, "client failed under a wrong password");
  expect(std::chrono::steady_clock::now() < end - std::chrono::seconds(13), "failed within 2 s: 401 ends a check");
}

//------------------------------------------------------------------------------
// include/mcx/ice.hpp: the peer must give a candidate for each component; a lite peer needs this agent controlling;
// the checks start once.
static void Rfc8445_6_1_StartRefusals() {
  Side client(true, false), server(false, false);
  auto missing = server.agent->local_description();
  missing.audio.pop_back();
  bool refused = false;
  try {
    client.agent->start(missing);
  } catch (const std::invalid_argument &) {
    refused = true;
  }
  expect(refused, "no RTCP candidate refused");
  auto lite = client.agent->local_description();
  lite.lite = true;
  refused = false;
  try {
    server.agent->start(lite);
  } catch (const std::invalid_argument &) {
    refused = true;
  }
  expect(refused, "a lite peer refused by a controlled agent");
  client.agent->start(server.agent->local_description());
  refused = false;
  try {
    client.agent->start(server.agent->local_description());
  } catch (const std::logic_error &) {
    refused = true;
  }
  expect(refused, "a second start refused");
}

int main() {
  const std::vector<std::pair<const char *, void (*)()>> tests = {
      {"Rfc7983_7_Demultiplexing", Rfc7983_7_Demultiplexing},
      {"Rfc8445_8_CompletesOnAllComponents", Rfc8445_8_CompletesOnAllComponents},
      {"Rfc8445_7_3_ChecksBeforeTheAnswer", Rfc8445_7_3_ChecksBeforeTheAnswer},
      {"Rfc5389_7_2_1_LostChecksRetransmitted", Rfc5389_7_2_1_LostChecksRetransmitted},
      {"Rfc8445_7_3_1_3_PeerReflexiveRemote", Rfc8445_7_3_1_3_PeerReflexiveRemote},
      {"Rfc8445_8_1_1_NominationNeverAnswered", Rfc8445_8_1_1_NominationNeverAnswered},
      {"Rfc8445_7_3_1_1_RoleConflict", Rfc8445_7_3_1_1_RoleConflict},
      {"Rfc8445_7_3_1_1_BothControlled", Rfc8445_7_3_1_1_BothControlled},
      {"Rfc8445_7_2_5_1_WrongPasswordFails", Rfc8445_7_2_5_1_WrongPasswordFails},
      {"Rfc8445_6_1_StartRefusals", Rfc8445_6_1_StartRefusals},
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
  if (failures == 0) std::cout << tests.size() << " ICE tests passed\n";
  return failures == 0 ? 0 : 1;
}
