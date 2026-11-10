//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// ICE for a pre-established session (include/mcx/ice.hpp): two agents on real UDP sockets on the loopback address,
// as an MCPTT client (controlling: the offerer) and its participating function, run the connectivity checks of the
// speech RTP and RTCP and the control channel to completion; a role conflict is repaired; a wrong password fails;
// RTP and floor control are told from STUN (RFC 7983).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 8445, RFC 8839, RFC 5389, RFC 7983.

#include "mcx/ice.hpp"
#include "mcx/runtime.hpp"

#include <arpa/inet.h>

#include <array>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Helper: one side of a session: its three sockets (RTP, RTCP, control) and its agent.
struct Side {
  std::vector<std::unique_ptr<mcx::UdpSocket>> sockets;
  std::unique_ptr<mcx::IceAgent> agent;
  unsigned media_seen = 0; // datagrams that were not STUN

  explicit Side(bool controlling, bool control = true) {
    for (int index = 0; index < (control ? 3 : 2); ++index)
      sockets.push_back(std::make_unique<mcx::UdpSocket>("127.0.0.1", 0));
    mcx::IceLocalSockets local{"127.0.0.1", sockets[0]->port(), sockets[1]->port(),
                               control ? sockets[2]->port() : std::uint16_t{0}};
    agent = std::make_unique<mcx::IceAgent>(
        controlling, local,
        [this](mcx::IceStream stream, unsigned component, std::span<const std::uint8_t> packet,
               const std::string &host, std::uint16_t port) { socket_of(stream, component).send(packet, host, port); });
  }

  mcx::UdpSocket &socket_of(mcx::IceStream stream, unsigned component) {
    return stream == mcx::IceStream::Audio ? *sockets[component - 1] : *sockets[2];
  }

  // The caller's part (include/mcx/ice.hpp): STUN to the agent, everything else to the media plane.
  void pump() {
    for (std::size_t index = 0; index < sockets.size(); ++index) {
      while (auto datagram = sockets[index]->receive()) {
        if (!mcx::is_stun_packet(datagram->bytes)) {
          ++media_seen;
          continue;
        }
        std::array<char, INET_ADDRSTRLEN> host{};
        inet_ntop(AF_INET, &datagram->source.sin_addr, host.data(), host.size());
        const auto stream = index == 2 ? mcx::IceStream::Control : mcx::IceStream::Audio;
        const unsigned component = index == 2 ? 1 : static_cast<unsigned>(index + 1);
        agent->receive(stream, component, datagram->bytes, host.data(), ntohs(datagram->source.sin_port));
      }
    }
    agent->tick();
  }
};

//------------------------------------------------------------------------------
// Helper: runs both sides until both leave 'Checking' or the time runs out.
static void run(Side &offerer, Side &answerer, std::chrono::milliseconds limit) {
  const auto end = std::chrono::steady_clock::now() + limit;
  while (std::chrono::steady_clock::now() < end &&
         (offerer.agent->state() == mcx::IceState::Checking || answerer.agent->state() == mcx::IceState::Checking)) {
    offerer.pump();
    answerer.pump();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
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
  server.agent->start(offer);
  client.agent->start(server.agent->local_description());
  run(client, server, std::chrono::seconds(5));
  expect(client.agent->state() == mcx::IceState::Completed, "client completed");
  expect(server.agent->state() == mcx::IceState::Completed, "server completed");
  const auto rtcp = client.agent->selected(mcx::IceStream::Audio, 2);
  expect(rtcp && rtcp->second == server.sockets[1]->port(), "RTCP pair names the server's RTCP socket");
  const auto control = server.agent->selected(mcx::IceStream::Control, 1);
  expect(control && control->second == client.sockets[2]->port(), "control pair names the client's socket");
  expect(!client.agent->needs_updated_offer(), "host candidates are the defaults (RFC 8445 section 8.1.2)");
  expect(client.media_seen == 0 && server.media_seen == 0, "all traffic was STUN");
}

//------------------------------------------------------------------------------
// RFC 8445 section 7.3.1.1: both agents controlling; the conflict is repaired and the checks complete.
static void Rfc8445_7_3_1_1_RoleConflict() {
  Side first(true, false), second(true, false);
  second.agent->start(first.agent->local_description());
  first.agent->start(second.agent->local_description());
  run(first, second, std::chrono::seconds(5));
  expect(first.agent->state() == mcx::IceState::Completed && second.agent->state() == mcx::IceState::Completed,
         "role conflict repaired, session without control channel completed");
}

//------------------------------------------------------------------------------
// RFC 8445 section 7.2.5.1 (with RFC 5389 section 10.1.2): checks under a wrong password are refused; the agent fails.
static void Rfc8445_7_2_5_1_WrongPasswordFails() {
  Side client(true, false), server(false, false);
  auto wrong = server.agent->local_description();
  wrong.pwd = "WRONGWRONGWRONGWRONGWRONG";
  server.agent->start(client.agent->local_description());
  client.agent->start(wrong);
  run(client, server, std::chrono::seconds(15));
  expect(client.agent->state() == mcx::IceState::Failed, "client failed under a wrong password");
}

int main() {
  const std::vector<std::pair<const char *, void (*)()>> tests = {
      {"Rfc7983_7_Demultiplexing", Rfc7983_7_Demultiplexing},
      {"Rfc8445_8_CompletesOnAllComponents", Rfc8445_8_CompletesOnAllComponents},
      {"Rfc8445_7_3_1_1_RoleConflict", Rfc8445_7_3_1_1_RoleConflict},
      {"Rfc8445_7_2_5_1_WrongPasswordFails", Rfc8445_7_2_5_1_WrongPasswordFails},
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
