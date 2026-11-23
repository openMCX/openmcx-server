//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Helper of the ICE tests (test_ice): one side of a pre-established session on real UDP sockets on the loopback
// address, its three sockets (RTP, RTCP, control) and an agent of type Agent (mcx::IceAgent), with the caller's part of include/mcx/ice.hpp: STUN to the agent, everything else counted as
// media. The first `drop` datagrams it would send are lost, to exercise retransmission.

#pragma once

#include "mcx/ice.hpp"
#include "mcx/runtime.hpp"

#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

template <typename Agent> struct IceSide {
  std::vector<std::unique_ptr<mcx::UdpSocket>> sockets;
  std::unique_ptr<Agent> agent;
  unsigned media_seen = 0; // datagrams that were not STUN
  unsigned drop = 0;       // datagrams still to lose
  unsigned sent = 0;
  // Received STUN datagrams for which it returns true are lost before the agent sees them.
  std::function<bool(std::span<const std::uint8_t>)> lose_received;

  explicit IceSide(bool controlling, bool control = true) {
    for (int index = 0; index < (control ? 3 : 2); ++index)
      sockets.push_back(std::make_unique<mcx::UdpSocket>("127.0.0.1", 0));
    mcx::IceLocalSockets local{"127.0.0.1", sockets[0]->port(), sockets[1]->port(),
                               control ? sockets[2]->port() : std::uint16_t{0}};
    agent =
        std::make_unique<Agent>(controlling, local,
                                [this](mcx::IceStream stream, unsigned component, std::span<const std::uint8_t> packet,
                                       const std::string &host, std::uint16_t port) {
                                  ++sent;
                                  if (drop > 0) {
                                    --drop;
                                    return;
                                  }
                                  socket_of(stream, component).send(packet, host, port);
                                });
  }

  mcx::UdpSocket &socket_of(mcx::IceStream stream, unsigned component) {
    return stream == mcx::IceStream::Audio ? *sockets[component - 1] : *sockets[2];
  }

  void pump() {
    for (std::size_t index = 0; index < sockets.size(); ++index) {
      while (auto datagram = sockets[index]->receive()) {
        if (!mcx::is_stun_packet(datagram->bytes)) {
          ++media_seen;
          continue;
        }
        if (lose_received && lose_received(datagram->bytes)) continue;
        std::array<char, INET_ADDRSTRLEN> host{};
        inet_ntop(AF_INET, &datagram->source.sin_addr, host.data(), host.size());
        const auto stream = index == 2 ? mcx::IceStream::Control : mcx::IceStream::Audio;
        const unsigned component = index == 2 ? 1 : static_cast<unsigned>(index + 1);
        const auto before = agent->state();
        agent->receive(stream, component, datagram->bytes, host.data(), ntohs(datagram->source.sin_port));
        // include/mcx/ice.hpp: the servers and the client look for the state's change around tick only.
        if (agent->state() != before) throw std::logic_error("ICE state changed in receive, not in tick");
      }
    }
    agent->tick();
  }
};

//------------------------------------------------------------------------------
// Runs both sides until neither is 'Checking' (or 'Gathered') or the time runs out; returns the time taken.
template <typename A, typename B>
std::chrono::milliseconds run_ice(IceSide<A> &first, IceSide<B> &second, std::chrono::milliseconds limit) {
  const auto begin = std::chrono::steady_clock::now();
  const auto busy = [](mcx::IceState state) {
    return state == mcx::IceState::Checking || state == mcx::IceState::Gathered;
  };
  while (std::chrono::steady_clock::now() - begin < limit &&
         (busy(first.agent->state()) || busy(second.agent->state()))) {
    first.pump();
    second.pump();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin);
}
