//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// ICE for a pre-established session (TS 24.379 clauses 4.9, 8.2.1 steps 1 and 9, 8.2.2 steps 9 e and 12): an agent
// with host candidates on the session's own UDP sockets (the speech RTP and RTCP ports and the media plane control
// port) that runs the connectivity checks of RFC 8445 through pjnath's ICE session, one per media section, with the
// same credentials. The caller owns the sockets: it passes received STUN packets (is_stun_packet, RFC 7983) to
// receive, transmits what the sender callback gives it, and calls tick on its poll loop.
//
// Deviation from RFC 8445: pjnath implements the checks of RFC 5245 (pacing, the candidate pair states, the
// role-conflict repair), which RFC 8445 changed in details; the agent uses regular nomination, the only nomination
// RFC 8445 keeps (section 8.1.1), and does not claim the "ice2" option (RFC 8839 section 5.6).
// Not implemented: server reflexive and relayed candidates (RFC 8445 section 5.1.1.2): no STUN or TURN server is
// configured, so only UDP host candidates are gathered, on the address the session uses for MCPTT service (TS 24.379
// clause 8.2.1 NOTE 1: "only gathered on interfaces that the MCPTT UE uses to obtain MCPTT service").
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 8445, RFC 8839, RFC 5389, RFC 7983.

#pragma once

#include "mcx/protocol.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace mcx {

//------------------------------------------------------------------------------
// The media sections of a pre-established session's SDP that ICE runs on: the speech (components 1 RTP and 2 RTCP)
// and the media plane control channel (component 1).
enum class IceStream : unsigned { Audio = 0, Control = 1 };

//------------------------------------------------------------------------------
// RFC 8445 sections 6.1.3 and 8.1.3: the agent's progress: candidates ready (before start), checks running, every
// component of every stream nominated, or a stream's check list failed.
enum class IceState { Gathered, Checking, Completed, Failed };

//------------------------------------------------------------------------------
// RFC 7983 section 7 with RFC 5389 section 6: whether a datagram is a STUN message (first octet 0 to 3, the magic
// cookie), to tell connectivity checks from RTP, RTCP and floor control on the same socket.
[[nodiscard]] bool is_stun_packet(std::span<const std::uint8_t> datagram) noexcept;

//------------------------------------------------------------------------------
// Helper: transmits a STUN packet of a stream's component from its socket to a numeric IPv4 address and port.
using IceSender = std::function<void(IceStream stream, unsigned component, std::span<const std::uint8_t> packet,
                                     const std::string &host, std::uint16_t port)>;

//------------------------------------------------------------------------------
// The local sockets of the session the agent gathers its host candidates on: one IPv4 address, the speech RTP and
// RTCP ports, and the control port (0: a session without floor control).
struct IceLocalSockets {
  std::string address;
  std::uint16_t rtp_port = 0, rtcp_port = 0, control_port = 0;
};

//------------------------------------------------------------------------------
// RFC 8445: a full ICE agent for one pre-established session. The offerer is controlling (RFC 8445 section 6.1.1);
// pjnath repairs a role conflict (section 7.3.1.1).
class IceAgent {
public:
  // RFC 8445 sections 5.1.1.1 and 5.3: gathers a host candidate per component and draws the credentials. Throws when
  // a port is missing or pjnath fails.
  IceAgent(bool controlling, IceLocalSockets sockets, IceSender sender);
  ~IceAgent();
  IceAgent(const IceAgent &) = delete;
  IceAgent &operator=(const IceAgent &) = delete;

  // RFC 8839 sections 5.1 and 5.4: this agent's credentials and candidates for its SDP (TS 24.379 clauses 8.2.1
  // step 9 and 8.2.2 step 9 e).
  [[nodiscard]] const IceDescription &local_description() const noexcept;
  // RFC 8445 sections 6.1.2 and 6.1.4: pairs the local candidates with the peer's of each stream and starts the
  // checks. Throws when the peer gives no candidate for a component this agent has, or is a lite agent while this one
  // is controlled (a lite peer is not supported here).
  void start(const IceDescription &remote);
  // RFC 8445 section 7.3: a STUN packet received on a stream's component socket from the address; returns whether
  // the agent took it.
  bool receive(IceStream stream, unsigned component, std::span<const std::uint8_t> packet, const std::string &host,
               std::uint16_t port);
  // The retransmissions and paced checks due by now (pjnath's timers).
  void tick();

  [[nodiscard]] IceState state() const noexcept { return state_; }
  // RFC 8445 section 8.1.1: the peer address of a component's nominated pair, once its stream completed.
  [[nodiscard]] std::optional<std::pair<std::string, std::uint16_t>> selected(IceStream stream,
                                                                              unsigned component) const;
  // RFC 8445 section 8.1.2 (TS 24.379 clause 8.2.1 NOTE 2): whether a nominated pair's local candidate is not the
  // default candidate of the SDP, so that the controlling agent sends an updated offer (TS 24.379 clause 8.3). With
  // host candidates only it is always false.
  [[nodiscard]] bool needs_updated_offer() const;

  struct Impl;

private:
  std::unique_ptr<Impl> impl_;
  IceState state_ = IceState::Gathered;
  friend struct Impl;
};

} // namespace mcx
