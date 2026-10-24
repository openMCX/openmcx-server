//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IP multicast delivery of MCPTT group call speech, an OpenMCX profile and not a 3GPP procedure: each configured
// group's speech goes to an IPv4 host group that the server and the clients know from their configuration, without
// an MBMS bearer, its announcement or listening status (TS 24.379 clause 14) or MBMS subchannel control (TS 24.380
// clause 10). Floor control stays on each participant's unicast media plane.
//
// Specifications: RFC 1112, TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.3.0 (Rel-19).
#pragma once
#include "mcx/runtime.hpp"

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: an IPv4 host group address and UDP port.
struct MulticastDestination {
  std::string address;
  std::uint16_t port = 0;

  bool operator==(const MulticastDestination &) const = default;
};

//------------------------------------------------------------------------------
// Helper: the "multicast" block of a server's "mcptt" configuration, or of a client's: the interface to send or
// join on, the time-to-live, the RTP payload format of the multicast speech (TS 26.179: AMR-WB, RFC 4867), the
// MCPTT IDs served by multicast (the server's opt-in list) and the host group of each group URI.
struct MulticastConfig {
  std::string interface = "0.0.0.0";
  int ttl = 1;
  std::uint8_t payload_type = 96;
  bool octet_aligned = false;
  std::set<std::string> users;
  std::map<std::string, MulticastDestination> groups;

  // The host group of a group URI, or none.
  [[nodiscard]] const MulticastDestination *group(const std::string &uri) const;
  // Whether the MCPTT ID is on the opt-in list.
  [[nodiscard]] bool serves(const std::string &user) const { return users.contains(user); }
};

//------------------------------------------------------------------------------
// Helper: reads and checks a "multicast" block. Each group is "<IPv4 host group>:<port>", and two groups never
// share one; an invalid block is refused.
[[nodiscard]] MulticastConfig multicast_config(const Json &block);

} // namespace mcx
