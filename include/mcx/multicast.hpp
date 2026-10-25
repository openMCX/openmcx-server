//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IP multicast delivery of MCPTT group call speech, an OpenMCX profile and not a 3GPP procedure: each configured
// group's speech goes to an IPv4 host group that the server and the clients know from their configuration, with a
// TMGI of its own, without an MBMS bearer, its announcement (TS 24.379 clause 14.2.2) or MBMS subchannel control
// (TS 24.380 clause 10). Of TS 24.379 clause 14 only the listening status report is used (clauses 14.2.3 and
// 14.3.3): a client receives a session's speech by multicast once it reported "listening" for it. Floor control
// stays on each participant's unicast media plane.
//
// Specifications: RFC 1112, TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
#pragma once
#include "mcx/runtime.hpp"

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: an IPv4 host group address and UDP port, and the TMGI that stands for it in a listening status report
// (TS 24.379 annex F.2.3: TS 24.008 clause 10.5.6.13 without its octets 1 and 2, in lower-case hexadecimal).
struct MulticastDestination {
  std::string address;
  std::uint16_t port = 0;
  std::string tmgi;

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
// Helper: reads and checks a "multicast" block. Each group is {"host_group": "<IPv4 host group>:<port>", "tmgi":
// "<TMGI>"}, and two groups never share a host group or a TMGI; an invalid block is refused.
[[nodiscard]] MulticastConfig multicast_config(const Json &block);

} // namespace mcx
