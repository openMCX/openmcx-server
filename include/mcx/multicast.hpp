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
#include <optional>
#include <set>
#include <string>
#include <vector>

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
// TS 24.380 clause 4.1.3.1 (TS 24.581 clause 4.1.2.1): a pre-activated MBMS bearer of the "mbms" block of a
// server's "mcptt" or "mcvideo" configuration: what TS 24.379 clause 14.2.2.2 announces of it (TMGI, QCI,
// frequency, MBMS service area IDs, whether clients report its suspension), the IPv4 host group and port of its
// general purpose MBMS subchannel, and the pool of host groups and ports from which its MBMS subchannels are
// allocated (clause 4.1.3.2). The emulated BM-SC delivers each host group on the lab network; TS 29.468 activation
// is not used.
struct MbmsBearerConfig {
  std::string tmgi;
  std::optional<int> qci;
  std::optional<std::uint64_t> frequency;
  std::vector<std::string> service_areas;
  std::optional<bool> report_suspension;
  MulticastDestination general_purpose;
  std::vector<MulticastDestination> subchannels;
};

//------------------------------------------------------------------------------
// The "mbms" block: the interface and time-to-live of the multicast datagrams, the RTP payload format of the media
// sent on MBMS subchannels, the MC service IDs the bearers are announced to (TS 24.379 clause 14.2.2.1: whom to
// announce to is local policy), the bearers, and how often the Bearer Announcement message goes over each general
// purpose subchannel (TS 24.380 clause 4.1.3.7; 0: never).
struct MbmsConfig {
  std::string interface = "0.0.0.0";
  int ttl = 1;
  std::uint8_t payload_type = 96;
  bool octet_aligned = false;
  std::set<std::string> users;
  std::vector<MbmsBearerConfig> bearers;
  std::uint64_t bearer_announcement_ms = 0;

  // The bearer of a TMGI, or none.
  [[nodiscard]] const MbmsBearerConfig *bearer(const std::string &tmgi) const;
  [[nodiscard]] bool serves(const std::string &user) const { return users.contains(user); }
};

//------------------------------------------------------------------------------
// Helper: reads and checks an "mbms" block. Each bearer is {"tmgi", "general_purpose": "<host group>:<port>",
// "subchannels": ["<host group>:<port>", ...], "service_areas": ["<hexBinary>", ...], optional "qci", "frequency"
// and "report_suspension"}; no two bearers share a TMGI, and no two subchannels (general purpose or not) share a
// host group and port.
[[nodiscard]] MbmsConfig mbms_config(const Json &block);

//------------------------------------------------------------------------------
// Helper: reads and checks a "multicast" block. Each group is {"host_group": "<IPv4 host group>:<port>", "tmgi":
// "<TMGI>"}, and two groups never share a host group or a TMGI; an invalid block is refused.
[[nodiscard]] MulticastConfig multicast_config(const Json &block);

} // namespace mcx
