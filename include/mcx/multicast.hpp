//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The configuration of the participating function's pre-activated MBMS bearers (TS 24.380 clause 4.1.3, TS 24.581
// clause 4.1.2): the bearers, their general purpose MBMS subchannels and the pools their MBMS subchannels are
// allocated from. The BM-SC and the radio are emulated: each subchannel is an IPv4 host group (RFC 1112) on the
// media network, without TS 29.468 activation.
//
// Specifications: RFC 1112, TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19).
#pragma once
#include "mcx/runtime.hpp"

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: an IPv4 host group address and UDP port (a general purpose or MBMS subchannel), and the TMGI of its bearer
// (TS 24.379 annex F.2.3: TS 24.008 clause 10.5.6.13 without its octets 1 and 2, in lower-case hexadecimal).
struct MulticastDestination {
  std::string address;
  std::uint16_t port = 0;
  std::string tmgi;

  bool operator==(const MulticastDestination &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.380 clause 4.1.3.1 (TS 24.581 clause 4.1.2.1): a pre-activated MBMS bearer of the "mbms" block of a
// server's "mcptt" or "mcvideo" configuration: what TS 24.379 clause 14.2.2.2 announces of it (TMGI, QCI,
// frequency, MBMS service area IDs, whether clients report its suspension), the IPv4 host group and port of its
// general purpose MBMS subchannel, and the pool of host groups and ports from which its MBMS subchannels are
// allocated (clause 4.1.3.2). The emulated BM-SC delivers each host group on the lab network; TS 29.468 activation
// is not used.
struct MbmsBearerConfig {
  // A 5G MBS session (TS 24.379 clause 14B, TS 24.380 clause 10B) rather than an EPS MBMS bearer: tmgi is then its MBS
  // session ID (a TMGI, TS 23.247 clause 6.5.1), mode "multicast" or "broadcast", and report_join and fsa_ids go in
  // its announcement.
  bool mbs = false;
  std::string mode = "broadcast";
  std::optional<bool> report_join;
  std::vector<std::string> fsa_ids;
  std::string tmgi;
  std::optional<int> qci;
  std::optional<std::uint64_t> frequency;
  std::vector<std::string> service_areas;
  std::optional<bool> report_suspension;
  MulticastDestination general_purpose;
  std::vector<MulticastDestination> subchannels;
};

//------------------------------------------------------------------------------
// The "mbms" block: the interface and time-to-live of the multicast datagrams, the RTP payload formats of the media
// sent on MBMS subchannels (AMR-WB speech; H.264 video for MCVideo, whose subchannel carries the video on its port and
// the audio on the port two above), the MC service IDs the bearers are announced to (TS 24.379 clause 14.2.2.1: whom to
// announce to is local policy), the bearers, and how often the Bearer Announcement message goes over each general
// purpose subchannel (TS 24.380 clause 4.1.3.7; 0: never).
struct MbmsConfig {
  std::string interface = "0.0.0.0";
  int ttl = 1;
  std::uint8_t payload_type = 96;
  std::uint8_t video_payload_type = 97;
  bool octet_aligned = false;
  std::set<std::string> users;
  std::vector<MbmsBearerConfig> bearers;
  std::uint64_t bearer_announcement_ms = 0;
  // TS 24.379 clause 14.2.2.2 step 5 d and TS 24.380 clause 13: whether the MBMS subchannel control messages are
  // protected with an MSCCK sent in the announcement, and the multicast floor and transmission control with a
  // MuSiK sent by key download (clause 14.2.2.5) when the call's floor control is protected.
  bool mscck = false, musik = false;

  // The bearer of a TMGI, or none.
  [[nodiscard]] const MbmsBearerConfig *bearer(const std::string &tmgi) const;
  // Without a "users" list every served user is announced to.
  bool all_users = false;
  [[nodiscard]] bool serves(const std::string &user) const { return all_users || users.contains(user); }
};

//------------------------------------------------------------------------------
// Helper: reads and checks an "mbms" block. Each bearer is {"tmgi", "general_purpose": "<host group>:<port>",
// "subchannels": ["<host group>:<port>", ...], "service_areas": ["<hexBinary>", ...], optional "qci", "frequency"
// and "report_suspension" (for an MBS session: whether de-announcement is acknowledged)}, with "system": "mbs" an
// MBS session with optional "mode", "report_join" and "fsa_ids"; no two bearers share a TMGI, and no two subchannels (general purpose or not) share a
// host group and port.
[[nodiscard]] MbmsConfig mbms_config(const Json &block);

} // namespace mcx
