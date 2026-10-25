//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MBMS usage information body of TS 24.379 annex F.2 (application/vnd.3gpp.mcptt-mbms-usage-info+xml), as far
// as the IP multicast profile uses it (include/mcx/multicast.hpp): the client's listening status report of clause
// 14.3.3.2, and what the participating function must refuse in it (clause 14.2.4).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19).
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.4: the MIME type, and annex F.2.2: the namespace.
inline constexpr const char *mbms_usage_mime = "application/vnd.3gpp.mcptt-mbms-usage-info+xml";
inline constexpr const char *mbms_usage_ns = "urn:3gpp:ns:mcpttMbmsUsage:1.0";

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1: the <mbms-listening-status> element: "listening" or "not-listening", the session
// (the URI of the session's Contact, clause F.2.3 item 1 b), the general purpose subchannel, and the TMGIs (lower-case
// hexadecimal) the status applies to.
struct MbmsListeningStatus {
  bool listening = false;
  std::string session_id;
  std::optional<bool> general_purpose;
  std::vector<std::string> tmgis;

  bool operator==(const MbmsListeningStatus &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3: what an <mcptt-mbms-usage-info> document carries: a listening status, a suspension status
// (read only for its presence) and whether it has an <announcement> (which a client never sends, clause 14.2.4).
struct MbmsUsageInfo {
  std::optional<MbmsListeningStatus> listening_status;
  bool suspension_status = false;
  bool announcement = false;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 14.3.3.2 steps 1 e) to 1 g): writes the listening status report, with <version> 1. A status
// without <general-purpose> needs a session (annex F.2.3 item 1 b), and at least one TMGI.
std::string mbms_listening_status_xml(const MbmsListeningStatus &status);

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.2 and annex F.2.3: reads an MBMS usage information document; throws when it is not one, or
// when its listening status breaks annex F.2.3 item 1.
MbmsUsageInfo parse_mbms_usage_info(std::string_view xml);

} // namespace mcx
