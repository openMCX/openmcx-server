//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MBMS usage information bodies of TS 24.379 annex F.2 (application/vnd.3gpp.mcptt-mbms-usage-info+xml) and
// TS 24.281 annex F.2 (application/vnd.3gpp.mcvideo-mbms-usage-info+xml): the MBMS bearer announcement of
// TS 24.379 clause 14.2.2 (TS 24.281 clause 16.3.2), the listening and suspension status reports of clause 14.3.3
// (TS 24.281 clause 16.2.3) and the MuSiK download of clause 14.2.2.5 (TS 24.281 clause 16.3.2.5). The two bodies
// differ only in their MIME type, namespace, root element and ROHC element.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.008 V19.4.0 (Rel-19).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// The MC service whose MBMS procedures are used: MCPTT (TS 24.379 clause 14, TS 24.380 clause 10) or MCVideo
// (TS 24.281 clause 16, TS 24.581 clause 10).
enum class MbmsService : std::uint8_t { Mcptt, Mcvideo };

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.4 and annex F.2.2 (TS 24.281 annex F.2.4 and annex F.2.2): the MIME type, the namespace,
// the root element and the anyExt element announcing ROHC of each service's body.
struct MbmsUsageType {
  const char *mime;
  const char *ns;
  const char *root;
  const char *rohc;
};

[[nodiscard]] const MbmsUsageType &mbms_usage_type(MbmsService service);

// The MCPTT body's MIME type and namespace (TS 24.379 annex F.2.4 and annex F.2.2).
inline constexpr const char *mbms_usage_mime = "application/vnd.3gpp.mcptt-mbms-usage-info+xml";
inline constexpr const char *mbms_usage_ns = "urn:3gpp:ns:mcpttMbmsUsage:1.0";

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 1: the <mbms-listening-status> element: "listening" or "not-listening", the session
// (the URI of the session's Contact, clause F.2.3 item 1 b), the general purpose subchannel, the TMGIs (lower-case
// hexadecimal, TS 24.008 clause 10.5.6.13 octets 3 to 8) the status applies to, and the reception quality (0 to 5,
// in <anyExt>, item 1 e).
struct MbmsListeningStatus {
  bool listening = false;
  std::string session_id;
  std::optional<bool> general_purpose;
  std::vector<std::string> tmgis;
  std::optional<int> reception_quality;

  bool operator==(const MbmsListeningStatus &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 2: the <mbms-suspension-status> element: "suspending" or "not-suspending", the TMGI
// reported, and the other TMGIs sharing its MCH. <number-of-reported-bearers> is written as their count.
struct MbmsSuspensionStatus {
  bool suspending = false;
  std::string suspended_tmgi;
  std::vector<std::string> other_tmgis;

  bool operator==(const MbmsSuspensionStatus &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 3: one <announcement> element: the TMGI, QCI, frequency, MBMS service area IDs
// (hexBinary, TS 29.061 MBMS-Service-Area encoding), the number of the media line of the general purpose MBMS
// subchannel (<GPMS>) and whether suspension is to be reported; <anyExt> may announce ROHC (item 3 g). An
// announcement without service areas cancels the announcement of its TMGI (TS 24.379 clause 14.2.2.4).
struct MbmsAnnouncement {
  std::string tmgi;
  std::optional<int> qci;
  std::optional<std::uint64_t> frequency;
  std::vector<std::string> service_areas;
  std::optional<unsigned> gpms;
  std::optional<bool> report_suspension;
  bool rohc = false;

  [[nodiscard]] bool cancellation() const { return service_areas.empty(); }

  bool operator==(const MbmsAnnouncement &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3 item 5 (in the root's <anyExt>): a default (<mbms-defaultMuSiK-download>, zero or more
// groups) or an explicit (<mbms-explicitMuSiK-download>, one or more groups) MuSiK download (clause 14.2.2.5).
struct MusikDownload {
  bool explicit_groups = false;
  std::vector<std::string> groups;

  bool operator==(const MusikDownload &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3: what an MBMS usage information document carries. The schema allows one <announcement>,
// while clause 14.2.2.1 sends one or more; several are written and read.
struct MbmsUsageInfo {
  std::optional<MbmsListeningStatus> listening_status;
  std::optional<MbmsSuspensionStatus> suspension_status;
  std::vector<MbmsAnnouncement> announcements;
  std::optional<MusikDownload> musik_download;

  bool operator==(const MbmsUsageInfo &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.008 clause 10.5.6.13: a TMGI as lower-case hexadecimal: the MBMS Service ID (3 octets), optionally followed
// by the MCC and MNC (3 octets); anything else is refused.
[[nodiscard]] std::string tmgi_hex(std::string value);

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.2 (TS 24.281 annex F.2.2): writes an MBMS usage information document with <version> 1. A
// listening status needs a TMGI, and without <general-purpose> a session (annex F.2.3 item 1 b); an explicit MuSiK
// download needs a group. What an announcement carries is left to the procedures of clause 14.2.2: only the schema
// and annex F.2.3 are checked here.
[[nodiscard]] std::string mbms_usage_xml(const MbmsUsageInfo &info, MbmsService service = MbmsService::Mcptt);

//------------------------------------------------------------------------------
// TS 24.379 clause 14.3.3.2 steps 1 e) to 1 g): writes the listening status report alone.
std::string mbms_listening_status_xml(const MbmsListeningStatus &status, MbmsService service = MbmsService::Mcptt);

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.2 and annex F.2.3 (TS 24.281 annex F.2): reads an MBMS usage information document; throws
// when it is not one of the service, or breaks the schema or annex F.2.3. Unknown elements are ignored.
MbmsUsageInfo parse_mbms_usage_info(std::string_view xml, MbmsService service = MbmsService::Mcptt);

} // namespace mcx
