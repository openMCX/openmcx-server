//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MBMS and 5G MBS media plane messages that the participating function sends to its clients over a general
// purpose subchannel or a subchannel of an MBMS bearer (an MBS session): the subchannel control messages of
// TS 24.380 clause 8.4 ("MCMC") and clause 8.6 ("MCSC") for MCPTT and of TS 24.581 clause 9.3 ("MCV3") and clause
// 9.5 ("MCV5") for MCVideo, and the MBMS notifications of TS 24.380 clause 8.5 and TS 24.581 clause 9.4 ("MCNC").
// All are RTCP APP packets coded as in TS 24.380 clause 8.1 (include/mcx/floor.hpp), except that the Bearer
// Announcement and Session Announcement messages have no SSRC.
//
// Where the specifications leave a code point open, this coding takes:
//   - subtype 00011 for the MCVideo Bearer Announcement and Session Announcement (TS 24.581 tables 9.3.2-1 and
//     9.5.2-1 give "a"), as for MCPTT;
//   - field ID 3 for the MCVideo Monitoring State field (TS 24.581 tables 9.3.3.1-1 and 9.5.3.1-1 give "b"), as for
//     MCPTT;
//   - field ID 1 for the TMGI fields of a Session Announcement (TS 24.380 table 8.6.3.1-1 and TS 24.581 table
//     9.5.3.1-1 have no TMGI): the first field with ID 1 is the MBS Session ID, the following ones the TMGI and the
//     alternative TMGIs, in the order of table 8.6.7-1;
//   - field ID 5 for the Group ID field of a Group Dynamic Data Notify (TS 24.380 table 8.5.3.1-1 and TS 24.581
//     table 9.4.3.1-1 have none, and IDs 2 and 3 of the fields it is "coded as" are taken in those tables).
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.008 V19.4.0 (Rel-19), RFC 3550.
#pragma once

#include "mcx/mbms_usage.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// The delivery system: an EPS MBMS bearer (TS 24.380 clause 10) or a 5G MBS session (TS 24.380 clause 10B, with the
// terminology mapping of annex X; TS 24.581 annex A).
enum class MbmsSystem : std::uint8_t { Mbms, Mbs };

//------------------------------------------------------------------------------
// TS 24.380 tables 8.4.2-1 and 8.6.2-1, TS 24.581 tables 9.3.2-1 and 9.5.2-1: the subchannel control messages, by
// subtype: Map Group To Bearer (MapGroupToSessionStream), Unmap Group To Bearer (UnMapGroupFromSessionStream),
// Application Paging (MBS Application Paging) and Bearer Announcement (Session Announcement).
enum class SubchannelMessageType : std::uint8_t {
  MapGroup = 0,
  UnmapGroup = 1,
  ApplicationPaging = 2,
  Announcement = 3
};

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.4.3.3 and 8.6.3.3, TS 24.581 clauses 9.3.3.3 and 9.5.3.3: the MBMS (MBS) Subchannel field:
// the numbers of the media lines of the announcement's SDP (four bits each) and the IPv4 or IPv6 address and ports
// of the subchannel. For MCPTT, media is the audio m-line and control the floor control m-line; for MCVideo, media
// is the video m-line, audio a separate audio m-line (0: audio goes with the video), control the transmission
// control m-line and fec the FEC m-line (0: no FEC). A control line of 0 sends control on the media port. The MBS
// field adds the SSRC that the participating function puts in the control messages over the subchannel.
struct MbmsSubchannel {
  std::uint8_t media_line = 0;
  std::uint8_t audio_line = 0;
  std::uint8_t control_line = 0;
  std::uint8_t fec_line = 0;
  std::string address;
  std::uint16_t media_port = 0;
  std::uint16_t audio_port = 0;
  std::uint16_t control_port = 0;
  std::uint16_t fec_port = 0;
  std::optional<std::uint32_t> control_ssrc;

  bool operator==(const MbmsSubchannel &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.4.4 to 8.4.7 and 8.6.4 to 8.6.7, TS 24.581 clauses 9.3.4 to 9.3.7 and 9.5.4 to 9.5.7: a
// subchannel control message. The service and the system select the RTCP APP name. Which fields a message has:
//   Map Group To Bearer: group, one TMGI and the subchannel (MBMS); group, MBS session ID and subchannel (MBS);
//   Unmap Group To Bearer: group (MBMS); group, MBS session ID and subchannel (MBS);
//   Application Paging: group;
//   Bearer Announcement: no SSRC; the TMGI, alternative TMGIs and monitoring state (MBMS), preceded by the MBS
//   session ID (MBS).
// TMGIs and MBS session IDs are lower-case hexadecimal (TS 24.008 clause 10.5.6.13 octets 3 to 8; TS 23.247
// clause 6.5.1).
struct SubchannelMessage {
  MbmsService service = MbmsService::Mcptt;
  MbmsSystem system = MbmsSystem::Mbms;
  SubchannelMessageType type = SubchannelMessageType::MapGroup;
  std::uint32_t ssrc = 0;
  std::string group;
  std::vector<std::string> tmgis;
  std::string mbs_session_id;
  std::optional<MbmsSubchannel> subchannel;
  std::optional<bool> monitoring;

  bool operator==(const SubchannelMessage &) const = default;
};

//------------------------------------------------------------------------------
// Encodes a subchannel control message; throws when a field the message needs is missing or invalid.
std::vector<std::uint8_t> encode_subchannel(const SubchannelMessage &message);
//------------------------------------------------------------------------------
// Decodes a subchannel control message ("MCMC", "MCSC", "MCV3" or "MCV5"); throws when it is not one, or breaks
// its message table.
SubchannelMessage decode_subchannel(std::span<const std::uint8_t> bytes);
//------------------------------------------------------------------------------
// Whether a packet is an RTCP APP packet named "MCMC", "MCSC", "MCV3" or "MCV5" (with or without the SSRC word).
[[nodiscard]] bool is_subchannel_message(std::span<const std::uint8_t> bytes);

//------------------------------------------------------------------------------
// TS 24.380 clause 8.5.4, TS 24.581 clause 9.4.4: the Group Dynamic Data Notify message ("MCNC"): the group, its
// status (0 emergency, 1 in-peril; clause 8.5.3.2), the MC service ID that changed it, whether a group call is
// ongoing, and its group broadcast and regroup aliases. Fields left empty are not sent.
struct GroupDynamicData {
  std::uint32_t ssrc = 0;
  std::string group;
  std::optional<std::uint16_t> status;
  std::string status_changer;
  std::optional<bool> call_ongoing;
  std::string broadcast_alias;
  std::string regroup_alias;

  bool operator==(const GroupDynamicData &) const = default;
};

std::vector<std::uint8_t> encode_group_dynamic_data(const GroupDynamicData &message);
GroupDynamicData decode_group_dynamic_data(std::span<const std::uint8_t> bytes);

} // namespace mcx
