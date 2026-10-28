//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MBMS and 5G MBS media plane messages (include/mcx/mbms.hpp) and the MBMS usage information bodies
// (include/mcx/mbms_usage.hpp): byte-exact codings worked out from the message tables, round trips of each message
// of each service and system, and what is refused.
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19),
// TS 24.281 V19.6.0 (Rel-19), TS 24.008 V19.4.0 (Rel-19).

#include "mcx/floor.hpp"
#include "mcx/mbms.hpp"

#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// Checks that the operation throws; what names what would have been wrongly accepted.
static void rejects(const std::function<void()> &operation, const std::string &what) {
  try {
    operation();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(what + " accepted");
}

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Helper: an MCPTT MBMS subchannel with a separate floor control subchannel.
static mcx::MbmsSubchannel mcptt_channel() {
  mcx::MbmsSubchannel channel;
  channel.media_line = 1;
  channel.control_line = 2;
  channel.address = "239.10.0.2";
  channel.media_port = 40002;
  channel.control_port = 40003;
  return channel;
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.4.4-1 and clauses 8.4.3.2 to 8.4.3.4: Map Group To Bearer, octet by octet.
static void Clause_8_4_4_MapGroupToBearer() {
  mcx::SubchannelMessage map;
  map.ssrc = 0x11223344;
  map.group = "sip:g@x";
  map.tmgis = {"00000199F907"};
  map.subchannel = mcptt_channel();
  const Bytes expected = {
      0x80, 0xcc, 0x00, 0x0b, 0x11, 0x22, 0x33, 0x44, 'M', 'C',  'M',  'C',  // header, SSRC, name
      0x02, 0x07, 's',  'i',  'p',  ':',  'g',  '@',  'x', 0x00, 0x00, 0x00, // MCPTT Group ID, padded
      0x01, 0x06, 0x00, 0x00, 0x01, 0x99, 0xf9, 0x07,                        // TMGI (6 octets)
      0x00, 0x0e, 0x12, 0x00,                                                // subchannel: lines 1 and 2, IPv4
      0x00, 0x00, 0x9c, 0x43,                                                // floor control port 40003
      0x00, 0x00, 0x9c, 0x42,                                                // media port 40002
      0xef, 0x0a, 0x00, 0x02};                                               // 239.10.0.2
  const auto bytes = mcx::encode_subchannel(map);
  expect(bytes == expected, "Map Group To Bearer coding");
  auto read = mcx::decode_subchannel(bytes);
  map.tmgis = {"00000199f907"};
  expect(read == map, "Map Group To Bearer not read back");
  expect(mcx::is_subchannel_message(bytes), "Map Group To Bearer not recognised");
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.4.7-1 and clauses 8.4.3.4 and 8.4.3.6: Bearer Announcement without an SSRC, a 3-octet TMGI
// padded to 6 octets, an alternative TMGI and the monitoring state.
static void Clause_8_4_7_BearerAnnouncement() {
  mcx::SubchannelMessage announcement;
  announcement.type = mcx::SubchannelMessageType::Announcement;
  announcement.tmgis = {"000001", "00000299f907"};
  announcement.monitoring = true;
  const Bytes expected = {0x83, 0xcc, 0x00, 0x06, 'M',  'C',  'M',  'C',  // header, name (no SSRC)
                          0x01, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // TMGI (3 octets), padded
                          0x01, 0x06, 0x00, 0x00, 0x02, 0x99, 0xf9, 0x07, // alternative TMGI
                          0x03, 0x01, 0x01, 0x00};                        // Monitoring State: active
  const auto bytes = mcx::encode_subchannel(announcement);
  expect(bytes == expected, "Bearer Announcement coding");
  expect(mcx::decode_subchannel(bytes) == announcement, "Bearer Announcement not read back");
  expect(mcx::is_subchannel_message(bytes), "Bearer Announcement not recognised");
  announcement.tmgis.clear();
  rejects([&] { (void)mcx::encode_subchannel(announcement); }, "a Bearer Announcement without a TMGI");
}

//------------------------------------------------------------------------------
// TS 24.380 tables 8.4.5-1 and 8.4.6-1: Unmap Group To Bearer and Application Paging carry the group only.
static void Clauses_8_4_5_and_8_4_6_UnmapAndPaging() {
  for (const auto type : {mcx::SubchannelMessageType::UnmapGroup, mcx::SubchannelMessageType::ApplicationPaging}) {
    mcx::SubchannelMessage message;
    message.type = type;
    message.ssrc = 7;
    message.group = "sip:fire@example.test";
    const auto bytes = mcx::encode_subchannel(message);
    expect(bytes[0] == (0x80 | static_cast<int>(type)), "subtype");
    expect(mcx::decode_subchannel(bytes) == message, "Unmap or Paging not read back");
    message.group.clear();
    rejects([&] { (void)mcx::encode_subchannel(message); }, "a message without a group");
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.6.3.3, 8.6.4 and 8.6.5: MCSC carries the MBS session ID and the floor control SSRC; an IPv6
// subchannel without a separate floor control subchannel; UnMapGroupFromSessionStream carries the subchannel too.
static void Clause_8_6_McsCSessionStream() {
  mcx::SubchannelMessage map;
  map.system = mcx::MbmsSystem::Mbs;
  map.ssrc = 0x0a;
  map.group = "sip:g@x";
  map.mbs_session_id = "00000399f907";
  mcx::MbmsSubchannel channel;
  channel.media_line = 1;
  channel.address = "ff15::1";
  channel.media_port = 40010;
  channel.control_ssrc = 0xcafebabe;
  map.subchannel = channel;
  const auto bytes = mcx::encode_subchannel(map);
  expect(std::string(bytes.begin() + 8, bytes.begin() + 12) == "MCSC", "MCSC name");
  expect(mcx::decode_subchannel(bytes) == map, "MapGroupToSessionStream not read back");
  map.type = mcx::SubchannelMessageType::UnmapGroup;
  expect(mcx::decode_subchannel(mcx::encode_subchannel(map)) == map, "UnMapGroupFromSessionStream not read back");

  mcx::SubchannelMessage announcement;
  announcement.system = mcx::MbmsSystem::Mbs;
  announcement.type = mcx::SubchannelMessageType::Announcement;
  announcement.mbs_session_id = "00000399f907";
  announcement.tmgis = {"00000399f907", "000004"};
  announcement.monitoring = false;
  expect(mcx::decode_subchannel(mcx::encode_subchannel(announcement)) == announcement,
         "Session Announcement not read back");

  auto mbms = map;
  mbms.system = mcx::MbmsSystem::Mbms;
  mbms.type = mcx::SubchannelMessageType::MapGroup;
  mbms.tmgis = {"000001"};
  rejects([&] { (void)mcx::encode_subchannel(mbms); }, "a control SSRC in an MBMS subchannel field");
  map.subchannel->control_ssrc.reset();
  rejects([&] { (void)mcx::encode_subchannel(map); }, "an MBS subchannel field without the control SSRC");
}

//------------------------------------------------------------------------------
// TS 24.581 tables 9.5.3.3-1 and 9.5.4-1: an MCVideo MapGroupToSessionStream ("MCV5") with video, separate audio
// and transmission control subchannels and no FEC, octet by octet.
static void Clause_9_5_4_McVideoMapGroupToSessionStream() {
  mcx::SubchannelMessage map;
  map.service = mcx::MbmsService::Mcvideo;
  map.system = mcx::MbmsSystem::Mbs;
  map.ssrc = 0x0a;
  map.group = "sip:v@x";
  map.mbs_session_id = "00000399f907";
  mcx::MbmsSubchannel channel;
  channel.media_line = 1;
  channel.audio_line = 2;
  channel.control_line = 3;
  channel.address = "239.20.0.1";
  channel.control_port = 41000;
  channel.control_ssrc = 0xcafebabe;
  channel.media_port = 41002;
  channel.audio_port = 41004;
  map.subchannel = channel;
  const Bytes expected = {
      0x80, 0xcc, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x0a, 'M', 'C',  'V',  '5',  // header, SSRC, name
      0x02, 0x07, 's',  'i',  'p',  ':',  'v',  '@',  'x', 0x00, 0x00, 0x00, // MCVideo Group ID, padded
      0x01, 0x06, 0x00, 0x00, 0x03, 0x99, 0xf9, 0x07,                        // MBS Session ID
      0x00, 0x1a, 0x12, 0x30, 0x00, 0x00, 0x00, 0x00,                        // lines 1, 2, 3, 0; IPv4; spare
      0x00, 0x00, 0xa0, 0x28,                                                // transmission control port 41000
      0xca, 0xfe, 0xba, 0xbe,                                                // transmission control SSRC
      0x00, 0x00, 0xa0, 0x2a,                                                // video port 41002
      0x00, 0x00, 0xa0, 0x2c,                                                // audio port 41004
      0xef, 0x14, 0x00, 0x01};                                               // 239.20.0.1
  const auto bytes = mcx::encode_subchannel(map);
  expect(bytes == expected, "MCVideo MapGroupToSessionStream coding");
  expect(mcx::decode_subchannel(bytes) == map, "MCVideo MapGroupToSessionStream not read back");
}

//------------------------------------------------------------------------------
// TS 24.581 clauses 9.3.3.3 and 9.3.4 to 9.3.7 ("MCV3"): each message, with audio combined with the video, and a
// FEC subchannel (whose port is coded even though this implementation sends no repair packets).
static void Clause_9_3_McVideoMbms() {
  mcx::SubchannelMessage map;
  map.service = mcx::MbmsService::Mcvideo;
  map.ssrc = 99;
  map.group = "sip:video@example.test";
  map.tmgis = {"000005"};
  mcx::MbmsSubchannel channel;
  channel.media_line = 1;
  channel.fec_line = 3;
  channel.address = "239.20.0.9";
  channel.media_port = 42000;
  channel.fec_port = 42004;
  map.subchannel = channel;
  const auto bytes = mcx::encode_subchannel(map);
  expect(std::string(bytes.begin() + 8, bytes.begin() + 12) == "MCV3", "MCV3 name");
  expect(mcx::decode_subchannel(bytes) == map, "MCVideo Map Group To Bearer not read back");
  for (const auto type : {mcx::SubchannelMessageType::UnmapGroup, mcx::SubchannelMessageType::ApplicationPaging}) {
    mcx::SubchannelMessage message;
    message.service = mcx::MbmsService::Mcvideo;
    message.type = type;
    message.group = map.group;
    expect(mcx::decode_subchannel(mcx::encode_subchannel(message)) == message, "MCVideo Unmap or Paging");
  }
  mcx::SubchannelMessage announcement;
  announcement.service = mcx::MbmsService::Mcvideo;
  announcement.type = mcx::SubchannelMessageType::Announcement;
  announcement.tmgis = {"000005"};
  const auto announced = mcx::encode_subchannel(announcement);
  expect(announced[0] == 0x83 && std::string(announced.begin() + 4, announced.begin() + 8) == "MCV3",
         "MCVideo Bearer Announcement subtype and name");
  expect(mcx::decode_subchannel(announced) == announcement, "MCVideo Bearer Announcement not read back");
  map.subchannel->audio_line = 0;
  map.service = mcx::MbmsService::Mcptt;
  rejects([&] { (void)mcx::encode_subchannel(map); }, "an MCPTT subchannel with a FEC line");
}

//------------------------------------------------------------------------------
// Decoding: fields in any order, unknown fields ignored; refused: a missing TMGI or subchannel, a length mismatch, a
// reserved IP version, a port out of range, and packets that are not subchannel control messages.
static void Decoding() {
  // Fields reordered and an unknown field (ID 9) added: the subchannel first, then the TMGI, the group last.
  mcx::AppPacket packet{0, 0, {'M', 'C', 'M', 'C'}, {}};
  const auto map = mcx::decode_subchannel([] {
    mcx::SubchannelMessage message;
    message.group = "sip:g@x";
    message.tmgis = {"000001"};
    message.subchannel = mcptt_channel();
    return mcx::encode_subchannel(message);
  }());
  const auto original = mcx::decode_app(mcx::encode_subchannel(map));
  packet.fields = {original.fields[2], {9, {1, 2, 3}}, original.fields[1], original.fields[0]};
  expect(mcx::decode_subchannel(mcx::encode_app(packet)) == map, "reordered fields");

  auto without_tmgi = packet;
  without_tmgi.fields = {original.fields[0], original.fields[2]};
  rejects([&] { (void)mcx::decode_subchannel(mcx::encode_app(without_tmgi)); }, "Map Group To Bearer without TMGI");
  auto without_channel = packet;
  without_channel.fields = {original.fields[0], original.fields[1]};
  rejects([&] { (void)mcx::decode_subchannel(mcx::encode_app(without_channel)); },
          "Map Group To Bearer without subchannel");

  auto channel = original.fields[2];
  auto mismatch = packet;
  channel.value.push_back(0);
  mismatch.fields = {original.fields[0], original.fields[1], channel};
  rejects([&] { (void)mcx::decode_subchannel(mcx::encode_app(mismatch)); }, "a subchannel field length mismatch");
  channel = original.fields[2];
  channel.value[1] = 0x20;
  mismatch.fields.back() = channel;
  rejects([&] { (void)mcx::decode_subchannel(mcx::encode_app(mismatch)); }, "a reserved IP version");
  channel = original.fields[2];
  channel.value[2] = 0x01; // floor control port 0x0001_9c43
  mismatch.fields.back() = channel;
  rejects([&] { (void)mcx::decode_subchannel(mcx::encode_app(mismatch)); }, "a port beyond 65535");

  const auto floor = mcx::encode_floor({mcx::FloorType::Taken, false, 5, {}});
  expect(!mcx::is_subchannel_message(floor), "a floor control message taken for subchannel control");
  rejects([&] { (void)mcx::decode_subchannel(floor); }, "a floor control message");
  packet.subtype = 4;
  rejects([&] { (void)mcx::decode_subchannel(mcx::encode_app(packet)); }, "subtype 4");
  auto bad = map;
  bad.subchannel->address = "fire-station";
  rejects([&] { (void)mcx::encode_subchannel(bad); }, "a host name as subchannel address");
  bad = map;
  bad.subchannel->media_line = 16;
  rejects([&] { (void)mcx::encode_subchannel(bad); }, "an m-line number of five bits");
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.5.4-1 and clauses 8.5.3.2 to 8.5.3.4 (TS 24.581 table 9.4.4-1): Group Dynamic Data Notify,
// octet by octet, and the aliases read back.
static void Clause_8_5_4_GroupDynamicDataNotify() {
  mcx::GroupDynamicData notify;
  notify.ssrc = 1;
  notify.group = "sip:g@x";
  notify.status = 0;
  notify.status_changer = "sip:a@x";
  notify.call_ongoing = true;
  const Bytes expected = {
      0x80, 0xcc, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 'M', 'C',  'N',  'C',  // header, SSRC, name
      0x00, 0x02, 0x00, 0x00,                                                // Status: emergency
      0x01, 0x07, 's',  'i',  'p',  ':',  'a',  '@',  'x', 0x00, 0x00, 0x00, // Status changing user
      0x05, 0x07, 's',  'i',  'p',  ':',  'g',  '@',  'x', 0x00, 0x00, 0x00, // Group ID (field ID 5)
      0x02, 0x01, 0x01, 0x00};                                               // Group call ongoing
  const auto bytes = mcx::encode_group_dynamic_data(notify);
  expect(bytes == expected, "Group Dynamic Data Notify coding");
  expect(mcx::decode_group_dynamic_data(bytes) == notify, "Group Dynamic Data Notify not read back");
  notify.status = 1;
  notify.broadcast_alias = "sip:broadcast@x";
  notify.regroup_alias = "sip:regroup@x";
  expect(mcx::decode_group_dynamic_data(mcx::encode_group_dynamic_data(notify)) == notify, "aliases not read back");
  notify.status = 2;
  rejects([&] { (void)mcx::encode_group_dynamic_data(notify); }, "a reserved group status");
  notify.status.reset();
  notify.group.clear();
  rejects([&] { (void)mcx::encode_group_dynamic_data(notify); }, "a notification without a group");
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 14.2.2.2 to 14.2.2.4 and annex F.2.3 item 3 (TS 24.281 clause 16.3.2 and annex F.2): an
// announcement and a cancellation in one body, for each service.
static void Clause_14_2_2_Announcement() {
  for (const auto service : {mcx::MbmsService::Mcptt, mcx::MbmsService::Mcvideo}) {
    mcx::MbmsAnnouncement initial;
    initial.tmgi = "00000199f907";
    initial.qci = 65;
    initial.frequency = 3500;
    initial.service_areas = {"0001", "0002"};
    initial.gpms = 1;
    initial.report_suspension = true;
    mcx::MbmsAnnouncement cancelled;
    cancelled.tmgi = "000002";
    mcx::MbmsUsageInfo info;
    info.announcements = {initial, cancelled};
    const auto xml = mcx::mbms_usage_xml(info, service);
    const auto &type = mcx::mbms_usage_type(service);
    expect(xml.find(std::string("<") + type.root + " xmlns=\"" + type.ns + "\">") != std::string::npos, "root");
    const auto read = mcx::parse_mbms_usage_info(xml, service);
    expect(read == info, "announcement not read back: " + xml);
    expect(!read.announcements[0].cancellation() && read.announcements[1].cancellation(), "cancellation");
    const auto other = service == mcx::MbmsService::Mcptt ? mcx::MbmsService::Mcvideo : mcx::MbmsService::Mcptt;
    rejects([&] { (void)mcx::parse_mbms_usage_info(xml, other); }, "a body of the other service");
  }
  const std::string ns = mcx::mbms_usage_ns;
  const auto document = [&](const std::string &inner) {
    return "<mcptt-mbms-usage-info xmlns=\"" + ns + "\">" + inner + "<version>1</version></mcptt-mbms-usage-info>";
  };
  const auto rohc = mcx::parse_mbms_usage_info(
      document("<announcement><TMGI>000001</TMGI><mbms-service-areas><mbms-service-area-id>0001"
               "</mbms-service-area-id></mbms-service-areas><GPMS>2</GPMS><unknown/><anyExt><mcptt-mbms-rohc/>"
               "<max-cid>15</max-cid></anyExt></announcement>"));
  expect(rohc.announcements.size() == 1 && rohc.announcements[0].rohc && rohc.announcements[0].gpms == 2u,
         "ROHC announcement");
  rejects([&] { (void)mcx::parse_mbms_usage_info(document("<announcement><QCI>9</QCI></announcement>")); },
          "an announcement without a TMGI");
  rejects([&] { (void)mcx::parse_mbms_usage_info(document("<announcement><TMGI>01</TMGI></announcement>")); },
          "a TMGI of one octet");
  rejects(
      [&] {
        (void)mcx::parse_mbms_usage_info(document("<announcement><TMGI>000001</TMGI><GPMS>0</GPMS></announcement>"));
      },
      "GPMS 0");
  rejects(
      [&] {
        (void)mcx::parse_mbms_usage_info(
            document("<announcement><TMGI>000001</TMGI><mbms-service-areas/></announcement>"));
      },
      "empty mbms-service-areas");
  rejects(
      [&] {
        (void)mcx::parse_mbms_usage_info(document("<announcement><TMGI>000001</TMGI><mbms-service-areas>"
                                                  "<mbms-service-area-id>123</mbms-service-area-id>"
                                                  "</mbms-service-areas></announcement>"));
      },
      "an odd-length service area ID");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.3.3.2 and annex F.2.3 items 1 and 2: a listening report on the general purpose subchannel with
// a reception quality, and a suspension report.
static void Clause_14_3_3_2_ListeningAndSuspension() {
  mcx::MbmsUsageInfo info;
  info.listening_status = mcx::MbmsListeningStatus{true, "", true, {"000001", "000002"}, 4};
  info.suspension_status = mcx::MbmsSuspensionStatus{true, "000001", {"000003"}};
  const auto xml = mcx::mbms_usage_xml(info, mcx::MbmsService::Mcvideo);
  expect(xml.find("<number-of-reported-bearers>2</number-of-reported-bearers>") != std::string::npos,
         "number of reported bearers");
  expect(mcx::parse_mbms_usage_info(xml, mcx::MbmsService::Mcvideo) == info, "reports not read back: " + xml);
  info.listening_status->reception_quality = 6;
  rejects([&] { (void)mcx::mbms_usage_xml(info); }, "reception quality 6");
  info.listening_status->reception_quality.reset();
  info.suspension_status->suspended_tmgi.clear();
  rejects([&] { (void)mcx::mbms_usage_xml(info); }, "a suspension report without a suspended TMGI");
  const std::string ns = mcx::mbms_usage_ns;
  rejects(
      [&] {
        (void)mcx::parse_mbms_usage_info("<mcptt-mbms-usage-info xmlns=\"" + ns +
                                         "\"><mbms-suspension-status><mbms-suspension-status>maybe"
                                         "</mbms-suspension-status><suspended-TMGI>000001</suspended-TMGI>"
                                         "</mbms-suspension-status><version>1</version></mcptt-mbms-usage-info>");
      },
      "an unknown suspension status");
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 14.2.2.5 and 14.3.4, annex F.2.3 item 5: default and explicit MuSiK downloads in <anyExt>.
static void Clause_14_2_2_5_MusikDownload() {
  mcx::MbmsUsageInfo by_default;
  by_default.musik_download = mcx::MusikDownload{false, {}};
  const auto xml = mcx::mbms_usage_xml(by_default);
  expect(xml.find("<anyExt><mbms-defaultMuSiK-download></mbms-defaultMuSiK-download></anyExt>") != std::string::npos,
         "default MuSiK download element: " + xml);
  expect(mcx::parse_mbms_usage_info(xml) == by_default, "default MuSiK download not read back");
  mcx::MbmsUsageInfo by_group;
  by_group.musik_download = mcx::MusikDownload{true, {"sip:fire@example.test", "sip:police@example.test"}};
  expect(mcx::parse_mbms_usage_info(mcx::mbms_usage_xml(by_group)) == by_group, "explicit MuSiK download");
  by_group.musik_download->groups.clear();
  rejects([&] { (void)mcx::mbms_usage_xml(by_group); }, "an explicit MuSiK download without a group");
  const std::string ns = mcx::mbms_usage_ns;
  rejects(
      [&] {
        (void)mcx::parse_mbms_usage_info("<mcptt-mbms-usage-info xmlns=\"" + ns +
                                         "\"><version>1</version><anyExt><mbms-defaultMuSiK-download/>"
                                         "<mbms-explicitMuSiK-download><group>sip:g@x</group>"
                                         "</mbms-explicitMuSiK-download></anyExt></mcptt-mbms-usage-info>");
      },
      "a default and an explicit MuSiK download together");
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2A and clause 14B (TS 24.281 annex F.2A): an MBS session announcement and a cancellation, the
// listening status with <unicast-listening-status>, the de-announcement status and the UE session join notification,
// for each service; what is refused.
static void Clause_14B_MbsUsage() {
  for (const auto service : {mcx::MbmsService::Mcptt, mcx::MbmsService::Mcvideo}) {
    mcx::MbsAnnouncement session;
    session.session_id = "00000399f907";
    session.mode = "multicast";
    session.gpms = 3;
    session.service_areas = {"0001"};
    session.report_join = true;
    session.fsa_ids = {"000001"};
    session.de_announcement_ack = true;
    mcx::MbsAnnouncement cancelled;
    cancelled.session_id = "000004";
    mcx::MbsUsageInfo info;
    info.announcements = {session, cancelled};
    info.musik_download = mcx::MusikDownload{false, {}};
    const auto xml = mcx::mbs_usage_xml(info, service);
    expect(xml.find("<multicast-mbs-session-related-info/>") != std::string::npos, "related info element");
    expect(mcx::parse_mbs_usage_info(xml, service) == info, "MBS announcement not read back: " + xml);
    const auto other = service == mcx::MbmsService::Mcptt ? mcx::MbmsService::Mcvideo : mcx::MbmsService::Mcptt;
    rejects([&] { (void)mcx::parse_mbs_usage_info(xml, other); }, "an MBS body of the other service");
    rejects([&] { (void)mcx::parse_mbms_usage_info(xml, service); }, "an MBS body read as MBMS");

    mcx::MbsUsageInfo reports;
    reports.listening_status = mcx::MbsListeningStatus{true, false, "sip:s@example.test;session=1", std::nullopt,
                                                       {"00000399f907"}};
    reports.de_announcement_status = mcx::MbsDeAnnouncementStatus{true, "00000399f907", {}};
    reports.join_notification = mcx::UeSessionJoin{true, "00000399f907", "sip:s@example.test;session=1"};
    const auto report_xml = mcx::mbs_usage_xml(reports, service);
    expect(mcx::parse_mbs_usage_info(report_xml, service) == reports, "MBS reports not read back: " + report_xml);
  }
  const auto ns = std::string(mcx::mbs_usage_type(mcx::MbmsService::Mcptt).ns);
  const auto document = [&](const std::string &inner) {
    return "<mcptt-mbs-usage-info xmlns=\"" + ns + "\">" + inner + "<version>1</version></mcptt-mbs-usage-info>";
  };
  rejects([&] {
    (void)mcx::parse_mbs_usage_info(document("<mbs-listening-status><mbs-listening-status>listening</mbs-listening-status>"
                                             "<general-purpose>true</general-purpose><mbs-session-id>000001</mbs-session-id>"
                                             "</mbs-listening-status>"));
  }, "an MBS listening status without <unicast-listening-status>");
  rejects([&] {
    (void)mcx::parse_mbs_usage_info(document("<announcement><mbs-session-info><mbs-session-id>000001</mbs-session-id>"
                                             "<mbs-session-mode>anycast</mbs-session-mode>"
                                             "<multicast-mbs-session-related-info/></mbs-session-info></announcement>"));
  }, "an unknown MBS session mode");
  mcx::MbsUsageInfo bad;
  bad.listening_status = mcx::MbsListeningStatus{true, false, "", std::nullopt, {"000001"}};
  rejects([&] { (void)mcx::mbs_usage_xml(bad); }, "an MBS listening status without session or general purpose");
}

//------------------------------------------------------------------------------
int main() {
  Clause_8_4_4_MapGroupToBearer();
  Clause_8_4_7_BearerAnnouncement();
  Clauses_8_4_5_and_8_4_6_UnmapAndPaging();
  Clause_8_6_McsCSessionStream();
  Clause_9_5_4_McVideoMapGroupToSessionStream();
  Clause_9_3_McVideoMbms();
  Decoding();
  Clause_8_5_4_GroupDynamicDataNotify();
  Clause_14_2_2_Announcement();
  Clause_14_3_3_2_ListeningAndSuspension();
  Clause_14_2_2_5_MusikDownload();
  Clause_14B_MbsUsage();
  std::cout << "mbms tests passed\n";
}
