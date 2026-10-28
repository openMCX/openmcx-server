//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MBMS and 5G MBS subchannel control messages and the MBMS notifications (include/mcx/mbms.hpp), coded on the
// RTCP APP framing of TS 24.380 clause 8.1 (include/mcx/floor.hpp).
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.008 V19.4.0 (Rel-19), RFC 3550.

#include "mcx/mbms.hpp"

#include "mcx/floor.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <stdexcept>

namespace mcx {
namespace {

constexpr std::uint8_t kRtcpApp = 204;
constexpr std::size_t kSsrcOffset = 4, kNameOffset = 8;

// TS 24.380 clause 8.4.1, clause 8.5.1 and clause 8.6.1; TS 24.581 clause 9.3.1 and clause 9.5.1.
constexpr std::array<std::uint8_t, 4> kMcmc{'M', 'C', 'M', 'C'}, kMcsc{'M', 'C', 'S', 'C'}, kMcv3{'M', 'C', 'V', '3'},
    kMcv5{'M', 'C', 'V', '5'}, kMcnc{'M', 'C', 'N', 'C'};

// TS 24.380 tables 8.4.3.1-2 and 8.6.3.1-1, TS 24.581 tables 9.3.3.1-1 and 9.5.3.1-1 (see the header for the
// MCVideo Monitoring State and the Session Announcement's TMGIs).
enum SubchannelField : std::uint8_t { kSubchannel = 0, kTmgi = 1, kSessionId = 1, kGroupId = 2, kMonitoring = 3 };

// TS 24.380 table 8.5.3.1-1, TS 24.581 table 9.4.3.1-1 (see the header for the Group ID).
enum NotifyField : std::uint8_t {
  kStatus = 0,
  kStatusChanger = 1,
  kCallOngoing = 2,
  kBroadcastAlias = 3,
  kRegroupAlias = 4,
  kNotifyGroupId = 5
};

//------------------------------------------------------------------------------
// Helper: reads a 32-bit value in network byte order.
std::uint32_t read_u32(std::span<const std::uint8_t> bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24) | (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]);
}

//------------------------------------------------------------------------------
// Helper: appends a 32-bit value in network byte order.
void append_u32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) bytes.push_back(static_cast<std::uint8_t>(value >> shift));
}

//------------------------------------------------------------------------------
// Helper: the RTCP APP name of a service and system.
const std::array<std::uint8_t, 4> &subchannel_name(MbmsService service, MbmsSystem system) {
  if (service == MbmsService::Mcptt) return system == MbmsSystem::Mbms ? kMcmc : kMcsc;
  return system == MbmsSystem::Mbms ? kMcv3 : kMcv5;
}

//------------------------------------------------------------------------------
// Helper: whether four octets are one of the subchannel control names.
bool subchannel_named(std::span<const std::uint8_t> name) {
  return std::ranges::any_of(std::array{&kMcmc, &kMcsc, &kMcv3, &kMcv5},
                             [&](const auto *known) { return std::ranges::equal(*known, name); });
}

//------------------------------------------------------------------------------
// Helper: a hexadecimal string as octets (lower or upper case, even length).
std::vector<std::uint8_t> hex_octets(const std::string &hex) {
  if (hex.empty() || hex.size() % 2 != 0 || hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
    throw std::runtime_error("not hexadecimal octets: " + hex);
  std::vector<std::uint8_t> out;
  for (std::size_t at = 0; at < hex.size(); at += 2)
    out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(at, 2), nullptr, 16)));
  return out;
}

//------------------------------------------------------------------------------
// Helper: octets as lower-case hexadecimal.
std::string octets_hex(std::span<const std::uint8_t> octets) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (const auto octet : octets) {
    out += digits[octet >> 4];
    out += digits[octet & 0x0f];
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.4.3.4: the TMGI field: TS 24.008 clause 10.5.6.13 octets 3 to 8 (3 or 6 octets).
FloorField tmgi_field(const std::string &tmgi) { return {kTmgi, hex_octets(tmgi_hex(tmgi))}; }

std::string read_tmgi(const FloorField &field) {
  if (field.value.size() != 3 && field.value.size() != 6) throw std::runtime_error("TMGI field of 3 or 6 octets");
  return octets_hex(field.value);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.6.3.4: the MBS Session ID field (TS 23.247 clause 6.5.1), opaque here.
FloorField session_id_field(const std::string &session_id) { return {kSessionId, hex_octets(session_id)}; }

std::string read_session_id(const FloorField &field) {
  if (field.value.empty()) throw std::runtime_error("empty MBS Session ID field");
  return octets_hex(field.value);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.3.3.5 (as clauses 8.4.3.2, 8.5.4 and 8.6.3.2 code the Group ID; TS 24.581 clause 9.2.3.20):
// a URI field, and the other URI fields of the notifications.
FloorField uri_field(std::uint8_t id, const std::string &uri) {
  if (uri.empty()) throw std::runtime_error("empty URI field");
  return {id, {uri.begin(), uri.end()}};
}

std::string read_uri(const FloorField &field) {
  if (field.value.empty()) throw std::runtime_error("empty URI field");
  return {field.value.begin(), field.value.end()};
}

//------------------------------------------------------------------------------
// TS 24.380 clause 8.4.3.6: the Monitoring State field: one octet, 0 inactive or 1 active.
FloorField monitoring_field(bool active) { return {kMonitoring, {static_cast<std::uint8_t>(active ? 1 : 0)}}; }

bool read_monitoring(const FloorField &field) {
  if (field.value.size() != 1 || field.value[0] > 1) throw std::runtime_error("invalid Monitoring State field");
  return field.value[0] == 1;
}

//------------------------------------------------------------------------------
// Helper: a four-bit media line number.
std::uint8_t line_number(std::uint8_t line) {
  if (line > 15) throw std::runtime_error("subchannel m-line number exceeds four bits");
  return line;
}

//------------------------------------------------------------------------------
// Helper: a port of the subchannel field: a 32-bit value (clause 8.4.3.3) holding a UDP port.
void append_port(std::vector<std::uint8_t> &bytes, std::uint16_t port) {
  if (port == 0) throw std::runtime_error("subchannel port 0");
  append_u32(bytes, port);
}

std::uint16_t read_port(std::span<const std::uint8_t> bytes, std::size_t &at) {
  if (bytes.size() < at + 4) throw std::runtime_error("truncated subchannel field");
  const auto value = read_u32(bytes.subspan(at, 4));
  at += 4;
  if (value == 0 || value > 65535) throw std::runtime_error("subchannel port out of range");
  return static_cast<std::uint16_t>(value);
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.4.3.3 and 8.6.3.3 (MCPTT), TS 24.581 clauses 9.3.3.3 and 9.5.3.3 (MCVideo): the subchannel
// field. MCPTT: audio and floor m-lines, IP version, [floor port], [control SSRC], media port, address. MCVideo:
// video, audio, control and FEC m-lines, IP version and 28 spare bits, [control port], [control SSRC], video port,
// [audio port], [FEC port], address. The control SSRC is in the MBS field only.
FloorField subchannel_field(const MbmsSubchannel &channel, MbmsService service, MbmsSystem system) {
  std::array<std::uint8_t, 16> address{};
  bool v6 = false;
  if (inet_pton(AF_INET, channel.address.c_str(), address.data()) != 1) {
    if (inet_pton(AF_INET6, channel.address.c_str(), address.data()) != 1)
      throw std::runtime_error("subchannel address is not an IP address: " + channel.address);
    v6 = true;
  }
  if ((system == MbmsSystem::Mbs) != channel.control_ssrc.has_value())
    throw std::runtime_error("the control SSRC is in the MBS subchannel field only");
  const auto version = static_cast<std::uint8_t>((v6 ? 1 : 0) << 4);
  std::vector<std::uint8_t> value;
  if (service == MbmsService::Mcptt) {
    if (channel.audio_line != 0 || channel.fec_line != 0) throw std::runtime_error("MCPTT subchannel with video lines");
    value = {static_cast<std::uint8_t>(line_number(channel.media_line) << 4 | line_number(channel.control_line)),
             version};
  } else {
    value = {static_cast<std::uint8_t>(line_number(channel.media_line) << 4 | line_number(channel.audio_line)),
             static_cast<std::uint8_t>(line_number(channel.control_line) << 4 | line_number(channel.fec_line)),
             version,
             0,
             0,
             0};
  }
  if (channel.control_line != 0) append_port(value, channel.control_port);
  if (channel.control_ssrc) append_u32(value, *channel.control_ssrc);
  append_port(value, channel.media_port);
  if (service == MbmsService::Mcvideo) {
    if (channel.audio_line != 0) append_port(value, channel.audio_port);
    if (channel.fec_line != 0) append_port(value, channel.fec_port);
  }
  value.insert(value.end(), address.begin(), address.begin() + (v6 ? 16 : 4));
  return {kSubchannel, std::move(value)};
}

MbmsSubchannel read_subchannel(const FloorField &field, MbmsService service, MbmsSystem system) {
  const std::span<const std::uint8_t> bytes = field.value;
  MbmsSubchannel channel;
  const std::size_t lines = service == MbmsService::Mcptt ? 2 : 6;
  if (bytes.size() < lines) throw std::runtime_error("truncated subchannel field");
  channel.media_line = bytes[0] >> 4;
  std::uint8_t version = 0;
  if (service == MbmsService::Mcptt) {
    channel.control_line = bytes[0] & 0x0f;
    version = bytes[1] >> 4;
  } else {
    channel.audio_line = bytes[0] & 0x0f;
    channel.control_line = bytes[1] >> 4;
    channel.fec_line = bytes[1] & 0x0f;
    version = bytes[2] >> 4;
  }
  if (version > 1) throw std::runtime_error("reserved subchannel IP version");
  std::size_t at = lines;
  if (channel.control_line != 0) channel.control_port = read_port(bytes, at);
  if (system == MbmsSystem::Mbs) {
    if (bytes.size() < at + 4) throw std::runtime_error("truncated subchannel field");
    channel.control_ssrc = read_u32(bytes.subspan(at, 4));
    at += 4;
  }
  channel.media_port = read_port(bytes, at);
  if (channel.audio_line != 0) channel.audio_port = read_port(bytes, at);
  if (channel.fec_line != 0) channel.fec_port = read_port(bytes, at);
  const std::size_t address_size = version == 1 ? 16 : 4;
  if (bytes.size() != at + address_size) throw std::runtime_error("subchannel field length mismatch");
  std::array<char, INET6_ADDRSTRLEN> text{};
  if (!inet_ntop(version == 1 ? AF_INET6 : AF_INET, bytes.data() + at, text.data(), text.size()))
    throw std::runtime_error("invalid subchannel address");
  channel.address = text.data();
  return channel;
}

//------------------------------------------------------------------------------
// Helper: the Bearer Announcement and Session Announcement have no SSRC word (TS 24.380 tables 8.4.7-1 and 8.6.7-1):
// the APP packet is coded with one and the word removed.
std::vector<std::uint8_t> without_ssrc(std::vector<std::uint8_t> bytes) {
  bytes.erase(bytes.begin() + kSsrcOffset, bytes.begin() + kNameOffset);
  const auto words_minus_one = static_cast<std::uint16_t>(bytes.size() / 4 - 1);
  bytes[2] = static_cast<std::uint8_t>(words_minus_one >> 8);
  bytes[3] = static_cast<std::uint8_t>(words_minus_one);
  return bytes;
}

std::vector<std::uint8_t> with_ssrc(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < kNameOffset) throw std::runtime_error("truncated subchannel control message");
  std::vector<std::uint8_t> out(bytes.begin(), bytes.end());
  out.insert(out.begin() + kSsrcOffset, 4, 0);
  const auto words_minus_one = static_cast<std::uint16_t>(out.size() / 4 - 1);
  out[2] = static_cast<std::uint8_t>(words_minus_one >> 8);
  out[3] = static_cast<std::uint8_t>(words_minus_one);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the subtype of an RTCP APP packet (the five low bits of the first octet), or none.
std::optional<std::uint8_t> app_subtype(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < kNameOffset || (bytes[0] >> 6) != 2 || bytes[1] != kRtcpApp) return std::nullopt;
  return static_cast<std::uint8_t>(bytes[0] & 0x1f);
}

} // namespace

//------------------------------------------------------------------------------
// TS 24.380 tables 8.4.4-1 to 8.4.7-1 and 8.6.4-1 to 8.6.7-1, TS 24.581 tables 9.3.4-1 to 9.3.7-1 and 9.5.4-1 to
// 9.5.7-1: the fields of each message, in the tables' order.
std::vector<std::uint8_t> encode_subchannel(const SubchannelMessage &message) {
  const bool mbs = message.system == MbmsSystem::Mbs;
  AppPacket packet{
      static_cast<std::uint8_t>(message.type), message.ssrc, subchannel_name(message.service, message.system), {}};
  auto &fields = packet.fields;
  if (message.type == SubchannelMessageType::Announcement) {
    if (message.tmgis.empty()) throw std::runtime_error("announcement without a TMGI");
    if (mbs) fields.push_back(session_id_field(message.mbs_session_id));
    for (const auto &tmgi : message.tmgis) fields.push_back(tmgi_field(tmgi));
    if (message.monitoring) fields.push_back(monitoring_field(*message.monitoring));
    return without_ssrc(encode_app(packet));
  }
  fields.push_back(uri_field(kGroupId, message.group));
  const bool mapping =
      message.type == SubchannelMessageType::MapGroup || (mbs && message.type == SubchannelMessageType::UnmapGroup);
  if (mapping) {
    if (!message.subchannel) throw std::runtime_error("subchannel control message without a subchannel");
    if (mbs) {
      fields.push_back(session_id_field(message.mbs_session_id));
    } else {
      if (message.tmgis.size() != 1) throw std::runtime_error("Map Group To Bearer with one TMGI");
      fields.push_back(tmgi_field(message.tmgis.front()));
    }
    fields.push_back(subchannel_field(*message.subchannel, message.service, message.system));
  }
  return encode_app(packet);
}

//------------------------------------------------------------------------------
// The inverse of encode_subchannel: fields in any order after the first three words (the tables' note), unknown
// fields ignored, required fields checked.
SubchannelMessage decode_subchannel(std::span<const std::uint8_t> bytes) {
  const auto subtype = app_subtype(bytes);
  if (!subtype || *subtype > static_cast<std::uint8_t>(SubchannelMessageType::Announcement))
    throw std::runtime_error("not a subchannel control message");
  SubchannelMessage message;
  message.type = static_cast<SubchannelMessageType>(*subtype);
  const bool announcement = message.type == SubchannelMessageType::Announcement;
  const auto packet = announcement ? decode_app(with_ssrc(bytes)) : decode_app(bytes);
  if (!subchannel_named(packet.name)) throw std::runtime_error("not a subchannel control message");
  message.service = packet.name[2] == 'V' ? MbmsService::Mcvideo : MbmsService::Mcptt;
  message.system = packet.name == kMcmc || packet.name == kMcv3 ? MbmsSystem::Mbms : MbmsSystem::Mbs;
  const bool mbs = message.system == MbmsSystem::Mbs;
  message.ssrc = announcement ? 0 : packet.ssrc;
  for (const auto &field : packet.fields) {
    if (announcement) {
      if (field.id == kTmgi && mbs && message.mbs_session_id.empty())
        message.mbs_session_id = read_session_id(field);
      else if (field.id == kTmgi)
        message.tmgis.push_back(read_tmgi(field));
      else if (field.id == kMonitoring)
        message.monitoring = read_monitoring(field);
      continue;
    }
    if (field.id == kGroupId)
      message.group = read_uri(field);
    else if (field.id == kTmgi && mbs)
      message.mbs_session_id = read_session_id(field);
    else if (field.id == kTmgi)
      message.tmgis.push_back(read_tmgi(field));
    else if (field.id == kSubchannel)
      message.subchannel = read_subchannel(field, message.service, message.system);
  }
  if (announcement) {
    if (message.tmgis.empty() || (mbs && message.mbs_session_id.empty()))
      throw std::runtime_error("announcement without its TMGI or MBS Session ID");
    return message;
  }
  if (message.group.empty()) throw std::runtime_error("subchannel control message without a Group ID");
  const bool mapping =
      message.type == SubchannelMessageType::MapGroup || (mbs && message.type == SubchannelMessageType::UnmapGroup);
  if (mapping && (!message.subchannel || (mbs ? message.mbs_session_id.empty() : message.tmgis.size() != 1)))
    throw std::runtime_error("subchannel control message without its TMGI, MBS Session ID or subchannel");
  return message;
}

//------------------------------------------------------------------------------
// The name is at octet 8, or at octet 4 for an announcement (subtype 3) without the SSRC word.
bool is_subchannel_message(std::span<const std::uint8_t> bytes) {
  const auto subtype = app_subtype(bytes);
  if (!subtype) return false;
  if (bytes.size() >= kNameOffset + 4 && subchannel_named(bytes.subspan(kNameOffset, 4))) return true;
  return *subtype == static_cast<std::uint8_t>(SubchannelMessageType::Announcement) &&
         subchannel_named(bytes.subspan(kSsrcOffset, 4));
}

//------------------------------------------------------------------------------
// TS 24.380 table 8.5.4-1, clauses 8.5.3.2 to 8.5.3.6 (TS 24.581 table 9.4.4-1): Group Dynamic Data Notify,
// subtype 00000.
std::vector<std::uint8_t> encode_group_dynamic_data(const GroupDynamicData &message) {
  AppPacket packet{0, message.ssrc, kMcnc, {}};
  auto &fields = packet.fields;
  if (message.status) {
    if (*message.status > 1) throw std::runtime_error("reserved group status");
    fields.push_back({kStatus, {0, static_cast<std::uint8_t>(*message.status)}});
  }
  if (!message.status_changer.empty()) fields.push_back(uri_field(kStatusChanger, message.status_changer));
  fields.push_back(uri_field(kNotifyGroupId, message.group));
  if (message.call_ongoing) fields.push_back({kCallOngoing, {static_cast<std::uint8_t>(*message.call_ongoing)}});
  if (!message.broadcast_alias.empty()) fields.push_back(uri_field(kBroadcastAlias, message.broadcast_alias));
  if (!message.regroup_alias.empty()) fields.push_back(uri_field(kRegroupAlias, message.regroup_alias));
  return encode_app(packet);
}

GroupDynamicData decode_group_dynamic_data(std::span<const std::uint8_t> bytes) {
  const auto packet = decode_app(bytes);
  if (packet.name != kMcnc || packet.subtype != 0) throw std::runtime_error("not a Group Dynamic Data Notify");
  GroupDynamicData message;
  message.ssrc = packet.ssrc;
  for (const auto &field : packet.fields) {
    switch (field.id) {
    case kStatus:
      if (field.value.size() != 2 || field.value[0] != 0 || field.value[1] > 1)
        throw std::runtime_error("invalid Status field");
      message.status = field.value[1];
      break;
    case kStatusChanger: message.status_changer = read_uri(field); break;
    case kCallOngoing:
      if (field.value.size() != 1 || field.value[0] > 1) throw std::runtime_error("invalid Group call ongoing field");
      message.call_ongoing = field.value[0] == 1;
      break;
    case kBroadcastAlias: message.broadcast_alias = read_uri(field); break;
    case kRegroupAlias: message.regroup_alias = read_uri(field); break;
    case kNotifyGroupId: message.group = read_uri(field); break;
    default: break;
    }
  }
  if (message.group.empty()) throw std::runtime_error("Group Dynamic Data Notify without a Group ID");
  return message;
}

} // namespace mcx
