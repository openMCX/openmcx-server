//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The configuration of the participating function's pre-activated MBMS bearers (include/mcx/multicast.hpp).
//
// Specifications: RFC 1112, TS 24.379 V19.7.0 (Rel-19).

#include "mcx/multicast.hpp"

#include <cctype>
#include <limits>
#include <stdexcept>

namespace mcx {

//------------------------------------------------------------------------------
// RFC 3551 section 3: the dynamic RTP payload types.
inline constexpr unsigned first_dynamic_payload_type = 96, last_dynamic_payload_type = 127;

//------------------------------------------------------------------------------
// Helper: "<IPv4 host group>:<port>" of a group.
static MulticastDestination host_group(const std::string &group, const std::string &value) {
  const auto colon = value.rfind(':');
  if (colon == std::string::npos) throw std::runtime_error("mbms: " + group + " needs <address>:<port>");
  MulticastDestination result{value.substr(0, colon), 0, {}};
  if (!is_ipv4_multicast(result.address))
    throw std::runtime_error("mbms: " + group + ": not an IPv4 host group address: " + result.address);
  const auto port = value.substr(colon + 1);
  constexpr auto max_port = std::numeric_limits<std::uint16_t>::max();
  constexpr std::size_t max_port_digits = 5;
  if (port.empty() || port.size() > max_port_digits || port.find_first_not_of("0123456789") != std::string::npos ||
      std::stoul(port) == 0 || std::stoul(port) > max_port)
    throw std::runtime_error("mbms: " + group + ": port must be 1 to 65535");
  result.port = static_cast<std::uint16_t>(std::stoul(port));
  return result;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.2.3: a TMGI is coded as TS 24.008 clause 10.5.6.13 octets 3 to 8: the MBMS Service ID (3 octets),
// optionally followed by the MCC and MNC (3 octets). Kept in lower case, as the reports are compared with it.
static std::string tmgi(const std::string &group, std::string value) {
  constexpr std::size_t service_id_digits = 6, with_plmn_digits = 12;
  if ((value.size() != service_id_digits && value.size() != with_plmn_digits) ||
      value.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
    throw std::runtime_error("mbms: " + group + ": tmgi must be 3 or 6 octets in hexadecimal");
  for (auto &digit : value) digit = static_cast<char>(std::tolower(static_cast<unsigned char>(digit)));
  return value;
}

//------------------------------------------------------------------------------
// Helper: the bearer of a TMGI, or none.
const MbmsBearerConfig *MbmsConfig::bearer(const std::string &tmgi) const {
  for (const auto &entry : bearers)
    if (entry.tmgi == tmgi) return &entry;
  return nullptr;
}

//------------------------------------------------------------------------------
// Helper: TS 24.379 annex F.2.3 item 3 d): an MBMS service area ID is hexBinary (TS 29.061 MBMS-Service-Area
// coding), kept in lower case.
static std::string service_area(const std::string &bearer, std::string value) {
  if (value.empty() || value.size() % 2 != 0 || value.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
    throw std::runtime_error("mbms: bearer " + bearer + ": service area IDs are hexBinary");
  for (auto &digit : value) digit = static_cast<char>(std::tolower(static_cast<unsigned char>(digit)));
  return value;
}

//------------------------------------------------------------------------------
// Helper: reads and checks an "mbms" block.
MbmsConfig mbms_config(const Json &block) {
  if (!block.is_object()) throw std::runtime_error("mbms: the block must be an object");
  MbmsConfig result;
  result.interface = block.value("interface", result.interface);
  result.ttl = block.value("ttl", result.ttl);
  if (result.ttl < 1 || result.ttl > max_multicast_ttl) throw std::runtime_error("mbms: ttl must be 1 to 255");
  const auto payload_type = block.value("payload_type", unsigned{result.payload_type});
  if (payload_type < first_dynamic_payload_type || payload_type > last_dynamic_payload_type)
    throw std::runtime_error("mbms: payload_type must be a dynamic payload type, 96 to 127");
  result.payload_type = static_cast<std::uint8_t>(payload_type);
  const auto video_payload_type = block.value("video_payload_type", unsigned{result.video_payload_type});
  if (video_payload_type < first_dynamic_payload_type || video_payload_type > last_dynamic_payload_type)
    throw std::runtime_error("mbms: video_payload_type must be a dynamic payload type, 96 to 127");
  result.video_payload_type = static_cast<std::uint8_t>(video_payload_type);
  result.octet_aligned = block.value("octet_aligned", result.octet_aligned);
  result.bearer_announcement_ms = block.value("bearer_announcement_ms", result.bearer_announcement_ms);
  result.mscck = block.value("mscck", false);
  result.musik = block.value("musik", false);
  result.all_users = !block.contains("users");
  const auto users = block.value("users", Json::array());
  if (!users.is_array()) throw std::runtime_error("mbms: users must be a list of MC service IDs");
  for (const auto &user : users) result.users.insert(user.get<std::string>());

  std::set<std::pair<std::string, std::uint16_t>> used;
  const auto take = [&](const std::string &bearer, const std::string &value) {
    auto target = host_group("mbms bearer " + bearer, value);
    if (!used.emplace(target.address, target.port).second)
      throw std::runtime_error("mbms: bearer " + bearer + ": " + value + " is used twice");
    return target;
  };
  const auto bearers = block.value("bearers", Json::array());
  if (!bearers.is_array() || bearers.empty()) throw std::runtime_error("mbms: bearers must be a non-empty list");
  for (const auto &entry : bearers) {
    if (!entry.is_object() || !entry.contains("tmgi") || !entry.contains("general_purpose"))
      throw std::runtime_error("mbms: a bearer needs tmgi and general_purpose");
    MbmsBearerConfig bearer;
    bearer.tmgi = tmgi("mbms bearer", entry.at("tmgi").get<std::string>());
    if (result.bearer(bearer.tmgi)) throw std::runtime_error("mbms: TMGI " + bearer.tmgi + " is used twice");
    bearer.general_purpose = take(bearer.tmgi, entry.at("general_purpose").get<std::string>());
    bearer.general_purpose.tmgi = bearer.tmgi;
    for (const auto &channel : entry.value("subchannels", Json::array())) {
      bearer.subchannels.push_back(take(bearer.tmgi, channel.get<std::string>()));
      bearer.subchannels.back().tmgi = bearer.tmgi;
    }
    for (const auto &area : entry.value("service_areas", Json::array()))
      bearer.service_areas.push_back(service_area(bearer.tmgi, area.get<std::string>()));
    if (bearer.service_areas.empty())
      throw std::runtime_error("mbms: bearer " + bearer.tmgi + " needs service_areas (TS 24.379 clause 14.2.2.2)");
    if (entry.contains("qci")) bearer.qci = entry.at("qci").get<int>();
    if (entry.contains("frequency")) bearer.frequency = entry.at("frequency").get<std::uint64_t>();
    if (entry.contains("report_suspension")) bearer.report_suspension = entry.at("report_suspension").get<bool>();
    result.bearers.push_back(std::move(bearer));
  }
  return result;
}

} // namespace mcx
