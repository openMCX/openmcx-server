//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The configuration of the IP multicast delivery of MCPTT group call speech (an OpenMCX profile,
// include/mcx/multicast.hpp).
//
// Specifications: RFC 1112, TS 24.379 V19.7.0 (Rel-19).

#include "mcx/multicast.hpp"

#include <limits>
#include <stdexcept>

namespace mcx {

//------------------------------------------------------------------------------
// RFC 3551 section 3: the dynamic RTP payload types.
inline constexpr unsigned first_dynamic_payload_type = 96, last_dynamic_payload_type = 127;

//------------------------------------------------------------------------------
// Helper: the host group of a group URI, or none.
const MulticastDestination *MulticastConfig::group(const std::string &uri) const {
  const auto found = groups.find(uri);
  return found == groups.end() ? nullptr : &found->second;
}

//------------------------------------------------------------------------------
// Helper: "<IPv4 host group>:<port>" of a group.
static MulticastDestination destination(const std::string &group, const std::string &value) {
  const auto colon = value.rfind(':');
  if (colon == std::string::npos) throw std::runtime_error("multicast: group " + group + " needs <address>:<port>");
  MulticastDestination result{value.substr(0, colon), 0};
  if (!is_ipv4_multicast(result.address))
    throw std::runtime_error("multicast: group " + group + ": not an IPv4 host group address: " + result.address);
  const auto port = value.substr(colon + 1);
  constexpr auto max_port = std::numeric_limits<std::uint16_t>::max();
  constexpr std::size_t max_port_digits = 5;
  if (port.empty() || port.size() > max_port_digits || port.find_first_not_of("0123456789") != std::string::npos ||
      std::stoul(port) == 0 || std::stoul(port) > max_port)
    throw std::runtime_error("multicast: group " + group + ": port must be 1 to 65535");
  result.port = static_cast<std::uint16_t>(std::stoul(port));
  return result;
}

//------------------------------------------------------------------------------
// Helper: reads and checks a "multicast" block.
MulticastConfig multicast_config(const Json &block) {
  if (!block.is_object()) throw std::runtime_error("multicast: the block must be an object");
  MulticastConfig result;
  result.interface = block.value("interface", result.interface);
  result.ttl = block.value("ttl", result.ttl);
  if (result.ttl < 1 || result.ttl > max_multicast_ttl) throw std::runtime_error("multicast: ttl must be 1 to 255");
  const auto payload_type = block.value("payload_type", unsigned{result.payload_type});
  if (payload_type < first_dynamic_payload_type || payload_type > last_dynamic_payload_type)
    throw std::runtime_error("multicast: payload_type must be a dynamic payload type, 96 to 127");
  result.payload_type = static_cast<std::uint8_t>(payload_type);
  result.octet_aligned = block.value("octet_aligned", result.octet_aligned);
  const auto users = block.value("users", Json::array());
  if (!users.is_array()) throw std::runtime_error("multicast: users must be a list of MCPTT IDs");
  for (const auto &user : users) result.users.insert(user.get<std::string>());

  std::set<std::pair<std::string, std::uint16_t>> used;
  const auto groups = block.value("groups", Json::object());
  if (!groups.is_object()) throw std::runtime_error("multicast: groups must map group URIs to host groups");
  for (const auto &[group, value] : groups.items()) {
    auto target = destination(group, value.get<std::string>());
    if (!used.emplace(target.address, target.port).second)
      throw std::runtime_error("multicast: group " + group + " shares its address and port with another group");
    result.groups.emplace(group, std::move(target));
  }
  if (result.groups.empty()) throw std::runtime_error("multicast: no groups configured");
  return result;
}

} // namespace mcx
