//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The peers of an MC server from the configuration (peers.hpp).
//
// Specifications: TS 23.379 V19.11.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 3261.

#include "parts/peers.hpp"

#include <array>
#include <ctime>
#include <stdexcept>

namespace mcx {

// TS 33.180 clause 5.5: the purpose tag of an SPK-ID (its four most significant bits).
static constexpr std::uint32_t spk_purpose_tag = 3;
// TS 33.180 table E.6.11-1: the key type of an SPK.
static constexpr std::uint8_t spk_key_type = 3;
// The validity of a directly provisioned SPK, which has no expiry of its own (a local choice): ten years.
static constexpr std::uint64_t provisioned_spk_validity_s = 10ULL * 365 * 86400;

//------------------------------------------------------------------------------
// Helper: 128 bits from 32 hexadecimal digits.
static std::array<std::uint8_t, 16> key_bytes(const std::string &hex, const char *error) {
  std::array<std::uint8_t, 16> out{};
  if (hex.size() != 2 * out.size()) throw std::runtime_error(error);
  for (std::size_t index = 0; index < out.size(); ++index)
    out[index] = static_cast<std::uint8_t>(std::stoul(hex.substr(2 * index, 2), nullptr, 16));
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.5: an SPK provisioned in the configuration.
keying::KeyMessage configured_spk(const Json &spk, const std::string &name) {
  keying::KeyMessage key;
  key.csb_id = spk.at("id").get<std::uint32_t>();
  if (key.csb_id >> 28 != spk_purpose_tag) throw std::runtime_error("an SPK-ID has purpose tag 3");
  key.key = key_bytes(spk.at("key").get<std::string>(), "an SPK and its RAND are 128 bits");
  const auto random = key_bytes(spk.at("rand").get<std::string>(), "an SPK and its RAND are 128 bits");
  key.random.assign(random.begin(), random.end());
  // Provisioned directly (TS 33.180 clause 5.5): active from now, with no expiry of its own.
  const auto now = static_cast<std::uint64_t>(std::time(nullptr));
  key.properties = keying::KeyProperties{spk_key_type, 1, now - 1, now + provisioned_spk_validity_s, "SPK " + name, {}};
  return key;
}

//------------------------------------------------------------------------------
// Helper: the SPK of a peer: it also keys floor control between the servers.
static void peer_keys(ServicePeer &peer, const std::string &name, const Json &entry) {
  if (!entry.contains("spk")) return;
  const auto key = configured_spk(entry.at("spk"), name);
  peer.spk = std::make_shared<ProtectedCall>();
  peer.spk->set_floor(key);
  peer.spk_key = key;
}

//------------------------------------------------------------------------------
// TS 23.379 clause 7.5.2.4 (MCPTT-3): a peer from the configuration: its hosts, route and PSI, its SPK (TS 33.180
// clause 5.5) and its controlling role.
ServicePeer configured_peer(const std::string &name, const Json &entry, bool disable_tls) {
  ServicePeer peer;
  peer.host = entry.at("host");
  peer.media_host = entry.value("media_host", peer.host);
  const auto port = std::to_string(disable_tls ? entry.value("debug_port", 5060U) : entry.value("port", 5061U));
  peer.route = "sip:" + peer.host + ":" + port + (disable_tls ? ";transport=tcp" : ";transport=tls");
  peer.service_uri = entry.at("service_uri");
  peer_keys(peer, name, entry);
  peer.controlling = entry.value("controlling", false);
  return peer;
}

//------------------------------------------------------------------------------
// Helper: the IPv4 address a host name resolves to, or empty when it does not resolve.
std::string address_of(const std::string &host) {
  if (host.empty()) return {};
  try {
    return resolve_ipv4(host);
  } catch (const std::exception &) {
    return {};
  }
}

//------------------------------------------------------------------------------
// Helper: whether a host is the address (an unresolved host is not, unless the address is empty too).
static bool host_is(const std::string &host, const std::string &address) {
  const auto resolved = address_of(host);
  return resolved.empty() ? address.empty() : resolved == address;
}

//------------------------------------------------------------------------------
// Helper: the configured peer whose SIP host or media host has the address.
std::string peer_at(const PeerMap &peers, const std::string &address) {
  for (const auto &[name, peer] : peers)
    if (host_is(peer.host, address) || host_is(peer.media_host, address)) return name;
  return {};
}

//------------------------------------------------------------------------------
// Helper: whether a media description came from the peer's media address.
bool peer_media(const ServicePeer &peer, const std::string &address) { return address_of(peer.media_host) == address; }

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.2: a loose Route towards the peer.
std::vector<SipHeader> peer_route(const PeerMap &peers, const std::string &peer, std::vector<SipHeader> headers) {
  headers.push_back({"Route", "<" + peers.at(peer).route + ";lr>"});
  return headers;
}

} // namespace mcx
