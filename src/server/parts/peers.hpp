// The peers of an MC server: the other participating and controlling servers of its own MC system (TS 23.379 clause
// 7.5.2.4 over MCPTT-3), from the configuration: their addresses, route, PSI and the Signalling Protection Key shared
// with them (TS 33.180 clause 5.5). Used by the MCPTT and MCVideo servers (McServer), which can run as a split of a
// participating and a controlling function.
//
// Specifications: TS 23.379 V19.11.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 3261.
#pragma once

#include "mcx/keying.hpp"
#include "mcx/protected_call.hpp"
#include "mcx/runtime.hpp"
#include "mcx/sip.hpp"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// A configured peer. Every configured peer is trusted: its requests are accepted by source address.
struct ServicePeer {
  // host: its SIP host; route: the Route towards it; service_uri: its PSI. media_host: its media address when it
  // differs from its SIP host (a server on several networks).
  std::string host, media_host, route, service_uri;
  // A controlling server of this system.
  bool controlling = false;
  // TS 33.180 clauses 5.5 and 9.4.5: the SPK as the KFC of the floor and media control between the two servers.
  std::shared_ptr<ProtectedCall> spk;
  // TS 33.180 clauses 5.5 and 11.1.3: the SPK of the signalling bodies and XML exchanged with the peer (the XPK).
  std::optional<keying::KeyMessage> spk_key;
};

using PeerMap = std::map<std::string, ServicePeer>;

//------------------------------------------------------------------------------
// TS 33.180 clause 5.5: an SPK provisioned in the configuration ({"id", "key", "rand"}, hex), with purpose tag 3 in
// its SPK-ID; it is active from now with no expiry of its own, named after the peer.
keying::KeyMessage configured_spk(const Json &spk, const std::string &name);

//------------------------------------------------------------------------------
// A peer from the configuration's "servers" entry.
ServicePeer configured_peer(const std::string &name, const Json &entry, bool disable_tls);

//------------------------------------------------------------------------------
// Helper: the IPv4 address a host name resolves to, or empty when it does not resolve.
std::string address_of(const std::string &host);

//------------------------------------------------------------------------------
// Helper: the configured peer whose SIP host or media host has the address; empty for none.
std::string peer_at(const PeerMap &peers, const std::string &address);

//------------------------------------------------------------------------------
// Helper: whether a media description came from the peer's media address.
bool peer_media(const ServicePeer &peer, const std::string &address);

//------------------------------------------------------------------------------
// RFC 3261 section 8.1.2: the header fields with a loose Route towards the peer added.
std::vector<SipHeader> peer_route(const PeerMap &peers, const std::string &peer, std::vector<SipHeader> headers);
} // namespace mcx
