//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Peer registration: a participating function reports each served user's service authorization and group
// affiliations to the controlling servers of its system, and a controlling function takes the users served by its
// peers (TS 24.379 clauses 9.2.2.2.6 and 9.2.2.3.3, TS 24.281 likewise, over MCPTT-3 of TS 23.379 clause 7.5.2.4).
// Used by the MCPTT and MCVideo servers (McServer); the server is its PeerRegistrationHost, called per request.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19), RFC 3903.
#pragma once

#include "mcx/protocol.hpp"
#include "mcx/runtime.hpp"
#include "mcx/service.hpp"
#include "mcx/sip.hpp"
#include "parts/peers.hpp"
#include "parts/service_host.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>

namespace mcx {
//------------------------------------------------------------------------------
// A user as peer registration sees it: its MC service ID, client ID, public user identity, serving peer (empty for a
// user served here), the end of its service authorization, its affiliated groups and whether those affiliations are
// current (while the user's affiliation subscription lasts).
struct PeerUser {
  std::string id, client, sip, peer;
  std::int64_t expires = 0;
  std::set<std::string> groups;
  bool affiliations_current = true;
};

//------------------------------------------------------------------------------
// What peer registration needs from its server besides ServiceHost, called per request.
class PeerRegistrationHost : public virtual ServiceHost {
public:
  // The configured peers.
  [[nodiscard]] virtual const PeerMap &peer_table() const = 0;
  // The peer controlling a group's calls or communications, empty for this server.
  virtual std::string registration_group_controller(const std::string &group) = 0;
  // How often the registrations are repeated (<service>.registration_refresh_ms; 0: never).
  [[nodiscard]] virtual std::uint64_t registration_refresh_ms() const = 0;
  // Every user the server knows.
  virtual void each_registration_user(const std::function<void(const PeerUser &)> &visit) = 0;
  // The server's own checks of a received registration (role, PIDF, its namespace, Expires): the refusal status, or
  // nothing with the affiliation and Expires read.
  virtual std::optional<int> registration_refusal(const SipMessage &message, Affiliation &affiliation,
                                                  std::uint64_t &expires_s) = 0;
  // The user with the public user identity, or with the MC service ID (as the server finds them).
  virtual std::optional<PeerUser> registration_user(const std::string &sip) = 0;
  virtual std::optional<PeerUser> registration_user_by_id(const std::string &id) = 0;
  // Whether a peer may register the user's affiliation to the group (controlled here, the user a member).
  virtual bool registration_group_allowed(const std::string &group, const std::string &id, const std::string &peer) = 0;
  // A peer withdraws its user (Expires 0).
  virtual void withdraw_peer_user(const std::string &sip, const std::string &id) = 0;
  // A peer registers its user: the user's entry is set (its groups as the server keeps them).
  virtual void update_peer_user(const std::string &sip, const Affiliation &affiliation, const std::string &peer,
                                const std::set<std::string> &groups, std::uint64_t expires_s) = 0;
  // A registration that changed the user: the server applies the affiliations (previous: the entry before).
  virtual void peer_user_changed(const std::string &sip, const std::optional<PeerUser> &previous,
                                 std::set<std::string> groups) = 0;
};

//------------------------------------------------------------------------------
// The peer registration procedures, both sides.
class PeerRegistration {
public:
  PeerRegistration(PeerRegistrationHost &host, const ServiceProfile &service);

  // TS 24.379 clause 9.2.2.2.6: a served user's registration with the controlling servers (withdraw: Expires 0;
  // refresh: a periodic repetition).
  void publish(const PeerUser &user, bool withdraw = false, bool refresh = false);
  // The periodic repetition, so that a restarted peer learns the users again.
  void refresh(std::uint64_t now);
  // TS 24.379 clause 9.2.2.3.3: a peer's registration of one of its users.
  SipResponse receive(const SipMessage &message, const std::string &peer);

private:
  [[nodiscard]] std::string event_name(std::string_view suffix) const;
  void publish_to(const PeerUser &user, const std::string &name, const ServicePeer &peer, bool active, bool refresh);
  static bool changes(const std::optional<PeerUser> &previous, const Affiliation &affiliation, const std::string &peer,
                      const std::set<std::string> &groups);

  PeerRegistrationHost &host_;
  const ServiceProfile &service_;
  std::uint64_t last_refresh_ = 0;
};
} // namespace mcx
