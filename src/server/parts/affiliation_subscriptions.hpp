//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The affiliation of a user as other users see and change it, for the MCPTT and MCVideo servers (McServer): the
// subscriptions to a served user's affiliation status (TS 24.379 clauses 9.2.2.2.4 and 9.2.2.2.5, TS 24.281 clauses
// 8.2.2.2.4 and 8.2.2.2.5), several per user, each in its own dialog (RFC 6665 section 4.2: the user's own clients'
// and those of the users authorised to determine its affiliation), and the decisions of the affiliation status change
// request in negotiated mode (TS 24.379 clauses 9.2.1.4, 9.2.2.2.8; TS 24.281 clauses 8.2.1.4, 8.2.2.2.8) and of the
// forwarding of a subscription towards another user's server (TS 24.379 clause 9.2.2.2.10, TS 24.281 clause
// 8.2.2.2.10), kept apart from the SIP engine so that they can be tested on their own.
//
// Where the specification leaves a point open, this coding takes:
//   - the authorisation of clause 9.2.2.2.4 step 4 ("authorized to modify affiliation status of the served MCPTT
//     ID") is the subscriber's <allow-request-affiliated-groups> (TS 24.484 table 8.3.2.7-24: the list of the groups
//     a specified user is affiliated to) or <allow-request-to-affiliate-other-users> (table 8.3.2.7-25);
//   - the authorisation of clause 9.2.2.2.8 step 3 is the requester's <allow-request-to-affiliate-other-users>;
//   - a subscription is granted the Expires it asks for, at most 3600 s, and 3600 s without Expires (RFC 6665 section
//     4.2.1.1 lets the notifier shorten it; the event package names no default);
//   - TS 24.379 does not say how the originating participating function finds the terminating one of another user
//     (clause 9.2.2.2.10 NOTE 4): the server that registered the user with this one (peer registration), else the
//     controlling server of a participating-only server, which knows every participating server's users.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), RFC 6665.
#pragma once

#include "mcx/runtime.hpp"
#include "mcx/service.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

// Local choice (see the header comment): the longest affiliation status subscription, and the one without Expires.
inline constexpr std::uint64_t affiliation_subscription_max_s = 3600;

//------------------------------------------------------------------------------
// TS 24.379 annex F.4 (TS 24.281 annex F.4): the MIME type of the (de-)affiliation request of negotiated mode,
// application/vnd.3gpp.<service>-affiliation-command+xml.
std::string affiliation_command_mime(const ServiceProfile &service);

//------------------------------------------------------------------------------
// TS 24.484 tables 8.3.2.7-24 and 8.3.2.7-25 (MCVideo: clause 9.3.2.7): whether a user profile (the servers' JSON
// form: "request_affiliated_groups", "affiliate_others") authorises the user to determine another user's affiliation
// status (TS 24.379 clause 9.2.2.2.4 step 4); and to send it an affiliation status change request in negotiated mode
// (clause 9.2.2.2.8 step 3).
bool may_determine_affiliation(const Json &profile);
bool may_request_affiliation(const Json &profile);

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.4 steps 1 to 5 (TS 24.281 clause 8.2.2.2.4): the answer to a SUBSCRIBE for the
// affiliation status of the served MC service ID (step 1) from the originating one (steps 2 and 3): 200 for the
// user's own, or for an originating user that `authorised` (step 4), else 403.
int affiliation_subscribe_status(std::string_view served, std::string_view originating, bool authorised);

//------------------------------------------------------------------------------
// RFC 6665 sections 4.1.2.1 and 4.2.1.1 with RFC 3261 section 20.19: the duration granted to a SUBSCRIBE for the
// affiliation status: the Expires asked for, at most affiliation_subscription_max_s; that value without Expires; 0 for
// a fetch or the end of the subscription; none for an Expires that is not delta-seconds (400).
std::optional<std::uint64_t> affiliation_subscription_expires(std::optional<std::string_view> header);

//------------------------------------------------------------------------------
// Where a request about another user's affiliation goes (TS 24.379 clauses 9.2.2.2.8 to 9.2.2.2.10):
//   served_here: the target is served by this server (the terminating participating function, clause 9.2.2.2.8 or
//     9.2.2.2.4);
//   to_peer: to the terminating participating function on `peer` (clauses 9.2.2.2.9 and 9.2.2.2.10);
//   unknown: no server known to serve the target (404).
struct AffiliationRoute {
  enum class Kind { served_here, to_peer, unknown } kind = Kind::unknown;
  std::string peer;
};

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.2.2.8 to 9.2.2.2.10: the route of a request about the target: served here when `served_here`;
// else to the peer that registered the target with this server (`registered_by`), else to `controller` (the
// controlling server of a participating-only server, empty for none); never back to the peer the request came from
// (`from_peer`, empty for a served user's request), which would loop.
AffiliationRoute affiliation_route(bool served_here, std::string_view registered_by, std::string_view controller,
                                   std::string_view from_peer);

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.2.2.4 and 9.2.2.2.5 (TS 24.281 clauses 8.2.2.2.4 and 8.2.2.2.5) with RFC 6665 section 4.2: the
// subscriptions to the affiliation status of the users served here, by dialog: the served MC service ID, the
// subscriber (the originating MC service ID) and the end of the subscription (POSIX time). A user has as many as are
// made: its own clients', and those of the users authorised to determine its affiliation; none replaces another.
class AffiliationSubscriptions {
public:
  struct Subscription {
    std::string served, subscriber;
    std::int64_t expires = 0;
  };

  [[nodiscard]] const Subscription *find(const std::string &dialog) const;

  [[nodiscard]] std::size_t size() const { return subscriptions_.size(); }

  // Clause 9.2.2.2.4 step 5: a subscription is created; or (RFC 6665 section 4.2.1.2) refreshed in its dialog.
  void add(const std::string &dialog, const std::string &served, const std::string &subscriber, std::int64_t expires);
  // RFC 6665 section 4.2.1.2: the subscription ends in its dialog (Expires 0), or it expired.
  bool erase(const std::string &dialog);

  // Clause 9.2.2.2.5: the dialogs of the subscriptions to the user's affiliation status that last at `now`.
  [[nodiscard]] std::vector<std::string> of_served(const std::string &served, std::int64_t now) const;
  // RFC 6665 section 4.2.2: the dialogs held by a subscriber (their end when its service authorisation ends).
  [[nodiscard]] std::vector<std::string> of_subscriber(const std::string &subscriber) const;
  // Whether one of the user's own subscriptions (subscriber the user itself) lasts at `now`.
  [[nodiscard]] bool own_live(const std::string &served, std::int64_t now) const;
  // RFC 6665 section 4.2.2: the dialogs of the subscriptions whose duration is over at `now`.
  [[nodiscard]] std::vector<std::string> expired(std::int64_t now) const;

private:
  std::map<std::string, Subscription> subscriptions_;
};

} // namespace mcx
