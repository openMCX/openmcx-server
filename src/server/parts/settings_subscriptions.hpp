//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The subscription to and notification of the service settings (TS 24.379 clause 7.3.6, TS 24.281 clause 7.3.6,
// TS 24.282 clause 7.3.6), shared by the MCPTT and MCVideo servers (McServer) and the MCData server (DataServer):
// the checks of clause 7.3.6.1, the application/poc-settings+xml body of clause 7.3.6.2 from the settings cached by
// the PUBLISH of clauses 7.3.3 and 7.3.4, the Expires rule of RFC 6665, and the bookkeeping of the subscriptions
// (by dialog: the subscribed user, the end of the subscription and the last body sent), kept apart from the SIP
// engine so that it can be tested on its own.
//
// Where the specification leaves a point open, this coding takes:
//   - the subscriber gets the Expires it asks for (TS 24.379 clause 7.2.4 steps 6 and 7: 4294967295 or 0; RFC 6665
//     section 4.2.1.1 lets the notifier shorten it, which is not done); a SUBSCRIBE without Expires gets 3600 s (RFC
//     6665 section 4.1.2.1 leaves the default to the event package, RFC 4354 names none: a local choice, as the
//     affiliation status subscription's);
//   - the body names the one client bound to the MC service ID (one binding per MC service ID, clause 7.3.3 steps 3a
//     and 3b); a client that has not published settings, or whose publication has expired, is an <entity> with its
//     "id" only (RFC 4354 section 5.1: every setting is optional).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 4354,
// RFC 6665.
#pragma once

#include "parts/served_users.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mcx {

// RFC 4354 section 4: the event package of the subscription.
inline constexpr std::string_view poc_settings_event = "poc-settings";
inline constexpr std::string_view poc_settings_mime = "application/poc-settings+xml";

// TS 24.379 clause 7.2.4 step 6 (NOTE 1): the longest Expires, 2^32-1 (RFC 3261 section 20.19).
inline constexpr std::uint64_t settings_max_expires_s = 4294967295ull;
// Local choice (see the header comment): the duration of a subscription whose SUBSCRIBE has no Expires.
inline constexpr std::uint64_t settings_default_expires_s = 3600;
// Local choice: how often the subscriptions are checked for their expiry and for a change of the settings.
inline constexpr std::uint64_t settings_check_interval_ms = 1000;

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.1 steps 1 to 4 (TS 24.281 and TS 24.282 clause 7.3.6.1 likewise): the answer to an initial
// SUBSCRIBE whose service information names the served MC service ID (`served`, step 1; empty when the request has
// none: condition 2 fails) from the originating MC service ID (`originating`, from P-Asserted-Identity, step 2):
// 403 when they differ (step 3) or nothing is named, else 200 (step 4).
int settings_subscribe_status(std::string_view served, std::string_view originating);

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2.1 with RFC 3261 section 20.19: the duration a SUBSCRIBE for poc-settings asks for, in
// seconds (0: fetch the state, or end the subscription in its dialog); absent, the default of the header comment;
// none for an Expires that is not delta-seconds of at most 2^32-1 (400, RFC 3261 section 21.4.1).
std::optional<std::uint64_t> settings_expires(std::optional<std::string_view> header);

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.2 step 1 (TS 24.281 clause 7.3.6.2 step 1): the application/poc-settings+xml of the user's
// client: a) <am-settings>, its current answer mode (the RFC 5373 value cached by clause 7.3.4 step 10, as an RFC
// 4354 <answer-mode>), b) <selected-user-profile-index>, the active user profile (clause 7.3.4 step 11), while the
// settings last. With `answer_mode` false only b) (TS 24.282 clause 7.3.6.2 step 1: MCData has no answer mode).
std::string service_settings_notification(const ServedUser &user, std::int64_t now, bool answer_mode = true);

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6 (TS 24.281 and TS 24.282 likewise) with RFC 6665 section 4.2: the subscriptions to the
// service settings, by dialog: the subscribed MC service ID, the end of the subscription (POSIX time) and the last
// body sent, so that a NOTIFY goes out on every change of the settings and only then.
class SettingsSubscriptions {
public:
  struct Subscription {
    std::string user;
    std::int64_t expires = 0;
    std::string last_body;
  };

  [[nodiscard]] bool contains(const std::string &dialog) const { return subscriptions_.contains(dialog); }

  [[nodiscard]] const Subscription *find(const std::string &dialog) const;

  [[nodiscard]] std::size_t size() const { return subscriptions_.size(); }

  // Clause 7.3.6.1 step 4: a subscription is created; or (RFC 6665 section 4.2.1.2) refreshed in its dialog, which
  // keeps its last body.
  void add(const std::string &dialog, const std::string &user, std::int64_t expires);
  // RFC 6665 section 4.2.1.2: the subscription ends in its dialog (Expires 0), or it expired, or its user is gone.
  bool erase(const std::string &dialog);

  // RFC 6665 section 4.2.2: the dialogs of the subscriptions to a user's settings (their end when its service
  // authorisation ends, TS 24.379 clause 7.3.5).
  [[nodiscard]] std::vector<std::string> of_user(const std::string &user) const;
  // RFC 6665 section 4.2.2: the dialogs of the subscriptions whose duration is over at `now`.
  [[nodiscard]] std::vector<std::string> expired(std::int64_t now) const;

  // Clause 7.3.6.2: the body of the subscription now, recorded as sent; for the NOTIFY that an accepted or refreshed
  // SUBSCRIBE always gets (RFC 6665 section 4.2.1.2).
  template <typename BodyOf> std::string current(const std::string &dialog, BodyOf &&body_of) {
    auto &subscription = subscriptions_.at(dialog);
    subscription.last_body = body_of(subscription);
    return subscription.last_body;
  }

  // Clause 7.3.6.2: each subscription whose body differs from the last one sent, with the new body (recorded as
  // sent); the others are left alone.
  template <typename BodyOf> std::vector<std::pair<std::string, std::string>> changed(BodyOf &&body_of) {
    std::vector<std::pair<std::string, std::string>> out;
    for (auto &[dialog, subscription] : subscriptions_) {
      auto body = body_of(subscription);
      if (body == subscription.last_body) continue;
      subscription.last_body = body;
      out.emplace_back(dialog, std::move(body));
    }
    return out;
  }

private:
  std::map<std::string, Subscription> subscriptions_;
};

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2.3: the Subscription-State of an active subscription with `remaining` seconds left.
std::string settings_active_state(std::int64_t remaining);

} // namespace mcx
