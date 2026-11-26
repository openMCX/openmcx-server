//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The affiliation of a user as other users see and change it (affiliation_subscriptions.hpp).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), RFC 6665.

#include "parts/affiliation_subscriptions.hpp"

#include <algorithm>
#include <cctype>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 annex F.4 (TS 24.281 annex F.4): the service's info MIME type with "-info+xml" replaced.
std::string affiliation_command_mime(const ServiceProfile &service) {
  std::string mime = service.info_mime;
  constexpr std::string_view info_suffix = "-info+xml";
  if (mime.ends_with(info_suffix)) mime.resize(mime.size() - info_suffix.size());
  return mime + "-affiliation-command+xml";
}

//------------------------------------------------------------------------------
// TS 24.484 tables 8.3.2.7-24 and 8.3.2.7-25.
bool may_determine_affiliation(const Json &profile) {
  return profile.is_object() &&
         (profile.value("request_affiliated_groups", false) || profile.value("affiliate_others", false));
}

//------------------------------------------------------------------------------
// TS 24.484 table 8.3.2.7-25.
bool may_request_affiliation(const Json &profile) {
  return profile.is_object() && profile.value("affiliate_others", false);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.4 steps 4 and 5.
int affiliation_subscribe_status(std::string_view served, std::string_view originating, bool authorised) {
  if (served.empty() || originating.empty()) return 403;
  if (served != originating && !authorised) return 403; // step 4
  return 200;                                           // step 5
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.1.1: the notifier may shorten the duration, not lengthen it.
std::optional<std::uint64_t> affiliation_subscription_expires(std::optional<std::string_view> header) {
  if (!header) return affiliation_subscription_max_s;
  auto value = *header;
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.remove_prefix(1);
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.remove_suffix(1);
  // RFC 3261 section 20.19: delta-seconds, at most 2^32-1 (ten digits).
  constexpr std::size_t max_digits = 10;
  constexpr std::uint64_t max_delta_seconds = 4294967295ull;
  if (value.empty() || value.size() > max_digits ||
      !std::all_of(value.begin(), value.end(), [](unsigned char character) { return std::isdigit(character); }))
    return std::nullopt;
  const std::uint64_t seconds = std::stoull(std::string(value));
  if (seconds > max_delta_seconds) return std::nullopt;
  return std::min(seconds, affiliation_subscription_max_s);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.2.2.8 to 9.2.2.2.10 (clause 9.2.2.2.10 NOTE 4: the choice of the header comment).
AffiliationRoute affiliation_route(bool served_here, std::string_view registered_by, std::string_view controller,
                                   std::string_view from_peer) {
  if (served_here) return {AffiliationRoute::Kind::served_here, {}};
  const auto next = !registered_by.empty() ? registered_by : controller;
  if (next.empty() || next == from_peer) return {AffiliationRoute::Kind::unknown, {}};
  return {AffiliationRoute::Kind::to_peer, std::string(next)};
}

//------------------------------------------------------------------------------
const AffiliationSubscriptions::Subscription *AffiliationSubscriptions::find(const std::string &dialog) const {
  const auto found = subscriptions_.find(dialog);
  return found == subscriptions_.end() ? nullptr : &found->second;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.4 step 5 and RFC 6665 section 4.2.1.2: a refresh keeps the served user and the subscriber.
void AffiliationSubscriptions::add(const std::string &dialog, const std::string &served, const std::string &subscriber,
                                   std::int64_t expires) {
  auto &subscription = subscriptions_[dialog];
  if (subscription.served.empty()) {
    subscription.served = served;
    subscription.subscriber = subscriber;
  }
  subscription.expires = expires;
}

//------------------------------------------------------------------------------
bool AffiliationSubscriptions::erase(const std::string &dialog) { return subscriptions_.erase(dialog) > 0; }

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.5.
std::vector<std::string> AffiliationSubscriptions::of_served(const std::string &served, std::int64_t now) const {
  std::vector<std::string> dialogs;
  for (const auto &[dialog, subscription] : subscriptions_)
    if (subscription.served == served && subscription.expires > now) dialogs.push_back(dialog);
  return dialogs;
}

//------------------------------------------------------------------------------
std::vector<std::string> AffiliationSubscriptions::of_subscriber(const std::string &subscriber) const {
  std::vector<std::string> dialogs;
  for (const auto &[dialog, subscription] : subscriptions_)
    if (subscription.subscriber == subscriber) dialogs.push_back(dialog);
  return dialogs;
}

//------------------------------------------------------------------------------
bool AffiliationSubscriptions::own_live(const std::string &served, std::int64_t now) const {
  return std::any_of(subscriptions_.begin(), subscriptions_.end(), [&](const auto &entry) {
    return entry.second.served == served && entry.second.subscriber == served && entry.second.expires > now;
  });
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.2.
std::vector<std::string> AffiliationSubscriptions::expired(std::int64_t now) const {
  std::vector<std::string> dialogs;
  for (const auto &[dialog, subscription] : subscriptions_)
    if (subscription.expires <= now) dialogs.push_back(dialog);
  return dialogs;
}

} // namespace mcx
