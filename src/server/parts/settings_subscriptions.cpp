//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The subscription to and notification of the service settings (settings_subscriptions.hpp).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 4354,
// RFC 6665.

#include "parts/settings_subscriptions.hpp"

#include <algorithm>
#include <cctype>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.1 steps 3 and 4.
int settings_subscribe_status(std::string_view served, std::string_view originating) {
  if (served.empty() || originating.empty() || served != originating) return 403; // step 3 (or condition 2)
  return 200;                                                                     // step 4
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2.1 with RFC 3261 section 20.19 (delta-seconds, at most 2^32-1).
std::optional<std::uint64_t> settings_expires(std::optional<std::string_view> header) {
  if (!header) return settings_default_expires_s;
  auto value = *header;
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.remove_prefix(1);
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.remove_suffix(1);
  // The digits of 4294967295 at most.
  constexpr std::size_t max_digits = 10;
  if (value.empty() || value.size() > max_digits ||
      !std::all_of(value.begin(), value.end(), [](unsigned char character) { return std::isdigit(character); }))
    return std::nullopt;
  const auto seconds = std::stoull(std::string(value));
  if (seconds > settings_max_expires_s) return std::nullopt;
  return seconds;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.2 step 1 a) and b) (TS 24.282 clause 7.3.6.2 step 1 a) only the profile index): the cached
// RFC 5373 "Auto" or "Manual" (clause 7.3.4 step 10) is RFC 4354's "automatic" or "manual".
std::string service_settings_notification(const ServedUser &user, std::int64_t now, bool answer_mode) {
  PocSettingsEntity entity;
  entity.id = user.client;
  if (user.settings && user.settings->expires > now) {
    if (answer_mode && user.settings->answer_mode == "Auto") entity.answer_mode = "automatic";
    if (answer_mode && user.settings->answer_mode == "Manual") entity.answer_mode = "manual";
    entity.profile_index = user.settings->profile_index;
  }
  return poc_settings_xml(std::vector<PocSettingsEntity>{entity});
}

//------------------------------------------------------------------------------
const SettingsSubscriptions::Subscription *SettingsSubscriptions::find(const std::string &dialog) const {
  const auto found = subscriptions_.find(dialog);
  return found == subscriptions_.end() ? nullptr : &found->second;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.1 step 4, RFC 6665 section 4.2.1.2: a refresh keeps the last body sent.
void SettingsSubscriptions::add(const std::string &dialog, const std::string &user, std::int64_t expires) {
  auto &subscription = subscriptions_[dialog];
  subscription.user = user;
  subscription.expires = expires;
}

//------------------------------------------------------------------------------
bool SettingsSubscriptions::erase(const std::string &dialog) { return subscriptions_.erase(dialog) > 0; }

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.2: the subscriptions to the user's settings.
std::vector<std::string> SettingsSubscriptions::of_user(const std::string &user) const {
  std::vector<std::string> out;
  for (const auto &[dialog, subscription] : subscriptions_)
    if (subscription.user == user) out.push_back(dialog);
  return out;
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.2: the subscriptions whose duration is over.
std::vector<std::string> SettingsSubscriptions::expired(std::int64_t now) const {
  std::vector<std::string> out;
  for (const auto &[dialog, subscription] : subscriptions_)
    if (subscription.expires <= now) out.push_back(dialog);
  return out;
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2.3: "active" with the remaining duration in "expires".
std::string settings_active_state(std::int64_t remaining) {
  return "active;expires=" + std::to_string(std::max<std::int64_t>(remaining, 0));
}

} // namespace mcx
