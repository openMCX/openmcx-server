//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Subscription to and notification of the MCData service settings (members of DataServer): the participating MCData
// function accepts a client's subscription to the settings of its own MCData ID (TS 24.282 clause 7.3.6.1) and
// notifies the active user profile its client published (clause 7.3.4) at once and on every change (clause
// 7.3.6.2), until the subscription is ended (Expires 0), expires, or the user's service authorisation ends. The rules
// and the bookkeeping are those of the MCPTT and MCVideo servers (parts/settings_subscriptions.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), RFC 4354, RFC 6665.

#include "data_server.hpp"

namespace mcx {

namespace {
//------------------------------------------------------------------------------
// Helper: the Expires header field, none when absent.
std::optional<std::string_view> expires_header(const SipMessage &message) {
  const auto value = get_header(message.headers, "Expires");
  return value.empty() ? std::nullopt : std::optional(value);
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.6.1 for a SUBSCRIBE with Event "poc-settings" (condition 4) from a service authorised user
// (`user`, its asserted identity; the request opened with its CSK on receipt, clause 7.3.1A): condition 2 and step 1,
// the served MCData ID in <mcdata-request-uri>; condition 3, the MCData ICSI in P-Asserted-Service (a different one is
// refused, none is taken as the SIP core's omission); step 2, the originating MCData ID; step 3, 403 when they differ;
// step 4, 200 by RFC 6665 with the NOTIFY of clause 7.3.6.2. With Expires 0 that NOTIFY ends it (a fetch, clause
// 7.2.4). In the dialog of a subscription: a refresh, or with Expires 0 its end (RFC 6665 section 4.2.1.2).
SipResponse DataServer::settings_subscribe(const SipMessage &request, const User &user) {
  SipResponse response;
  const auto expires = settings_expires(expires_header(request));
  if (const auto *held = settings_subscriptions_.find(request.dialog_id)) {
    if (held->user != user.id) return reject(403, "", user.id, "settings-subscription");
  } else {
    const auto *info_part = part(request, mcdata::info_mime);
    if (info_part && xmlsec::is_protected(info_part->body)) {
      ++xml_refused_;
      return reject(403, "140 unable to decrypt XML content", user.id, "settings-subscription");
    }
    const auto served = info_part ? mcdata::parse_info(info_part->body).request_uri : std::string{}; // step 1
    if (const auto service = get_header(request.headers, "P-Asserted-Service");
        !service.empty() && service.find(mcdata::icsi) == std::string_view::npos)
      return reject(403, "", user.id, "settings-subscription");
    if (settings_subscribe_status(served, user.id) != 200) // steps 2 and 3
      return reject(403, "", user.id, "settings-subscription");
  }
  if (!expires) return reject(400, "", user.id, "settings-subscription");

  // Step 4 (or the refresh).
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(*expires)}};
  const bool initial = !settings_subscriptions_.contains(request.dialog_id);
  if (*expires == 0 && initial) {
    pending_.push_back([this, dialog = request.dialog_id, id = user.id] {
      notify_settings(dialog, settings_body({id, 0, {}}), "terminated;reason=timeout");
    });
    return response;
  }
  if (*expires) settings_subscriptions_.add(request.dialog_id, user.id, std::time(nullptr) + std::int64_t(*expires));
  event(*expires == 0 ? "mcdata_settings_unsubscribed" : "mcdata_settings_subscribed", {{"user_id", user.id}});
  pending_.push_back([this, dialog = request.dialog_id, end = *expires == 0] {
    const auto *held = settings_subscriptions_.find(dialog);
    if (!held) return;
    const auto remaining = held->expires - std::time(nullptr);
    const auto body = settings_subscriptions_.current(dialog, [this](const auto &each) { return settings_body(each); });
    if (end) settings_subscriptions_.erase(dialog);
    notify_settings(dialog, body, end ? "terminated;reason=timeout" : settings_active_state(remaining));
  });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.6.2 step 1: the <selected-user-profile-index> of the subscribed user's client (no answer mode);
// a user no longer served is its subscription's last body.
std::string DataServer::settings_body(const SettingsSubscriptions::Subscription &subscription) const {
  for (const auto &[sip, user] : users_)
    if (user.id == subscription.user) return service_settings_notification(user, std::time(nullptr), false);
  return subscription.last_body.empty() ? poc_settings_xml(std::vector<PocSettingsEntity>{}) : subscription.last_body;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.6.2 step 2: the NOTIFY with the application/poc-settings+xml body. RFC 6665 section 4.2.2: a
// failure response to it ends the subscription.
void DataServer::notify_settings(const std::string &dialog, const std::string &body, const std::string &state) {
  sip_.notify(dialog, poc_settings_event, state, poc_settings_mime, body, {},
              [this, dialog](const SipResponse &answer) {
                if (answer.status_code < 300) return;
                pending_.push_back([this, dialog] { settings_subscriptions_.erase(dialog); });
              });
}

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.6.2: a NOTIFY to each subscription whose settings changed (a PUBLISH of clause 7.3.4, or their
// expiry).
void DataServer::settings_changed() {
  const auto now = std::time(nullptr);
  for (const auto &[dialog, body] :
       settings_subscriptions_.changed([this](const auto &held) { return settings_body(held); }))
    if (const auto *subscription = settings_subscriptions_.find(dialog))
      notify_settings(dialog, body, settings_active_state(subscription->expires - now));
}

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.5 steps 3 and 4 and clause 7.3.3 step 8 with RFC 6665 section 4.2.2: the subscriptions to the
// settings of a user whose service authorisation ends end with a final NOTIFY, reason "noresource".
void DataServer::end_settings_subscriptions(const std::string &user, const char *reason) {
  for (const auto &dialog : settings_subscriptions_.of_user(user)) {
    const auto body = settings_subscriptions_.current(dialog, [this](const auto &held) { return settings_body(held); });
    settings_subscriptions_.erase(dialog);
    notify_settings(dialog, body, "terminated;reason=noresource");
    event("mcdata_settings_subscription_ended", {{"user_id", user}, {"reason", reason}});
  }
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.2: every settings_check_interval_ms, a subscription whose duration is over ends (reason
// "timeout"), one whose user's service authorisation has expired ends (reason "noresource"), and a change of the
// settings is notified.
void DataServer::settings_subscription_tick(std::uint64_t now) {
  if (settings_subscriptions_.size() == 0 || now < settings_next_check_) return;
  settings_next_check_ = now + settings_check_interval_ms;
  for (const auto &dialog : settings_subscriptions_.expired(std::time(nullptr))) {
    const auto body = settings_subscriptions_.current(dialog, [this](const auto &held) { return settings_body(held); });
    settings_subscriptions_.erase(dialog);
    notify_settings(dialog, body, "terminated;reason=timeout");
  }
  std::set<std::string> gone;
  for (const auto &[sip, user] : users_)
    if (user.expires <= std::time(nullptr)) gone.insert(user.id);
  for (const auto &id : gone) end_settings_subscriptions(id, "service authorisation expired");
  settings_changed();
}

} // namespace mcx
