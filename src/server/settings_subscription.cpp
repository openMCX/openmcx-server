//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Subscription to and notification of the service settings (members of McServer): the participating function
// accepts a client's subscription to the settings of its own MC service ID (TS 24.379 clause 7.3.6.1, TS 24.281
// clause 7.3.6.1) and notifies the settings its client published (clauses 7.3.3 and 7.3.4) at once and on every
// change (clause 7.3.6.2), until the subscription is ended (Expires 0), expires, or the user's service authorisation
// ends (clause 7.3.5). The rules and the bookkeeping are those of parts/settings_subscriptions.hpp.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 4354, RFC 6665.

#include "server.hpp"

#include <ctime>

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
// TS 24.379 clause 7.3.6.1 (TS 24.281 clause 7.3.6.1) for a SUBSCRIBE with Event "poc-settings" (condition 4) from a
// served user (`user`: the binding of the public user identity in P-Asserted-Identity, authenticated): condition 2,
// the service information with <mcptt-request-uri> (<mcvideo-request-uri>), whose content clause 7.3.1A protects
// (decrypted on receipt with the user's CSK, TS 24.379 clause 6.6.2.4; content that could not be is refused with 403
// and warning 140, refuse_unprotectable, and so is content left protected here); condition 3, the service's ICSI in
// P-Asserted-Service (a different one is refused, none is taken as the SIP core's omission); step 1, the served MC
// service ID from it; step 2, the originating one from P-Asserted-Identity; step 3, 403 when they differ; step 4,
// 200 by RFC 6665 with the NOTIFY of clause 7.3.6.2 (RFC 6665 section 4.2.1.2). With Expires 0 that NOTIFY ends it at
// once (a fetch, clause 7.2.4 step 7). Condition 1 (the Request-URI is this function's PSI) is the SIP core's
// routing: the core passes this server the requests for its PSI.
void McServer::settings_subscribe(const SipMessage &message, User &user, SipResponse &response) {
  if (settings_subscriptions_.contains(message.dialog_id)) return settings_resubscribe(message, user, response);
  const auto refuse = [&](int status, const std::string &reason) {
    response.status_code = status;
    event("service_settings_subscription_rejected", {{"user_id", user.id}, {"status", status}, {"reason", reason}});
  };
  const auto parts = parts_of(message);
  for (const auto &part : parts)
    if (mcptt_xml_part(part.content_type) && xmlsec::is_protected(part.body)) {
      ++xml_refused_;
      event("xml_refused", {{"method", message.method}, {"reason", "settings subscription not decrypted"}});
      response.headers = {{"Warning", warning_value(warn(Warning::decrypt_failed))}};
      return refuse(403, "service information not decrypted");
    }
  std::string served;
  try {
    served = message_info(message, svc_).request_uri; // step 1
  } catch (const std::exception &) {
    served.clear(); // no (readable) service information: condition 2 fails, refused below
  }
  if (const auto service = get_header(message.headers, "P-Asserted-Service");
      !service.empty() && service.find(svc_.icsi) == std::string_view::npos)
    return refuse(403, "P-Asserted-Service is not the service's ICSI");
  if (settings_subscribe_status(served, user.id) != 200) // steps 2 and 3
    return refuse(403, served.empty() ? "no request URI in the service information" : "another MC service ID");
  const auto expires = settings_expires(expires_header(message));
  if (!expires) return refuse(400, "malformed Expires");

  // Step 4.
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(*expires)}};
  const auto now = std::time(nullptr);
  if (*expires == 0) {
    event("service_settings_fetched", {{"user_id", user.id}});
    schedule([this, dialog = message.dialog_id, id = user.id] {
      notify_settings(dialog, settings_body({id, 0, {}}), "terminated;reason=timeout");
    });
    return;
  }
  settings_subscriptions_.add(message.dialog_id, user.id, now + static_cast<std::int64_t>(*expires));
  event("service_settings_subscribed", {{"user_id", user.id}, {"expires", *expires}});
  schedule([this, dialog = message.dialog_id] {
    const auto *subscription = settings_subscriptions_.find(dialog);
    if (!subscription) return;
    const auto remaining = subscription->expires - std::time(nullptr);
    notify_settings(dialog,
                    settings_subscriptions_.current(dialog, [this](const auto &held) { return settings_body(held); }),
                    settings_active_state(remaining));
  });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.2.4 (re-subscribe or de-subscribe in the dialog) with RFC 6665 section 4.2.1.2: a nonzero Expires
// refreshes the subscription, 0 ends it; either way a NOTIFY with the current settings follows, the last one
// "terminated". Only the subscriber may (403 for another served user).
void McServer::settings_resubscribe(const SipMessage &message, const User &user, SipResponse &response) {
  const auto *subscription = settings_subscriptions_.find(message.dialog_id);
  if (subscription->user != user.id) {
    response.status_code = 403;
    return;
  }
  const auto expires = settings_expires(expires_header(message));
  if (!expires) {
    response.status_code = 400;
    return;
  }
  response.status_code = 200;
  response.headers = {{"Expires", std::to_string(*expires)}};
  const bool end = *expires == 0;
  if (!end)
    settings_subscriptions_.add(message.dialog_id, user.id, std::time(nullptr) + static_cast<std::int64_t>(*expires));
  event(end ? "service_settings_unsubscribed" : "service_settings_refreshed", {{"user_id", user.id}});
  schedule([this, dialog = message.dialog_id, end] {
    const auto *held = settings_subscriptions_.find(dialog);
    if (!held) return;
    const auto remaining = held->expires - std::time(nullptr);
    const auto body = settings_subscriptions_.current(dialog, [this](const auto &each) { return settings_body(each); });
    if (end) settings_subscriptions_.erase(dialog);
    notify_settings(dialog, body, end ? "terminated;reason=timeout" : settings_active_state(remaining));
  });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.2 step 1 (TS 24.281 likewise): the settings of the subscribed user's client; a user no
// longer served is the bare entity of its subscription's last body (or none).
std::string McServer::settings_body(const SettingsSubscriptions::Subscription &subscription) const {
  for (const auto &[sip, user] : users_)
    if (user.id == subscription.user && user.peer.empty())
      return service_settings_notification(user, std::time(nullptr));
  return subscription.last_body.empty() ? poc_settings_xml(std::vector<PocSettingsEntity>{}) : subscription.last_body;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.2 step 2: the NOTIFY with the application/poc-settings+xml body (RFC 4354 section 4). RFC
// 6665 section 4.2.2: a failure response to it (such as 481) ends the subscription.
void McServer::notify_settings(const std::string &dialog, const std::string &body, const std::string &state) {
  sip_.notify(dialog, poc_settings_event, state, poc_settings_mime, body, {},
              [this, dialog](const SipResponse &answer) {
                if (answer.status_code < 300) return;
                schedule([this, dialog, status = answer.status_code] {
                  if (settings_subscriptions_.erase(dialog))
                    event("service_settings_subscription_ended", {{"dialog", dialog}, {"status", status}});
                });
              });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.2: "for the duration of the subscription" (clause 7.3.6.1), a NOTIFY whenever the settings
// change: a PUBLISH of clause 7.3.3 or 7.3.4, or the end of the cached settings (clause 7.3.4 step 8).
void McServer::settings_changed() {
  const auto now = std::time(nullptr);
  for (const auto &[dialog, body] :
       settings_subscriptions_.changed([this](const auto &held) { return settings_body(held); }))
    if (const auto *subscription = settings_subscriptions_.find(dialog))
      notify_settings(dialog, body, settings_active_state(subscription->expires - now));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.5 steps 3 and 4 and clause 7.3.3 step 8 (the user's service authorisation ends) with RFC 6665
// section 4.2.2: the subscriptions to its settings end with a final NOTIFY, reason "noresource" (the settings are no
// more); `reason` is the event's.
void McServer::end_settings_subscriptions(const std::string &user, const char *reason) {
  for (const auto &dialog : settings_subscriptions_.of_user(user)) {
    const auto body = settings_subscriptions_.current(dialog, [this](const auto &held) { return settings_body(held); });
    settings_subscriptions_.erase(dialog);
    notify_settings(dialog, body, "terminated;reason=noresource");
    event("service_settings_subscription_ended", {{"dialog", dialog}, {"user_id", user}, {"reason", reason}});
  }
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.2: every settings_check_interval_ms, a subscription whose duration is over ends with a final
// NOTIFY (reason "timeout"), and a change of the cached settings (their expiry) is notified (clause 7.3.6.2).
void McServer::settings_subscription_tick(std::uint64_t now) {
  if (settings_subscriptions_.size() == 0 || now < settings_next_check_) return;
  settings_next_check_ = now + settings_check_interval_ms;
  for (const auto &dialog : settings_subscriptions_.expired(std::time(nullptr))) {
    const auto body = settings_subscriptions_.current(dialog, [this](const auto &held) { return settings_body(held); });
    settings_subscriptions_.erase(dialog);
    notify_settings(dialog, body, "terminated;reason=timeout");
  }
  settings_changed();
}

} // namespace mcx
