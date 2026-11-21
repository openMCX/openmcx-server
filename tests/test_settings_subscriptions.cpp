//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The subscription to and notification of the service settings (src/server/parts/settings_subscriptions.hpp): the
// answers of TS 24.379 clause 7.3.6.1 (accepted for the user's own MC service ID, 403 for another), the Expires rule
// of RFC 6665, the application/poc-settings+xml body of clause 7.3.6.2 from the cached settings (and the MCData one
// of TS 24.282 clause 7.3.6.2), and the subscriptions: the initial NOTIFY, a NOTIFY on a settings change (clauses
// 7.3.3 and 7.3.4) and only then, a refresh, the end by Expires 0, by expiry and by the end of the user's service
// authorisation.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 4354,
// RFC 6665.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "parts/settings_subscriptions.hpp"

#include <cassert>
#include <iostream>
using namespace mcx;

namespace {
//------------------------------------------------------------------------------
// Helper: whether the text contains the part.
bool has(const std::string &text, const std::string &part) { return text.find(part) != std::string::npos; }

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.1 steps 1 to 4: 200 for the subscriber's own MC service ID, 403 for another (step 3) or
// none (condition 2).
void Clause_7_3_6_1_SubscribeStatus() {
  assert(settings_subscribe_status("sip:alice@x", "sip:alice@x") == 200);
  assert(settings_subscribe_status("sip:bob@x", "sip:alice@x") == 403);
  assert(settings_subscribe_status("", "sip:alice@x") == 403);
  assert(settings_subscribe_status("sip:alice@x", "") == 403);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.2.4 steps 6 and 7 with RFC 6665 section 4.1.2.1: 4294967295 subscribes, 0 fetches (or ends in
// the dialog), none takes the default, anything else than delta-seconds of at most 2^32-1 is malformed.
void Clause_7_2_4_Expires() {
  assert(settings_expires("4294967295") == 4294967295ull);
  assert(settings_expires(" 0 ") == 0ull);
  assert(settings_expires(std::nullopt) == settings_default_expires_s);
  assert(settings_expires("600") == 600ull);
  assert(!settings_expires("4294967296"));
  assert(!settings_expires("-1"));
  assert(!settings_expires("12a"));
  assert(!settings_expires(""));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.6.2 step 1: a) <am-settings> with the client's answer mode, b) <selected-user-profile-index>,
// read back by the client as clause 7.2.4 caches them; without cached (or with expired) settings the bare entity;
// TS 24.282 clause 7.3.6.2: the profile index only.
void Clause_7_3_6_2_Body() {
  const auto now = std::time(nullptr);
  ServedUser user;
  user.id = "sip:alice@x";
  user.client = "urn:uuid:client-a";
  auto bare = service_settings_notification(user, now);
  auto entities = parse_poc_settings(bare);
  assert(entities.size() == 1 && entities[0].id == "urn:uuid:client-a" && entities[0].answer_mode.empty() &&
         !entities[0].profile_index);

  user.settings = read_service_settings(poc_settings_xml("urn:uuid:client-a", 2, true, true), user.client, now + 60);
  const auto body = service_settings_notification(user, now);
  assert(has(body, "<poc-settings xmlns=\"urn:oma:params:xml:ns:poc:poc-settings\""));
  assert(has(body, "<am-settings><answer-mode>manual</answer-mode></am-settings>"));
  assert(has(body, "<mc:selected-user-profile-index><mc:user-profile-index>2</mc:user-profile-index>"));
  assert(!has(body, "multiplex-support")); // not a setting of clause 7.3.6.2
  entities = parse_poc_settings(body);
  assert(entities.size() == 1 && entities[0].answer_mode == "manual" && entities[0].profile_index == 2U);

  user.settings = read_service_settings(poc_settings_xml("urn:uuid:client-a", 0, false), user.client, now + 60);
  assert(parse_poc_settings(service_settings_notification(user, now))[0].answer_mode == "automatic");
  assert(service_settings_notification(user, now + 60) == bare); // the cached settings have expired

  const auto data = service_settings_notification(user, now, false);
  assert(!has(data, "am-settings") && has(data, "<mc:user-profile-index>0</mc:user-profile-index>"));

  bool refused = false;
  try {
    (void)poc_settings_xml(std::vector<PocSettingsEntity>{{"c1", "Auto", std::nullopt, std::nullopt}});
  } catch (const std::exception &) {
    refused = true;
  }
  assert(refused); // RFC 4354 <answer-mode> is "automatic" or "manual"
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 7.3.6.1 and 7.3.6.2 with RFC 6665 section 4.2: the initial NOTIFY records the body; a NOTIFY on
// a settings PUBLISH (clause 7.3.4) only to that user's subscriptions, none while nothing changes; a refresh keeps the
// body sent; Expires 0 ends it with a final NOTIFY; expiry; the end of the user's service authorisation (clause
// 7.3.5) ends all its subscriptions.
void Clause_7_3_6_Lifecycle() {
  const auto now = std::time(nullptr);
  std::map<std::string, ServedUser> users;
  users["sip:alice@x"] = {"sip:alice@x", "client-a"};
  users["sip:bob@x"] = {"sip:bob@x", "client-b"};
  const auto body_of = [&](const SettingsSubscriptions::Subscription &held) {
    return service_settings_notification(users.at(held.user), now);
  };
  SettingsSubscriptions subscriptions;
  subscriptions.add("d1", "sip:alice@x", now + 3600);
  subscriptions.add("d2", "sip:bob@x", now + 3600);
  subscriptions.add("d3", "sip:alice@x", now + 10);
  assert(subscriptions.size() == 3 && subscriptions.contains("d2") && !subscriptions.contains("d4"));
  for (const auto *dialog : {"d1", "d2", "d3"}) assert(has(subscriptions.current(dialog, body_of), "<entity id="));
  assert(subscriptions.changed(body_of).empty());

  // Clause 7.3.4: alice's client publishes manual answer.
  users["sip:alice@x"].settings = read_service_settings(poc_settings_xml("client-a", 1, true), "client-a", now + 60);
  auto changes = subscriptions.changed(body_of);
  assert(changes.size() == 2 && changes[0].first == "d1" && changes[1].first == "d3");
  assert(has(changes[0].second, "<answer-mode>manual</answer-mode>"));
  assert(subscriptions.changed(body_of).empty());

  // RFC 6665 section 4.2.1.2: a refresh keeps the last body; the NOTIFY it gets carries the same state.
  subscriptions.add("d1", "sip:alice@x", now + 7200);
  assert(subscriptions.find("d1")->expires == now + 7200 && has(subscriptions.find("d1")->last_body, "manual"));
  assert(subscriptions.changed(body_of).empty());

  // Expiry (RFC 6665 section 4.2.2).
  const auto expired = subscriptions.expired(now + 10);
  assert(expired.size() == 1 && expired[0] == "d3");
  assert(subscriptions.erase("d3") && !subscriptions.erase("d3"));

  // Expires 0 in the dialog: the final NOTIFY carries the current state, then nothing.
  assert(has(subscriptions.current("d2", body_of), "client-b"));
  assert(subscriptions.erase("d2"));
  users["sip:bob@x"].settings = read_service_settings(poc_settings_xml("client-b", 3, true), "client-b", now + 60);
  assert(subscriptions.changed(body_of).empty());

  // Clause 7.3.5: alice's service authorisation ends: all her subscriptions.
  subscriptions.add("d5", "sip:alice@x", now + 3600);
  const auto of_alice = subscriptions.of_user("sip:alice@x");
  assert(of_alice.size() == 2 && of_alice[0] == "d1" && of_alice[1] == "d5");
  assert(subscriptions.of_user("sip:bob@x").empty());
  assert(settings_active_state(42) == "active;expires=42" && settings_active_state(-3) == "active;expires=0");
}
} // namespace

//------------------------------------------------------------------------------
int main() {
  Clause_7_3_6_1_SubscribeStatus();
  Clause_7_2_4_Expires();
  Clause_7_3_6_2_Body();
  Clause_7_3_6_Lifecycle();
  std::cout << "settings_subscriptions: all checks passed\n";
}
