//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The affiliation of a user as other users see and change it (src/server/parts/affiliation_subscriptions.hpp): several
// subscriptions to one user's affiliation status, none replacing another (TS 24.379 clauses 9.2.2.2.4 and 9.2.2.2.5
// with RFC 6665 section 4.2), the authorisation of another user's subscription (clause 9.2.2.2.4 step 4) and of a
// request in negotiated mode (clause 9.2.2.2.8 step 3) by the user profile (TS 24.484 tables 8.3.2.7-24 and
// 8.3.2.7-25), the granted Expires, the affiliation command MIME type (annex F.4) and the route of a request about
// another user (clauses 9.2.2.2.8 to 9.2.2.2.10).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), RFC 6665.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "parts/affiliation_subscriptions.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
using namespace mcx;

namespace {
const std::string alice = "sip:alice@mcx.test";
const std::string bob = "sip:bob@mcx.test";
const std::string carol = "sip:carol@mcx.test";

//------------------------------------------------------------------------------
// Helper: whether the list holds the dialog.
bool holds(const std::vector<std::string> &dialogs, const std::string &dialog) {
  return std::find(dialogs.begin(), dialogs.end(), dialog) != dialogs.end();
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.2.2.4 step 5 and 9.2.2.2.5 with RFC 6665 section 4.2: two subscriptions to alice's status
// (two dialogs of her clients) and one of bob to it are all kept and all notified; a second SUBSCRIBE does not replace
// the first.
void Clause_9_2_2_2_4_SeveralSubscriptionsPerUser() {
  AffiliationSubscriptions subscriptions;
  const std::int64_t now = 1000;
  subscriptions.add("dialog-1", alice, alice, now + 3600);
  subscriptions.add("dialog-2", alice, alice, now + 3600);
  subscriptions.add("dialog-3", alice, bob, now + 600);
  subscriptions.add("dialog-4", bob, bob, now + 3600);
  const auto notified = subscriptions.of_served(alice, now);
  assert(notified.size() == 3);
  assert(holds(notified, "dialog-1") && holds(notified, "dialog-2") && holds(notified, "dialog-3"));
  assert(!holds(notified, "dialog-4"));
  assert(subscriptions.size() == 4);
  // The end of one subscription leaves the others.
  assert(subscriptions.erase("dialog-1"));
  assert(!subscriptions.erase("dialog-1"));
  assert(subscriptions.of_served(alice, now).size() == 2);
  assert(subscriptions.own_live(alice, now));
  assert(subscriptions.erase("dialog-2"));
  // Bob's subscription to alice is not alice's own.
  assert(!subscriptions.own_live(alice, now));
  assert(subscriptions.own_live(bob, now));
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.1.2: a refresh in the dialog keeps the served user and the subscriber, and moves the end; an
// expired subscription is no longer notified and is reported for removal (section 4.2.2).
void Section_4_2_1_2_RefreshAndExpiry() {
  AffiliationSubscriptions subscriptions;
  subscriptions.add("dialog-1", alice, bob, 100);
  subscriptions.add("dialog-1", carol, carol, 500); // a refresh: served user and subscriber stay
  const auto *held = subscriptions.find("dialog-1");
  assert(held && held->served == alice && held->subscriber == bob && held->expires == 500);
  assert(subscriptions.of_served(alice, 499).size() == 1);
  assert(subscriptions.of_served(alice, 500).empty());
  assert(subscriptions.expired(499).empty());
  assert(subscriptions.expired(500) == std::vector<std::string>{"dialog-1"});
  assert(subscriptions.find("none") == nullptr);
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.2.2: the dialogs a subscriber holds, for their end with its binding.
void Section_4_2_2_SubscriberDialogs() {
  AffiliationSubscriptions subscriptions;
  subscriptions.add("dialog-1", alice, bob, 100);
  subscriptions.add("dialog-2", carol, bob, 100);
  subscriptions.add("dialog-3", bob, bob, 100);
  subscriptions.add("dialog-4", bob, alice, 100);
  const auto held = subscriptions.of_subscriber(bob);
  assert(held.size() == 3 && holds(held, "dialog-1") && holds(held, "dialog-2") && holds(held, "dialog-3"));
  assert(subscriptions.of_subscriber(carol).empty());
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.4 step 4 with TS 24.484 tables 8.3.2.7-24 and 8.3.2.7-25: the user's own status is always
// granted; another user's only with <allow-request-affiliated-groups> or <allow-request-to-affiliate-other-users>.
void Clause_9_2_2_2_4_Step4_Authorisation() {
  assert(affiliation_subscribe_status(alice, alice, false) == 200);
  assert(affiliation_subscribe_status(alice, bob, false) == 403);
  assert(affiliation_subscribe_status(alice, bob, true) == 200);
  assert(affiliation_subscribe_status("", bob, true) == 403);
  assert(affiliation_subscribe_status(alice, "", true) == 403);
  assert(!may_determine_affiliation(Json::object()));
  assert(!may_determine_affiliation(Json()));
  assert(may_determine_affiliation(Json{{"request_affiliated_groups", true}}));
  assert(may_determine_affiliation(Json{{"affiliate_others", true}}));
  assert(!may_determine_affiliation(Json{{"request_affiliated_groups", false}}));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.8 step 3 with TS 24.484 table 8.3.2.7-25: a request in negotiated mode only from a user with
// <allow-request-to-affiliate-other-users>; the right to determine the status is not enough.
void Clause_9_2_2_2_8_Step3_Authorisation() {
  assert(may_request_affiliation(Json{{"affiliate_others", true}}));
  assert(!may_request_affiliation(Json{{"request_affiliated_groups", true}}));
  assert(!may_request_affiliation(Json::object()));
  assert(!may_request_affiliation(Json::array()));
}

//------------------------------------------------------------------------------
// RFC 6665 sections 4.1.2.1 and 4.2.1.1: the Expires asked for, shortened to 3600 s, 3600 s without Expires, 0 kept
// (a fetch or the end), a malformed value refused.
void Section_4_2_1_1_Expires() {
  assert(affiliation_subscription_expires(std::nullopt) == 3600U);
  assert(affiliation_subscription_expires("600") == 600U);
  assert(affiliation_subscription_expires(" 7200 ") == 3600U);
  assert(affiliation_subscription_expires("4294967295") == 3600U);
  assert(affiliation_subscription_expires("0") == 0U);
  assert(!affiliation_subscription_expires("4294967296"));
  assert(!affiliation_subscription_expires("-1"));
  assert(!affiliation_subscription_expires(""));
  assert(!affiliation_subscription_expires("ten"));
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.4 and TS 24.281 annex F.4: the affiliation command MIME type of each service.
void AnnexF4_AffiliationCommandMime() {
  assert(affiliation_command_mime(mcptt_service) == "application/vnd.3gpp.mcptt-affiliation-command+xml");
  assert(affiliation_command_mime(mcvideo_service) == "application/vnd.3gpp.mcvideo-affiliation-command+xml");
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.2.2.8 to 9.2.2.2.10: a target served here is handled here; else the request goes to the peer
// that registered it, else to the controlling server of a participating-only server; never back where it came from;
// with neither, no server is known (404).
void Clause_9_2_2_2_10_Route() {
  using Kind = AffiliationRoute::Kind;
  assert(affiliation_route(true, "peer-b", "controller", "").kind == Kind::served_here);
  const auto registered = affiliation_route(false, "peer-b", "controller", "");
  assert(registered.kind == Kind::to_peer && registered.peer == "peer-b");
  const auto upward = affiliation_route(false, "", "controller", "");
  assert(upward.kind == Kind::to_peer && upward.peer == "controller");
  assert(affiliation_route(false, "", "", "").kind == Kind::unknown);
  assert(affiliation_route(false, "", "controller", "controller").kind == Kind::unknown);
  assert(affiliation_route(false, "peer-b", "", "peer-b").kind == Kind::unknown);
  const auto onward = affiliation_route(false, "peer-b", "", "peer-a");
  assert(onward.kind == Kind::to_peer && onward.peer == "peer-b");
}
} // namespace

int main() {
  Clause_9_2_2_2_4_SeveralSubscriptionsPerUser();
  Section_4_2_1_2_RefreshAndExpiry();
  Section_4_2_2_SubscriberDialogs();
  Clause_9_2_2_2_4_Step4_Authorisation();
  Clause_9_2_2_2_8_Step3_Authorisation();
  Section_4_2_1_1_Expires();
  AnnexF4_AffiliationCommandMime();
  Clause_9_2_2_2_10_Route();
  std::cout << "affiliation subscriptions tests passed\n";
  return 0;
}
