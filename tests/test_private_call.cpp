//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Private call: the resource-lists body naming the called user and the authorisation checks of the participating
// MCPTT function for private, first-to-answer and emergency private calls and alerts.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).

#include "mcx/private_call.hpp"
#include "mcx/protocol.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>

using namespace mcx;

//------------------------------------------------------------------------------
// Throws the message when the condition does not hold.
static void check(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Checks that the action throws (malformed input refused).
static void rejects(const std::function<void()> &fn) {
  bool failed = false;
  try {
    fn();
  } catch (const std::exception &) {
    failed = true;
  }
  check(failed, "malformed input was accepted");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.4.2 (table 4.4.2-2): the three-digit warning code of a refusal's Warning header field text.
static std::string warning_code(const PrivateCallDecision &decision) { return decision.warning.substr(0, 3); }

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 8 to 12 and 18 (originating private and first-to-answer call), clause
// 11.1.1.3.2 steps 8 and 9 (terminating private call), clause 6.3.3.1.13.1 and clause 6.3.3.1.13.2 (emergency alert
// and emergency private call authorisation), with the user profile defaults of TS 24.484 clause 8.3.2.7.
int main() {
  const std::string alice = "sip:alice@mcx.test", bob = "sip:bob@mcx.test", carol = "sip:carol@mcx.test";

  // Resource list round trip carries exactly one called MCPTT ID.
  const auto list = private_call_resource_list(bob);
  check(parse_private_call_target(list) == bob, "called party lost");
  check(list.find("urn:ietf:params:xml:ns:resource-lists") != std::string::npos, "resource-lists namespace missing");
  rejects([&] { (void)private_call_resource_list(""); });
  rejects([&] { (void)private_call_resource_list("tel:+123"); });
  rejects([&] { (void)private_call_resource_list("sip:a\"b@mcx.test"); });
  auto two = list;
  two.insert(two.find("</list>"), "<entry uri=\"" + carol + "\"/>");
  rejects([&] { (void)parse_private_call_target(two); }); // TS 24.379 clause 11.1.1.3.1.1 step 9: more than one entry
  auto two_lists = list;
  two_lists.insert(two_lists.find("</resource-lists>"), "<list><entry uri=\"" + carol + "\"/></list>");
  rejects([&] { (void)parse_private_call_target(two_lists); });
  auto empty = list;
  empty.replace(empty.find("<entry"), empty.find("/>") + 2 - empty.find("<entry"), "");
  rejects([&] { (void)parse_private_call_target(empty); });
  auto wrong_ns = list;
  wrong_ns.replace(wrong_ns.find("resource-lists\""), 15, "resource-list\"");
  rejects([&] { (void)parse_private_call_target(wrong_ns); });
  auto foreign = list;
  foreign.insert(foreign.find("</list>"), "<external anchor=\"x\"/>");
  rejects([&] { (void)parse_private_call_target(foreign); });

  const nlohmann::json full = {
      {"allow", true}, {"automatic_commencement", true}, {"manual_commencement", true}, {"force_auto_answer", true}};
  check(bool(authorize_private_call(full, {alice, bob, "Auto", ""})), "authorised automatic call rejected");
  check(bool(authorize_private_call(full, {alice, bob, "Manual", ""})), "authorised manual call rejected");
  check(bool(authorize_private_call(full, {alice, bob, "", "Auto"})), "authorised forced call rejected");
  check(bool(authorize_private_call(full, {alice, bob, "", ""})), "callee-selected mode rejected");

  // Absent elements deny (TS 24.484 clause 8.3.2.7, table 8.3.2.7-7: ruleset defaults).
  check(warning_code(authorize_private_call(nlohmann::json::object(), {alice, bob, "Auto", ""})) == "107",
        "missing allow-private-call");
  check(warning_code(authorize_private_call({{"allow", false}}, {alice, bob, "Auto", ""})) == "107",
        "allow=false accepted");
  check(warning_code(authorize_private_call({{"allow", "true"}}, {alice, bob, "Auto", ""})) == "107",
        "non-boolean flag accepted");
  check(warning_code(authorize_private_call({{"allow", true}}, {alice, bob, "Auto", ""})) == "125",
        "automatic commencement not checked");
  check(warning_code(authorize_private_call({{"allow", true}}, {alice, bob, "Manual", ""})) == "126",
        "manual commencement not checked");
  check(warning_code(authorize_private_call({{"allow", true}, {"automatic_commencement", true}},
                                            {alice, bob, "Auto", "Auto"})) == "143",
        "force auto answer not checked");
  const auto invalid_mode = authorize_private_call(full, {alice, bob, "Sometimes", ""});
  check(invalid_mode.status == 400, "invalid Answer-Mode accepted");
  check(authorize_private_call(full, {alice, bob, "", "Manual"}).status == 400, "invalid Priv-Answer-Mode accepted");

  // Called party determination.
  check(warning_code(authorize_private_call(full, {alice, alice, "Auto", ""})) == "145", "self call accepted");
  check(warning_code(authorize_private_call(full, {alice, "", "Auto", ""})) == "145", "empty target accepted");

  // <PrivateCall> list restricts targets unless calls outside it are allowed.
  auto listed = full;
  listed["targets"] = {bob};
  check(bool(authorize_private_call(listed, {alice, bob, "Auto", ""})), "listed target rejected");
  const auto unlisted = authorize_private_call(listed, {alice, carol, "Auto", ""});
  check(unlisted.status == 403 && warning_code(unlisted) == "144", "unlisted target accepted");
  listed["any_target"] = true;
  check(bool(authorize_private_call(listed, {alice, carol, "Auto", ""})), "any_target ignored");

  // First-to-answer originating checks (TS 24.379 clause 11.1.1.3.1.1 steps 8 to 12 and step 15a).
  const std::string dave = "sip:dave@mcx.test";
  auto fta = full;
  fta["first_to_answer"] = true;
  const auto both = authorize_first_to_answer(fta, alice, {bob, carol});
  check(bool(both) && both.targets == std::vector<std::string>({bob, carol}),
        "authorised first-to-answer call rejected");
  check(warning_code(authorize_first_to_answer(fta, alice, {bob})) == "145", "single invitee accepted");
  check(warning_code(authorize_first_to_answer(fta, alice, {bob, alice})) == "145", "caller accepted as invitee");
  check(warning_code(authorize_first_to_answer(fta, alice, {bob, ""})) == "145", "empty invitee accepted");
  check(warning_code(authorize_first_to_answer(full, alice, {bob, carol})) == "156",
        "first-to-answer without permission");
  check(warning_code(authorize_first_to_answer({{"first_to_answer", true}}, alice, {bob, carol})) == "107",
        "first-to-answer without private call permission");
  fta["targets"] = {bob, carol};
  const auto filtered = authorize_first_to_answer(fta, alice, {bob, dave});
  check(bool(filtered) && filtered.targets == std::vector<std::string>({bob}), "unlisted invitee not filtered out");
  const auto none = authorize_first_to_answer(fta, alice, {dave, "sip:erin@mcx.test"});
  check(none.status == 403 && warning_code(none) == "153", "all-unlisted first-to-answer call accepted");
  fta["any_target"] = true;
  check(authorize_first_to_answer(fta, alice, {bob, dave}).targets.size() == 2,
        "any_target ignored for first-to-answer");

  // Terminating checks on the called user's ruleset (TS 24.379 clause 11.1.1.3.2 steps 8 and 9).
  check(bool(authorize_private_callee(nlohmann::json::object(), alice)), "absent callee policy rejected");
  check(bool(authorize_private_callee(nlohmann::json(), alice)), "missing callee profile ruleset rejected");
  check(bool(authorize_private_callee({{"callable", true}}, alice)), "callable user rejected");
  const auto uncallable = authorize_private_callee({{"callable", false}, {"incoming_from", {alice}}}, alice);
  check(uncallable.status == 403 && warning_code(uncallable) == "127", "uncallable user accepted");
  check(bool(authorize_private_callee({{"callable", "false"}}, alice)), "non-boolean callable treated as false");
  const nlohmann::json incoming = {{"incoming_from", {alice}}};
  check(bool(authorize_private_callee(incoming, alice)), "listed caller rejected");
  const auto unlisted_caller = authorize_private_callee(incoming, carol);
  check(unlisted_caller.status == 403 && warning_code(unlisted_caller) == "159", "unlisted caller accepted");
  check(bool(authorize_private_callee({{"incoming_from", {alice}}, {"incoming_any", true}}, carol)),
        "incoming_any ignored");
  check(bool(authorize_private_callee({{"incoming_from", nlohmann::json::array()}}, carol)),
        "empty incoming list restricted callers");
  // Emergency private call and alert authorisation (TS 24.379 clause 6.3.3.1.13.1 and clause 6.3.3.1.13.2).
  check(!authorize_emergency_private(nlohmann::json::object(), bob), "absent emergency permission accepted");
  check(!authorize_emergency_private({{"emergency_any", true}}, bob), "recipient scope without permission accepted");
  check(authorize_emergency_private({{"emergency", true}, {"emergency_any", true}}, bob), "LocallyDetermined rejected");
  const nlohmann::json preconfigured = {{"emergency", true}, {"emergency_recipients", {bob}}};
  check(authorize_emergency_private(preconfigured, bob), "UsePreConfigured recipient rejected");
  check(!authorize_emergency_private(preconfigured, carol), "unlisted emergency recipient accepted");
  check(!authorize_emergency_private({{"emergency", true}}, bob), "emergency without recipient scope accepted");
  check(authorize_private_alert({{"alert", true}, {"alert_recipients", {carol}}}, carol),
        "listed alert recipient rejected");
  check(!authorize_private_alert({{"alert", true}, {"alert_recipients", {carol}}}, bob),
        "unlisted alert recipient accepted");
  check(!authorize_private_alert({{"emergency", true}, {"emergency_any", true}}, bob),
        "emergency permission granted alert");
  check(private_policy_flag({{"emergency_cancel", true}}, "emergency_cancel") &&
            !private_policy_flag({{"emergency_cancel", "true"}}, "emergency_cancel"),
        "cancel flag parsing");
  std::cout << "private call authorization and resource-list tests passed\n";
}
