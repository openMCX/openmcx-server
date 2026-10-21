//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Ad hoc group call: the resource list of invited users, the controlling function's admission checks with their
// warnings, participant criteria and participant list modification entries.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19).
#include "mcx/adhoc_call.hpp"
#include "mcx/protocol.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>

using namespace mcx;

//------------------------------------------------------------------------------
// Test helper: fail the test with the message when the condition is false.
static void check(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Test helper: the function must throw (malformed input refused).
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
// Test helper: the three-digit warning code of a refusal (TS 24.379 table 4.4.2-1).
static std::string code(const AdhocCallDecision &decision) { return decision.warning.substr(0, 3); }

//------------------------------------------------------------------------------
// TS 24.379 clause 17.2.2.1.1 step 11: the application/resource-lists+xml MIME body of invited users; clause
// 17.4.2.2 steps 4 to 7 and clause 17.3.2.1.1 step 9: the ad hoc group call admission checks and their warnings
// (185, 186, 187, 189); clause 17.4.6.1: participant criteria (local policy); clause 17.2.6.1.1 step 2: the
// "method" SIP URI parameter (INVITE or BYE) of participant list modification entries.
int main() {
  const std::string caller = "sip:a@mcx.test", bob = "sip:b@mcx.test", carol = "sip:c@mcx.test",
                    dave = "sip:d@mcx.test";

  // TS 24.379 clause 17.2.2.1.1 step 11: multi-entry resource list: round trip, order kept, duplicates dropped.
  const auto list = resource_list_xml({bob, carol, bob});
  const auto parsed = parse_resource_list_targets(list);
  check(parsed == std::vector<std::string>({bob, carol}), "resource list entries lost or reordered");
  auto split = list;
  split.insert(split.find("</resource-lists>"), "<list><entry uri=\"" + dave + "\"/></list>");
  check(parse_resource_list_targets(split).back() == dave, "second list ignored");
  rejects([] { (void)resource_list_xml({}); });
  rejects([] { (void)resource_list_xml({"tel:+1"}); });
  rejects([&] { (void)parse_resource_list_targets(list.substr(0, list.find("<entry")) + "</list></resource-lists>"); });
  auto foreign = list;
  foreign.insert(foreign.find("</list>"), "<external anchor=\"x\"/>");
  rejects([&] { (void)parse_resource_list_targets(foreign); });
  std::string many = "<?xml version=\"1.0\"?><resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\"><list>";
  // No count limit: 200 entries are read (the configured maximum of participants is checked by the procedure).
  for (int index = 0; index < 200; ++index) many += "<entry uri=\"sip:u" + std::to_string(index) + "@mcx.test\"/>";
  check(parse_resource_list_targets(many + "</list></resource-lists>").size() == 200, "200 resource-list entries");

  // TS 24.379 clause 17.4.2.2 steps 4 to 7: allowed (185), supported (186), participants determinable (187),
  // within the participant limit (189); the caller is not an invitee of its own call.
  const nlohmann::json service = {{"enabled", true}, {"max_participants", 2}};
  const nlohmann::json allowed = {{"allow", true}};
  std::vector<std::string> invitees{bob, caller, carol};
  check(bool(authorize_adhoc_call(service, allowed, caller, invitees)), "authorised ad hoc call rejected");
  check(invitees == std::vector<std::string>({bob, carol}), "caller not removed from invitees");

  invitees = {bob};
  check(code(authorize_adhoc_call(service, nlohmann::json::object(), caller, invitees)) == "185",
        "missing allow accepted");
  invitees = {bob};
  check(code(authorize_adhoc_call(service, {{"allow", "true"}}, caller, invitees)) == "185",
        "non-boolean allow accepted");
  invitees = {bob};
  check(code(authorize_adhoc_call({{"max_participants", 2}}, allowed, caller, invitees)) == "186",
        "disabled service accepted");
  invitees = {caller};
  check(code(authorize_adhoc_call(service, allowed, caller, invitees)) == "187", "self-only list accepted");
  invitees = {bob};
  check(code(authorize_adhoc_call(service, allowed, caller, invitees, true)) == "187", "list with criteria accepted");
  invitees.clear();
  check(bool(authorize_adhoc_call(service, allowed, caller, invitees, true)), "criteria-only call rejected");
  invitees = {bob, carol, dave};
  const auto over = authorize_adhoc_call(service, allowed, caller, invitees);
  check(over.status == 403 && code(over) == "189", "participant limit not enforced");
  invitees = {bob};
  check(code(authorize_adhoc_call({{"enabled", true}}, allowed, caller, invitees)) == "189", "missing limit must deny");
  // TS 24.379 clause 17.4.6.1: participant criteria (local policy vocabulary); clause 17.2.6.1.1 step 2: the
  // modification entries.
  const auto criteria = parse_participant_criteria("affiliated:sip:team@mcx.test, member:sip:ops@mcx.test");
  check(criteria.size() == 2 && criteria[0].kind == "affiliated" && criteria[0].group == "sip:team@mcx.test" &&
            criteria[1].kind == "member" && criteria[1].group == "sip:ops@mcx.test",
        "criteria not parsed");
  for (const char *bad : {"", "affiliated", "location:sip:x@y", "member:tel:1", "affiliated:sip:a@b,"})
    rejects([&] { (void)parse_participant_criteria(bad); });
  const auto changes =
      split_participant_changes({bob + ";method=INVITE", carol + ";METHOD=BYE", bob + ";method=INVITE"});
  check(changes.invite == std::vector<std::string>({bob}) && changes.remove == std::vector<std::string>({carol}),
        "changes not split");
  rejects([&] { (void)split_participant_changes({bob}); });
  rejects([&] { (void)split_participant_changes({bob + ";method=REFER"}); });
  rejects([&] { (void)split_participant_changes({bob + ";method=INVITE", bob + ";method=BYE"}); });
  rejects([&] { (void)split_participant_changes({bob + ";method=INVITE;method=BYE"}); });
  std::cout << "ad hoc authorization and resource-list tests passed\n";
}
