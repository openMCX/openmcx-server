// Functional alias activations (src/server/parts/alias_registry.hpp): the per-alias admission by the alias
// definition for each service, the take-over, the refresh, the deactivation and the queries.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "parts/alias_registry.hpp"

#include <cassert>
#include <iostream>
using namespace mcx;

namespace {
//------------------------------------------------------------------------------
// TS 24.484 clause 8.4.2.1: a definition with its user list for each service.
Json definition(unsigned limit, bool takeover) {
  return {{"users", {"alice", "bob"}},
          {"mcvideo_users", {"alice"}},
          {"mcdata_users", {"bob"}},
          {"max_simultaneous_activations", limit},
          {"allow_takeover", takeover}};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.3, TS 24.282 clause 22.2.2.3.3 step 4a: each service reads its own user list; a
// definition with no activation allowed refuses every one.
void Clause_9A_2_2_3_3_UserListAndLimitZero() {
  AliasRegistry registry;
  auto change = registry.change();
  const AliasAdmissionRules mcptt{Service::mcptt, false, true, false, [] { return false; }};
  const AliasAdmissionRules mcvideo{Service::mcvideo, false, true, false, [] { return false; }};
  const AliasAdmissionRules mcdata{Service::mcdata, false, false, true, [] { return false; }};
  assert(AliasRegistry::admit(change, "fa", "bob", definition(2, false), mcptt) == AliasAdmission::Admitted);
  assert(AliasRegistry::admit(change, "fv", "bob", definition(2, false), mcvideo) == AliasAdmission::NotListed);
  assert(AliasRegistry::admit(change, "fb", "alice", definition(2, false), mcdata) == AliasAdmission::NotListed);
  assert(AliasRegistry::admit(change, "fc", "bob", definition(0, true), mcdata) == AliasAdmission::NoneAllowed);
  assert(registry.commit(std::move(change)).empty());
  assert(registry.active("fa", "bob") && !registry.contains("fb") && !registry.contains("fc") &&
         !registry.contains("fv"));
}

//------------------------------------------------------------------------------
// TS 24.282 clause 22.2.2.3.3 steps 5 and 6 (TS 24.484 clauses 8.4.2.1 and 8.3.2.1): at the limit, the oldest
// activation is taken over only when the request asks, the definition allows and the user may; the user's own
// permission is asked only when needed, or (MCData) before the other conditions.
void Clause_22_2_2_3_3_TakeOver() {
  AliasRegistry registry;
  auto change = registry.change();
  unsigned asked = 0;
  const auto may = [&] {
    ++asked;
    return true;
  };
  assert(AliasRegistry::admit(change, "fa", "alice", definition(1, true), {Service::mcptt, false, true, false, may}) ==
         AliasAdmission::Admitted);
  assert(AliasRegistry::admit(change, "fa", "bob", definition(1, true), {Service::mcptt, false, true, false, may}) ==
         AliasAdmission::LimitReached);
  assert(asked == 0);
  assert(AliasRegistry::admit(change, "fa", "bob", definition(1, true), {Service::mcptt, false, true, true, may}) ==
         AliasAdmission::LimitReached);
  assert(asked == 1);
  assert(AliasRegistry::admit(change, "fa", "bob", definition(1, false), {Service::mcptt, true, true, false, may}) ==
         AliasAdmission::LimitReached);
  assert(AliasRegistry::admit(change, "fa", "bob", definition(1, true), {Service::mcptt, true, true, false, may}) ==
         AliasAdmission::Admitted);
  const auto taken = registry.commit(std::move(change));
  assert(taken.size() == 1 && taken.front() == std::make_pair(std::string("fa"), std::string("alice")));
  assert(registry.users("fa") == std::vector<std::string>{"bob"});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.3: an active user is refreshed (the core); without the refresh (MCData, which removes the
// user's set first) a repeated alias counts again against the limit.
void Clause_9A_2_2_3_3_Refresh() {
  AliasRegistry registry;
  auto change = registry.change();
  const AliasAdmissionRules core{Service::mcptt, false, true, false, [] { return false; }};
  const AliasAdmissionRules data{Service::mcdata, false, false, true, [] { return false; }};
  assert(AliasRegistry::admit(change, "fa", "bob", definition(1, false), core) == AliasAdmission::Admitted);
  assert(AliasRegistry::admit(change, "fa", "bob", definition(1, false), core) == AliasAdmission::Admitted);
  assert(AliasRegistry::admit(change, "fa", "bob", definition(1, false), data) == AliasAdmission::LimitReached);
  registry.commit(std::move(change));
  assert(registry.users("fa").size() == 1);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.6, TS 24.282 clauses 22.2.2.3.6 and 22.2.2.2.8: deactivation returns the aliases the user
// had and drops aliases left without users; the users of an alias but the sender.
void Clause_9A_2_2_3_6_Deactivate() {
  AliasRegistry registry;
  auto change = registry.change();
  const AliasAdmissionRules core{Service::mcptt, false, true, false, [] { return false; }};
  AliasRegistry::admit(change, "fa", "alice", definition(2, false), core);
  AliasRegistry::admit(change, "fa", "bob", definition(2, false), core);
  AliasRegistry::admit(change, "fb", "alice", definition(2, false), core);
  registry.commit(std::move(change));
  assert(registry.users("fa", "alice") == std::vector<std::string>{"bob"});
  assert(registry.deactivate("alice") == std::set<std::string>({"fa", "fb"}));
  assert(!registry.contains("fb") && registry.activations().size() == 1 && registry.users("none").empty());
}
} // namespace

//------------------------------------------------------------------------------
int main() {
  Clause_9A_2_2_3_3_UserListAndLimitZero();
  Clause_22_2_2_3_3_TakeOver();
  Clause_9A_2_2_3_3_Refresh();
  Clause_9A_2_2_3_6_Deactivate();
  std::cout << "alias_registry: all checks passed\n";
}
