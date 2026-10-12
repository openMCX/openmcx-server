//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Functional alias activations (alias_registry.hpp).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).

#include "parts/alias_registry.hpp"

#include <algorithm>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: whether the user has activated the functional alias.
bool AliasRegistry::active(const std::string &alias, const std::string &id) const {
  const auto found = activations_.find(alias);
  return found != activations_.end() &&
         std::find(found->second.begin(), found->second.end(), id) != found->second.end();
}

//------------------------------------------------------------------------------
// Helper: the users that have activated the functional alias, but one.
std::vector<std::string> AliasRegistry::users(const std::string &alias, const std::string &except) const {
  std::vector<std::string> users;
  if (const auto found = activations_.find(alias); found != activations_.end())
    for (const auto &id : found->second)
      if (except.empty() || id != except) users.push_back(id);
  return users;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.6, TS 24.282 clause 22.2.2.3.6: a user's activations end with its service authorization.
std::set<std::string> AliasRegistry::deactivate(const std::string &id) {
  std::set<std::string> aliases;
  for (auto &[alias, active] : activations_)
    if (std::erase(active, id)) aliases.insert(alias);
  std::erase_if(activations_, [](const auto &entry) { return entry.second.empty(); });
  return aliases;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.3, TS 24.282 clause 22.2.2.3.3 steps 4 to 6 (TS 24.484 clauses 8.4.2.1 and 8.3.2.1): the
// user must be in the definition's user list (<mcptt-user-list>, <mcvideo-user-list>, <mcdata-user-list>); with the
// maximum of simultaneous activations reached, the oldest activations are taken over when the request asks for it,
// the definition has <allow-takeover> and the user <allow-takeover-functional-alias-other-user>. A definition that
// allows no activation refuses every one (and the take-over needs a limit).
AliasAdmission AliasRegistry::admit(Change &change, const std::string &alias, const std::string &id,
                                    const Json &definition, const AliasAdmissionRules &rules) {
  auto &active = change.next[alias];
  if (rules.refresh_active && std::find(active.begin(), active.end(), id) != active.end())
    return AliasAdmission::Admitted;
  const auto users = definition.value(alias_user_list(rules.service), std::vector<std::string>{});
  if (std::find(users.begin(), users.end(), id) == users.end()) return AliasAdmission::NotListed;
  const auto limit = definition.value("max_simultaneous_activations", 1U);
  if (limit == 0) return AliasAdmission::NoneAllowed;
  if (active.size() >= limit) {
    const bool user_policy = rules.eager_takeover_policy && rules.user_may_take_over();
    if (!rules.take_over || !definition.value("allow_takeover", false) ||
        !(rules.eager_takeover_policy ? user_policy : rules.user_may_take_over()))
      return AliasAdmission::LimitReached;
    while (active.size() >= limit) {
      change.taken.emplace_back(alias, active.front());
      active.erase(active.begin());
    }
  }
  active.push_back(id);
  return AliasAdmission::Admitted;
}

//------------------------------------------------------------------------------
// Helper: the change takes effect.
std::vector<std::pair<std::string, std::string>> AliasRegistry::commit(Change change) {
  std::erase_if(change.next, [](const auto &entry) { return entry.second.empty(); });
  activations_ = std::move(change.next);
  return std::move(change.taken);
}

} // namespace mcx
