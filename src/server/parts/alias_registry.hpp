//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Functional alias activations, shared by the MCPTT and MCVideo servers (TS 24.379 clause 9A, TS 24.281 clause 20)
// and the MCData server (TS 24.282 clause 22.2.2): which users have activated each alias, the per-alias admission of
// an activation (the user list of the alias definition, the maximum number of simultaneous activations and the
// take-over, TS 24.484 clauses 8.4.2.1 and 8.3.2.1), and the deactivation of a user's aliases. Each service keeps its
// own PUBLISH procedure: the core changes the listed aliases one by one, MCData replaces the user's whole set.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.484
// V19.6.0 (Rel-19).
#pragma once

#include "mcx/runtime.hpp"
#include "mcx/service.hpp"

#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// The outcome of the admission of one activation (TS 24.379 clause 9A.2.2.3.3, TS 24.282 clause 22.2.2.3.3).
enum class AliasAdmission {
  Admitted,     // activated, refreshed, or taken over
  NotListed,    // the user is not in the definition's user list (TS 24.282 clause 22.2.2.3.3 step 4a)
  NoneAllowed,  // the definition allows no activation
  LimitReached, // the maximum is reached and no take-over is allowed (TS 24.282 clause 22.2.2.3.3 steps 5 and 6)
};

//------------------------------------------------------------------------------
// How one activation is admitted: the service (its user list key), the request's take-over flag, whether a user
// already active is only refreshed, and the user's own take-over permission (<allow-takeover-functional-alias-other-
// user>), asked when needed or, with `eager_takeover_policy`, before the other take-over conditions.
struct AliasAdmissionRules {
  Service service;
  bool take_over = false;
  bool refresh_active = true;
  bool eager_takeover_policy = false;
  std::function<bool()> user_may_take_over;
};

//------------------------------------------------------------------------------
// The activations: alias -> MC service IDs in activation order.
class AliasRegistry {
public:
  using Activations = std::map<std::string, std::vector<std::string>>;

  //------------------------------------------------------------------------------
  // A change of the activations, prepared on a copy and committed only when every listed alias passes.
  struct Change {
    Activations next;
    std::vector<std::pair<std::string, std::string>> taken; // alias, user taken over
  };

  [[nodiscard]] bool contains(const std::string &alias) const { return activations_.contains(alias); }

  // Whether the user has activated the alias.
  [[nodiscard]] bool active(const std::string &alias, const std::string &id) const;
  // The users that have activated the alias, but `except`.
  [[nodiscard]] std::vector<std::string> users(const std::string &alias, const std::string &except = {}) const;

  [[nodiscard]] const Activations &activations() const { return activations_; }

  // TS 24.379 clause 9A.2.2.3.6, TS 24.282 clause 22.2.2.3.6: the user's activations end; the aliases it had.
  std::set<std::string> deactivate(const std::string &id);

  [[nodiscard]] Change change() const { return {activations_, {}}; }

  // TS 24.379 clause 9A.2.2.3.3, TS 24.282 clause 22.2.2.3.3: the activation of the alias by the user in the change,
  // by the alias definition (from the CMS).
  static AliasAdmission admit(Change &change, const std::string &alias, const std::string &id, const Json &definition,
                              const AliasAdmissionRules &rules);
  // The change takes effect (aliases left with no user are dropped); returns the take-overs.
  std::vector<std::pair<std::string, std::string>> commit(Change change);

private:
  Activations activations_;
};
} // namespace mcx
