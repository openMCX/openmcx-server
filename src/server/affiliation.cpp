//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Affiliation: the N2 limit, implicit affiliation, affiliation status and its notification (members of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 3.1 (N2) and clause 9.2.2.2.12 step 9: the N2 value, <MaxAffiliationsN2> of the user profile;
// 0 means no limit.
unsigned McServer::affiliation_limit(const std::string &id) {
  try {
    return user_profile(id).value("max_affiliations", 0u);
  } catch (const std::exception &) {
    return 0;
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.12 step 10: an implicit affiliation beyond N2 is refused. Local policy (TS 24.379 clauses
// 10.1.1.3.1.1 and 10.1.2.3.1.1 NOTE 5) exempts only an authorised request for originating a priority call as
// clause 6.3.2.1.8.1 determines it: the user profile's <allow-emergency-group-call> (<allow-imminent-peril-call>),
// with its <MCPTTGroupInitiation> entry naming this group or the currently selected group.
bool McServer::affiliation_limit_reached(const User &user, const McpttInfo &info) {
  if (info.emergency == true || info.imminent_peril == true) {
    const bool emergency = info.emergency == true;
    try {
      const auto rights = user_profile(user.id).value("group_call", Json::object());
      const auto dedicated = rights.value(emergency ? "emergency_group" : "imminent_group", std::string());
      if (rights.value(emergency ? "emergency" : "imminent", false) &&
          (dedicated.empty() || dedicated == info.request_uri))
        return false;
    } catch (const std::exception &) {}
  }
  const auto limit = affiliation_limit(user.id);
  return limit && user.groups.size() >= limit;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.3.1.1 step 7 (and clause 10.1.1.3.1.1 step 7): the implicit affiliation failed on N2,
// so the request is refused with SIP 486 (Busy Here) and warning 102 (table 4.4.2-2).
SipResponse &McServer::too_many_affiliations(SipResponse &response, const User &user) {
  response.status_code = 486;
  response.headers = {{"Warning", warning_value(warn(Warning::too_many_affiliations))}};
  event("implicit_affiliation_refused", {{"user_id", user.id}, {"reason", "N2"}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.12: a chat join, an emergency or imminent peril group call or an emergency alert
// from a user not affiliated to the group affiliates the user implicitly while the request is passed on.
// Returns the group.
std::string McServer::begin_implicit_affiliation(User &user, const McpttInfo &info, bool alert) {
  const auto &group = info.request_uri;
  const bool group_call = info.session_type == "chat" || info.session_type == "prearranged";
  const bool triggers =
      alert ? info.alert == true
            : group_call && (info.session_type == "chat" || info.emergency == true || info.imminent_peril == true);
  if (!triggers || group.empty() || user.groups.contains(group)) return {};
  try {
    if (!member(group_profile(group), user.id)) return {};
  } catch (const std::exception &) {
    return {};
  }
  user.groups.insert(group);
  return group;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.13 on a 2xx response from the controlling function (completion, then the
// notification of clause 9.2.2.2.5); clause 9.2.2.2.14 otherwise (cancellation).
void McServer::end_implicit_affiliation(const std::string &id, const std::string &group, bool accepted) {
  auto *user = by_id(id);
  if (!user || group.empty()) return;
  if (!accepted) {
    user->groups.erase(group);
    event("implicit_affiliation_cancelled", {{"user_id", id}, {"group_id", group}});
    return;
  }
  if (!user->groups.contains(group)) return;
  notify(*user);
  register_with_controllers(*user);
  event("implicitly_affiliated", {{"user_id", id}, {"group_id", group}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.11: affiliation status determination: whether the user is affiliated to the group (its
// client's group entry, while the registration lives, or membership of a user regroup). The status subscription
// (clause 9.2.2.2.4) only carries notifications: the affiliation does not depend on it (clause 9.2.2.2.3).
bool McServer::affiliated(const std::string &id, const std::string &group) {
  const auto *user = by_id(id);
  if (!user || user->expires <= std::time(nullptr)) return false;
  // TS 24.379 clause 16.3.2.4 step 3h: a member of a user regroup is affiliated with it without asking.
  if (const auto regroup = regroups_.find(group); regroup != regroups_.end() && regroup->second.affiliated.contains(id))
    return true;
  return user->groups.contains(group);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.8.1 step 4 and warning 162 (table 4.4.2-2): whether the group has its minimum number of
// affiliated members and, with include_required, all its required members affiliated.
bool McServer::sufficient_affiliation(const std::string &group, const std::vector<std::string> &members,
                                      const Json &policy, bool include_required) {
  std::set<std::string> affiliated_members;
  for (const auto &id : members)
    if (affiliated(id, group)) affiliated_members.insert(id);
  if (affiliated_members.size() < policy.value("minimum_affiliated_members", 0u)) return false;
  if (include_required)
    for (const auto &id : policy.value("required_affiliated_members", std::vector<std::string>{}))
      if (!affiliated(id, group)) return false;
  return true;
}

//------------------------------------------------------------------------------
// Helper: whether the Accept-Contact header fields (the compact form "a" included) carry the service's media
// feature tag and ICSI, as the controlling function requires (TS 24.379 clause 10.1.1.4.2 step 3 for a group call,
// clause 17.4.2.2 step 3 for an ad hoc group call; a request without them is refused 403).
bool McServer::accepts_mcptt(const SipMessage &message) const {
  std::vector<std::string> values;
  for (const auto &header : message.headers) {
    std::string name = header.name;
    for (auto &character : name) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    if (name == "accept-contact" || name == "a") values.push_back(header.value);
  }
  return has_service_accept_contact(values, svc_);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 9.2.2.3.6 and 9.2.2.3.7: the server owning the group affiliates an eligible member
// implicitly; the guard cancels it (clause 9.2.2.3.11) unless the response accepts the request.
bool McServer::implicitly_affiliate(User &user, const std::string &group, const Json &profile,
                                    const SipResponse &response, ImplicitAffiliation &guard) {
  if (!member(profile, user.id)) return false;
  user.groups.insert(group);
  guard.server = this;
  guard.user = user.id;
  guard.group = group;
  guard.response = &response;
  schedule([this, id = user.id, group] {
    auto *target = by_id(id);
    if (!target || !target->groups.contains(group)) return;
    notify(*target);
    event("implicitly_affiliated", {{"user_id", id}, {"group_id", group}});
  });
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3 step 10 a0: a de-affiliation is refused while the group document lists in
// <forbidden-deaffiliation-FAs> a functional alias the user has activated, or in <forbidden-deaffiliation-if-last-FAs>
// one the user has activated and is the last user to have bound to the group (clause 9A.4). It is the controlling
// function's step, taken here only when this server controls the groups: a participating function of split servers
// holds neither the bindings nor the decision (the per-user PUBLISH of the split link, docs/LIMITATIONS.md). MCPTT only:
// TS 24.281 and TS 24.282 have no such step.
std::set<std::string> McServer::deaffiliation_forbidden(const User &user, const std::set<std::string> &leaving) {
  std::set<std::string> kept;
  if (svc_.service != Service::mcptt || !call_controller().empty()) return kept;
  const auto activated = [&](const std::string &alias) { return functional_alias_active(alias, user.id); };
  const auto last_bound = [&](const std::string &alias, const std::string &group) {
    const auto bound = [&](const std::string &id) {
      const auto user_bindings = alias_bindings_.find(id);
      if (user_bindings == alias_bindings_.end()) return false;
      const auto binding = user_bindings->second.find(group);
      return binding != user_bindings->second.end() && binding->second == alias;
    };
    if (!bound(user.id)) return false;
    for (const auto &[id, bindings] : alias_bindings_)
      if (id != user.id && bound(id)) return false;
    return true;
  };
  for (const auto &group : leaving) {
    Json profile;
    try {
      profile = group_profile(group);
    } catch (const std::exception &) { // a group no longer known
      continue;
    }
    std::string alias;
    for (const auto &entry : profile.value("forbidden_deaffiliation_fas", std::vector<std::string>{}))
      if (alias.empty() && activated(entry)) alias = entry;
    for (const auto &entry : profile.value("forbidden_deaffiliation_if_last_fas", std::vector<std::string>{}))
      if (alias.empty() && activated(entry) && last_bound(entry, group)) alias = entry;
    if (alias.empty()) continue;
    kept.insert(group);
    event("deaffiliation_refused", {{"user_id", user.id}, {"group_id", group}, {"alias", alias}});
  }
  return kept;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.3: new group affiliations of a user: late entry to ongoing calls, current
// priority state, and release from calls of groups no longer affiliated.
void McServer::apply_affiliation(User &user, std::set<std::string> groups) {
  // TS 24.379 clause 16.2.4.3: a new affiliation to a regrouped constituent group.
  for (const auto &group : groups)
    if (!user.groups.contains(group) && is_regrouped(group))
      schedule([this, id = user.id, group] { regroup_member_added(id, group); });
  for (const auto &[group, session] : sessions_)
    if (session->established && !session->chat && groups.contains(group) && !user.groups.contains(group))
      session->late_entry_pending.insert(user.id);
  user.groups = std::move(groups);
  schedule([this, id = user.id] {
    if (auto *target = by_id(id)) {
      notify(*target);
      register_with_controllers(*target);
      for (const auto &[group, priority] : priorities_) {
        if (!target->groups.contains(group)) continue;
        if (priority.emergency || priority.imminent) {
          McpttInfo state;
          state.calling_group = group;
          populate_priority(state, priority);
          priority_message(*target, state);
        }
        // TS 24.379 clause 12.1.3.4 step 1: a late emergency alert only while no call is ongoing on the group; with a
        // call, the user is brought into it (late entry) instead.
        if (sessions_.contains(group)) continue;
        for (const auto &origin : priority.alerts) {
          McpttInfo alert;
          alert.calling_group = group;
          alert.calling_user = origin;
          alert.alert = true;
          priority_message(*target, alert);
        }
      }
      // Private calls do not depend on group affiliation; a regroup's on the regroup affiliation.
      for (const auto &[group, session] : sessions_)
        if (!session->private_call && !session->adhoc && !target->groups.contains(group) &&
            !regroup_affiliated(*target, group) && !reachable_via_hierarchy(*session, *target))
          disconnect_user(id, session);
    }
  });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.2.5: the NOTIFY of the user's affiliation status to its subscription.
void McServer::notify(User &user) {
  // A peer's user gets affiliation notifications from its own server.
  if (!user.peer.empty() || user.subscription.empty() || user.subscription_expires <= std::time(nullptr)) return;
  // Clause 9.2.2.2.5 step 3d: the <p-id> only when a PUBLISH caused the notification (its handled p-id).
  const auto affiliation = affiliation_status(svc_, user, std::exchange(user.handled_pid, std::string{}));
  auto body = affiliation_xml(affiliation, true);
  sip_.notify(user.subscription, "presence", "active;expires=3600", "application/pidf+xml", body);
}

} // namespace mcx
