//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Temporary groups formed by the GMS and the availability of the common services (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.481 clauses 6.3.14.3 and 6.3.15.3: poll the GMS for the temporary groups it has formed or torn down
// and apply them as regroups (TS 24.379 clause 16), controlled here unless configured otherwise.
void McServer::temporary_tick(std::uint64_t now) {
  if (role_ == "participating" || now < next_temporary_poll_ || service_down("gms")) return;
  next_temporary_poll_ = now + cfg_.at(svc_.name).value("temporary_group_poll_ms", 2000u);
  const auto &common = cfg_.at("common");
  HttpResponse reply;
  try {
    reply = http_.request("GET", common.at("gms").get<std::string>() + "/internal/temporary-groups", {}, {},
                          common.at("client_id"), common.at("secret"));
  } catch (const std::exception &) {
    // Status 0 stays: the GMS counts as failed below.
  }
  if (reply.status == 0 || reply.status >= 500) {
    service_failed("gms");
    return;
  }
  if (reply.status != 200) return;
  Json list;
  try {
    list = reply.json();
  } catch (const std::exception &) {
    return;
  }

  struct Formed {
    Regroup regroup;
    std::string requestor, controller;
  };

  std::map<std::string, Formed> formed;
  // The temporary groups of this system's GMS, controlled here unless configured otherwise.
  for (const auto &entry : list.value("temporary", Json::array())) {
    Formed formation;
    formation.regroup = Regroup{"create",
                                entry.value("id", ""),
                                entry.value("id", ""),
                                entry.value("constituents", std::vector<std::string>{}),
                                {}};
    formation.requestor = entry.value("requestor", "");
    const auto groups = cfg_.at(svc_.name).value("group_controllers", Json::object());
    formation.controller = groups.contains(formation.regroup.regroup_uri)
                               ? groups.at(formation.regroup.regroup_uri).get<std::string>()
                               : "";
    if (!formation.regroup.regroup_uri.empty()) formed[formation.regroup.regroup_uri] = formation;
  }
  // A temporary group combining a group of this system that another function formed: controlled by that function.
  for (const auto &entry : list.value("regrouped", Json::array())) {
    const auto tgi = entry.value("temporary_group_id", "");
    if (tgi.empty() || formed.contains(tgi)) continue;
    Formed formation;
    formation.regroup = Regroup{"create", tgi, tgi, entry.value("constituents", std::vector<std::string>{}), {}};
    formation.requestor = entry.value("requestor", "");
    const auto groups = cfg_.at(svc_.name).value("group_controllers", Json::object());
    if (groups.contains(tgi)) formation.controller = groups.at(tgi).get<std::string>();
    formed[tgi] = formation;
  }
  for (const auto &[tgi, formation] : formed) {
    // A record kept while passing the regroup notice to a user (TS 24.379 clause 16.2.2.4) gives
    // way to the temporary group itself.
    if (const auto held = regroups_.find(tgi);
        held != regroups_.end() && !held->second.temporary && !held->second.controlling && held->second.creator.empty())
      regroups_.erase(held);
    if (regroups_.contains(tgi)) continue;
    // A group already in a regroup of TS 24.379 clause 16 stays there (TS 24.379 clause 16.2.4.1 step 2a).
    if (std::any_of(formation.regroup.groups.begin(), formation.regroup.groups.end(), [&](const std::string &group) {
          const auto mapped = regrouped_.find(group);
          return mapped != regrouped_.end() && mapped->second != tgi;
        })) {
      event("temporary_group_conflict", {{"regroup", tgi}, {"groups", formation.regroup.groups}});
      continue;
    }
    auto &state =
        regroup_store(formation.regroup, formation.requestor, formation.controller.empty(), formation.controller);
    state.temporary = true;
    event("temporary_group_applied", {{"regroup", tgi},
                                      {"groups", formation.regroup.groups},
                                      {"controlling", state.controlling},
                                      {"controller", formation.controller}});
  }
  std::vector<std::string> ended;
  for (const auto &[tgi, state] : regroups_)
    if (state.temporary && !formed.contains(tgi)) ended.push_back(tgi);
  for (const auto &tgi : ended) {
    const auto state = regroups_.at(tgi);
    regroup_discard(tgi, state);
    if (state.controlling) schedule([this, tgi] { end_group_calls(tgi); });
    const Regroup notice{"remove", tgi, state.preconfigured, state.groups, {}};
    schedule([this, notice, was_told = state.told] { regroup_notify(notice, false, was_told); });
    event("temporary_group_ended", {{"regroup", tgi}, {"controlling", state.controlling}});
  }
}

//------------------------------------------------------------------------------
// Helper: whether the common service of the given role (gms, cms, ...) is marked unavailable.
bool McServer::service_down(const std::string &role) const {
  const auto found = service_down_until_.find(role);
  return found != service_down_until_.end() && monotonic_ms() < found->second;
}

//------------------------------------------------------------------------------
// Helper: mark the common service of the given role unavailable for 10 s and report it.
void McServer::service_failed(const std::string &role) {
  service_down_until_[role] = monotonic_ms() + 10000;
  event("common_service_unavailable", {{"service", role}});
}

} // namespace mcx
