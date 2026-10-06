// Group regroup and user regroup using a preconfigured group: the participating, controlling and non-controlling
// function procedures (member functions of McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.229.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 16.2.4.1: the non-controlling function of a constituent group looks after that
// group's members, so a user it serves may affiliate to the regroup here even
// when this system is not shown that group's whole member list.
bool McServer::regroup_vouched(const std::string &regroup, const std::string &peer) const {
  const auto found = regroups_.find(regroup);
  if (peer.empty() || found == regroups_.end() || !found->second.controlling) return false;
  return std::any_of(found->second.groups.begin(), found->second.groups.end(),
                     [&](const std::string &group) { return group_controller(group) == peer; });
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 16.2.3.1 step 3 and 16.3.3.1 step 3: the identity is in use as a regroup, as a
// regrouped group or as a group in the GMS.
bool McServer::regroup_identity_taken(const std::string &id) {
  if (regroups_.contains(id) || is_regrouped(id) || creating_regroups_.contains(id)) return true;
  try {
    (void)group_profile(id);
    return true;
  } catch (const std::exception &) {
    return false;
  }
}

//------------------------------------------------------------------------------
// Helper: the application/vnd.3gpp.mcptt-regroup+xml (or MCVideo) body of a request, in a multipart body or as
// the whole body, or null.
const std::string *McServer::regroup_part(const SipMessage &message) const {
  for (const auto &part : message.parts)
    if (part.content_type == regroup_mime_of(svc_)) return &part.body;
  return message.content_type == regroup_mime_of(svc_) ? &message.body : nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.2.3.1 step 4g (and the other regroup requests between functions): the headers of a SIP
// MESSAGE request to another MCPTT function, with the P-Asserted-Identity set to this function's public service
// identity.
std::vector<SipHeader> McServer::function_headers(const std::string &peer) const {
  // The function asserts its public service identity (sip:), as every server
  // checks an asserted identity; session_service_ is the sips: form that its
  // session URIs take over TLS.
  return route_to(peer, {{"P-Asserted-Identity", "<" + own_service_uri() + ">"}, {"P-Asserted-Service", svc_.icsi}});
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 16.2.2.2 and 16.2.2.3 (clauses 16.3.2.2 and 16.3.2.3 for a user regroup): the
// participating function authorises its own user, then the request goes to the
// controlling function of the preconfigured group, or of the regroup to remove.
SipResponse McServer::regroup_message(const SipMessage &message, User &user, const std::string &body) {
  SipResponse response;
  Regroup regroup;
  try {
    regroup = parse_regroup(body, svc_);
  } catch (const std::exception &error) {
    event("regroup_rejected", {{"user_id", user.id}, {"reason", error.what()}});
    response.status_code = 403;
    return response;
  }
  const bool create = regroup.action == "create";
  if (user.peer.empty()) {
    bool allowed = false;
    try {
      allowed = user_profile(user.id).value("regroup", false);
    } catch (const std::exception &) {
      allowed = false;
    }
    if (!allowed) {
      response.status_code = 403;
      response.headers = {{"Warning", create ? "399 mcx \"" + warn(Warning::regroup_create_not_authorised) + "\""
                                             : "399 mcx \"" + warn(Warning::regroup_remove_not_authorised) + "\""}};
      event("regroup_refused", {{"user_id", user.id},
                                {"action", regroup.action},
                                {"regroup", regroup.regroup_uri},
                                {"warning", create ? 160 : 161}});
      return response;
    }
    // TS 24.379 clause 16.2.2.2 steps 4 to 6: to the controlling function of the preconfigured group.
    const auto held = regroups_.find(regroup.regroup_uri);
    const auto owner =
        !create && held != regroups_.end() ? held->second.controller : group_controller(regroup.preconfigured_group);
    if (!owner.empty())
      return relay_message(message, peers_.at(owner).service_uri,
                           route_to(owner, {{"P-Asserted-Identity", "<" + user.sip + ">"}}));
  }
  if (!create) return regroup_remove(user, regroup);
  return regroup.users.empty() ? regroup_create(message, user, regroup) : regroup_user_create(message, user, regroup);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.2.3.1: the controlling function of the preconfigured group creates the
// regroup, after every constituent group's controlling function has accepted it.
SipResponse McServer::regroup_create(const SipMessage &message, User &user, const Regroup &regroup) {
  SipResponse response;
  // TS 24.379 clause 16.2.3.1 step 2: the preconfigured group must be one this function can serve.
  Json preconfigured;
  try {
    preconfigured = group_profile(regroup.preconfigured_group);
  } catch (const std::exception &) {
    response.status_code = 480;
    return response;
  }
  // TS 24.379 clause 16.2.3.1 step 3: the proposed identity must be free, as a regroup and as a group.
  if (regroup_identity_taken(regroup.regroup_uri)) {
    response.status_code = 403;
    response.headers = {{"Warning", "399 mcx \"" + warn(Warning::regroup_id_in_use) + "\""}};
    event("regroup_refused", {{"user_id", user.id}, {"regroup", regroup.regroup_uri}, {"warning", 165}});
    return response;
  }
  // TS 24.379 clause 16.2.3.1 step 4: every constituent group is offered to its own controlling function,
  // which is a non-controlling function for this regroup.
  std::set<std::string> functions;
  for (const auto &group : regroup.groups) {
    const auto owner = non_controlling(group);
    if (owner.empty()) {
      // TS 24.379 clause 16.2.4.1 step 2a locally: a group may belong to one regroup only.
      if (is_regrouped(group)) {
        response.status_code = 403;
        response.headers = {{"Warning", "399 mcx \"" + warn(Warning::regrouped) + "\""}};
        return response;
      }
      try {
        (void)group_profile(group);
      } catch (const std::exception &) {
        response.status_code = 480;
        return response;
      }
    } else if (!peers_.contains(owner)) {
      response.status_code = 480;
      return response;
    } else {
      functions.insert(owner);
    }
  }
  if (functions.empty()) {
    regroup_store(regroup, user.id, true);
    response.status_code = 200;
    return response;
  }
  // TS 24.379 clause 16.2.3.1 step 5: the answer waits for every non-controlling function.
  creating_regroups_.insert(regroup.regroup_uri);
  const auto pending = std::make_shared<PendingRegroup>();
  pending->outstanding = functions.size();
  pending->transaction = message.transaction_id;
  pending->regroup = regroup;
  pending->creator = user.id;
  pending->accepted.reserve(functions.size());
  for (const auto &owner : functions) {
    sip_.request("MESSAGE", peers_.at(owner).service_uri, regroup_mime_of(svc_), regroup_xml(regroup, svc_),
                 function_headers(owner), [this, pending, owner](const SipResponse &answer) {
                   if (answer.status_code < 200) return;
                   schedule([this, pending, owner, status = answer.status_code,
                             warning = std::string(get_header(answer.headers, "Warning"))] {
                     regroup_answered(pending, owner, status, warning);
                   });
                 });
  }
  response.deferred = true;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.2.3.1 steps 6 and 7: a non-controlling function answered; when all have, the regroup is
// created if all accepted, or the ones that did are told to remove it again.
void McServer::regroup_answered(const std::shared_ptr<PendingRegroup> &pending, const std::string &owner, int status,
                                const std::string &warning) {
  if (status < 300)
    pending->accepted.push_back(owner);
  else if (!pending->failed) {
    pending->failed = true;
    pending->warning = warning;
  }
  if (--pending->outstanding) return;
  creating_regroups_.erase(pending->regroup.regroup_uri);
  SipResponse reply;
  if (!pending->failed) {
    regroup_store(pending->regroup, pending->creator, true);
    reply.status_code = 200;
  } else {
    reply.status_code = 480;
    if (!pending->warning.empty()) reply.headers = {{"Warning", pending->warning}};
    Regroup undo = pending->regroup;
    undo.action = "remove";
    for (const auto &accepted : pending->accepted)
      sip_.request("MESSAGE", peers_.at(accepted).service_uri, regroup_mime_of(svc_), regroup_xml(undo, svc_),
                   function_headers(accepted));
    event("regroup_failed", {{"regroup", pending->regroup.regroup_uri}, {"warning", pending->warning}});
  }
  sip_.respond(pending->transaction, reply);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 16.2.3.1 step 6, 16.2.4.1 step 3, 16.3.2.4 step 4 and 16.3.3.1 step 6: store the regroup
// (identity, preconfigured group, constituent groups or users), mark the constituent groups this function
// controls as regrouped and notify their members.
McServer::RegroupState &McServer::regroup_store(const Regroup &regroup, const std::string &creator, bool controlling,
                                                const std::string &controller) {
  RegroupState state;
  state.preconfigured = regroup.preconfigured_group;
  state.creator = creator;
  state.groups = regroup.groups;
  state.users = regroup.users;
  state.controller = controller;
  state.controlling = controlling;
  auto &stored = regroups_[regroup.regroup_uri] = state;
  // Each function marks only the constituent groups it controls.
  for (const auto &group : regroup.groups)
    if (non_controlling(group).empty()) regrouped_[group] = regroup.regroup_uri;
  event("regroup_created", {{"regroup", regroup.regroup_uri},
                            {"preconfigured", regroup.preconfigured_group},
                            {"groups", regroup.groups},
                            {"users", regroup.users},
                            {"controlling", controlling},
                            {"user_id", creator}});
  if (!regroup.groups.empty()) schedule([this, regroup] { regroup_notify(regroup, true); });
  return stored;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.3.3.1: the controlling function of the preconfigured group creates a user regroup, after at
// least one terminating participating function has accepted it.
SipResponse McServer::regroup_user_create(const SipMessage &message, const User &user, const Regroup &regroup) {
  SipResponse response;
  // TS 24.379 clause 16.3.3.1 step 2: the preconfigured group must be one this function can serve.
  try {
    (void)group_profile(regroup.preconfigured_group);
  } catch (const std::exception &) {
    response.status_code = 480;
    return response;
  }
  // TS 24.379 clause 16.3.3.1 step 3: the proposed identity must be free.
  if (regroup_identity_taken(regroup.regroup_uri)) {
    response.status_code = 403;
    response.headers = {{"Warning", "399 mcx \"" + warn(Warning::regroup_id_in_use) + "\""}};
    event("regroup_refused", {{"user_id", user.id}, {"regroup", regroup.regroup_uri}, {"warning", 165}});
    return response;
  }
  // TS 24.379 clause 16.3.3.1 step 4: one list per terminating participating function. A member this
  // server holds no registration for is taken to be served here, unless this
  // server only controls calls.
  const auto pending = std::make_shared<PendingUserRegroup>();
  pending->transaction = message.transaction_id;
  pending->regroup = regroup;
  pending->creator = user.id;
  std::map<std::string, std::vector<std::string>> remote;
  for (const auto &id : regroup.users) {
    const auto *target = by_id(id);
    if (target && !target->peer.empty())
      remote[target->peer].push_back(id);
    else if (target || role_ != "controlling")
      pending->local.push_back(id);
  }
  pending->accepted.insert(pending->local.begin(), pending->local.end());
  if (remote.empty()) return regroup_user_finish(*pending);
  // TS 24.379 clause 16.3.3.1 step 5: each participating function is sent its own members.
  creating_regroups_.insert(regroup.regroup_uri);
  pending->outstanding = remote.size();
  for (const auto &[peer, ids] : remote) {
    if (!peers_.contains(peer)) {
      schedule([this, pending] { regroup_user_answered(pending, {}, 480); });
      continue;
    }
    Regroup offer = regroup;
    offer.users = ids;
    sip_.request(
        "MESSAGE", peers_.at(peer).service_uri, regroup_mime_of(svc_), regroup_xml(offer, svc_), function_headers(peer),
        [this, pending, ids](const SipResponse &answer) {
          if (answer.status_code < 200) return;
          schedule([this, pending, ids, status = answer.status_code] { regroup_user_answered(pending, ids, status); });
        });
  }
  response.deferred = true;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.3.3.1 steps 6 and 7: a terminating participating function answered; the members it
// accepted count, and when all have answered the user regroup is finished.
void McServer::regroup_user_answered(const std::shared_ptr<PendingUserRegroup> &pending,
                                     const std::vector<std::string> &ids, int status) {
  if (status < 300) pending->accepted.insert(ids.begin(), ids.end());
  if (--pending->outstanding) return;
  creating_regroups_.erase(pending->regroup.regroup_uri);
  sip_.respond(pending->transaction, regroup_user_finish(*pending));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.3.3.1 steps 6 and 7: created when any participating function accepted, otherwise 480.
SipResponse McServer::regroup_user_finish(const PendingUserRegroup &pending) {
  SipResponse reply;
  if (pending.accepted.empty()) {
    reply.status_code = 480;
    event("regroup_failed", {{"regroup", pending.regroup.regroup_uri}});
    return reply;
  }
  auto &state = regroup_store(pending.regroup, pending.creator, true);
  state.affiliated = pending.accepted;
  // TS 24.379 clause 16.3.2.4 at this server's own participating function.
  Regroup notice = pending.regroup;
  notice.users = pending.local;
  if (!notice.users.empty()) schedule([this, notice] { regroup_user_notify(notice, notice.users, true); });
  reply.status_code = 200;
  return reply;
}

//------------------------------------------------------------------------------
// A regroup request from another MCPTT function, which asserts its own service
// identity rather than a user's: this server is the terminating participating
// function of members of a user regroup (TS 24.379 clauses 16.3.2.4 and 16.2.2.5), or the
// non-controlling function of constituent groups of a group regroup (TS 24.379 clauses 16.2.4.1 and
// 16.2.4.2).
SipResponse McServer::regroup_from_function(const std::string &peer, const std::string &body) {
  SipResponse response;
  response.status_code = 200;
  Regroup regroup;
  try {
    regroup = parse_regroup(body, svc_);
  } catch (const std::exception &error) {
    event("regroup_rejected", {{"server", peer}, {"reason", error.what()}});
    response.status_code = 400;
    return response;
  }
  const auto found = regroups_.find(regroup.regroup_uri);
  if (found != regroups_.end() && found->second.controller != peer) {
    // Only the function that controls a regroup changes it.
    response.status_code = 403;
    if (regroup.action == "create")
      response.headers = {{"Warning", "399 mcx \"" + warn(Warning::regroup_id_in_use) + "\""}};
    return response;
  }
  if (regroup.action == "remove") {
    if (found == regroups_.end()) return response;
    const auto state = found->second;
    std::vector<std::string> told;
    for (const auto &id : state.affiliated)
      if (regroup.users.empty() || std::find(regroup.users.begin(), regroup.users.end(), id) != regroup.users.end())
        told.push_back(id);
    regroup_discard(regroup.regroup_uri, state);
    event("regroup_removed", {{"regroup", regroup.regroup_uri}, {"server", peer}, {"controlling", false}});
    Regroup notice = regroup;
    notice.preconfigured_group = state.preconfigured;
    notice.groups = state.groups;
    notice.users.clear();
    if (!state.groups.empty())
      schedule([this, notice, was_told = state.told] { regroup_notify(notice, false, was_told); });
    else
      schedule([this, notice, told] { regroup_user_notify(notice, told, false); });
    return response;
  }
  if (!regroup.groups.empty()) {
    // TS 24.379 clause 16.2.4.1 step 2a: a group this function controls may be in one regroup only.
    for (const auto &group : regroup.groups)
      if (non_controlling(group).empty() && is_regrouped(group)) {
        response.status_code = 403;
        response.headers = {{"Warning", "399 mcx \"" + warn(Warning::regrouped) + "\""}};
        return response;
      }
    regroup_store(regroup, {}, false, peer);
    return response;
  }
  // TS 24.379 clause 16.3.2.4 steps 3 and 4: notify the members not yet told, consider them
  // affiliated, and keep the regroup until it is removed.
  std::set<std::string> known = found != regroups_.end() ? found->second.affiliated : std::set<std::string>{};
  auto &state = regroup_store(regroup, {}, false, peer);
  state.affiliated = known;
  std::vector<std::string> fresh;
  for (const auto &id : regroup.users)
    if (state.affiliated.insert(id).second) fresh.push_back(id);
  if (!fresh.empty()) schedule([this, regroup, fresh] { regroup_user_notify(regroup, fresh, true); });
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 16.2.2.4 step 4 and 16.2.2.5: a participating function passing a group
// regroup notice on to its user keeps the regroup until it is removed, so that
// the user can affiliate to it and call it through this function.
void McServer::regroup_relayed(const std::string &peer, const std::string &body) {
  Regroup regroup;
  try {
    regroup = parse_regroup(body, svc_);
  } catch (const std::exception &) {
    return;
  }
  const auto found = regroups_.find(regroup.regroup_uri);
  if (regroup.action == "remove") {
    // A temporary group ends when its GMS removes it, which this server reads itself.
    if (found != regroups_.end() && found->second.controller == peer && found->second.users.empty() &&
        !found->second.temporary)
      regroup_discard(regroup.regroup_uri, found->second);
    return;
  }
  if (found != regroups_.end() || regroup.groups.empty()) return;
  RegroupState state;
  state.preconfigured = regroup.preconfigured_group;
  state.groups = regroup.groups;
  state.controller = peer;
  regroups_[regroup.regroup_uri] = state;
}

//------------------------------------------------------------------------------
// Helper: forget a regroup and free the constituent groups this function marked.
void McServer::regroup_discard(const std::string &id, const RegroupState state) {
  regroups_.erase(id);
  for (const auto &group : state.groups)
    if (const auto mapped = regrouped_.find(group); mapped != regrouped_.end() && mapped->second == id)
      regrouped_.erase(mapped);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.2.3.2 (clause 16.3.3.2 for a user regroup): the controlling function removes the regroup
// on a user's request, everywhere it is held (TS 24.379 clause 16.2.4.2 at the non-controlling functions).
SipResponse McServer::regroup_remove(const User &user, const Regroup &regroup) {
  SipResponse response;
  const auto found = regroups_.find(regroup.regroup_uri);
  // TS 24.379 clause 16.2.3.2 step 3: the regroup does not exist.
  if (found == regroups_.end()) {
    response.status_code = 403;
    response.headers = {{"Warning", "399 mcx \"" + warn(Warning::group_unknown) + "\""}};
    return response;
  }
  const auto state = found->second;
  // TS 24.379 clause 16.2.3.2 step 2: a regroup in an in-progress emergency state stays (TS 24.379 clause
  // 16.2.1.2 step 1).
  if (const auto emergency = priorities_.find(regroup.regroup_uri);
      emergency != priorities_.end() && emergency->second.emergency) {
    response.status_code = 403;
    response.headers = {{"Warning", "399 mcx \"" + warn(Warning::regroup_remove_in_emergency) + "\""}};
    return response;
  }
  regroup_teardown(regroup.regroup_uri, state, user.id);
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 16.2.3.2 steps 5 and 6 and 16.2.3.3: the regroup ends everywhere it is held: requested by a
// user (clause 16.2.3.2) or decided by this controlling function (clause 16.2.3.3). The non-controlling function
// of each constituent group and the participating function of each member of a
// user regroup are told, the call on the regroup is released, and the members
// this server serves are notified.
void McServer::regroup_teardown(const std::string &id, const RegroupState state, const std::string &by) {
  const Regroup regroup{"remove", id, {}, {}, {}};
  regroup_discard(id, state);
  std::vector<std::string> local;
  if (state.controlling) {
    Regroup forward = regroup;
    forward.preconfigured_group = state.preconfigured;
    forward.groups = state.groups;
    forward.users.clear();
    // TS 24.379 clause 16.2.3.2 step 5: the non-controlling function of each constituent group.
    std::set<std::string> functions;
    for (const auto &group : state.groups)
      if (const auto owner = non_controlling(group); !owner.empty() && peers_.contains(owner)) functions.insert(owner);
    // TS 24.379 clause 16.2.3.2 step 6: the participating function of each affiliated member, with its own members.
    std::map<std::string, std::vector<std::string>> remote;
    for (const auto &member_id : state.affiliated) {
      const auto *target = by_id(member_id);
      if (target && !target->peer.empty())
        remote[target->peer].push_back(member_id);
      else
        local.push_back(member_id);
    }
    for (const auto &owner : functions)
      sip_.request("MESSAGE", peers_.at(owner).service_uri, regroup_mime_of(svc_), regroup_xml(forward, svc_),
                   function_headers(owner));
    for (const auto &[peer, ids] : remote) {
      if (!peers_.contains(peer)) continue;
      Regroup members = forward;
      members.users = ids;
      sip_.request("MESSAGE", peers_.at(peer).service_uri, regroup_mime_of(svc_), regroup_xml(members, svc_),
                   function_headers(peer));
    }
  }
  schedule([this, id] { end_group_calls(id); });
  event("regroup_removed", {{"regroup", id}, {"user_id", by}, {"controlling", state.controlling}});
  Regroup notice = regroup;
  notice.preconfigured_group = state.preconfigured;
  notice.groups = state.groups;
  if (!state.groups.empty())
    schedule([this, notice, was_told = state.told] { regroup_notify(notice, false, was_told); });
  else
    schedule([this, notice, local] { regroup_user_notify(notice, local, false); });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.2.3.3 (clause 16.3.3.3 for a user regroup): the controlling function decides to remove a
// regroup it created
// (here on an administrator's command; the emergency state does not hold it).
bool McServer::regroup_decide_remove(const std::string &id) {
  const auto found = regroups_.find(id);
  if (found == regroups_.end() || !found->second.controlling) return false;
  regroup_teardown(id, found->second, "controlling function");
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.2.4.3: a user affiliating to a constituent group this function controls
// while the group is regrouped is told of the regroup, so that it can use it.
void McServer::regroup_member_added(const std::string &user, const std::string &group) {
  const auto mapped = regrouped_.find(group);
  if (mapped == regrouped_.end()) return;
  const auto found = regroups_.find(mapped->second);
  const auto *target = by_id(user);
  if (found == regroups_.end() || !target) return;
  const Regroup notice{"create", mapped->second, found->second.preconfigured, found->second.groups, {}};
  found->second.told.insert(user);
  sip_.request("MESSAGE", target->sip, regroup_mime_of(svc_), regroup_xml(notice, svc_),
               user_route(*target, {{"P-Asserted-Service", svc_.icsi}, {"Accept-Contact", feature_accept()}}));
  event("regroup_member_notified", {{"regroup", mapped->second}, {"group_id", group}, {"user_id", user}});
}

//------------------------------------------------------------------------------
// Helper: a call on the removed regroup cannot continue, as its group no longer exists: release every leg with
// SIP BYE.
void McServer::end_group_calls(const std::string &group) {
  const auto found = sessions_.find(group);
  if (found == sessions_.end()) return;
  for (const auto &leg : session_legs(*found->second)) {
    leg->active = false;
    try {
      sip_.bye(leg->dialog, {}, {{"Reason", "SIP ;cause=200 ;text=\"Regroup removed\""}});
    } catch (const std::exception &error) {
      event("sip_error", {{"reason", error.what()}});
    }
  }
  event("regroup_call_released", {{"group_id", group}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 16.2.4.1 steps 5 to 7 with clauses 16.2.2.4 and 16.2.1.3 (clauses 16.2.4.2 and 16.2.2.5 for a
// removal): every affiliated member of a
// constituent group is told that its group has been regrouped, and by which
// temporary group identity, so that it can use the regroup at once.
void McServer::regroup_notify(const Regroup &regroup, bool created, const std::set<std::string> &was_told) {
  std::set<std::string> told;
  for (const auto &group : regroup.groups) {
    if (!non_controlling(group).empty()) continue; // told by its own controlling function
    std::vector<std::string> members;
    try {
      members = group_profile(group).at("members").get<std::vector<std::string>>();
    } catch (const std::exception &) {
      continue;
    }
    for (const auto &id : members) {
      // A member that has already moved its affiliation to the regroup is told
      // as well, since the notice concerns the group it is now using.
      if ((!affiliated(id, group) && !affiliated(id, regroup.regroup_uri) && !was_told.contains(id)) ||
          !told.insert(id).second)
        continue;
      const auto *target = by_id(id);
      if (!target) continue;
      Regroup notice = regroup;
      notice.action = created ? "create" : "remove";
      // TS 24.379 clause 16.2.2.5 step 3 e): a removal notice carries no <users-for-regroup> or
      // <groups-for-regroup>.
      if (!created) {
        notice.groups.clear();
        notice.users.clear();
      }
      sip_.request("MESSAGE", target->sip, regroup_mime_of(svc_), regroup_xml(notice, svc_),
                   user_route(*target, {{"P-Asserted-Service", svc_.icsi}, {"Accept-Contact", feature_accept()}}));
    }
  }
  if (created)
    if (const auto found = regroups_.find(regroup.regroup_uri); found != regroups_.end())
      found->second.told.insert(told.begin(), told.end());
  event("regroup_notified", {{"regroup", regroup.regroup_uri}, {"created", created}, {"notified", told.size()}});
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 16.3.2.4 step 3 and 16.2.2.5 step 3: each member served here is told of the
// user regroup. A creation names the members (without <groups-for-regroup>);
// a removal names neither list.
void McServer::regroup_user_notify(Regroup notice, const std::vector<std::string> &ids, bool created) {
  notice.action = created ? "create" : "remove";
  notice.groups.clear();
  if (!created) notice.users.clear();
  std::size_t told = 0;
  for (const auto &id : ids) {
    const auto *target = by_id(id);
    if (!target || !target->peer.empty() || target->expires <= std::time(nullptr)) continue;
    sip_.request("MESSAGE", target->sip, regroup_mime_of(svc_), regroup_xml(notice, svc_),
                 {{"P-Asserted-Service", svc_.icsi}, {"Accept-Contact", feature_accept()}});
    ++told;
  }
  event("regroup_notified", {{"regroup", notice.regroup_uri}, {"created", created}, {"notified", told}});
}

} // namespace mcx
