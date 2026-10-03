// Private call and group services relayed by SIP MESSAGE: private call call-back, remotely initiated private and
// group calls, private call transfer and forwarding, and remote change of the selected group (member functions of
// McServer).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.229.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.5.4 steps 4 to 9 (and the corresponding steps of the other services relayed by SIP
// MESSAGE): send the SIP MESSAGE request with the service information to the target user, with Accept-Contact
// header fields for the media feature tag and the ICSI and the P-Asserted-Service header field; unless
// `keep_request_uri`, the <mcptt-request-uri> is set to the target's ID.
void McServer::relay_service_message(const User &target, McpttInfo info, bool keep_request_uri) {
  if (!keep_request_uri) info.request_uri = target.id;
  sip_.request("MESSAGE", target.sip, svc_.info_mime, service_info_xml_(info),
               user_route(target, {{"P-Asserted-Service", svc_.icsi},
                                   {"Accept-Contact", feature_accept()},
                                   {"Accept-Contact", icsi_accept()}}));
}

//------------------------------------------------------------------------------
// Helper: reject a service request relayed by SIP MESSAGE: set the status and the Warning, report the rejection
// and return the response.
SipResponse McServer::private_service_rejected(SipResponse &response, const User &user, int status,
                                               const std::string &warning) {
  response.status_code = status;
  if (!warning.empty()) response.headers = {{"Warning", "399 mcx \"" + warning + "\""}};
  event("private_service_rejected", {{"user_id", user.id}, {"status", status}, {"warning", warning}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.5.4 (combined participating and controlling function): relay a remotely initiated group
// call request (to the remote user) or response (to the requesting user) after its authorisation.
SipResponse McServer::relay_remote_group_call(const User &user, McpttInfo &info, const std::string &target,
                                              const User &recipient, const std::string &service_type) {
  SipResponse response;
  const auto reject = [&](int status, const std::string &warning) {
    return private_service_rejected(response, user, status, warning);
  };
  const bool request = service_type == "remotely-initiated-group-call-request";
  // <mcptt-request-uri> names the targeted group (request) or the group that
  // was called (response, TS 24.379 clause 10.1.5.2.2 step 1e).
  const auto group = info.request_uri;
  if (group.empty()) return reject(403, warn(Warning::called_party_unknown));
  if (request && !private_policy_flag(requester_rules(user, "group_call"), "remote_init"))
    return reject(403, warn(Warning::remote_group_call_not_authorised));
  // TS 24.379 clause 10.1.5.4 step 2A: no remotely initiated call on a preconfigured-use-only group.
  bool preconfigured = false;
  try {
    preconfigured = internal("gms", "/internal/group?id=" + url_encode(group)).value("preconfigured_use_only", false);
  } catch (const std::exception &) {} // an unknown group fails the affiliation check below
  if (preconfigured) return reject(403, warn(Warning::preconfigured_use_only));
  // TS 24.379 clause 10.1.5.4 step 3: the remote user must be affiliated to the group.
  if (request && !affiliated(target, group)) return reject(403, warn(Warning::not_affiliated));
  // TS 24.379 clause 10.1.5.4 step 7: the group moves to <mcptt-calling-group-id>; relay_service_message
  // sets <mcptt-request-uri> to the listed user.
  info.calling_user = user.id;
  info.calling_group = group;
  info.called_party.clear();
  info.client_id.clear();
  if (request) remember_ric_priority(target, group, info);
  relay_service_message(recipient, info);
  if (request)
    event("group_remote_init_relayed", {{"user_id", user.id}, {"remote", target}, {"group", group}});
  else
    event("group_remote_init_response_relayed", {{"user_id", user.id}, {"requester", target}, {"group", group}});
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.4.4 and TS 24.281 clause 9.2.4.4 (combined participating and controlling function):
// relay a remote change of the selected group request (to the targeted user) or response (to the requester)
// after its authorisation.
SipResponse McServer::relay_group_selection_change(const User &user, McpttInfo &info, const std::string &target,
                                                   const User &recipient, const std::string &service_type) {
  SipResponse response;
  const auto reject = [&](int status, const std::string &warning) {
    return private_service_rejected(response, user, status, warning);
  };
  const bool request = service_type == "group-selection-change-request";
  const auto group = info.request_uri;
  if (group.empty()) return reject(403, warn(Warning::called_party_unknown));
  if (request) {
    // TS 24.281 clause 9.2.4.3.1 step 3a (TS 24.379 clause 10.1.4.3.1 step 3a): the targeted user must be in
    // <RemoteGroupSelectionURIList>. The step names <mcvideo-request-uri>, which holds the group; the client
    // procedure (TS 24.281 clause 9.2.4.2.1 step 1) checks the targeted user, as done here.
    const auto allowed = user_profile(user.id).value("remote_group_selection", std::vector<std::string>{});
    if (std::find(allowed.begin(), allowed.end(), target) == allowed.end())
      return reject(403, warn(Warning::group_selection_not_authorised));
  }
  // TS 24.281 clause 9.2.4.4 step 2A (TS 24.379 clause 10.1.4.4 step 2A): not a preconfigured-use-only group.
  Json profile;
  try {
    profile = group_profile(group);
  } catch (const std::exception &) {
    // No group document: no restriction to apply here.
  }
  if (profile.value("preconfigured_use_only", false)) return reject(403, warn(Warning::preconfigured_use_only));
  info.service.erase("affiliation-required");
  if (request && !affiliated(target, group)) {
    // TS 24.281 clause 9.2.4.4 step 3a: a user not affiliated but eligible is asked to affiliate (step 8a);
    // one who is not a member is refused with 120.
    if (!profile.is_object() || !profile.contains("members") || !member(profile, target))
      return reject(403, warn(Warning::not_affiliated));
    info.service["affiliation-required"] = "true";
  }
  // TS 24.281 clause 9.2.4.4 step 7: the group moves to <calling-group-id>, the targeted user to <request-uri>.
  info.calling_user = user.id;
  info.calling_group = group;
  info.client_id.clear();
  relay_service_message(recipient, info);
  event(request ? "group_selection_change_relayed" : "group_selection_change_response_relayed",
        {{"user_id", user.id},
         {"target", target},
         {"group", group},
         {"affiliation_required", info.service.contains("affiliation-required")},
         {"outcome", info.service.contains("selected-group-change-outcome")
                         ? info.service.at("selected-group-change-outcome")
                         : ""}});
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.5.4, 11.1.7.4, 11.1.8.4 and 11.1.9.4: authorise a private call call-back, remotely
// initiated private call, transfer or forwarding request of the given type with the requester's <private-call>
// ruleset, and store the transfer or forwarding mapping its private call will need. Returns the rejection, or
// nothing.
std::optional<SipResponse> McServer::authorize_private_service(const User &user, McpttInfo &info,
                                                               const std::string &target, const Json &policy,
                                                               const std::string &type, SipResponse &response) {
  const auto reject = [&](int status, const std::string &warning) {
    return private_service_rejected(response, user, status, warning);
  };
  const auto in_private_call_with = [&](const std::string &peer, bool established) {
    for (const auto &[key, session] : sessions_)
      if (session->private_call &&
          std::find(session->members.begin(), session->members.end(), user.id) != session->members.end() &&
          std::find(session->members.begin(), session->members.end(), peer) != session->members.end() &&
          session->established == established)
        return true;
    return false;
  };
  const auto deadline = monotonic_ms() + 60000;
  if (type == "private-call-call-back-request" && !private_policy_flag(policy, "callback"))
    return reject(403, warn(Warning::call_back_not_authorised));
  if (type == "private-call-call-back-cancel-request" && !private_policy_flag(policy, "callback_cancel"))
    return reject(403, warn(Warning::call_back_cancel_not_authorised));
  if (type == "remotely-initiated-private-call-request") {
    if (!private_policy_flag(policy, "remote_init"))
      return reject(403, warn(Warning::remote_private_call_not_authorised));
    if (info.called_party.empty()) return reject(403, warn(Warning::called_party_unknown));
    remember_ric_priority(target, info.called_party, info);
  }
  if (type == "transfer-private-call-request") {
    // The requester transfers the user it is in an established private call with.
    if (!private_policy_flag(policy, "transfer") || !in_private_call_with(target, true) || info.called_party.empty())
      return reject(403, warn(Warning::transfer_not_authorised));
    auto destination = info.called_party;
    if (info.call_to_functional_alias == true) {
      auto users = functional_alias_users(destination);
      std::erase(users, target);
      if (users.empty()) return reject(403, warn(Warning::called_party_unknown));
      info.called_functional_alias = destination;
      info.called_party = destination = users.front();
    }
    transfer_mappings_[target] = {destination, deadline};
  }
  if (type == "forward-private-call-request") {
    // Manual forwarding of a ringing incoming private call (TS 24.379 clause 11.1.9.2.1).
    const auto orig =
        info.service.contains("forwarding-target-orig-id") ? info.service.at("forwarding-target-orig-id") : "";
    if (!private_policy_flag(policy, "forward_manual") || !in_private_call_with(target, false) || orig.empty())
      return reject(403, warn(Warning::forwarding_not_authorised));
    std::string destination = orig;
    if (info.call_to_functional_alias == true) {
      auto users = functional_alias_users(orig);
      std::erase(users, target);
      if (users.empty()) return reject(403, warn(Warning::called_party_unknown));
      destination = users.front();
    }
    info.service["forwarded-by-mcptt-id"] = user.id;
    info.service["forwarding-target-id"] = destination;
    forwarding_mappings_[target] = {destination, deadline};
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 11.1.5.3, 11.1.5.4, 11.1.7.3, 11.1.7.4, 11.1.8.3, 11.1.8.4, 11.1.9.3 and 11.1.9.4 (combined
// participating and controlling function): private call call-back, remotely initiated private call, transfer and
// forwarding requests and responses; with clauses 10.1.5.3 and 10.1.5.4 remotely initiated group calls and with
// clauses 10.1.4.3 and 10.1.4.4 (TS 24.281 clause 9.2.4) remote changes of the selected group: authorise the
// originator, then relay to the single listed user.
SipResponse McServer::private_service_message(const SipMessage &message, const User &user, McpttInfo info) {
  SipResponse response;
  const auto reject = [&](int status, const std::string &warning) {
    return private_service_rejected(response, user, status, warning);
  };
  const auto service_type = info.service.contains("request-type")    ? info.service.at("request-type")
                            : info.service.contains("response-type") ? info.service.at("response-type")
                                                                     : std::string{};
  // A service MESSAGE names its service in <request-type> or <response-type>.
  if (service_type.empty() || info.client_id != user.client || !accepts_mcptt(message) ||
      message.request_uri != cfg_.at(svc_.name).at("service_uri").get<std::string>())
    return reject(403, "");
  std::string target;
  for (const auto &part : message.parts)
    if (part.content_type == resource_lists_mime) {
      try {
        target = parse_private_call_target(part.body);
      } catch (const std::exception &) {
        return reject(403, warn(Warning::called_party_unknown));
      }
    }
  if (target.empty() || target == user.id) return reject(403, warn(Warning::called_party_unknown));
  const auto *recipient = by_id(target);
  if (!recipient || recipient->expires <= std::time(nullptr)) return reject(480, "");
  // Remotely initiated group call (TS 24.379 clause 10.1.5): the resource list names
  // the remote user (request) or the requesting user (response); the group is
  // in mcptt-request-uri. Combined participating and controlling function.
  if (service_type == "remotely-initiated-group-call-request" ||
      service_type == "remotely-initiated-group-call-response")
    return relay_remote_group_call(user, info, target, *recipient, service_type);
  // Remote change of the selected group (TS 24.379 clause 10.1.4, TS 24.281 clause 9.2.4): the group
  // is in <request-uri>, the targeted user (request) or the requester (response) in
  // the resource list. Combined participating and controlling function.
  if (service_type == "group-selection-change-request" || service_type == "group-selection-change-response")
    return relay_group_selection_change(user, info, target, *recipient, service_type);
  const auto policy = requester_rules(user, "private_call");
  const auto type = info.service.contains("request-type") ? info.service.at("request-type") : std::string{};
  if (auto refused = authorize_private_service(user, info, target, policy, type, response)) return *refused;
  info.calling_user = user.id;
  info.client_id.clear();
  relay_service_message(*recipient, info);
  event("private_service_relayed", {{"user_id", user.id}, {"target", target}, {"type", service_type}});
  response.status_code = 200;
  return response;
}

} // namespace mcx
