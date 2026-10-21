//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Private call admission of the participating function: the on-demand, first-to-answer and emergency private call
// authorisation checks against the user profile <ruleset>.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 5373.
#pragma once
#include "mcx/warning.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace mcx {
// Subset of the user-profile <ruleset> of TS 24.484 clause 8.3 (the MCPTT user profile configuration document)
// relevant to on-demand private calls, as served by the CMS internal user resource:
//   {"allow": bool,                  <allow-private-call>
//    "automatic_commencement": bool, <allow-automatic-commencement>
//    "manual_commencement": bool,    <allow-manual-commencement>
//    "force_auto_answer": bool,      <allow-force-auto-answer>
//    "targets": [MCPTT ID...],       <PrivateCall> <entry> list
//    "any_target": bool,             call users outside <PrivateCall>
//    "callable": bool,               false: unable to participate in private calls
//    "incoming_from": [MCPTT ID...], <IncomingPrivateCallList> <entry> list
//    "incoming_any": bool}           receive calls from users outside that list
// Absent elements mean "not authorised", as in the profile schema. The exception is "callable": an absent flag leaves
// the user callable, so only an explicit false marks the user as unable to participate.

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1: what the originating participating function checks of a private call request.
struct PrivateCallRequest {
  std::string caller, target;
  std::string answer_mode;      // RFC 5373 Answer-Mode value, empty when absent
  std::string priv_answer_mode; // RFC 5373 Priv-Answer-Mode value
};

//------------------------------------------------------------------------------
// Helper: the outcome of an admission check: 0 admits, otherwise the SIP status code and the Warning text.
struct PrivateCallDecision {
  int status = 0; // 0 admits the request
  std::string warning;

  explicit operator bool() const { return status == 0; }
};

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 9 to 11: the originating participating-function checks (single called party,
// profile authorisation, commencement mode, target list). Not implemented: the transfer, forwarding and
// functional-alias branches.
inline PrivateCallDecision authorize_private_call(const nlohmann::json &policy, const PrivateCallRequest &request,
                                                  const ServiceProfile &service = mcptt_service) {
  const auto deny = [](int status, std::string warning) { return PrivateCallDecision{status, std::move(warning)}; };
  const auto flag = [&](const char *key) {
    return policy.is_object() && policy.contains(key) && policy.at(key).is_boolean() && policy.at(key).get<bool>();
  };

  if (request.target.empty() || request.target == request.caller)
    return deny(403, warning_text(service, Warning::called_party_unknown));
  if (!flag("allow")) return deny(403, warning_text(service, Warning::private_call_not_authorised));
  if (!request.priv_answer_mode.empty()) {
    if (request.priv_answer_mode != "Auto")
      return deny(400, warning_text(service, Warning::function_not_allowed, "invalid Priv-Answer-Mode"));
    if (!flag("force_auto_answer")) return deny(403, warning_text(service, Warning::force_auto_answer_not_authorised));
  } else if (request.answer_mode == "Auto") {
    if (!flag("automatic_commencement"))
      return deny(403, warning_text(service, Warning::automatic_commencement_not_authorised));
  } else if (request.answer_mode == "Manual") {
    if (!flag("manual_commencement"))
      return deny(403, warning_text(service, Warning::manual_commencement_not_authorised));
  } else if (!request.answer_mode.empty()) {
    return deny(400, warning_text(service, Warning::function_not_allowed, "invalid Answer-Mode"));
  }

  std::vector<std::string> targets;
  if (policy.is_object() && policy.contains("targets")) targets = policy.at("targets").get<std::vector<std::string>>();
  if (!targets.empty() && !flag("any_target") &&
      std::find(targets.begin(), targets.end(), request.target) == targets.end())
    return deny(403, warning_text(service, Warning::callee_not_authorised));
  return {};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 8 to 12 and 15 a): the originating checks for a first-to-answer call:
// "first_to_answer" mirrors <allow-request-first-to-answer-call>. On success, targets holds the invitees permitted by
// the <PrivateCall> list.
struct FirstToAnswerDecision : PrivateCallDecision {
  std::vector<std::string> targets;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 8 to 12 and 15 a): the first-to-answer call checks. First-to-answer calls are
// MCPTT only (TS 24.281 has none).
inline FirstToAnswerDecision authorize_first_to_answer(const nlohmann::json &policy, const std::string &caller,
                                                       const std::vector<std::string> &requested) {
  const ServiceProfile &service = mcptt_service;
  const auto deny = [](int status, std::string warning) {
    FirstToAnswerDecision decision;
    decision.status = status;
    decision.warning = std::move(warning);
    return decision;
  };
  const auto flag = [&](const char *key) {
    return policy.is_object() && policy.contains(key) && policy.at(key).is_boolean() && policy.at(key).get<bool>();
  };

  // The caller, empty entries and repeats call nobody; the clause refuses only a request that leaves no one to call
  // (step 8: 145). Two or more invitees are the client's rule (clause 11.1), not a check of the participating function.
  std::vector<std::string> targets;
  for (const auto &target : requested)
    if (!target.empty() && target != caller && std::find(targets.begin(), targets.end(), target) == targets.end())
      targets.push_back(target);
  if (targets.empty()) return deny(403, warning_text(service, Warning::called_party_unknown));
  if (!flag("allow")) return deny(403, warning_text(service, Warning::private_call_not_authorised));
  if (!flag("first_to_answer")) return deny(403, warning_text(service, Warning::first_to_answer_not_authorised));

  std::vector<std::string> listed;
  if (policy.is_object() && policy.contains("targets")) listed = policy.at("targets").get<std::vector<std::string>>();
  if (!listed.empty() && !flag("any_target")) {
    std::erase_if(targets,
                  [&](const auto &target) { return std::find(listed.begin(), listed.end(), target) == listed.end(); });
    if (targets.empty()) return deny(403, warning_text(service, Warning::first_to_answer_none_callable));
  }

  FirstToAnswerDecision decision;
  decision.targets = std::move(targets);
  return decision;
}

// Emergency private call and private emergency alert authorisation (TS 24.379 clauses 6.3.3.1.13.1 to 6.3.3.1.13.4)
// from the requesting user's ruleset:
//   "emergency": <allow-emergency-private-call>
//   "emergency_recipients": <MCPTTPrivateRecipient> entries ("UsePreConfigured")
//   "emergency_any": entry-info "LocallyDetermined"
//   "emergency_cancel": <allow-cancel-private-emergency-call>
//   "alert", "alert_recipients", "alert_any": <allow-activate-emergency-alert>
//                                            and <PrivateEmergencyAlert>
//   "alert_cancel": <allow-cancel-emergency-alert>

//------------------------------------------------------------------------------
// Helper: whether a <ruleset> flag of the policy is present and true.
inline bool private_policy_flag(const nlohmann::json &policy, const char *key) {
  return policy.is_object() && policy.contains(key) && policy.at(key).is_boolean() && policy.at(key).get<bool>();
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.3.1.13.1 and 6.3.3.1.13.2: whether the flag allows the request and the target is a permitted
// recipient: any recipient ("LocallyDetermined") or one of the listed ones ("UsePreConfigured").
inline bool private_recipient_allowed(const nlohmann::json &policy, const char *allow, const char *list,
                                      const char *any, const std::string &target) {
  if (!private_policy_flag(policy, allow)) return false;
  if (private_policy_flag(policy, any)) return true;
  if (!policy.contains(list)) return false;
  const auto ids = policy.at(list).get<std::vector<std::string>>();
  return std::find(ids.begin(), ids.end(), target) != ids.end();
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.1.13.2: authorisation for initiating an MCPTT emergency private call to the target.
inline bool authorize_emergency_private(const nlohmann::json &policy, const std::string &target) {
  return private_recipient_allowed(policy, "emergency", "emergency_recipients", "emergency_any", target);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.3.1.13.1: authorisation for initiating an MCPTT emergency alert to the target.
inline bool authorize_private_alert(const nlohmann::json &policy, const std::string &target) {
  return private_recipient_allowed(policy, "alert", "alert_recipients", "alert_any", target);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.2 steps 8 and 9: the terminating participating-function checks, applied to the called
// user's own ruleset.
inline PrivateCallDecision authorize_private_callee(const nlohmann::json &policy, const std::string &caller,
                                                    const ServiceProfile &service = mcptt_service) {
  if (!policy.is_object()) return {};
  if (policy.contains("callable") && policy.at("callable").is_boolean() && !policy.at("callable").get<bool>())
    return {403, warning_text(service, Warning::not_callable_in_private_call)};
  std::vector<std::string> allowed;
  if (policy.contains("incoming_from")) allowed = policy.at("incoming_from").get<std::vector<std::string>>();
  const bool any = policy.contains("incoming_any") && policy.at("incoming_any").is_boolean() &&
                   policy.at("incoming_any").get<bool>();
  if (!allowed.empty() && !any && std::find(allowed.begin(), allowed.end(), caller) == allowed.end())
    return {403, warning_text(service, Warning::caller_not_permitted)};
  return {};
}
} // namespace mcx
