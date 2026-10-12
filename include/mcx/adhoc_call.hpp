//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Ad hoc group call admission: the authorisation of the request, the participant criteria and the participant list
// modification.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).
#pragma once
#include "mcx/warning.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// TS 24.379 clause 17.3.2.1.1 step 9 and clause 17.4.2.2 steps 4 to 7: the outcome of ad hoc group call admission.
//   service: server mcptt.adhoc_call  {"enabled": bool, "max_participants": N}
//            (<allow-adhoc-group-call-support>, <max-no-participants>)
//   policy:  user profile adhoc_call  {"allow": bool}  (<allow-adhoc-group-call>)
// Absent elements deny, as in the service configuration and profile schemas.
struct AdhocCallDecision {
  int status = 0; // 0 admits the request
  std::string warning;

  explicit operator bool() const { return status == 0; }
};

//------------------------------------------------------------------------------
// TS 24.379 clause 17.3.2.1.1 step 9 and clause 17.4.2.2 steps 4 to 7: ad hoc group call admission. On success,
// invitees holds the listed users without the caller, in order.
inline AdhocCallDecision authorize_adhoc_call(const nlohmann::json &service, const nlohmann::json &policy,
                                              const std::string &caller, std::vector<std::string> &invitees,
                                              bool has_criteria = false,
                                              const ServiceProfile &mc_service = mcptt_service) {
  const auto deny = [](int status, std::string warning) { return AdhocCallDecision{status, std::move(warning)}; };
  const auto flag = [](const nlohmann::json &object, const char *key) {
    return object.is_object() && object.contains(key) && object.at(key).is_boolean() && object.at(key).get<bool>();
  };
  if (!flag(policy, "allow")) return deny(403, warning_text(mc_service, Warning::adhoc_initiation_not_authorised));
  if (!flag(service, "enabled")) return deny(403, warning_text(mc_service, Warning::adhoc_not_supported));
  // A list together with criteria is ambiguous (TS 24.379 clause 17.4.2.2 step 7). Criteria alone are resolved later
  // (TS 24.379 clause 17.4.6), and the limit applies to the result.
  if (has_criteria && !invitees.empty())
    return deny(403, warning_text(mc_service, Warning::adhoc_participants_unknown));
  if (has_criteria) return {};
  invitees.erase(std::remove(invitees.begin(), invitees.end(), caller), invitees.end());
  if (invitees.empty()) return deny(403, warning_text(mc_service, Warning::adhoc_participants_unknown));
  const auto limit = service.is_object() ? service.value("max_participants", 0u) : 0u;
  if (!limit || invitees.size() > limit)
    return deny(403, warning_text(mc_service, Warning::adhoc_too_many_participants));
  return {};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.6.1: a participant criterion; the content of the criteria is local policy.
// This implementation accepts a comma-separated list of
//   "affiliated:<group URI>"  users currently affiliated to the group
//   "member:<group URI>"      members of the group in the GMS
// and invites the union of the matching users.
struct ParticipantCriterion {
  std::string kind, group;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 17.4.6.1: parses the comma-separated <call-participants-criterias> (at most 16 criteria).
inline std::vector<ParticipantCriterion> parse_participant_criteria(const std::string &text) {
  std::vector<ParticipantCriterion> criteria;
  std::size_t start = 0;
  while (start <= text.size()) {
    auto end = text.find(',', start);
    if (end == std::string::npos) end = text.size();
    auto item = text.substr(start, end - start);
    item.erase(0, item.find_first_not_of(" \t"));
    item.erase(item.find_last_not_of(" \t") + 1);
    const auto colon = item.find(':');
    if (colon == std::string::npos) throw std::invalid_argument("participant criterion lacks a kind");
    ParticipantCriterion criterion{item.substr(0, colon), item.substr(colon + 1)};
    if ((criterion.kind != "affiliated" && criterion.kind != "member") ||
        !(criterion.group.starts_with("sip:") || criterion.group.starts_with("sips:")) || criterion.group.size() < 6)
      throw std::invalid_argument("unsupported participant criterion");
    criteria.push_back(std::move(criterion));
    if (criteria.size() > 16) throw std::invalid_argument("too many participant criteria");
    start = end + 1;
  }
  if (criteria.empty()) throw std::invalid_argument("empty participant criteria");
  return criteria;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 17.2.6.1.1 step 2: participant list modification: every entry carries a "method" URI parameter of
// INVITE or BYE.
struct ParticipantChanges {
  std::vector<std::string> invite, remove;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 17.2.6.1.1 step 2: splits the entries into the users to invite and to remove by their "method"
// URI parameter; refuses a missing, duplicate or other method and a user both invited and removed.
inline ParticipantChanges split_participant_changes(const std::vector<std::string> &entries) {
  ParticipantChanges changes;
  for (const auto &entry : entries) {
    const auto semicolon = entry.find(';');
    if (semicolon == std::string::npos) throw std::invalid_argument("participant entry lacks a method parameter");
    const auto uri = entry.substr(0, semicolon);
    std::string method;
    std::size_t at = semicolon;
    while (at != std::string::npos) {
      const auto next = entry.find(';', at + 1);
      const auto parameter = entry.substr(at + 1, next == std::string::npos ? std::string::npos : next - at - 1);
      std::string name = parameter.substr(0, parameter.find('='));
      std::transform(name.begin(), name.end(), name.begin(),
                     [](unsigned char character) { return std::tolower(character); });
      if (name == "method") {
        if (!method.empty()) throw std::invalid_argument("duplicate method parameter");
        method = parameter.find('=') == std::string::npos ? "" : parameter.substr(parameter.find('=') + 1);
      }
      at = next;
    }

    auto &target = method == "INVITE" ? changes.invite
                   : method == "BYE"  ? changes.remove
                                      : throw std::invalid_argument("participant method must be INVITE or BYE");
    if (std::find(target.begin(), target.end(), uri) == target.end()) target.push_back(uri);
  }

  for (const auto &uri : changes.invite)
    if (std::find(changes.remove.begin(), changes.remove.end(), uri) != changes.remove.end())
      throw std::invalid_argument("participant both invited and removed");
  return changes;
}
} // namespace mcx
