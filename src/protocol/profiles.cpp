// User profile and group document fields the MC clients and servers read: the profile index, the granted actions, the
// MCVideo profile, and group flags and enhanced status values.
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 4745.

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.484 clauses 8.3.2.1, 9.3.2.1 and 10.3.2.1: the root of an MCPTT, an MCVideo or an MCData user profile; ns
// receives its namespace.
static xmlNode *profile_root(xmlDoc *doc, const char **ns) {
  auto root = xmlDocGetRootElement(doc);
  if (is(root, "mcptt-user-profile", profile_ns))
    *ns = profile_ns;
  else if (is(root, "mcvideo-user-profile", mcvideo_profile_ns))
    *ns = mcvideo_profile_ns;
  else if (is(root, "mcdata-user-profile", mcdata_profile_ns))
    *ns = mcdata_profile_ns;
  else
    invalid("wrong user profile root");
  return root;
}

// TS 24.484 clause 8.3.2.3 (and clause 9.3.2.3): "user-profile-index" is an xs:unsignedByte.
constexpr std::uint32_t max_profile_index = 255;

//------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 4 and clause 9.3.2.1 item 4: the "user-profile-index" attribute of the root (1 when
// absent), at most 255.
static unsigned profile_index_of(xmlNode *root) {
  const auto index = attr(root, "user-profile-index");
  if (index.empty()) return 1;
  if (index.size() > 3) invalid("invalid user-profile-index");
  return number(index, max_profile_index);
}

//------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 4 and clause 9.3.2.1 item 4: the user profile index of an MCPTT or MCVideo user
// profile.
unsigned parse_profile_index(std::string_view xml) {
  auto doc = document(xml);
  const char *ns = nullptr;
  return profile_index_of(profile_root(doc.get(), &ns));
}

//------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: the granted rights of a user profile. The rights are boolean elements of the
// <actions> of the <cp:ruleset> (RFC 4745), directly or in its <anyExt>; the MCData ones are elements of the
// MCData user profile (TS 24.484 clause 10.3.2.3). A right is granted when its element is true.
std::set<std::string> parse_profile_actions(std::string_view xml) {
  auto doc = document(xml);
  const char *ns = nullptr;
  auto root = profile_root(doc.get(), &ns);
  std::set<std::string> actions;
  const std::function<void(xmlNode *)> collect = [&](xmlNode *list) {
    for (auto action = list->children; action; action = action->next) {
      if (is(action, "anyExt", ns)) {
        collect(action);
        continue;
      }
      if (action->type != XML_ELEMENT_NODE || !action->ns ||
          (!xmlStrEqual(action->ns->href, BAD_CAST ns) &&
           !xmlStrEqual(action->ns->href, BAD_CAST profile_extension_ns) &&
           (ns != profile_ns || !xmlStrEqual(action->ns->href, BAD_CAST mcdata_profile_ns))))
        continue;
      auto value = scalar(action);
      value.erase(0, value.find_first_not_of(" \t\r\n"));
      value.erase(value.find_last_not_of(" \t\r\n") + 1);
      if (value != "true" && value != "1" && value != "false" && value != "0") invalid("invalid profile action value");
      if (value == "false" || value == "0") continue;
      std::string name = reinterpret_cast<const char *>(action->name);
      if (name.size() > 128 || actions.size() >= 64) invalid("invalid profile action");
      // The name this implementation's clients use for <allow-call-forward-manual-input>.
      if (name == "allow-call-forward-manual-input") actions.insert("allow-call-fwd-manual-any");
      actions.insert(std::move(name));
    }
  };
  for (auto ruleset = root->children; ruleset; ruleset = ruleset->next) {
    if (!is(ruleset, "ruleset", common_policy_ns)) continue;
    for (auto rule = ruleset->children; rule; rule = rule->next) {
      if (!is(rule, "rule", common_policy_ns)) continue;
      for (auto list = rule->children; list; list = list->next)
        if (is(list, "actions", common_policy_ns)) collect(list);
    }
  }
  return actions;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1: reads an MCData user profile: its index (item 4), the MCData ID (<Common>/<MCDataUserID>,
// equal to "XUI-URI") and the granted rights of its ruleset (item 11 b).
McdataProfile parse_mcdata_profile(std::string_view xml) {
  auto doc = document(xml);
  const char *ns = nullptr;
  auto root = profile_root(doc.get(), &ns);
  if (ns != mcdata_profile_ns) invalid("not an MCData user profile");
  McdataProfile out;
  out.profile_index = profile_index_of(root);
  auto common = unique_child(root, "Common", ns);
  out.user_id = text(unique_child(unique_child(common, "MCDataUserID", ns), "uri-entry", ns));
  if (out.user_id.empty() || attr(root, "XUI-URI") != out.user_id) invalid("MCData user profile identity mismatch");
  out.actions = parse_profile_actions(xml);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1: reads an MCVideo user profile: its index, the MCVideo ID (equal to "XUI-URI"), the
// private call targets, the MCVideo groups of <OnNetwork> and the granted actions.
McvideoProfile parse_mcvideo_profile(std::string_view xml) {
  auto doc = document(xml);
  const char *ns = nullptr;
  auto root = profile_root(doc.get(), &ns);
  if (ns != mcvideo_profile_ns) invalid("not an MCVideo user profile");
  McvideoProfile out;
  out.profile_index = profile_index_of(root);
  const auto uri = [&](xmlNode *entry) { return text(unique_child(entry, "uri-entry", ns)); };
  auto common = unique_child(root, "Common", ns);
  out.user_id = uri(unique_child(common, "MCVideoUserID", ns));
  if (out.user_id.empty() || attr(root, "XUI-URI") != out.user_id) invalid("MCVideo user profile identity mismatch");
  if (auto call = unique_child(common, "PrivateCall", ns, false))
    for (auto entry = unique_child(call, "PrivateCallList", ns)->children; entry; entry = entry->next)
      if (is(entry, "PrivateCallOnNetwork", ns)) {
        if (out.private_call_targets.size() >= 256) invalid("too many private call targets");
        out.private_call_targets.push_back(uri(unique_child(entry, "PrivateCallURI", ns)));
      }
  for (auto on = root->children; on; on = on->next) {
    if (!is(on, "OnNetwork", ns)) continue;
    for (auto entry = on->children; entry; entry = entry->next)
      if (is(entry, "MCVideoGroupInfo", ns)) {
        if (out.groups.size() >= 256) invalid("too many MCVideo groups");
        out.groups.push_back(uri(unique_child(entry, "MCVideo-Group-ID", ns)));
      }
  }
  out.actions = parse_profile_actions(xml);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.484 clauses 8.4.2.1, 9.4.2.1 and 10.4.2.1: the resource priorities of a service configuration document.
std::map<std::string, std::string> parse_service_resource_priorities(std::string_view xml) {
  static const char *const namespaces[] = {"urn:3gpp:ns:mcpttServiceConfig:1.0", "urn:3gpp:ns:mcvideoServiceConfig:1.0",
                                           "urn:3gpp:ns:mcdataServiceConfig:1.0"};
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  const char *ns = nullptr;
  for (const auto *candidate : namespaces)
    if (is(root, "service-configuration-info", candidate)) ns = candidate;
  if (!ns) invalid("not a service configuration document");
  auto on = unique_child(unique_child(root, "service-configuration-params", ns), "on-network", ns);
  // The MCData document carries them in the <anyExt> of <on-network> (clause 10.4.2.1 item 4).
  auto holder = ns == namespaces[2] ? unique_child(on, "anyExt", ns) : on;
  std::map<std::string, std::string> out;
  for (const auto &[level, element] : {std::pair{"emergency", "emergency-resource-priority"},
                                       std::pair{"imminent", "imminent-peril-resource-priority"},
                                       std::pair{"normal", "normal-resource-priority"}}) {
    auto value = unique_child(holder, element, ns);
    const auto space = text(unique_child(value, "resource-priority-namespace", ns));
    const auto priority = text(unique_child(value, "resource-priority-priority", ns));
    // RFC 8101 section 3.2: mcpttp or mcpttq, levels 0 to 15.
    const bool level_ok = !priority.empty() && priority.size() <= 2 &&
                          priority.find_first_not_of("0123456789") == std::string::npos &&
                          (priority.size() == 1 || priority[0] != '0') && std::stoi(priority) <= 15;
    if ((space != "mcpttp" && space != "mcpttq") || !level_ok) invalid("resource priority not of RFC 8101");
    out[level] = space + "." + priority;
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: the <list-service> of a group document.
static xmlNode *group_list_service(xmlDoc *doc) {
  auto root = xmlDocGetRootElement(doc);
  if (!is(root, "group", poc_ns)) invalid("wrong group document root");
  return unique_child(root, "list-service", poc_ns);
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: a boolean MCS extension element of <list-service>; false when absent.
static bool group_flag(xmlNode *list_service, const char *name) {
  auto flag = unique_child(list_service, name, mcpttgi_ns, false);
  if (!flag) return false;
  const auto value = scalar(flag);
  if (value != "true" && value != "false" && value != "1" && value != "0")
    invalid((std::string("invalid ") + name + " value").c_str());
  return value == "true" || value == "1";
}

//------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: the <preconfigured-group-use-only> flag of a group document.
bool group_preconfigured_use_only(std::string_view xml) {
  auto doc = document(xml);
  return group_flag(group_list_service(doc.get()), "preconfigured-group-use-only");
}

//------------------------------------------------------------------------------
// TS 24.282 clause 14.2.1 with TS 24.481 clause 7.2.4.2: <mcdata-allow-enhanced-status> and the
// <status> entries of <mcdata-enhanced-status-operational-values>, each an <id>
// with its <shortText>.
EnhancedStatusValues group_enhanced_status(std::string_view xml) {
  auto doc = document(xml);
  auto list_service = group_list_service(doc.get());
  EnhancedStatusValues out;
  out.allowed = group_flag(list_service, "mcdata-allow-enhanced-status");
  if (auto list = unique_child(list_service, "mcdata-enhanced-status-operational-values", mcpttgi_ns, false)) {
    std::set<std::string> ids;
    for (auto node = list->children; node; node = node->next) {
      if (node->type != XML_ELEMENT_NODE) continue;
      if (!is(node, "status", mcpttgi_ns)) invalid("unknown enhanced status element");
      const auto id = scalar(unique_child(node, "id", mcpttgi_ns));
      if (id.empty() || id.find_first_not_of("0123456789") != std::string::npos || !ids.insert(id).second)
        invalid("missing, non-numeric or repeated operational value id");
      if (out.values.size() >= 64) invalid("too many operational values");
      auto text = unique_child(node, "shortText", mcpttgi_ns);
      out.values.emplace_back(id, scalar(unique_child(text, "langText", mcpttgi_ns)));
    }
  }
  return out;
}

} // namespace mcx
