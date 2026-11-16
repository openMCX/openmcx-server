//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

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
// TS 24.484 clause 8.3.2.3 (PrivateCallKMSURIEntryType): the <uri-entry> of the <PrivateCallKMSURI> entry of the
// <PrivateCallKMSURI> in an <anyExt>; empty when absent.
static std::string profile_private_call_kms(xmlNode *any_ext, const char *ns) {
  if (auto outer = unique_child(any_ext, "PrivateCallKMSURI", ns, false))
    if (auto inner = unique_child(outer, "PrivateCallKMSURI", ns, false))
      if (auto value = unique_child(inner, "uri-entry", ns, false)) return text(value);
  return {};
}

std::map<std::string, std::string> parse_profile_private_call_kms(std::string_view xml) {
  auto doc = document(xml);
  const char *ns = nullptr;
  auto root = profile_root(doc.get(), &ns);
  if (ns != profile_ns) invalid("not an MCPTT user profile");
  std::map<std::string, std::string> out;
  auto common = unique_child(root, "Common", ns, false);
  auto call = common ? unique_child(common, "PrivateCall", ns, false) : nullptr;
  auto list = call ? unique_child(call, "PrivateCallList", ns, false) : nullptr;
  if (!list) return out;
  // Item 8 d) i) C) I): the KMS URI of the MCPTT IDs of the list (clause 8.3.2.7).
  std::string common_kms;
  for (auto ext = list->children; ext; ext = ext->next)
    if (is(ext, "anyExt", ns))
      if (auto kms = profile_private_call_kms(ext, ns); !kms.empty()) common_kms = kms;
  // Item 8 d) i) A) I): the KMS URI of one target, present when it differs from the list's (clause 8.3.2.7).
  for (auto entry = list->children; entry; entry = entry->next) {
    if (!is(entry, "PrivateCallURI", ns)) continue;
    if (out.size() >= 256) invalid("too many private call targets");
    auto target = text(unique_child(entry, "uri-entry", ns));
    std::string kms;
    if (auto ext = unique_child(entry, "anyExt", ns, false)) kms = profile_private_call_kms(ext, ns);
    out[std::move(target)] = kms.empty() ? common_kms : kms;
  }
  return out;
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
  if (auto list = unique_child(common, "One-to-One-Communication", ns, false))
    for (auto entry = list->children; entry; entry = entry->next) {
      if (!is(entry, "One-to-One-CommunicationListEntry", ns)) continue;
      const auto id = text(unique_child(unique_child(entry, "MCData-ID", ns), "uri-entry", ns));
      std::string kms;
      if (auto uri = unique_child(entry, "MCData-ID-KMSURI", ns, false))
        if (auto inner = unique_child(uri, "uri-entry", ns, false)) kms = text(inner);
      if (!id.empty()) out.one_to_one_kms[id] = kms;
    }
  if (auto alert = unique_child(common, "GroupEmergencyAlert", ns, false))
    if (auto entry = unique_child(alert, "entry", ns, false)) {
      out.group_alert_entry_info = attr(entry, "entry-info");
      if (auto uri = unique_child(entry, "uri-entry", ns, false)) out.group_alert_uri = text(uri);
    }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1: reads an MCVideo user profile: its index, the MCVideo ID (equal to "XUI-URI"), the
// private call targets, the MCVideo groups of <OnNetwork> and the granted actions.
//------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.3: a <GeographicalAreaType> of a user profile: a <PolygonArea> of 3 to 15 <Corner>s or an
// <EllipsoidArcArea>, each point a <Longitude> and a <Latitude> coded as in TS 23.032 clause 6.1 (0 to 16777215).
static location::Area profile_area(xmlNode *node, const char *ns) {
  const auto coded = [&](xmlNode *parent, const char *name, std::uint32_t max) {
    const auto value = text(unique_child(parent, name, ns));
    if (value.empty() || value.size() > 10) invalid("invalid profile area coordinate or size");
    return static_cast<std::uint32_t>(number(value, max));
  };
  const auto point = [&](xmlNode *parent) {
    location::Point out;
    out.longitude = coded(parent, "Longitude", 0xffffff);
    out.latitude = coded(parent, "Latitude", 0xffffff);
    return out;
  };
  location::Area area;
  if (auto polygon = unique_child(node, "PolygonArea", ns, false)) {
    for (auto corner = polygon->children; corner; corner = corner->next)
      if (is(corner, "Corner", ns)) {
        if (area.polygon.size() >= 15) invalid("a polygon has 3 to 15 corners");
        area.polygon.push_back(point(corner));
      }
    if (area.polygon.size() < 3) invalid("a polygon has 3 to 15 corners");
  } else if (auto arc = unique_child(node, "EllipsoidArcArea", ns, false)) {
    area.center = point(unique_child(arc, "Center", ns));
    area.radius = coded(arc, "Radius", 0xffffffff);
    area.offset_angle = static_cast<std::uint8_t>(coded(arc, "OffsetAngle", 255));
    area.included_angle = static_cast<std::uint8_t>(coded(arc, "IncludedAngle", 255));
  } else {
    invalid("an area is a polygon or an ellipsoid arc");
  }
  return area;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 10: the <entry> elements of <FunctionalAliasList> in the <anyExt> of <OnNetwork>, with
// the location criteria and the manual deactivation lock of their <anyExt>.
static void profile_functional_aliases(xmlNode *on, const char *ns, McvideoProfile &out) {
  for (auto ext = on->children; ext; ext = ext->next) {
    if (!is(ext, "anyExt", ns)) continue;
    for (auto list = ext->children; list; list = list->next) {
      if (!is(list, "FunctionalAliasList", ns)) continue;
      for (auto entry = list->children; entry; entry = entry->next) {
        if (!is(entry, "entry", ns)) continue;
        if (out.functional_aliases.size() >= 256) invalid("too many functional aliases");
        McvideoProfile::FunctionalAlias alias;
        alias.alias = text(unique_child(entry, "uri-entry", ns));
        if (alias.alias.empty()) invalid("a functional alias entry without its URI");
        if (auto entry_ext = unique_child(entry, "anyExt", ns, false))
          for (auto node = entry_ext->children; node; node = node->next) {
            const bool activation = is(node, "LocationCriteriaForActivation", ns);
            if (activation || is(node, "LocationCriteriaForDeactivation", ns)) {
              for (auto area = node->children; area; area = area->next) {
                const bool entry_area = is(area, "EnterSpecificArea", ns);
                if (!entry_area && !is(area, "ExitSpecificArea", ns)) continue;
                auto &areas = activation ? (entry_area ? alias.activate_on_entry : alias.activate_on_exit)
                                         : (entry_area ? alias.deactivate_on_entry : alias.deactivate_on_exit);
                if (areas.size() >= 16) invalid("too many functional alias location criteria");
                areas.push_back(profile_area(area, ns));
              }
            } else if (is(node, "manual-deactivation-not-allowed-if-location-criteria-met", ns)) {
              const auto value = text(node);
              alias.manual_deactivation_locked = value == "true" || value == "1";
            }
          }
        out.functional_aliases.push_back(std::move(alias));
      }
    }
  }
}

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
        // TS 24.484 clause 9.3.2.1 item 8 d) (schema PrivateCallKMSURIEntryType): <PrivateCallKMSURI> with one
        // <PrivateCallKMSURI> <entry> holding the <uri-entry>; TS 24.281 clause 6.2.8.3.9 1) a).
        std::string kms;
        if (auto outer = unique_child(entry, "PrivateCallKMSURI", ns, false))
          if (auto inner = unique_child(outer, "PrivateCallKMSURI", ns, false))
            if (auto value = unique_child(inner, "uri-entry", ns, false)) kms = text(value);
        out.private_call_kms[out.private_call_targets.back()] = kms;
      }
  for (auto on = root->children; on; on = on->next) {
    if (!is(on, "OnNetwork", ns)) continue;
    for (auto entry = on->children; entry; entry = entry->next)
      if (is(entry, "MCVideoGroupInfo", ns)) {
        if (out.groups.size() >= 256) invalid("too many MCVideo groups");
        out.groups.push_back(uri(unique_child(entry, "MCVideo-Group-ID", ns)));
      }
    profile_functional_aliases(on, ns, out);
  }
  // TS 24.484 clause 9.3.2.3: the EntryType <entry> of a target element, with its "entry-info" and <uri-entry>
  // (absent for "UseCurrentlySelectedGroup" and "LocallyDetermined", which name no target).
  const auto target = [&](xmlNode *holder, const char *name) {
    McvideoProfile::TargetEntry out;
    if (!holder) return out;
    auto element = unique_child(holder, name, ns, false);
    if (!element) return out;
    auto entry = unique_child(element, "entry", ns, false);
    if (!entry) return out;
    out.present = true;
    out.entry_info = attr(entry, "entry-info");
    if (auto uri_entry = unique_child(entry, "uri-entry", ns, false)) out.uri = text(uri_entry);
    if (out.entry_info.size() > 64 || out.uri.size() > 1024) invalid("invalid profile target entry");
    return out;
  };
  // Item 8 e): <MCVideo-group-call> with <EmergencyCall>, <ImminentPerilCall> (each an <MCVideoGroupInitiation>) and
  // <EmergencyAlert>.
  if (auto group_call = unique_child(common, "MCVideo-group-call", ns, false)) {
    out.emergency_group_initiation = target(unique_child(group_call, "EmergencyCall", ns, false), "MCVideoGroupInitiation");
    out.imminent_group_initiation =
        target(unique_child(group_call, "ImminentPerilCall", ns, false), "MCVideoGroupInitiation");
    out.group_emergency_alert = target(group_call, "EmergencyAlert");
    // Item 8 e) v): <Priority>, PriorityType 0 to 255.
    if (auto priority = unique_child(group_call, "Priority", ns, false)) {
      const auto value = scalar(priority);
      if (value.empty() || value.size() > 3) invalid("invalid MCVideo group call priority");
      out.group_call_priority = number(value, 255);
    }
  }
  // Item 8 d) ii): <PrivateCall>/<EmergencyCall>/<MCVideoPrivateRecipient>.
  if (auto call = unique_child(common, "PrivateCall", ns, false))
    out.emergency_private_recipient = target(unique_child(call, "EmergencyCall", ns, false), "MCVideoPrivateRecipient");
  // Item 9 f): <OnNetwork>/<PrivateEmergencyAlert> (the first <OnNetwork> carrying one).
  for (auto on = root->children; on && !out.private_emergency_alert.present; on = on->next)
    if (is(on, "OnNetwork", ns)) out.private_emergency_alert = target(on, "PrivateEmergencyAlert");
  out.actions = parse_profile_actions(xml);

  return out;
}

//------------------------------------------------------------------------------
// TS 24.484 clauses 8.4.2.1, 9.4.2.1 and 10.4.2.1: the namespaces of the MCPTT, MCVideo and MCData service
// configuration documents.
static const char *const service_config_namespaces[] = {"urn:3gpp:ns:mcpttServiceConfig:1.0",
                                                        "urn:3gpp:ns:mcvideoServiceConfig:1.0",
                                                        "urn:3gpp:ns:mcdataServiceConfig:1.0"};

//------------------------------------------------------------------------------
// Helper: the <on-network> element of a service configuration document and the document's namespace.
static std::pair<xmlNode *, const char *> service_on_network(xmlDoc *doc) {
  auto root = xmlDocGetRootElement(doc);
  const char *ns = nullptr;
  for (const auto *candidate : service_config_namespaces)
    if (is(root, "service-configuration-info", candidate)) ns = candidate;
  if (!ns) invalid("not a service configuration document");
  return {unique_child(unique_child(root, "service-configuration-params", ns), "on-network", ns), ns};
}

//------------------------------------------------------------------------------
// TS 24.484 clauses 8.4.2.1, 9.4.2.1 and 10.4.2.1: the resource priorities of a service configuration document.
std::map<std::string, std::string> parse_service_resource_priorities(std::string_view xml) {
  const auto *const *namespaces = service_config_namespaces;
  auto doc = document(xml);
  const auto [on, ns] = service_on_network(doc.get());

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
// TS 24.484 clauses 8.4.2.1 items 8 and 12, 9.4.2.1 items 1 and 2, 10.4.2.1 items 2 and 3: the signalling protection
// of a service configuration document. Each value is true when its element is "true" or absent (TS 24.379 clauses
// 6.6.2.3.1, 6.6.2.3.2, 6.6.3.3.1 and 6.6.3.3.2: "is set to "true" or no <confidentiality-protection> element is
// present in the Service Configuration document"; TS 24.281 and TS 24.282 likewise; TS 24.484 clause 8.4.2.7 NOTE 4,
// 9.4.2.7 NOTE 1, 10.4.2.7 NOTE 1: the default values are "true"), false only when it is "false".
ServiceProtection parse_service_protection(std::string_view xml) {
  auto doc = document(xml);
  const auto [on, ns] = service_on_network(doc.get());
  const auto flag = [ns](xmlNode *parent, const char *name) {
    auto element = parent ? unique_child(parent, name, ns, false) : nullptr;
    if (!element) return true;
    // xs:boolean: "true", "false", "1" or "0".
    const auto value = scalar(element);
    if (value != "true" && value != "false" && value != "1" && value != "0")
      invalid((std::string("invalid ") + name + " value").c_str());
    return value == "true" || value == "1";
  };
  const bool mcptt = ns == service_config_namespaces[0], mcvideo = ns == service_config_namespaces[1];
  auto signalling = unique_child(on, "signalling-protection", ns, false);
  auto between = unique_child(on,
                              mcptt     ? "protection-between-mcptt-servers"
                              : mcvideo ? "protection-between-mcvideo-servers"
                                        : "protection-between-mcdata-servers",
                              ns, false);
  ServiceProtection out;
  out.confidentiality = flag(signalling, "confidentiality-protection");
  out.integrity = flag(signalling, "integrity-protection");
  out.between_servers = flag(between, "allow-signalling-protection");
  // MCData has no control signalling between its servers (clause 10.4.2.1 item 3).
  if (mcptt || mcvideo)
    out.between_servers_control =
        flag(between, mcptt ? "allow-floor-control-protection" : "allow-transmission-control-protection");
  return out;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 9.4.2.1 item c and 9.4.2.6 (clause 8.4.2.1 for MCPTT): the <adhoc-group-call> of the <anyExt> of
// <on-network>. Absent, ad hoc group calls are not supported; present, <allow-adhoc-group-call-support> says whether
// they are (TS 24.281 clause 22.2.2.1.1: the client skips the procedure when it is absent or "false").
ServiceAdhoc parse_service_adhoc(std::string_view xml) {
  auto doc = document(xml);
  const auto [on, ns] = service_on_network(doc.get());
  ServiceAdhoc out;
  for (auto ext = on->children; ext; ext = ext->next) {
    if (!is(ext, "anyExt", ns)) continue;
    auto adhoc = unique_child(ext, "adhoc-group-call", ns, false);
    if (!adhoc) continue;
    const auto allow = scalar(unique_child(adhoc, "allow-adhoc-group-call-support", ns));
    if (allow != "true" && allow != "false" && allow != "1" && allow != "0")
      invalid("invalid allow-adhoc-group-call-support value");
    out.supported = allow == "true" || allow == "1";
    if (auto max = unique_child(adhoc, "max-no-participants", ns, false))
      out.max_participants = number(scalar(max), 65535);
  }
  return out;
}

//------------------------------------------------------------------------------
McDataTxRxLimits parse_mcdata_tx_limits(std::string_view xml) {
  auto doc = document(xml);
  const auto [on, ns] = service_on_network(doc.get());
  McDataTxRxLimits out;
  auto control = unique_child(on, "tx-and-rx-control", ns, false);
  if (!control) return out;
  const auto value = [&](const char *name) -> std::optional<std::uint64_t> {
    auto element = unique_child(control, name, ns, false);
    if (!element) return std::nullopt;
    return number(scalar(element), 0xFFFFFFFFull); // xs:unsignedInt
  };
  out.max_data_size_sds = value("max-data-size-sds-bytes");
  out.max_payload_size_sds_cplane = value("max-payload-size-sds-cplane-bytes");
  out.max_data_size_fd = value("max-data-size-fd-bytes");
  out.max_data_size_auto_recv = value("max-data-size-auto-recv-bytes");
  return out;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 7.2.2.1 item 4: <mcptt-UE-initial-configuration> (clause 7.2.2.2 namespace) / <on-network> /
// <GMS-URI>, mandatory.
std::string parse_initial_gms_uri(std::string_view xml) {
  static constexpr const char *ns = "urn:3gpp:mcptt:mcpttUEinitConfig:1.0";
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "mcptt-UE-initial-configuration", ns)) invalid("wrong UE initial configuration root");
  const auto uri = scalar(unique_child(unique_child(root, "on-network", ns), "GMS-URI", ns));
  if (uri.empty()) invalid("empty GMS-URI");
  return uri;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 7.2.2.1 item 3 c), g): <on-network> / <App-Server-Info> / <http-proxy> and <tls-tunnel-auth-method>
// / <mutual-authentication> (xs:boolean, XML Schema Part 2 section 3.2.2: "true", "false", "1", "0").
InitialHttpProxy parse_initial_http_proxy(std::string_view xml) {
  static constexpr const char *ns = "urn:3gpp:mcptt:mcpttUEinitConfig:1.0";
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "mcptt-UE-initial-configuration", ns)) invalid("wrong UE initial configuration root");
  auto server_info = unique_child(unique_child(root, "on-network", ns), "App-Server-Info", ns);
  InitialHttpProxy out;
  out.uri = scalar(unique_child(server_info, "http-proxy", ns));
  const auto mutual = scalar(unique_child(unique_child(server_info, "tls-tunnel-auth-method", ns), "mutual-authentication", ns));
  if (mutual != "true" && mutual != "false" && mutual != "1" && mutual != "0") invalid("invalid mutual-authentication");
  out.mutual = mutual == "true" || mutual == "1";
  return out;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 7.2.2.1 item 3 f): <on-network> / <App-Server-Info> / <kms>, mandatory.
std::string parse_initial_kms(std::string_view xml) {
  static constexpr const char *ns = "urn:3gpp:mcptt:mcpttUEinitConfig:1.0";
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "mcptt-UE-initial-configuration", ns)) invalid("wrong UE initial configuration root");
  return scalar(unique_child(unique_child(unique_child(root, "on-network", ns), "App-Server-Info", ns), "kms", ns));
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
std::vector<std::string> group_temporary_constituents(std::string_view xml) {
  auto doc = document(xml);
  auto list_service = group_list_service(doc.get());
  std::vector<std::string> out;
  if (auto temporary = unique_child(list_service, "on-network-temporary", mcpttgi_ns, false))
    if (auto ids = unique_child(temporary, "constituent-MCPTT-group-IDs", mcpttgi_ns, false))
      for (auto id = ids->children; id; id = id->next)
        if (is(id, "constituent-MCPTT-group-ID", mcpttgi_ns)) out.push_back(text(id));
  return out;
}

//------------------------------------------------------------------------------
std::vector<std::string> group_regrouped_tgis(std::string_view xml) {
  auto doc = document(xml);
  auto list_service = group_list_service(doc.get());
  std::vector<std::string> out;
  for (auto node = list_service->children; node; node = node->next)
    if (is(node, "on-network-regrouped", mcpttgi_ns))
      if (const auto tgi = attr(node, "temporary-MCPTT-group-ID"); !tgi.empty()) out.push_back(tgi);
  return out;
}

//------------------------------------------------------------------------------
McdataGroupSds parse_mcdata_group_sds(std::string_view xml) {
  auto doc = document(xml);
  auto list_service = group_list_service(doc.get());
  McdataGroupSds out;
  out.allow_sds = group_flag(list_service, "mcdata-allow-short-data-service");
  out.preconfigured_use_only = group_flag(list_service, "preconfigured-group-use-only");
  if (auto max = unique_child(list_service, "mcdata-on-network-max-data-size-for-SDS", mcpttgi_ns, false))
    out.max_sds_bytes = number(scalar(max), 0xFFFFFFFFull);
  if (auto fd = unique_child(list_service, "mcdata-allow-file-distribution", mcpttgi_ns, false))
    out.allow_fd = scalar(fd) == "true" || scalar(fd) == "1";
  if (auto max = unique_child(list_service, "mcdata-on-network-max-data-size-for-FD", mcpttgi_ns, false))
    out.max_fd_bytes = number(scalar(max), 0xFFFFFFFFull);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.481 clauses 7.2.2 (the <ruleset>, <rule>, <conditions> with <identity> and <is-list-member>, <actions>),
// 7.2.8 (a condition element not specified is evaluated as not known, RFC 4745: the rule does not apply) and RFC 4745
// sections 7.1 (<identity>/<one id>), 10.1 (a rule applies when all its conditions match) and 10.2 (boolean
// permissions combine by OR).
bool group_document_allows(std::string_view xml, std::string_view action, const std::vector<std::string> &identities) {
  auto doc = document(xml);
  auto list_service = group_list_service(doc.get());
  const auto mine = [&](const std::string &id) {
    return !id.empty() && std::find(identities.begin(), identities.end(), id) != identities.end();
  };
  // <is-list-member>: the user is an <entry> of the <list>, by its "uri" or its MCVideo / MCData ID (clause 7.2.2).
  bool member = false;
  if (auto list = unique_child(list_service, "list", poc_ns, false))
    for (auto entry = list->children; entry && !member; entry = entry->next) {
      if (!is(entry, "entry", poc_ns)) continue;
      member = mine(attr(entry, "uri"));
      for (auto id = entry->children; id && !member; id = id->next)
        if (is(id, "mcvideo-mcvideo-id", mcpttgi_ns) || is(id, "mcdata-mcdata-id", mcpttgi_ns))
          member = mine(attr(id, "uri"));
    }
  auto ruleset = unique_child(list_service, "ruleset", common_policy_ns, false);
  if (!ruleset) return false;
  for (auto rule = ruleset->children; rule; rule = rule->next) {
    if (!is(rule, "rule", common_policy_ns)) continue;
    bool applies = true;
    if (auto conditions = unique_child(rule, "conditions", common_policy_ns, false))
      for (auto condition = conditions->children; condition && applies; condition = condition->next) {
        if (condition->type != XML_ELEMENT_NODE) continue;
        if (is(condition, "identity", common_policy_ns)) {
          bool listed = false;
          for (auto one = condition->children; one && !listed; one = one->next)
            if (is(one, "one", common_policy_ns)) listed = mine(attr(one, "id"));
          applies = listed;
        } else if (is(condition, "is-list-member", poc_ns)) {
          applies = member;
        } else {
          applies = false;
        }
      }
    if (!applies) continue;
    auto actions = unique_child(rule, "actions", common_policy_ns, false);
    if (!actions) continue;
    for (auto element = actions->children; element; element = element->next) {
      if (element->type != XML_ELEMENT_NODE || !element->ns || !xmlStrEqual(element->ns->href, BAD_CAST mcpttgi_ns) ||
          action != reinterpret_cast<const char *>(element->name))
        continue;
      auto value = scalar(element);
      value.erase(0, value.find_first_not_of(" \t\r\n"));
      value.erase(value.find_last_not_of(" \t\r\n") + 1);
      if (value == "true" || value == "1") return true;
    }
  }
  return false;
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
