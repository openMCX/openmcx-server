// MC service information documents (<mcpttinfo>, <mcvideoinfo>) with their private call service elements, and the
// regroup documents.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 3891,
// RFC 8101, RFC 4412.

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: the private call service <anyExt> elements, in schema order, with
// the enumerated values the schema allows (empty set = free text or URI). (The releaseReasonType enumeration of
// TS 24.379 is release_reasons.)
const std::vector<std::pair<std::string, std::set<std::string>>> &service_elements() {
  static const std::vector<std::pair<std::string, std::set<std::string>>> elements{
      {"request-type",
       {"private-call-call-back-request", "private-call-call-back-cancel-request",
        "remotely-initiated-private-call-request", "remotely-initiated-group-call-request",
        "transfer-private-call-request", "forward-private-call-request", "fa-group-binding-req",
        "group-selection-change-request", "functional-alias-status-determination"}},
      {"response-type",
       {"private-call-call-back-response", "private-call-call-back-cancel-response",
        "remotely-initiated-private-call-response", "remotely-initiated-group-call-response",
        "transfer-private-call-response", "forward-private-call-response", "group-selection-change-response"}},
      {"urgency-ind", {"low", "normal", "high"}},
      {"time-of-request", {}},
      {"notify-remote-user", {"true", "false"}},
      {"ric-app-level-priority", {}},
      {"ric-commencement-mode", {"force-auto-mode", "auto-mode", "manual-mode"}},
      {"remotely-initiated-call-outcome", {"success", "fail"}},
      {"call-transfer-ind", {"true", "false"}},
      {"transfer-call-outcome", {"success", "fail"}},
      // Announced transfer (TS 24.379 clause 11.1.8.2.3): the indication on the call to the
      // target, and the target's dialog (RFC 3891 Replaces value) in its answer.
      {"transfer-announced-ind", {"true", "false"}},
      {"replaces-header-value", {}},
      {"call-forwarding-ind", {"true", "false"}},
      {"forwarding-reason", {"immediate", "no-answer", "manual-input"}},
      {"forwarded-by-mcptt-id", {}},
      {"forwarding-target-id", {}},
      {"forwarding-target-orig-id", {}},
      {"forwarding-call-outcome", {"success", "fail"}},
      // Functional alias status determination (TS 24.379 clause 9A.2.1.3, TS 24.281 clause 20.2.1.3).
      {"req-type",
       {"mc-service-authorisation-notify-request", "functional-alias-status-determination",
        "fa-user-status-determination"}},
      {"mc-service-auth-result", {"true", "false"}},
      // Functional alias to group binding (TS 24.379 clause 9A.4.2.1, TS 24.281 clause 20.4.2.1).
      {"binding-ind", {"true", "false"}},
      {"binding-fa-uri", {}},
      {"unbinding-fa-uri", {}},
      // Remote change of the selected group (TS 24.379 clause 10.1.4, TS 24.281 clause 9.2.4).
      {"selected-group-change-outcome", {"success", "fail"}},
      {"affiliation-required", {"true", "false"}}};
  return elements;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.3: checks the value of a private call service element against its enumeration, URI, Replaces
// (RFC 3891) or priority (RFC 8101) syntax; an unknown element is refused.
void check_service_value(const std::string &name, const std::string &value) {
  for (const auto &[element, allowed] : service_elements())
    if (element == name) {
      if (value.empty() || value.size() > 256 || (!allowed.empty() && !allowed.contains(value)))
        invalid(("invalid " + name + " value").c_str());
      if (name.ends_with("-id") || name.ends_with("-fa-uri")) conference_uri(value);
      // RFC 3891: Call-ID ";to-tag=" tag ";from-tag=" tag, carried into a header.
      if (name == "replaces-header-value" &&
          (value.find_first_of("\r\n,<>\" ") != std::string::npos || value.find(";to-tag=") == std::string::npos ||
           value.find(";from-tag=") == std::string::npos || value.front() == ';'))
        invalid("invalid replaces-header-value");
      // RFC 8101 / RFC 4412 r-value: namespace "." priority.
      if (name == "ric-app-level-priority") {
        const auto dot = value.find('.');
        const auto token = [](std::string_view part, bool digits) {
          return !part.empty() && std::all_of(part.begin(), part.end(), [digits](unsigned char character) {
            return digits ? std::isdigit(character) != 0 : std::isalnum(character) != 0 || character == '-';
          });
        };
        if (dot == std::string::npos || !token(std::string_view(value).substr(0, dot), false) ||
            !token(std::string_view(value).substr(dot + 1), true))
          invalid("invalid ric-app-level-priority value");
      }
      return;
    }
  invalid(("unsupported private call service element " + name).c_str());
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: writes the <mcpttinfo> or <mcvideoinfo> document of the service:
// the <mcptt-Params> or <mcvideo-Params> elements and their <anyExt> extensions.
std::string service_info_xml(const McpttInfo &info, const ServiceProfile &service) {
  const InfoNames names(service);
  std::string out = "<?xml version=\"1.0\"?><" + names.root + " xmlns=\"" + names.ns + "\"><" + names.params + ">";
  out += wrapped(names.element("access-token"), names.str, info.access_token);
  if (!info.session_type.empty()) out += "<session-type>" + xml_escape(info.session_type) + "</session-type>";
  out += wrapped(names.element("request-uri"), names.uri, info.request_uri);
  out += wrapped(names.element("calling-user-id"), names.uri, info.calling_user);
  out += wrapped(names.element("called-party-id"), names.uri, info.called_party);
  out += wrapped(names.element("calling-group-id"), names.uri, info.calling_group);
  const auto flag = [&](const char *name, std::optional<bool> value) {
    if (!value) return;
    if (std::string_view(name) == "broadcast-ind")
      out += "<broadcast-ind>" + std::string(*value ? "true" : "false") + "</broadcast-ind>";
    else
      out += wrapped(name, names.boolean, *value ? "true" : "false");
  };
  flag("emergency-ind", info.emergency);
  flag("alert-ind", info.alert);
  flag("imminentperil-ind", info.imminent_peril);
  flag("broadcast-ind", info.broadcast);
  // TS 24.379 annex F.1.2: <associated-group-id> is a contentType (wrapped in <mcpttURI>); TS 24.281 annex F.1.2 types
  // it xs:string, so the MCVideo element holds the group identity as its text.
  if (names.prefix == "mcvideo") {
    if (!info.associated_group.empty())
      out += "<associated-group-id>" + xml_escape(info.associated_group) + "</associated-group-id>";
  } else {
    out += wrapped("associated-group-id", names.uri, info.associated_group);
  }
  out += wrapped("originated-by", names.uri, info.originated_by);
  out += wrapped(names.element("client-id"), names.str, info.client_id);
  flag("alert-ind-rcvd", info.alert_received);
  flag("emergency-ind-rcvd", info.emergency_received);
  out += wrapped("video-pull-url", names.uri, info.video_pull_url);
  std::string ext;
  if (!info.ambient_listening_type.empty()) {
    if (info.ambient_listening_type != "remote-init" && info.ambient_listening_type != "local-init")
      invalid("unsupported ambient listening type");
    ext += "<" + names.ambient + ">" + info.ambient_listening_type + "</" + names.ambient + ">";
  }
  if (!info.release_reason.empty()) {
    if (!release_reasons.contains(info.release_reason)) invalid("unsupported release reason");
    ext += "<release-reason>" + xml_escape(info.release_reason) + "</release-reason>";
  }
  const auto plain = [&](const char *name, std::optional<bool> value) {
    if (value) ext += std::string("<") + name + ">" + (*value ? "true" : "false") + "</" + name + ">";
  };
  if (!info.video_push_url.empty()) ext += "<video-push-url>" + xml_escape(info.video_push_url) + "</video-push-url>";
  if (!info.participant_criteria.empty())
    ext += "<" + names.criteria + ">" + xml_escape(info.participant_criteria) + "</" + names.criteria + ">";
  // contentType in TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: the URI in <mcpttURI> or <mcvideoURI>.
  const auto uri = [&](const char *name, const std::string &value) {
    if (value.empty()) return;
    conference_uri(value);
    ext += wrapped(name, names.uri, value);
  };
  uri("functional-alias-URI", info.functional_alias);
  uri("called-functional-alias-URI", info.called_functional_alias);
  plain("call-to-functional-alias-ind", info.call_to_functional_alias);
  plain("emergency-alert-area-ind", info.emergency_alert_area);
  plain("group-geo-area-ind", info.group_geo_area);
  if (!info.location_of_functional_alias.empty()) {
    conference_uri(info.location_of_functional_alias);
    ext += wrapped("location-of-functional-alias-URI", names.uri, info.location_of_functional_alias); // contentType
  }
  // Every element is checked once, unknown ones refused; they are then written in schema order.
  for (const auto &[name, value] : info.service) check_service_value(name, value);
  for (const auto &element : service_elements()) {
    const auto &name = element.first;
    const auto found = info.service.find(name);
    if (found == info.service.end()) continue;
    // TS 24.379 annex F.1.2: <selected-user-profile-index> holds a <user-profile-index>; marked \"Normal\"
    // so that its content can be encrypted (TS 24.379 clause 7A.2.1).
    if (name == "selected-user-profile-index")
      ext += "<selected-user-profile-index type=\"Normal\"><user-profile-index>" + xml_escape(found->second) +
             "</user-profile-index></selected-user-profile-index>";
    else
      ext += "<" + name + ">" + xml_escape(found->second) + "</" + name + ">";
  }
  if (!info.private_call_kms_uri.empty()) {
    conference_uri(info.private_call_kms_uri);
    ext += "<PrivateCallKMSURI><PrivateCallKMSURI><uri-entry>" + xml_escape(info.private_call_kms_uri) +
           "</uri-entry></PrivateCallKMSURI></PrivateCallKMSURI>";
  }
  plain("adhoc-emergency-ind", info.adhoc_emergency);
  plain("adhoc-alert-ind", info.adhoc_alert);
  plain("adhoc-grp-emg-alert-grp-ind", info.adhoc_emergency_alert_group);
  plain("adhoc-alert-ind-rcvd", info.adhoc_alert_received);
  if (!ext.empty()) out += "<anyExt>" + ext + "</anyExt>";
  out += "</" + names.params + "></" + names.root + ">";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2: writes the <mcpttinfo> document.
std::string mcptt_info_xml(const McpttInfo &info) { return service_info_xml(info, mcptt_service); }

//------------------------------------------------------------------------------
// TS 24.379 annex F.7.4 (TS 24.281 annex F.6.4, TS 24.282 annex D.6.4): the regroup MIME type of the service, for
// the <mcpttregroup> of annex F.7.2 with the parameters of TS 24.379 clause 16.
std::string regroup_mime_of(const ServiceProfile &service) {
  return std::string("application/vnd.3gpp.") + service.info_prefix + "-regroup+xml";
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.7.2 (TS 24.281 annex F.6.2, TS 24.282 annex D.6.2): writes a regroup document: the
// preconfigured group, the regroup URI, the groups or the users, and the action.
std::string regroup_xml(const Regroup &regroup, const ServiceProfile &service) {
  const std::string root = std::string(service.info_prefix) + "regroup",
                    uri = std::string(service.info_prefix) + "-regroup-uri";
  if (regroup.action != "create" && regroup.action != "remove") invalid("unsupported regroup action");
  const bool create = regroup.action == "create";
  if (regroup.regroup_uri.empty() || (create && regroup.preconfigured_group.empty())) invalid("incomplete regroup");
  if (!regroup.groups.empty() && !regroup.users.empty()) invalid("a regroup names groups or users, not both");
  if (create && regroup.groups.empty() && regroup.users.empty()) invalid("a regroup names groups or users");
  // Every identity is a URI (TS 24.379 annex F.7.2: the group and user IDs and the regroup URI are anyURI).
  conference_uri(regroup.regroup_uri);
  if (!regroup.preconfigured_group.empty()) conference_uri(regroup.preconfigured_group);
  for (const auto &group : regroup.groups) conference_uri(group);
  for (const auto &user : regroup.users) conference_uri(user);
  // <preconfigured-group> is optional (TS 24.379 annex F.7.2); a removal may leave it out.
  std::string out = "<?xml version=\"1.0\"?><" + root + " xmlns=\"" + std::string(regroup_ns) + "\"><" + root +
                    "-Params><preconfig-group-id>";
  if (!regroup.preconfigured_group.empty())
    out += "<preconfigured-group>" + xml_escape(regroup.preconfigured_group) + "</preconfigured-group>";
  out += "</preconfig-group-id><" + uri + "><" + uri + ">" + xml_escape(regroup.regroup_uri) + "</" + uri + "></" +
         uri + ">";
  if (!regroup.groups.empty()) {
    out += "<groups-for-regroup>";
    for (const auto &group : regroup.groups) out += "<group>" + xml_escape(group) + "</group>";
    out += "</groups-for-regroup>";
  }
  if (!regroup.users.empty()) {
    out += "<users-for-regroup>";
    for (const auto &user : regroup.users) out += "<user>" + xml_escape(user) + "</user>";
    out += "</users-for-regroup>";
  }
  out += "<regroup-action>" + regroup.action + "</regroup-action></" + root + "-Params></" + root + ">";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.7.2 and annex F.7.3 (TS 24.281 annex F.6, TS 24.282 annex D.6): reads a regroup document.
Regroup parse_regroup(std::string_view xml, const ServiceProfile &service) {
  const std::string root_name = std::string(service.info_prefix) + "regroup",
                    uri = std::string(service.info_prefix) + "-regroup-uri";
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, root_name.c_str(), regroup_ns)) invalid("wrong regroup root namespace");
  auto params = unique_child(root, (root_name + "-Params").c_str(), regroup_ns);
  Regroup out;
  out.action = text(unique_child(params, "regroup-action", regroup_ns));
  if (out.action != "create" && out.action != "remove") invalid("unsupported regroup action");
  const bool create = out.action == "create";
  if (auto group = unique_child(unique_child(params, "preconfig-group-id", regroup_ns), "preconfigured-group",
                                regroup_ns, false))
    out.preconfigured_group = text(group);
  out.regroup_uri = text(unique_child(unique_child(params, uri.c_str(), regroup_ns), uri.c_str(), regroup_ns));
  if (out.regroup_uri.empty() || (create && out.preconfigured_group.empty())) invalid("incomplete regroup");
  const auto list = [&](const char *container, const char *item, std::vector<std::string> &into) {
    auto node = unique_child(params, container, regroup_ns, false);
    if (!node) return;
    for (auto *child = node->children; child; child = child->next)
      if (is(child, item, regroup_ns)) {
        auto value = text(child);
        if (value.empty()) invalid("empty regroup entry");
        if (std::find(into.begin(), into.end(), value) != into.end()) invalid("duplicate regroup entry");
        if (into.size() >= 64) invalid("too many regroup entries");
        into.push_back(std::move(value));
      }
  };
  list("groups-for-regroup", "group", out.groups);
  list("users-for-regroup", "user", out.users);
  // TS 24.379 annex F.7.3: groups or users, not both. A removal names neither (TS 24.379 clause 16.2.1.2 step 9,
  // clause 16.2.2.5 step 3 e, clause 16.2.3.3), or the users it concerns (clause 16.2.3.2 step 6 f).
  if (!out.groups.empty() && !out.users.empty()) invalid("a regroup names groups or users, not both");
  if (create && out.groups.empty() && out.users.empty()) invalid("a regroup names groups or users");
  return out;
}

namespace {

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: the value of an optional element of <mcpttinfo-Params>, its
// contentType wrapper read when wrap is set; empty when absent.
std::string info_value(xmlNode *params, std::string_view name, bool wrap, const InfoNames &names) {
  const char *info_ns = names.ns.c_str();
  auto node = unique_child(params, std::string(name).c_str(), info_ns, false);
  return node ? (wrap ? content(node, names) : text(node)) : "";
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: <associated-group-id>, wrapped in <mcpttURI> (MCPTT
// contentType) or as plain text (MCVideo xs:string); either form is read.
std::string associated_group_id(xmlNode *parent, const InfoNames &names) {
  auto node = unique_child(parent, "associated-group-id", names.ns.c_str(), false);
  if (!node) return {};
  for (auto child = node->children; child; child = child->next)
    if (child->type == XML_ELEMENT_NODE) return content(node, names);
  return scalar(node);
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: an optional boolean of <mcpttinfo-Params>, wrapped in
// <mcpttBoolean> (unprotected) except <broadcast-ind>.
std::optional<bool> info_flag(xmlNode *params, const char *name, const InfoNames &names) {
  const char *info_ns = names.ns.c_str();
  auto node = unique_child(params, name, info_ns, false);
  if (!node) return std::nullopt;
  const bool wrapped_boolean = std::string_view(name) != "broadcast-ind";
  if (wrapped_boolean) {
    const auto protection = attr(node, "type");
    if (!protection.empty() && protection != "Normal") invalid("unsupported MCPTT boolean protection");
    for (auto child = node->children; child; child = child->next)
      if (child->type == XML_ELEMENT_NODE && !is(child, names.boolean.c_str(), info_ns))
        invalid("invalid MCPTT boolean content wrapper");
  }
  const auto value = wrapped_boolean ? scalar(unique_child(node, names.boolean.c_str(), info_ns)) : scalar(node);
  if (value == "true" || value == "1") return true;
  if (value == "false" || value == "0") return false;
  invalid("invalid MCPTT boolean");
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: an optional plain boolean of <anyExt>.
std::optional<bool> ext_flag(xmlNode *ext, const char *name, const char *info_ns) {
  auto node = unique_child(ext, name, info_ns, false);
  if (!node) return std::nullopt;
  const auto value = scalar(node);
  if (value == "true" || value == "1") return true;
  if (value == "false" || value == "0") return false;
  invalid("invalid MCPTT boolean");
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: an optional URI of <anyExt>: a contentType URI; a bare URI, as
// this codec once sent, is still accepted.
std::string ext_uri(xmlNode *ext, const char *name, const InfoNames &names) {
  const char *info_ns = names.ns.c_str();
  auto node = unique_child(ext, name, info_ns, false);
  if (!node) return std::string{};
  bool nested = false;
  for (auto child = node->children; child; child = child->next) nested = nested || child->type == XML_ELEMENT_NODE;
  auto value = nested ? content(node, names) : scalar(node);
  conference_uri(value);
  return value;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: the private call service elements of <anyExt>, each checked
// against the values its schema allows.
void parse_service_elements(xmlNode *ext, const char *info_ns, McpttInfo &out) {
  for (const auto &element : service_elements())
    if (const auto &name = element.first; auto node = unique_child(ext, name.c_str(), info_ns, false)) {
      if (name == "selected-user-profile-index") {
        if (attr(node, "type") == "Encrypted") invalid("MIKEY/XML protected profile is unavailable");
        if (auto index = unique_child(node, "user-profile-index", info_ns, false)) node = index;
      }
      const auto value = scalar(node);
      check_service_value(name, value);
      out.service[name] = value;
    }
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: the <anyExt> extensions: video push URL, ambient listening or
// viewing type, release reason, participant criteria, private call service elements, functional aliases, the
// private call KMS URI and the ad hoc group indications.
void parse_info_extensions(xmlNode *ext, const InfoNames &names, McpttInfo &out) {
  const char *info_ns = names.ns.c_str();
  if (auto url = unique_child(ext, "video-push-url", info_ns, false)) out.video_push_url = scalar(url);
  if (auto type = unique_child(ext, names.ambient.c_str(), info_ns, false)) {
    out.ambient_listening_type = scalar(type);
    if (out.ambient_listening_type != "remote-init" && out.ambient_listening_type != "local-init")
      invalid("unsupported ambient listening type");
  }
  if (auto reason = unique_child(ext, "release-reason", info_ns, false)) {
    out.release_reason = scalar(reason);
    if (!release_reasons.contains(out.release_reason)) invalid("unsupported release reason");
  }
  if (auto criteria = unique_child(ext, names.criteria.c_str(), info_ns, false))
    out.participant_criteria = scalar(criteria);
  parse_service_elements(ext, info_ns, out);
  out.functional_alias = ext_uri(ext, "functional-alias-URI", names);
  out.called_functional_alias = ext_uri(ext, "called-functional-alias-URI", names);
  out.call_to_functional_alias = ext_flag(ext, "call-to-functional-alias-ind", info_ns);
  out.emergency_alert_area = ext_flag(ext, "emergency-alert-area-ind", info_ns);
  out.group_geo_area = ext_flag(ext, "group-geo-area-ind", info_ns);
  if (auto node = unique_child(ext, "location-of-functional-alias-URI", info_ns, false)) {
    out.location_of_functional_alias = content(node, names);
    conference_uri(out.location_of_functional_alias);
  }
  if (auto outer = unique_child(ext, "PrivateCallKMSURI", info_ns, false)) {
    auto inner = unique_child(outer, "PrivateCallKMSURI", info_ns);
    out.private_call_kms_uri = scalar(unique_child(inner, "uri-entry", info_ns));
    conference_uri(out.private_call_kms_uri);
  }
  out.adhoc_emergency = ext_flag(ext, "adhoc-emergency-ind", info_ns);
  out.adhoc_alert = ext_flag(ext, "adhoc-alert-ind", info_ns);
  out.adhoc_emergency_alert_group = ext_flag(ext, "adhoc-grp-emg-alert-grp-ind", info_ns);
  out.adhoc_alert_received = ext_flag(ext, "adhoc-alert-ind-rcvd", info_ns);
}

} // namespace

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: reads an <mcpttinfo> or <mcvideoinfo> document, with the
// contentType wrappers, the booleans and the <anyExt> extensions; encrypted content is not supported.
McpttInfo parse_service_info(std::string_view xml, const ServiceProfile &service) {
  const InfoNames names(service);
  const char *info_ns = names.ns.c_str();
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, names.root.c_str(), info_ns)) invalid("wrong MCPTT root namespace");
  auto params = unique_child(root, names.params.c_str(), info_ns);
  McpttInfo out;
  out.access_token = info_value(params, names.element("access-token"), true, names);
  out.session_type = info_value(params, "session-type", false, names);
  out.request_uri = info_value(params, names.element("request-uri"), true, names);
  out.calling_user = info_value(params, names.element("calling-user-id"), true, names);
  out.called_party = info_value(params, names.element("called-party-id"), true, names);
  out.calling_group = info_value(params, names.element("calling-group-id"), true, names);
  out.client_id = info_value(params, names.element("client-id"), true, names);
  out.emergency = info_flag(params, "emergency-ind", names);
  out.imminent_peril = info_flag(params, "imminentperil-ind", names);
  out.alert = info_flag(params, "alert-ind", names);
  out.broadcast = info_flag(params, "broadcast-ind", names);
  out.alert_received = info_flag(params, "alert-ind-rcvd", names);
  out.emergency_received = info_flag(params, "emergency-ind-rcvd", names);
  out.originated_by = info_value(params, "originated-by", true, names);
  out.associated_group = associated_group_id(params, names);
  out.video_pull_url = info_value(params, "video-pull-url", true, names);
  if (auto ext = unique_child(params, "anyExt", info_ns, false)) {
    parse_info_extensions(ext, names, out);
    // TS 24.281 clause 9.2.1.2.1.1 step 14 d) i) places <associated-group-id> in <anyExt>, while annex F.1 has it in
    // <mcvideo-Params> (written there): read either.
    if (out.associated_group.empty()) out.associated_group = associated_group_id(ext, names);
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2: reads an <mcpttinfo> document.
McpttInfo parse_mcptt_info(std::string_view xml) { return parse_service_info(xml, mcptt_service); }

} // namespace mcx
