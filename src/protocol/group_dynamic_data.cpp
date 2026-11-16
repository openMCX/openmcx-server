//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The subscription to group dynamic data (include/mcx/group_dynamic_data.hpp): the application/pidf+xml body
// indicating per-group dynamic data, the application/simple-filter+xml body indicating per-group dynamic data
// restrictions, the Expires rule and the subscriptions of the MCVideo server owning the group.
//
// The documents are those of TS 24.281 clauses 8.3.1.2 and 8.3.2.2, of TS 24.379 clauses 9.3.1.2 and 9.3.2.2 (MCPTT,
// namespace urn:3gpp:ns:mcpttPresInfo:1.0, prefix mcpttPI10 of table 9.3.1.2-2) and of TS 24.282 clause 8.4.1 (MCData,
// urn:3gpp:ns:mcdataPresInfo:1.0): the same elements and filter values in the presence namespace of each service.
//
// Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), RFC 3856,
// RFC 3863, RFC 4661, RFC 6665.

#include "mcx/group_dynamic_data.hpp"

#include "protocol_internal.hpp"

namespace mcx {

namespace {
// RFC 4661 section 5: the simple-filter namespace.
constexpr const char *simple_filter_ns = "urn:ietf:params:xml:ns:simple-filter";

// The presence namespace of a service and its prefix: TS 24.281 table 8.3.1.2-2 (mcvideoPI10), TS 24.379 table
// 9.3.1.2-2 (mcpttPI10), TS 24.282 clause 8.4.1 (mcdataPI10).
struct PresenceNames {
  const char *ns;
  const char *prefix;
};

PresenceNames presence_names(Service service) {
  switch (service) {
  case Service::mcptt: return {affiliation_ns, "mcpttPI10"};
  case Service::mcdata: return {mcdata_affiliation_ns, "mcdataPI10"};
  case Service::mcvideo: break;
  }
  return {mcvideo_affiliation_ns, "mcvideoPI10"};
}

//------------------------------------------------------------------------------
// Helper: a filter value without white space, the prefix of any service's presence namespace read as "pidf" (see
// the header comment).
std::string normalised(std::string_view value) {
  std::string out;
  for (const char character : value)
    if (!std::isspace(static_cast<unsigned char>(character))) out += character;
  for (const auto service : {Service::mcptt, Service::mcvideo, Service::mcdata}) {
    const std::string prefix = std::string(presence_names(service).prefix) + ":";
    for (auto at = out.find(prefix); at != std::string::npos; at = out.find(prefix, at))
      out.replace(at, prefix.size(), "pidf:");
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.281 table 8.3.1.2-3: the values of <groupStatus>.
void group_status_value(const std::string &value) {
  if (value != "emergency" && value != "in-peril") invalid("invalid groupStatus");
}

//------------------------------------------------------------------------------
// Helper: an xs:boolean.
bool boolean_value(const std::string &value) {
  if (value == "true" || value == "1") return true;
  if (value == "false" || value == "0") return false;
  invalid("invalid boolean");
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.1.2 (per-group dynamic data): items 1 and 2 the <presence> and its "entity"; items 9 to 15
// one <tuple> per affiliated MCVideo ID with one <affiliation> per client ("client", "expires": clause 8.2.2.3.10
// step 2 a) and its <functionalAlias> elements; items 3 and 4 <groupStatus> with "ModifiedBy"; items 5 to 8
// <additionalData> with its attributes. RFC 3863 section 4.1.2: the <tuple> elements come before the extensions.
std::string group_dynamic_data_xml(const GroupDynamicDataDocument &document, const GroupDynamicDataFilter *filter,
                                   Service service) {
  conference_uri(document.group);
  const bool all = !filter || !filter->selects();
  const auto wanted = [&](bool item) { return all || item; };
  const auto names = presence_names(service);
  const std::string p = std::string(names.prefix) + ":";
  std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><presence xmlns=\"" + std::string(pidf_ns) +
                    "\" xmlns:" + names.prefix + "=\"" + names.ns + "\" entity=\"" +
                    xml_escape(document.group) + "\">";
  if (wanted(filter && filter->affiliated))
    for (const auto &member : document.members) {
      out += "<tuple id=\"" + xml_escape(member.id) + "\"><status>";
      for (const auto &client : member.clients) {
        out += "<" + p + "affiliation client=\"" + xml_escape(client.client) + "\"";
        if (!client.expires.empty()) out += " expires=\"" + xml_escape(client.expires) + "\"";
        out += "/>";
      }
      for (const auto &alias : member.functional_aliases)
        out += "<" + p + "functionalAlias functionalAliasID=\"" + xml_escape(alias) + "\"/>";
      out += "</status></tuple>";
    }
  if (!document.group_status.empty() && wanted(filter && filter->group_status)) {
    group_status_value(document.group_status);
    out += "<" + p + "groupStatus";
    if (!document.modified_by.empty()) out += " ModifiedBy=\"" + xml_escape(document.modified_by) + "\"";
    out += ">" + document.group_status + "</" + p + "groupStatus>";
  }
  std::string additional;
  if (!document.broadcast_alias.empty() && wanted(filter && filter->broadcast_alias))
    additional += " groupBroadcastAlias=\"" + xml_escape(document.broadcast_alias) + "\"";
  if (!document.regroup_alias.empty() && wanted(filter && filter->regroup_alias))
    additional += " groupRegroupAlias=\"" + xml_escape(document.regroup_alias) + "\"";
  if (document.call_ongoing && wanted(filter && filter->call_ongoing))
    additional += std::string(" groupCallOngoing=\"") + (*document.call_ongoing ? "true" : "false") + "\"";
  if (!additional.empty()) out += "<" + p + "additionalData" + additional + "/>";
  out += "</presence>";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.1.2 (per-group dynamic data), as the MCVideo client determines it (clause 8.2.1.6); TS 24.379
// clause 9.3.1.2 as the MCPTT client does (clause 9.2.1.6): the elements in the service's presence namespace.
GroupDynamicDataDocument parse_group_dynamic_data(std::string_view xml, Service service) {
  const char *ns = presence_names(service).ns;
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "presence", pidf_ns)) invalid("wrong PIDF namespace");
  GroupDynamicDataDocument out;
  out.group = attr(root, "entity");
  conference_uri(out.group);
  for (auto child = root->children; child; child = child->next) {
    if (child->type != XML_ELEMENT_NODE) continue;
    if (is(child, "tuple", pidf_ns)) {
      GroupDynamicDataMember member;
      member.id = attr(child, "id");
      if (member.id.empty()) invalid("tuple without id");
      auto status = unique_child(child, "status", pidf_ns); // item 11
      for (auto node = status->children; node; node = node->next) {
        if (is(node, "affiliation", ns))
          member.clients.push_back({attr(node, "client"), attr(node, "expires")});
        else if (is(node, "functionalAlias", ns))
          member.functional_aliases.push_back(attr(node, "functionalAliasID"));
      }
      out.members.push_back(std::move(member));
    } else if (is(child, "groupStatus", ns)) {
      if (!out.group_status.empty()) invalid("duplicate groupStatus");
      out.group_status = trim(scalar(child));
      group_status_value(out.group_status);
      out.modified_by = attr(child, "ModifiedBy");
    } else if (is(child, "additionalData", ns)) {
      out.broadcast_alias = attr(child, "groupBroadcastAlias");
      out.regroup_alias = attr(child, "groupRegroupAlias");
      if (const auto ongoing = attr(child, "groupCallOngoing"); !ongoing.empty())
        out.call_ongoing = boolean_value(trim(ongoing));
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.2.2 (per-group dynamic data restrictions; TS 24.379 clause 9.3.2.2 for MCPTT): items 1 to 4
// the <filter-set> with the "pidf" and the service's presence bindings ("mcvideoPI10", "mcpttPI10"); item 5 one
// <filter> with an "id" and no "uri" or "domain"; items 6 and 7 a <what> with one <include> without "type" per item of
// 7 B asked for (and the group, see the header comment).
std::string group_dynamic_data_filter_xml(const GroupDynamicDataFilter &filter, Service service) {
  if (filter.id.empty()) invalid("filter without id");
  const auto names = presence_names(service);
  std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><filter-set xmlns=\"" + std::string(simple_filter_ns) +
                    "\"><ns-bindings><ns-binding prefix=\"pidf\" urn=\"" + pidf_ns + "\"/><ns-binding prefix=\"" +
                    names.prefix + "\" urn=\"" + names.ns + "\"/></ns-bindings><filter id=\"" +
                    xml_escape(filter.id) + "\"><what>";
  const auto include = [&](std::string_view value) { out += "<include>" + xml_escape(value) + "</include>"; };
  if (!filter.group.empty()) {
    conference_uri(filter.group);
    include("//pidf:presence[@entity=\"" + filter.group + "\"]");
  }
  if (filter.group_status) include(gdd_filter_group_status);
  if (filter.broadcast_alias) include(gdd_filter_broadcast_alias);
  if (filter.regroup_alias) include(gdd_filter_regroup_alias);
  if (filter.call_ongoing) include(gdd_filter_call_ongoing);
  if (filter.affiliated) include(gdd_filter_affiliated);
  out += "</what></filter></filter-set>";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.3.2.2 (per-group dynamic data restrictions): reads the items of 7 B asked for, and the group
// a filter names. A per-client or per-user filter (the other two lists of the clause) is none.
std::optional<GroupDynamicDataFilter> parse_group_dynamic_data_filter(std::string_view xml) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "filter-set", simple_filter_ns)) invalid("wrong simple-filter namespace");
  GroupDynamicDataFilter out;
  out.id.clear();
  bool found = false, constraints_broken = false;
  const std::string entity_head = "//pidf:presence[@entity=\"", entity_tail = "\"]";
  for (auto filter = root->children; filter; filter = filter->next) {
    if (filter->type != XML_ELEMENT_NODE || !is(filter, "filter", simple_filter_ns)) continue;
    const bool restricted = xmlHasProp(filter, BAD_CAST "uri") || xmlHasProp(filter, BAD_CAST "domain");
    auto what = unique_child(filter, "what", simple_filter_ns, false);
    if (!what) continue;
    for (auto include = what->children; include; include = include->next) {
      if (include->type != XML_ELEMENT_NODE || !is(include, "include", simple_filter_ns)) continue;
      const auto value = normalised(scalar(include));
      bool item = true;
      if (value == normalised(gdd_filter_group_status))
        out.group_status = true;
      else if (value == normalised(gdd_filter_broadcast_alias))
        out.broadcast_alias = true;
      else if (value == normalised(gdd_filter_regroup_alias))
        out.regroup_alias = true;
      else if (value == normalised(gdd_filter_call_ongoing))
        out.call_ongoing = true;
      else if (value == normalised(gdd_filter_affiliated))
        out.affiliated = true;
      else if (value.starts_with(entity_head) && value.ends_with(entity_tail) &&
               value.size() > entity_head.size() + entity_tail.size()) {
        auto group = value.substr(entity_head.size(), value.size() - entity_head.size() - entity_tail.size());
        conference_uri(group);
        if (!out.group.empty() && out.group != group) invalid("filter names two groups");
        out.group = std::move(group);
      } else
        item = false; // such as the //pidf:presence/pidf:tuple[@id="..."] of a per-client or per-user filter
      if (!item) continue;
      found = true;
      if (out.id.empty()) out.id = attr(filter, "id");
      if (restricted || xmlHasProp(include, BAD_CAST "type")) constraints_broken = true;
    }
  }
  if (!found) return std::nullopt; // a per-client or per-user filter, or one of nothing known
  if (constraints_broken) invalid("group dynamic data filter with uri, domain or type"); // items 5 B, 5 C, 7 A
  if (out.id.empty()) invalid("group dynamic data filter without id");                   // item 5 A
  return out;
}

//------------------------------------------------------------------------------
// RFC 6665 section 4.1.2.1 with RFC 3261 section 20.19 (delta-seconds, at most 2^32-1), TS 24.281 clause
// 8.2.2.3.9 step 3: the Expires of a subscription to group dynamic data.
GddExpires classify_gdd_expires(std::optional<std::string_view> header) {
  if (!header) return GddExpires::too_brief;
  const auto value = trim(*header);
  if (value.empty() || value.size() > 10 ||
      !std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c); }))
    return GddExpires::malformed;
  const auto seconds = std::stoull(value);
  if (seconds > 4294967295ull) return GddExpires::malformed;
  if (seconds == 0) return GddExpires::fetch;
  return seconds == 4294967295ull ? GddExpires::subscribe : GddExpires::too_brief;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 8.2.2.3.9 steps 3 to 6.
int gdd_subscribe_status(GddExpires expires, bool group_exists, bool authorised) {
  if (expires == GddExpires::malformed) return 400;
  if (expires == GddExpires::too_brief) return 423; // step 3
  if (!group_exists) return 403;                    // step 4
  if (!authorised) return 403;                      // step 5
  return 200;                                       // step 6
}

//------------------------------------------------------------------------------
const GroupDynamicDataSubscriptions::Subscription *
GroupDynamicDataSubscriptions::find(const std::string &dialog) const {
  const auto found = subscriptions_.find(dialog);
  return found == subscriptions_.end() ? nullptr : &found->second;
}

void GroupDynamicDataSubscriptions::add(const std::string &dialog, Subscription subscription) {
  subscriptions_[dialog] = std::move(subscription);
}

bool GroupDynamicDataSubscriptions::erase(const std::string &dialog) { return subscriptions_.erase(dialog) > 0; }

} // namespace mcx
