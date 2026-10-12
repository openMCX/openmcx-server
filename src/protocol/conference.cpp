//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Conference event package documents: conference-info with the MCPTT extension (functional alias).
//
// Specifications: RFC 4575, TS 24.379 V19.7.0 (Rel-19).

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// RFC 4575 with TS 24.379 clause 10.1.3.6.1.2: writes a conference-info document (full, partial or deleted) with
// the participation URI, each user's endpoint and status, and the <functional-alias> extension.
std::string conference_info_xml(const ConferenceInfo &info) {
  conference_uri(info.group_id);
  if (!info.session_uri.empty()) conference_uri(info.session_uri, true);
  if (info.deleted && !info.users.empty()) invalid("deleted conference contains users");
  std::string out = "<?xml version=\"1.0\"?><conference-info xmlns=\"" + std::string(conference_ns) +
                    "\" xmlns:mcpttConfInfo=\"" + conference_mcptt_ns + "\" entity=\"" + xml_escape(info.group_id) +
                    "\" version=\"" + std::to_string(info.version) + "\" state=\"" +
                    (info.deleted ? "deleted"
                     : info.full  ? "full"
                                  : "partial") +
                    "\">";
  if (!info.deleted && !info.session_uri.empty())
    out += "<conference-description><conf-uris><entry><uri>" + xml_escape(info.session_uri) +
           "</uri><purpose>participation</purpose></entry></conf-uris></conference-description>";
  if (!info.deleted) {
    out += "<users>";
    std::set<std::string> users;
    for (const auto &user : info.users) {
      conference_uri(user.user_id);
      conference_uri(user.endpoint_uri);
      conference_status(user.status);
      if (!users.insert(user.user_id).second) invalid("duplicate conference user");
      out += "<user entity=\"" + xml_escape(user.user_id) + "\"><endpoint entity=\"" + xml_escape(user.endpoint_uri) +
             "\"><status>" + user.status + "</status>";
      if (!user.functional_alias.empty()) {
        conference_uri(user.functional_alias);
        out += "<mcpttConfInfo:functional-alias>" + xml_escape(user.functional_alias) +
               "</mcpttConfInfo:functional-alias>";
      }
      out += "</endpoint></user>";
    }
    out += "</users>";
  }
  out += "</conference-info>";
  bounded(out);

  return out;
}

//------------------------------------------------------------------------------
// RFC 4575 with TS 24.379 clause 10.1.3.6.1.2: reads a conference-info document: its state, the SIP participation
// URI, and each user's endpoint, status and functional alias.
ConferenceInfo parse_conference_info(std::string_view xml) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "conference-info", conference_ns)) invalid("wrong conference root namespace");
  ConferenceInfo info;
  info.group_id = attr(root, "entity");
  conference_uri(info.group_id);
  info.version = number(attr(root, "version"), UINT32_MAX);
  const auto state = attr(root, "state");
  if (!state.empty() && state != "full" && state != "partial" && state != "deleted")
    invalid("invalid conference state");
  info.full = state.empty() || state == "full";
  info.deleted = state == "deleted";
  auto description = unique_child(root, "conference-description", conference_ns, false);
  if (description) {
    auto uris = unique_child(description, "conf-uris", conference_ns, false);
    if (uris)
      for (auto entry = uris->children; entry; entry = entry->next) {
        if (!is(entry, "entry", conference_ns)) continue;
        auto purpose = unique_child(entry, "purpose", conference_ns, false);
        auto value = scalar(unique_child(entry, "uri", conference_ns));
        conference_uri(value);
        if ((!purpose || scalar(purpose) == "participation") &&
            (value.starts_with("sip:") || value.starts_with("sips:"))) {
          if (!info.session_uri.empty()) invalid("ambiguous conference session URI");
          info.session_uri = value;
        }
      }
  }
  auto users = unique_child(root, "users", conference_ns, false);
  if (info.deleted && users) invalid("deleted conference contains users");
  std::set<std::string> identities;
  if (users)
    for (auto node = users->children; node; node = node->next) {
      if (!is(node, "user", conference_ns)) continue;
      ConferenceUser user;
      user.user_id = attr(node, "entity");
      conference_uri(user.user_id);
      if (!identities.insert(user.user_id).second) invalid("duplicate conference user");
      auto endpoint = unique_child(node, "endpoint", conference_ns);
      user.endpoint_uri = attr(endpoint, "entity");
      conference_uri(user.endpoint_uri);
      user.status = scalar(unique_child(endpoint, "status", conference_ns));
      conference_status(user.status);
      auto alias = unique_child(endpoint, "functional-alias", conference_mcptt_ns, false);
      if (alias) {
        user.functional_alias = scalar(alias);
        conference_uri(user.functional_alias);
      }
      info.users.push_back(std::move(user));
    }
  return info;
}

} // namespace mcx
