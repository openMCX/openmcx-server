//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Conference event package documents: conference-info with the MCPTT or MCVideo extension (functional alias).
//
// Specifications: RFC 4575, TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19).

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// RFC 4575 with TS 24.379 clause 10.1.3.6.1.2 (TS 24.281 clause 9.2.3.6.1.2 for MCVideo): writes a conference-info
// document (full, partial or deleted) with the participation URI, each user's endpoint and status, and the
// <functional-alias> extension.
std::string conference_info_xml(const ConferenceInfo &info) {
  conference_uri(info.group_id);
  if (!info.session_uri.empty()) conference_uri(info.session_uri, true);
  if (info.deleted && !info.users.empty()) invalid("deleted conference contains users");
  const std::string prefix = info.mcvideo ? "mcvideoConfInfo" : "mcpttConfInfo";
  std::string out = "<?xml version=\"1.0\"?><conference-info xmlns=\"" + std::string(conference_ns) +
                    "\" xmlns:" + prefix + "=\"" + (info.mcvideo ? conference_mcvideo_ns : conference_mcptt_ns) +
                    "\" entity=\"" + xml_escape(info.group_id) + "\" version=\"" + std::to_string(info.version) +
                    "\" state=\"" +
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
      if (!users.insert(user.user_id).second) invalid("duplicate conference user");
      // RFC 4575 section 5.6: a user removed in a partial notification, without <endpoint>.
      if (user.state == "deleted") {
        out += "<user entity=\"" + xml_escape(user.user_id) + "\" state=\"deleted\"/>";
        continue;
      }
      conference_uri(user.endpoint_uri);
      conference_status(user.status);
      out += "<user entity=\"" + xml_escape(user.user_id) + "\"" +
             (user.state.empty() ? std::string{} : " state=\"" + xml_escape(user.state) + "\"") +
             "><endpoint entity=\"" + xml_escape(user.endpoint_uri) + "\"><status>" + user.status + "</status>";
      if (!user.functional_alias.empty()) {
        conference_uri(user.functional_alias);
        out += "<" + prefix + ":functional-alias>" + xml_escape(user.functional_alias) + "</" + prefix +
               ":functional-alias>";
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
// RFC 4575 with TS 24.379 clause 10.1.3.6.1.2 (TS 24.281 clause 9.2.3.6.1.2): reads a conference-info document: its
// state, the SIP participation URI, and each user's endpoint, status and functional alias, in the MCPTT or the
// MCVideo extension namespace.
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
      user.state = attr(node, "state");
      if (!user.state.empty() && user.state != "full" && user.state != "partial" && user.state != "deleted")
        invalid("invalid conference user state");
      // RFC 4575 section 5.6: a user removed in a partial notification needs no <endpoint>.
      auto endpoint = unique_child(node, "endpoint", conference_ns, user.state != "deleted");
      if (!endpoint) {
        user.status = "disconnected";
        info.users.push_back(std::move(user));
        continue;
      }
      user.endpoint_uri = attr(endpoint, "entity");
      conference_uri(user.endpoint_uri);
      user.status = scalar(unique_child(endpoint, "status", conference_ns));
      conference_status(user.status);
      auto alias = unique_child(endpoint, "functional-alias", conference_mcptt_ns, false);
      if (!alias) {
        alias = unique_child(endpoint, "functional-alias", conference_mcvideo_ns, false);
        if (alias) info.mcvideo = true;
      }
      if (alias) {
        user.functional_alias = scalar(alias);
        conference_uri(user.functional_alias);
      }
      info.users.push_back(std::move(user));
    }
  return info;
}

} // namespace mcx
