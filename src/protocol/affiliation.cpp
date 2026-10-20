//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Affiliation documents (application/pidf+xml with the MC service affiliation extension) and the PoC settings document.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 3863,
// RFC 3856, OMA PoC settings (application/poc-settings+xml).

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1.2 (TS 24.282 clause 8.4.1, TS 24.281 clause 8.3.1): writes the affiliation PIDF of one
// client, as a request (TS 24.379 clause 9.2.1.2) or, with notification set, with the "status" of each group as
// in a notification (TS 24.379 clause 9.2.2.2.5).
std::string affiliation_xml(const Affiliation &affiliation, bool notification) {
  const char *ns = affiliation_namespace(affiliation.mcdata, affiliation.mcvideo);
  std::string out = "<?xml version=\"1.0\"?><presence xmlns=\"" + std::string(pidf_ns) + "\" xmlns:mc=\"" + ns +
                    "\" entity=\"" + xml_escape(affiliation.user_id) + "\"><tuple id=\"" +
                    xml_escape(affiliation.client_id) + "\"><status>";
  for (std::size_t index = 0; index < affiliation.groups.size(); ++index) {
    out += "<mc:affiliation group=\"" + xml_escape(affiliation.groups[index]) + "\"";
    if (notification)
      out += " status=\"" +
             xml_escape(index < affiliation.statuses.size() ? affiliation.statuses[index] : "affiliated") + "\"";
    out += "/>";
  }
  out += "</status></tuple>";
  if (!affiliation.publication_id.empty()) out += "<mc:p-id>" + xml_escape(affiliation.publication_id) + "</mc:p-id>";
  out += "</presence>";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1.2 (TS 24.282 clause 8.4.1, TS 24.281 clause 8.3.1): reads an affiliation PIDF (a request
// of TS 24.379 clause 9.2.2.2.3 or a notification): the client, its groups with their status and the service by
// namespace. A request has the one <tuple> of its client. A notification has one <tuple> "per each MCPTT client" of
// the user (clause 9.3.1.2), so with `client` set the tuple of that client is read, and none means no group.
Affiliation parse_affiliation(std::string_view xml, std::string_view client) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "presence", pidf_ns)) invalid("wrong PIDF namespace");
  Affiliation affiliation;
  affiliation.user_id = attr(root, "entity");
  std::vector<xmlNode *> tuples;
  for (auto child = root->children; child; child = child->next)
    if (is(child, "tuple", pidf_ns)) tuples.push_back(child);
  if (client.empty() && tuples.size() != 1) invalid("an affiliation request has one tuple");

  // TS 24.282 clause 8.4.1 and TS 24.281 clause 8.3.1: MCData and MCVideo use the same
  // structure in their own namespaces.
  bool mcptt = false;
  xmlNode *tuple = client.empty() ? tuples.front() : nullptr;
  for (auto *each : tuples) {
    auto status = unique_child(each, "status", pidf_ns);
    for (auto node = status->children; node; node = node->next) {
      if (is(node, "affiliation", affiliation_ns)) mcptt = true;
      if (is(node, "affiliation", mcdata_affiliation_ns)) affiliation.mcdata = true;
      if (is(node, "affiliation", mcvideo_affiliation_ns)) affiliation.mcvideo = true;
    }
    if (!client.empty() && attr(each, "id") == client) {
      if (tuple) invalid("duplicate tuple of the client");
      tuple = each;
    }
  }
  if (int(mcptt) + int(affiliation.mcdata) + int(affiliation.mcvideo) > 1) invalid("mixed MC service affiliation");

  // A PIDF with no affiliation (a de-affiliation from every group, or a peer
  // registration without groups) names its service by the namespace of its p-id.
  if (!mcptt && !affiliation.mcdata && !affiliation.mcvideo) {
    const bool data = unique_child(root, "p-id", mcdata_affiliation_ns, false) != nullptr;
    const bool video = unique_child(root, "p-id", mcvideo_affiliation_ns, false) != nullptr;
    if (data && video) invalid("mixed MC service affiliation");
    affiliation.mcdata = data;
    affiliation.mcvideo = video;
  }
  const char *ns = affiliation_namespace(affiliation.mcdata, affiliation.mcvideo);
  auto id = unique_child(root, "p-id", ns, false);
  if (id) affiliation.publication_id = text(id);
  affiliation.client_id = tuple ? attr(tuple, "id") : std::string(client);
  std::set<std::string> seen;
  if (tuple)
    for (auto node = unique_child(tuple, "status", pidf_ns)->children; node; node = node->next)
      if (is(node, "affiliation", ns)) {
        auto group = attr(node, "group");
        if (group.empty() || !seen.insert(group).second) invalid("invalid affiliation groups");
        affiliation.groups.push_back(group);
        affiliation.statuses.push_back(attr(node, "status"));
      }
  if (affiliation.user_id.empty() || affiliation.client_id.empty()) invalid("missing PIDF identity");

  return affiliation;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.2.3 with clause 7.4.1.2.2: writes the application/poc-settings+xml of a client: automatic
// answer mode, the selected user profile index and multiplex support.
std::string poc_settings_xml(std::string_view client_id, unsigned profile_index) {
  if (client_id.empty()) throw std::invalid_argument("PoC client identity required");
  return "<?xml version=\"1.0\"?><poc-settings "
         "xmlns=\"urn:oma:params:xml:ns:poc:poc-settings\" "
         "xmlns:mc=\"urn:3gpp:mcsSettings:1.0\"><entity id=\"" +
         xml_escape(client_id) +
         "\"><am-settings><answer-mode>automatic</answer-mode></"
         "am-settings><mc:selected-user-profile-index><mc:user-profile-index>" +
         std::to_string(profile_index) +
         "</mc:user-profile-index></"
         "mc:selected-user-profile-index><mc:multiplex-support>true</"
         "mc:multiplex-support></entity></poc-settings>";
}

} // namespace mcx
