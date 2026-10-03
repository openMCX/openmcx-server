// Functional alias documents: the application/pidf+xml functional alias extension for the status change request,
// the status notification and the status determination, for MCPTT, MCData and MCVideo.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 3863.

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.3.1.2, TS 24.282 clause 22.3.1.2, TS 24.281 clause 20.3.1.2: the functional alias namespace
// of the service.
static const char *functional_alias_namespace(bool mcdata, bool mcvideo) {
  return mcdata ? mcdata_functional_alias_ns : mcvideo ? mcvideo_functional_alias_ns : mcptt_functional_alias_ns;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.1.2 with the syntax of clause 9A.3.1.2 (TS 24.282 clause 22.2.1.2, TS 24.281 clause
// 20.2.1.2): writes a functional alias status change request: the <p-id-fa>, the aliases to activate and
// <take-over>.
std::string functional_alias_xml(const FunctionalAliasRequest &request) {
  if (request.mcdata && request.mcvideo) invalid("functional alias request for two services");
  const char *functional_alias_ns = functional_alias_namespace(request.mcdata, request.mcvideo);
  conference_uri(request.user_id);
  if (request.client_id.empty() || request.aliases.size() > 64) invalid("invalid functional alias request");
  std::string out = "<?xml version=\"1.0\"?><presence xmlns=\"" + std::string(pidf_ns) + "\" xmlns:fa=\"" +
                    functional_alias_ns + "\" entity=\"" + xml_escape(request.user_id) + "\">";
  if (!request.publish_id.empty()) out += "<fa:p-id-fa>" + xml_escape(request.publish_id) + "</fa:p-id-fa>";
  out += "<tuple id=\"" + xml_escape(request.client_id) + "\"><status>";
  for (const auto &alias : request.aliases) {
    conference_uri(alias);
    out += "<fa:functionalAlias functionalAliasID=\"" + xml_escape(alias) + "\"/>";
  }
  if (request.take_over) out += "<fa:take-over>true</fa:take-over>";
  out += "</status></tuple></presence>";
  bounded(out);
  return out;
}

namespace {
// TS 24.379 clause 9A.3.1.2, TS 24.282 clause 22.3.1.2, TS 24.281 clause 20.3.1.2: the functional alias namespaces
// a parsed document uses, on its elements or declared by them (an empty request declares one but has no element in
// it); text, comments and attribute values do not count.
struct AliasNamespaces {
  bool mcptt = false, mcdata = false, mcvideo = false;

  [[nodiscard]] int count() const { return int(mcptt) + int(mcdata) + int(mcvideo); }
};

//------------------------------------------------------------------------------
// Helper: notes a namespace URI if it is one of the functional alias namespaces.
void note_namespace(const xmlChar *href, AliasNamespaces &found) {
  if (href == nullptr) return;
  found.mcptt = found.mcptt || xmlStrEqual(href, BAD_CAST mcptt_functional_alias_ns);
  found.mcdata = found.mcdata || xmlStrEqual(href, BAD_CAST mcdata_functional_alias_ns);
  found.mcvideo = found.mcvideo || xmlStrEqual(href, BAD_CAST mcvideo_functional_alias_ns);
}

//------------------------------------------------------------------------------
// Helper: the functional alias namespaces of the elements under (and including) a node.
void collect_namespaces(xmlNode *node, AliasNamespaces &found) {
  for (; node != nullptr; node = node->next) {
    if (node->type != XML_ELEMENT_NODE) continue;
    if (node->ns != nullptr) note_namespace(node->ns->href, found);
    for (auto *declared = node->nsDef; declared != nullptr; declared = declared->next)
      note_namespace(declared->href, found);
    collect_namespaces(node->children, found);
  }
}

//------------------------------------------------------------------------------
// Helper: the functional alias namespaces of a parsed document.
AliasNamespaces alias_namespaces(xmlDoc *doc) {
  AliasNamespaces found;
  collect_namespaces(xmlDocGetRootElement(doc), found);
  return found;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.3.1.2: exactly one of the MCPTT, MCData and MCVideo functional alias namespaces; sets the
// service flags and returns that namespace.
const char *single_alias_namespace(xmlDoc *doc, bool &mcdata, bool &mcvideo) {
  const auto found = alias_namespaces(doc);
  if (found.count() != 1) invalid("functional alias presence needs one functional alias namespace");
  mcdata = found.mcdata;
  mcvideo = found.mcvideo;
  return functional_alias_namespace(mcdata, mcvideo);
}
} // namespace

//------------------------------------------------------------------------------
// Helper: whether a PIDF is a functional alias document (rather than an affiliation): an XML document whose
// elements use or declare a functional alias namespace.
bool is_functional_alias_pidf(std::string_view xml) {
  try {
    auto doc = document(xml);
    return alias_namespaces(doc.get()).count() > 0;
  } catch (const std::exception &) {
    return false; // not a well-formed bounded document: not a functional alias document either
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.2.3 with the syntax of clause 9A.3.1.2 (TS 24.282 clause 22.2.2.2.3): reads a
// functional alias status change request: the user, the client, the <p-id-fa>, the aliases and <take-over>.
FunctionalAliasRequest parse_functional_alias(std::string_view xml) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "presence", pidf_ns)) invalid("wrong functional alias presence namespace");
  FunctionalAliasRequest out;
  const char *functional_alias_ns = single_alias_namespace(doc.get(), out.mcdata, out.mcvideo);
  out.user_id = attr(root, "entity");
  conference_uri(out.user_id);
  if (auto id = unique_child(root, "p-id-fa", functional_alias_ns, false)) out.publish_id = scalar(id);
  auto tuple = unique_child(root, "tuple", pidf_ns);
  out.client_id = attr(tuple, "id");
  if (out.client_id.empty()) invalid("functional alias tuple lacks the client ID");
  auto status = unique_child(tuple, "status", pidf_ns);
  for (auto node = status->children; node; node = node->next) {
    if (node->type != XML_ELEMENT_NODE) continue;
    if (is(node, "functionalAlias", functional_alias_ns)) {
      auto alias = attr(node, "functionalAliasID");
      conference_uri(alias);
      if (std::find(out.aliases.begin(), out.aliases.end(), alias) == out.aliases.end()) out.aliases.push_back(alias);
      if (out.aliases.size() > 64) invalid("too many functional aliases");
    } else if (is(node, "take-over", functional_alias_ns)) {
      const auto value = scalar(node);
      if (value != "true" && value != "false" && value != "1" && value != "0") invalid("invalid take-over value");
      out.take_over = value == "true" || value == "1";
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.5 and clause 9A.2.1.3 with the syntax of clause 9A.3.1.2: writes a functional alias
// status notification or determination, per alias ("functionalAliasID") or per user ("user"), with each status.
std::string functional_alias_status_xml(const FunctionalAliasStatus &status) {
  if (status.mcdata && status.mcvideo) invalid("functional alias status for two services");
  const char *functional_alias_ns = functional_alias_namespace(status.mcdata, status.mcvideo);
  conference_uri(status.entity);
  if (status.tuple_id.empty() || status.entries.size() > 64) invalid("invalid functional alias status");
  std::string out = "<?xml version=\"1.0\"?><presence xmlns=\"" + std::string(pidf_ns) + "\" xmlns:fa=\"" +
                    functional_alias_ns + "\" entity=\"" + xml_escape(status.entity) + "\">";
  if (!status.publish_id.empty()) out += "<fa:p-id-fa>" + xml_escape(status.publish_id) + "</fa:p-id-fa>";
  out += "<tuple id=\"" + xml_escape(status.tuple_id) + "\"><status>";
  for (const auto &entry : status.entries) {
    out += "<fa:functionalAlias";
    if (status.per_alias) {
      conference_uri(entry.user);
      out += " user=\"" + xml_escape(entry.user) + "\"";
    } else {
      conference_uri(entry.alias);
      out += " functionalAliasID=\"" + xml_escape(entry.alias) + "\"";
    }
    if (!entry.status.empty()) {
      if (!functional_alias_statuses.contains(entry.status)) invalid("invalid functional alias status value");
      out += " status=\"" + entry.status + "\"";
    }
    out += "/>";
  }
  out += "</status></tuple></presence>";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.3.1.2: reads a functional alias status notification or determination; its entries are all
// per alias or all per user.
FunctionalAliasStatus parse_functional_alias_status(std::string_view xml) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "presence", pidf_ns)) invalid("wrong functional alias presence namespace");
  FunctionalAliasStatus out;
  const char *functional_alias_ns = single_alias_namespace(doc.get(), out.mcdata, out.mcvideo);
  out.entity = attr(root, "entity");
  conference_uri(out.entity);
  if (auto id = unique_child(root, "p-id-fa", functional_alias_ns, false)) out.publish_id = scalar(id);
  auto tuple = unique_child(root, "tuple", pidf_ns);
  out.tuple_id = attr(tuple, "id");
  if (out.tuple_id.empty()) invalid("functional alias tuple lacks its id");
  auto status = unique_child(tuple, "status", pidf_ns);
  bool per_user = false;
  for (auto node = status->children; node; node = node->next) {
    if (node->type != XML_ELEMENT_NODE || !is(node, "functionalAlias", functional_alias_ns)) continue;
    FunctionalAliasStatus::Entry entry{attr(node, "functionalAliasID"), attr(node, "user"), attr(node, "status")};
    if (entry.alias.empty() == entry.user.empty()) invalid("functional alias entry needs an alias or a user");
    (entry.alias.empty() ? out.per_alias : per_user) = true;
    conference_uri(entry.alias.empty() ? entry.user : entry.alias);
    if (!entry.status.empty() && !functional_alias_statuses.contains(entry.status))
      invalid("invalid functional alias status value");
    out.entries.push_back(std::move(entry));
    if (out.entries.size() > 64) invalid("too many functional alias entries");
  }
  if (out.per_alias && per_user) invalid("mixed functional alias status entries");
  return out;
}

} // namespace mcx
