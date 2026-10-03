// Resource lists: the private call target, participant lists and XCAP references in application/resource-lists+xml.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 4826, RFC 5366, RFC 5875.

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.2.1.1 step 8 with RFC 5366: writes the resource list of a private call, a single <entry>
// with the called user's URI.
std::string private_call_resource_list(std::string_view target) {
  conference_uri(target, true);
  std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><resource-lists xmlns=\"" +
                    std::string(resource_lists_ns) + "\"><list><entry uri=\"" + xml_escape(target) +
                    "\"/></list></resource-lists>";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 step 9: reads the called party of a private call, the single <entry> of the
// resource list.
std::string parse_private_call_target(std::string_view xml) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "resource-lists", resource_lists_ns)) invalid("wrong resource-lists namespace");
  // TS 24.379 clause 11.1.1.3.1.1 step 9: a private call names exactly one entry
  // across every list; anything else leaves the called party undetermined.
  std::string target;
  std::size_t entries = 0;
  for (auto list = root->children; list; list = list->next) {
    if (list->type != XML_ELEMENT_NODE) continue;
    if (!is(list, "list", resource_lists_ns)) invalid("unexpected resource-lists element");
    for (auto entry = list->children; entry; entry = entry->next) {
      if (entry->type != XML_ELEMENT_NODE) continue;
      if (!is(entry, "entry", resource_lists_ns)) invalid("unsupported resource-list member");
      if (++entries > 1) invalid("private call names more than one called party");
      target = attr(entry, "uri");
    }
  }
  if (entries != 1) invalid("private call lacks a called party");
  conference_uri(target, true);
  return target;
}

//------------------------------------------------------------------------------
// RFC 4826 with RFC 5366: writes a resource list of the given SIP URIs, one <entry> each.
std::string resource_list_xml(const std::vector<std::string> &targets) {
  if (targets.empty()) invalid("empty resource list");
  std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><resource-lists xmlns=\"" +
                    std::string(resource_lists_ns) + "\"><list>";
  for (const auto &target : targets) {
    conference_uri(target, true);
    out += "<entry uri=\"" + xml_escape(target) + "\"/>";
  }
  out += "</list></resource-lists>";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// RFC 4826 with RFC 5366: reads the distinct SIP URIs of a resource list (at most 64 entries).
std::vector<std::string> parse_resource_list_targets(std::string_view xml) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "resource-lists", resource_lists_ns)) invalid("wrong resource-lists namespace");
  std::vector<std::string> targets;
  std::set<std::string> seen;
  std::size_t entries = 0;
  for (auto list = root->children; list; list = list->next) {
    if (list->type != XML_ELEMENT_NODE) continue;
    if (!is(list, "list", resource_lists_ns)) invalid("unexpected resource-lists element");
    for (auto entry = list->children; entry; entry = entry->next) {
      if (entry->type != XML_ELEMENT_NODE) continue;
      if (!is(entry, "entry", resource_lists_ns)) invalid("unsupported resource-list member");
      if (++entries > 64) invalid("too many resource-list entries");
      auto target = attr(entry, "uri");
      conference_uri(target, true);
      if (seen.insert(target).second) targets.push_back(target);
    }
  }
  if (targets.empty()) invalid("resource list names no users");
  return targets;
}

//------------------------------------------------------------------------------
// RFC 5875: checks one entry of a resource list naming XCAP documents or elements by relative path.
static void xcap_reference(std::string_view uri) {
  if (uri.empty() || uri.size() > 1024 || uri.front() == '/' || uri.find("..") != std::string_view::npos ||
      uri.find_first_of(" <>\"\\") != std::string_view::npos || uri.find("://") != std::string_view::npos)
    invalid("invalid XCAP reference in a resource list");
}

//------------------------------------------------------------------------------
// RFC 5875 with RFC 4826: writes a resource list of XCAP references, one <entry> each.
std::string xcap_resource_list(const std::vector<std::string> &references) {
  std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><resource-lists xmlns=\"" +
                    std::string(resource_lists_ns) + "\"><list>";
  for (const auto &reference : references) {
    xcap_reference(reference);
    out += "<entry uri=\"" + xml_escape(reference) + "\"/>";
  }
  out += "</list></resource-lists>";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// RFC 5875 with RFC 4826: reads the XCAP references of a resource list (at most 64).
std::vector<std::string> parse_xcap_resource_list(std::string_view xml) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "resource-lists", resource_lists_ns)) invalid("wrong resource-lists namespace");
  std::vector<std::string> out;
  for (auto list = root->children; list; list = list->next) {
    if (list->type != XML_ELEMENT_NODE) continue;
    if (!is(list, "list", resource_lists_ns)) invalid("unexpected resource-lists element");
    for (auto entry = list->children; entry; entry = entry->next) {
      if (entry->type != XML_ELEMENT_NODE) continue;
      if (!is(entry, "entry", resource_lists_ns) || out.size() >= 64)
        invalid("unsupported or too many resource-list entries");
      auto reference = attr(entry, "uri");
      xcap_reference(reference);
      out.push_back(reference);
    }
  }
  if (out.empty()) invalid("resource list names no documents");
  return out;
}

} // namespace mcx
