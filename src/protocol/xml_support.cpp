// XML support for the MC service documents: parsing (libxml2), size limits, element and attribute access, and
// value checks.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 4575,
// RFC 3986.

#include "protocol_internal.hpp"

namespace mcx {
namespace protocol_detail {

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1.2, TS 24.282 clause 8.4.1, TS 24.281 clause 8.3.1: the affiliation namespace of the
// service; an affiliation belongs to one MC service.
const char *affiliation_namespace(bool mcdata, bool mcvideo) {
  if (mcdata && mcvideo) throw std::runtime_error("an affiliation belongs to one MC service");
  return mcdata ? mcdata_affiliation_ns : mcvideo ? mcvideo_affiliation_ns : affiliation_ns;
}

//------------------------------------------------------------------------------
// Helper: throws the protocol error with its message.
[[noreturn]] void invalid(const char *message) { throw std::runtime_error(message); }

//------------------------------------------------------------------------------
// Helper: refuses an empty, oversized or binary (NUL-carrying) protocol body.
void bounded(std::string_view body) {
  if (body.empty() || body.size() > max_body || body.find('\0') != body.npos)
    invalid("empty, oversized or binary protocol body");
}

//------------------------------------------------------------------------------
// TS 24.282 annex E.1 and annex E.2: refuses an empty or oversized body. A multipart envelope may carry binary
// parts (MCData TLV bodies); each XML part is still checked by bounded() when it is parsed.
void bounded_envelope(std::string_view body) {
  if (body.empty() || body.size() > max_body) invalid("empty or oversized protocol body");
}

//------------------------------------------------------------------------------
// Helper: removes the leading and trailing white space.
std::string trim(std::string_view value) {
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.remove_prefix(1);
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.remove_suffix(1);
  return std::string(value);
}

//------------------------------------------------------------------------------
// Helper: the ASCII lower-case form.
std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char character) { return std::tolower(character); });
  return value;
}

//------------------------------------------------------------------------------
// Helper: parses a bounded XML document without network access, DTD or entities.
Doc document(std::string_view xml) {
  bounded(xml);
  if (xml.find("<!DOCTYPE") != xml.npos || xml.find("<!ENTITY") != xml.npos)
    invalid("DTD and XML entities are unsupported");
  Doc doc(xmlReadMemory(xml.data(), static_cast<int>(xml.size()), "mcptt.xml", nullptr,
                        XML_PARSE_NONET | XML_PARSE_NOBLANKS | XML_PARSE_NOERROR | XML_PARSE_NOWARNING),
          xmlFreeDoc);
  if (!doc || doc->intSubset || doc->extSubset) invalid("invalid XML document");
  return doc;
}

//------------------------------------------------------------------------------
// Helper: whether the node is the element of the given name in the given namespace.
bool is(xmlNode *node, const char *name, const char *ns) {
  return node && node->type == XML_ELEMENT_NODE && xmlStrEqual(node->name, BAD_CAST name) && node->ns &&
         xmlStrEqual(node->ns->href, BAD_CAST ns);
}

//------------------------------------------------------------------------------
// Helper: the text content of a node.
std::string text(xmlNode *node) {
  xmlChar *value = xmlNodeGetContent(node);
  std::string out = value ? reinterpret_cast<char *>(value) : "";
  xmlFree(value);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the value of an attribute (empty when absent).
std::string attr(xmlNode *node, const char *key) {
  xmlChar *value = xmlGetProp(node, BAD_CAST key);
  std::string out = value ? reinterpret_cast<char *>(value) : "";
  xmlFree(value);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the single child element of the given name and namespace; a duplicate, or a missing required one, is
// refused.
xmlNode *unique_child(xmlNode *root, const char *name, const char *ns, bool required) {
  xmlNode *found = nullptr;
  for (auto child = root->children; child; child = child->next)
    if (is(child, name, ns)) {
      if (found) invalid("duplicate XML element");
      found = child;
    }
  if (!found && required) invalid("missing XML element");
  return found;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and annex F.1.3 (TS 24.281 annex F.1.2): reads a contentType element: its single
// <mcpttURI> or <mcpttString> (or the service's equivalent), unprotected ("Normal"); "Encrypted" content is not
// supported.
std::string content(xmlNode *node, const InfoNames &names) {
  if (attr(node, "type") == "Encrypted") invalid("MIKEY/XML protected profile is unavailable");
  if (!attr(node, "type").empty() && attr(node, "type") != "Normal") invalid("unknown XML protection type");
  xmlNode *value = nullptr;
  for (auto child = node->children; child; child = child->next)
    if (child->type == XML_ELEMENT_NODE) {
      if (value || (!is(child, names.uri.c_str(), names.ns.c_str()) && !is(child, names.str.c_str(), names.ns.c_str())))
        invalid("unsupported MCPTT content wrapper");
      value = child;
    }
  if (!value) invalid("missing MCPTT content wrapper");
  return text(value);
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2: writes a contentType element with type "Normal" and its value wrapper; nothing when
// the value is empty.
std::string wrapped(std::string_view key, std::string_view type, const std::string &value) {
  if (value.empty()) return "";
  return "<" + std::string(key) + " type=\"Normal\"><" + std::string(type) + ">" + xml_escape(value) + "</" +
         std::string(type) + "></" + std::string(key) + ">";
}

//------------------------------------------------------------------------------
// Helper: a decimal number of at most max.
std::uint32_t number(std::string_view value, std::uint32_t max) {
  std::uint32_t result = 0;
  auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), result);
  if (ec != std::errc{} || end != value.data() + value.size() || result > max) invalid("invalid protocol number");
  return result;
}

//------------------------------------------------------------------------------
// Helper: the non-empty trimmed fields of a text separated by sep.
std::vector<std::string> tokens(std::string_view value, char sep) {
  std::vector<std::string> out;
  std::istringstream in{std::string(value)};
  std::string token;
  while (std::getline(in, token, sep))
    if (!trim(token).empty()) out.push_back(trim(token));
  return out;
}

//------------------------------------------------------------------------------
// Helper: refuses a media address that is not a routable IPv4 address.
void address(std::string_view value) {
  in_addr ipv4{};
  if (inet_pton(AF_INET, std::string(value).c_str(), &ipv4) != 1 || ipv4.s_addr == INADDR_ANY)
    invalid("media requires a routable IPv4 address");
}

//------------------------------------------------------------------------------
// RFC 4575 with RFC 3986 section 3.1: checks a conference URI: a scheme, printable characters, valid
// percent-escapes and, for a session, a SIP or SIPS URI.
void conference_uri(std::string_view uri, bool session) {
  if (uri.empty() || uri.size() > 4096) invalid("invalid conference URI");
  const auto colon = uri.find(':');
  if (colon == uri.npos || colon == 0 || colon + 1 == uri.size() ||
      !std::isalpha(static_cast<unsigned char>(uri.front())))
    invalid("invalid conference URI scheme");
  for (std::size_t index = 0; index < uri.size(); ++index) {
    const unsigned char character = uri[index];
    if (character <= 0x20 || character >= 0x7f || character == '<' || character == '>' || character == '"' ||
        character == '\\')
      invalid("invalid conference URI character");
    if (index < colon && !(std::isalnum(character) || character == '+' || character == '-' || character == '.'))
      invalid("invalid conference URI scheme");
    if (character == '%' && (index + 2 >= uri.size() || !std::isxdigit(static_cast<unsigned char>(uri[index + 1])) ||
                             !std::isxdigit(static_cast<unsigned char>(uri[index + 2]))))
      invalid("invalid conference URI escape");
  }
  if (session && !uri.starts_with("sip:") && !uri.starts_with("sips:")) invalid("conference session requires SIP URI");
}

//------------------------------------------------------------------------------
// RFC 4575: checks an endpoint <status> value.
void conference_status(const std::string &status) {
  static const std::set<std::string> values{"pending",   "dialing-out",     "dialing-in",    "alerting",    "on-hold",
                                            "connected", "muted-via-focus", "disconnecting", "disconnected"};
  if (!values.contains(status)) invalid("invalid conference endpoint status");
}

//------------------------------------------------------------------------------
// Helper: the text of an element that must have no child elements.
std::string scalar(xmlNode *node) {
  for (auto child = node->children; child; child = child->next)
    if (child->type == XML_ELEMENT_NODE) invalid("nested conference scalar");
  return text(node);
}

} // namespace protocol_detail

//------------------------------------------------------------------------------
// Helper: escapes text for an XML attribute or element; rejects the control characters XML 1.0 does not allow.
std::string xml_escape(std::string_view value) {
  std::string out;
  for (unsigned char character : value) switch (character) {
    case '&': out += "&amp;"; break;
    case '<': out += "&lt;"; break;
    case '>': out += "&gt;"; break;
    case '"': out += "&quot;"; break;
    case '\'': out += "&apos;"; break;
    default:
      if (character < 0x20 && character != '\t' && character != '\r' && character != '\n')
        invalid("invalid XML character");
      out += static_cast<char>(character);
    }
  return out;
}

} // namespace mcx
