//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Canonical XML 1.1 clause 2.4 on top of libxml2 (src/security/c14n11.hpp) and its join-URI-References function
// (include/mcx/xml_security.hpp).
//
// Specifications: W3C Canonical XML Version 1.1 (Recommendation 2 May 2008) clauses 2.4 and 3.8; RFC 3986 clauses
// 5.2.1 to 5.2.4, 5.3 and appendix B; W3C XML Signature Syntax and Processing (Second Edition, 2008) clause 6.5.

#include "c14n11.hpp"

#include "mcx/xml_security.hpp"

#include <cstring>
#include <functional>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace mcx::xmlsec {
namespace {

//------------------------------------------------------------------------------
// Throws the message when the condition does not hold.
void require(bool condition, const char *what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// RFC 3986 appendix B: the components of a URI reference (null when absent).
struct Parts {
  std::optional<std::string> scheme;
  std::optional<std::string> authority;
  std::string path;
  std::optional<std::string> query;
};

Parts parse(std::string_view text) {
  static const std::regex reference("^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?$");
  const std::string input(text);
  std::smatch match;
  require(std::regex_match(input, match, reference), "invalid xml:base");
  Parts parts;
  if (match[2].matched) parts.scheme = match[2].str();
  if (match[3].matched) parts.authority = match[4].str();
  parts.path = match[5].str();
  if (match[6].matched) parts.query = match[7].str();
  return parts; // the fragment (group 9) is not kept: clause 2.4 "After parsing R set R.fragment = null"
}

bool trailing_dot_dot(const std::string &path) { return path == ".." || path.ends_with("/.."); }

//------------------------------------------------------------------------------
// RFC 3986 clause 5.2.4 with the modifications of Canonical XML 1.1 clause 2.4: "Keep leading "../" segments",
// "Replace multiple consecutive "/" characters with a single "/" character", "Append a "/" character to a trailing
// ".." segment".
std::string remove_dot_segments(const std::string &input) {
  std::string path;
  for (const char character : input)
    if (character != '/' || path.empty() || path.back() != '/') path.push_back(character);
  if (trailing_dot_dot(path)) path += "/";
  const bool absolute = path.starts_with("/");
  std::vector<std::string> segments{""};
  for (const char character : absolute ? path.substr(1) : path) {
    if (character == '/')
      segments.emplace_back();
    else
      segments.back().push_back(character);
  }
  std::vector<std::string> out;
  bool trailing_slash = false;
  for (std::size_t i = 0; i < segments.size(); ++i) {
    const bool last = i + 1 == segments.size();
    const auto &segment = segments[i];
    if (segment == ".") {
      trailing_slash = last;
    } else if (segment == "..") {
      if (!out.empty() && out.back() != "..")
        out.pop_back();
      else if (!absolute)
        out.push_back("..");
      trailing_slash = last;
    } else if (segment.empty()) {
      trailing_slash = last && !out.empty();
    } else {
      out.push_back(segment);
      trailing_slash = false;
    }
  }
  std::string body;
  for (std::size_t i = 0; i < out.size(); ++i) body += (i ? "/" : "") + out[i];
  return (absolute ? "/" : "") + body + (trailing_slash && !body.empty() ? "/" : "");
}

//------------------------------------------------------------------------------
// RFC 3986 clause 5.2.3.
std::string merge(const Parts &base, const std::string &path) {
  if (base.authority && base.path.empty()) return "/" + path;
  const auto slash = base.path.rfind('/');
  return (slash == std::string::npos ? std::string{} : base.path.substr(0, slash + 1)) + path;
}

//------------------------------------------------------------------------------
// Helpers on libxml2 attributes.
bool in_xml_namespace(xmlAttrPtr attr) {
  return attr->ns && attr->ns->href &&
         std::strcmp(reinterpret_cast<const char *>(attr->ns->href), reinterpret_cast<const char *>(XML_XML_NAMESPACE)) ==
             0;
}

bool named(xmlAttrPtr attr, const char *name) { return std::strcmp(reinterpret_cast<const char *>(attr->name), name) == 0; }

xmlAttrPtr xml_base_of(xmlNodePtr element) {
  for (auto *attr = element->properties; attr; attr = attr->next)
    if (in_xml_namespace(attr) && named(attr, "base")) return attr;
  return nullptr;
}

std::string value_of(xmlAttrPtr attr) {
  xmlChar *value = xmlNodeListGetString(attr->doc, attr->children, 1);
  std::string out = value ? reinterpret_cast<const char *>(value) : "";
  if (value) xmlFree(value);
  return out;
}

//------------------------------------------------------------------------------
// The changes made to a document for one canonicalization, undone in reverse order on destruction.
class Prepared {
public:
  Prepared() = default;
  Prepared(const Prepared &) = delete;
  Prepared &operator=(const Prepared &) = delete;
  ~Prepared() {
    for (auto step = undo_.rbegin(); step != undo_.rend(); ++step) (*step)();
  }

  // Takes an attribute out of its element's attribute list.
  void hide(xmlAttrPtr attr) {
    auto *owner = attr->parent;
    auto *before = attr->prev;
    auto *after = attr->next;
    if (before)
      before->next = after;
    else
      owner->properties = after;
    if (after) after->prev = before;
    undo_.push_back([=] {
      attr->prev = before;
      attr->next = after;
      if (before)
        before->next = attr;
      else
        owner->properties = attr;
      if (after) after->prev = attr;
    });
  }

  // Gives an element an xml:base attribute of the value (as text, no entity references).
  xmlAttrPtr add_base(xmlNodePtr element, xmlNsPtr ns, const std::string &value) {
    auto *attr = xmlNewNsProp(element, ns, reinterpret_cast<const xmlChar *>("base"),
                              reinterpret_cast<const xmlChar *>(value.c_str()));
    require(attr != nullptr, "XML allocation failed");
    undo_.push_back([attr] { xmlRemoveProp(attr); });
    return attr;
  }

private:
  std::vector<std::function<void()>> undo_;
};

//------------------------------------------------------------------------------
// The planned change of a visible element's xml:base: its own attribute (or none), the attribute whose namespace
// node names the result, and the fixed-up value (nothing when it is not rendered).
struct BaseFixUp {
  xmlNodePtr element = nullptr;
  xmlAttrPtr own = nullptr;
  xmlNsPtr ns = nullptr;
  std::optional<std::string> value;
};

} // namespace

//------------------------------------------------------------------------------
// Canonical XML 1.1 clause 2.4 "join-URI-References": RFC 3986 clauses 5.2.1, 5.2.2 (with 5.2.3) and 5.2.4, then
// 5.3, with its modifications: 5.2.1 "The scheme component is not required in the base URI" and "Replace a trailing
// ".." segment with "../" segment before processing"; 5.2.2 "After parsing R set R.fragment = null"; 5.2.4 as in
// remove_dot_segments.
std::string join_uri_references(std::string_view base, std::string_view reference) {
  auto b = parse(base);
  if (trailing_dot_dot(b.path)) b.path += "/";
  const auto r = parse(reference);
  Parts t;
  if (r.scheme) {
    t.scheme = r.scheme;
    t.authority = r.authority;
    t.path = remove_dot_segments(r.path);
    t.query = r.query;
  } else {
    t.scheme = b.scheme;
    if (r.authority) {
      t.authority = r.authority;
      t.path = remove_dot_segments(r.path);
      t.query = r.query;
    } else {
      t.authority = b.authority;
      if (r.path.empty()) {
        t.path = b.path;
        t.query = r.query ? r.query : b.query;
      } else {
        t.path = remove_dot_segments(r.path.starts_with("/") ? r.path : merge(b, r.path));
        t.query = r.query;
      }
    }
  }
  // RFC 3986 clause 5.3, without a fragment.
  std::string out;
  if (t.scheme) out += *t.scheme + ":";
  if (t.authority) out += "//" + *t.authority;
  out += t.path;
  if (t.query) out += "?" + *t.query;
  return out;
}

//------------------------------------------------------------------------------
// Canonical XML 1.1 clause 2.4 for the elements E of the node-set:
// - xml:lang and xml:space: "All element nodes along E's ancestor axis are examined for the nearest occurrences" not
//   in E's attribute axis, merged into it when E's parent is omitted: libxml2's Canonical XML 1.0 processing, kept.
// - xml:id "is not a simple inheritable attribute and no processing of these attributes is performed", and other
//   xml: attributes "MUST be processed as ordinary attributes": hidden from libxml2 on omitted elements, so that
//   its Canonical XML 1.0 processing does not import them.
// - xml:base: the fix-up "is only performed if at least one of E1 ... En" (the contiguously omitted ancestors) "had
//   an xml:base attribute"; the values X1 ... Xm on E1 ... En+1 are "reduced in reverse document order to a single
//   value by first combining Xm with Xm-1, then the result with Xm-2, and so on" with join-URI-References, and an
//   empty result "MUST NOT be rendered". Without a fix-up E's own xml:base is an ordinary attribute (also empty).
//   Example 3.8 as corrected by W3C erratum E11-01 (2008): e3's xml:base joins only e2's ("bar/foo"); the
//   Recommendation's own "something/bar/foo" also joined the xml:base of doc, beyond the rendered e1.
int c14n11_execute(xmlDocPtr doc, xmlC14NIsVisibleCallback is_visible, void *user_data, int with_comments,
                   xmlOutputBufferPtr buffer) {
  require(doc != nullptr, "XML canonicalization failed");
  const auto visible = [&](xmlNodePtr node) {
    return is_visible == nullptr || is_visible(user_data, node, node->parent) != 0;
  };
  std::vector<xmlNodePtr> hidden_from;
  std::vector<BaseFixUp> fix_ups;
  // Whether a visible element has an xml:base during the call (its own, or the fixed-up one), by element: ancestors
  // come before their descendants in the plan.
  std::unordered_map<xmlNodePtr, bool> has_base;
  // Whether E has, in its attribute axis, an attribute of the name and namespace of an ancestor's.
  const auto attr_visible = [&](xmlAttrPtr attr) {
    return is_visible == nullptr || is_visible(user_data, reinterpret_cast<xmlNodePtr>(attr), attr->parent) != 0;
  };
  const auto carries = [&](xmlNodePtr element, xmlAttrPtr of) {
    for (auto *attr = element->properties; attr; attr = attr->next)
      if (in_xml_namespace(attr) && named(attr, reinterpret_cast<const char *>(of->name)) && attr_visible(attr))
        return true;
    return false;
  };
  std::vector<xmlNodePtr> pending;
  for (auto *node = doc->children; node; node = node->next)
    if (node->type == XML_ELEMENT_NODE) pending.push_back(node);
  // The plan, from the document as it is.
  while (!pending.empty()) {
    auto *element = pending.back();
    pending.pop_back();
    for (auto *child = element->children; child; child = child->next)
      if (child->type == XML_ELEMENT_NODE) pending.push_back(child);
    if (!visible(element)) {
      hidden_from.push_back(element);
      continue;
    }
    auto *own = xml_base_of(element);
    std::vector<std::string> values; // Xm first (E's own)
    if (own) values.push_back(value_of(own));
    xmlAttrPtr naming = own;
    bool omitted = false;
    auto *current = element->parent;
    for (; current && current->type == XML_ELEMENT_NODE && !visible(current); current = current->parent) {
      if (auto *base = xml_base_of(current)) {
        values.push_back(value_of(base));
        omitted = true;
        if (!naming) naming = base;
      }
    }
    std::optional<std::string> value;
    if (omitted) {
      std::string joined = values.front();
      for (std::size_t i = 1; i < values.size(); ++i) joined = join_uri_references(values[i], joined);
      if (!joined.empty()) value = joined;
      fix_ups.push_back(BaseFixUp{element, own, naming->ns, value});
    }
    // An own xml:base outside the node-set is not in E's attribute axis for libxml2 (the fixed-up one is checked
    // when it is added).
    has_base[element] = omitted ? value.has_value() : own != nullptr && attr_visible(own);
    // When E's parent is omitted, libxml2 merges into E's attribute axis the nearest xml: attribute of each name of
    // every ancestor as it is during the call, unless E has one of that name. The omitted ancestors then keep only
    // xml:lang and xml:space (inherited, as the clause wants); a visible ancestor beyond the omitted ones keeps its
    // xml: attributes and its own or fixed-up xml:base, and any of them other than xml:lang and xml:space would be
    // merged into E against the clause: such a node-set is refused rather than canonicalized with them.
    if (current != element->parent)
      for (; current && current->type == XML_ELEMENT_NODE; current = current->parent) {
        if (!visible(current)) continue;
        for (auto *attr = current->properties; attr; attr = attr->next)
          if (in_xml_namespace(attr) && !named(attr, "lang") && !named(attr, "space") && !named(attr, "base"))
            require(carries(element, attr), "unsupported node-set for Canonical XML 1.1");
        require(!has_base.at(current) || has_base.at(element), "unsupported node-set for Canonical XML 1.1");
      }
  }
  // The changes, undone when the call ends.
  Prepared prepared;
  for (auto *element : hidden_from) {
    std::vector<xmlAttrPtr> attrs;
    for (auto *attr = element->properties; attr; attr = attr->next)
      if (in_xml_namespace(attr) && !named(attr, "lang") && !named(attr, "space")) attrs.push_back(attr);
    for (auto *attr : attrs) prepared.hide(attr);
  }
  for (const auto &fix_up : fix_ups) {
    if (fix_up.own) prepared.hide(fix_up.own);
    if (fix_up.value)
      require(attr_visible(prepared.add_base(fix_up.element, fix_up.ns, *fix_up.value)),
              "unsupported node-set for Canonical XML 1.1");
  }
  return xmlC14NExecute(doc, is_visible, user_data, XML_C14N_1_0, nullptr, with_comments, buffer);
}

} // namespace mcx::xmlsec
