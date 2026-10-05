// SEAL location management documents: the location-info XML (application/vnd.3gpp.seal-location-info+xml) that
// a location management client and an MC service server exchange with the location management server over HTTP.
//
// Specifications: TS 24.545 (clauses 6.2 and 7), TS 23.032, RFC 3339.

#include "mcx/seal_location.hpp"

#include "mcx/protocol.hpp"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <charconv>
#include <memory>
#include <stdexcept>

namespace mcx::seal {
namespace {

constexpr const char *ns = "urn:3gpp:ns:sealLocationInfo:1.0";
constexpr const char *ext_ns = "urn:openmcx:ns:sealLocation:1.0";
constexpr std::size_t max_body = 256 * 1024;

//------------------------------------------------------------------------------
// Helper: refuses a location-info document.
[[noreturn]] void invalid(const std::string &why) { throw std::runtime_error("seal location-info: " + why); }

//------------------------------------------------------------------------------
// Helper: an XML element with its content (already escaped) and attributes.
std::string element(const std::string &name, const std::string &inner, const std::string &attrs = {}) {
  return "<" + name + attrs + ">" + inner + "</" + name + ">";
}

//------------------------------------------------------------------------------
// TS 24.545 clause 7: the <location-info> root element of a document.
std::string root(const std::string &inner) {
  return std::string("<?xml version=\"1.0\" encoding=\"UTF-8\"?><location-info xmlns=\"") + ns + "\">" + inner +
         "</location-info>";
}

//------------------------------------------------------------------------------
// TS 24.545 clause 7: a <VAL-user-id> with a <sealURI>.
std::string user_id(const std::string &id) { return element("VAL-user-id", element("sealURI", xml_escape(id))); }

//------------------------------------------------------------------------------
// TS 24.545 clause 7: the <identity> of the sender.
std::string identity(const std::string &id) { return element("identity", user_id(id)); }

//------------------------------------------------------------------------------
// TS 24.545 clause 7: an <identities-list> of the users concerned.
std::string identities(const std::vector<std::string> &ids) {
  std::string out;
  for (const auto &id : ids) out += user_id(id);
  return element("identities-list", out);
}

//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: a point as longitude and latitude, each coded in three bytes (<threebytes>).
std::string point(const char *name, const Fix &fix) {
  return element(name, element("longitude", element("threebytes", std::to_string(fix.longitude))) +
                           element("latitude", element("threebytes", std::to_string(fix.latitude))));
}

using Doc = std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)>;

//------------------------------------------------------------------------------
// TS 24.545 clause 7: parses a location-info document; bodies with a DTD, entities, NUL bytes or over 256 KiB
// are refused.
Doc document(std::string_view body) {
  if (body.empty() || body.size() > max_body || body.find('\0') != body.npos)
    invalid("empty, oversized or binary body");
  if (body.find("<!DOCTYPE") != body.npos || body.find("<!ENTITY") != body.npos)
    invalid("DTD and entities are unsupported");
  Doc doc(xmlReadMemory(body.data(), static_cast<int>(body.size()), "seal.xml", nullptr,
                        XML_PARSE_NONET | XML_PARSE_NOBLANKS | XML_PARSE_NOERROR | XML_PARSE_NOWARNING),
          xmlFreeDoc);
  if (!doc || doc->intSubset || doc->extSubset) invalid("invalid XML document");
  auto *top = xmlDocGetRootElement(doc.get());
  if (!top || !xmlStrEqual(top->name, BAD_CAST "location-info") || !top->ns || !xmlStrEqual(top->ns->href, BAD_CAST ns))
    invalid("not a location-info document");
  return doc;
}

//------------------------------------------------------------------------------
// Helper: whether the node is the element `name` in the namespace `space`.
bool is(xmlNode *node, const char *name, const char *space = ns) {
  return node && node->type == XML_ELEMENT_NODE && xmlStrEqual(node->name, BAD_CAST name) && node->ns &&
         xmlStrEqual(node->ns->href, BAD_CAST space);
}

//------------------------------------------------------------------------------
// Helper: the child elements `name` of the parent.
std::vector<xmlNode *> all(xmlNode *parent, const char *name, const char *space = ns) {
  std::vector<xmlNode *> out;
  if (parent)
    for (auto *child = parent->children; child; child = child->next)
      if (is(child, name, space)) out.push_back(child);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the first child element `name` of the parent, or null.
xmlNode *one(xmlNode *parent, const char *name, const char *space = ns) {
  const auto found = all(parent, name, space);
  return found.empty() ? nullptr : found.front();
}

//------------------------------------------------------------------------------
// Helper: an element directly in the parent or in its <anyExt>.
xmlNode *one_ext(xmlNode *parent, const char *name, const char *space = ns) {
  if (auto *found = one(parent, name, space)) return found;
  for (auto *ext : all(parent, "anyExt"))
    if (auto *found = one(ext, name, space)) return found;
  return nullptr;
}

//------------------------------------------------------------------------------
// Helper: the text content of an element without leading and trailing white space; empty for null.
std::string text(xmlNode *node) {
  if (!node) return {};
  xmlChar *value = xmlNodeGetContent(node);
  std::string out = value ? reinterpret_cast<char *>(value) : "";
  xmlFree(value);
  const auto first = out.find_first_not_of(" \t\r\n"), last = out.find_last_not_of(" \t\r\n");
  return first == std::string::npos ? std::string{} : out.substr(first, last - first + 1);
}

//------------------------------------------------------------------------------
// Helper: the value of an attribute, empty when absent.
std::string attr(xmlNode *node, const char *key) {
  xmlChar *value = xmlGetProp(node, BAD_CAST key);
  std::string out = value ? reinterpret_cast<char *>(value) : "";
  xmlFree(value);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the integer content of an element, refused outside [min, max].
std::int64_t integer(xmlNode *node, std::int64_t min, std::int64_t max) {
  const auto digits = text(node);
  std::int64_t value = 0;
  const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
  if (ec != std::errc{} || end != digits.data() + digits.size() || value < min || value > max)
    invalid("invalid number '" + digits + "'");
  return value;
}

//------------------------------------------------------------------------------
// TS 24.545 clause 7: the value of a contentType element: its <sealURI> or <sealString>, else its text.
std::string content(xmlNode *node) {
  if (auto *uri = one(node, "sealURI")) return text(uri);
  if (auto *str = one(node, "sealString")) return text(str);
  return text(node);
}

//------------------------------------------------------------------------------
// TS 24.545 clause 7: the <VAL-user-id> values of an <identities-list>.
std::vector<std::string> ids(xmlNode *list) {
  std::vector<std::string> out;
  for (auto *entry : all(list, "VAL-user-id")) out.push_back(content(entry));
  return out;
}

} // namespace

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.2.3.1: reads the location reporting configuration a client receives (<periodic-report>,
// <minimum-interval-length>) and, in the openMCX <anyExt> extension, where it reports.
Configuration parse_configuration(std::string_view xml) {
  const auto doc = document(xml);
  auto *top = xmlDocGetRootElement(doc.get());
  auto *config = one(top, "configuration");
  if (!config) invalid("missing <configuration>");
  Configuration out;
  if (auto *criteria = one(config, "triggering-criteria"))
    if (auto *periodic = one(criteria, "periodic-report"))
      out.periodic = static_cast<unsigned>(integer(periodic, 1, 86400));
  if (auto *minimum = one(config, "minimum-interval-length"))
    out.minimum_interval = static_cast<unsigned>(integer(minimum, 1, 86400));
  out.report_uri = text(one_ext(top, "report-uri", ext_ns));
  out.history_uri = text(one_ext(top, "history-uri", ext_ns));
  return out;
}

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.2.2.2: a client's location report, with the trigger that caused it.
std::string report_xml(const std::string &user, const std::string &trigger, const Fix &fix) {
  std::string report = trigger.empty() ? std::string{} : element("trigger-id", xml_escape(trigger));
  report += element("current-location", point("current-geographical-coordinate", fix));
  if (!fix.timestamp.empty()) report += element("anyExt", element("timestamp", xml_escape(fix.timestamp)));
  return root(identity(user) + element("report", report));
}

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.20.2: the positions a client stored while it could not report.
std::string history_xml(const std::string &subscription, const std::vector<Fix> &fixes) {
  std::string inner = element("subscription-identifier", xml_escape(subscription));
  for (const auto &fix : fixes)
    inner += element("reports", element("current-location", point("current-geographical-coordinate", fix)) +
                                    element("anyExt", element("timestamp", xml_escape(fix.timestamp))));
  // <history-loc-result-report> is an element of <anyExt> in the schema (TS 24.545 clause 7.4.2).
  return root(element("anyExt", element("history-loc-result-report", inner)));
}

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.6.1.2: an MC service server's location reporting subscription for users.
std::string subscription_xml(const std::string &server, const std::vector<std::string> &users, unsigned interval,
                             unsigned expiry) {
  // TS 24.545 clause 7.5: <expiry-time> is the subscription's expiry in seconds (0 deletes it). The schema types it
  // xs:nonPositiveInteger by mistake; the clause 7.5 meaning, positive seconds, is followed.
  return root(identity(server) +
              element("subscription", identities(users) + element("time-interval-length", std::to_string(interval)) +
                                          element("expiry-time", std::to_string(expiry))));
}

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.6.1.2: deletes a subscription (expiry time 0).
std::string unsubscription_xml(const std::string &server, const std::string &subscription) {
  return root(identity(server) + element("subscription-identifier", xml_escape(subscription)) +
              element("expiry-time", "0"));
}

//------------------------------------------------------------------------------
// TS 24.545 clause 6.2.8.1: an on-demand location request; with history, the stored positions too.
std::string request_xml(const std::string &server, const std::vector<std::string> &users, bool history) {
  std::string inner = identity(server) + identities(users);
  if (history) inner += element("anyExt", std::string("<history xmlns=\"") + ext_ns + "\"/>");
  return root(inner);
}

//------------------------------------------------------------------------------
// TS 24.545 clause 7: reads an answer or notification of the location management server: subscription,
// expiry, users and their latest positions.
Answer parse_answer(std::string_view xml) {
  const auto doc = document(xml);
  auto *top = xmlDocGetRootElement(doc.get());
  Answer out;
  auto *holder = top;
  if (auto *notification = one(top, "notification")) {
    out.notification = true;
    out.trigger = attr(notification, "trigger-id");
    holder = notification;
  }
  if (auto *sub = one(holder, "subscription-identifier")) out.subscription = text(sub);
  if (auto *sub = one(top, "subscription"))
    if (auto *id = one(sub, "subscription-identifier")) out.subscription = text(id);
  if (auto *expiry = one(top, "expiry-time")) out.expiry = static_cast<int>(integer(expiry, -31536000, 31536000));
  if (auto *list = one(holder, "identities-list")) out.users = ids(list);
  for (auto *reports : all(holder, "reports"))
    for (auto *report : all(reports, "loc-info-report")) {
      UserFix entry;
      if (auto *id = one(report, "VAL-user-id")) entry.user = content(id);
      auto *latest = one(report, "latest-location");
      auto *coordinate = one(latest, "latest-coordinate");
      if (!coordinate) continue;
      entry.fix.longitude =
          static_cast<std::uint32_t>(integer(one(one(coordinate, "longitude"), "threebytes"), 0, 0xffffff));
      entry.fix.latitude =
          static_cast<std::uint32_t>(integer(one(one(coordinate, "latitude"), "threebytes"), 0, 0xffffff));
      entry.fix.timestamp = text(one_ext(report, "timestamp"));
      entry.fix.history = one_ext(report, "history", ext_ns) != nullptr;
      out.reports.push_back(std::move(entry));
    }
  return out;
}

} // namespace mcx::seal
