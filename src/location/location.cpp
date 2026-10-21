//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Location information of MC service users: the location-info XML body (configuration, request, report) of
// TS 24.379 annex F.3, TS 24.282 annex D.4 and TS 24.281 annex F.3, the TS 23.032 coordinate coding, the
// client's reporting triggers (TS 24.379 clause 13.3, TS 24.282 clause 17.3, TS 24.281 clause 18.3) and the
// participating function's location registry (TS 24.379 clause 13.2, TS 24.282 clause 17.2, TS 24.281 clause 18.2).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 23.032.

#include "mcx/location.hpp"

#include "mcx/protocol.hpp"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <memory>
#include <regex>
#include <stdexcept>
#include <utility>

namespace mcx::location {
namespace {
constexpr double earth_radius = 6371008.8;
constexpr double pi = 3.14159265358979323846;
constexpr std::size_t max_body = 65536;
constexpr const char *mcptt_ns = "urn:3gpp:ns:mcpttLocationInfo:1.0";
constexpr const char *mcdata_ns = "urn:3gpp:ns:mcdataLocationInfo:1.0";
constexpr const char *mcvideo_ns = "urn:3gpp:ns:mcvideoLocationInfo:1.0";

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the service's name in its elements: <Mcptt...SignallingEvent>, <mcptt-reporting-uri>.
const char *capitalised(Service service) {
  return service == Service::Mcptt ? "Mcptt" : service == Service::Mcdata ? "Mcdata" : "Mcvideo";
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the service's name in lower case, as in <mcptt-reporting-uri>.
const char *lower(Service service) {
  return service == Service::Mcptt ? "mcptt" : service == Service::Mcdata ? "mcdata" : "mcvideo";
}

using Doc = std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)>;

//------------------------------------------------------------------------------
// Helper: refuses a location-info document.
[[noreturn]] void invalid(const std::string &message) { throw std::runtime_error("location-info: " + message); }

//------------------------------------------------------------------------------
// Helper: degrees to radians.
double radians(double degrees) { return degrees * pi / 180; }

//------------------------------------------------------------------------------
// Helper: a trigger of this kind with its TriggerId, and the radio dimension and value it watches.
Trigger trigger(Trigger::Kind kind, std::string id, Dimension dimension = Dimension::Cell, std::string value = {}) {
  Trigger result;
  result.kind = kind;
  result.id = std::move(id);
  result.dimension = dimension;
  result.value = std::move(value);
  return result;
}

//------------------------------------------------------------------------------
// A point in metres on the plane tangent at (lat0, lon0).
struct Xy {
  double x, y;
};

//------------------------------------------------------------------------------
// Helper: the point (lat, lon) projected on the plane tangent at (lat0, lon0), in metres.
Xy project(double lat0, double lon0, double lat, double lon) {
  return {radians(lon - lon0) * std::cos(radians(lat0)) * earth_radius, radians(lat - lat0) * earth_radius};
}

//------------------------------------------------------------------------------
// Helper: the distance in metres from a point to the segment from start to end, on the tangent plane.
double segment_distance(Xy point, Xy start, Xy end) {
  const double dx = end.x - start.x, dy = end.y - start.y, length = dx * dx + dy * dy;
  const double fraction =
      length == 0 ? 0 : std::clamp(((point.x - start.x) * dx + (point.y - start.y) * dy) / length, 0.0, 1.0);
  return std::hypot(point.x - start.x - fraction * dx, point.y - start.y - fraction * dy);
}

//------------------------------------------------------------------------------
// Helper: the initial great-circle bearing in degrees from the first point to the second.
double bearing(double lat1, double lon1, double lat2, double lon2) {
  const double east = std::sin(radians(lon2 - lon1)) * std::cos(radians(lat2));
  const double north = std::cos(radians(lat1)) * std::sin(radians(lat2)) -
                       std::sin(radians(lat1)) * std::cos(radians(lat2)) * std::cos(radians(lon2 - lon1));
  return std::fmod(std::atan2(east, north) * 180 / pi + 360, 360);
}

//------------------------------------------------------------------------------
// Helper: the point reached from (lat, lon) along a great circle with this bearing and distance.
std::pair<double, double> destination(double lat, double lon, double bearing_degrees, double metres) {
  const double angular = metres / earth_radius, heading = radians(bearing_degrees), lat1 = radians(lat);
  const double lat2 =
      std::asin(std::sin(lat1) * std::cos(angular) + std::cos(lat1) * std::sin(angular) * std::cos(heading));
  const double lon2 = radians(lon) + std::atan2(std::sin(heading) * std::sin(angular) * std::cos(lat1),
                                                std::cos(angular) - std::sin(lat1) * std::sin(lat2));
  return {lat2 * 180 / pi, std::fmod(lon2 * 180 / pi + 540, 360) - 180};
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2: the formats the schema gives the ECGI, NCGI, TAI, 5G TAI, PLMN, MBMS SA, MBSFN area and
// 5G MBSFSA identities; a RAT is any short text.
void check_identity(Dimension dimension, const std::string &value) {
  static const std::regex ecgi(R"(\d{6}[01]{28})"), ncgi(R"(\d{6}[01]{36})"), tai(R"(\d{6}[01]{16})"),
      tai5g(R"([A-Fa-f0-9]{4}|[A-Fa-f0-9]{6})"), plmn(R"(\d{6})"), hex6(R"([A-Fa-f0-9]{6})"), digits(R"(\d{1,5})");
  bool ok = false;
  switch (dimension) {
  case Dimension::Cell: ok = std::regex_match(value, ecgi); break;
  case Dimension::NrCell: ok = std::regex_match(value, ncgi); break;
  case Dimension::TrackingArea: ok = std::regex_match(value, tai); break;
  case Dimension::TrackingArea5G: ok = std::regex_match(value, tai5g); break;
  case Dimension::Plmn: ok = std::regex_match(value, plmn); break;
  case Dimension::MbmsSa: ok = std::regex_match(value, digits) && std::stoul(value) <= 65535; break;
  case Dimension::Mbsfn: ok = std::regex_match(value, digits) && std::stoul(value) <= 255; break;
  case Dimension::Mbsfsa5G: ok = std::regex_match(value, hex6); break;
  case Dimension::Rat: ok = !value.empty() && value.size() <= 64; break;
  }
  if (!ok) invalid("malformed identity '" + value + "'");
}

// ---- generation ----
//------------------------------------------------------------------------------
// Helper: an XML element with its content (already escaped) and attributes; empty content gives <name/>.
std::string element(const std::string &name, const std::string &body, const std::string &attributes = {}) {
  return "<" + name + attributes + (body.empty() ? "/>" : ">" + body + "</" + name + ">");
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the mandatory TriggerId attribute of a trigger.
std::string id_attribute(const std::string &id) {
  if (id.empty() || id.size() > 256) invalid("a trigger needs a TriggerId");
  return " TriggerId=\"" + xml_escape(id) + "\"";
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: a point: longitude and latitude coded as in TS 23.032 clause 6.1, and in <anyExt> the
// altitude (TS 23.032 clause 6.3) and the horizontal and vertical uncertainty codes (TS 23.032 clauses 6.2 and 6.4).
std::string point_xml(const Point &point) {
  if (point.latitude > 0xffffff || point.longitude > 0xffffff) invalid("coordinate exceeds 24 bits");
  std::string ext;
  if (point.altitude)
    ext += element("altitude", element("twobytes", std::to_string(*point.altitude)), " type=\"Normal\"");
  const auto uncertainty = [&](const char *name, std::optional<std::uint8_t> code) {
    if (!code) return;
    if (*code > 127) invalid("uncertainty code exceeds 127");
    ext += element(name, element("onebyteunsignedhalfrange", std::to_string(*code)), " type=\"Normal\"");
  };
  uncertainty("horizontalaccuracy", point.horizontal_accuracy);
  uncertainty("verticalaccuracy", point.vertical_accuracy);
  return element("longitude", element("threebytes", std::to_string(point.longitude)), " type=\"Normal\"") +
         element("latitude", element("threebytes", std::to_string(point.latitude)), " type=\"Normal\"") +
         (ext.empty() ? "" : element("anyExt", ext));
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: a <GeographicalArea>: a polygon of 3 to 15 corners (TS 23.032 clause 5.4) or an
// ellipsoid arc (TS 23.032 clause 5.7), with the <InnerBorderWidth> and <OuterBorderWidth> in <anyExt>.
std::string area_xml(const Area &area) {
  std::string body;
  if (!area.polygon.empty()) {
    if (area.polygon.size() < 3 || area.polygon.size() > 15 || area.center)
      invalid("an area is a polygon of 3 to 15 corners or an arc");
    std::string corners;
    for (const auto &corner : area.polygon) corners += element("Corner", point_xml(corner));
    body += element("PolygonArea", corners);
  } else if (area.center) {
    body += element("EllipsoidArcArea", element("Center", point_xml(*area.center)) +
                                            element("Radius", std::to_string(area.radius)) +
                                            element("OffsetAngle", std::to_string(area.offset_angle)) +
                                            element("IncludedAngle", std::to_string(area.included_angle)));
  } else
    invalid("an area needs a polygon or an arc");
  if (area.inner_border > 127 || area.outer_border > 127) invalid("border width exceeds 127");
  std::string ext;
  if (area.inner_border) ext += element("InnerBorderWidth", std::to_string(area.inner_border));
  if (area.outer_border) ext += element("OuterBorderWidth", std::to_string(area.outer_border));
  if (!ext.empty()) body += element("anyExt", ext);
  return element("GeographicalArea", body);
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the element name of a signalling event trigger.
const char *event_name(Event event) {
  switch (event) {
  case Event::InitialLogOn: return "InitialLogOn";
  case Event::GroupCallNonEmergency: return "GroupCallNonEmergency";
  case Event::PrivateCallNonEmergency: return "PrivateCallNonEmergency";
  case Event::LocationConfigurationReceived: return "LocationConfigurationReceived";
  case Event::FunctionalAliasActivation: return "FunctionalAliasActivation";
  case Event::FunctionalAliasDeactivation: return "FunctionalAliasDeactivation";
  }
  return "";
}

//------------------------------------------------------------------------------
// The element names of a radio dimension: {change, any, enter, exit}.
struct RadioNames {
  const char *change, *any, *enter, *exit;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the change, any-change, enter and exit element names of a radio dimension.
RadioNames radio_names(Dimension dimension) {
  switch (dimension) {
  case Dimension::Cell: return {"CellChange", "AnyCellChange", "EnterSpecificCell", "ExitSpecificCell"};
  case Dimension::NrCell: return {"CellChange", "AnyCellChange", "EnterSpecificNRCell", "ExitSpecificNRCell"};
  case Dimension::TrackingArea:
    return {"TrackingAreaChange", "AnyTrackingAreaChange", "EnterSpecificTrackingArea", "ExitSpecificTrackingArea"};
  case Dimension::TrackingArea5G:
    return {"NR5GTrackingAreaChange", "Any5GTrackingAreaChange", "EnterSpecific5GTrackingArea",
            "ExitSpecific5GTrackingArea"};
  case Dimension::Plmn: return {"PlmnChange", "AnyPlmnChange", "EnterSpecificPlmn", "ExitSpecificPlmn"};
  case Dimension::MbmsSa: return {"MbmsSaChange", "AnyMbmsSaChange", "EnterSpecificMbmsSa", "ExitSpecificMbmsSa"};
  case Dimension::Mbsfn:
    return {"MbsfnAreaChange", "AnyMbsfnAreaChange", "EnterSpecificMbsfnArea", "ExitSpecificMbsfnArea"};
  case Dimension::Mbsfsa5G:
    return {"NR5GMbsfsaAreaChange", "Any5GMbsfsaAreaChange", "EnterSpecific5GMbsfsaArea", "ExitSpecific5GMbsfsaArea"};
  case Dimension::Rat: return {"RatTypeChange", "AnyRatTypeChange", "", ""};
  }
  return {"", "", "", ""};
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the content of <TriggeringCriteria> or <EmergencyTriggeringCriteria>, in schema order;
// TriggerIds are unique and single-instance triggers appear at most once.
std::string criteria_xml(const std::vector<Trigger> &triggers, Service service) {
  std::set<std::string> ids;
  for (const auto &entry : triggers)
    if (!ids.insert(entry.id).second) invalid("TriggerId '" + entry.id + "' is used twice");

  const auto of = [&](Trigger::Kind kind) {
    std::vector<const Trigger *> out;
    for (const auto &entry : triggers)
      if (entry.kind == kind) out.push_back(&entry);
    return out;
  };
  const auto single = [&](Trigger::Kind kind, const char *what) -> const Trigger * {
    const auto found = of(kind);
    if (found.size() > 1) invalid(std::string("at most one ") + what + " trigger");
    return found.empty() ? nullptr : found.front();
  };

  // The radio changes: an Any element at most once per change element; the
  // enter/exit values that the schema allows only once in the element itself go
  // to its <anyExt> (MBMS SA, MBSFN area and 5G MBSFSA).
  const auto radio = [&](std::initializer_list<Dimension> dims, bool any_in_ext, bool single_specific) {
    std::string any, specific, ext;
    int any_count = 0, enters = 0, exits = 0;
    for (const auto &entry : triggers) {
      if (std::find(dims.begin(), dims.end(), entry.dimension) == dims.end()) continue;
      const auto names = radio_names(entry.dimension);
      if (entry.kind == Trigger::Kind::AnyChange) {
        if (++any_count > 1) invalid(std::string("at most one ") + names.any);
        (any_in_ext ? ext : any) += element(names.any, "", id_attribute(entry.id));
      } else if (entry.kind == Trigger::Kind::Enter || entry.kind == Trigger::Kind::Exit) {
        if (!*names.enter) invalid("a RAT change trigger has no specific values");
        check_identity(entry.dimension, entry.value);
        const bool enter = entry.kind == Trigger::Kind::Enter;
        const auto xml = element(enter ? names.enter : names.exit, xml_escape(entry.value), id_attribute(entry.id));
        const bool nr = entry.dimension == Dimension::NrCell;
        const bool extra = nr || (single_specific && ++(enter ? enters : exits) > 1);
        (extra ? ext : specific) += xml;
      }
    }
    if (any.empty() && specific.empty() && ext.empty()) return std::string{};
    return element(radio_names(*dims.begin()).change, any + specific + (ext.empty() ? "" : element("anyExt", ext)));
  };

  std::string body = radio({Dimension::Cell, Dimension::NrCell}, false, false) +
                     radio({Dimension::TrackingArea}, false, false) + radio({Dimension::Plmn}, false, false) +
                     radio({Dimension::MbmsSa}, false, true) + radio({Dimension::Mbsfn}, true, true);
  if (const auto *entry = single(Trigger::Kind::Periodic, "periodic")) {
    if (!entry->amount) invalid("a periodic report needs an interval");
    body += element("PeriodicReport", std::to_string(entry->amount), id_attribute(entry->id));
  }
  if (const auto *entry = single(Trigger::Kind::Distance, "travelled distance")) {
    if (!entry->amount) invalid("a travelled distance needs a distance");
    body += element("TravelledDistance", std::to_string(entry->amount), id_attribute(entry->id));
  }

  std::string events, alias_events;
  std::set<Event> seen;
  for (const auto *entry : of(Trigger::Kind::Signalling)) {
    if (!seen.insert(entry->event).second) invalid(std::string("at most one ") + event_name(entry->event) + " trigger");
    const bool alias =
        entry->event == Event::FunctionalAliasActivation || entry->event == Event::FunctionalAliasDeactivation;
    (alias ? alias_events : events) += element(event_name(entry->event), "", id_attribute(entry->id));
  }
  // Schema order within the signalling event element.
  if (!events.empty() || !alias_events.empty()) {
    std::string ordered;
    for (auto event : {Event::InitialLogOn, Event::GroupCallNonEmergency, Event::PrivateCallNonEmergency,
                       Event::LocationConfigurationReceived})
      for (const auto *entry : of(Trigger::Kind::Signalling))
        if (entry->event == event) ordered += element(event_name(event), "", id_attribute(entry->id));
    body += element(std::string(capitalised(service)) + "SignallingEvent",
                    ordered + (alias_events.empty() ? "" : element("anyExt", alias_events)));
  }

  std::string areas;
  if (const auto *entry = single(Trigger::Kind::AnyArea, "any area change"))
    areas += element("AnyAreaChange", "", id_attribute(entry->id));
  if (const auto *entry = single(Trigger::Kind::EnterArea, "area entry"))
    areas += element("EnterSpecificAreaType", area_xml(entry->area), id_attribute(entry->id));
  if (const auto *entry = single(Trigger::Kind::ExitArea, "area exit"))
    areas += element("ExitSpecificAreaType", area_xml(entry->area), id_attribute(entry->id));
  if (!areas.empty()) body += element("GeographicalAreaChange", areas);

  std::string ext = radio({Dimension::Rat}, false, false) + radio({Dimension::Mbsfsa5G}, true, true) +
                    radio({Dimension::TrackingArea5G}, false, false);
  if (const auto *entry = single(Trigger::Kind::Adaptive, "adaptive")) {
    const auto &adaptive = entry->adaptive;
    std::string inner = element("MinPeriod", std::to_string(adaptive.min_period), id_attribute(entry->id));
    if (adaptive.min_distance) {
      if (!*adaptive.min_distance) invalid("MinDistance is strictly positive");
      inner += element("MinDistance", std::to_string(*adaptive.min_distance));
    }
    inner += element("PersistencePeriod", std::to_string(adaptive.persistence), id_attribute(entry->id));
    if (!adaptive.additional) invalid("AdditionalTime is strictly positive");
    inner += element("AdditionalTime", std::to_string(adaptive.additional));
    ext += element("AddaptiveTrigger", inner, id_attribute(entry->id));
  }
  if (!ext.empty()) body += element("anyExt", ext);
  return body;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the content of <NonEmergencyLocationInformation> or <EmergencyLocationInformation>:
// what the client reports, and the mandatory <minimumIntervalLength>.
std::string requested_xml(const Requested &wanted) {
  std::string body;
  if (wanted.serving_ecgi) body += "<ServingEcgi/>";
  if (wanted.neighbouring_ecgi) body += "<NeighbouringEcgi/>";
  if (wanted.mbms_sa) body += "<MbmsSaId/>";
  if (wanted.mbsfn) body += "<MbsfnArea/>";
  if (wanted.coordinate) body += "<GeographicalCoordinate/>";
  if (!wanted.minimum_interval) invalid("minimumIntervalLength is strictly positive");
  body += element("minimumIntervalLength", std::to_string(wanted.minimum_interval));
  std::string ext;
  if (wanted.serving_ncgi) ext += "<ServingNcgi/>";
  if (wanted.neighbouring_ncgi) ext += "<NeighbouringNcgi/>";
  if (wanted.mbsfsa) ext += "<NR5GMbsfsaArea/>";
  if (wanted.bearing_speed) ext += "<R_BearingAndSpeed/>";
  if (!ext.empty()) body += element("anyExt", ext);
  return body;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: a tLocationType element (type="Normal") with its value, directly or in its <anyExt>.
std::string located(const char *name, const char *inner, const std::string &value, bool in_ext = false) {
  const auto value_xml = element(inner, xml_escape(value));
  return element(name, in_ext ? element("anyExt", value_xml) : value_xml, " type=\"Normal\"");
}

// ---- parsing ----
//------------------------------------------------------------------------------
// Helper: parses a location-info document; bodies with a DTD, entities, NUL bytes or over 64 KiB are refused.
Doc document(std::string_view body) {
  if (body.empty() || body.size() > max_body || body.find('\0') != body.npos)
    invalid("empty, oversized or binary body");
  if (body.find("<!DOCTYPE") != body.npos || body.find("<!ENTITY") != body.npos)
    invalid("DTD and entities are unsupported");
  Doc doc(xmlReadMemory(body.data(), static_cast<int>(body.size()), "location.xml", nullptr,
                        XML_PARSE_NONET | XML_PARSE_NOBLANKS | XML_PARSE_NOERROR | XML_PARSE_NOWARNING),
          xmlFreeDoc);
  if (!doc || doc->intSubset || doc->extSubset) invalid("invalid XML document");
  return doc;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: reads a location-info document in one service's namespace.
struct Reader {
  const char *ns;
  bool optional_ids = false;

  bool is(xmlNode *node, const char *name) const {
    return node && node->type == XML_ELEMENT_NODE && xmlStrEqual(node->name, BAD_CAST name) && node->ns &&
           xmlStrEqual(node->ns->href, BAD_CAST ns);
  }

  // The recipient ignores unknown elements (TS 24.379 annex F.3.3): children are looked up by name.
  std::vector<xmlNode *> all(xmlNode *parent, const char *name) const {
    std::vector<xmlNode *> out;
    if (!parent) return out;
    for (auto child = parent->children; child; child = child->next)
      if (is(child, name)) out.push_back(child);
    return out;
  }

  xmlNode *one(xmlNode *parent, const char *name, bool required = false) const {
    const auto found = all(parent, name);
    if (found.size() > 1) invalid(std::string("duplicate <") + name + ">");
    if (found.empty() && required) invalid(std::string("missing <") + name + ">");
    return found.empty() ? nullptr : found.front();
  }

  // An element or its <anyExt>.
  std::vector<xmlNode *> with_ext(xmlNode *parent, const char *name) const {
    auto out = all(parent, name);
    for (auto *ext : all(parent, "anyExt"))
      for (auto *child : all(ext, name)) out.push_back(child);
    return out;
  }

  xmlNode *one_ext(xmlNode *parent, const char *name) const {
    const auto found = with_ext(parent, name);
    if (found.size() > 1) invalid(std::string("duplicate <") + name + ">");
    return found.empty() ? nullptr : found.front();
  }

  static std::string attr(xmlNode *node, const char *key) {
    xmlChar *value = xmlGetProp(node, BAD_CAST key);
    std::string out = value ? reinterpret_cast<char *>(value) : "";
    xmlFree(value);
    return out;
  }

  static std::string text(xmlNode *node) {
    xmlChar *value = xmlNodeGetContent(node);
    std::string out = value ? reinterpret_cast<char *>(value) : "";
    xmlFree(value);
    const auto first = out.find_first_not_of(" \t\r\n"), last = out.find_last_not_of(" \t\r\n");
    return first == std::string::npos ? std::string{} : out.substr(first, last - first + 1);
  }

  // TS 24.379 annex F.3.3: only "Normal" (unencrypted) content is read; encrypted content must be opened first.
  static void clear(xmlNode *node) {
    const auto type = attr(node, "type");
    if (type == "Encrypted") invalid("encrypted content must be opened first");
    if (!type.empty() && type != "Normal") invalid("unknown protection type");
  }

  static std::int64_t integer(xmlNode *node, std::int64_t min, std::int64_t max) {
    const auto digits = text(node);
    std::int64_t value = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
    if (ec != std::errc{} || end != digits.data() + digits.size() || value < min || value > max)
      invalid("invalid number '" + digits + "'");
    return value;
  }

  std::string id(xmlNode *node) const {
    const auto value = attr(node, "TriggerId");
    if ((value.empty() && !optional_ids) || value.size() > 256) invalid("a trigger needs a TriggerId");
    return value;
  }

  std::int64_t coded(xmlNode *parent, const char *name, const char *inner, std::int64_t min, std::int64_t max) const {
    auto *node = one(parent, name, true);
    clear(node);
    return integer(one(node, inner, true), min, max);
  }

  Point point(xmlNode *node) const {
    Point parsed;
    parsed.longitude = static_cast<std::uint32_t>(coded(node, "longitude", "threebytes", 0, 0xffffff));
    parsed.latitude = static_cast<std::uint32_t>(coded(node, "latitude", "threebytes", 0, 0xffffff));
    for (auto *ext : all(node, "anyExt")) {
      if (one(ext, "altitude"))
        parsed.altitude = static_cast<std::int16_t>(coded(ext, "altitude", "twobytes", -32768, 32767));
      if (one(ext, "horizontalaccuracy"))
        parsed.horizontal_accuracy =
            static_cast<std::uint8_t>(coded(ext, "horizontalaccuracy", "onebyteunsignedhalfrange", 0, 127));
      if (one(ext, "verticalaccuracy"))
        parsed.vertical_accuracy =
            static_cast<std::uint8_t>(coded(ext, "verticalaccuracy", "onebyteunsignedhalfrange", 0, 127));
    }
    return parsed;
  }

  Area area(xmlNode *specific) const {
    auto *geographical = one(specific, "GeographicalArea", true);
    Area parsed;
    if (auto *polygon = one(geographical, "PolygonArea")) {
      for (auto *corner : all(polygon, "Corner")) parsed.polygon.push_back(point(corner));
      if (parsed.polygon.size() < 3 || parsed.polygon.size() > 15) invalid("a polygon has 3 to 15 corners");
    }
    if (auto *arc = one(geographical, "EllipsoidArcArea")) {
      if (!parsed.polygon.empty()) invalid("an area is a polygon or an arc");
      parsed.center = point(one(arc, "Center", true));
      parsed.radius = static_cast<std::uint32_t>(integer(one(arc, "Radius", true), 0, 0xffffffff));
      parsed.offset_angle = static_cast<std::uint8_t>(integer(one(arc, "OffsetAngle", true), 0, 255));
      parsed.included_angle = static_cast<std::uint8_t>(integer(one(arc, "IncludedAngle", true), 0, 255));
    }
    if (parsed.polygon.empty() && !parsed.center) invalid("an area needs a polygon or an arc");
    if (auto *width = one_ext(geographical, "InnerBorderWidth"))
      parsed.inner_border = static_cast<std::uint8_t>(integer(width, 0, 127));
    if (auto *width = one_ext(geographical, "OuterBorderWidth"))
      parsed.outer_border = static_cast<std::uint8_t>(integer(width, 0, 127));
    return parsed;
  }

  // TS 24.379 annex F.3.3: the triggers of <TriggeringCriteria> or <EmergencyTriggeringCriteria>.
  std::vector<Trigger> criteria(xmlNode *criteria_node) const {
    std::vector<Trigger> out;
    const auto radio = [&](xmlNode *change, std::initializer_list<Dimension> dims) {
      if (!change) return;
      for (auto dimension : dims) {
        const auto names = radio_names(dimension);
        if (dimension == *dims.begin())
          for (auto *node : with_ext(change, names.any))
            out.push_back(trigger(Trigger::Kind::AnyChange, id(node), dimension));
        if (!*names.enter) continue;
        for (auto kind : {Trigger::Kind::Enter, Trigger::Kind::Exit})
          for (auto *node : with_ext(change, kind == Trigger::Kind::Enter ? names.enter : names.exit)) {
            auto entry = trigger(kind, id(node), dimension, text(node));
            check_identity(dimension, entry.value);
            out.push_back(entry);
          }
      }
    };

    radio(one(criteria_node, "CellChange"), {Dimension::Cell, Dimension::NrCell});
    radio(one(criteria_node, "TrackingAreaChange"), {Dimension::TrackingArea});
    radio(one(criteria_node, "PlmnChange"), {Dimension::Plmn});
    radio(one(criteria_node, "MbmsSaChange"), {Dimension::MbmsSa});
    radio(one(criteria_node, "MbsfnAreaChange"), {Dimension::Mbsfn});
    radio(one_ext(criteria_node, "RatTypeChange"), {Dimension::Rat});
    radio(one_ext(criteria_node, "NR5GMbsfsaAreaChange"), {Dimension::Mbsfsa5G});
    radio(one_ext(criteria_node, "NR5GTrackingAreaChange"), {Dimension::TrackingArea5G});

    if (auto *node = one(criteria_node, "PeriodicReport")) {
      auto entry = trigger(Trigger::Kind::Periodic, id(node));
      entry.amount = static_cast<std::uint64_t>(integer(node, 1, 86400 * 366));
      out.push_back(entry);
    }
    if (auto *node = one(criteria_node, "TravelledDistance")) {
      auto entry = trigger(Trigger::Kind::Distance, id(node));
      entry.amount = static_cast<std::uint64_t>(integer(node, 1, 40000000));
      out.push_back(entry);
    }

    auto *events = one(criteria_node, "McpttSignallingEvent");
    if (!events) events = one(criteria_node, "McdataSignallingEvent");
    if (!events) events = one(criteria_node, "McvideoSignallingEvent");
    if (events)
      for (auto event :
           {Event::InitialLogOn, Event::GroupCallNonEmergency, Event::PrivateCallNonEmergency,
            Event::LocationConfigurationReceived, Event::FunctionalAliasActivation, Event::FunctionalAliasDeactivation})
        if (auto *node = one_ext(events, event_name(event))) {
          auto entry = trigger(Trigger::Kind::Signalling, id(node));
          entry.event = event;
          out.push_back(entry);
        }

    if (auto *area_change = one(criteria_node, "GeographicalAreaChange")) {
      if (auto *node = one(area_change, "AnyAreaChange")) out.push_back(trigger(Trigger::Kind::AnyArea, id(node)));
      for (auto kind : {Trigger::Kind::EnterArea, Trigger::Kind::ExitArea})
        if (auto *node =
                one(area_change, kind == Trigger::Kind::EnterArea ? "EnterSpecificAreaType" : "ExitSpecificAreaType")) {
          auto entry = trigger(kind, id(node));
          entry.area = area(node);
          out.push_back(entry);
        }
    }

    // The schema names it AddaptiveTrigger, the semantics AdaptiveTrigger.
    auto *adaptive = one_ext(criteria_node, "AddaptiveTrigger");
    if (!adaptive) adaptive = one_ext(criteria_node, "AdaptiveTrigger");
    if (adaptive) {
      auto entry = trigger(Trigger::Kind::Adaptive, id(adaptive));
      if (auto *node = one(adaptive, "MinPeriod"))
        entry.adaptive.min_period = static_cast<std::uint64_t>(integer(node, 0, 86400 * 366));
      if (auto *node = one(adaptive, "MinDistance"))
        entry.adaptive.min_distance = static_cast<std::uint64_t>(integer(node, 1, 40000000));
      if (auto *node = one(adaptive, "PersistencePeriod"))
        entry.adaptive.persistence = static_cast<std::uint64_t>(integer(node, 0, 86400 * 366));
      if (auto *node = one(adaptive, "AdditionalTime"))
        entry.adaptive.additional = static_cast<std::uint64_t>(integer(node, 1, 86400 * 366));
      out.push_back(entry);
    }

    std::set<std::string> ids;
    for (const auto &entry : out)
      if (!entry.id.empty() && !ids.insert(entry.id).second) invalid("TriggerId '" + entry.id + "' is used twice");
    return out;
  }

  // TS 24.379 annex F.3.3: <NonEmergencyLocationInformation> or <EmergencyLocationInformation>.
  Requested requested(xmlNode *node) const {
    Requested parsed;
    parsed.serving_ecgi = one(node, "ServingEcgi");
    parsed.neighbouring_ecgi = !all(node, "NeighbouringEcgi").empty();
    parsed.mbms_sa = one(node, "MbmsSaId");
    parsed.mbsfn = one(node, "MbsfnArea");
    parsed.coordinate = one(node, "GeographicalCoordinate");
    parsed.minimum_interval =
        static_cast<std::uint32_t>(integer(one(node, "minimumIntervalLength", true), 1, 86400 * 366));
    parsed.serving_ncgi = one_ext(node, "ServingNcgi");
    parsed.neighbouring_ncgi = !with_ext(node, "NeighbouringNcgi").empty();
    parsed.mbsfsa = one_ext(node, "NR5GMbsfsaArea");
    parsed.bearing_speed = one_ext(node, "R_BearingAndSpeed");
    return parsed;
  }

  // A tLocationType value: its element, or one inside its <anyExt>.
  std::string located(xmlNode *node, const char *inner, Dimension dimension) const {
    clear(node);
    auto *inner_node = one_ext(node, inner);
    if (!inner_node) invalid(std::string("missing <") + inner + ">");
    const auto value = text(inner_node);
    check_identity(dimension, value);
    return value;
  }

  // TS 24.379 annex F.3.3: the <CurrentLocation> of a report.
  Current current(xmlNode *node) const {
    Current parsed;
    if (auto *child = one(node, "CurrentServingEcgi")) parsed.serving_ecgi = located(child, "Ecgi", Dimension::Cell);
    for (auto *child : all(node, "NeighbouringEcgi"))
      parsed.neighbouring_ecgi.push_back(located(child, "Ecgi", Dimension::Cell));
    if (auto *child = one(node, "MbmsSaId")) parsed.mbms_sa = located(child, "SaId", Dimension::MbmsSa);
    if (auto *child = one(node, "MbsfnArea")) parsed.mbsfn = located(child, "MbsfnAreaId", Dimension::Mbsfn);
    if (auto *child = one(node, "CurrentCoordinate")) parsed.coordinate = point(child);

    if (auto *child = one_ext(node, "CurrentServingNcgi"))
      parsed.serving_ncgi = located(child, "Ncgi", Dimension::NrCell);
    for (auto *child : with_ext(node, "CL_NeighbouringNcgi"))
      parsed.neighbouring_ncgi.push_back(located(child, "Ncgi", Dimension::NrCell));
    if (auto *child = one_ext(node, "CL_5GMbsfsaArea"))
      parsed.mbsfsa = located(child, "NR5GMbsfsaAreaId", Dimension::Mbsfsa5G);
    if (auto *child = one_ext(node, "CL_BearingAndSpeed")) {
      clear(child);
      const auto value = text(one(child, "BearingAndSpeed", true));
      static const std::regex hex14(R"([A-Fa-f0-9]{14})");
      if (!std::regex_match(value, hex14)) invalid("BearingAndSpeed is 14 hexadecimal digits");
      parsed.bearing_speed = value;
    }

    if (auto *child = one_ext(node, "locTimestamp")) parsed.timestamp = text(child);
    if (auto *child = one_ext(node, "FunctionalAlias")) parsed.functional_alias = text(child);
    if (auto *child = one_ext(node, "InterRatType")) {
      const auto value = text(child);
      if (value != "5G-MBS-to-LTE-MBMS" && value != "5G-MBS-to-LTE-unicast" && value != "LTE-MBMS-to-5G-MBS" &&
          value != "LTE-MBMS-to-5G-unicast")
        invalid("unknown InterRatType");
      parsed.inter_rat = value;
    }
    return parsed;
  }
};

//------------------------------------------------------------------------------
// Helper: a whole number of the JSON location configuration, within [min, max].
std::uint64_t whole(const nlohmann::json &value, const char *what, std::uint64_t min, std::uint64_t max) {
  if (!value.is_number_unsigned() && !(value.is_number_integer() && value.get<std::int64_t>() >= 0))
    throw std::runtime_error(std::string("location configuration: ") + what + " must be a whole number");
  const auto number = value.get<std::uint64_t>();
  if (number < min || number > max)
    throw std::runtime_error(std::string("location configuration: ") + what + " out of range");
  return number;
}

//------------------------------------------------------------------------------
// Helper: a point of the JSON location configuration, [latitude, longitude] in degrees.
Point json_point(const nlohmann::json &value) {
  if (!value.is_array() || value.size() != 2)
    throw std::runtime_error("location configuration: a point is [latitude, longitude]");
  return Point::at(value.at(0).get<double>(), value.at(1).get<double>());
}

//------------------------------------------------------------------------------
// Helper: an area of the JSON location configuration: a polygon of 3 to 15 corners or an arc, with borders.
Area json_area(const nlohmann::json &value) {
  Area area;
  if (value.contains("polygon"))
    for (const auto &corner : value.at("polygon")) area.polygon.push_back(json_point(corner));
  if (value.contains("arc")) {
    const auto &arc = value.at("arc");
    area.center = json_point(arc.at("center"));
    area.radius = static_cast<std::uint32_t>(whole(arc.at("radius"), "radius", 0, 0xffffffff));
    area.offset_angle =
        static_cast<std::uint8_t>(whole(arc.value("offset_angle", nlohmann::json(0)), "offset_angle", 0, 179));
    area.included_angle =
        static_cast<std::uint8_t>(whole(arc.value("included_angle", nlohmann::json(179)), "included_angle", 0, 179));
  }
  area.inner_border =
      static_cast<std::uint8_t>(whole(value.value("inner_border", nlohmann::json(0)), "inner_border", 0, 127));
  area.outer_border =
      static_cast<std::uint8_t>(whole(value.value("outer_border", nlohmann::json(0)), "outer_border", 0, 127));
  if ((area.polygon.empty() == !area.center) ||
      (!area.polygon.empty() && (area.polygon.size() < 3 || area.polygon.size() > 15)))
    throw std::runtime_error("location configuration: an area is a polygon of 3 to 15 corners or an arc");
  return area;
}

//------------------------------------------------------------------------------
// Helper: a radio dimension of the JSON location configuration by name.
Dimension json_dimension(const std::string &name) {
  static const std::map<std::string, Dimension> names = {{"cell", Dimension::Cell},
                                                         {"nr_cell", Dimension::NrCell},
                                                         {"tracking_area", Dimension::TrackingArea},
                                                         {"tracking_area_5g", Dimension::TrackingArea5G},
                                                         {"plmn", Dimension::Plmn},
                                                         {"mbms_sa", Dimension::MbmsSa},
                                                         {"mbsfn", Dimension::Mbsfn},
                                                         {"mbsfsa_5g", Dimension::Mbsfsa5G},
                                                         {"rat", Dimension::Rat}};
  const auto found = names.find(name);
  if (found == names.end()) throw std::runtime_error("location configuration: unknown dimension " + name);
  return found->second;
}

//------------------------------------------------------------------------------
// Helper: a signalling event of the JSON location configuration by its element name.
Event json_event(const std::string &name) {
  for (auto event :
       {Event::InitialLogOn, Event::GroupCallNonEmergency, Event::PrivateCallNonEmergency,
        Event::LocationConfigurationReceived, Event::FunctionalAliasActivation, Event::FunctionalAliasDeactivation})
    if (name == event_name(event)) return event;
  throw std::runtime_error("location configuration: unknown signalling event " + name);
}

//------------------------------------------------------------------------------
// Helper: the triggers of the JSON location configuration; a trigger without "id" gets one from next_id.
std::vector<Trigger> json_triggers(const nlohmann::json &list, const std::function<std::string()> &next_id) {
  std::vector<Trigger> out;
  for (const auto &item : list) {
    Trigger entry;
    if (item.contains("periodic")) {
      entry.kind = Trigger::Kind::Periodic;
      entry.amount = whole(item.at("periodic"), "periodic", 1, 86400 * 366);
    } else if (item.contains("distance")) {
      entry.kind = Trigger::Kind::Distance;
      entry.amount = whole(item.at("distance"), "distance", 1, 40000000);
    } else if (item.contains("event")) {
      entry.kind = Trigger::Kind::Signalling;
      entry.event = json_event(item.at("event"));
    } else if (item.contains("any_change")) {
      entry.kind = Trigger::Kind::AnyChange;
      entry.dimension = json_dimension(item.at("any_change"));
    } else if (item.contains("enter") || item.contains("exit")) {
      entry.kind = item.contains("enter") ? Trigger::Kind::Enter : Trigger::Kind::Exit;
      entry.dimension = json_dimension(item.at(item.contains("enter") ? "enter" : "exit"));
      entry.value = item.at("value").get<std::string>();
      check_identity(entry.dimension, entry.value);
    } else if (item.contains("enter_area") || item.contains("exit_area")) {
      entry.kind = item.contains("enter_area") ? Trigger::Kind::EnterArea : Trigger::Kind::ExitArea;
      entry.area = json_area(item.at(item.contains("enter_area") ? "enter_area" : "exit_area"));
    } else if (item.contains("any_area"))
      entry.kind = Trigger::Kind::AnyArea;
    else if (item.contains("adaptive")) {
      entry.kind = Trigger::Kind::Adaptive;
      const auto &adaptive = item.at("adaptive");
      entry.adaptive.min_period = whole(adaptive.value("min_period", nlohmann::json(0)), "min_period", 0, 86400 * 366);
      if (adaptive.contains("min_distance"))
        entry.adaptive.min_distance = whole(adaptive.at("min_distance"), "min_distance", 1, 40000000);
      entry.adaptive.persistence =
          whole(adaptive.value("persistence", nlohmann::json(0)), "persistence", 0, 86400 * 366);
      entry.adaptive.additional = whole(adaptive.value("additional", nlohmann::json(1)), "additional", 1, 86400 * 366);
    } else
      throw std::runtime_error("location configuration: unknown trigger " + item.dump());

    entry.id = item.contains("id") ? item.at("id").get<std::string>() : next_id();
    out.push_back(entry);
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: what the JSON location configuration requests the client to report.
Requested json_requested(const nlohmann::json &value) {
  Requested parsed;
  parsed.serving_ecgi = value.value("serving_ecgi", false);
  parsed.neighbouring_ecgi = value.value("neighbouring_ecgi", false);
  parsed.mbms_sa = value.value("mbms_sa", false);
  parsed.mbsfn = value.value("mbsfn", false);
  parsed.coordinate = value.value("coordinate", false);
  parsed.serving_ncgi = value.value("serving_ncgi", false);
  parsed.neighbouring_ncgi = value.value("neighbouring_ncgi", false);
  parsed.mbsfsa = value.value("mbsfsa", false);
  parsed.bearing_speed = value.value("bearing_speed", false);
  parsed.minimum_interval = static_cast<std::uint32_t>(
      whole(value.value("minimum_interval", nlohmann::json(1)), "minimum_interval", 1, 86400 * 366));
  return parsed;
}

//------------------------------------------------------------------------------
// Helper: a point as JSON, in degrees and as its TS 23.032 codes.
nlohmann::json point_json(const Point &point) {
  nlohmann::json out = {{"latitude", point.lat()},
                        {"longitude", point.lon()},
                        {"encoded", {{"latitude", point.latitude}, {"longitude", point.longitude}}}};
  if (point.altitude) out["altitude"] = *point.altitude;
  if (point.horizontal_accuracy) out["horizontal_accuracy"] = *point.horizontal_accuracy;
  if (point.vertical_accuracy) out["vertical_accuracy"] = *point.vertical_accuracy;
  return out;
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.4, TS 24.282 annex D.4.4, TS 24.281 annex F.3.4: the MIME type of the location-info body.
const char *mime(Service service) {
  return service == Service::Mcptt    ? "application/vnd.3gpp.mcptt-location-info+xml"
         : service == Service::Mcdata ? "application/vnd.3gpp.mcdata-location-info+xml"
                                      : "application/vnd.3gpp.mcvideo-location-info+xml";
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2, TS 24.282 annex D.4.2, TS 24.281 annex F.3.2: the namespace of the location-info schema.
const char *xml_namespace(Service service) {
  return service == Service::Mcptt ? mcptt_ns : service == Service::Mcdata ? mcdata_ns : mcvideo_ns;
}

//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: a latitude as a sign bit and 23 bits of magnitude, N <= 2^23 X / 90 < N + 1.
std::uint32_t encode_latitude(double degrees) {
  if (!(degrees >= -90 && degrees <= 90)) throw std::invalid_argument("latitude out of range");
  const auto magnitude =
      std::min<std::uint32_t>(static_cast<std::uint32_t>(std::floor(std::fabs(degrees) * 8388608.0 / 90)), 8388607);
  return (degrees < 0 ? 0x800000u : 0u) | magnitude;
}

//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: a longitude as a 24-bit two's complement number, N <= 2^24 X / 360 < N + 1.
std::uint32_t encode_longitude(double degrees) {
  if (!(degrees >= -180 && degrees <= 180)) throw std::invalid_argument("longitude out of range");
  if (degrees == 180) degrees = -180;
  const auto steps = static_cast<std::int32_t>(std::floor(degrees * 16777216.0 / 360));
  return static_cast<std::uint32_t>(steps) & 0xffffffu;
}

//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: the latitude in degrees at the middle of the coded interval.
double decode_latitude(std::uint32_t encoded) {
  const double value = ((encoded & 0x7fffffu) + 0.5) * 90 / 8388608.0;
  return encoded & 0x800000u ? -value : value;
}

//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: the longitude in degrees at the middle of the coded interval.
double decode_longitude(std::uint32_t encoded) {
  const std::int32_t steps = encoded & 0x800000u ? static_cast<std::int32_t>(encoded & 0xffffffu) - 16777216
                                                 : static_cast<std::int32_t>(encoded & 0xffffffu);
  return (steps + 0.5) * 360 / 16777216.0;
}

//------------------------------------------------------------------------------
// TS 23.032 clause 6.2: the uncertainty in metres of the uncertainty code K, 10 (1.1^K - 1).
double horizontal_uncertainty(std::uint8_t code) { return 10 * (std::pow(1.1, code) - 1); }

//------------------------------------------------------------------------------
// TS 23.032 clause 6.4: the altitude uncertainty in metres of the uncertainty code K, 45 (1.025^K - 1).
double vertical_uncertainty(std::uint8_t code) { return 45 * (std::pow(1.025, code) - 1); }

//------------------------------------------------------------------------------
// Helper: the great-circle (haversine) distance in metres between two points.
double distance(double lat1, double lon1, double lat2, double lon2) {
  const double haversine =
      std::pow(std::sin(radians(lat2 - lat1) / 2), 2) +
      std::cos(radians(lat1)) * std::cos(radians(lat2)) * std::pow(std::sin(radians(lon2 - lon1) / 2), 2);
  return 2 * earth_radius * std::asin(std::min(1.0, std::sqrt(haversine)));
}

//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: a point from a latitude and longitude in degrees.
Point Point::at(double latitude, double longitude) {
  Point point;
  point.latitude = encode_latitude(latitude);
  point.longitude = encode_longitude(longitude);
  return point;
}

//------------------------------------------------------------------------------
// Helper: how far in metres a position is inside an area (TS 23.032 clause 5.4 polygon or clause 5.7 ellipsoid
// arc), negative when outside; the border widths of TS 24.379 annex F.3.3 are applied to it.
double depth(const Area &area, double lat, double lon) {
  if (!area.polygon.empty()) {
    std::vector<Xy> corners;
    for (const auto &corner : area.polygon) corners.push_back(project(lat, lon, corner.lat(), corner.lon()));
    bool in = false;
    double nearest = INFINITY;
    for (std::size_t index = 0, previous = corners.size() - 1; index < corners.size(); previous = index++) {
      if ((corners[index].y > 0) != (corners[previous].y > 0) && 0 < (corners[previous].x - corners[index].x) *
                                                                             (0 - corners[index].y) /
                                                                             (corners[previous].y - corners[index].y) +
                                                                         corners[index].x)
        in = !in;
      nearest = std::min(nearest, segment_distance({0, 0}, corners[previous], corners[index]));
    }
    return in ? nearest : -nearest;
  }

  if (!area.center) return -INFINITY;
  const double clat = area.center->lat(), clon = area.center->lon(), radius = area.radius;
  const double range = distance(clat, clon, lat, lon);
  const double start = 2.0 * area.offset_angle, span = 2.0 * (area.included_angle + 1);
  if (span >= 360) return radius - range;

  const double heading = bearing(clat, clon, lat, lon);
  const bool in_sector = std::fmod(heading - start + 360, 360) <= span;
  const auto end1 = destination(clat, clon, start, radius), end2 = destination(clat, clon, start + span, radius);
  const Xy centre = project(lat, lon, clat, clon), e1 = project(lat, lon, end1.first, end1.second),
           e2 = project(lat, lon, end2.first, end2.second);
  double nearest = std::min(segment_distance({0, 0}, centre, e1), segment_distance({0, 0}, centre, e2));
  nearest = std::min(nearest,
                     in_sector ? std::fabs(radius - range) : std::min(std::hypot(e1.x, e1.y), std::hypot(e2.x, e2.y)));
  return in_sector && range <= radius ? nearest : -nearest;
}

//------------------------------------------------------------------------------
// Helper: whether a position is inside an area (on its contour counts as inside).
bool inside(const Area &area, double lat, double lon) { return depth(area, lat, lon) >= 0; }

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: writes a location-info document with a <Configuration> (TS 24.379 clause 13.2.2), a
// <Request> (clause 13.2.3) or a <Report> (clause 13.3.4.2).
std::string to_xml(const Content &content, Service service) {
  std::string body;
  if (const auto *configuration = std::get_if<Configuration>(&content)) {
    std::string inner;
    if (configuration->non_emergency)
      inner += element("NonEmergencyLocationInformation", requested_xml(*configuration->non_emergency));
    if (configuration->emergency)
      inner += element("EmergencyLocationInformation", requested_xml(*configuration->emergency));
    // <TriggeringCriteria> is mandatory; the emergency criteria are the one
    // element its <anyExt> shall carry (TS 24.379 annex F.3.3 item 4).
    inner += "<TriggeringCriteria>" + criteria_xml(configuration->triggers, service) + "</TriggeringCriteria>";
    inner += "<anyExt><EmergencyTriggeringCriteria>" + criteria_xml(configuration->emergency_triggers, service) +
             "</EmergencyTriggeringCriteria></anyExt>";
    body = element("Configuration", inner,
                   std::string(" ConfigScope=\"") + (configuration->full ? "Full" : "Update") + "\"");
  } else if (const auto *request = std::get_if<Request>(&content)) {
    if (request->id.empty() || request->id.size() > 256) invalid("a request needs a RequestId");
    std::string inner;
    if (request->filter)
      inner =
          element("anyExt", element("LocationFilter", element("AreaIdentifier", xml_escape(request->filter->area)) +
                                                          element("AreaIn", request->filter->in ? "true" : "false")));
    body = element("Request", inner,
                   " RequestId=\"" + xml_escape(request->id) + "\"" + (request->refresh ? " refresh=\"true\"" : ""));
  } else {
    const auto &report = std::get<Report>(content);
    const auto &known = report.location;
    std::string inner;
    for (const auto &trigger_id : report.triggers) inner += element("TriggerId", xml_escape(trigger_id));
    if (!report.reporting_uri.empty())
      inner += element(std::string(lower(service)) + "-reporting-uri", xml_escape(report.reporting_uri));

    std::string current;
    if (known.serving_ecgi) {
      check_identity(Dimension::Cell, *known.serving_ecgi);
      current += located("CurrentServingEcgi", "Ecgi", *known.serving_ecgi);
    }
    for (const auto &cell : known.neighbouring_ecgi) {
      check_identity(Dimension::Cell, cell);
      current += located("NeighbouringEcgi", "Ecgi", cell);
    }
    if (known.mbms_sa) {
      check_identity(Dimension::MbmsSa, *known.mbms_sa);
      current += located("MbmsSaId", "SaId", *known.mbms_sa);
    }
    if (known.mbsfn) {
      check_identity(Dimension::Mbsfn, *known.mbsfn);
      current += located("MbsfnArea", "MbsfnAreaId", *known.mbsfn);
    }
    if (known.coordinate) current += element("CurrentCoordinate", point_xml(*known.coordinate));

    std::string ext;
    if (known.timestamp) ext += element("locTimestamp", xml_escape(*known.timestamp));
    if (known.functional_alias) ext += element("FunctionalAlias", xml_escape(*known.functional_alias));
    if (known.inter_rat) ext += element("InterRatType", xml_escape(*known.inter_rat));
    if (known.serving_ncgi) {
      check_identity(Dimension::NrCell, *known.serving_ncgi);
      ext += located("CurrentServingNcgi", "Ncgi", *known.serving_ncgi, true);
    }
    for (const auto &cell : known.neighbouring_ncgi) {
      check_identity(Dimension::NrCell, cell);
      ext += located("CL_NeighbouringNcgi", "Ncgi", cell, true);
    }
    if (known.mbsfsa) {
      check_identity(Dimension::Mbsfsa5G, *known.mbsfsa);
      ext += located("CL_5GMbsfsaArea", "NR5GMbsfsaAreaId", *known.mbsfsa, true);
    }
    if (known.bearing_speed) {
      static const std::regex hex14(R"([A-Fa-f0-9]{14})");
      if (!std::regex_match(*known.bearing_speed, hex14)) invalid("BearingAndSpeed is 14 hexadecimal digits");
      ext += element("CL_BearingAndSpeed", element("BearingAndSpeed", *known.bearing_speed), " type=\"Normal\"");
    }
    if (!ext.empty()) current += element("anyExt", ext);

    // <CurrentLocation> is mandatory, even when nothing is known.
    inner += "<CurrentLocation>" + current + "</CurrentLocation>";
    body = element("Report", inner,
                   (report.id.empty() ? std::string{} : " ReportID=\"" + xml_escape(report.id) + "\"") +
                       " ReportType=\"" + (report.emergency ? "Emergency" : "NonEmergency") + "\"");
  }
  return std::string("<?xml version=\"1.0\" encoding=\"UTF-8\"?><location-info xmlns=\"") + xml_namespace(service) +
         "\">" + body + "</location-info>";
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: reads a location-info document of any of the three services: exactly one of
// <Configuration>, <Request> or <Report>.
Content parse(std::string_view xml, Service *service, bool trigger_ids_optional) {
  auto doc = document(xml);
  auto *root = xmlDocGetRootElement(doc.get());
  Reader mcptt{mcptt_ns, trigger_ids_optional}, mcdata{mcdata_ns, trigger_ids_optional},
      mcvideo{mcvideo_ns, trigger_ids_optional};
  const auto found = mcdata.is(root, "location-info")    ? Service::Mcdata
                     : mcvideo.is(root, "location-info") ? Service::Mcvideo
                     : mcptt.is(root, "location-info")   ? std::optional<Service>(Service::Mcptt)
                                                         : std::nullopt;
  if (!found) invalid("root is not a location-info element");
  if (service) *service = *found;
  const Reader &reader = *found == Service::Mcdata ? mcdata : *found == Service::Mcvideo ? mcvideo : mcptt;

  auto *configuration = reader.one(root, "Configuration");
  auto *request = reader.one(root, "Request");
  auto *report = reader.one(root, "Report");
  if ((configuration != nullptr) + (request != nullptr) + (report != nullptr) != 1)
    invalid("exactly one of Configuration, Request or Report");

  if (configuration) {
    Configuration config;
    const auto scope = Reader::attr(configuration, "ConfigScope");
    if (!scope.empty() && scope != "Full" && scope != "Update") invalid("unknown ConfigScope");
    config.full = scope != "Update";
    if (auto *node = reader.one(configuration, "NonEmergencyLocationInformation"))
      config.non_emergency = reader.requested(node);
    if (auto *node = reader.one(configuration, "EmergencyLocationInformation"))
      config.emergency = reader.requested(node);
    if (auto *node = reader.one(configuration, "TriggeringCriteria")) config.triggers = reader.criteria(node);
    if (auto *node = reader.one_ext(configuration, "EmergencyTriggeringCriteria"))
      config.emergency_triggers = reader.criteria(node);
    return config;
  }

  if (request) {
    Request parsed_request;
    parsed_request.id = Reader::attr(request, "RequestId");
    if (parsed_request.id.empty()) parsed_request.id = Reader::attr(request, "RequestID");
    if (parsed_request.id.empty() || parsed_request.id.size() > 256) invalid("a request needs a RequestId");
    const auto refresh = Reader::attr(request, "refresh");
    if (!refresh.empty() && refresh != "true" && refresh != "false" && refresh != "1" && refresh != "0")
      invalid("invalid refresh");
    parsed_request.refresh = refresh == "true" || refresh == "1";
    if (auto *filter_node = reader.one_ext(request, "LocationFilter")) {
      Filter filter;
      filter.area = Reader::text(reader.one(filter_node, "AreaIdentifier", true));
      const auto in = Reader::text(reader.one(filter_node, "AreaIn", true));
      if (in != "true" && in != "false" && in != "1" && in != "0") invalid("invalid AreaIn");
      filter.in = in == "true" || in == "1";
      parsed_request.filter = filter;
    }
    return parsed_request;
  }

  Report parsed_report;
  parsed_report.id = Reader::attr(report, "ReportID");
  const auto type = Reader::attr(report, "ReportType");
  if (type != "Emergency" && type != "NonEmergency") invalid("ReportType is Emergency or NonEmergency");
  parsed_report.emergency = type == "Emergency";
  for (auto *node : reader.all(report, "TriggerId")) parsed_report.triggers.push_back(Reader::text(node));
  if (auto *uri = reader.one(report, (std::string(lower(*found)) + "-reporting-uri").c_str()))
    parsed_report.reporting_uri = Reader::text(uri);
  parsed_report.location = reader.current(reader.one(report, "CurrentLocation", true));
  return parsed_report;
}

//------------------------------------------------------------------------------
// Helper: an area of the JSON location configuration.
Area area_from_json(const nlohmann::json &json) { return json_area(json); }

//------------------------------------------------------------------------------
// Helper: a location reporting configuration from its JSON form, checked against the schema's limits by
// writing it as XML.
Configuration configuration_from_json(const nlohmann::json &json, const std::function<std::string()> &next_id) {
  Configuration config;
  config.full = json.value("scope", std::string("full")) != "update";
  if (json.contains("non_emergency")) config.non_emergency = json_requested(json.at("non_emergency"));
  if (json.contains("emergency")) config.emergency = json_requested(json.at("emergency"));
  if (json.contains("triggers")) config.triggers = json_triggers(json.at("triggers"), next_id);
  if (json.contains("emergency_triggers"))
    config.emergency_triggers = json_triggers(json.at("emergency_triggers"), next_id);
  // Checks the schema's limits (one periodic trigger, one area entry, ...).
  (void)to_xml(config, Service::Mcptt);
  return config;
}

//------------------------------------------------------------------------------
// Helper: a location report as JSON.
nlohmann::json to_json(const Report &report) {
  nlohmann::json out = {{"emergency", report.emergency}, {"triggers", report.triggers}};
  if (!report.id.empty()) out["id"] = report.id;
  if (!report.reporting_uri.empty()) out["reporting_uri"] = report.reporting_uri;
  const auto &known = report.location;
  if (known.coordinate) out["coordinate"] = point_json(*known.coordinate);
  const auto optional = [&](const char *key, const std::optional<std::string> &value) {
    if (value) out[key] = *value;
  };
  optional("serving_ecgi", known.serving_ecgi);
  optional("serving_ncgi", known.serving_ncgi);
  optional("mbms_sa", known.mbms_sa);
  optional("mbsfn", known.mbsfn);
  optional("mbsfsa", known.mbsfsa);
  optional("bearing_speed", known.bearing_speed);
  optional("timestamp", known.timestamp);
  optional("functional_alias", known.functional_alias);
  optional("inter_rat", known.inter_rat);
  if (!known.neighbouring_ecgi.empty()) out["neighbouring_ecgi"] = known.neighbouring_ecgi;
  if (!known.neighbouring_ncgi.empty()) out["neighbouring_ncgi"] = known.neighbouring_ncgi;
  return out;
}

//------------------------------------------------------------------------------
// Helper: a summary of a location reporting configuration as JSON.
nlohmann::json to_json(const Configuration &configuration) {
  const auto ids = [](const std::vector<Trigger> &triggers) {
    nlohmann::json out = nlohmann::json::array();
    for (const auto &entry : triggers) out.push_back(entry.id);
    return out;
  };
  nlohmann::json result = {{"full", configuration.full},
                           {"triggers", ids(configuration.triggers)},
                           {"emergency_triggers", ids(configuration.emergency_triggers)}};
  if (configuration.non_emergency) result["minimum_interval"] = configuration.non_emergency->minimum_interval;
  if (configuration.emergency) result["emergency_minimum_interval"] = configuration.emergency->minimum_interval;
  return result;
}

// ---- the client's reporting ----
//------------------------------------------------------------------------------
// TS 24.379 clause 13.3.2.1: replaces ("Full") or extends ("Update", TS 24.379 annex F.3.3) the stored
// configuration, sets the triggers and starts the minimumReportInterval timer; a LocationConfigurationReceived
// trigger fires.
void Reporter::configure(const Configuration &configuration, std::uint64_t now) {
  if (configuration.full) {
    configuration_ = configuration;
    area_state_.clear();
    periodic_.clear();
    detected_.clear();
    fired_.clear();
  } else {
    // "Update": the configuration is in addition to the previous one (the requested elements are added to those
    // requested before); a trigger with an existing TriggerId replaces it.
    configuration_.full = true;
    if (configuration.non_emergency)
      configuration_.non_emergency = updated(configuration_.non_emergency, *configuration.non_emergency);
    if (configuration.emergency) configuration_.emergency = updated(configuration_.emergency, *configuration.emergency);
    const auto merge = [&](std::vector<Trigger> &into, const std::vector<Trigger> &from) {
      for (const auto &entry : from) {
        const auto same =
            std::find_if(into.begin(), into.end(), [&](const Trigger &other) { return other.id == entry.id; });
        if (same != into.end())
          *same = entry;
        else
          into.push_back(entry);
        area_state_.erase(entry.id);
        periodic_.erase(entry.id);
        detected_.erase(entry.id);
      }
    };
    merge(configuration_.triggers, configuration.triggers);
    merge(configuration_.emergency_triggers, configuration.emergency_triggers);
  }

  configured_ = !configuration_.cancels();
  if (!configured_) {
    fired_.clear();
    return;
  }

  const auto *wanted = requested();
  timer_until_ = now + (wanted ? wanted->minimum_interval : 0) * 1000ull;
  origin_ = now;
  reported_position_ = position_;
  evaluate_areas();
  for (const auto &entry : active())
    if (entry.kind == Trigger::Kind::Signalling && entry.event == Event::LocationConfigurationReceived) fire(entry.id);
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the triggers in force: <EmergencyTriggeringCriteria> in an emergency, else
// <TriggeringCriteria>.
const std::vector<Trigger> &Reporter::active() const {
  return emergency_ ? configuration_.emergency_triggers : configuration_.triggers;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: what to report: the emergency or non-emergency location information, the other one
// when it is absent.
const Requested *Reporter::requested() const {
  const auto &first = emergency_ ? configuration_.emergency : configuration_.non_emergency;
  const auto &second = emergency_ ? configuration_.non_emergency : configuration_.emergency;
  return first ? &*first : second ? &*second : nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: <EnterSpecificAreaType>, <ExitSpecificAreaType> and <AnyAreaChange> fire when the
// position crosses the area's contour, or its inner or outer border fence when one is set.
void Reporter::evaluate_areas() {
  if (!position_) return;
  const double lat = position_->lat(), lon = position_->lon();
  bool changed = false;
  for (const auto &entry : active()) {
    if (entry.kind != Trigger::Kind::EnterArea && entry.kind != Trigger::Kind::ExitArea) continue;
    const double margin = depth(entry.area, lat, lon);
    const auto previous = area_state_.find(entry.id);
    bool now_inside;
    if (previous == area_state_.end())
      now_inside = margin >= 0; // the first position fires nothing
    else if (previous->second)
      now_inside = !(entry.area.outer_border ? margin <= -double(entry.area.outer_border) : margin < 0);
    else
      now_inside = entry.area.inner_border ? margin >= double(entry.area.inner_border) : margin >= 0;
    if (previous != area_state_.end() && previous->second != now_inside) {
      changed = true;
      if ((entry.kind == Trigger::Kind::EnterArea) == now_inside) fire(entry.id);
    }
    area_state_[entry.id] = now_inside;
  }
  if (changed)
    for (const auto &entry : active())
      if (entry.kind == Trigger::Kind::AnyArea) fire(entry.id);
}

//------------------------------------------------------------------------------
// Helper: whether the last position was inside the area of this area trigger.
bool Reporter::inside_area(const std::string &trigger_id) const {
  const auto found = area_state_.find(trigger_id);
  return found != area_state_.end() && found->second;
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: a new position; area triggers and <TravelledDistance> may fire.
void Reporter::position(const Point &point, std::uint64_t) {
  position_ = point;
  if (!configured_) return;
  // <TravelledDistance> counts from the last reported position, or from this first one.
  const Point reference = reported_position_.value_or(point);
  if (!reported_position_) reported_position_ = point;
  evaluate_areas();
  const double moved = distance(reference.lat(), reference.lon(), point.lat(), point.lon());
  for (const auto &entry : active())
    if (entry.kind == Trigger::Kind::Distance && moved >= double(entry.amount)) fire(entry.id);
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: a new serving radio identity (cell, tracking area, PLMN, MBMS SA, MBSFN area, 5G MBSFSA,
// RAT); the any-change, enter and exit triggers of that dimension may fire.
void Reporter::radio(Dimension dimension, const std::string &value, std::uint64_t) {
  const auto old = radio_[dimension];
  radio_[dimension] = value;
  if (!configured_ || old == value) return;
  for (const auto &entry : active()) {
    const bool same =
        entry.dimension == dimension || (entry.kind == Trigger::Kind::AnyChange && entry.dimension == Dimension::Cell &&
                                         dimension == Dimension::NrCell);
    if (!same) continue;
    if ((entry.kind == Trigger::Kind::AnyChange && !old.empty()) ||
        (entry.kind == Trigger::Kind::Enter && entry.value == value) ||
        (entry.kind == Trigger::Kind::Exit && !old.empty() && entry.value == old))
      fire(entry.id);
  }
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: a signalling event (<McpttSignallingEvent>); its trigger fires.
void Reporter::signal(Event event, std::uint64_t) {
  if (!configured_) return;
  for (const auto &entry : active())
    if (entry.kind == Trigger::Kind::Signalling && entry.event == event) fire(entry.id);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.3.4.2: builds a report with the fired TriggerIds and the requested location elements,
// starts the minimumReportInterval timer and resets all triggers.
Report Reporter::build(std::uint64_t now) {
  Report report;
  report.emergency = emergency_;
  report.triggers.assign(fired_.begin(), fired_.end());
  const auto *want = requested();
  const auto has = [&](Dimension dimension) {
    const auto found = radio_.find(dimension);
    return found != radio_.end() && !found->second.empty();
  };
  const auto value = [&](Dimension dimension) { return radio_.at(dimension); };
  // Without a configuration (a request only), everything known is reported.
  if (position_ && (!want || want->coordinate)) report.location.coordinate = position_;
  if (has(Dimension::Cell) && (!want || want->serving_ecgi)) report.location.serving_ecgi = value(Dimension::Cell);
  if (has(Dimension::NrCell) && (!want || want->serving_ncgi)) report.location.serving_ncgi = value(Dimension::NrCell);
  if (has(Dimension::MbmsSa) && (!want || want->mbms_sa)) report.location.mbms_sa = value(Dimension::MbmsSa);
  if (has(Dimension::Mbsfn) && (!want || want->mbsfn)) report.location.mbsfn = value(Dimension::Mbsfn);
  if (has(Dimension::Mbsfsa5G) && (!want || want->mbsfsa)) report.location.mbsfsa = value(Dimension::Mbsfsa5G);
  fired_.clear();
  timer_until_ = now + (want ? want->minimum_interval : 0) * 1000ull;
  origin_ = now;
  reported_position_ = position_;
  detected_.clear();
  return report;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.3.3.1: a request is answered at once with a report carrying its RequestId as ReportID,
// and the minimumReportInterval timer is reset.
Report Reporter::answer(const std::string &request_id, std::uint64_t now) {
  auto report = build(now);
  report.id = request_id;
  return report;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.3.4.1: runs the periodic and adaptive triggers (TS 24.379 annex F.3.3) and returns a
// report when a trigger has fired and the minimumReportInterval timer is not running.
std::optional<Report> Reporter::poll(std::uint64_t now) {
  if (!configured_) return std::nullopt;
  for (const auto &entry : active()) {
    if (entry.kind == Trigger::Kind::Periodic) {
      auto due = periodic_.find(entry.id);
      if (due == periodic_.end()) due = periodic_.emplace(entry.id, now + entry.amount * 1000).first;
      if (now >= due->second) {
        fire(entry.id);
        due->second = now + entry.amount * 1000;
      }
    } else if (entry.kind == Trigger::Kind::Adaptive) {
      const auto &adaptive = entry.adaptive;
      const auto since = now - std::min(now, origin_);
      if (adaptive.min_distance && position_ && reported_position_ && since >= adaptive.min_period * 1000) {
        const double moved =
            distance(reported_position_->lat(), reported_position_->lon(), position_->lat(), position_->lon());
        if (moved >= double(*adaptive.min_distance)) {
          const auto first = detected_.emplace(entry.id, now).first->second;
          if (now - first >= adaptive.persistence * 1000) fire(entry.id);
        } else
          detected_.erase(entry.id);
      }
      if (since >= (adaptive.min_period + adaptive.persistence + adaptive.additional) * 1000) fire(entry.id);
    }
  }

  if (fired_.empty() || now < timer_until_) return std::nullopt;
  return build(now);
}

} // namespace mcx::location

namespace mcx::location {
//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: a received configuration applied to the stored one: "Full" replaces it, "Update" adds
// to it (the requested elements to those requested before; a trigger with an existing TriggerId replaces that one).
Configuration apply(const Configuration &stored, const Configuration &received) {
  if (received.full) return received;
  Configuration out = stored;
  out.full = true;
  if (received.non_emergency) out.non_emergency = updated(out.non_emergency, *received.non_emergency);
  if (received.emergency) out.emergency = updated(out.emergency, *received.emergency);
  const auto merge = [](std::vector<Trigger> &into, const std::vector<Trigger> &from) {
    for (const auto &entry : from) {
      const auto same =
          std::find_if(into.begin(), into.end(), [&](const Trigger &other) { return other.id == entry.id; });
      if (same != into.end())
        *same = entry;
      else
        into.push_back(entry);
    }
  };
  merge(out.triggers, received.triggers);
  merge(out.emergency_triggers, received.emergency_triggers);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the area of the area trigger with this TriggerId, in either criteria.
const Area *find_area(const Configuration &configuration, const std::string &trigger_id) {
  for (const auto *list : {&configuration.triggers, &configuration.emergency_triggers})
    for (const auto &entry : *list)
      if (entry.id == trigger_id && (entry.kind == Trigger::Kind::EnterArea || entry.kind == Trigger::Kind::ExitArea))
        return &entry.area;
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.2 step 10: stores the location reporting configuration for the client.
const Configuration &Registry::configure(const std::string &user, const Configuration &configuration) {
  auto &entry = users_[user];
  entry.configuration = apply(entry.configured ? entry.configuration : Configuration{}, configuration);
  entry.configured = true;
  return entry.configuration;
}

//------------------------------------------------------------------------------
// Helper: the stored configuration of a user, or null.
const Configuration *Registry::configuration(const std::string &user) const {
  const auto found = users_.find(user);
  return found == users_.end() || !found->second.configured ? nullptr : &found->second.configuration;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.4.1: stores a client's report (keeping the last known coordinate when it has none) and
// returns the requests it answers.
std::vector<Registry::Waiter> Registry::reported(const std::string &user, const Report &report, std::uint64_t now) {
  auto &entry = users_[user];
  // A report without a coordinate keeps the last known one.
  auto kept = report;
  if (!kept.location.coordinate && entry.report) kept.location.coordinate = entry.report->location.coordinate;
  entry.report = kept;
  entry.reported_at = now;
  entry.outstanding.clear();
  return std::exchange(entry.waiters, {});
}

//------------------------------------------------------------------------------
// Helper: the last report of a user, or null.
const Report *Registry::last(const std::string &user) const {
  const auto found = users_.find(user);
  return found == users_.end() || !found->second.report ? nullptr : &*found->second.report;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b iii: whether the stored location information is recent enough.
bool Registry::fresh(const std::string &user, std::uint64_t now, std::uint64_t max_age_ms) const {
  const auto found = users_.find(user);
  if (found == users_.end() || !found->second.report) return false;
  // A report time ahead of now (another clock) is as recent as can be, not wrapped into a great age.
  const auto reported_at = found->second.reported_at;
  return reported_at >= now || now - reported_at <= max_age_ms;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b ii and iii: a request waits for the user's next report; the RequestId to
// send the client is returned when no request to it is outstanding. A user not yet known gets an entry for the
// waiter, which expire() removes again when the wait ends without a report.
std::optional<std::string> Registry::await(const std::string &user, Waiter waiter, std::uint64_t now,
                                           std::uint64_t wait_ms, const std::function<std::string()> &new_id) {
  auto &entry = users_[user];
  waiter.deadline = now + wait_ms;
  entry.waiters.push_back(std::move(waiter));
  if (!entry.outstanding.empty()) return std::nullopt;
  entry.outstanding = new_id();
  return entry.outstanding;
}

//------------------------------------------------------------------------------
// Helper: the requests whose wait has ended without a report.
std::vector<std::pair<std::string, Registry::Waiter>> Registry::expire(std::uint64_t now) {
  std::vector<std::pair<std::string, Waiter>> out;
  for (auto user = users_.begin(); user != users_.end();) {
    auto &entry = user->second;
    for (auto it = entry.waiters.begin(); it != entry.waiters.end();) {
      if (it->deadline > now) {
        ++it;
        continue;
      }
      out.emplace_back(user->first, *it);
      it = entry.waiters.erase(it);
    }
    if (entry.waiters.empty()) entry.outstanding.clear();
    // An entry that only held waiters (a request for a user who never reported) goes with them.
    if (entry.waiters.empty() && !entry.configured && !entry.report && entry.inside.empty())
      user = users_.erase(user);
    else
      ++user;
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b iv: whether the user's last known position passes a <LocationFilter>
// (inside or outside the area of the given area trigger).
bool Registry::passes(const std::string &user, const Filter &filter) const {
  const auto found = users_.find(user);
  if (found == users_.end() || !found->second.report) return false;
  const auto &coordinate = found->second.report->location.coordinate;
  if (!coordinate) return false;
  const auto *area = find_area(found->second.configuration, filter.area);
  if (!area) return false;
  return inside(*area, coordinate->lat(), coordinate->lon()) == filter.in;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.2.4.1 and 6.3.2.4.2: the entries into and exits from named areas (emergency alert areas,
// group geographic areas) by the user's last position; the first position counts as an entry into every area it
// is inside.
std::vector<std::pair<std::string, bool>> Registry::areas(const std::string &user,
                                                          const std::map<std::string, Area> &named) {
  std::vector<std::pair<std::string, bool>> out;
  // A user never heard of has no position: nothing to compare, and no entry is made for the query.
  const auto found = users_.find(user);
  if (found == users_.end()) return out;
  auto &entry = found->second;
  if (!entry.report || !entry.report->location.coordinate) return out;
  const auto &coordinate = *entry.report->location.coordinate;
  for (const auto &[name, area] : named) {
    const bool now_inside = inside(area, coordinate.lat(), coordinate.lon());
    const auto previous = entry.inside.find(name);
    if (previous == entry.inside.end() ? now_inside : previous->second != now_inside)
      out.emplace_back(name, now_inside);
    entry.inside[name] = now_inside;
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: drops everything kept about a user.
void Registry::forget(const std::string &user) { users_.erase(user); }

//------------------------------------------------------------------------------
// Helper: the number of requests waiting for a report.
std::size_t Registry::waiting() const {
  std::size_t count = 0;
  for (const auto &[user, entry] : users_) count += entry.waiters.size();
  return count;
}
} // namespace mcx::location
