//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Emergency location documents: the <location-info> Report of type Emergency with the current coordinate, for
// MCPTT, MCData and MCVideo.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 2046.

#include "protocol_internal.hpp"

namespace mcx {

namespace {
// TS 24.379 annex F.3, TS 24.282 annex D.4 and TS 24.281 annex F.3: the location-info namespaces of the services.
constexpr const char *mcptt_location_ns = "urn:3gpp:ns:mcpttLocationInfo:1.0";
constexpr const char *mcdata_location_ns = "urn:3gpp:ns:mcdataLocationInfo:1.0";
constexpr const char *mcvideo_location_ns = "urn:3gpp:ns:mcvideoLocationInfo:1.0";

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2, TS 24.282 annex D.4, TS 24.281 annex F.3: reads an Emergency <Report> that carries exactly
// a <CurrentCoordinate>, in the expected namespace or, with none expected, in that of any MC service.
EmergencyLocation parse_location_in(std::string_view xml, const char *expected_ns);
} // namespace

//------------------------------------------------------------------------------
// TS 24.379 annex F.3, TS 24.281 annex F.3 and TS 24.282 annex D.4: the emergency location document of the service;
// MCVideo's differs from MCPTT's in its namespace only, MCData's is emergency_location_xml(location, true).
std::string service_location_xml(const EmergencyLocation &location, const ServiceProfile &service) {
  if (service.service == Service::mcptt) return emergency_location_xml(location);
  if (service.service == Service::mcdata) return emergency_location_xml(location, true);
  auto xml = emergency_location_xml(location);
  const std::string from = mcptt_location_ns;
  return xml.replace(xml.find(from), from.size(), mcvideo_location_ns);
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2 (TS 24.282 annex D.4 with mcdata): writes an Emergency <Report> with the <CurrentCoordinate>
// longitude and latitude, each three bytes, unprotected ("Normal").
std::string emergency_location_xml(const EmergencyLocation &location, bool mcdata) {
  if (location.latitude > 0xffffff || location.longitude > 0xffffff) invalid("emergency coordinate exceeds 24 bits");
  return std::string("<?xml version=\"1.0\"?><location-info xmlns=\"") +
         (mcdata ? mcdata_location_ns : mcptt_location_ns) +
         "\"><Report ReportType=\"Emergency\"><CurrentLocation><CurrentCoordinate>"
         "<longitude type=\"Normal\"><threebytes>" +
         std::to_string(location.longitude) +
         "</threebytes></longitude>"
         "<latitude type=\"Normal\"><threebytes>" +
         std::to_string(location.latitude) +
         "</threebytes></latitude>"
         "</CurrentCoordinate></CurrentLocation></Report></location-info>";
}

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2, TS 24.282 annex D.4, TS 24.281 annex F.3: reads an Emergency <Report> that carries exactly
// a <CurrentCoordinate>, in the namespace of any MC service; protected (non-"Normal") coordinates are not supported.
EmergencyLocation parse_emergency_location(std::string_view xml) { return parse_location_in(xml, nullptr); }

namespace {
//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2, TS 24.282 annex D.4, TS 24.281 annex F.3: reads an Emergency <Report> that carries exactly
// a <CurrentCoordinate>, in the expected namespace or, with none expected, in that of any MC service; protected
// (non-"Normal") coordinates are not supported.
EmergencyLocation parse_location_in(std::string_view xml, const char *expected_ns) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  // The MCPTT, MCData and MCVideo documents differ in namespace only (TS 24.379 annex F.3,
  // TS 24.282 annex D.4, TS 24.281 annex F.3).
  const char *ns = expected_ns != nullptr                           ? expected_ns
                   : is(root, "location-info", mcdata_location_ns)  ? mcdata_location_ns
                   : is(root, "location-info", mcvideo_location_ns) ? mcvideo_location_ns
                                                                    : mcptt_location_ns;
  if (!is(root, "location-info", ns)) invalid("invalid emergency location namespace or root");
  const auto children = [&](xmlNode *parent, std::initializer_list<const char *> names) {
    auto expected = names.begin();
    for (auto child = parent->children; child; child = child->next) {
      if (child->type == XML_ELEMENT_NODE) {
        if (expected == names.end() || !is(child, *expected++, ns))
          invalid("unsupported or duplicate emergency location element");
      } else if (child->type != XML_COMMENT_NODE && !trim(text(child)).empty())
        invalid("unexpected emergency location text");
    }
    if (expected != names.end()) invalid("missing emergency location element");
  };
  children(root, {"Report"});
  auto report = unique_child(root, "Report", ns);
  if (attr(report, "ReportType") != "Emergency") invalid("location report must be Emergency");
  children(report, {"CurrentLocation"});
  auto current = unique_child(report, "CurrentLocation", ns);
  children(current, {"CurrentCoordinate"});
  auto coordinate = unique_child(current, "CurrentCoordinate", ns);
  children(coordinate, {"longitude", "latitude"});
  const auto value = [&](const char *name) {
    auto element = unique_child(coordinate, name, ns);
    const auto protection = attr(element, "type");
    if (!protection.empty() && protection != "Normal") invalid("unsupported emergency location protection");
    children(element, {"threebytes"});
    auto bytes = unique_child(element, "threebytes", ns);
    return number(scalar(bytes), 0xffffff);
  };

  return {value("latitude"), value("longitude")};
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.379 annex F.3, TS 24.282 annex D.4, TS 24.281 annex F.3: the emergency location of a multipart body (the
// MCPTT, MCData or MCVideo location-info MIME part, whose document must be in that service's namespace), if any;
// more than one is refused.
std::optional<EmergencyLocation> parse_emergency_location_parts(const std::vector<BodyPart> &parts) {
  static const std::pair<std::string_view, const char *> location_types[]{
      {mcptt_location_mime, mcptt_location_ns},
      {"application/vnd.3gpp.mcdata-location-info+xml", mcdata_location_ns},
      {mcvideo_service.location_mime, mcvideo_location_ns}};
  std::optional<EmergencyLocation> location;
  for (const auto &part : parts)
    for (const auto &[type, ns] : location_types)
      if (part.content_type == type) {
        if (location) invalid("duplicate emergency location MIME part");
        location = parse_location_in(part.body, ns);
      }
  return location;
}

} // namespace mcx
