//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MC services of OpenMCX, and what tells one MC service apart on the wire and in configuration.
//
// Specifications: TS 23.280 V19.10.1 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282
// V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
#pragma once

#include "mcx/mcdata.hpp"

#include <string>
#include <string_view>

namespace mcx {
//------------------------------------------------------------------------------
// TS 23.280 clause 7.3.1.2: the MC services. MCPTT and MCVideo share the call-handling core (McServer); MCData has
// its own server (DataServer) and shares only the service parts (src/server/parts).
enum class Service { mcptt, mcvideo, mcdata };

//------------------------------------------------------------------------------
// TS 24.379 annexes D.2, E.2, F.1 and F.3, TS 24.281 annexes D.2, E.2, F.1 and F.3 and TS 24.282 annexes C.2, D.1
// and D.4: what tells one MC service apart on the wire and in configuration. The MCVideo <mcvideoinfo> mirrors the
// TS 24.379 <mcpttinfo> with the element prefix changed; the MCData <mcdatainfo> has its own elements (TS 24.282
// annex D.1, src/protocol/mcdata.cpp).
struct ServiceProfile {
  Service service;
  const char *name;          // configuration section and log label
  const char *label;         // the service's name in text: "MCPTT", "MCVideo", "MCData"
  const char *icsi;          // P-Preferred-Service, P-Asserted-Service (annex E.2)
  const char *icsi_encoded;  // the ICSI as a +g.3gpp.icsi-ref feature-tag value
  const char *feature_tag;   // media feature tag without the leading '+' (annex D.2)
  const char *info_mime;     // application/vnd.3gpp.<service>-info+xml (annex F.1)
  const char *info_ns;       // namespace of <prefix>info (annex F.1)
  const char *info_prefix;   // element prefix: <prefix>info, <prefix>-Params, <prefix>URI
  const char *location_mime; // location-info body (annex F.3)
  const char *id_claim;      // IdMS access-token claim with the user's MC service ID (TS 33.180 table B.2.2.3-1)
  const char *scope;         // the access token's scope for the service (TS 33.180 table B.4.2.2-1)
  // The ambient call: its <session-type> and <...-type> element prefix, and the word for the party it is about, as in
  // its release reasons (TS 24.379 clause 11.1.6 ambient listening, "listened-to"; TS 24.281 clause 15 ambient
  // viewing, "viewed-to").
  const char *ambient;       // "ambient-listening" or "ambient-viewing"
  const char *ambient_party; // "listened-to" or "viewed-to"; MCData has no ambient call: ""
  // The prefix of the server's event names (the stdout event lines and the lab scenarios read them): "" for MCPTT
  // and MCVideo, "mcdata_" for MCData.
  const char *event_prefix;
};

//------------------------------------------------------------------------------
// TS 24.379: the MCPTT service profile.
inline constexpr ServiceProfile mcptt_service{
    Service::mcptt,
    "mcptt",
    "MCPTT",
    "urn:urn-7:3gpp-service.ims.icsi.mcptt",
    "urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt",
    "g.3gpp.mcptt",
    "application/vnd.3gpp.mcptt-info+xml",
    "urn:3gpp:ns:mcpttInfo:1.0",
    "mcptt",
    "application/vnd.3gpp.mcptt-location-info+xml",
    "mcptt_id",
    "3gpp:mc:ptt_service",
    "ambient-listening",
    "listened-to",
    "",
};

//------------------------------------------------------------------------------
// TS 24.281: the MCVideo service profile.
inline constexpr ServiceProfile mcvideo_service{
    Service::mcvideo,
    "mcvideo",
    "MCVideo",
    "urn:urn-7:3gpp-service.ims.icsi.mcvideo",
    "urn%3Aurn-7%3A3gpp-service.ims.icsi.mcvideo",
    "g.3gpp.mcvideo",
    "application/vnd.3gpp.mcvideo-info+xml",
    "urn:3gpp:ns:mcvideoInfo:1.0",
    "mcvideo",
    "application/vnd.3gpp.mcvideo-location-info+xml",
    "mcvideo_id",
    "3gpp:mc:video_service",
    "ambient-viewing",
    "viewed-to",
    "",
};

//------------------------------------------------------------------------------
// TS 24.282: the MCData service profile (ICSI and feature tag: annex C.2; mcdata-info: annex D.1; location-info:
// annex D.4).
inline constexpr ServiceProfile mcdata_service{
    Service::mcdata,
    "mcdata",
    "MCData",
    mcdata::icsi,
    "urn%3Aurn-7%3A3gpp-service.ims.icsi.mcdata",
    "g.3gpp.mcdata",
    mcdata::info_mime,
    mcdata::info_ns,
    "mcdata",
    mcdata::location_mime,
    "mcdata_id",
    "3gpp:mc:data_service",
    "",
    "",
    "mcdata_",
};

//------------------------------------------------------------------------------
// Helper: the profile of an MC service.
inline constexpr const ServiceProfile &service_profile(Service service) {
  switch (service) {
  case Service::mcptt: return mcptt_service;
  case Service::mcvideo: return mcvideo_service;
  case Service::mcdata: return mcdata_service;
  }
  return mcptt_service;
}

//------------------------------------------------------------------------------
// Helper: the profile of a call service (MCPTT or MCVideo) by its configuration name; nullptr for any other name,
// "mcdata" included: the MCData server is not built on the call-handling core.
inline constexpr const ServiceProfile *call_service_named(std::string_view name) {
  if (name == mcptt_service.name) return &mcptt_service;
  if (name == mcvideo_service.name) return &mcvideo_service;
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.379 annex D.2, TS 24.281 annex D.2, TS 24.282 annex C.2: an Accept-Contact value requiring the service's media
// feature tag (g.3gpp.mcptt, g.3gpp.mcvideo or g.3gpp.mcdata).
inline std::string feature_accept(const ServiceProfile &service) {
  return std::string("*;+") + service.feature_tag + ";require;explicit";
}

//------------------------------------------------------------------------------
// TS 24.379 annex E.2, TS 24.281 annex E.2, TS 24.282 annex C.2: an Accept-Contact value requiring the service's ICSI.
inline std::string icsi_accept(const ServiceProfile &service) {
  return std::string("*;+g.3gpp.icsi-ref=\"") + service.icsi_encoded + "\";require;explicit";
}

//------------------------------------------------------------------------------
// Helper: the list of a functional alias definition (CMS) naming the users allowed to activate it (TS 24.379 clause
// 9A.2.2.3.3, TS 24.282 clause 22.2.2.3.3 step 4a): one per service.
inline constexpr const char *alias_user_list(Service service) {
  switch (service) {
  case Service::mcptt: return "users";
  case Service::mcvideo: return "mcvideo_users";
  case Service::mcdata: return "mcdata_users";
  }
  return "users";
}
} // namespace mcx
