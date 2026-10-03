// Service admission by feature tag and ICSI: the Accept-Contact checks that select the MCPTT or the MCVideo
// service for an incoming SIP request.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "mcx/admission.hpp"

#include <cassert>
#include <iostream>

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.2 step 3: a request is refused unless an Accept-Contact header field carries the
// g.3gpp.mcptt media feature tag (annex D.2) and the g.3gpp.icsi-ref media feature tag with the MCPTT ICSI
// "urn:urn-7:3gpp-service.ims.icsi.mcptt" (annex E.2). Checks escaped and case-varied forms, multiple and
// comma-joined header values, and near misses (extended tag names, FALSE, extended or negated ICSI, an
// unterminated quote, a tag hidden inside another parameter's quoted value).
int main() {
  using mcx::has_mcptt_accept_contact;
  assert(has_mcptt_accept_contact(
      {"*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\";+g.3gpp.mcptt;require;explicit"}));
  assert(has_mcptt_accept_contact({"*; +G.3GPP.MCPTT = \"TRUE\";require",
                                   "*;+g.3gpp.icsi-ref=\"urn:other,urn:urn-7:3gpp-service.ims.icsi.mcptt\""}));
  assert(
      has_mcptt_accept_contact({"*;+g.3gpp.mcptt, *;+g.3gpp.icsi-ref=\"urn%3aurn-7%3a3gpp-service.ims.icsi.mcptt\""}));
  assert(!has_mcptt_accept_contact({}));
  assert(
      !has_mcptt_accept_contact({"*;+g.3gpp.mcptt-extra;+g.3gpp.icsi-ref=\"urn:urn-7:3gpp-service.ims.icsi.mcptt\""}));
  assert(
      !has_mcptt_accept_contact({"*;+g.3gpp.mcptt=FALSE;+g.3gpp.icsi-ref=\"urn:urn-7:3gpp-service.ims.icsi.mcptt\""}));
  assert(
      !has_mcptt_accept_contact({"*;+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"urn:urn-7:3gpp-service.ims.icsi.mcptt-extra\""}));
  assert(!has_mcptt_accept_contact({"*;+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"!urn:urn-7:3gpp-service.ims.icsi.mcptt\""}));
  assert(!has_mcptt_accept_contact({"*;+g.3gpp.mcptt;+g.3gpp.icsi-ref=\"unterminated"}));
  assert(
      !has_mcptt_accept_contact({"*;other=\";+g.3gpp.mcptt;+g.3gpp.icsi-ref=urn:urn-7:3gpp-service.ims.icsi.mcptt\""}));
  // TS 24.281 annex D.2 and annex E.2: the g.3gpp.mcvideo media feature tag and the MCVideo ICSI select MCVideo,
  // not MCPTT.
  using mcx::has_service_accept_contact;
  assert(has_service_accept_contact(
      {"*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcvideo\";+g.3gpp.mcvideo;require;explicit"},
      mcx::mcvideo_service));
  assert(!has_service_accept_contact(
      {"*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcptt\";+g.3gpp.mcptt;require;explicit"},
      mcx::mcvideo_service));
  assert(!has_mcptt_accept_contact(
      {"*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mcvideo\";+g.3gpp.mcvideo;require;explicit"}));
  assert(!has_service_accept_contact({"*;+g.3gpp.mcvideo;+g.3gpp.icsi-ref=\"urn:urn-7:3gpp-service.ims.icsi.mcptt\""},
                                     mcx::mcvideo_service));
  std::cout << "admission tests passed\n";
}
