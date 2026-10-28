//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The request values of the MCPTT, MCVideo and MCData servers (src/server/request_values.hpp): the Expires header
// field, percent-decoding of URI components, the outcome rule of an implicit affiliation and the configuration
// management documents of a subscription's resource list; and the implicit floor request rules of the MCPTT server
// (src/server/implicit_floor.hpp).
//
// Specifications: RFC 3261, RFC 3986, RFC 5875, TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19),
// TS 24.484 V19.6.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "implicit_floor.hpp"
#include "request_values.hpp"

#include <cassert>
#include <iostream>
using namespace mcx;

//------------------------------------------------------------------------------
// RFC 3261 section 20.19: Expires is a decimal number of seconds from 0 to 2**32-1; anything else is refused
// (std::nullopt, answered 400) instead of throwing out of the procedure.
static void Section_20_19_Expires() {
  assert(parse_expires("0") == 0U);
  assert(parse_expires("3600") == 3600U);
  assert(parse_expires("4294967295") == max_expires_s);
  assert(!parse_expires(""));
  assert(!parse_expires("4294967296"));
  assert(!parse_expires("99999999999999999999999"));
  assert(!parse_expires("-1"));
  assert(!parse_expires("60s"));
  assert(!parse_expires(" 60"));
  assert(!parse_expires("abc"));
}

//------------------------------------------------------------------------------
// RFC 3986 section 2.1: '%' with two hexadecimal digits is one octet; a bad or truncated escape is refused.
static void Section_2_1_PercentDecoding() {
  assert(percent_decode("group%40example.com") == "group@example.com");
  assert(percent_decode("a%2Fb%2fc") == "a/b/c");
  assert(percent_decode("plain") == "plain");
  assert(percent_decode("") == "");
  assert(!percent_decode("%zz"));
  assert(!percent_decode("%4"));
  assert(!percent_decode("%"));
  assert(!percent_decode("%4z"));
  assert(!percent_decode("x%g1"));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.11: an implicit affiliation is kept only when the request is finally accepted; a final
// failure or an exception (answered 403 after the guard is gone) cancels it.
static void Clause_9_2_2_3_11_ImplicitAffiliationCancellation() {
  assert(!implicit_affiliation_cancelled(200, false));
  assert(!implicit_affiliation_cancelled(202, false));
  assert(implicit_affiliation_cancelled(200, true));
  assert(implicit_affiliation_cancelled(403, false));
  assert(implicit_affiliation_cancelled(488, false));
  assert(implicit_affiliation_cancelled(302, false));
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step e and TS 37.579-1 table 5.3.2.6.1-1: the entries of one configuration
// subscription name the UE configuration, user profile and service configuration documents, by AUID, XUI and name;
// anything else (another AUID, a node selector, a collection, a bad escape) names none.
static void Clause_6_3_13_3_2_2_ConfigurationDocuments() {
  const auto ue = config_document_reference("org.3gpp.mcptt.ue-config/users/sip%3Aalice%40example.org/"
                                            "urn%3Auuid%3A6e8bc430-9c3a-11d9-9669-0800200c9a66");
  assert(ue && ue->auid == "org.3gpp.mcptt.ue-config" && ue->xui == "sip:alice@example.org" &&
         ue->document == "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66");
  const auto profile = config_document_reference(
      "xcap-root/org.3gpp.mcptt.user-profile/users/sip:alice@example.org/mcptt-user-profile-1.xml");
  assert(profile && profile->auid == "org.3gpp.mcptt.user-profile" && profile->document == "mcptt-user-profile-1.xml");
  const auto service = config_document_reference("org.3gpp.mcptt.service-config/global/service-config.xml");
  assert(service && service->xui.empty() && service->document == "service-config.xml");
  assert(!config_document_reference("org.openmobilealliance.groups/global/byGroupID/sip:g@example.org"));
  assert(!config_document_reference("org.3gpp.mcptt.user-profile/users/sip:a@example.org/p.xml/~~/x"));
  assert(!config_document_reference("org.3gpp.mcptt.ue-config/users/sip:a@example.org/"));
  assert(!config_document_reference("org.3gpp.mcptt.ue-config/users/sip%zz/doc"));
  assert(!config_document_reference("xorg.3gpp.mcptt.service-config/global/service-config.xml"));
  assert(!config_document_reference("org.3gpp.mcptt.service-config/other/service-config.xml"));
}

//------------------------------------------------------------------------------
// TS 24.380 clause 14.3.5: the initial INVITE that initiates a call with floor control is accepted as an implicit
// floor request; a join of an existing chat group call, a rejoin by session identity (clause 6.2.1 item 2), a call
// without floor control and an offer without "mc_implicit_request" are not.
static void Clause_14_3_5_ImplicitFloorAccepted() {
  assert(implicit_floor_accepted(true, true, true));
  assert(!implicit_floor_accepted(false, true, true));
  assert(!implicit_floor_accepted(true, false, true));
  assert(!implicit_floor_accepted(true, true, false));
}

//------------------------------------------------------------------------------
// TS 24.380 clause 14.3.6: "mc_ssrc" returns the offer's "a=ssrc" unless it collides, then a new value; nothing
// without an "a=ssrc".
static void Clause_14_3_6_McSsrc() {
  std::uint32_t next = 40;
  const auto fresh = [&] { return next++; };
  assert(implicit_audio_ssrc(0, {}, fresh) == 0);
  assert(implicit_audio_ssrc(17, {}, fresh) == 17);
  assert(implicit_audio_ssrc(17, {16, 18}, fresh) == 17);
  assert(implicit_audio_ssrc(17, {17, 40}, fresh) == 41); // collision: a new value, itself not in use
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5.2.2 items 1 and 3: with nobody sending media the implicit request is processed as a Floor
// Request; with another talker it is queued when queueing is negotiated (3b), or answered with Floor Taken (3c).
static void Clause_6_3_5_2_2_ImplicitFloorOutcome() {
  assert(implicit_floor_outcome(false, false) == ImplicitFloorOutcome::request);
  assert(implicit_floor_outcome(false, true) == ImplicitFloorOutcome::request);
  assert(implicit_floor_outcome(true, true) == ImplicitFloorOutcome::queue);
  assert(implicit_floor_outcome(true, false) == ImplicitFloorOutcome::taken);
}

//------------------------------------------------------------------------------
int main() {
  Section_20_19_Expires();
  Section_2_1_PercentDecoding();
  Clause_9_2_2_3_11_ImplicitAffiliationCancellation();
  Clause_6_3_13_3_2_2_ConfigurationDocuments();
  Clause_14_3_5_ImplicitFloorAccepted();
  Clause_14_3_6_McSsrc();
  Clause_6_3_5_2_2_ImplicitFloorOutcome();
  std::cout << "server request values: all checks passed\n";
  return 0;
}
