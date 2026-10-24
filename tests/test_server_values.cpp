//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The request values of the MCPTT, MCVideo and MCData servers (src/server/request_values.hpp): the Expires header
// field, percent-decoding of URI components, the outcome rule of an implicit affiliation and the configuration
// management documents of a subscription's resource list.
//
// Specifications: RFC 3261, RFC 3986, RFC 5875, TS 24.379 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
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
int main() {
  Section_20_19_Expires();
  Section_2_1_PercentDecoding();
  Clause_9_2_2_3_11_ImplicitAffiliationCancellation();
  Clause_6_3_13_3_2_2_ConfigurationDocuments();
  std::cout << "server request values: all checks passed\n";
  return 0;
}
