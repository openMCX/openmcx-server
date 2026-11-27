//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The served users (src/server/parts/served_users.hpp): the lookup by MC service ID with each service's rule, the
// affiliation documents in each service's namespace, the list membership, and the PUBLISH for the service settings
// only (TS 24.379 clause 7.3.4): which procedure a poc-settings PUBLISH starts, the binding, RFC 3903 and the settings.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "parts/served_users.hpp"

#include <cassert>
#include <iostream>
using namespace mcx;

namespace {
//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.3 step 5a, TS 24.282 clause 7.3.3 step 5a: the user bound to an MC service ID; MCData finds
// it only while its service authorisation lasts, the core whether it lasts or not.
void Clause_7_3_3_ByIdentity() {
  std::map<std::string, ServedUser> users;
  users["sip:a@x"].id = "alice";
  users["sip:a@x"].expires = std::time(nullptr) - 1;
  users["sip:b@x"].id = "bob";
  users["sip:b@x"].expires = std::time(nullptr) + 60;
  assert(served_by_id(users, "alice", false) == &users["sip:a@x"]);
  assert(served_by_id(users, "alice", true) == nullptr);
  assert(served_by_id(users, "bob", true) == &users["sip:b@x"]);
  assert(served_by_id(users, "carol", false) == nullptr);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1, TS 24.281 clause 8.3.1, TS 24.282 clause 8.4.1: the affiliation document is in the
// service's namespace; the status lists every affiliated group (TS 24.379 clause 9.2.2.2.5, TS 24.282 clause
// 8.3.2.5).
void Clause_9_3_1_AffiliationDocuments() {
  const auto mcptt = service_affiliation(mcptt_service, "alice", "c1", "p1");
  const auto video = service_affiliation(mcvideo_service, "alice", "c1", "p1");
  const auto data = service_affiliation(mcdata_service, "alice", "c1", "p1");
  assert(!mcptt.mcvideo && !mcptt.mcdata && video.mcvideo && !video.mcdata && data.mcdata && !data.mcvideo);
  assert(data.user_id == "alice" && data.client_id == "c1" && data.publication_id == "p1");
  ServedUser user;
  user.id = "alice";
  user.client = "c1";
  user.groups = {"g1", "g2"};
  const auto status = affiliation_status(mcdata_service, user, "p2");
  assert(status.groups == std::vector<std::string>({"g1", "g2"}));
  assert(status.statuses == std::vector<std::string>({"affiliated", "affiliated"}) && status.publication_id == "p2");
  assert(parse_affiliation(affiliation_xml(status, true)).mcdata);
}

//------------------------------------------------------------------------------
// Helper: a JSON list names an ID only as a string entry; anything else names nobody.
void Listed() {
  assert(listed(Json::array({"alice", 3}), "alice") && !listed(Json::array({3}), "3"));
  assert(!listed(Json::object(), "alice") && !listed(Json(), "alice"));
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 7.3.3 and 7.3.4 condition 3 (TS 24.281, TS 24.282 likewise): a poc-settings PUBLISH with an access
// token is a service authorisation, encrypted or not; one with the request URI and client ID and no access token is
// for the service settings only; anything else (no service information, two of them, unreadable) goes to the service
// authorisation, which refuses it.
void Clause_7_3_4_Dispatch() {
  const auto poc = BodyPart{"application/poc-settings+xml", poc_settings_xml("c1", 0, true)};
  McpttInfo settings;
  settings.request_uri = "sip:alice@x";
  settings.client_id = "c1";
  McpttInfo authorisation = settings;
  authorisation.request_uri.clear();
  authorisation.access_token = "token";
  const auto kind = [&](const McpttInfo &info, const ServiceProfile &service) {
    return poc_settings_publish_kind({{service.info_mime, service_info_xml(info, service)}, poc}, service);
  };
  assert(kind(authorisation, mcptt_service) == PocSettingsPublish::service_authorisation);
  assert(kind(settings, mcptt_service) == PocSettingsPublish::settings_only);
  assert(kind(settings, mcvideo_service) == PocSettingsPublish::settings_only);
  assert(kind(authorisation, mcvideo_service) == PocSettingsPublish::service_authorisation);
  // The access token and client ID encrypted with the CSK the request uploads (TS 24.379 clause 6.6.2.3, clause
  // 7.3.1A): still a service authorisation, also when it names the request URI.
  const std::string encrypted =
      "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><mcptt-Params>"
      "<mcptt-access-token type=\"Encrypted\"><EncryptedData xmlns=\"http://www.w3.org/2009/xmlenc11#\"/>"
      "</mcptt-access-token><mcptt-request-uri type=\"Normal\"><mcpttURI>sip:alice@x</mcpttURI></mcptt-request-uri>"
      "<mcptt-client-id type=\"Encrypted\"><EncryptedData xmlns=\"http://www.w3.org/2009/xmlenc11#\"/>"
      "</mcptt-client-id></mcptt-Params></mcpttinfo>";
  assert(poc_settings_publish_kind({{mcptt_service.info_mime, encrypted}, poc}, mcptt_service) ==
         PocSettingsPublish::service_authorisation);
  // The request URI and client ID encrypted (clause 7.3.1A, third case): for the settings only.
  const std::string settings_encrypted =
      "<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><mcptt-Params>"
      "<mcptt-request-uri type=\"Encrypted\"><EncryptedData xmlns=\"http://www.w3.org/2009/xmlenc11#\"/>"
      "</mcptt-request-uri><mcptt-client-id type=\"Encrypted\"><EncryptedData "
      "xmlns=\"http://www.w3.org/2009/xmlenc11#\"/></mcptt-client-id></mcptt-Params></mcpttinfo>";
  assert(poc_settings_publish_kind({{mcptt_service.info_mime, settings_encrypted}, poc}, mcptt_service) ==
         PocSettingsPublish::settings_only);
  // MCData (TS 24.282 clause 7.3.4).
  const std::string mcdata_settings =
      std::string("<mcdatainfo xmlns=\"") + mcdata_service.info_ns +
      "\"><mcdata-Params><mcdata-request-uri type=\"Normal\"><mcdataURI>sip:alice@x</mcdataURI></mcdata-request-uri>"
      "<mcdata-client-id type=\"Normal\"><mcdataString>c1</mcdataString></mcdata-client-id></mcdata-Params>"
      "</mcdatainfo>";
  assert(poc_settings_publish_kind({{mcdata_service.info_mime, mcdata_settings}, poc}, mcdata_service) ==
         PocSettingsPublish::settings_only);
  // Only the client ID; no service information; two of them; one that cannot be read; another service's.
  McpttInfo client_only;
  client_only.client_id = "c1";
  assert(kind(client_only, mcptt_service) == PocSettingsPublish::service_authorisation);
  assert(poc_settings_publish_kind({poc}, mcptt_service) == PocSettingsPublish::service_authorisation);
  const BodyPart info{mcptt_service.info_mime, service_info_xml(settings, mcptt_service)};
  assert(poc_settings_publish_kind({info, info, poc}, mcptt_service) == PocSettingsPublish::service_authorisation);
  assert(poc_settings_publish_kind({{mcptt_service.info_mime, "<mcpttinfo"}, poc}, mcptt_service) ==
         PocSettingsPublish::service_authorisation);
  assert(poc_settings_publish_kind({{mcptt_service.info_mime, service_info_xml(settings, mcvideo_service)}, poc},
                                   mcptt_service) == PocSettingsPublish::service_authorisation);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.4 steps 4 and 6: the binding of identity, MC service ID and client ID, served here and valid;
// none (404, warning 141) for another ID, another client, an expired binding, a user served by a peer, or none.
void Clause_7_3_4_Binding() {
  const auto now = std::time(nullptr);
  std::map<std::string, ServedUser> users;
  auto &alice = users["sip:a@x"];
  alice.id = "sip:alice@x";
  alice.client = "c1";
  alice.expires = now + 60;
  assert(settings_binding(users, "sip:a@x", "sip:alice@x", "c1", now) == &alice);
  assert(!settings_binding(users, "sip:a@x", "sip:bob@x", "c1", now));
  assert(!settings_binding(users, "sip:a@x", "sip:alice@x", "c2", now));
  assert(!settings_binding(users, "sip:b@x", "sip:alice@x", "c1", now));
  assert(!settings_binding(users, "sip:a@x", "", "c1", now));
  assert(!settings_binding(users, "sip:a@x", "sip:alice@x", "c1", now + 60));
  alice.peer = "peer";
  assert(!settings_binding(users, "sip:a@x", "sip:alice@x", "c1", now));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.4 step 7, RFC 3903 section 6: the entity tag of the user's publication modifies it, another
// one is 412, two are 400; no entity tag needs a body (initial publication); Expires as requested, else the longest,
// and one that is not delta-seconds 400.
void Clause_7_3_4_Rfc3903() {
  auto checked = settings_publication("e1", "4294967295", "e1", true);
  assert(checked.status == 0 && checked.expires == 4294967295ULL);
  checked = settings_publication("", "3600", "e1", true);
  assert(checked.status == 0 && checked.expires == 3600);
  checked = settings_publication("", "", "", true); // after an authorisation by REGISTER: no entity tag yet
  assert(checked.status == 0 && checked.expires == 4294967295ULL);
  assert(settings_publication("e2", "3600", "e1", true).status == 412);
  assert(settings_publication("e1", "3600", "", true).status == 412);
  assert(settings_publication("e1, e2", "3600", "e1", true).status == 400);
  assert(settings_publication("", "3600", "e1", false).status == 400);
  assert(settings_publication("e1", "60s", "e1", true).status == 400);
  assert(settings_publication("e1", "", "e1", false).status == 0); // a refresh
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.3.4 steps 8, 10, 10a and 11: the client's entity: its answer mode as RFC 5373 "Auto" or
// "Manual", its user profile index and multiplex support (absent: false); cached while the settings last.
void Clause_7_3_4_Settings() {
  const auto now = std::time(nullptr);
  auto settings = read_service_settings(poc_settings_xml("c1", 2, true, true), "c1", now + 60);
  assert(settings.answer_mode == "Manual" && settings.profile_index == 2U && settings.multiplex_support);
  settings = read_service_settings(poc_settings_xml("c1", 0, false), "c1", now + 60);
  assert(settings.answer_mode == "Auto" && settings.profile_index == 0U && !settings.multiplex_support);
  const std::string bare = "<poc-settings xmlns=\"urn:oma:params:xml:ns:poc:poc-settings\"><entity id=\"c1\"/>"
                           "<entity id=\"c2\"><am-settings><answer-mode>manual</answer-mode></am-settings></entity>"
                           "</poc-settings>";
  settings = read_service_settings(bare, "c1", now + 60);
  assert(settings.answer_mode.empty() && !settings.profile_index && !settings.multiplex_support);
  assert(read_service_settings(bare, "c2", now + 60).answer_mode == "Manual");
  bool refused = false;
  try {
    (void)read_service_settings(bare, "c3", now + 60);
  } catch (const std::exception &) {
    refused = true;
  }
  assert(refused);
  ServedUser user;
  assert(cached_answer_mode(user, now).empty());
  user.settings = read_service_settings(poc_settings_xml("c1", 0, true), "c1", now + 60);
  assert(cached_answer_mode(user, now) == "Manual");
  assert(cached_answer_mode(user, now + 60).empty());
  // TS 24.379 clauses 10.1.1.3.2 and 17.3.2.1.2 steps 7 and 8: a group call INVITE has the member's own Answer-Mode
  // Indication, whatever the call policy; the policy's only without cached settings; none for a member of a peer.
  assert(group_answer_mode(user, now, "Auto") == "Manual");
  assert(group_answer_mode(user, now + 60, "Auto") == "Auto");
  user.settings = read_service_settings(poc_settings_xml("c1", 0, false), "c1", now + 60);
  assert(group_answer_mode(user, now, "Manual") == "Auto");
  ServedUser fresh;
  assert(group_answer_mode(fresh, now, "Manual") == "Manual");
  fresh.peer = "mcptt.partner.example";
  assert(group_answer_mode(fresh, now, "Auto").empty());
  fresh.settings = read_service_settings(poc_settings_xml("c1", 0, true), "c1", now + 60);
  assert(group_answer_mode(fresh, now, "Auto") == "Manual");
}
} // namespace

//------------------------------------------------------------------------------
namespace {
//------------------------------------------------------------------------------
// TS 24.379 clauses 6.6.2.3.2 and 6.6.3.3.2 with RFC 6665 section 4.2.2: a terminating NOTIFY whose body cannot be
// protected for its recipient goes without a body (it still ends the subscription); any other is not sent.
void Section_4_2_2_UnprotectableNotify() {
  assert(notify_without_body("terminated;reason=noresource"));
  assert(notify_without_body("terminated;reason=rejected"));
  assert(notify_without_body("terminated;reason=timeout"));
  assert(notify_without_body("terminated"));
  assert(notify_without_body(" Terminated ;reason=noresource"));
  assert(!notify_without_body("active;expires=3600"));
  assert(!notify_without_body("pending"));
  assert(!notify_without_body("terminatedx"));
  assert(!notify_without_body(""));
}
} // namespace

int main() {
  Clause_7_3_3_ByIdentity();
  Clause_9_3_1_AffiliationDocuments();
  Listed();
  Clause_7_3_4_Dispatch();
  Clause_7_3_4_Binding();
  Clause_7_3_4_Rfc3903();
  Clause_7_3_4_Settings();
  Section_4_2_2_UnprotectableNotify();
  std::cout << "served_users: all checks passed\n";
}
