//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCPTT and MCVideo protocol bodies: mcpttinfo, mcvideoinfo, location, conference-info, PIDF, regroup, profiles, SDP.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19),
// TS 24.581 V19.2.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19),
// TS 24.229, RFC 4575, RFC 4567, RFC 2046, RFC 8101.

#include "mcx/protocol.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>

using namespace mcx;

//------------------------------------------------------------------------------
// Fails the test with the given message when the condition does not hold.
static void check(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Checks that the operation throws: the codec refuses the malformed input.
static void rejects(const std::function<void()> &operation) {
  bool failed = false;
  try {
    operation();
  } catch (const std::exception &) {
    failed = true;
  }
  check(failed, "malformed input was accepted");
}

//------------------------------------------------------------------------------
// The codecs of the MCPTT and MCVideo bodies: each round trip, its schema order, and the refusal of malformed input.
int main() {
  // TS 24.379 clause 6.2.9.1 and annex F.3: the emergency location report, <ReportType> "Emergency".
  EmergencyLocation location{0, 16777215};
  const auto location_xml = emergency_location_xml(location);
  const auto location_copy = parse_emergency_location(location_xml);
  check(location_copy.latitude == 0 && location_copy.longitude == 16777215, "encoded emergency coordinates lost");
  check(location_xml.find("ReportType=\"Emergency\"") != std::string::npos &&
            location_xml.find("<threebytes>") != std::string::npos,
        "location schema wrappers missing");
  rejects([&] { (void)emergency_location_xml({16777216, 0}); });
  for (const auto &[from, to] :
       std::vector<std::pair<std::string, std::string>>{{"mcpttLocationInfo", "wrongLocationInfo"},
                                                        {"16777215", "16777216"},
                                                        {"16777215", "-1"},
                                                        {"16777215", "1.5"},
                                                        {"Normal", "Encrypted"},
                                                        {"Emergency", "NonEmergency"},
                                                        {"threebytes", "three-bytes"}}) {
    auto bad = location_xml;
    auto pos = bad.find(from);
    bad.replace(pos, from.size(), to);
    rejects([&] { (void)parse_emergency_location(bad); });
  }
  auto duplicate_location = location_xml;
  const auto start = duplicate_location.find("<latitude");
  const auto end = duplicate_location.find("</latitude>", start) + std::string("</latitude>").size();
  duplicate_location.insert(end, duplicate_location.substr(start, end - start));
  rejects([&] { (void)parse_emergency_location(duplicate_location); });
  rejects([&] {
    (void)parse_emergency_location_parts({{mcptt_location_mime, location_xml}, {mcptt_location_mime, location_xml}});
  });
  // TS 24.282 annex D.4: the MCData location-info part is read too; each MIME type needs its own namespace.
  {
    const auto mcdata_location = emergency_location_xml(location, true);
    const auto found =
        parse_emergency_location_parts({{"application/vnd.3gpp.mcdata-location-info+xml", mcdata_location}});
    check(found && found->longitude == 16777215, "MCData emergency location part not read");
    rejects([&] { (void)parse_emergency_location_parts({{mcptt_location_mime, mcdata_location}}); });
    rejects([&] { (void)parse_emergency_location_parts({{mcvideo_service.location_mime, location_xml}}); });
    check(service_location_xml(location, mcvideo_service).find("urn:3gpp:ns:mcvideoLocationInfo:1.0") !=
              std::string::npos,
          "MCVideo emergency location namespace");
    check(parse_emergency_location_parts(
              {{mcvideo_service.location_mime, service_location_xml(location, mcvideo_service)}})
              .has_value(),
          "MCVideo emergency location part not read");
  }

  // TS 24.379 clause 6.3.3.4 and RFC 4575: conference-info names the group in "entity", one <endpoint> per <user>.
  ConferenceInfo conference;
  conference.session_uri = "sip:focus@example.test;mcptt-session=abc";
  conference.group_id = "sip:rescue@example.test";
  conference.version = 7;
  conference.users = {{"sip:medic@example.test", "sip:device@example.test", "connected", "sip:alias@example.test"},
                      {"sip:driver@example.test", "sip:radio@example.test", "disconnected", ""}};
  auto conference_xml = conference_info_xml(conference);
  check(conference_xml.find("entity=\"sip:rescue@example.test\"") != std::string::npos,
        "MCPTT conference entity must identify group, not session");
  auto conference_copy = parse_conference_info(conference_xml);
  check(conference_copy.session_uri == conference.session_uri && conference_copy.group_id == conference.group_id &&
            conference_copy.version == 7 && conference_copy.full && !conference_copy.deleted &&
            conference_copy.users.size() == 2,
        "conference identity/version/users lost");
  check(conference_copy.users[0].functional_alias == conference.users[0].functional_alias &&
            conference_copy.users[1].status == "disconnected",
        "conference endpoint data lost");
  check(conference_xml.find("mcvideoConfInfo") == std::string::npos && !conference_copy.mcvideo,
        "MCPTT conference uses the MCPTT extension namespace");
  {
    // TS 24.281 clause 9.2.3.6.1.2: an MCVideo conference-info document's <functional-alias> is in the MCVideo
    // extension namespace.
    auto video = conference;
    video.mcvideo = true;
    const auto video_xml = conference_info_xml(video);
    const auto back = parse_conference_info(video_xml);
    check(video_xml.find("urn:3gpp:ns:mcvideoConfInfo:1.0") != std::string::npos &&
              video_xml.find("mcpttConfInfo") == std::string::npos && back.mcvideo &&
              back.users[0].functional_alias == conference.users[0].functional_alias,
          "MCVideo conference functional alias namespace");
  }
  conference.full = false;
  check(!parse_conference_info(conference_info_xml(conference)).full, "partial conference state lost");
  {
    // RFC 4575 section 5.6: a partial notification removes a user with state "deleted", without <endpoint>.
    auto partial = conference;
    partial.users = {{"sip:bob@example.test", {}, "disconnected", {}, "deleted"}};
    const auto back = parse_conference_info(conference_info_xml(partial));
    check(!back.full && back.users.size() == 1 && back.users[0].state == "deleted" &&
              back.users[0].status == "disconnected",
          "a deleted user of a partial notification");
    rejects([&] {
      (void)parse_conference_info(R"(<conference-info xmlns="urn:ietf:params:xml:ns:conference-info" )"
                                  R"(entity="sip:g@example.test" state="partial" version="2"><users>)"
                                  R"(<user entity="sip:bob@example.test" state="gone"/></users></conference-info>)");
    });
  }
  conference.deleted = true;
  conference.users.clear();
  check(parse_conference_info(conference_info_xml(conference)).deleted, "deleted conference state lost");
  rejects([&] {
    auto bad = conference;
    bad.group_id = "not a URI";
    conference_info_xml(bad);
  });
  rejects([&] {
    auto bad = conference;
    bad.session_uri = "sip:a@example.test\r\nInjected:x";
    conference_info_xml(bad);
  });
  rejects([&] {
    auto bad = conference_copy;
    bad.users.push_back(bad.users[0]);
    conference_info_xml(bad);
  });
  rejects([&] {
    auto bad = conference_copy;
    bad.users[0].status = "nonsense";
    conference_info_xml(bad);
  });
  rejects([&] {
    auto bad = conference_xml;
    bad.replace(bad.find("version=\"7\""), 11, "version=\"-1\"");
    parse_conference_info(bad);
  });
  rejects([&] {
    auto bad = conference_xml;
    bad.replace(bad.find("version=\"7\""), 11, "version=\"4294967296\"");
    parse_conference_info(bad);
  });
  rejects([&] {
    parse_conference_info("<conference-info xmlns='evil' entity='sip:x@example.test' version='1' state='full'/>");
  });
  {
    // A DTD with an external entity in front of an otherwise valid document: refused for the DTD alone.
    (void)parse_conference_info(conference_xml);
    auto with_dtd = conference_xml;
    const auto root = with_dtd.find("<conference-info");
    with_dtd.insert(root, "<!DOCTYPE conference-info [<!ENTITY a SYSTEM 'file:///etc/passwd'>]>");
    rejects([&] { parse_conference_info(with_dtd); });
  }
  rejects([&] {
    auto bad = conference_xml;
    auto position = bad.find("<status>connected</status>");
    bad.insert(position, "<status>disconnected</status>");
    parse_conference_info(bad);
  });
  auto escaped_conference = conference_copy;
  escaped_conference.session_uri = "sip:focus@example.test;token=a&b";
  check(parse_conference_info(conference_info_xml(escaped_conference)).session_uri == escaped_conference.session_uri,
        "conference URI escaping changed value");
  const std::string independent_conference =
      R"(<c:conference-info xmlns:c="urn:ietf:params:xml:ns:conference-info" entity="sip:group@example.test" version="0" state="full"><c:users><c:user entity="sip:user@example.test"><c:endpoint entity="urn:uuid:device"><c:status>connected</c:status></c:endpoint></c:user></c:users></c:conference-info>)";
  auto external_conference = parse_conference_info(independent_conference);
  check(external_conference.session_uri.empty() && external_conference.version == 0 &&
            external_conference.users[0].endpoint_uri == "urn:uuid:device",
        "standard prefixed conference body without optional description rejected");
  rejects([&] {
    auto bad = independent_conference;
    bad.insert(bad.find("</c:user>"),
               "<c:endpoint entity='urn:uuid:other'><c:status>connected</c:status></c:endpoint>");
    parse_conference_info(bad);
  });
  rejects([&] {
    auto bad = independent_conference;
    const std::string identity = " entity=\"urn:uuid:device\"";
    bad.erase(bad.find(identity), identity.size());
    parse_conference_info(bad);
  });
  rejects([&] {
    auto bad = conference_xml;
    bad.insert(bad.find("</status>"), "<nested/>");
    parse_conference_info(bad);
  });
  // TS 24.379 clause 7.4.1.2.2: the application/poc-settings+xml body with the mcsSettings extension.
  auto settings = poc_settings_xml("urn:uuid:test-client");
  check(settings.find("<entity id=\"urn:uuid:test-client\">") != std::string::npos, "PoC entity missing");
  check(settings.find("urn:3gpp:mcsSettings:1.0") != std::string::npos, "MCS settings namespace wrong");
  check(settings.find("<answer-mode>automatic</answer-mode>") != std::string::npos, "PoC answer mode wrong");
  // TS 24.379 annex F.1: the application/vnd.3gpp.mcptt-info+xml body.
  const std::string fixture =
      R"(<?xml version="1.0"?><mcpttinfo xmlns="urn:3gpp:ns:mcpttInfo:1.0"><mcptt-Params><session-type>prearranged</session-type><mcptt-request-uri type="Normal"><mcpttURI>sip:rescue@example.test</mcpttURI></mcptt-request-uri><mcptt-client-id type="Normal"><mcpttString>urn:uuid:client-a</mcpttString></mcptt-client-id></mcptt-Params></mcpttinfo>)";
  // TS 24.281 annex F.1: <mcvideoinfo> is <mcpttinfo> with the mcvideo prefix and namespace.
  const std::string video_fixture =
      R"(<?xml version="1.0"?><mcvideoinfo xmlns="urn:3gpp:ns:mcvideoInfo:1.0"><mcvideo-Params><session-type>prearranged</session-type><mcvideo-request-uri type="Normal"><mcvideoURI>sip:rescue@example.test</mcvideoURI></mcvideo-request-uri><mcvideo-calling-user-id type="Normal"><mcvideoURI>sip:alice@example.test</mcvideoURI></mcvideo-calling-user-id><emergency-ind type="Normal"><mcvideoBoolean>true</mcvideoBoolean></emergency-ind><mcvideo-client-id type="Normal"><mcvideoString>urn:uuid:client-a</mcvideoString></mcvideo-client-id></mcvideo-Params></mcvideoinfo>)";
  const auto video = parse_service_info(video_fixture, mcvideo_service);
  check(video.request_uri == "sip:rescue@example.test" && video.calling_user == "sip:alice@example.test" &&
            video.client_id == "urn:uuid:client-a" && video.emergency == true && video.session_type == "prearranged",
        "MCVideo information must parse");
  check(service_info_xml(video, mcvideo_service) == video_fixture, "MCVideo information must round-trip byte for byte");
  // TS 24.281 clauses 12.2.2.4 and 13.2.3.2.3: <video-pull-url> in <mcvideo-Params> (a
  // contentType), <video-push-url> in <anyExt> (an anyURI, sent in the SIP INFO).
  const std::string pull_fixture =
      R"(<?xml version="1.0"?><mcvideoinfo xmlns="urn:3gpp:ns:mcvideoInfo:1.0"><mcvideo-Params><session-type>one-from-server video pull</session-type><mcvideo-client-id type="Normal"><mcvideoString>urn:uuid:client-a</mcvideoString></mcvideo-client-id><video-pull-url type="Normal"><mcvideoURI>https://mcvideo-server/recordings/0a1b</mcvideoURI></video-pull-url></mcvideo-Params></mcvideoinfo>)";
  const auto pull = parse_service_info(pull_fixture, mcvideo_service);
  check(pull.session_type == "one-from-server video pull" &&
            pull.video_pull_url == "https://mcvideo-server/recordings/0a1b",
        "a video pull URL must parse");
  check(service_info_xml(pull, mcvideo_service) == pull_fixture, "a video pull request must round-trip byte for byte");
  const std::string push_fixture =
      R"(<?xml version="1.0"?><mcvideoinfo xmlns="urn:3gpp:ns:mcvideoInfo:1.0"><mcvideo-Params><anyExt><video-push-url>https://mcvideo-server/recordings/0a1b</video-push-url></anyExt></mcvideo-Params></mcvideoinfo>)";
  const auto push = parse_service_info(push_fixture, mcvideo_service);
  check(push.video_push_url == "https://mcvideo-server/recordings/0a1b", "a video push URL must parse");
  check(service_info_xml(push, mcvideo_service) == push_fixture, "a video push URL must round-trip byte for byte");
  // TS 24.281 clause 15.2.1.1 step 8 and annex F.1: an ambient viewing call names its type in
  // <ambient-viewing-type>, and its release reasons speak of the viewed-to client.
  McpttInfo viewing;
  viewing.session_type = "ambient-viewing";
  viewing.ambient_listening_type = "remote-init";
  viewing.release_reason = "call-request-initiated-by-viewed-to-client";
  const auto viewing_xml = service_info_xml(viewing, mcvideo_service);
  check(viewing_xml.find("<ambient-viewing-type>remote-init</ambient-viewing-type>") != std::string::npos &&
            viewing_xml.find("ambient-listening-type") == std::string::npos,
        "MCVideo writes <ambient-viewing-type>");
  const auto viewing_back = parse_service_info(viewing_xml, mcvideo_service);
  check(viewing_back.ambient_listening_type == "remote-init" &&
            viewing_back.release_reason == "call-request-initiated-by-viewed-to-client",
        "an ambient viewing call must round-trip");
  McpttInfo ambient_listening;
  ambient_listening.ambient_listening_type = "local-init";
  check(service_info_xml(ambient_listening, mcptt_service)
                .find("<ambient-listening-type>local-init</ambient-listening-type>") != std::string::npos,
        "MCPTT still writes <ambient-listening-type>");
  bool mixed = false;
  try {
    (void)parse_mcptt_info(video_fixture);
  } catch (const std::exception &) {
    mixed = true;
  }
  check(mixed, "an MCPTT parser must refuse MCVideo information");
  // TS 24.379 annex F.1: <mcptt-calling-group-id>, <emergency-ind> and <alert-ind> (contentType booleans).
  auto terminating_fixture = fixture;
  terminating_fixture.insert(
      terminating_fixture.find("</mcptt-Params>"),
      "<mcptt-calling-group-id type=\"Normal\"><mcpttURI>sip:rescue@example.test</mcpttURI></mcptt-calling-group-id>");
  check(mcptt_info_xml(parse_mcptt_info(terminating_fixture)).find("mcptt-calling-group-id") != std::string::npos,
        "terminating invitation must preserve calling group separately from target user");
  auto emergency_fixture = fixture;
  emergency_fixture.insert(emergency_fixture.find("</mcptt-Params>"),
                           "<emergency-ind type=\"Normal\"><mcpttBoolean>true</mcpttBoolean></emergency-ind><alert-ind "
                           "type=\"Normal\"><mcpttBoolean>false</mcpttBoolean></alert-ind>");
  check(mcptt_info_xml(parse_mcptt_info(emergency_fixture)).find("<mcpttBoolean>true</mcpttBoolean>") !=
            std::string::npos,
        "emergency call indication must survive parsing");
  auto priority_info = parse_mcptt_info(emergency_fixture);
  check(priority_info.emergency == true && priority_info.alert == false && !priority_info.imminent_peril,
        "false and absent priority flags must be distinct");
  priority_info.emergency = false;
  priority_info.originated_by = "sip:originator@example.test";
  priority_info.alert_received = true;
  priority_info.emergency_received = true;
  auto priority_copy = parse_mcptt_info(mcptt_info_xml(priority_info));
  check(priority_copy.emergency == false && priority_copy.alert_received == true &&
            priority_copy.emergency_received == true && priority_copy.originated_by == priority_info.originated_by,
        "priority cancellation state lost");
  for (const auto *value : {"TRUE", "yes", "", "<x>true</x>"}) {
    auto bad = fixture;
    bad.insert(bad.find("</mcptt-Params>"), "<emergency-ind>" + std::string(value) + "</emergency-ind>");
    rejects([&] { parse_mcptt_info(bad); });
  }
  for (const auto *protection : {"Encrypted", "unsupported"}) {
    auto bad = emergency_fixture;
    auto flag_type = bad.find("type=\"Normal\"", bad.find("<emergency-ind"));
    bad.replace(flag_type, 13, "type=\"" + std::string(protection) + "\"");
    rejects([&] { parse_mcptt_info(bad); });
  }
  auto conflicting_wrapper = emergency_fixture;
  conflicting_wrapper.insert(conflicting_wrapper.find("</emergency-ind>"), "<mcpttString>false</mcpttString>");
  rejects([&] { parse_mcptt_info(conflicting_wrapper); });
  auto duplicate = emergency_fixture;
  duplicate.insert(duplicate.find("</mcptt-Params>"), "<emergency-ind>false</emergency-ind>");
  rejects([&] { parse_mcptt_info(duplicate); });
  auto info = parse_mcptt_info(fixture);
  check(info.request_uri == "sip:rescue@example.test", "group identity parsed incorrectly");
  check(info.client_id == "urn:uuid:client-a", "client identity parsed incorrectly");
  check(info.session_type == "prearranged", "call type parsed incorrectly");
  info.access_token = "header.payload.signature";
  auto encoded = mcptt_info_xml(info);
  check(encoded.find("<mcpttURI>sip:rescue@example.test</mcpttURI>") != std::string::npos, "URI wrapper missing");
  check(parse_mcptt_info(encoded).access_token == info.access_token, "token lost");
  {
    // A DTD with an external entity in front of an otherwise valid <mcpttinfo>: refused for the DTD alone.
    auto with_dtd = encoded;
    with_dtd.insert(with_dtd.find("<mcpttinfo"), "<!DOCTYPE mcpttinfo [<!ENTITY a SYSTEM 'file:///etc/passwd'>]>");
    rejects([&] { parse_mcptt_info(with_dtd); });
  }
  rejects([&] { parse_mcptt_info("<mcpttinfo xmlns='evil'><mcptt-Params/></mcpttinfo>"); });
  rejects([&] {
    parse_mcptt_info("<mcpttinfo "
                     "xmlns='urn:3gpp:ns:mcpttInfo:1.0'><mcptt-Params><session-"
                     "type>a</session-type><session-type>b</session-type></"
                     "mcptt-Params></mcpttinfo>");
  });
  {
    // A well-formed <mcpttinfo> above the 64 KiB body limit, refused for its size.
    auto oversized = info;
    oversized.participant_criteria = std::string(70000, 'x');
    auto large = encoded;
    large.insert(large.find("</mcptt-Params>"), "<anyExt><call-participants-criterias>" + std::string(70000, 'x') +
                                                    "</call-participants-criterias></anyExt>");
    rejects([&] { parse_mcptt_info(large); });
    rejects([&] { (void)mcptt_info_xml(oversized); });
  }
  // TS 24.379 clause 9.3.1.2: the affiliation PIDF, <affiliation> elements and the <p-id> of the publication.
  auto affiliation = parse_affiliation(
      R"(<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:mc="urn:3gpp:ns:mcpttPresInfo:1.0" entity="sip:medic@example.test"><tuple id="urn:uuid:client-a"><status><mc:affiliation group="sip:rescue@example.test"/></status></tuple><mc:p-id>unique-publication</mc:p-id></presence>)");
  check(affiliation.user_id == "sip:medic@example.test", "PIDF entity lost");
  check(affiliation.groups.size() == 1 && affiliation.groups[0] == "sip:rescue@example.test", "PIDF group lost");
  check(parse_affiliation(affiliation_xml(affiliation, false)).client_id == "urn:uuid:client-a", "PIDF tuple lost");
  {
    // TS 24.281 clause 8.3.1.2: MCVideo affiliation in urn:3gpp:ns:mcvideoPresInfo:1.0.
    Affiliation video{"sip:alice.mcvideo@mcx.test", "urn:uuid:client-a", "pid", {"sip:operations@mcx.test"}, {}};
    video.mcvideo = true;
    const auto xml = affiliation_xml(video, true);
    check(xml.find("xmlns:mc=\"urn:3gpp:ns:mcvideoPresInfo:1.0\"") != std::string::npos,
          "MCVideo affiliation namespace");
    const auto back = parse_affiliation(xml);
    check(back.mcvideo && !back.mcdata && back.groups == video.groups && back.publication_id == "pid" &&
              back.statuses == std::vector<std::string>{"affiliated"},
          "MCVideo affiliation round trip");
    check(!parse_affiliation(affiliation_xml(affiliation, false)).mcvideo, "MCPTT affiliation is not MCVideo");
    // Without groups, the p-id still names the service (a de-affiliation from every
    // group, or a participating server's peer registration before any affiliation).
    Affiliation none{"sip:alice.mcvideo@mcx.test", "urn:uuid:client-a", "pid", {}, {}};
    none.mcvideo = true;
    const auto empty = parse_affiliation(affiliation_xml(none, false));
    check(empty.mcvideo && !empty.mcdata && empty.groups.empty() && empty.publication_id == "pid",
          "MCVideo affiliation without groups keeps its service");
    none.mcvideo = false;
    none.mcdata = true;
    check(parse_affiliation(affiliation_xml(none, false)).mcdata,
          "MCData affiliation without groups keeps its service");
    none.mcdata = false;
    const auto plain = parse_affiliation(affiliation_xml(none, false));
    check(!plain.mcvideo && !plain.mcdata && plain.publication_id == "pid", "MCPTT affiliation without groups");
    auto mixed = xml;
    mixed.insert(mixed.find("</status>"),
                 "<mp:affiliation xmlns:mp=\"urn:3gpp:ns:mcpttPresInfo:1.0\" group=\"sip:x@mcx.test\"/>");
    rejects([&] { parse_affiliation(mixed); });
    // TS 24.379 clause 9.3.1.2: a notification has one <tuple> per client of the user: the client reads its own,
    // and none of its own is no group; a request has the one tuple of its client. No count limit on groups.
    const std::string two =
        R"(<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:mc="urn:3gpp:ns:mcpttPresInfo:1.0" entity="sip:a@x">)"
        R"(<tuple id="urn:uuid:phone"><status><mc:affiliation group="sip:g1@x" status="affiliated"/></status></tuple>)"
        R"(<tuple id="urn:uuid:tablet"><status><mc:affiliation group="sip:g2@x" status="affiliating"/>)"
        R"(<mc:affiliation group="sip:g3@x"/></status></tuple></presence>)";
    const auto tablet = parse_affiliation(two, "urn:uuid:tablet");
    check(tablet.client_id == "urn:uuid:tablet" &&
              tablet.groups == std::vector<std::string>{"sip:g2@x", "sip:g3@x"} &&
              tablet.statuses == std::vector<std::string>{"affiliating", ""},
          "the client's own tuple of a notification");
    const auto other = parse_affiliation(two, "urn:uuid:laptop");
    check(other.client_id == "urn:uuid:laptop" && other.groups.empty(), "no tuple of the client: no group");
    rejects([&] { parse_affiliation(two); });
    std::string many = R"(<presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:mc="urn:3gpp:ns:mcpttPresInfo:1.0" )"
                       R"(entity="sip:a@x"><tuple id="urn:uuid:phone"><status>)";
    for (int index = 0; index < 100; ++index)
      many += "<mc:affiliation group=\"sip:g" + std::to_string(index) + "@x\"/>";
    many += "</status></tuple></presence>";
    check(parse_affiliation(many).groups.size() == 100, "100 groups read");
    auto both = video;
    both.mcdata = true;
    rejects([&] { (void)affiliation_xml(both, false); });
  }

  // TS 24.379 clause 6.2.1 and TS 24.380 clause 12.1.2.3: the SDP offer with the "mc_priority" and "mc_floor_ssrc"
  // fmtp attributes (TS 24.380 clauses 14.2.3 and 14.2.7).
  const std::string sdp = "v=0\r\no=- 123 1 IN IP4 192.0.2.1\r\ns=MCPTT\r\nc=IN IP4 "
                          "192.0.2.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP "
                          "110\r\ni=speech\r\na=rtpmap:110 AMR-WB/16000/1\r\na=fmtp:110 "
                          "octet-align=0\r\na=rtcp:4001\r\nm=application 5000 udp "
                          "MCPTT\r\na=fmtp:MCPTT mc_floor_ssrc=12345\r\n";
  auto priority_sdp = sdp;
  priority_sdp.insert(priority_sdp.find("mc_floor_ssrc="), "mc_priority=12;");
  auto negotiated = parse_sdp(priority_sdp);
  check(negotiated.floor_priority == 12, "negotiated floor priority lost");
  check(parse_sdp(make_sdp(negotiated, 456)).floor_priority == 12, "floor priority SDP round trip lost");
  for (const auto *parameters :
       {"mc_priority=100;", "mc_priority=-1;", "mc_priority=;", "mc_priority=1;mc_priority=2;"}) {
    auto bad = sdp;
    bad.insert(bad.find("mc_floor_ssrc="), parameters);
    rejects([&] { parse_sdp(bad); });
  }
  auto media = parse_sdp(sdp);
  check(!media.floor_priority, "missing floor priority must remain absent");
  check(media.audio_port == 4000 && media.floor_port == 5000, "SDP ports lost");
  check(media.payload_type == 110 && media.floor_ssrc == 12345, "negotiated identifiers lost");
  check(!media.octet_aligned && !media.queueing, "implicit unsupported capability");
  check(parse_sdp(make_sdp(media, 789)).payload_type == 110, "generated SDP changed PT");
  // TS 24.379 clause 11.1.1.2.1.1 step 11 and RFC 4567: the PCK travels in a=key-mgmt.
  auto keyed = media;
  keyed.protected_media = true;
  keyed.key_mgmt = "AQIDBAUG";
  const auto keyed_sdp = make_sdp(keyed, 791);
  check(keyed_sdp.find("a=key-mgmt:mikey AQIDBAUG\r\n") != std::string::npos, "key-mgmt attribute missing");
  check(parse_sdp(keyed_sdp).key_mgmt == "AQIDBAUG", "key-mgmt SDP round trip lost");
  check(parse_sdp(make_sdp(media, 792)).key_mgmt.empty(), "clear SDP gained key management");
  {
    auto clear_keyed = keyed;
    clear_keyed.protected_media = false;
    rejects([&] { make_sdp(clear_keyed, 793); });
    auto bad = keyed_sdp;
    bad.replace(bad.find("RTP/SAVP"), 8, "RTP/AVP");
    rejects([&] { parse_sdp(bad); });
    for (const auto *value : {"a=key-mgmt:mikey AQID*AUG", "a=key-mgmt:kerberos AQIDBAUG", "a=key-mgmt:mikey AQIDBA"}) {
      auto wrong = keyed_sdp;
      wrong.replace(wrong.find("a=key-mgmt:mikey AQIDBAUG"), 25, value);
      rejects([&] { parse_sdp(wrong); });
    }
  }
  // TS 24.379 clause 6.2.1 step 2 c: ambient listening offers carry sendonly or recvonly.
  check(media.direction == "sendrecv", "absent direction must default to sendrecv");
  auto listening = media;
  listening.direction = "recvonly";
  listening.implicit_request = true;
  const auto listening_sdp = make_sdp(listening, 790);
  check(listening_sdp.find("a=recvonly\r\n") != std::string::npos &&
            listening_sdp.find("a=sendrecv") == std::string::npos,
        "direction not encoded");
  check(parse_sdp(listening_sdp).direction == "recvonly" && parse_sdp(listening_sdp).implicit_request,
        "direction or implicit request lost");
  listening.direction = "both";
  rejects([&] { (void)make_sdp(listening, 791); });
  {
    // TS 24.380 clauses 14.2.5, 14.3.5 and 14.3.6: an offer's "mc_implicit_request" and the "mc_ssrc" an answer
    // returns for it; clause 14.4: the offerer reads "mc_ssrc" (an MCVideo answer names it "mc_audio_ssrc").
    auto implicit = media;
    implicit.implicit_request = true;
    implicit.granted_audio_ssrc = 4242;
    const auto implicit_sdp = make_sdp(implicit, 794);
    check(implicit_sdp.find("a=fmtp:MCPTT mc_floor_ssrc=12345;mc_implicit_request;mc_ssrc=4242\r\n") !=
                  std::string::npos &&
              implicit_sdp.find("mc_audio_ssrc") == std::string::npos,
          "implicit floor request or mc_ssrc not encoded");
    const auto read = parse_sdp(implicit_sdp);
    check(read.implicit_request && read.granted_audio_ssrc == 4242, "implicit floor request or mc_ssrc lost");
    auto offer = sdp;
    offer.replace(offer.find("mc_floor_ssrc=12345"), 19, "mc_floor_ssrc=12345;mc_implicit_request");
    check(parse_sdp(offer).implicit_request && !parse_sdp(offer).granted_audio_ssrc, "implicit offer misread");
    auto bad = sdp;
    bad.replace(bad.find("mc_floor_ssrc=12345"), 19, "mc_floor_ssrc=12345;mc_ssrc=x");
    rejects([&] { parse_sdp(bad); });
    auto granted = media;
    granted.granted = true; // no MCPTT "mc_granted" is written (optional: TS 24.380 clauses 14.2.4 and 14.3.4)
    rejects([&] { (void)make_sdp(granted, 795); });
  }
  auto malformed_rtcp = sdp;
  malformed_rtcp.replace(malformed_rtcp.find("a=rtcp:4001"), 11, "a=rtcp:");
  rejects([&] { parse_sdp(malformed_rtcp); });
  auto wrong = sdp;
  wrong.replace(wrong.find("AMR-WB/16000/1"), 14, "PCMU/8000/1");
  rejects([&] { parse_sdp(wrong); });
  wrong = sdp;
  wrong.replace(wrong.find("audio 4000"), 10, "audio 99999");
  rejects([&] { parse_sdp(wrong); });
  wrong = sdp;
  wrong += "m=audio 4444 RTP/AVP 110\r\n";
  rejects([&] { parse_sdp(wrong); });
  // RFC 4566 section 5: "v=" comes first.
  wrong = sdp;
  wrong.erase(0, 5);
  wrong.insert(wrong.find("s=MCPTT"), "v=0\r\n");
  rejects([&] { parse_sdp(wrong); });
  rejects([&] { parse_sdp("o=- 1 1 IN IP4 192.0.2.1\r\n" + sdp); });
  // RFC 4566 section 6: "a=fmtp" is a media-level attribute.
  wrong = sdp;
  wrong.insert(wrong.find("m=audio"), "a=fmtp:110 octet-align=1\r\n");
  rejects([&] { parse_sdp(wrong); });
  // RFC 3264 section 8.4: an inactive stream is read and written back.
  {
    auto held = sdp;
    held.insert(held.find("a=rtcp:4001"), "a=inactive\r\n");
    const auto inactive = parse_sdp(held);
    check(inactive.direction == "inactive", "inactive direction lost");
    check(parse_sdp(make_sdp(inactive, 794)).direction == "inactive", "inactive SDP round trip lost");
  }

  {
    // An MCPTT offer stays exactly what it was before MCVideo (TS 24.379 clause 6.2.1).
    MediaDescription ptt;
    ptt.address = ptt.floor_address = "192.0.2.1";
    ptt.audio_port = 4000;
    ptt.rtcp_port = 4001;
    ptt.floor_port = 5000;
    ptt.floor_ssrc = 12345;
    ptt.audio_ssrc = 777;
    ptt.queueing = true;
    check(make_sdp(ptt, 1) ==
              "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=MCPTT\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n"
              "m=audio 4000 RTP/AVP 96\r\ni=speech\r\na=rtpmap:96 AMR-WB/16000/1\r\n"
              "a=fmtp:96 octet-align=0;mode-change-capability=2;max-red=0\r\na=ptime:20\r\na=maxptime:240\r\na=sendrecv\r\n"
              "a=rtcp:4001\r\na=ssrc:777 cname:mcptt\r\nm=application 5000 udp MCPTT\r\n"
              "a=fmtp:MCPTT mc_floor_ssrc=12345;mc_queueing\r\n",
          "MCPTT SDP changed");
    // TS 24.281 clause 6.2.1 and TS 24.581 clause 12.1.2: audio, H.264 video and "udp MCVideo".
    MediaDescription mcv = ptt;
    mcv.control = MediaControl::transmission;
    VideoMedia video_media;
    video_media.port = 4002;
    video_media.rtcp_port = 4003;
    video_media.ssrc = 888;
    mcv.video = video_media;
    mcv.implicit_request = true;
    mcv.granted = true;
    const auto video_sdp = make_sdp(mcv, 2);
    check(video_sdp ==
              "v=0\r\no=- 2 1 IN IP4 192.0.2.1\r\ns=MCVideo\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n"
              "m=audio 4000 RTP/AVP 96\r\ni=audio component of MCVideo\r\na=rtpmap:96 AMR-WB/16000/1\r\n"
              "a=fmtp:96 octet-align=0;mode-change-capability=2;max-red=0\r\na=ptime:20\r\na=maxptime:240\r\na=sendrecv\r\n"
              "a=rtcp:4001\r\na=ssrc:777 cname:mcvideo\r\n"
              "m=video 4002 RTP/AVP 97\r\ni=video component of MCVideo\r\na=rtpmap:97 H264/90000\r\n"
              "a=fmtp:97 profile-level-id=42e01f;packetization-mode=1\r\na=sendrecv\r\na=rtcp:4003\r\n"
              "a=ssrc:888 cname:mcvideo\r\nm=application 5000 udp MCVideo\r\n"
              "a=fmtp:MCVideo mc_transmission_ssrc=12345;mc_queueing;mc_implicit_request;mc_granted\r\n",
          "MCVideo SDP layout");
    const auto back = parse_sdp(video_sdp);
    check(back.control == MediaControl::transmission && back.video && back.video->port == 4002 &&
              back.video->rtcp_port == 4003 && back.video->payload_type == 97 &&
              back.video->profile_level_id == "42e01f" && back.video->packetization_mode == 1 &&
              back.floor_ssrc == 12345 && back.granted && back.implicit_request && back.queueing,
          "MCVideo SDP round trip");
    // TS 24.581 clause 12.1.2.3 (table 12.1.2.3-1) writes the parameters with COLON between them.
    auto colon = video_sdp;
    colon.replace(colon.find("mc_transmission_ssrc=12345;mc_queueing"), 38, "mc_transmission_ssrc=12345:mc_queueing");
    check(parse_sdp(colon).queueing, "colon-separated MCVideo parameters");
    auto answer = mcv;
    answer.granted_audio_ssrc = 5;
    answer.granted_video_ssrc = 6;
    const auto answered = parse_sdp(make_sdp(answer, 3));
    check(answered.granted_audio_ssrc == 5 && answered.granted_video_ssrc == 6, "granted SSRCs round trip");
    // Video in an MCPTT call, MCVideo without video, another codec: all refused.
    auto in_mcptt = video_sdp;
    in_mcptt.replace(in_mcptt.find("udp MCVideo"), 11, "udp MCPTT")
        .replace(in_mcptt.find("a=fmtp:MCVideo mc_transmission_ssrc"), 35, "a=fmtp:MCPTT mc_floor_ssrc");
    rejects([&] { parse_sdp(in_mcptt); });
    auto no_video = video_sdp;
    no_video.erase(no_video.find("m=video"), no_video.find("m=application") - no_video.find("m=video"));
    rejects([&] { parse_sdp(no_video); });
    auto vp8 = video_sdp;
    vp8.replace(vp8.find("H264/90000"), 10, "VP8/90000");
    rejects([&] { parse_sdp(vp8); });
    auto ptt_video = ptt;
    ptt_video.video = video_media;
    rejects([&] { (void)make_sdp(ptt_video, 4); });
    auto clash = mcv;
    clash.video->port = 5000;
    rejects([&] { (void)make_sdp(clash, 5); });
    check(back.video->ssrc == 888, "video SSRC round trip");
    // TS 24.281 clause 10.2.3: a private call without transmission control has no m=application.
    auto open = mcv;
    open.control = MediaControl::none;
    open.implicit_request = open.granted = open.queueing = false;
    const auto open_sdp = make_sdp(open, 6);
    check(open_sdp.find("m=application") == std::string::npos && open_sdp.find("m=video") != std::string::npos,
          "no transmission control section");
    const auto open_back = parse_sdp(open_sdp);
    check(open_back.control == MediaControl::none && open_back.video && open_back.video->ssrc == 888,
          "MCVideo without transmission control round trip");
    auto open_queue = open;
    open_queue.queueing = true;
    rejects([&] { (void)make_sdp(open_queue, 7); });
    // TS 24.379 clause 11.1.2: an MCPTT private call without floor control has speech only.
    auto ptt_open = ptt;
    ptt_open.control = MediaControl::none;
    rejects([&] { (void)make_sdp(ptt_open, 8); }); // mc_queueing needs floor control
    ptt_open.queueing = false;
    const auto ptt_open_sdp = make_sdp(ptt_open, 8);
    check(ptt_open_sdp.find("m=application") == std::string::npos &&
              ptt_open_sdp.find("s=MCPTT") != std::string::npos &&
              ptt_open_sdp.find("a=ssrc:777 cname:mcptt") != std::string::npos,
          "MCPTT SDP without floor control");
    const auto ptt_open_back = parse_sdp(ptt_open_sdp);
    check(ptt_open_back.control == MediaControl::none && !ptt_open_back.video && ptt_open_back.audio_ssrc == 777 &&
              !ptt_open_back.floor_port && !ptt_open_back.floor_ssrc,
          "MCPTT without floor control round trip");
    auto no_floor = make_sdp(ptt, 9);
    no_floor.erase(no_floor.find("m=application"));
    check(parse_sdp(no_floor).control == MediaControl::none, "an SDP without m=application has no floor control");
    auto ptt_video_open = ptt_open;
    ptt_video_open.video = mcv.video;
    check(make_sdp(ptt_video_open, 10).find("s=MCVideo") != std::string::npos, "video without control is MCVideo");
    auto conflicting = ptt_open_sdp + "a=ssrc:778 cname:mcptt\r\n";
    rejects([&] { parse_sdp(conflicting); });
    // The port overlaps make_sdp refuses are refused when read: the video RTCP port (RFC 3605) on the control or
    // the audio RTP port, the video RTP port on the audio RTCP port.
    for (const auto &[from, to] : std::vector<std::pair<std::string, std::string>>{
             {"a=rtcp:4003", "a=rtcp:5000"}, {"a=rtcp:4003", "a=rtcp:4000"}, {"m=video 4002", "m=video 4001"}}) {
      auto overlapping = video_sdp;
      overlapping.replace(overlapping.find(from), from.size(), to);
      rejects([&] { parse_sdp(overlapping); });
    }
  }
  // RFC 2046 section 5.1: the multipart/mixed body of the INVITE (mcptt-info and SDP).
  std::vector<BodyPart> parts{{"application/vnd.3gpp.mcptt-info+xml", fixture}, {"application/sdp", sdp}};
  auto multi = multipart_body(parts, "fixture-boundary");
  auto decoded = parse_body_parts("multipart/mixed; boundary=\"fixture-boundary\"", multi);
  check(decoded.size() == 2 && decoded[1].body == sdp, "multipart body changed");
  // RFC 3261 section 7.4: one part travels as it is, several as multipart/mixed.
  const auto single = message_body({parts.front()}, "fixture-boundary");
  const auto several = message_body(parts, "fixture-boundary");
  check(single.first == parts.front().content_type && single.second == fixture &&
            several.first == "multipart/mixed; boundary=fixture-boundary" && several.second == multi,
        "message body of one or several parts");
  // RFC 2046 section 5.1.1 and RFC 2045 section 5.1: the boundary loses its quotes only when it has both (the IS
  // proxy rebuilds a body with it).
  check(multipart_boundary("multipart/mixed; boundary=\"fixture-boundary\"") == "fixture-boundary" &&
            multipart_boundary("multipart/mixed;Boundary=abc;x=1") == "abc" &&
            multipart_boundary("multipart/mixed; charset=x; boundary=a-b_c") == "a-b_c",
        "MIME boundary not read");
  for (const auto *type :
       {"multipart/mixed; boundary=\"abc", "multipart/mixed; boundary=abc\"", "multipart/mixed; boundary=\"\"",
        "multipart/mixed", "multipart/mixed; boundary=a; boundary=b"})
    rejects([&] { (void)multipart_boundary(type); });
  rejects([&] {
    parse_body_parts("multipart/mixed; boundary=x", "--x\r\nContent-Type: application/sdp\r\n\r\nmissing-end");
  });
  rejects([&] { multipart_body(parts, "x\r\nInjected: yes"); });
  // TS 24.379 annex F.1: <broadcast-ind> and <associated-group-id>.
  McpttInfo broadcast_info;
  broadcast_info.session_type = "prearranged";
  broadcast_info.request_uri = "sip:group@mcx.test";
  broadcast_info.broadcast = true;
  const auto broadcast_xml = mcptt_info_xml(broadcast_info);
  check(broadcast_xml.find("<broadcast-ind>true</broadcast-ind>") != std::string::npos, "broadcast-ind not encoded");
  check(parse_mcptt_info(broadcast_xml).broadcast == true, "broadcast-ind lost");
  broadcast_info.associated_group = "sip:subordinate@mcx.test";
  const auto associated_xml = mcptt_info_xml(broadcast_info);
  check(associated_xml.find(
            "</broadcast-ind><associated-group-id type=\"Normal\"><mcpttURI>sip:subordinate@mcx.test</mcpttURI>") !=
            std::string::npos,
        "associated-group-id not encoded in schema order");
  // TS 24.379 clause 6.3.3.1.12 and annex F.1: <mc-org>, an xs:string between <broadcast-ind> and
  // <associated-group-id>.
  broadcast_info.organization = "Alpha <Fire>";
  const auto organization_xml = mcptt_info_xml(broadcast_info);
  check(organization_xml.find("</broadcast-ind><mc-org>Alpha &lt;Fire&gt;</mc-org><associated-group-id") !=
            std::string::npos,
        "mc-org not encoded in schema order");
  check(parse_mcptt_info(organization_xml).organization == "Alpha <Fire>", "mc-org lost");
  check(parse_mcptt_info(associated_xml).associated_group == "sip:subordinate@mcx.test", "associated-group-id lost");
  {
    // TS 24.281 annex F.1: the MCVideo <associated-group-id> is an xs:string (plain text, not <mcvideoURI>); it is
    // read plain or wrapped, in <mcvideo-Params> or in <anyExt> (TS 24.281 clause 9.2.1.2.1.1 step 14 d) i)).
    McpttInfo video;
    video.session_type = "prearranged";
    video.request_uri = "sip:regroup@mcx.test";
    video.associated_group = "sip:constituent@mcx.test";
    const auto video_xml = service_info_xml(video, mcvideo_service);
    check(video_xml.find("<associated-group-id>sip:constituent@mcx.test</associated-group-id>") != std::string::npos,
          "MCVideo associated-group-id must be plain text");
    check(parse_service_info(video_xml, mcvideo_service).associated_group == video.associated_group,
          "MCVideo associated-group-id lost");
    auto wrapped_xml = video_xml;
    wrapped_xml.replace(wrapped_xml.find("sip:constituent@mcx.test"), 24,
                        "<mcvideoURI>sip:constituent@mcx.test</mcvideoURI>");
    check(parse_service_info(wrapped_xml, mcvideo_service).associated_group == video.associated_group,
          "a wrapped MCVideo associated-group-id must be read");
    auto in_ext = video_xml;
    const auto element = std::string("<associated-group-id>sip:constituent@mcx.test</associated-group-id>");
    in_ext.erase(in_ext.find(element), element.size());
    in_ext.replace(in_ext.find("</mcvideo-Params>"), 17, "<anyExt>" + element + "</anyExt></mcvideo-Params>");
    check(parse_service_info(in_ext, mcvideo_service).associated_group == video.associated_group,
          "an MCVideo associated-group-id in <anyExt> must be read");
  }
  broadcast_info.associated_group.clear();
  broadcast_info.broadcast.reset();
  check(!parse_mcptt_info(mcptt_info_xml(broadcast_info)).broadcast, "absent broadcast-ind must mean non-broadcast");
  // TS 24.379 clause 11.1.1.4.2 steps 5 and 8 a (first-to-answer): <mcptt-called-party-id> in the 200 OK and the
  // BYE <anyExt><release-reason>.
  McpttInfo answered;
  answered.session_type = "first-to-answer";
  answered.calling_user = "sip:alice@mcx.test";
  answered.called_party = "sip:bob@mcx.test";
  const auto answered_xml = mcptt_info_xml(answered);
  check(answered_xml.find(
            "<mcptt-called-party-id type=\"Normal\"><mcpttURI>sip:bob@mcx.test</mcpttURI></mcptt-called-party-id>") !=
            std::string::npos,
        "called party not encoded");
  check(answered_xml.find("</mcptt-calling-user-id><mcptt-called-party-id ") != std::string::npos,
        "called party out of schema order");
  const auto answered_copy = parse_mcptt_info(answered_xml);
  check(answered_copy.called_party == answered.called_party && answered_copy.session_type == "first-to-answer",
        "called party lost");
  McpttInfo released;
  released.release_reason = "not selected for call";
  const auto released_xml = mcptt_info_xml(released);
  check(released_xml.find("<anyExt><release-reason>not selected for call</release-reason></anyExt></mcptt-Params>") !=
            std::string::npos,
        "release reason not encoded in anyExt");
  check(parse_mcptt_info(released_xml).release_reason == "not selected for call", "release reason lost");
  check(parse_mcptt_info(mcptt_info_xml(answered)).release_reason.empty(), "absent release reason invented");
  released.release_reason = "because";
  rejects([&] { (void)mcptt_info_xml(released); });
  auto bad_reason = released_xml;
  bad_reason.replace(bad_reason.find("not selected for call"), 21, "not selected");
  rejects([&] { (void)parse_mcptt_info(bad_reason); });
  // TS 24.379 annex F.1: the ambient listening type precedes the release reason in <anyExt> (schema order).
  McpttInfo ambient;
  ambient.session_type = "ambient-listening";
  ambient.ambient_listening_type = "remote-init";
  ambient.release_reason = "private-call-expiry";
  const auto ambient_xml = mcptt_info_xml(ambient);
  check(ambient_xml.find("<session-type>ambient-listening</session-type>") != std::string::npos &&
            ambient_xml.find("<anyExt><ambient-listening-type>remote-init</"
                             "ambient-listening-type><release-reason>private-call-expiry</release-reason></anyExt>") !=
                std::string::npos,
        "ambient listening type not encoded");
  const auto ambient_copy = parse_mcptt_info(ambient_xml);
  check(ambient_copy.ambient_listening_type == "remote-init" && ambient_copy.release_reason == "private-call-expiry",
        "ambient listening type lost");
  ambient.ambient_listening_type = "remote";
  rejects([&] { (void)mcptt_info_xml(ambient); });
  auto bad_ambient = ambient_xml;
  bad_ambient.replace(bad_ambient.find(">remote-init<"), 13, ">nearby-init<");
  rejects([&] { (void)parse_mcptt_info(bad_ambient); });
  // TS 24.379 annex F.1: the ad hoc priority indicators live in <anyExt> as plain booleans.
  McpttInfo adhoc;
  adhoc.session_type = "adhoc";
  adhoc.adhoc_emergency = true;
  adhoc.adhoc_alert = false;
  const auto adhoc_xml = mcptt_info_xml(adhoc);
  check(
      adhoc_xml.find(
          "<anyExt><adhoc-emergency-ind>true</adhoc-emergency-ind><adhoc-alert-ind>false</adhoc-alert-ind></anyExt>") !=
          std::string::npos,
      "ad hoc indicators not encoded");
  const auto adhoc_copy = parse_mcptt_info(adhoc_xml);
  check(adhoc_copy.adhoc_emergency == true && adhoc_copy.adhoc_alert == false &&
            !adhoc_copy.adhoc_emergency_alert_group,
        "ad hoc indicators lost");
  adhoc.adhoc_alert_received = true;
  adhoc.adhoc_emergency_alert_group = true;
  check(parse_mcptt_info(mcptt_info_xml(adhoc)).adhoc_alert_received == true &&
            parse_mcptt_info(mcptt_info_xml(adhoc)).adhoc_emergency_alert_group == true,
        "ad hoc alert flags lost");
  adhoc.adhoc_alert_received.reset();
  adhoc.adhoc_emergency_alert_group.reset();
  adhoc.participant_criteria = "affiliated:sip:team@mcx.test";
  check(parse_mcptt_info(mcptt_info_xml(adhoc)).participant_criteria == "affiliated:sip:team@mcx.test",
        "criteria lost");
  check(mcptt_info_xml(adhoc).find("<anyExt><call-participants-criterias>") != std::string::npos,
        "criteria not in anyExt");
  auto bad_adhoc = adhoc_xml;
  bad_adhoc.replace(bad_adhoc.find(">true<"), 6, ">yes<");
  rejects([&] { (void)parse_mcptt_info(bad_adhoc); });
  // TS 24.484 clause 8.3.2.1 item 11: the rights of the profile <ruleset>, as served by the CMS.
  const std::string profile_head =
      "<mcptt-user-profile xmlns=\"urn:3gpp:mcptt:user-profile:1.0\" XUI-URI=\"sip:a@x\" user-profile-index=\"1\">"
      "<Status>true</Status><cp:ruleset xmlns:cp=\"urn:ietf:params:xml:ns:common-policy\"><cp:rule "
      "id=\"r\"><cp:actions>";
  const std::string profile_tail = "</cp:actions></cp:rule></cp:ruleset></mcptt-user-profile>";
  const auto actions = parse_profile_actions(
      profile_head +
      "<allow-private-call>true</allow-private-call><allow-force-auto-answer>false</allow-force-auto-answer>"
      "<allow-transmit-data xmlns=\"urn:3gpp:ns:mcdata:user-profile:1.0\"> 1 </allow-transmit-data>"
      "<anyExt><allow-call-transfer>true</allow-call-transfer><allow-call-forward-manual-input>true</"
      "allow-call-forward-manual-input></anyExt>"
      "<other xmlns=\"urn:x\">true</other>" +
      profile_tail);
  check(actions == std::set<std::string>({"allow-private-call", "allow-transmit-data", "allow-call-transfer",
                                          "allow-call-forward-manual-input", "allow-call-fwd-manual-any"}),
        "profile actions not parsed");
  check(parse_profile_actions("<mcptt-user-profile xmlns=\"urn:3gpp:mcptt:user-profile:1.0\"/>").empty(),
        "absent ruleset grants actions");
  rejects([&] { (void)parse_profile_actions("<profile xmlns=\"urn:x\"/>"); });
  rejects([&] {
    (void)parse_profile_actions(profile_head + "<allow-private-call>yes</allow-private-call>" + profile_tail);
  });
  // TS 26.179 clause 4.1.3: the AMR-WB format offers max-red 0, ptime 20, maxptime 240 and no mode-set; a peer's
  // mode-set (RFC 4867 section 8.1) is read and limits the mode sent.
  {
    MediaDescription offer;
    offer.address = offer.floor_address = "192.0.2.1";
    offer.audio_port = 4000;
    offer.rtcp_port = 4001;
    offer.floor_port = 5000;
    offer.floor_ssrc = 12345;
    const auto sdp = make_sdp(offer, 1);
    check(sdp.find(";mode-change-capability=2;max-red=0") != std::string::npos && sdp.find("a=maxptime:240") != std::string::npos &&
              sdp.find("mode-set") == std::string::npos,
          "AMR-WB offer per TS 26.179");
    auto remote = parse_sdp(std::string(sdp).replace(sdp.find("max-red=0"), 9, "max-red=0;mode-set=0,1,2"));
    check(remote.mode_set == std::vector<std::uint8_t>{0, 1, 2}, "mode-set parsed");
    check(amr_wb_send_mode(2, remote.mode_set) == 2 && amr_wb_send_mode(8, remote.mode_set) == 2 &&
              amr_wb_send_mode(0, {}) == 0 && amr_wb_send_mode(1, {4, 6}) == 4,
          "send mode within the mode-set");
    rejects([&] { (void)parse_sdp(std::string(sdp).replace(sdp.find("max-red=0"), 9, "mode-set=9")); });
  }
  // TS 24.484 clauses 8.4.2.1 and 10.4.2.1: the resource priorities of the service configuration documents, RFC 8101
  // namespaces only; MCData's in the <anyExt> of <on-network>.
  {
    const auto rp = [](const char *element, const char *space, const char *level) {
      return std::string("<") + element + "><resource-priority-namespace>" + space +
             "</resource-priority-namespace><resource-priority-priority>" + level + "</resource-priority-priority></" +
             element + ">";
    };
    const auto three = rp("emergency-resource-priority", "mcpttp", "15") +
                       rp("imminent-peril-resource-priority", "mcpttp", "10") +
                       rp("normal-resource-priority", "mcpttq", "0");
    const auto mcptt = parse_service_resource_priorities(
        "<service-configuration-info xmlns=\"urn:3gpp:ns:mcpttServiceConfig:1.0\"><service-configuration-params "
        "domain=\"x\"><on-network>" + three + "</on-network></service-configuration-params></service-configuration-info>");
    check(mcptt.at("emergency") == "mcpttp.15" && mcptt.at("imminent") == "mcpttp.10" && mcptt.at("normal") == "mcpttq.0",
          "MCPTT service configuration resource priorities");
    const auto mcdata = parse_service_resource_priorities(
        "<service-configuration-info xmlns=\"urn:3gpp:ns:mcdataServiceConfig:1.0\"><service-configuration-params "
        "domain=\"x\"><on-network><anyExt>" + three + "</anyExt></on-network></service-configuration-params>"
        "</service-configuration-info>");
    check(mcdata.at("emergency") == "mcpttp.15", "MCData service configuration resource priorities");
    for (const auto *bad : {"mcptt", "mcpttp.16"})
      rejects([&] {
        const std::string space = std::string(bad) == "mcptt" ? "mcptt" : "mcpttp";
        const std::string level = std::string(bad) == "mcptt" ? "15" : "16";
        (void)parse_service_resource_priorities(
            "<service-configuration-info xmlns=\"urn:3gpp:ns:mcpttServiceConfig:1.0\"><service-configuration-params "
            "domain=\"x\"><on-network>" + rp("emergency-resource-priority", space.c_str(), level.c_str()) +
            rp("imminent-peril-resource-priority", "mcpttp", "10") + rp("normal-resource-priority", "mcpttp", "0") +
            "</on-network></service-configuration-params></service-configuration-info>");
      });
  }
  // TS 24.484 clause 7.2.2.1 item 4: the <GMS-URI> of the UE initial configuration (TS 24.483 clause 8.2.9).
  {
    const auto initial = [](const std::string &on_network) {
      return "<mcptt-UE-initial-configuration xmlns=\"urn:3gpp:mcptt:mcpttUEinitConfig:1.0\" domain=\"x\"><on-network>" +
             on_network + "</on-network></mcptt-UE-initial-configuration>";
    };
    check(parse_initial_gms_uri(initial("<GMS-XCAP-root-URI>https://gms</GMS-XCAP-root-URI><GMS-URI>"
                                        "sip:gms-proxy@x</GMS-URI>")) == "sip:gms-proxy@x",
          "GMS-URI of the UE initial configuration");
    rejects([&] { (void)parse_initial_gms_uri(initial("")); });
    rejects([&] { (void)parse_initial_gms_uri(initial("<GMS-URI></GMS-URI>")); });
  }
  // TS 24.379 clauses 6.6.2.3 and 6.6.3.3, TS 24.484 clauses 8.4.2.1, 9.4.2.1 and 10.4.2.1: the signalling protection
  // of a service configuration document; an absent element (or parent) means enabled, only "false" disables.
  {
    const auto document = [](const char *ns, const std::string &on_network) {
      return std::string("<service-configuration-info xmlns=\"urn:3gpp:ns:") + ns +
             "ServiceConfig:1.0\"><service-configuration-params domain=\"x\"><on-network>" + on_network +
             "</on-network></service-configuration-params></service-configuration-info>";
    };
    const auto absent = parse_service_protection(document("mcptt", ""));
    check(absent.confidentiality && absent.integrity && absent.between_servers && absent.between_servers_control,
          "absent protection elements: enabled");
    const auto off = parse_service_protection(document(
        "mcptt", "<signalling-protection><confidentiality-protection>false</confidentiality-protection>"
                 "<integrity-protection>0</integrity-protection></signalling-protection>"
                 "<protection-between-mcptt-servers><allow-signalling-protection>false</allow-signalling-protection>"
                 "</protection-between-mcptt-servers>"));
    check(!off.confidentiality && !off.integrity && !off.between_servers && off.between_servers_control,
          "MCPTT protection disabled by false, floor control between servers still enabled when absent");
    const auto video = parse_service_protection(document(
        "mcvideo", "<signalling-protection><integrity-protection>true</integrity-protection></signalling-protection>"
                   "<protection-between-mcvideo-servers><allow-transmission-control-protection>false"
                   "</allow-transmission-control-protection></protection-between-mcvideo-servers>"));
    check(video.confidentiality && video.integrity && video.between_servers && !video.between_servers_control,
          "MCVideo transmission control protection between servers");
    const auto data = parse_service_protection(
        document("mcdata", "<signalling-protection><confidentiality-protection>false</confidentiality-protection>"
                           "</signalling-protection><protection-between-mcdata-servers/>"));
    check(!data.confidentiality && data.integrity && data.between_servers && data.between_servers_control,
          "MCData protection");
    // Another service's element is not this document's: ignored, so the default applies.
    check(parse_service_protection(document("mcdata", "<protection-between-mcptt-servers><allow-signalling-protection>"
                                                      "false</allow-signalling-protection>"
                                                      "</protection-between-mcptt-servers>"))
              .between_servers,
          "another service's element ignored");
    rejects([&] {
      (void)parse_service_protection(document(
          "mcptt", "<signalling-protection><integrity-protection>yes</integrity-protection></signalling-protection>"));
    });
    rejects(
        [&] { (void)parse_service_protection(document("mcptt", "<signalling-protection/><signalling-protection/>")); });
  }
  // TS 24.481 clauses 7.2.2 and 7.2.8: <preconfigured-group-use-only> of the group document (TS 24.379
  // clause 10.1.5.2.1 step 1A).
  const std::string group_doc =
      "<group xmlns=\"urn:oma:xml:poc:list-service\" xmlns:gi=\"urn:3gpp:ns:mcpttGroupInfo:1.0\">"
      "<list-service uri=\"sip:g@x\"><list><entry uri=\"sip:a@x\"/></list>";
  const std::string group_end = "</list-service></group>";
  check(group_preconfigured_use_only(
            group_doc + "<gi:preconfigured-group-use-only>true</gi:preconfigured-group-use-only>" + group_end),
        "preconfigured-group-use-only lost");
  check(!group_preconfigured_use_only(group_doc + group_end) &&
            !group_preconfigured_use_only(
                group_doc + "<gi:preconfigured-group-use-only>false</gi:preconfigured-group-use-only>" + group_end),
        "absent or false preconfigured-group-use-only restricts the group");
  rejects([&] {
    (void)group_preconfigured_use_only(
        group_doc + "<gi:preconfigured-group-use-only>yes</gi:preconfigured-group-use-only>" + group_end);
  });
  rejects([&] { (void)group_preconfigured_use_only("<list-service xmlns=\"urn:oma:xml:xdm:group-list\"/>"); });
  // TS 24.282 clause 14.2.1 and TS 24.481 clause 7.2.8: enhanced status, the allow flag and the <status> entries
  // by <id>.
  const auto value = [](const char *id, const char *text) {
    return std::string("<gi:status><gi:id>") + id + "</gi:id><gi:shortText><gi:langType>en</gi:langType><gi:langText>" +
           text + "</gi:langText></gi:shortText><gi:description><gi:langType>en</gi:langType><gi:langText>" + text +
           "</gi:langText></gi:description></gi:status>";
  };
  const auto status =
      group_enhanced_status(group_doc +
                            "<gi:mcdata-allow-enhanced-status>true</"
                            "gi:mcdata-allow-enhanced-status><gi:mcdata-enhanced-status-operational-values>" +
                            value("1", "On scene") + value("2", "En route &amp; ready") +
                            "</gi:mcdata-enhanced-status-operational-values>" + group_end);
  check(status.allowed && status.values.size() == 2 &&
            status.values[0] == std::pair<std::string, std::string>{"1", "On scene"} &&
            status.values[1].second == "En route & ready",
        "enhanced status values");
  check(!group_enhanced_status(group_doc + group_end).allowed, "absent enhanced status allowed");
  rejects([&] {
    (void)group_enhanced_status(group_doc + "<gi:mcdata-allow-enhanced-status>maybe</gi:mcdata-allow-enhanced-status>" +
                                group_end);
  });
  rejects([&] {
    (void)group_enhanced_status(group_doc + "<gi:mcdata-enhanced-status-operational-values>" + value("1", "a") +
                                value("1", "b") + "</gi:mcdata-enhanced-status-operational-values>" + group_end);
  });
  rejects([&] {
    (void)group_enhanced_status(group_doc + "<gi:mcdata-enhanced-status-operational-values>" + value("x", "a") +
                                "</gi:mcdata-enhanced-status-operational-values>" + group_end);
  });
  // TS 24.379 clauses 11.1.5 to 11.1.9 and annex F.1: the private call service elements.
  McpttInfo callback;
  callback.service = {{"request-type", "private-call-call-back-request"},
                      {"urgency-ind", "high"},
                      {"time-of-request", "2026-09-22T10:00:00Z"}};
  const auto callback_xml = mcptt_info_xml(callback);
  check(
      callback_xml.find("<request-type>private-call-call-back-request</request-type><urgency-ind>high</urgency-ind>") !=
          std::string::npos,
      "service elements not in schema order");
  check(parse_mcptt_info(callback_xml).service == callback.service, "service elements lost");
  callback.service["urgency-ind"] = "urgent";
  rejects([&] { (void)mcptt_info_xml(callback); });
  callback.service = {{"made-up", "x"}};
  rejects([&] { (void)mcptt_info_xml(callback); });
  callback.service = {{"forwarding-target-id", "not a uri"}};
  rejects([&] { (void)mcptt_info_xml(callback); });
  auto bad_service = callback_xml;
  bad_service.replace(bad_service.find(">high<"), 6, ">soon<");
  rejects([&] { (void)parse_mcptt_info(bad_service); });
  // TS 24.379 clause 10.1.5.2.1 step 3 d ii D: <ric-app-level-priority>, an RFC 8101 namespace.priority.
  McpttInfo ric;
  ric.service = {{"request-type", "remotely-initiated-group-call-request"},
                 {"notify-remote-user", "true"},
                 {"ric-app-level-priority", "mcptt.5"}};
  const auto ric_xml = mcptt_info_xml(ric);
  check(ric_xml.find(
            "<notify-remote-user>true</notify-remote-user><ric-app-level-priority>mcptt.5</ric-app-level-priority>") !=
            std::string::npos,
        "ric-app-level-priority not in schema order");
  check(parse_mcptt_info(ric_xml).service == ric.service, "ric-app-level-priority lost");
  for (const auto *bad : {"mcptt", "mcptt.", ".5", "mcptt.x", "mc ptt.5", "mcptt.5,mcptt.6"}) {
    ric.service["ric-app-level-priority"] = bad;
    rejects([&] { (void)mcptt_info_xml(ric); });
  }
  // TS 24.379 clause 9A.2.1.3 step 2 b) and annex F.1.3: the functional alias status determination is a
  // <request-type> value; the users of an alias are asked for with <req-type> (step 2a b)).
  McpttInfo status_request;
  status_request.service = {{"request-type", "functional-alias-status-determination"}};
  check(mcptt_info_xml(status_request).find("<request-type>functional-alias-status-determination</request-type>") !=
            std::string::npos,
        "functional alias status determination not in <request-type>");
  check(parse_mcptt_info(mcptt_info_xml(status_request)).service == status_request.service,
        "functional alias status determination lost");
  status_request.service = {{"req-type", "fa-user-status-determination"}};
  check(parse_mcptt_info(mcptt_info_xml(status_request)).service == status_request.service,
        "functional alias user status determination lost");
  // TS 24.379 clauses 11.1.8.2.3 and 11.1.8.2.1: announced transfer, <transfer-announced-ind> and
  // <replaces-header-value>.
  McpttInfo announced;
  announced.service = {{"transfer-announced-ind", "true"}};
  check(parse_mcptt_info(mcptt_info_xml(announced)).service == announced.service, "transfer-announced-ind lost");
  announced.service = {{"request-type", "transfer-private-call-request"},
                       {"replaces-header-value", "abc@h;to-tag=1;from-tag=2"}};
  check(parse_mcptt_info(mcptt_info_xml(announced)).service == announced.service, "replaces-header-value lost");
  for (const auto *bad : {"abc@h", ";to-tag=1;from-tag=2", "abc@h;to-tag=1", "abc@h;to-tag=1;from-tag=2\r\nX: y"}) {
    announced.service["replaces-header-value"] = bad;
    rejects([&] { (void)mcptt_info_xml(announced); });
  }
  // TS 24.379 clause 11.1.1.3.2 step 4a b iii: <PrivateCallKMSURI> of a forwarding.
  McpttInfo moved;
  moved.service = {{"request-type", "forward-private-call-request"}, {"forwarding-reason", "manual-input"}};
  moved.private_call_kms_uri = "https://kms.other.example";
  const auto moved_xml = mcptt_info_xml(moved);
  check(moved_xml.find("<PrivateCallKMSURI><PrivateCallKMSURI><uri-entry>https://kms.other.example</uri-entry>") !=
            std::string::npos,
        "PrivateCallKMSURI not nested");
  check(parse_mcptt_info(moved_xml).private_call_kms_uri == moved.private_call_kms_uri, "PrivateCallKMSURI lost");
  moved.private_call_kms_uri = "not a uri";
  rejects([&] { (void)mcptt_info_xml(moved); });
  // RFC 2046 section 5.1.1: the CRLF PJSIP writes before the first delimiter.
  check(parse_body_parts("multipart/mixed; boundary=b", "\r\n--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n")
                .size() == 1,
        "multipart body with a leading CRLF");
  // TS 24.379 annex F.1: the functional alias elements of <mcpttinfo>.
  McpttInfo aliased;
  aliased.session_type = "private";
  aliased.functional_alias = "sip:dispatcher@mcx.test";
  aliased.call_to_functional_alias = true;
  aliased.called_functional_alias = "sip:medic@mcx.test";
  const auto aliased_copy = parse_mcptt_info(mcptt_info_xml(aliased));
  check(aliased_copy.functional_alias == "sip:dispatcher@mcx.test" && aliased_copy.call_to_functional_alias == true &&
            aliased_copy.called_functional_alias == "sip:medic@mcx.test",
        "functional alias elements lost");
  // Both are contentType (TS 24.379 annex F.1.2): the URI in <mcpttURI>, or <mcvideoURI> for MCVideo. A bare
  // URI, as this codec sent before, still parses.
  const auto aliased_xml = mcptt_info_xml(aliased);
  const std::string wrapped_alias =
      "<functional-alias-URI type=\"Normal\"><mcpttURI>sip:dispatcher@mcx.test</mcpttURI></functional-alias-URI>";
  check(aliased_xml.find(wrapped_alias) != std::string::npos &&
            aliased_xml.find("<called-functional-alias-URI type=\"Normal\"><mcpttURI>sip:medic@mcx.test</mcpttURI>") !=
                std::string::npos,
        "functional alias URIs not in contentType form");
  check(service_info_xml(aliased, mcvideo_service)
                .find("<called-functional-alias-URI type=\"Normal\"><mcvideoURI>sip:medic@mcx.test") !=
            std::string::npos,
        "MCVideo functional alias URI not in contentType form");
  auto bare_alias = aliased_xml;
  bare_alias.replace(bare_alias.find(wrapped_alias), wrapped_alias.size(),
                     "<functional-alias-URI>sip:dispatcher@mcx.test</functional-alias-URI>");
  check(parse_mcptt_info(bare_alias).functional_alias == "sip:dispatcher@mcx.test",
        "bare functional alias URI refused");
  aliased.functional_alias = "sip:a\"b@mcx.test";
  rejects([&] { (void)mcptt_info_xml(aliased); });
  // TS 24.379 clause 9A.3.1.2: the functional alias PIDF request.
  FunctionalAliasRequest fa{
      "sip:alice@mcx.test", "urn:uuid:1", "p1", {"sip:dispatcher@mcx.test", "sip:medic@mcx.test"}, true};
  const auto fa_xml = functional_alias_xml(fa);
  check(is_functional_alias_pidf(fa_xml) &&
            !is_functional_alias_pidf(affiliation_xml({"sip:alice@mcx.test", "c", "p", {}, {}}, false)),
        "functional alias PIDF not recognised");
  const auto fa_copy = parse_functional_alias(fa_xml);
  check(fa_copy.user_id == fa.user_id && fa_copy.client_id == fa.client_id && fa_copy.publish_id == "p1" &&
            fa_copy.aliases == fa.aliases && fa_copy.take_over,
        "functional alias request lost");
  {
    // The namespaces are read from the parsed document: a namespace URI in a comment or an attribute value is not a
    // namespace of the document.
    auto affiliation = affiliation_xml({"sip:alice@mcx.test", "c", "p", {}, {}}, false);
    affiliation.insert(affiliation.find("<presence"), "<!-- urn:3gpp:ns:mcpttPresInfoFA:1.0 -->");
    check(!is_functional_alias_pidf(affiliation), "a namespace URI in a comment taken for a functional alias PIDF");
    auto mentioned = fa_xml;
    mentioned.replace(mentioned.find("urn:uuid:1"), 10, "urn:3gpp:ns:mcdataPresInfoFA:1.0");
    const auto mentioned_copy = parse_functional_alias(mentioned);
    check(!mentioned_copy.mcdata && !mentioned_copy.mcvideo, "a namespace URI in an attribute value counted");
    // A request without aliases declares its namespace on the root and has no element in it.
    FunctionalAliasRequest empty{"sip:alice@mcx.test", "urn:uuid:1", {}, {}, false};
    empty.mcdata = true;
    const auto empty_xml = functional_alias_xml(empty);
    check(is_functional_alias_pidf(empty_xml) && parse_functional_alias(empty_xml).mcdata,
          "declared functional alias namespace not recognised");
  }
  auto bad_fa = fa_xml;
  bad_fa.replace(bad_fa.find(">true<"), 6, ">maybe<");
  rejects([&] { (void)parse_functional_alias(bad_fa); });
  // TS 24.281 clause 20.3.1.2: the MCVideo request in its own namespace, which excludes the others.
  auto video_fa = fa;
  video_fa.mcvideo = true;
  const auto video_fa_xml = functional_alias_xml(video_fa);
  check(video_fa_xml.find("urn:3gpp:ns:mcvideoPresInfoFA:1.0") != std::string::npos &&
            is_functional_alias_pidf(video_fa_xml),
        "MCVideo functional alias namespace missing");
  const auto video_fa_copy = parse_functional_alias(video_fa_xml);
  check(video_fa_copy.mcvideo && !video_fa_copy.mcdata && video_fa_copy.aliases == fa.aliases &&
            video_fa_copy.take_over,
        "MCVideo functional alias request lost");
  auto mixed_fa = video_fa_xml;
  mixed_fa.replace(mixed_fa.find("<tuple"), 0, "<x xmlns=\"urn:3gpp:ns:mcpttPresInfoFA:1.0\"/>");
  rejects([&] { (void)parse_functional_alias(mixed_fa); });
  video_fa.mcdata = true;
  rejects([&] { (void)functional_alias_xml(video_fa); });
  // TS 24.379 clause 9A.3.1.2 and TS 24.281 clause 20.3.1.2: the per-user and per-functional alias status of a
  // NOTIFY.
  FunctionalAliasStatus per_user{
      "sip:alice@mcx.test",
      "urn:uuid:1",
      "p1",
      false,
      {{"sip:dispatcher@mcx.test", "", "activated", ""}, {"sip:medic@mcx.test", "", "take-over-possible", ""}}};
  per_user.mcvideo = true;
  const auto per_user_copy = parse_functional_alias_status(functional_alias_status_xml(per_user));
  check(per_user_copy.mcvideo && !per_user_copy.per_alias && per_user_copy.entity == per_user.entity &&
            per_user_copy.tuple_id == "urn:uuid:1" && per_user_copy.publish_id == "p1" &&
            per_user_copy.entries.size() == 2 && per_user_copy.entries[1].alias == "sip:medic@mcx.test" &&
            per_user_copy.entries[1].status == "take-over-possible",
        "per-user functional alias status lost");
  FunctionalAliasStatus per_alias{"sip:dispatcher@mcx.test",
                                  "sip:dispatcher@mcx.test",
                                  {},
                                  true,
                                  {{"", "sip:alice@mcx.test", "", ""}, {"", "sip:bob@mcx.test", "", ""}}};
  const auto per_alias_xml = functional_alias_status_xml(per_alias);
  const auto per_alias_copy = parse_functional_alias_status(per_alias_xml);
  check(!per_alias_copy.mcvideo && per_alias_copy.per_alias && per_alias_copy.entries.size() == 2 &&
            per_alias_copy.entries[1].user == "sip:bob@mcx.test" && is_functional_alias_pidf(per_alias_xml),
        "per-functional alias status lost");
  auto bad_status = per_user;
  bad_status.entries[0].status = "held";
  rejects([&] { (void)functional_alias_status_xml(bad_status); });
  auto mixed_status = per_alias_xml;
  mixed_status.replace(mixed_status.find("</status>"), 0, "<fa:functionalAlias functionalAliasID=\"sip:x@mcx.test\"/>");
  rejects([&] { (void)parse_functional_alias_status(mixed_status); });
  // TS 24.379 clauses 9A.2.2.2.6 and 9A.2.2.3.5 between MCPTT servers: the user in the tuple id, the take-over
  // request and the "expires" of an activation; a user no longer active is a document without a tuple.
  FunctionalAliasStatus onward;
  onward.entity = "sip:dispatcher@mcx.test";
  onward.tuple_id = "sip:alice@mcx.test";
  onward.per_alias = true;
  onward.publish_id = "p9";
  onward.take_over = true;
  onward.entries.push_back({"", "sip:alice@mcx.test", "activating", "2106-02-07T06:28:15Z"});
  const auto onward_copy = parse_functional_alias_status(functional_alias_status_xml(onward));
  check(onward_copy.per_alias && onward_copy.take_over && onward_copy.tuple_id == "sip:alice@mcx.test" &&
            onward_copy.entries.size() == 1 && onward_copy.entries[0].status == "activating" &&
            onward_copy.entries[0].expires == "2106-02-07T06:28:15Z",
        "functional alias status between servers lost");
  FunctionalAliasStatus inactive;
  inactive.entity = "sip:dispatcher@mcx.test";
  inactive.publish_id = "p10";
  const auto inactive_xml = functional_alias_status_xml(inactive);
  const auto inactive_copy = parse_functional_alias_status(inactive_xml);
  check(inactive_xml.find("<tuple") == std::string::npos && inactive_copy.tuple_id.empty() &&
            inactive_copy.entries.empty() && inactive_copy.publish_id == "p10",
        "functional alias status without a tuple lost");
  auto stray = inactive;
  stray.entries.push_back({"", "sip:alice@mcx.test", "", ""});
  rejects([&] { (void)functional_alias_status_xml(stray); });
  // TS 24.379 clause 9A.3.2.2: the per-user filter of a functional alias status subscription.
  const auto filter = functional_alias_filter_xml("sip:alice@mcx.test");
  check(parse_functional_alias_filter(filter) == "sip:alice@mcx.test" &&
            filter.find("urn:3gpp:ns:mcpttPresInfoFA:1.0") != std::string::npos,
        "functional alias filter lost");
  check(parse_functional_alias_filter(functional_alias_filter_xml("sip:bob@mcx.test", false, true)) ==
            "sip:bob@mcx.test",
        "MCVideo functional alias filter lost");
  rejects([&] { (void)functional_alias_filter_xml("sip:a\"@mcx.test"); });
  check(parse_functional_alias_filter("<filter-set xmlns=\"urn:ietf:params:xml:ns:simple-filter\"/>").empty(),
        "an empty filter names a user");
  // TS 24.379 clause 16 and annex F.7: group and user regroups, and a removal naming neither list.
  Regroup users_regroup{
      "create", "sip:regroup-1@mcx.test", "sip:preconf@mcx.test", {}, {"sip:alice@mcx.test", "sip:bob@mcx.test"}};
  const auto users_copy = parse_regroup(regroup_xml(users_regroup));
  check(users_copy.action == "create" && users_copy.regroup_uri == users_regroup.regroup_uri &&
            users_copy.preconfigured_group == users_regroup.preconfigured_group && users_copy.groups.empty() &&
            users_copy.users == users_regroup.users,
        "user regroup lost");
  Regroup groups_regroup{"create", "sip:regroup-2@mcx.test", "sip:preconf@mcx.test", {"sip:north@mcx.test"}, {}};
  check(parse_regroup(regroup_xml(groups_regroup)).groups == groups_regroup.groups, "group regroup lost");
  const Regroup removal{"remove", "sip:regroup-1@mcx.test", {}, {}, {}};
  const auto removal_copy = parse_regroup(regroup_xml(removal));
  check(removal_copy.action == "remove" && removal_copy.preconfigured_group.empty() && removal_copy.groups.empty() &&
            removal_copy.users.empty(),
        "bare regroup removal lost");
  rejects([&] { (void)regroup_xml({"create", "sip:regroup-3@mcx.test", "sip:preconf@mcx.test", {}, {}}); });
  rejects([&] { (void)regroup_xml({"create", "sip:regroup-3@mcx.test", {}, {}, {"sip:alice@mcx.test"}}); });
  rejects([&] {
    (void)regroup_xml(
        {"create", "sip:regroup-3@mcx.test", "sip:preconf@mcx.test", {"sip:north@mcx.test"}, {"sip:alice@mcx.test"}});
  });
  // TS 24.379 annex F.7.2: every identity of a regroup is a URI, and the document is bounded.
  rejects([&] { (void)regroup_xml({"create", "regroup 3", "sip:preconf@mcx.test", {"sip:north@mcx.test"}, {}}); });
  rejects([&] { (void)regroup_xml({"create", "sip:regroup-3@mcx.test", "sip:pre<conf", {"sip:north@mcx.test"}, {}}); });
  rejects([&] { (void)regroup_xml({"create", "sip:regroup-3@mcx.test", "sip:preconf@mcx.test", {"north"}, {}}); });
  rejects([&] { (void)regroup_xml({"create", "sip:regroup-3@mcx.test", "sip:preconf@mcx.test", {}, {"sip:a\"b"}}); });
  {
    Regroup large{"create", "sip:regroup-4@mcx.test", "sip:preconf@mcx.test", {}, {}};
    for (int index = 0; index < 20; ++index)
      large.users.push_back("sip:" + std::to_string(index) + std::string(4000, 'u') + "@mcx.test");
    rejects([&] { (void)regroup_xml(large); });
  }
  auto duplicate_user = regroup_xml(users_regroup);
  duplicate_user.replace(duplicate_user.find("sip:bob@mcx.test"), 16, "sip:alice@mcx.test");
  rejects([&] { (void)parse_regroup(duplicate_user); });
  auto bare_create = regroup_xml(removal);
  bare_create.replace(bare_create.find(">remove<"), 8, ">create<");
  rejects([&] { (void)parse_regroup(bare_create); });
  {
    // TS 24.379 clauses 6.3.2.4.1, 6.3.2.4.2 and 13.3.3.2: location elements of <anyExt>.
    McpttInfo area;
    area.request_uri = "sip:alice@example.org";
    area.associated_group = "sip:group@example.org";
    area.group_geo_area = false;
    area.emergency_alert_area = true;
    area.location_of_functional_alias = "sip:medic@example.org";
    const auto xml = mcptt_info_xml(area);
    const auto back = parse_mcptt_info(xml);
    check(back.group_geo_area == false && back.emergency_alert_area == true &&
              back.location_of_functional_alias == "sip:medic@example.org" &&
              back.associated_group == area.associated_group,
          "location indications round trip");
    check(xml.find("<location-of-functional-alias-URI type=\"Normal\"><mcpttURI>") != std::string::npos,
          "location-of-functional-alias-URI is a contentType");
  }
  {
    // TS 24.484 clause 9.3.2.1: the MCVideo user profile's identity, targets, groups and rights.
    const std::string video_profile =
        "<mcvideo-user-profile xmlns=\"urn:3gpp:ns:mcvideo:user-profile:1.0\" XUI-URI=\"sip:v@x\" "
        "user-profile-index=\"2\">"
        "<Status>true</Status><Common "
        "index=\"0\"><MCVideoUserID><uri-entry>sip:v@x</uri-entry></MCVideoUserID><PrivateCall>"
        "<PrivateCallList><PrivateCallOnNetwork><PrivateCallURI><uri-entry>sip:w@x</uri-entry></"
        "PrivateCallURI><PrivateCallKMSURI>"
        "<PrivateCallKMSURI><uri-entry>https://kms.x</uri-entry></PrivateCallKMSURI></PrivateCallKMSURI></"
        "PrivateCallOnNetwork>"
        "</PrivateCallList></PrivateCall></Common><OnNetwork "
        "index=\"0\"><MCVideoGroupInfo><MCVideo-Group-ID><uri-entry>sip:g@x"
        "</uri-entry></MCVideo-Group-ID></MCVideoGroupInfo></OnNetwork><cp:ruleset "
        "xmlns:cp=\"urn:ietf:params:xml:ns:common-policy\">"
        "<cp:rule "
        "id=\"r\"><cp:actions><allow-private-call>true</allow-private-call><anyExt><allow-adhoc-group-call>true"
        "</allow-adhoc-group-call></anyExt><allow-video-push-to-server xmlns=\"urn:openmcx:ns:userProfile:1.0\">true"
        "</allow-video-push-to-server><allow-transmit-data "
        "xmlns=\"urn:3gpp:ns:mcdata:user-profile:1.0\">true</allow-transmit-data>"
        "<allow-regroup "
        "xmlns=\"urn:3gpp:mcptt:user-profile:1.0\">true</allow-regroup></cp:actions></cp:rule></cp:ruleset>"
        "</mcvideo-user-profile>";
    const auto read = parse_mcvideo_profile(video_profile);
    check(read.user_id == "sip:v@x" && read.profile_index == 2 &&
              read.private_call_targets == std::vector<std::string>{"sip:w@x"} &&
              read.groups == std::vector<std::string>{"sip:g@x"} &&
              read.actions ==
                  std::set<std::string>({"allow-private-call", "allow-adhoc-group-call", "allow-video-push-to-server"}),
          "MCVideo user profile");
    auto other = video_profile;
    other.replace(other.find("XUI-URI=\"sip:v@x\""), 17, "XUI-URI=\"sip:o@x\"");
    rejects([&] { (void)parse_mcvideo_profile(other); });
    rejects([&] {
      (void)parse_mcvideo_profile("<mcptt-user-profile xmlns=\"urn:3gpp:mcptt:user-profile:1.0\" XUI-URI=\"sip:a@x\" "
                                  "user-profile-index=\"3\"><Status>true</Status></mcptt-user-profile>");
    });
    // TS 24.484 clause 10.3.2.1: the MCData user profile: identity, index and the MCData rights only.
    const std::string data_profile =
        "<mcdata-user-profile xmlns=\"urn:3gpp:ns:mcdata:user-profile:1.0\" XUI-URI=\"sip:d@x\" "
        "user-profile-index=\"2\"><Status>true</Status><Common index=\"0\"><MCDataUserID><uri-entry>sip:d@x"
        "</uri-entry></MCDataUserID></Common><cp:ruleset xmlns:cp=\"urn:ietf:params:xml:ns:common-policy\"><cp:rule "
        "id=\"r\"><cp:actions><allow-transmit-data>true</allow-transmit-data><allow-activate-emergency-alert>false"
        "</allow-activate-emergency-alert><anyExt><allow-takeover-functional-alias-other-user>true"
        "</allow-takeover-functional-alias-other-user></anyExt><allow-private-call "
        "xmlns=\"urn:3gpp:mcptt:user-profile:1.0\">true</allow-private-call></cp:actions></cp:rule></cp:ruleset>"
        "</mcdata-user-profile>";
    const auto data = parse_mcdata_profile(data_profile);
    check(data.user_id == "sip:d@x" && data.profile_index == 2 &&
              data.actions ==
                  std::set<std::string>({"allow-transmit-data", "allow-takeover-functional-alias-other-user"}),
          "MCData user profile");
    auto stranger = data_profile;
    stranger.replace(stranger.find("XUI-URI=\"sip:d@x\""), 17, "XUI-URI=\"sip:o@x\"");
    rejects([&] { (void)parse_mcdata_profile(stranger); });
    rejects([&] { (void)parse_mcdata_profile(video_profile); });
  }
  std::cout << "MCPTT XML, PIDF, multipart and SDP tests passed\n";
}
