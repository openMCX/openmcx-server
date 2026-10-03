// The shared location procedures of the participating function (src/server/parts/location_service.hpp) against a
// fake host, once as the MCPTT core and once as the MCData server: the requests sent, the event names and fields, the
// Warning texts and the status, including where the two have always differed (LocationTraits).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "parts/location_service.hpp"
#include "parts/message_parts.hpp"

#include <algorithm>
#include <cassert>
#include <ctime>
#include <deque>
#include <iostream>
#include <sstream>
#include <string>
using namespace mcx;

namespace {
//------------------------------------------------------------------------------
// A SIP MESSAGE request the service sent through its host.
struct Sent {
  std::string uri, type, body;
  std::vector<SipHeader> headers;
  SipResponseHandler handler;
};

//------------------------------------------------------------------------------
// The fake server: users, rights, peers and settings set by the test; what the service sends is recorded, and the
// sealing only counted.
class FakeHost final : public LocationHost {
public:
  explicit FakeHost(const ServiceProfile &service) : service_(service) {}

  Json settings = Json::object();
  std::map<std::string, Json> profiles;
  std::map<std::string, LocationUser> users; // by public user identity
  std::map<std::string, std::string> peers;  // name -> PSI
  std::map<std::string, std::vector<std::string>> groups;
  std::vector<Sent> sent;
  std::deque<std::function<void()>> tasks;
  unsigned client_seals = 0, peer_seals = 0;

  [[nodiscard]] Json location_settings() const override { return settings; }

  Json location_profile(const std::string &id) override { return profiles.at(id); }

  std::optional<LocationUser> location_user_by_id(const std::string &id) override {
    for (const auto &[sip, user] : users)
      if (user.id == id) return user;
    return std::nullopt;
  }

  std::optional<LocationUser> location_user_by_sip(const std::string &sip) override {
    const auto found = users.find(sip);
    return found == users.end() ? std::nullopt : std::optional(found->second);
  }

  void each_location_user(const std::function<void(const std::string &id, const std::string &peer)> &visit) override {
    for (const auto &[sip, user] : users) visit(user.id, user.peer);
  }

  bool location_group_member(const std::string &group, const std::string &id) override {
    const auto found = groups.find(group);
    return found != groups.end() && std::find(found->second.begin(), found->second.end(), id) != found->second.end();
  }

  std::vector<std::string> location_alias_users(const std::string & /*alias*/) override { return {}; }

  LocationInfo location_info(const SipMessage & /*message*/, const BodyPart &info_part) override {
    const auto json = Json::parse(info_part.body);
    LocationInfo info;
    info.calling_user = json.value("calling", "");
    return info;
  }

  std::vector<BodyPart> location_info_parts(const LocationInfo &info) override {
    Json json = {{"uri", info.request_uri}, {"calling", info.calling_user}, {"group", info.associated_group}};
    if (info.emergency_alert_area) json["alert_area"] = *info.emergency_alert_area;
    return {{service_.info_mime, json.dump()}};
  }

  std::vector<BodyPart> seal_for_client(const std::string & /*sip*/, std::vector<BodyPart> parts) override {
    ++client_seals;
    return parts;
  }

  std::vector<BodyPart> seal_for_peer(const std::string & /*peer*/, std::vector<BodyPart> parts) override {
    ++peer_seals;
    return parts;
  }

  [[nodiscard]] bool peer_known(const std::string &peer) const override { return peers.contains(peer); }

  [[nodiscard]] std::string peer_uri(const std::string &peer) const override { return peers.at(peer); }

  [[nodiscard]] std::vector<SipHeader> route_to(const std::string &peer,
                                                std::vector<SipHeader> headers) const override {
    headers.push_back({"Route", "<" + peers.at(peer) + ";lr>"});
    return headers;
  }

  [[nodiscard]] std::string service_uri() const override { return "sip:server@example.com"; }

  void send_message(const std::string &uri, const std::string &type, const std::string &body,
                    const std::vector<SipHeader> &headers, SipResponseHandler handler) override {
    sent.push_back({uri, type, body, headers, std::move(handler)});
  }

  void schedule(std::function<void()> task) override { tasks.push_back(std::move(task)); }

  Json common_document(const std::string & /*role*/, const std::string & /*path*/) override { return Json::object(); }

  Json introspect(const std::string & /*token*/) override { return Json::object(); }

  void publish(const std::string &uri, const std::string &type, const std::string &body,
               const std::vector<SipHeader> &headers, SipResponseHandler handler) override {
    sent.push_back({uri, type, body, headers, std::move(handler)});
  }

  void respond(const std::string & /*transaction*/, const SipResponse & /*response*/) override {}

  // Runs the tasks scheduled for after the answer.
  void run() {
    while (!tasks.empty()) {
      auto task = std::move(tasks.front());
      tasks.pop_front();
      task();
    }
  }

private:
  const ServiceProfile &service_;
};

//------------------------------------------------------------------------------
// The event lines written to stdout while it lives.
class EventLog {
public:
  EventLog() : previous_(std::cout.rdbuf(lines_.rdbuf())) {}

  ~EventLog() { std::cout.rdbuf(previous_); }

  EventLog(const EventLog &) = delete;
  EventLog &operator=(const EventLog &) = delete;

  // The last event of the kind, or null.
  Json last(const std::string &kind) const {
    Json found;
    std::istringstream input(lines_.str());
    for (std::string line; std::getline(input, line);)
      if (const auto event = Json::parse(line, nullptr, false); event.is_object() && event.value("event", "") == kind)
        found = event;
    return found;
  }

private:
  std::ostringstream lines_;
  std::streambuf *previous_;
};

//------------------------------------------------------------------------------
// The service under test with its fake host: MCPTT on the core, or MCData.
struct Fixture {
  explicit Fixture(bool mcdata)
      : profile(mcdata ? mcdata_service : mcptt_service), host(profile),
        service(host, profile, mcdata ? mcdata_location_traits : core_location_traits) {
    const auto expires = static_cast<std::int64_t>(std::time(nullptr)) + 3600;
    host.users["sip:alice@example.com"] = {"sip:alice@mcx.example", "sip:alice@example.com", "", expires};
    host.users["sip:bob@example.com"] = {"sip:bob@mcx.example", "sip:bob@example.com", "", expires};
    host.profiles["sip:alice@mcx.example"] = {{"location", {{"request", true}, {"configure", true}}}};
    host.profiles["sip:bob@mcx.example"] = Json::object();
    host.peers["remote-peer"] = "sip:server@other.org";
    host.settings = {{"peers", {{"@other.org", "remote-peer"}}}};
  }

  // A MESSAGE from a client served here, or from a peer, with these bodies.
  [[nodiscard]] static SipMessage message(const std::string &from, std::vector<BodyPart> parts) {
    SipMessage request;
    request.method = "MESSAGE";
    request.from_uri = from;
    request.request_uri = "sip:server@example.com";
    request.headers = {{"P-Asserted-Identity", "<" + from + ">"}};
    request.parts = std::move(parts);
    return request;
  }

  [[nodiscard]] BodyPart location(const location::Content &content) const {
    return {profile.location_mime, location::to_xml(content, location_namespace(profile))};
  }

  // Bob's position reported by Bob.
  std::optional<SipResponse> bob_reports(double latitude, double longitude) {
    location::Report report;
    report.location.coordinate = location::Point::at(latitude, longitude);
    return service.from_client(message("sip:bob@example.com", {location(report)}));
  }

  [[nodiscard]] std::string event(const std::string &suffix) const { return profile.event_prefix + suffix; }

  const ServiceProfile &profile;
  FakeHost host;
  LocationService service;
};

//------------------------------------------------------------------------------
// Helper: the value of the first header field with the name.
std::string header(const Sent &sent, const std::string &name) { return std::string(get_header(sent.headers, name)); }

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.2 (TS 24.282 clause 17.2.2): the configuration sent upon service authorisation, with the
// service information naming the user, the ICSI header fields, the event and the stored state; a failed request is
// reported, MCData naming what it was.
void Clause_13_2_2_ConfigurationOnAuthorisation(bool mcdata) {
  Fixture fixture(mcdata);
  fixture.host.settings["configuration"] = {{"triggers", {{{"periodic", 30}}}}};
  EventLog events;
  fixture.service.configure("sip:bob@mcx.example");
  assert(fixture.host.sent.size() == 1);
  const auto &sent = fixture.host.sent.front();
  assert(sent.uri == "sip:bob@example.com" && sent.type.starts_with("multipart/mixed; boundary=mcx-"));
  assert(header(sent, "P-Asserted-Service") == fixture.profile.icsi);
  assert(header(sent, "Accept-Contact") == icsi_accept(fixture.profile));
  const auto parts = parse_body_parts(sent.type, sent.body);
  assert(parts.size() == 2 && parts.front().content_type == fixture.profile.info_mime);
  assert(Json::parse(parts.front().body).at("uri") == "sip:bob@mcx.example");
  assert(fixture.host.client_seals == 1);
  const auto configured = events.last(fixture.event("location_configured"));
  assert(configured.at("user_id") == "sip:bob@mcx.example" && configured.at("triggers") == 1);
  const auto status = fixture.service.status();
  assert(status.at("counters").at("configured") == 1);
  assert(status.at("users").at("sip:bob@mcx.example").contains("configuration"));
  SipResponse failure;
  failure.status_code = 480;
  sent.handler(failure);
  const auto failed = events.last(fixture.event("location_message_failed"));
  assert(failed.at("status") == 480 && failed.at("user_id") == "sip:bob@mcx.example");
  assert(failed.contains("what") == mcdata);
  if (mcdata) assert(failed.at("what") == "configuration");
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 13.2.4.1 and 13.2.3.2 step 7A b iv and v (TS 24.282 clauses 17.2.4.1 and 17.2.3.2): a report is
// stored, and a request for a user with a fresh location is answered at once with a report to the requester.
void Clause_13_2_3_2_RequestAnsweredFromFreshReport(bool mcdata) {
  Fixture fixture(mcdata);
  EventLog events;
  assert(fixture.bob_reports(48.85, 2.35)->status_code == 200);
  assert(events.last(fixture.event("location_report")).at("user_id") == "sip:bob@mcx.example");
  const auto response = fixture.service.from_client(
      Fixture::message("sip:alice@example.com", {{resource_lists_mime, resource_list_xml({"sip:bob@mcx.example"})},
                                                 fixture.location(location::Request{"r1", false, std::nullopt})}));
  assert(response && response->status_code == 200);
  const auto received = events.last(fixture.event("location_request_received"));
  assert(received.at("targets") == Json::array({"sip:bob@mcx.example"}));
  fixture.host.run();
  assert(fixture.host.sent.size() == 1);
  const auto &sent = fixture.host.sent.front();
  assert(sent.uri == "sip:alice@example.com" && sent.type == fixture.profile.location_mime);
  assert(header(sent, "Accept-Contact") == feature_accept(fixture.profile));
  assert(static_cast<bool>(sent.handler) == mcdata); // MCData watches the report as any request to a client
  const auto report_sent = events.last(fixture.event("location_report_sent"));
  assert(report_sent.at("request_id") == "r1" && report_sent.at("via") == "user");
  assert(fixture.service.status().at("counters").at("reports_sent") == 1);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.4 and clause 13.2.3.2 steps 2 to 6 (TS 24.282 clause 4.9 and table 4.9.2-2): the refusals, each
// with the service's Warning code and warn-agent.
void Clause_13_2_3_2_Refusals(bool mcdata) {
  Fixture fixture(mcdata);
  const std::string agent = mcdata ? "399 mcdata \"" : "399 mcx \"";
  const auto warning = [](const std::optional<SipResponse> &response) {
    return std::string(get_header(response->headers, "Warning"));
  };
  const auto request = fixture.location(location::Request{"r1", false, std::nullopt});
  const BodyPart list{resource_lists_mime, resource_list_xml({"sip:alice@mcx.example"})};
  const auto unknown = fixture.service.from_client(Fixture::message("sip:carol@example.com", {list, request}));
  assert(unknown->status_code == 404 && warning(unknown) == agent + "141 user unknown to the participating function\"");
  const auto refused = fixture.service.from_client(Fixture::message("sip:bob@example.com", {list, request}));
  assert(refused->status_code == 403);
  assert(warning(refused) ==
         agent + (mcdata ? "245" : "193") + " user not authorized to request location information\"");
  const auto no_target = fixture.service.from_client(Fixture::message("sip:alice@example.com", {request}));
  assert(warning(no_target) == agent + (mcdata ? "244" : "192") + " invalid location request target client list\"");
  assert(fixture.service.status().at("counters").at("refused") == 3);
  assert(!fixture.service.from_client(Fixture::message("sip:alice@example.com", {list})));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A a and clause 13.2.4.2 (TS 24.282 clauses 17.2.3.2 and 17.2.4.2): a request for a
// user served by another participating function goes to it (the core forwards the received location-info body,
// MCData writes it anew and protects it), and that function's report is relayed to the requester.
void Clause_13_2_4_2_ForwardAndRelay(bool mcdata) {
  Fixture fixture(mcdata);
  EventLog events;
  const location::Request request{"r2", false, std::nullopt};
  auto received = fixture.location(request);
  received.body += "\n";
  fixture.service.from_client(Fixture::message(
      "sip:alice@example.com", {{resource_lists_mime, resource_list_xml({"sip:carol@other.org"})}, received}));
  fixture.host.run();
  assert(fixture.host.sent.size() == 1);
  const auto &forwarded = fixture.host.sent.front();
  assert(forwarded.uri == "sip:server@other.org" && header(forwarded, "Route") == "<sip:server@other.org;lr>");
  assert(header(forwarded, "P-Asserted-Identity") == "<sip:alice@example.com>");
  const auto parts = parse_body_parts(forwarded.type, forwarded.body);
  assert(parts.size() == 3 && Json::parse(parts.front().body).at("calling") == "sip:alice@mcx.example");
  const auto *location_part = part_of(parts, fixture.profile.location_mime);
  assert(location_part && location_part->body == (mcdata ? fixture.location(request).body : received.body));
  assert(fixture.host.peer_seals == 1);
  assert(events.last(fixture.event("location_forwarded")).at("server") == "remote-peer");
  location::Report report;
  report.id = "r2";
  report.reporting_uri = "sip:carol@other.org";
  const auto relayed =
      fixture.service.from_peer(Fixture::message("sip:server@other.org", {fixture.location(report)}), "remote-peer");
  assert(relayed && relayed->status_code == 200 && fixture.host.sent.size() == 2);
  assert(fixture.host.sent.back().uri == "sip:alice@example.com");
  assert(events.last(fixture.event("location_report_relayed")).at("request_id") == "r2");
  const auto status = fixture.service.status();
  assert(status.at("counters").at("forwarded") == 1 && status.at("counters").at("relayed") == 1);
  assert(status.at("forwarded") == 1);
  fixture.service.tick(monotonic_ms() + 120000);
  assert(fixture.service.status().at("forwarded") == 0);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.3 step 2 (TS 24.282 clause 17.2.3.3): a peer's request without a readable target list is
// refused with the service's Warning; one naming a user served here who shares the location is answered and served.
void Clause_13_2_3_3_PeerRequest(bool mcdata) {
  Fixture fixture(mcdata);
  EventLog events;
  const auto request = fixture.location(location::Request{"r3", false, std::nullopt});
  const auto unreadable = fixture.service.from_peer(
      Fixture::message("sip:server@other.org", {{resource_lists_mime, "<resource-lists/>"}, request}), "remote-peer");
  assert(unreadable && unreadable->status_code == 403);
  const auto no_list = fixture.service.from_peer(Fixture::message("sip:server@other.org", {request}), "remote-peer");
  assert(no_list && no_list->status_code == 403 && fixture.service.status().at("counters").at("refused") == 2);
  fixture.bob_reports(48.85, 2.35);
  const auto answered = fixture.service.from_peer(
      Fixture::message("sip:server@other.org",
                       {{fixture.profile.info_mime, Json({{"calling", "sip:dave@other.org"}}).dump()},
                        {resource_lists_mime, resource_list_xml({"sip:bob@mcx.example"})},
                        request}),
      "remote-peer");
  assert(answered && answered->status_code == 200);
  assert(events.last(fixture.event("location_peer_request")).at("requester") == "sip:dave@other.org");
  fixture.host.run();
  assert(fixture.host.sent.size() == 1 && fixture.host.sent.front().uri == "sip:server@other.org");
  assert(header(fixture.host.sent.front(), "P-Asserted-Identity") == "<sip:server@example.com>");
  assert(events.last(fixture.event("location_report_sent")).at("via") == "remote-peer");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b iv (TS 24.282 clause 17.2.3.2 step 7A-b-iv): a report the <LocationFilter>
// keeps back is not sent; the core's event names the filter's side.
void Clause_13_2_3_2_LocationFilter(bool mcdata) {
  Fixture fixture(mcdata);
  EventLog events;
  fixture.bob_reports(48.85, 2.35);
  fixture.service.from_client(Fixture::message(
      "sip:alice@example.com", {{resource_lists_mime, resource_list_xml({"sip:bob@mcx.example"})},
                                fixture.location(location::Request{"r4", false, location::Filter{"zone", true}})}));
  fixture.host.run();
  assert(fixture.host.sent.empty());
  const auto filtered = events.last(fixture.event("location_filtered"));
  assert(filtered.at("area") == "zone" && filtered.contains("in") == !mcdata);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.4.1 steps 2 and 3 with clause 6.3.2.4.1 (TS 24.282 clause 6.3.7.1.6): an entry into an
// emergency alert area is notified with the service information alone, recorded when the client answers 200.
void Clause_6_3_2_4_1_AlertAreaNotice(bool mcdata) {
  Fixture fixture(mcdata);
  fixture.host.settings["emergency_alert_areas"] = {{"zone", {{"polygon", {{48.0, 2.0}, {49.0, 2.0}, {49.0, 3.0}}}}}};
  EventLog events;
  fixture.bob_reports(48.9, 2.5);
  assert(fixture.host.sent.size() == 1);
  const auto &notice = fixture.host.sent.front();
  assert(notice.type == fixture.profile.info_mime && Json::parse(notice.body).at("alert_area") == true);
  std::vector<std::string> accepted;
  for (const auto &field : notice.headers)
    if (field.name == "Accept-Contact") accepted.push_back(field.value);
  assert(accepted == std::vector<std::string>({icsi_accept(fixture.profile), feature_accept(fixture.profile)}));
  SipResponse ok;
  ok.status_code = 200;
  notice.handler(ok);
  fixture.host.run();
  assert(events.last(fixture.event("location_area_notified")).at("area") == "alert:zone");
  assert(fixture.service.status().at("users").at("sip:bob@mcx.example").at("areas").at("alert:zone") == true);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.5 (TS 24.282 clause 17.2.5): requests and configurations are removed from a request relayed
// to a client; reports stay.
void Clause_13_2_5_RequestsRemoved(bool mcdata) {
  Fixture fixture(mcdata);
  location::Report report;
  report.reporting_uri = "sip:bob@mcx.example";
  const auto kept = fixture.service.without_requests(
      {{"text/plain", "x"}, fixture.location(location::Request{"r5", false, std::nullopt}), fixture.location(report)});
  assert(kept.size() == 2 && kept.back().content_type == fixture.profile.location_mime);
  assert(fixture.service.status().at("counters").at("stripped") == 1);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b iii (TS 24.282 clause 17.2.3.2): with no fresh location the client is asked,
// and a request left unanswered expires.
void Clause_13_2_3_1_RequestToClientExpires(bool mcdata) {
  Fixture fixture(mcdata);
  EventLog events;
  fixture.service.from_client(
      Fixture::message("sip:alice@example.com", {{resource_lists_mime, resource_list_xml({"sip:bob@mcx.example"})},
                                                 fixture.location(location::Request{"r6", true, std::nullopt})}));
  fixture.host.run();
  assert(fixture.host.sent.size() == 1 && fixture.host.sent.front().uri == "sip:bob@example.com");
  assert(events.last(fixture.event("location_requested")).at("user_id") == "sip:bob@mcx.example");
  assert(fixture.service.status().at("waiting") == 1);
  fixture.service.tick(monotonic_ms() + 60000);
  assert(events.last(fixture.event("location_request_unanswered")).at("request_id") == "r6");
  assert(fixture.service.status().at("counters").at("unanswered") == 1);
}
} // namespace

//------------------------------------------------------------------------------
int main() {
  for (const bool mcdata : {false, true}) {
    Clause_13_2_2_ConfigurationOnAuthorisation(mcdata);
    Clause_13_2_3_2_RequestAnsweredFromFreshReport(mcdata);
    Clause_13_2_3_2_Refusals(mcdata);
    Clause_13_2_4_2_ForwardAndRelay(mcdata);
    Clause_13_2_3_3_PeerRequest(mcdata);
    Clause_13_2_3_2_LocationFilter(mcdata);
    Clause_6_3_2_4_1_AlertAreaNotice(mcdata);
    Clause_13_2_5_RequestsRemoved(mcdata);
    Clause_13_2_3_1_RequestToClientExpires(mcdata);
  }
  std::cout << "location_service: all checks passed\n";
}
