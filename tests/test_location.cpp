//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Location information of the MC services: the coordinate coding, the areas, the location reporting
// configuration, request and report documents, the client's report triggering and the participating
// function's registry.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19),
// TS 23.032 (not kept locally).

#include "mcx/location.hpp"

#include <cmath>
#include <iostream>
#include <stdexcept>

using namespace mcx::location;

namespace {
//------------------------------------------------------------------------------
// Fails the test with the message what when condition is false.
void check(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Checks that action throws: the input it builds or parses is refused.
template <class Action> void rejects(Action action, const std::string &what) {
  bool failed = false;
  try {
    action();
  } catch (const std::exception &) {
    failed = true;
  }
  check(failed, what + " accepted");
}

//------------------------------------------------------------------------------
// True when first and second differ by at most tolerance.
bool near(double first, double second, double tolerance) { return std::fabs(first - second) <= tolerance; }

//------------------------------------------------------------------------------
// TS 24.379 annex F.3: encodes value as a location-info document of service and parses it back,
// checking that the service (the namespace) survives.
template <class Message> Message round_trip(const Message &value, Service service) {
  Service found{};
  const auto parsed = parse(to_xml(value, service), &found);
  check(found == service, "service survives a round trip");
  return std::get<Message>(parsed);
}

//------------------------------------------------------------------------------
// A square polygon area of half-side half degrees around lat, lon.
Area square(double lat, double lon, double half) {
  Area area;
  area.polygon = {Point::at(lat - half, lon - half), Point::at(lat - half, lon + half),
                  Point::at(lat + half, lon + half), Point::at(lat + half, lon - half)};
  return area;
}

int counter = 0;

//------------------------------------------------------------------------------
// The generator of trigger IDs for configuration_from_json: "t1", "t2", ...
std::string next() { return "t" + std::to_string(++counter); }
} // namespace

//------------------------------------------------------------------------------
// TS 23.032 coordinate coding, TS 24.379 annex F.3 location documents and TS 24.379 clause 13 location
// procedures (client and participating function), with the MCData and MCVideo variants (TS 24.282, TS 24.281
// annex F.3).
int main() {
  try {
    // TS 23.032 clause 6.1: a sign bit and 23 bits of latitude, 24 bits of longitude in two's complement.
    check(encode_latitude(0) == 0 && encode_latitude(90) == 0x7fffff && encode_latitude(-45) == 0xc00000,
          "latitude coding");
    check(encode_longitude(0) == 0 && encode_longitude(90) == 0x400000 && encode_longitude(-180) == 0x800000 &&
              encode_longitude(-90) == 0xc00000 && encode_longitude(180) == 0x800000,
          "longitude coding");
    for (double lat : {48.8584, -33.8568, 0.0, 89.9999, -89.9999})
      check(near(decode_latitude(encode_latitude(lat)), lat, 90.0 / 8388608), "latitude round trip");
    for (double lon : {2.2945, 151.2153, -73.9857, 179.9999, -179.9999})
      check(near(decode_longitude(encode_longitude(lon)), lon, 360.0 / 16777216), "longitude round trip");
    rejects([] { (void)encode_latitude(90.5); }, "latitude beyond 90 degrees");
    // TS 23.032 clause 6.2 and clause 6.4: horizontal and altitude uncertainty.
    check(horizontal_uncertainty(0) == 0 && near(horizontal_uncertainty(1), 1, 1e-9) &&
              near(horizontal_uncertainty(127), 1800000, 20000),
          "horizontal uncertainty");
    check(vertical_uncertainty(0) == 0 && near(vertical_uncertainty(127), 990, 5), "vertical uncertainty");
    check(near(distance(0, 0, 0, 1), 111195, 5), "one degree of longitude on the equator");

    // TS 24.379 annex F.3.3: areas: a polygon, and ellipsoid arcs (a full disc and a sector).
    const auto box = square(48.0, 2.0, 0.01); // about 2.2 km across
    check(inside(box, 48.0, 2.0) && !inside(box, 48.02, 2.0), "point in polygon");
    check(near(depth(box, 48.0, 2.0), 744, 5), "depth at the centre of the square: the nearer east and west sides");
    check(near(depth(box, 48.0 + 0.011, 2.0), -111, 3), "depth outside the square");
    Area disc;
    disc.center = Point::at(10.0, 20.0);
    disc.radius = 1000;
    disc.included_angle = 179; // 360 degrees
    check(inside(disc, 10.0, 20.005) && !inside(disc, 10.0, 20.02), "point in disc");
    check(near(depth(disc, 10.0, 20.0), 1000, 2), "depth at the centre of the disc");
    Area sector = disc;
    sector.offset_angle = 0;
    sector.included_angle = 44; // north to east: 0 to 90 degrees
    check(inside(sector, 10.004, 20.004) && !inside(sector, 9.996, 19.996), "point in sector");

    // TS 24.379 annex F.3: configuration round trip, every trigger kind, both services.
    Configuration config;
    config.non_emergency = Requested{};
    config.non_emergency->coordinate = config.non_emergency->serving_ecgi = config.non_emergency->serving_ncgi = true;
    config.non_emergency->minimum_interval = 5;
    config.emergency = Requested{};
    config.emergency->coordinate = config.emergency->bearing_speed = true;
    config.emergency->minimum_interval = 1;
    const std::string ecgi = "001010" + std::string(28, '1'), ncgi = "001010" + std::string(36, '0');
    Trigger trigger;
    trigger = {Trigger::Kind::AnyChange, "cell", Dimension::Cell};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Enter, "cell-in", Dimension::Cell, ecgi};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Exit, "nr-out", Dimension::NrCell, ncgi};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::AnyChange, "ta", Dimension::TrackingArea};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Enter, "plmn", Dimension::Plmn, "001010"};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Enter, "sa1", Dimension::MbmsSa, "100"};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Enter, "sa2", Dimension::MbmsSa, "200"};
    config.triggers.push_back(trigger); // goes to <anyExt>
    trigger = {Trigger::Kind::AnyChange, "mbsfn", Dimension::Mbsfn};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::AnyChange, "rat", Dimension::Rat};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Exit, "ta5g", Dimension::TrackingArea5G, "00AB12"};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Periodic, "periodic"};
    trigger.amount = 30;
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Distance, "distance"};
    trigger.amount = 250;
    config.triggers.push_back(trigger);
    for (auto event : {Event::InitialLogOn, Event::GroupCallNonEmergency, Event::FunctionalAliasActivation}) {
      trigger = {Trigger::Kind::Signalling, "event-" + std::to_string(int(event))};
      trigger.event = event;
      config.triggers.push_back(trigger);
    }
    trigger = {Trigger::Kind::AnyArea, "any-area"};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::EnterArea, "enter"};
    trigger.area = box;
    trigger.area.inner_border = 20;
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::ExitArea, "exit"};
    trigger.area = sector;
    trigger.area.outer_border = 30;
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Adaptive, "adaptive"};
    trigger.adaptive = {5, 2, 10, 50};
    config.triggers.push_back(trigger);
    trigger = {Trigger::Kind::Periodic, "emergency-periodic"};
    trigger.amount = 2;
    config.emergency_triggers.push_back(trigger);
    check(round_trip(config, Service::Mcptt) == config, "MCPTT configuration round trip");
    check(round_trip(config, Service::Mcdata) == config, "MCData configuration round trip");
    const auto mcptt_xml = to_xml(config, Service::Mcptt), mcdata_xml = to_xml(config, Service::Mcdata);
    check(mcptt_xml.find("<McpttSignallingEvent>") != std::string::npos &&
              mcdata_xml.find("<McdataSignallingEvent>") != std::string::npos &&
              mcptt_xml.find("urn:3gpp:ns:mcpttLocationInfo:1.0") != std::string::npos &&
              mcdata_xml.find("urn:3gpp:ns:mcdataLocationInfo:1.0") != std::string::npos,
          "each service's names");
    // TS 24.281 annex F.3: the MCVideo namespace and <McvideoSignallingEvent>.
    const auto mcvideo_xml = to_xml(config, Service::Mcvideo);
    Service parsed_service = Service::Mcptt;
    check(round_trip(config, Service::Mcvideo) == config &&
              mcvideo_xml.find("<McvideoSignallingEvent>") != std::string::npos &&
              mcvideo_xml.find("urn:3gpp:ns:mcvideoLocationInfo:1.0") != std::string::npos &&
              (parse(mcvideo_xml, &parsed_service), parsed_service == Service::Mcvideo) &&
              std::string(mime(Service::Mcvideo)) == "application/vnd.3gpp.mcvideo-location-info+xml",
          "MCVideo configuration round trip");
    check(mcptt_xml.find("<anyExt><EmergencyTriggeringCriteria>") != std::string::npos &&
              mcptt_xml.find("<AddaptiveTrigger TriggerId=\"adaptive\">") != std::string::npos &&
              mcptt_xml.find("<anyExt><EnterSpecificMbmsSa TriggerId=\"sa2\">200</EnterSpecificMbmsSa></anyExt>") !=
                  std::string::npos,
          "extensions placed as Annex F.3 has them");
    Configuration update;
    update.full = false;
    check(to_xml(update, Service::Mcptt).find("ConfigScope=\"Update\"") != std::string::npos &&
              round_trip(update, Service::Mcptt).cancels(),
          "an update with nothing in it");

    // TS 24.379 annex F.3.2: schema limits.
    auto twice = config;
    trigger = {Trigger::Kind::Periodic, "periodic-2"};
    trigger.amount = 10;
    twice.triggers.push_back(trigger);
    rejects([&] { (void)to_xml(twice, Service::Mcptt); }, "two periodic triggers");
    auto same_id = config;
    same_id.triggers[1].id = same_id.triggers[0].id;
    rejects([&] { (void)to_xml(same_id, Service::Mcptt); }, "a TriggerId used twice");
    auto bad_cell = config;
    bad_cell.triggers[1].value = "12345";
    rejects([&] { (void)to_xml(bad_cell, Service::Mcptt); }, "a malformed ECGI");

    // TS 24.379 annex F.3: request and report.
    Request request{"req-1", true, Filter{"enter", false}};
    check(round_trip(request, Service::Mcptt) == request, "request round trip");
    check(round_trip(Request{"plain"}, Service::Mcdata) == Request{"plain"}, "plain request round trip");
    Report sent_report;
    sent_report.id = "req-1";
    sent_report.emergency = true;
    sent_report.triggers = {"cell", "periodic"};
    sent_report.reporting_uri = "sip:alice@example.org";
    sent_report.location.serving_ecgi = ecgi;
    sent_report.location.neighbouring_ecgi = {ecgi, "001010" + std::string(28, '0')};
    sent_report.location.mbms_sa = "100";
    sent_report.location.mbsfn = "7";
    sent_report.location.coordinate = Point::at(48.8584, 2.2945);
    sent_report.location.coordinate->altitude = -12;
    sent_report.location.coordinate->horizontal_accuracy = 20;
    sent_report.location.coordinate->vertical_accuracy = 30;
    sent_report.location.serving_ncgi = ncgi;
    sent_report.location.neighbouring_ncgi = {ncgi};
    sent_report.location.mbsfsa = "abcdef";
    sent_report.location.bearing_speed = "0011223344556a";
    sent_report.location.timestamp = "2026-09-25T10:00:00Z";
    sent_report.location.functional_alias = "sip:driver@example.org";
    sent_report.location.inter_rat = "LTE-MBMS-to-5G-MBS";
    check(round_trip(sent_report, Service::Mcptt) == sent_report, "MCPTT report round trip");
    check(to_xml(sent_report, Service::Mcdata).find("<mcdata-reporting-uri>") != std::string::npos &&
              round_trip(sent_report, Service::Mcdata) == sent_report,
          "MCData report round trip");
    check(to_xml(sent_report, Service::Mcvideo).find("<mcvideo-reporting-uri>") != std::string::npos &&
              round_trip(sent_report, Service::Mcvideo) == sent_report,
          "MCVideo report round trip");
    check(to_json(sent_report).at("coordinate").at("altitude") == -12, "report as JSON");

    // TS 24.379 annex F.3: parsing: unknown elements are ignored, protection must be removed first.
    const std::string ns = "urn:3gpp:ns:mcpttLocationInfo:1.0";
    const auto report = std::get<Report>(parse(
        "<location-info xmlns=\"" + ns +
        "\"><Report ReportType=\"NonEmergency\"><Unknown/><CurrentLocation>"
        "<CurrentCoordinate><longitude><threebytes>4194304</threebytes></longitude><latitude><threebytes>0</threebytes>"
        "</latitude></CurrentCoordinate></CurrentLocation></Report></location-info>"));
    check(report.location.coordinate && near(report.location.coordinate->lon(), 90, 1e-4), "tolerant parse");
    rejects(
        [&] {
          (void)parse("<location-info xmlns=\"" + ns +
                      "\"><Report ReportType=\"NonEmergency\"><CurrentLocation><CurrentCoordinate>"
                      "<longitude "
                      "type=\"Encrypted\"><EncryptedData/></longitude><latitude><threebytes>0</threebytes></latitude>"
                      "</CurrentCoordinate></CurrentLocation></Report></location-info>");
        },
        "encrypted content");
    rejects(
        [&] {
          (void)parse("<location-info xmlns=\"" + ns +
                      "\"><Request RequestId=\"a\"/><Report "
                      "ReportType=\"Emergency\"><CurrentLocation/></Report></location-info>");
        },
        "a request and a report together");
    rejects([&] { (void)parse("<location-info xmlns=\"urn:other\"><Request RequestId=\"a\"/></location-info>"); },
            "a foreign namespace");
    rejects(
        [&] {
          (void)parse("<location-info xmlns=\"" + ns +
                      "\"><Report ReportType=\"Sometimes\"><CurrentLocation/></Report></location-info>");
        },
        "an unknown ReportType");
    rejects([&] { (void)parse("<location-info xmlns=\"" + ns + "\"><Request/></location-info>"); },
            "a request without an ID");

    // JSON configuration, with generated trigger IDs.
    const auto from_json =
        configuration_from_json(nlohmann::json::parse(R"({"non_emergency": {"coordinate": true, "minimum_interval": 2},
                                  "triggers": [{"periodic": 10}, {"event": "InitialLogOn", "id": "logon"},
                                               {"enter_area": {"polygon": [[1, 1], [1, 2], [2, 2]]}},
                                               {"exit_area": {"arc": {"center": [0, 0], "radius": 100}}}]})"),
                                next);
    check(from_json.triggers.size() == 4 && from_json.triggers[0].id == "t1" && from_json.triggers[1].id == "logon" &&
              from_json.triggers[3].area.center && from_json.non_emergency->minimum_interval == 2,
          "configuration from JSON");
    rejects(
        [] {
          (void)configuration_from_json(nlohmann::json::parse(R"({"triggers": [{"periodic": 1}, {"periodic": 2}]})"),
                                        next);
        },
        "two periodic triggers from JSON");

    // TS 24.379 clause 13.3.2.1 and clause 13.3.4: the client's triggers and its minimumReportInterval timer.
    {
      Reporter rep;
      check(!rep.poll(0), "nothing without a configuration");
      rep.position(Point::at(48.0, 1.97), 0);
      const auto answered = rep.answer("r0", 0);
      check(answered.id == "r0" && answered.location.coordinate, "a request is answered without a configuration");
      rep.configure(config, 1000);
      check(!rep.poll(1000) && rep.pending().empty(), "no report before a trigger");
      rep.signal(Event::InitialLogOn, 1500);
      check(!rep.poll(1500), "the timer started by the configuration holds the report");
      const auto first = rep.poll(6000);
      check(first && first->triggers == std::vector<std::string>{"event-0"} && first->location.coordinate &&
                !first->emergency && !first->location.serving_ecgi,
            "a signalling event reported once the timer allows");
      check(!rep.poll(7000), "triggers reset after a report");
      // Area entry with a 20 m inner border: crossing the contour is not enough.
      rep.position(Point::at(48.0, 1.9901), 8000);            // outside
      rep.position(Point::at(48.0, 1.99005 + 0.00008), 9000); // just inside the contour, within the border band
      check(!rep.pending().count("enter"), "the inner border delays the entry");
      rep.position(Point::at(48.0, 2.0), 11000);
      check(rep.pending().count("enter") && rep.pending().count("any-area"), "entry and any-area change fire");
      check(rep.pending().count("distance"), "travelled distance fires after 250 m");
      const auto second = rep.poll(12000);
      check(second && second->triggers.size() == 3, "area and distance reported together");
      rep.radio(Dimension::Cell, ecgi, 12500);
      check(rep.pending().count("cell-in") && !rep.pending().count("cell"),
            "entering a cell; the first cell is no change");
      rep.radio(Dimension::NrCell, ncgi, 12600);
      rep.radio(Dimension::NrCell, "001010" + std::string(36, '1'), 12700);
      check(rep.pending().count("nr-out") && rep.pending().count("cell"), "leaving an NR cell is a cell change");
      const auto third = rep.poll(20000);
      check(third && third->location.serving_ecgi == ecgi && third->location.serving_ncgi,
            "the requested cells are reported");
      // Periodic: due 30 s after the configuration.
      check(!rep.poll(30000) && rep.poll(32000).has_value(), "the periodic report");
      // TS 24.379 clause 13.3.3.1: a request is answered at once and restarts the timer.
      rep.signal(Event::GroupCallNonEmergency, 33000);
      const auto now = rep.answer("r1", 33000);
      check(now.id == "r1" && now.triggers.size() == 1, "a request answered at once with what has fired");
      rep.signal(Event::GroupCallNonEmergency, 34000);
      check(!rep.poll(35000) && rep.poll(38000).has_value(), "the request restarted the timer");
      // Emergency: the emergency triggers and interval.
      rep.set_emergency(true);
      check(!rep.poll(41000), "the emergency periodic trigger counts from the emergency");
      const auto emergency_report = rep.poll(43000);
      check(emergency_report && emergency_report->emergency &&
                emergency_report->triggers == std::vector<std::string>{"emergency-periodic"},
            "the emergency triggers");
      rep.set_emergency(false);
      // An update adds a trigger; a full configuration with nothing cancels reporting.
      Configuration more;
      more.full = false;
      trigger = {Trigger::Kind::Signalling, "configured"};
      trigger.event = Event::LocationConfigurationReceived;
      more.triggers.push_back(trigger);
      rep.configure(more, 50000);
      check(rep.configuration().triggers.size() == config.triggers.size() + 1 && rep.pending().count("configured"),
            "an update adds to the configuration");
      rep.configure(Configuration{}, 60000);
      rep.signal(Event::InitialLogOn, 60000);
      check(!rep.configured() && !rep.poll(90000), "an empty configuration cancels reporting");
    }
    {
      // TS 24.379 annex F.3.3: an "Update" adds the elements it requests to those requested before (removing one needs
      // a "Full" configuration), and its minimumIntervalLength applies; the participating function's copy too.
      Configuration first;
      first.non_emergency = Requested{};
      first.non_emergency->coordinate = true;
      first.non_emergency->minimum_interval = 10;
      Configuration update;
      update.full = false;
      update.non_emergency = Requested{};
      update.non_emergency->serving_ecgi = true;
      update.non_emergency->minimum_interval = 5;
      Reporter rep;
      rep.configure(first, 0);
      rep.configure(update, 1000);
      const auto &held = rep.configuration().non_emergency;
      check(held && held->coordinate && held->serving_ecgi && held->minimum_interval == 5,
            "an update adds the requested elements to those requested before");
      Registry reg;
      reg.configure("dave", first);
      const auto stored = reg.configure("dave", update).non_emergency;
      check(stored && stored->coordinate && stored->serving_ecgi, "the stored configuration keeps them too");
      Configuration full = update;
      full.full = true;
      rep.configure(full, 2000);
      check(!rep.configuration().non_emergency->coordinate, "a full configuration replaces them");
    }
    {
      // TS 24.379 annex F.3.3: adaptive trigger: MinPeriod 5 s, PersistencePeriod 2 s, AdditionalTime 10 s, MinDistance 50 m.
      Reporter rep;
      Configuration adaptive;
      adaptive.non_emergency = Requested{};
      adaptive.non_emergency->coordinate = true;
      trigger = {Trigger::Kind::Adaptive, "ad"};
      trigger.adaptive = {5, 2, 10, 50};
      adaptive.triggers = {trigger};
      rep.position(Point::at(0, 0), 0);
      rep.configure(adaptive, 0);
      rep.position(Point::at(0, 0.001), 1000); // about 111 m
      check(!rep.poll(4000), "no distance report before MinPeriod");
      check(!rep.poll(5000), "the distance is first detected at MinPeriod");
      check(rep.poll(7000).has_value(), "and reported after PersistencePeriod");
      check(!rep.poll(20000), "no time-based report before 17 s");
      check(rep.poll(24000).has_value(), "a time-based report after MinPeriod + PersistencePeriod + AdditionalTime");
    }
    {
      // TS 24.379 clause 13.2: the participating function's registry.
      Registry reg;
      Configuration base;
      base.non_emergency = Requested{};
      trigger = {Trigger::Kind::EnterArea, "zone"};
      trigger.area = box;
      base.triggers = {trigger};
      reg.configure("alice", base);
      Configuration extra;
      extra.full = false;
      trigger = {Trigger::Kind::Periodic, "tick"};
      trigger.amount = 60;
      extra.triggers = {trigger};
      check(reg.configure("alice", extra).triggers.size() == 2 && find_area(*reg.configuration("alice"), "zone"),
            "an update extends the stored configuration");
      check(!reg.fresh("alice", 0, 30000) && !reg.passes("alice", Filter{"zone", true}), "nothing known yet");
      int ids = 0;
      const auto id = [&] { return "srv-" + std::to_string(++ids); };
      Registry::Waiter bob_waiter{"req-a", "sip:bob@example.org"},
          part_2_waiter{"req-b", "sip:part-2@example.org", "part-2", "carol"};
      const auto asked = reg.await("alice", bob_waiter, 1000, 3000, id);
      check(asked && *asked == "srv-1" && !reg.await("alice", part_2_waiter, 1500, 3000, id),
            "one request to the client for both waiters");
      Report in;
      in.id = "srv-1";
      in.location.coordinate = Point::at(48.0, 2.0);
      const auto answered = reg.reported("alice", in, 2000);
      check(answered.size() == 2 && answered[1].peer == "part-2" && reg.waiting() == 0,
            "the report answers both waiters");
      check(reg.fresh("alice", 2000, 30000) && !reg.fresh("alice", 40000, 30000), "freshness");
      check(reg.passes("alice", Filter{"zone", true}) && !reg.passes("alice", Filter{"zone", false}) &&
                !reg.passes("alice", Filter{"unknown", true}),
            "a LocationFilter on a configured area");
      Report no_coordinate;
      reg.reported("alice", no_coordinate, 3000);
      const auto *kept = reg.last("alice");
      check(kept != nullptr && kept->location.coordinate.has_value(), "the last coordinate is kept");
      // A report stamped ahead of the local clock is fresh, not wrapped into a great age.
      check(reg.fresh("alice", 2000, 0) && reg.fresh("alice", 2500, 30000), "a report from the future is fresh");
      (void)reg.await("alice", bob_waiter, 4000, 1000, id);
      check(reg.expire(4500).empty() && reg.expire(5000).size() == 1 && reg.waiting() == 0, "a wait expires");
      // Queries about users never heard of keep nothing: areas() makes no entry, and the entry a wait needs goes
      // when the wait ends without a report.
      const auto known = reg.users();
      check(reg.areas("nobody", {{"inner", box}}).empty() && reg.users() == known, "areas() of an unknown user");
      (void)reg.await("nobody", bob_waiter, 6000, 1000, id);
      check(reg.users() == known + 1 && reg.expire(7000).size() == 1 && reg.users() == known,
            "a wait for an unknown user leaves no entry behind");
      const std::map<std::string, Area> named{{"inner", box}, {"far", square(10, 10, 0.01)}};
      const auto first = reg.areas("alice", named);
      check(first.size() == 1 && first[0] == std::make_pair(std::string("inner"), true),
            "the first position enters its areas");
      check(reg.areas("alice", named).empty(), "no change, no transition");
      Report moved;
      moved.location.coordinate = Point::at(10.0, 10.0);
      reg.reported("alice", moved, 6000);
      const auto second = reg.areas("alice", named);
      const std::vector<std::pair<std::string, bool>> expected{{"far", true}, {"inner", false}};
      check(second == expected, "leaving one area and entering the other");
    }
    std::cout << "location tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
