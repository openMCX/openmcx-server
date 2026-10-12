//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Location information of MC service users (TS 23.280 clause 10.9): the location-info
// body of TS 24.379 annex F.3 (MCPTT), TS 24.282 annex D.4 (MCData) and TS 24.281 annex F.3 (MCVideo), the
// coordinate coding of TS 23.032, the client's reporting triggers of
// TS 24.379 clause 13.3 / TS 24.282 clause 17.3, and the participating function's store of
// TS 24.379 clause 13.2 / TS 24.282 clause 17.2.
//
// Specifications: TS 23.280 V19.10.1 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19),
// TS 24.281 V19.6.0 (Rel-19), TS 23.032.

#pragma once
#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace mcx::location {

//------------------------------------------------------------------------------
// TS 24.379 annex F.3, TS 24.282 annex D.4 and TS 24.281 annex F.3: one schema in three namespaces.
enum class Service { Mcptt, Mcdata, Mcvideo };
//------------------------------------------------------------------------------
// TS 24.379 annex F.3.4, TS 24.282 annex D.4.4, TS 24.281 annex F.3.4: the MIME type of the service's location-info
// body.
const char *mime(Service service);
//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2, TS 24.282 annex D.4.2, TS 24.281 annex F.3.2: the XML namespace of the service's schema.
const char *xml_namespace(Service service);

//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: a latitude is a sign bit and 23 bits, a longitude 24 bits in
// two's complement, each carried as the unsigned value of its three octets.
std::uint32_t encode_latitude(double degrees);
//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: the longitude code of a longitude in degrees.
std::uint32_t encode_longitude(double degrees);
//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: the latitude in degrees of a latitude code.
double decode_latitude(std::uint32_t encoded);
//------------------------------------------------------------------------------
// TS 23.032 clause 6.1: the longitude in degrees of a longitude code.
double decode_longitude(std::uint32_t encoded);
//------------------------------------------------------------------------------
// TS 23.032 clause 6.2: the uncertainty in metres that an uncertainty code K stands for.
double horizontal_uncertainty(std::uint8_t code);
//------------------------------------------------------------------------------
// TS 23.032 clause 6.4: the altitude uncertainty in metres that an uncertainty code K stands for.
double vertical_uncertainty(std::uint8_t code);
//------------------------------------------------------------------------------
// Helper: great-circle distance in metres.
double distance(double lat1, double lon1, double lat2, double lon2);

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3, TS 23.032 clause 6.1: a point of a <GeographicalArea> or a reported coordinate.
struct Point {
  std::uint32_t latitude = 0, longitude = 0;                          // TS 23.032 clause 6.1 codes
  std::optional<std::int16_t> altitude;                               // metres (TS 23.032 clause 6.3)
  std::optional<std::uint8_t> horizontal_accuracy, vertical_accuracy; // K codes (TS 23.032 clauses 6.2, 6.4)
  static Point at(double latitude, double longitude);

  double lat() const { return decode_latitude(latitude); }

  double lon() const { return decode_longitude(longitude); }

  bool operator==(const Point &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: a <GeographicalArea>: a polygon of 3 to 15 corners (TS 23.032 clause 5.4) or an
// ellipsoid arc (TS 23.032 clause 5.7). The arc is the sector within Radius metres of its centre
// between the offset angle (2N degrees clockwise from north) and the offset plus
// the included angle (2(N+1) degrees).
struct Area {
  std::vector<Point> polygon;
  std::optional<Point> center;
  std::uint32_t radius = 0;
  std::uint8_t offset_angle = 0, included_angle = 0;
  std::uint8_t inner_border = 0, outer_border = 0; // metres, 0..127
  bool operator==(const Area &) const = default;
};

//------------------------------------------------------------------------------
// Helper: signed distance in metres from the area's contour: positive inside, negative outside.
double depth(const Area &area, double lat, double lon);
//------------------------------------------------------------------------------
// Helper: whether a position is inside the area.
bool inside(const Area &area, double lat, double lon);

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the identities whose change a radio trigger follows.
enum class Dimension { Cell, NrCell, TrackingArea, TrackingArea5G, Plmn, MbmsSa, Mbsfn, Mbsfsa5G, Rat };
//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the signalling events that trigger a report.
enum class Event {
  InitialLogOn,
  GroupCallNonEmergency,
  PrivateCallNonEmergency,
  LocationConfigurationReceived,
  FunctionalAliasActivation,
  FunctionalAliasDeactivation
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: one trigger criterion of <TriggeringCriteria>, identified by its TriggerId.
struct Trigger {
  enum class Kind { AnyChange, Enter, Exit, Periodic, Distance, Signalling, AnyArea, EnterArea, ExitArea, Adaptive };
  Kind kind = Kind::Periodic;
  std::string id;
  Dimension dimension = Dimension::Cell; // AnyChange, Enter, Exit
  std::string value;                     // Enter, Exit
  std::uint64_t amount = 0;              // Periodic seconds, Distance metres
  Event event = Event::InitialLogOn;     // Signalling
  Area area;                             // EnterArea, ExitArea

  struct Adaptive {
    std::uint64_t min_period = 0, persistence = 0, additional = 1;
    std::optional<std::uint64_t> min_distance; // absent: infinity
    bool operator==(const Adaptive &) const = default;
  } adaptive;

  bool operator==(const Trigger &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: what a report carries (<NonEmergencyLocationInformation>, <EmergencyLocationInformation>).
struct Requested {
  bool serving_ecgi = false, neighbouring_ecgi = false, mbms_sa = false, mbsfn = false, coordinate = false;
  bool serving_ncgi = false, neighbouring_ncgi = false, mbsfsa = false, bearing_speed = false;
  std::uint32_t minimum_interval = 1; // seconds
  bool operator==(const Requested &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3, TS 23.280 table 10.9.2.1-1: a location reporting configuration, <Configuration>.
struct Configuration {
  bool full = true; // ConfigScope "Full" or "Update"
  std::optional<Requested> non_emergency, emergency;
  std::vector<Trigger> triggers, emergency_triggers;
  bool operator==(const Configuration &) const = default;

  // TS 23.280 table 10.9.2.1-1 NOTE 1: nothing requested and no trigger cancels reporting.
  bool cancels() const { return !non_emergency && !emergency && triggers.empty() && emergency_triggers.empty(); }
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: a <LocationFilter> of a request (TS 24.379 clause 13.2.3.2 step 7A b iv).
struct Filter {
  std::string area; // the TriggerId of an area trigger
  bool in = true;
  bool operator==(const Filter &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3, TS 23.280 clause 10.9.2.3: a location information request, <Request>.
struct Request {
  std::string id;
  bool refresh = false;
  std::optional<Filter> filter;
  bool operator==(const Request &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the <CurrentLocation> of a report.
struct Current {
  std::optional<std::string> serving_ecgi, serving_ncgi, mbms_sa, mbsfn, mbsfsa, bearing_speed;
  std::vector<std::string> neighbouring_ecgi, neighbouring_ncgi;
  std::optional<Point> coordinate;
  std::optional<std::string> timestamp, functional_alias, inter_rat;
  bool operator==(const Current &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3, TS 23.280 clause 10.9.2.2: a location information report, <Report>.
struct Report {
  std::string id; // the RequestId answered, if any
  bool emergency = false;
  std::vector<std::string> triggers;
  std::string reporting_uri; // <mcptt-reporting-uri>, <mcdata-reporting-uri> or <mcvideo-reporting-uri>
  Current location;
  bool operator==(const Report &) const = default;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2: the content of a <location-info> body.
using Content = std::variant<Configuration, Request, Report>;
//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2: the <location-info> body of the content, in the service's namespace.
std::string to_xml(const Content &content, Service service);
//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2: parses either namespace; the service found is returned through `service`.
// Encrypted content (type="Encrypted") is refused: it is opened before parsing.
// With `trigger_ids_optional`, a configuration's triggers may come without a
// TriggerId (TS 24.379 clause 13.2.2A step 7a: the participating function assigns one).
Content parse(std::string_view xml, Service *service = nullptr, bool trigger_ids_optional = false);

//------------------------------------------------------------------------------
// Helper: a configuration from JSON (server configuration and user profiles):
//   {"non_emergency": {"coordinate": true, "minimum_interval": 5}, "emergency": {...},
//    "triggers": [{"periodic": 30}, {"distance": 100}, {"event": "InitialLogOn"},
//                 {"any_change": "cell"}, {"enter": "cell", "value": "..."},
//                 {"enter_area": {"polygon": [[lat, lon], ...]}}, {"exit_area": {"arc": {...}}},
//                 {"any_area": true}, {"adaptive": {"min_period": 5, "min_distance": 50}}],
//    "emergency_triggers": [...]}
// Trigger IDs are taken from "id" or generated by `next_id`.
Configuration configuration_from_json(const nlohmann::json &json, const std::function<std::string()> &next_id);
//------------------------------------------------------------------------------
// Helper: {"polygon": [[lat, lon], ...]} or {"arc": {"center": [lat, lon], "radius": m, ...}}.
Area area_from_json(const nlohmann::json &json);
//------------------------------------------------------------------------------
// Helper: a report as JSON.
nlohmann::json to_json(const Report &report);
//------------------------------------------------------------------------------
// Helper: a configuration as JSON.
nlohmann::json to_json(const Configuration &configuration);

//------------------------------------------------------------------------------
// TS 24.379 clause 13.3, TS 24.282 clause 17.3: the MCPTT or MCData client side of location reporting. Times are
// milliseconds on a monotonic clock.
class Reporter {
public:
  // TS 24.379 clause 13.3.2.1: replace or extend the stored configuration, set the triggers and
  // start the minimumReportInterval timer.
  void configure(const Configuration &configuration, std::uint64_t now);

  bool configured() const { return configured_; }

  const Configuration &configuration() const { return configuration_; }

  void set_emergency(bool emergency) { emergency_ = emergency; }

  bool emergency() const { return emergency_; }

  // What the UE observes.
  void position(const Point &point, std::uint64_t now);
  void radio(Dimension dimension, const std::string &value, std::uint64_t now);
  void signal(Event event, std::uint64_t now);
  // TS 24.379 clause 13.3.3.1: a request is answered at once, and resets the timer.
  Report answer(const std::string &request_id, std::uint64_t now);
  // TS 24.379 clause 13.3.4.1: a report due now, once the minimumReportInterval timer allows it.
  std::optional<Report> poll(std::uint64_t now);

  std::optional<Point> last_position() const { return position_; }

  const std::set<std::string> &pending() const { return fired_; }

  bool inside_area(const std::string &trigger_id) const;

private:
  const std::vector<Trigger> &active() const;
  const Requested *requested() const;
  Report build(std::uint64_t now);

  void fire(const std::string &id) { fired_.insert(id); }

  void evaluate_areas();
  Configuration configuration_;
  bool configured_ = false, emergency_ = false;
  std::optional<Point> position_, reported_position_;
  std::map<Dimension, std::string> radio_;
  std::set<std::string> fired_;
  std::map<std::string, bool> area_state_;        // TriggerId -> inside
  std::map<std::string, std::uint64_t> periodic_; // TriggerId -> next due
  std::map<std::string, std::uint64_t> detected_; // adaptive TriggerId -> distance first exceeded
  std::uint64_t timer_until_ = 0, origin_ = 0;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 13.3.2.1: a configuration applied to a stored one, as the client applies it (ConfigScope).
Configuration apply(const Configuration &stored, const Configuration &received);
//------------------------------------------------------------------------------
// Helper: the area a TriggerId names in a configuration, if any.
const Area *find_area(const Configuration &configuration, const std::string &trigger_id);

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2, TS 24.282 clause 17.2: what a participating function keeps about the location of the users
// it serves: each user's configuration and last
// report, the requests waiting for a fresh report, and which areas each user
// is in. Times are milliseconds on a monotonic clock.
class Registry {
public:
  // Where a report answering a request goes (TS 24.379 clause 13.2.3.2 step 7A b v, clause 13.2.3.3 step 4 v).
  struct Waiter {
    std::string request_id;  // the requester's RequestId, returned as ReportID
    std::string destination; // the requesting user's URI, or the requesting server's PSI
    std::string peer;        // the requesting server, when the request came from one
    std::string requester;   // the requesting MC service ID
    std::optional<Filter> filter;
    std::uint64_t deadline = 0;
  };

  // TS 24.379 clause 13.2.2 step 10: store the configuration sent to the client.
  const Configuration &configure(const std::string &user, const Configuration &configuration);
  const Configuration *configuration(const std::string &user) const;
  // TS 24.379 clause 13.2.4.1: returns the requests this report answers.
  std::vector<Waiter> reported(const std::string &user, const Report &report, std::uint64_t now);
  const Report *last(const std::string &user) const;
  bool fresh(const std::string &user, std::uint64_t now, std::uint64_t max_age_ms) const;
  // TS 24.379 clause 13.2.3.2 step 7A b ii and iii: a request waits for the user's next report. The
  // RequestId to send the client is returned when no request to it is outstanding.
  std::optional<std::string> await(const std::string &user, Waiter waiter, std::uint64_t now, std::uint64_t wait_ms,
                                   const std::function<std::string()> &new_id);
  // Requests whose wait has ended without a report.
  std::vector<std::pair<std::string, Waiter>> expire(std::uint64_t now);
  // TS 24.379 clause 13.2.3.2 step 7A b iv: whether the user's last known position passes a LocationFilter.
  bool passes(const std::string &user, const Filter &filter) const;
  // Entry into and exit from named areas (emergency alert areas, group geographic
  // areas): the transitions of the user's last position. The first position counts
  // as an entry into every area it is inside.
  std::vector<std::pair<std::string, bool>> areas(const std::string &user, const std::map<std::string, Area> &named);
  void forget(const std::string &user);
  std::size_t waiting() const;

  // The number of users the registry keeps anything about (a configuration, a report, areas or waiters).
  std::size_t users() const { return users_.size(); }

private:
  struct Entry {
    Configuration configuration;
    bool configured = false;
    std::optional<Report> report;
    std::uint64_t reported_at = 0;
    std::string outstanding; // RequestId of this function's own request to the client
    std::vector<Waiter> waiters;
    std::map<std::string, bool> inside;
  };

  std::map<std::string, Entry> users_;
};

} // namespace mcx::location
