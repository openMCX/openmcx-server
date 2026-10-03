// Location procedures of the participating function, shared by the MCPTT and MCVideo servers (TS 24.379 clause 13,
// TS 24.281 clause 18) and the MCData server (TS 24.282 clause 17.2): location reporting configuration, location
// information requests and reports, from clients served here and from other participating functions, and the
// notices of entry into and exit from emergency alert areas and group geographic areas (TS 24.379 clauses 6.3.2.4.1
// and 6.3.2.4.2, TS 24.282 clauses 6.3.7.1.6 and 6.3.7.1.7).
//
// The service owns the location state; its server is its LocationHost, called per request. Where the MCPTT and
// MCVideo core and the MCData server have always differed, LocationTraits keeps each as it was.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).
#pragma once

#include "mcx/location.hpp"
#include "mcx/protocol.hpp"
#include "mcx/runtime.hpp"
#include "mcx/service.hpp"
#include "mcx/sip.hpp"
#include "parts/counters.hpp"
#include "parts/service_host.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// A user as the location procedures see it: the MC service ID, the public user identity, the peer serving a user
// served elsewhere (empty for a user served here) and the end of its service authorisation.
struct LocationUser {
  std::string id, sip, peer;
  std::int64_t expires = 0;
};

//------------------------------------------------------------------------------
// Helper: a server's user record (McServer::User, DataServer::User) as the location procedures see it.
template <typename User> LocationUser location_user_of(const User &user) {
  return {user.id, user.sip, user.peer, user.expires};
}

//------------------------------------------------------------------------------
// The service information (mcptt-info, mcvideo-info or mcdata-info) a location procedure writes or reads: TS 24.379
// clauses 13.2.2 step 8 and 13.2.2A step 7b iii (calling user), clause 13.3.3.2 step 5 ii (functional alias), clauses
// 6.3.2.4.1 and 6.3.2.4.2 (area notices); TS 24.282 clause 17.2 and clauses 6.3.7.1.6 and 6.3.7.1.7 likewise.
struct LocationInfo {
  std::string request_uri, calling_user, associated_group, location_of_functional_alias;
  std::optional<bool> emergency_alert_area, group_geo_area;
};

//------------------------------------------------------------------------------
// Where the MCPTT and MCVideo core and the MCData server differ, kept as each has always behaved.
struct LocationTraits {
  const char *warning_agent;        // the warn-agent of the 399 Warning header field: "mcx" or "mcdata"
  bool filtered_names_side;         // "in" (the filter's side of the area) in the location_filtered event
  bool failure_names_kind;          // "what" (request, configuration, report) in location_message_failed
  bool reports_through_client;      // reports go to a requesting user served here only, as any request to a client
  bool forwards_rewritten_location; // a forwarded request carries a location-info body written anew
};

// The MCPTT and MCVideo core (McServer).
inline constexpr LocationTraits core_location_traits{"mcx", true, false, false, false};
// The MCData server (DataServer).
inline constexpr LocationTraits mcdata_location_traits{"mcdata", false, true, true, true};

//------------------------------------------------------------------------------
// What the location procedures need from their server besides ServiceHost, called per request.
class LocationHost : public virtual ServiceHost {
public:
  // The configuration's "<service>.location" section.
  [[nodiscard]] virtual Json location_settings() const = 0;
  // The user profile of a user (its "location" object holds the rights); throws when there is none.
  virtual Json location_profile(const std::string &id) = 0;
  // The served or known user with the MC service ID, or with the public user identity.
  virtual std::optional<LocationUser> location_user_by_id(const std::string &id) = 0;
  virtual std::optional<LocationUser> location_user_by_sip(const std::string &sip) = 0;
  // Every user the server knows, served here (empty peer) or elsewhere.
  virtual void each_location_user(const std::function<void(const std::string &id, const std::string &peer)> &visit) = 0;
  // Whether the user is a member of the group; false for a group that cannot be read.
  virtual bool location_group_member(const std::string &group, const std::string &id) = 0;
  // The users that activated a functional alias.
  virtual std::vector<std::string> location_alias_users(const std::string &alias) = 0;
  // The service information of a request, from its service information body part.
  virtual LocationInfo location_info(const SipMessage &message, const BodyPart &info_part) = 0;
  // The service information body part(s) to send.
  virtual std::vector<BodyPart> location_info_parts(const LocationInfo &info) = 0;
};

//------------------------------------------------------------------------------
// Helper: the location-info namespace of a service (TS 24.379 annex F.3, TS 24.281 annex F.3, TS 24.282 annex D.4).
location::Service location_namespace(const ServiceProfile &service);

//------------------------------------------------------------------------------
// The location procedures of the participating function and their state.
class LocationService {
public:
  LocationService(LocationHost &host, const ServiceProfile &service, const LocationTraits &traits);

  // TS 24.379 clause 13.2.2, TS 24.282 clause 17.2.2: the configuration sent upon service authorisation.
  void configure(const std::string &id);
  // A request from a client served here, or from another participating function; std::nullopt when it is not a
  // location procedure.
  std::optional<SipResponse> from_client(const SipMessage &message);
  std::optional<SipResponse> from_peer(const SipMessage &message, const std::string &peer);
  // TS 24.379 clause 13.2.5, TS 24.282 clause 17.2.5: the bodies of a request relayed to a client, without location
  // requests and configurations.
  std::vector<BodyPart> without_requests(std::vector<BodyPart> parts);
  void tick(std::uint64_t now);
  Json status();

private:
  //------------------------------------------------------------------------------
  // TS 24.379 clause 13.2.4.2, TS 24.282 clause 17.2.4.2: a request forwarded to another participating function,
  // whose report goes to the requesting user, found by its RequestId.
  struct ForwardedLocation {
    std::string requester_sip;
    std::uint64_t expires = 0;
  };

  [[nodiscard]] std::string event_name(std::string_view suffix) const;
  void count(const char *key);
  Json rights(const std::string &id);
  bool shares(const std::string &target, const std::string &requester);
  SipResponse refusal(int status, const std::string &warning);
  std::string peer_of(const std::string &target);
  [[nodiscard]] std::vector<SipHeader> client_headers() const;
  [[nodiscard]] std::vector<SipHeader> report_headers() const;
  void to_client(const LocationUser &target, std::vector<BodyPart> parts, const std::vector<SipHeader> &headers,
                 const std::string &what);
  bool report_to_user(const std::string &sip, const BodyPart &part);
  void report_to_peer(const location::Registry::Waiter &waiter, const BodyPart &part);
  void send_location(const LocationUser &target, const location::Content &content, LocationInfo info = {});
  void send_configuration(const LocationUser &target, const location::Configuration &configuration,
                          const std::string &requester);
  void deliver(const std::string &target, const location::Registry::Waiter &waiter);
  void locate(const LocationUser &target, location::Registry::Waiter waiter, bool refresh);
  void forward(const std::string &peer, const std::string &target, const LocationUser &requester,
               const BodyPart &location_part, const std::string &request_id);
  [[nodiscard]] BodyPart forwarded_part(const BodyPart &received, const location::Request *request,
                                        const location::Configuration &configuration) const;
  void areas(const LocationUser &user);
  void notify_area(const LocationUser &user, const std::string &name, bool entered);
  SipResponse report(const LocationUser &user, const location::Report &report);
  std::vector<std::string> client_targets(const std::vector<BodyPart> &parts, const LocationInfo &info,
                                          bool is_request);
  void serve_client_targets(const location::Content &content, const std::vector<std::string> &targets,
                            const std::string &requester, const BodyPart &location_part);
  void serve_peer_targets(const location::Content &content, const std::vector<std::string> &targets,
                          const std::string &requester, const std::string &peer);
  std::optional<SipResponse> relay(const location::Report &report, const std::string &body, const std::string &peer);

  LocationHost &host_;
  const ServiceProfile &service_;
  const LocationTraits traits_;
  const location::Service namespace_;
  // Which users may request or change others' location reporting, and whose location a user shares, is left open
  // (TS 24.379 clause 13.2.2A NOTE 2, clause 13.2.3.2 NOTE 2 and NOTE 4; TS 24.282 clause 17.2.2A NOTE 2): the user
  // profile's "location" object carries "request", "configure" (both false by default), "report" (true by default)
  // and "share_with" (the MC service IDs allowed, "*" for any authorised requester; any by default).
  location::Registry registry_;
  std::map<std::string, ForwardedLocation> forwarded_;
  // TS 24.379 clauses 6.3.2.4.1 and 6.3.2.4.2: the area entries and exits each user has been told of.
  std::map<std::string, std::map<std::string, bool>> area_notices_;
  Counters counters_{"configured", "requested", "reports",      "requests", "reports_sent", "forwarded",
                     "relayed",    "refused",   "area_notices", "stripped", "unanswered"};
};
} // namespace mcx
