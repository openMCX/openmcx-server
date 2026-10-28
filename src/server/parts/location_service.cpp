//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Location procedures of the participating function, shared by the MCPTT, MCVideo and MCData servers
// (location_service.hpp). The clauses are those of TS 24.379 clause 13; TS 24.281 clause 18 follows them, and
// TS 24.282 clause 17.2 has the same steps under its own numbers (17.2.2 for 13.2.2, and so on).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19).

#include "parts/location_service.hpp"

#include "mcx/http.hpp"
#include "mcx/warning.hpp"
#include "parts/message_parts.hpp"

#include <ctime>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: TS 24.281 clause 18 and TS 24.282 clause 17.2 follow TS 24.379 clause 13, each in its own location-info
// namespace (TS 24.281 annex F.3, TS 24.282 annex D.4).
location::Service location_namespace(const ServiceProfile &service) {
  switch (service.service) {
  case Service::mcptt: return location::Service::Mcptt;
  case Service::mcvideo: return location::Service::Mcvideo;
  case Service::mcdata: return location::Service::Mcdata;
  }
  return location::Service::Mcptt;
}

//------------------------------------------------------------------------------
LocationService::LocationService(LocationHost &host, const ServiceProfile &service, const LocationTraits &traits)
    : host_(host), service_(service), traits_(traits), namespace_(location_namespace(service)) {}

//------------------------------------------------------------------------------
// Helper: an event name with the service's prefix ("location_..." or "mcdata_location_...").
std::string LocationService::event_name(std::string_view suffix) const {
  return std::string(service_.event_prefix) + std::string(suffix);
}

//------------------------------------------------------------------------------
// Helper: one more of the counted location procedures.
void LocationService::count(const char *key) { counters_.add(key); }

//------------------------------------------------------------------------------
// Helper: the location section of the user's profile, or empty when there is none.
Json LocationService::rights(const std::string &id) {
  try {
    return host_.location_profile(id).value("location", Json::object());
  } catch (const std::exception &) {
    return Json::object();
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b i: whether the target user shares its location with the requester
// (location.share_with, every user by default).
bool LocationService::shares(const std::string &target, const std::string &requester) {
  const auto with = rights(target).value("share_with", Json::array({"*"}));
  for (const auto &entry : with)
    if (entry == "*" || entry == requester) return true;
  return false;
}

//------------------------------------------------------------------------------
// Helper: a counted refusal of a location request, with a Warning header field unless warning is empty (TS 24.379
// clause 4.4, TS 24.282 clause 4.9).
SipResponse LocationService::refusal(int status, const std::string &warning) {
  count("refused");
  SipResponse response;
  response.status_code = status;
  if (!warning.empty()) response.headers = {{"Warning", host_.location_warning(warning)}};
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 NOTE 3: the participating function serving a user this one does not serve: the peer it
// is registered through, or <service>.location.peers by MC service ID or by "@domain" (how
// it is determined is left to implementation); empty when none is known.
std::string LocationService::peer_of(const std::string &target) {
  std::string registered;
  host_.each_location_user([&](const std::string &id, const std::string &peer) {
    if (registered.empty() && id == target && !peer.empty()) registered = peer;
  });
  if (!registered.empty()) return registered;
  const auto peers = host_.location_settings().value("peers", Json::object());
  if (peers.contains(target)) return peers.at(target).get<std::string>();
  const auto at = target.rfind('@');
  if (at != std::string::npos && peers.contains(target.substr(at)))
    return peers.at(target.substr(at)).get<std::string>();
  return {};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.2 steps 2 and 7 and clause 13.2.3.1 steps 2 and 5: the P-Asserted-Service and Accept-Contact
// header fields of a request to a client, with the service's ICSI.
std::vector<SipHeader> LocationService::client_headers() const {
  return {{"P-Asserted-Service", service_.icsi}, {"Accept-Contact", icsi_accept(service_)}};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b v A and clause 13.2.4.2: the header fields of a report to the requesting user,
// with the service's media feature tag.
std::vector<SipHeader> LocationService::report_headers() const {
  return {{"P-Asserted-Service", service_.icsi}, {"Accept-Contact", feature_accept(service_)}};
}

//------------------------------------------------------------------------------
// Helper: a SIP MESSAGE request to a client served here, its bodies protected as any other sent to it; a failure is
// reported.
void LocationService::to_client(const LocationUser &target, std::vector<BodyPart> parts,
                                const std::vector<SipHeader> &headers, const std::string &what) {
  // A body that cannot be protected for the client (TS 33.180 annex E.6.10: its CSK may no longer be used) is not
  // sent.
  try {
    parts = host_.seal_for_client(target.sip, std::move(parts));
  } catch (const std::exception &error) {
    event(event_name("location_message_not_protected"), {{"user_id", target.id}, {"reason", error.what()}});
    return;
  }
  std::string type, body;
  if (parts.size() == 1) {
    type = parts.front().content_type;
    body = parts.front().body;
  } else {
    const auto boundary = "mcx-" + random_id();
    type = "multipart/mixed; boundary=" + boundary;
    body = multipart_body(parts, boundary);
  }
  host_.send_message(target.sip, type, body, headers, [this, id = target.id, what](const SipResponse &response) {
    if (response.status_code < 300) return;
    Json detail = {{"user_id", id}, {"status", response.status_code}};
    if (traits_.failure_names_kind) detail["what"] = what;
    event(event_name("location_message_failed"), detail);
  });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b v and clause 13.2.4.2: a report to the requesting user. Through the client
// channel (traits) only to a user served here; false when it is not.
bool LocationService::report_to_user(const std::string &sip, const BodyPart &part) {
  if (!traits_.reports_through_client) {
    host_.send_message(sip, part.content_type, part.body, report_headers(), {});
    return true;
  }
  const auto user = host_.location_user_by_sip(sip);
  if (!user) return false;
  to_client(*user, {part}, report_headers(), "report");
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.3 step 4 v A: a report to the participating function of the requesting user. The clause names
// the PSI of that function; every participating function of a system shares that PSI, so the report is addressed to the
// requesting user's public user identity (known from its registration), which reaches the function that serves it; that
// function passes it on by its ReportID (clause 13.2.4.2).
void LocationService::report_to_peer(const location::Registry::Waiter &waiter, const BodyPart &part) {
  const auto sealed = host_.seal_for_peer(waiter.peer, {part});
  const auto requester = host_.location_user_by_id(waiter.requester);
  const auto uri = requester && requester->peer == waiter.peer ? requester->sip : host_.peer_uri(waiter.peer);
  host_.send_message(uri, sealed.front().content_type, sealed.front().body,
                     host_.route_to(waiter.peer, {{"P-Asserted-Identity", "<" + host_.service_uri() + ">"},
                                                  {"P-Asserted-Service", service_.icsi}}),
                     {});
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 13.2.2 and 13.2.3.1: a configuration or a request to a client served here, with a service
// information body naming the user.
void LocationService::send_location(const LocationUser &target, const location::Content &content, LocationInfo info) {
  info.request_uri = target.id;
  auto parts = host_.location_info_parts(info);
  parts.push_back({service_.location_mime, location::to_xml(content, namespace_)});
  to_client(target, std::move(parts), client_headers(),
            std::holds_alternative<location::Request>(content) ? "request" : "configuration");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.2: the location reporting configuration is stored as the client will hold it (step 10) and
// sent to it, naming the requesting user (step 8).
void LocationService::send_configuration(const LocationUser &target, const location::Configuration &configuration,
                                         const std::string &requester) {
  const auto &stored = registry_.configure(target.id, configuration);
  LocationInfo info;
  info.calling_user = requester;
  send_location(target, configuration, info);
  count("configured");
  event(event_name("location_configured"), {{"user_id", target.id},
                                            {"requester", requester},
                                            {"full", configuration.full},
                                            {"triggers", stored.triggers.size()},
                                            {"emergency_triggers", stored.emergency_triggers.size()}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.2, upon successful service authorisation: the user profile's configuration, or
// <service>.location.configuration. Trigger IDs are numbered in order, so that a user authorised again keeps the same
// ones (step 5).
void LocationService::configure(const std::string &id) {
  const auto user = host_.location_user_by_id(id);
  if (!user || !user->peer.empty()) return;
  auto source = rights(id).value("configuration", Json());
  if (source.is_null()) source = host_.location_settings().value("configuration", Json());
  if (source.is_null()) return;
  try {
    unsigned next = 0;
    const auto configuration = location::configuration_from_json(source, [&] { return "t" + std::to_string(++next); });
    send_configuration(*user, configuration, {});
  } catch (const std::exception &error) {
    event(event_name("location_configuration_invalid"), {{"user_id", id}, {"reason", error.what()}});
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b iv and v and clause 13.2.3.3 step 4 iv and v: the stored location of the
// target, filtered by the <LocationFilter>, goes to the requesting user or to the participating function of a
// requesting user served elsewhere.
void LocationService::deliver(const std::string &target, const location::Registry::Waiter &waiter) {
  if (waiter.filter && !registry_.passes(target, *waiter.filter)) {
    Json detail = {{"user_id", target}, {"request_id", waiter.request_id}, {"area", waiter.filter->area}};
    if (traits_.filtered_names_side) detail["in"] = waiter.filter->in;
    event(event_name("location_filtered"), detail);
    return;
  }
  const auto *last = registry_.last(target);
  if (!last) return;
  auto report = *last;
  report.id = waiter.request_id;
  report.reporting_uri = target;
  report.triggers.clear();
  const BodyPart part{service_.location_mime, location::to_xml(report, namespace_)};
  if (!waiter.peer.empty() && host_.peer_known(waiter.peer))
    report_to_peer(waiter, part);
  else if (!report_to_user(waiter.destination, part))
    return;
  count("reports_sent");
  event(event_name("location_report_sent"), {{"user_id", target},
                                             {"request_id", waiter.request_id},
                                             {"requester", waiter.requester},
                                             {"via", waiter.peer.empty() ? "user" : waiter.peer}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.3.2 step 7A b ii and iii and clause 13.2.3.3 step 4 ii and iii: the stored location while it
// is fresh, else a request to the client (clause 13.2.3.1) and a wait for its report.
void LocationService::locate(const LocationUser &target, location::Registry::Waiter waiter, bool refresh) {
  const auto now = monotonic_ms();
  const auto settings = host_.location_settings();
  if (!refresh && registry_.fresh(target.id, now, settings.value("max_age_ms", 30000U)))
    return deliver(target.id, waiter);
  const auto wait = settings.value("wait_ms", 5000U);
  if (const auto asked = registry_.await(target.id, std::move(waiter), now, wait, [] { return random_id(); })) {
    send_location(target, location::Request{*asked, false, std::nullopt});
    count("requested");
    event(event_name("location_requested"), {{"user_id", target.id}, {"request_id", *asked}});
  }
}

//------------------------------------------------------------------------------
// Helper: the location-info body forwarded for a request from a client (traits): the received one, with a
// configuration written anew (its TriggerIds assigned), or for MCData always written anew.
BodyPart LocationService::forwarded_part(const BodyPart &received, const location::Request *request,
                                         const location::Configuration &configuration) const {
  if (traits_.forwards_rewritten_location)
    return {service_.location_mime,
            request ? location::to_xml(*request, namespace_) : location::to_xml(configuration, namespace_)};
  auto part = received;
  if (!request) part.body = location::to_xml(configuration, namespace_);
  return part;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.2A step 7b and clause 13.2.3.2 step 7A a: a copy of an authorised client's request for a
// user served by another participating function, naming the requesting user (clause 13.2.2A step 7b iii).
void LocationService::forward(const std::string &peer, const std::string &target, const LocationUser &requester,
                              const BodyPart &location_part, const std::string &request_id) {
  LocationInfo info;
  info.calling_user = requester.id;
  auto parts = host_.location_info_parts(info);
  parts.push_back({resource_lists_mime, resource_list_xml({target})});
  parts.push_back(location_part);
  parts = host_.seal_for_peer(peer, std::move(parts));
  const auto boundary = "mcx-" + random_id();
  host_.send_message(
      host_.peer_uri(peer), "multipart/mixed; boundary=" + boundary, multipart_body(parts, boundary),
      host_.route_to(peer, {{"P-Asserted-Identity", "<" + requester.sip + ">"}, {"P-Asserted-Service", service_.icsi}}),
      {});
  if (!request_id.empty())
    forwarded_[request_id] = {requester.sip, monotonic_ms() + host_.location_settings().value("forward_ms", 60000U)};
  count("forwarded");
  event(event_name("location_forwarded"),
        {{"user_id", target}, {"server", peer}, {"requester", requester.id}, {"request_id", request_id}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.4.1 steps 2 and 3: entry into or exit from an emergency alert area
// (<service>.location.emergency_alert_areas) or a group geographic area (<service>.location.group_areas, for the
// groups the user is a member of).
void LocationService::areas(const LocationUser &user) {
  std::map<std::string, location::Area> named;
  const auto settings = host_.location_settings();
  const auto alert_areas = settings.value("emergency_alert_areas", Json::object());
  const auto group_areas = settings.value("group_areas", Json::object());
  try {
    for (const auto &[name, area] : alert_areas.items()) named["alert:" + name] = location::area_from_json(area);
    for (const auto &[group, area] : group_areas.items()) {
      if (!host_.location_group_member(group, user.id)) continue;
      named["group:" + group] = location::area_from_json(area);
    }
  } catch (const std::exception &error) {
    event(event_name("location_area_invalid"), {{"reason", error.what()}});
    return;
  }
  for (const auto &[name, entered] : registry_.areas(user.id, named)) notify_area(user, name, entered);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.2.4.1 (emergency alert area) and clause 6.3.2.4.2 (group geographic area): the notice of an
// entry or exit, recorded when the client answers 2xx.
void LocationService::notify_area(const LocationUser &user, const std::string &name, bool entered) {
  LocationInfo info;
  info.request_uri = user.id;
  if (name.starts_with("alert:"))
    info.emergency_alert_area = entered;
  else {
    info.associated_group = name.substr(std::string_view("group:").size());
    info.group_geo_area = entered;
  }
  auto headers = client_headers();
  headers.push_back({"Accept-Contact", feature_accept(service_)});
  std::vector<BodyPart> parts;
  try {
    parts = host_.seal_for_client(user.sip, host_.location_info_parts(info)); // not sent unprotected (to_client)
  } catch (const std::exception &error) {
    event(event_name("location_message_not_protected"), {{"user_id", user.id}, {"reason", error.what()}});
    return;
  }
  host_.send_message(user.sip, parts.front().content_type, parts.front().body, headers,
                     [this, id = user.id, name, entered](const SipResponse &response) {
                       if (response.status_code < 200) return;
                       host_.schedule([this, id, name, entered, status = response.status_code] {
                         if (status < 300) area_notices_[id][name] = entered;
                         event(event_name("location_area_notified"),
                               {{"user_id", id}, {"area", name}, {"entered", entered}, {"status", status}});
                       });
                     });
  count("area_notices");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.4.1: a location information report from a client served here answers the waiting requests
// and is checked against the configured areas.
SipResponse LocationService::report(const LocationUser &user, const location::Report &report) {
  // The refusal is not in the procedure. TS 24.379 and TS 24.281 have code 100 "function not allowed due to
  // <detailed reason>"; TS 24.282 table 4.9.2-2 has neither it nor a location reporting code, and its warn-text must
  // carry a code (clause 4.9.2), so the MCData 403 carries no Warning header field (optional, clause 4.9.1).
  if (!rights(user.id).value("report", true))
    return refusal(403, warning_entry(service_, Warning::function_not_allowed).code
                            ? warning_text(service_, Warning::function_not_allowed,
                                           "user authorisation: location reporting not authorised")
                            : std::string{});
  const auto waiters = registry_.reported(user.id, report, monotonic_ms());
  count("reports");
  auto detail = location::to_json(report);
  detail["user_id"] = user.id;
  event(event_name("location_report"), detail);
  for (const auto &waiter : waiters) deliver(user.id, waiter);
  areas(user);
  SipResponse response;
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 13.2.2A and 13.2.3.2: the users a client's configuration or request names, in its resource list,
// or for a request the users that activated the functional alias it names (clause 13.2.3.2 step 7b).
std::vector<std::string> LocationService::client_targets(const std::vector<BodyPart> &parts, const LocationInfo &info,
                                                         bool is_request) {
  std::vector<std::string> targets;
  if (const auto *lists = part_of(parts, resource_lists_mime)) {
    try {
      targets = parse_resource_list_targets(lists->body);
    } catch (const std::exception &) {
      targets.clear();
    }
  }
  if (targets.empty() && is_request && !info.location_of_functional_alias.empty())
    targets = host_.location_alias_users(info.location_of_functional_alias);
  return targets;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 13.2.2A and 13.2.3.2: a location reporting configuration, a location information request or a
// report from a client served here.
std::optional<SipResponse> LocationService::from_client(const SipMessage &message) {
  const auto parts = parts_of(message);
  const auto *loc = part_of(parts, service_.location_mime);
  if (!loc) return std::nullopt;
  location::Content content;
  try {
    content = location::parse(loc->body, nullptr, true);
  } catch (const std::exception &error) {
    event(event_name("location_body_invalid"), {{"reason", error.what()}});
    SipResponse bad;
    bad.status_code = 400;
    return bad;
  }
  // A report inside another request (an emergency alert, TS 24.379 clause 6.2.9.1) is that request's.
  if (std::holds_alternative<location::Report>(content) && part_of(parts, service_.info_mime)) return std::nullopt;

  // Steps 2 and 3: the requesting user.
  const auto asserted = asserted_identity(message);
  const auto user = host_.location_user_by_sip(asserted);
  if (!user || user->expires <= std::time(nullptr) || !user->peer.empty() || asserted != message.from_uri)
    return refusal(404, warning_text(service_, Warning::unknown_user));
  if (const auto *received = std::get_if<location::Report>(&content)) return report(*user, *received);
  const bool is_request = std::holds_alternative<location::Request>(content);

  // The service information is optional here: it only names a functional alias (clause 13.3.3.2 step 5 ii).
  const auto *info_part = part_of(parts, service_.info_mime);
  const auto info = info_part ? host_.location_info(message, *info_part) : LocationInfo{};
  const auto targets = client_targets(parts, info, is_request);
  if (targets.empty() && (!is_request || info.location_of_functional_alias.empty()))
    return refusal(403, warning_text(service_, Warning::location_target_invalid));
  if (!rights(user->id).value(is_request ? "request" : "configure", false))
    return refusal(403, warning_text(service_, is_request ? Warning::location_request_not_authorised
                                                          : Warning::location_configuration_not_authorised));
  count("requests");
  event(event_name(is_request ? "location_request_received" : "location_configuration_request"),
        {{"user_id", user->id}, {"targets", targets}, {"functional_alias", info.location_of_functional_alias}});
  host_.schedule([this, content, targets, requester = user->id, location_part = *loc] {
    serve_client_targets(content, targets, requester, location_part);
  });
  SipResponse response;
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.2A step 7 and clause 13.2.3.2 step 7A, after the answer: each target served elsewhere gets a
// copy of the request (step 7b, step 7A a); one served here that shares its location (else silently ignored: clause
// 13.2.2A step 7c i, clause 13.2.3.2 step 7A b i) is located or configured.
void LocationService::serve_client_targets(const location::Content &content, const std::vector<std::string> &targets,
                                           const std::string &requester, const BodyPart &location_part) {
  const auto requesting_user = host_.location_user_by_id(requester);
  if (!requesting_user) return;
  auto configuration = std::get_if<location::Configuration>(&content) ? std::get<location::Configuration>(content)
                                                                      : location::Configuration{};

  // TS 24.379 clause 13.2.2A step 7a: one TriggerId per criterion, the same for every client.
  for (auto *list : {&configuration.triggers, &configuration.emergency_triggers})
    for (auto &trigger : *list)
      if (trigger.id.empty()) trigger.id = random_id();
  const auto *request = std::get_if<location::Request>(&content);
  for (const auto &target : targets) {
    const auto target_user = host_.location_user_by_id(target);
    if (!target_user || !target_user->peer.empty() || target_user->expires <= std::time(nullptr)) {
      const auto peer = target_user && !target_user->peer.empty() ? target_user->peer : peer_of(target);
      if (peer.empty() || !host_.peer_known(peer)) {
        event(event_name("location_target_unknown"), {{"user_id", target}, {"requester", requester}});
        continue;
      }
      forward(peer, target, *requesting_user, forwarded_part(location_part, request, configuration),
              request ? request->id : "");
      continue;
    }
    if (!shares(target, requester)) {
      event(event_name("location_not_shared"), {{"user_id", target}, {"requester", requester}});
      continue;
    }
    if (request) {
      location::Registry::Waiter waiter;
      waiter.request_id = request->id;
      waiter.destination = requesting_user->sip;
      waiter.requester = requester;
      waiter.filter = request->filter;
      locate(*target_user, waiter, request->refresh);
    } else
      send_configuration(*target_user, configuration, requester);
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.4.2: a report from another participating function answers a request forwarded to it: the
// Request-URI becomes the requesting user's.
std::optional<SipResponse> LocationService::relay(const location::Report &report, const std::string &body,
                                                  const std::string &peer) {
  const auto forwarded = forwarded_.find(report.id);
  if (report.id.empty() || forwarded == forwarded_.end()) return std::nullopt;
  report_to_user(forwarded->second.requester_sip, {service_.location_mime, body});
  count("relayed");
  event(event_name("location_report_relayed"),
        {{"user_id", report.reporting_uri}, {"request_id", report.id}, {"server", peer}});
  SipResponse response;
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 13.2.2B, 13.2.3.3 and 13.2.4.2: location reporting configurations, location information requests
// and reports from another participating function.
std::optional<SipResponse> LocationService::from_peer(const SipMessage &message, const std::string &peer) {
  const auto parts = parts_of(message);
  const auto *loc = part_of(parts, service_.location_mime);
  if (!loc) return std::nullopt;
  location::Content content;
  try {
    content = location::parse(loc->body, nullptr, true);
  } catch (const std::exception &) {
    return std::nullopt;
  }
  if (const auto *received = std::get_if<location::Report>(&content)) return relay(*received, loc->body, peer);
  if (message.request_uri != host_.service_uri()) return std::nullopt;

  // A resource list that cannot be read names no target (parse_resource_list_targets refuses an empty one).
  const auto *lists = part_of(parts, resource_lists_mime);
  std::vector<std::string> targets;
  try {
    if (lists) targets = parse_resource_list_targets(lists->body);
  } catch (const std::exception &) {
    targets.clear();
  }
  if (targets.empty()) return refusal(403, warning_text(service_, Warning::location_target_invalid));

  // TS 24.379 clause 13.2.2B step 2 and clause 13.2.3.3 step 2: the requesting user.
  const auto *info_part = part_of(parts, service_.info_mime);
  auto requester = info_part ? host_.location_info(message, *info_part).calling_user : std::string{};
  if (requester.empty()) {
    const auto asserted = asserted_identity(message);
    if (const auto found = host_.location_user_by_sip(asserted)) requester = found->id;
    if (requester.empty()) requester = asserted;
  }
  count("requests");
  event(event_name("location_peer_request"), {{"server", peer}, {"requester", requester}, {"targets", targets}});
  host_.schedule([this, peer, content, targets, requester] { serve_peer_targets(content, targets, requester, peer); });
  SipResponse response;
  response.status_code = 200;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.2B steps 3 to 5 and clause 13.2.3.3 steps 3 and 4, after the answer: each target served here
// that shares its location is located or configured.
void LocationService::serve_peer_targets(const location::Content &content, const std::vector<std::string> &targets,
                                         const std::string &requester, const std::string &peer) {
  for (const auto &target : targets) {
    const auto target_user = host_.location_user_by_id(target);
    if (!target_user || !target_user->peer.empty() || !shares(target, requester)) {
      event(event_name("location_not_shared"), {{"user_id", target}, {"requester", requester}, {"server", peer}});
      continue;
    }
    if (const auto *request = std::get_if<location::Request>(&content)) {
      location::Registry::Waiter waiter;
      waiter.request_id = request->id;
      waiter.peer = peer;
      waiter.requester = requester;
      waiter.filter = request->filter;
      locate(*target_user, waiter, request->refresh);
    } else
      send_configuration(*target_user, std::get<location::Configuration>(content), requester);
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 13.2.5: a location request or configuration never reaches a client inside a request relayed to
// it; a body that cannot be read is dropped as well.
std::vector<BodyPart> LocationService::without_requests(std::vector<BodyPart> parts) {
  const auto before = parts.size();
  std::erase_if(parts, [this](const BodyPart &part) {
    if (part.content_type != service_.location_mime) return false;
    try {
      return !std::holds_alternative<location::Report>(location::parse(part.body, nullptr, true));
    } catch (const std::exception &) {
      return true;
    }
  });
  if (parts.size() != before) count("stripped");
  return parts;
}

//------------------------------------------------------------------------------
// Helper: location requests left unanswered and forwarded requests past their time are dropped.
void LocationService::tick(std::uint64_t now) {
  for (const auto &[user, waiter] : registry_.expire(now)) {
    count("unanswered");
    event(event_name("location_request_unanswered"),
          {{"user_id", user}, {"request_id", waiter.request_id}, {"requester", waiter.requester}});
  }
  std::erase_if(forwarded_, [now](const auto &entry) { return entry.second.expires <= now; });
}

//------------------------------------------------------------------------------
// Helper: the location state for the status report: counters, each served user's configuration, last report and area
// notices, and the requests waiting or forwarded.
Json LocationService::status() {
  Json users = Json::object();
  host_.each_location_user([&](const std::string &id, const std::string &peer) {
    if (!peer.empty()) return;
    Json entry = Json::object();
    if (const auto *configuration = registry_.configuration(id))
      entry["configuration"] = location::to_json(*configuration);
    if (const auto *last = registry_.last(id)) entry["report"] = location::to_json(*last);
    if (const auto notices = area_notices_.find(id); notices != area_notices_.end()) entry["areas"] = notices->second;
    if (!entry.empty()) users[id] = entry;
  });
  return {{"counters", counters_.json()},
          {"users", users},
          {"waiting", registry_.waiting()},
          {"forwarded", forwarded_.size()}};
}

} // namespace mcx
