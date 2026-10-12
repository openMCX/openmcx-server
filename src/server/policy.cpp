//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCPTT and MCVideo servers in the AF role towards policy control, for the QoS of each active leg's media
// (member functions of McServer): N5 for a UE on 5G access (TS 23.289 clauses 5.4 to 5.6, TS 29.514
// Npcf_PolicyAuthorization, "pcf" block) and Rx for a UE on EPS access (TS 23.379 clause 7.5.2.6 MCPTT-5,
// TS 23.280 clause 10.11.2a, TS 29.214, "rx" block). A UE on an access where no dedicated bearer can be set up (WLAN)
// is in neither block's ue_subnets and gets no request (TS 24.379 clause 4.13). Without either block, or with
// "enabled": false, nothing here runs.
//
// Specifications: TS 29.514 V19.4.0 (Rel-19), TS 29.214 V19.3.0 (Rel-19), TS 23.503, TS 23.501 clause 5.7.4,
// TS 23.379 V19.11.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19), TS 24.379 V19.7.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the process's freeDiameter core for MCPTT-2 ("diameter_config") and Rx (an enabled "rx" block), with the
// applications it serves; null when neither is configured. One core serves both, from one configuration file.
std::shared_ptr<DiameterCore> McServer::start_diameter_core_for(const Json &cfg) {
  DiameterApplications applications;
  std::string path;
  if (cfg.contains("diameter_config")) {
    applications.data_management = true;
    path = cfg.at("diameter_config").get<std::string>();
  }
  if (cfg.contains("rx")) {
    const auto rx = af::RxConfig::parse(cfg.at("rx"));
    if (rx.enabled) {
      applications.rx = true;
      if (path.empty()) path = rx.diameter_config;
      if (path.empty()) throw std::runtime_error("rx.enabled needs rx.diameter_config or diameter_config");
      if (!rx.diameter_config.empty() && rx.diameter_config != path)
        throw std::runtime_error("rx.diameter_config differs from diameter_config: one freeDiameter core serves both "
                                 "MCPTT-2 and Rx, from one configuration file");
    }
  }
  if (!applications.data_management && !applications.rx) return nullptr;
  return start_diameter_core(path, applications);
}

//------------------------------------------------------------------------------
// N5 and Rx: the policy clients of the enabled "pcf" and "rx" blocks (none: no QoS requests).
void McServer::policy_start() {
  if (cfg_.contains("pcf")) {
    auto pcf = af::PcfConfig::parse(cfg_.at("pcf"));
    if (pcf.enabled) {
      // The PCF reaches the notification receiver at the media address by default.
      if (pcf.notif_uri_base.empty())
        pcf.notif_uri_base = "http://" + resolve_ipv4(cfg_.at("media").at("advertise")) + ":" +
                             pcf.notif_bind.substr(pcf.notif_bind.rfind(':') + 1);
      event("pcf_enabled", {{"pcf_uri", pcf.pcf_uri},
                            {"nrf_uri", pcf.nrf_uri},
                            {"notif_uri_base", pcf.notif_uri_base},
                            {"ue_subnets", pcf.ue_subnets},
                            {"required", pcf.required}});
      policy_clients_.push_back(std::make_unique<af::PolicyAuthorizationClient>(std::move(pcf)));
    }
  }
  if (cfg_.contains("rx")) {
    auto rx = af::RxConfig::parse(cfg_.at("rx"));
    if (rx.enabled) {
      // TS 29.214 annex A.13.1 NOTE 3 and annex A.15.1 NOTE 3: the ICSI of the MC service.
      if (rx.af_application_identifier.empty()) rx.af_application_identifier = svc_.icsi;
      event("rx_enabled", {{"destination_realm", rx.destination_realm},
                           {"destination_host", rx.destination_host},
                           {"af_application_identifier", rx.af_application_identifier},
                           {"ue_subnets", rx.ue_subnets},
                           {"required", rx.required}});
      policy_clients_.push_back(std::make_unique<af::RxClient>(std::move(rx), diameter_core_));
    }
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.13: the client of the access the leg's UE is on (the first whose ue_subnets hold its address),
// or null: a UE on another access (WLAN) has no policy session.
af::PolicyClient *McServer::policy_client_for(const Leg &leg) const {
  if (!leg.remote) return nullptr;
  for (const auto &client : policy_clients_)
    if (client->covers(leg.remote->address)) return client.get();
  return nullptr;
}

//------------------------------------------------------------------------------
// What policy control is asked for a leg (TS 29.514 clause 5.6.2.3 AppSessionContext, TS 29.214 clause 4.4.1: the UE
// address, the MC service, the media with their flows, the priority), or nothing when the leg's UE is on no access
// with a policy client.
std::optional<af::SessionRequest> McServer::policy_request(const Leg &leg) const {
  if (!policy_client_for(leg)) return std::nullopt;
  const auto &local = leg.local;
  const auto &remote = *leg.remote;
  af::SessionRequest request;
  request.ue_ipv4 = remote.address;
  request.mc_id = leg.user;
  request.id_attribute = svc_.service == Service::mcvideo ? "mcVideoId" : "mcpttId";
  request.flows.rtp = {local.address, remote.address, local.audio_port, remote.audio_port};
  request.flows.rtcp = {local.address, remote.address,
                        static_cast<std::uint16_t>(local.rtcp_port ? local.rtcp_port : local.audio_port + 1),
                        static_cast<std::uint16_t>(remote.rtcp_port ? remote.rtcp_port : remote.audio_port + 1)};
  if (local.control != MediaControl::none && remote.control != MediaControl::none && remote.floor_port)
    request.flows.floor = af::FlowPair{local.floor_address.empty() ? local.address : local.floor_address,
                                       remote.floor_address.empty() ? remote.address : remote.floor_address,
                                       local.floor_port, remote.floor_port};
  if (local.video && remote.video && remote.video->port) {
    request.flows.video_rtp = af::FlowPair{local.address, remote.address, local.video->port, remote.video->port};
    request.flows.video_rtcp = af::FlowPair{
        local.address, remote.address,
        static_cast<std::uint16_t>(local.video->rtcp_port ? local.video->rtcp_port : local.video->port + 1),
        static_cast<std::uint16_t>(remote.video->rtcp_port ? remote.video->rtcp_port : remote.video->port + 1)};
  }
  // The call's priority, which also decides its Resource-Priority (TS 24.379 clause 6.2.8): the group's state, or a
  // private or ad hoc session's own.
  const auto &session = *leg.session;
  if (session.private_call || session.adhoc)
    request.priority = priority_name(session.priority);
  else if (const auto found = priorities_.find(session.group); found != priorities_.end())
    request.priority = priority_name(found->second);

  // TS 24.379 clause 6.3.3.1.19: the Resource-Priority provisioned for that priority (TS 29.214 annex A.13.2).
  request.resource_priority = service_resource_priority().value(request.priority, std::string{});
  return request;
}

//------------------------------------------------------------------------------
// A policy session for a leg that has become active, with the client of its UE's access.
void McServer::policy_open(const Leg &leg) {
  auto *client = policy_client_for(leg);
  if (!client) return;
  if (auto request = policy_request(leg)) client->open(leg.dialog, std::move(*request));
}

//------------------------------------------------------------------------------
// A result or notification from policy control, as an event; best effort unless the client is "required" (a
// refused or failed QoS releases the leg with BYE, Reason cause 503), and a network-initiated termination releases
// the leg only with release_on_terminate.
void McServer::policy_event(af::PolicyClient &client, const af::Event &result) {
  Json detail = {
      {"dialog", result.key},
      {client.interface_name() == std::string_view("rx") ? "session_id" : "app_session_id", result.app_session_id}};
  if (result.status) detail["status"] = result.status;
  if (!result.detail.empty()) detail["detail"] = result.detail;
  const auto leg = legs_.find(result.key);
  if (leg != legs_.end()) detail["user_id"] = leg->second->user;
  event(client.event_name(result.kind), detail);
  const std::string controller = client.interface_name() == std::string_view("rx") ? "PCRF" : "PCF";
  std::string why;
  if (client.required() && result.kind == af::Event::Kind::create_failed)
    why = "QoS not authorised by the " + controller;
  else if (client.required() && result.kind == af::Event::Kind::notified &&
           result.detail.find("FAILED_RESOURCES_ALLOCATION") != std::string::npos)
    why = "QoS resources not allocated";
  else if (client.release_on_terminate() && result.kind == af::Event::Kind::terminated)
    why = "QoS session terminated by the " + controller;
  if (why.empty() || leg == legs_.end() || !leg->second->active) return;
  event(std::string(client.interface_name()) + "_leg_released",
        {{"dialog", result.key}, {"user_id", leg->second->user}, {"reason", why}});
  leg->second->active = false;
  try {
    sip_.bye(result.key, {}, {{"Reason", "SIP ;cause=503 ;text=\"" + why + "\""}});
  } catch (const std::exception &error) {
    event("sip_error", {{"reason", error.what()}});
  }
}

//------------------------------------------------------------------------------
// The results and notifications of each client; then every tracked leg is brought up to date (a priority change or
// a re-INVITE becomes an update) and a leg that is gone, by whichever path, or now on another access, has its policy
// session ended.
void McServer::policy_tick(std::uint64_t now) {
  for (const auto &client : policy_clients_)
    for (const auto &result : client->poll()) policy_event(*client, result);
  if (now - policy_checked_ < 100) return;
  policy_checked_ = now;
  for (const auto &client : policy_clients_) {
    for (const auto &key : client->keys()) {
      const auto found = legs_.find(key);
      if (found == legs_.end() || !found->second->active || !current_session(found->second->session) ||
          policy_client_for(*found->second) != client.get()) {
        client->close(key);
        continue;
      }
      if (auto request = policy_request(*found->second))
        client->refresh(key, *request);
      else
        client->close(key);
    }
  }
}

//------------------------------------------------------------------------------
// At shutdown, every policy session ends (bounded wait).
void McServer::policy_stop() {
  for (const auto &client : policy_clients_)
    for (const auto &result : client->shutdown(std::chrono::milliseconds(1500)))
      event(client->event_name(result.kind), {{"dialog", result.key}});
  policy_clients_.clear();
}

} // namespace mcx
