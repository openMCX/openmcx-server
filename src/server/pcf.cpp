// The MCPTT and MCVideo servers in the 5GC AF role on N5 (TS 23.289 clauses 5.4 to 5.6, TS 29.514
// Npcf_PolicyAuthorization): for each active leg of a UE on 5G access, an app session asks the PCF for the QoS of the
// leg's media (member functions of McServer). Without a "pcf" block, or with "enabled": false, nothing here runs.
//
// Specifications: TS 29.514 V19.4.0 (Rel-19), TS 23.503, TS 23.501 clause 5.7.4, TS 24.379 V19.7.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// N5: the PCF client from the configuration's "pcf" block when it is enabled; null otherwise (no block: N5 off).
void McServer::pcf_start() {
  if (!cfg_.contains("pcf")) return;
  auto pcf = af::PcfConfig::parse(cfg_.at("pcf"));
  if (!pcf.enabled) return;
  // The PCF reaches the notification receiver at the media address by default.
  if (pcf.notif_uri_base.empty())
    pcf.notif_uri_base = "http://" + resolve_ipv4(cfg_.at("media").at("advertise")) + ":" +
                         pcf.notif_bind.substr(pcf.notif_bind.rfind(':') + 1);
  event("pcf_enabled", {{"pcf_uri", pcf.pcf_uri},
                        {"nrf_uri", pcf.nrf_uri},
                        {"http2", pcf.http2},
                        {"notif_uri_base", pcf.notif_uri_base},
                        {"ue_subnets", pcf.ue_subnets},
                        {"required", pcf.required}});
  pcf_ = std::make_unique<af::PolicyAuthorizationClient>(std::move(pcf));
}

//------------------------------------------------------------------------------
// N5: what the PCF is asked for a leg (TS 29.514 clause 5.6.2.3 AppSessionContext: the UE address, the MC service
// ID, the media components with their flows, the reservation priority), or nothing when the leg's UE is not on 5G
// access (outside pcf.ue_subnets).
std::optional<af::SessionRequest> McServer::pcf_request(const Leg &leg) const {
  if (!pcf_ || !leg.remote || !pcf_->covers(leg.remote->address)) return std::nullopt;
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
  return request;
}

//------------------------------------------------------------------------------
// N5: an app session for a leg that has become active.
void McServer::pcf_open(const Leg &leg) {
  if (!pcf_) return;
  if (auto request = pcf_request(leg)) pcf_->open(leg.dialog, std::move(*request));
}

//------------------------------------------------------------------------------
// N5: a result or notification from the PCF, as an event; best effort unless pcf.required (a refused or failed QoS
// releases the leg with BYE, Reason cause 503), and a PCF-initiated termination releases the leg only with
// pcf.release_on_terminate.
void McServer::pcf_event(const af::Event &result) {
  Json detail = {{"dialog", result.key}, {"app_session_id", result.app_session_id}};
  if (result.status) detail["status"] = result.status;
  if (!result.detail.empty()) detail["detail"] = result.detail;
  const auto leg = legs_.find(result.key);
  if (leg != legs_.end()) detail["user_id"] = leg->second->user;
  event(af::event_name(result.kind), detail);
  const auto &config = pcf_->config();
  std::string why;
  if (config.required && result.kind == af::Event::Kind::create_failed)
    why = "QoS not authorised by the PCF";
  else if (config.required && result.kind == af::Event::Kind::notified &&
           result.detail.find("FAILED_RESOURCES_ALLOCATION") != std::string::npos)
    why = "QoS resources not allocated";
  else if (config.release_on_terminate && result.kind == af::Event::Kind::terminated)
    why = "QoS session terminated by the PCF";
  if (why.empty() || leg == legs_.end() || !leg->second->active) return;
  event("pcf_leg_released", {{"dialog", result.key}, {"user_id", leg->second->user}, {"reason", why}});
  leg->second->active = false;
  try {
    sip_.bye(result.key, {}, {{"Reason", "SIP ;cause=503 ;text=\"" + why + "\""}});
  } catch (const std::exception &error) {
    event("sip_error", {{"reason", error.what()}});
  }
}

//------------------------------------------------------------------------------
// N5: the PCF's results and notifications; then every tracked leg is brought up to date (a priority change or a
// re-INVITE becomes an update) and a leg that is gone, by whichever path, has its app session deleted.
void McServer::pcf_tick(std::uint64_t now) {
  for (const auto &result : pcf_->poll()) pcf_event(result);
  if (now - pcf_checked_ < 100) return;
  pcf_checked_ = now;
  for (const auto &key : pcf_->keys()) {
    const auto found = legs_.find(key);
    if (found == legs_.end() || !found->second->active || !current_session(found->second->session)) {
      pcf_->close(key);
      continue;
    }
    if (auto request = pcf_request(*found->second))
      pcf_->refresh(key, *request);
    else
      pcf_->close(key);
  }
}

//------------------------------------------------------------------------------
// N5: at shutdown, the app sessions are deleted (bounded wait).
void McServer::pcf_stop() {
  if (!pcf_) return;
  for (const auto &result : pcf_->shutdown(std::chrono::milliseconds(1500)))
    event(af::event_name(result.kind), {{"dialog", result.key}});
  pcf_.reset();
}

} // namespace mcx
