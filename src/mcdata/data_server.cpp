// The MCData server: construction, the run loop with its operator commands and the periodic tick that runs
// the timers (TDC1, TDC2, TDC3) and writes the status (member functions of DataServer, declared in data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the periodic tick: runs the location, media and IP connectivity timers, TDC1 (disposition
// aggregation), TDC2 (file availability) and TDC3 (request for extension, TS 24.282 clause 13.2.4.5.4.1),
// expires users and writes the status file.
//------------------------------------------------------------------------------
// TS 24.484 clause 10.4: read the MCData service configuration from the CMS every 30 seconds, every 2 seconds until
// the first answer.
void DataServer::refresh_service_config(std::uint64_t now) {
  const bool known = !service_config_.empty();
  if (service_config_at_ && now - service_config_at_ < (known ? 30000u : 2000u)) return;
  service_config_at_ = now;
  try {
    auto config = internal("cms", "/internal/service-config?service=mcdata");
    if (!config.is_object() || !config.contains("resource_priority")) return;
    if (config != service_config_) event("service_config_read", Json{{"resource_priority", config.at("resource_priority")}});
    service_config_ = std::move(config);
  } catch (const std::exception &error) {
    if (!known) event("service_config_unavailable", Json{{"reason", error.what()}});
  }
}

//------------------------------------------------------------------------------
void DataServer::tick() {
  const auto now = monotonic_ms();
  refresh_service_config(now);
  location_.tick(now);
  for (auto &[group, sub] : group_subscriptions_)
    if (sub.active && now >= sub.refresh) {
      sub.refresh = now + 3000000;
      pending_.push_back([this, group] { subscribe_group_document(group); });
    }
  for (auto &[message, sent] : dispatched_)
    if (sent.tdc1 && (sent.tdc1 <= now || sent.deadline <= now)) send_aggregate(message, sent); // TDC1 expiry
  std::erase_if(dispatched_, [now](const auto &entry) { return entry.second.deadline <= now; });
  std::erase_if(adhoc_groups_, [now](const auto &entry) { return entry.second.deadline <= now; });
  for (auto &[key, held] : held_)
    if (held.redeliver_at && held.redeliver_at <= now) redeliver(key, held);
  const auto indication = file_distribution().value("intent_before_release_ms", 0u);
  media_tick();
  ipcon_tick();
  file_transfer_timers(now, indication);
  std::erase_if(transfers_, [](const auto &entry) { return !entry.second.expires; });
  std::erase_if(held_, [now](const auto &entry) { return entry.second.retain_until <= now; });
  if (held_order_.size() != held_.size())
    std::erase_if(held_order_, [this](const auto &key) { return !held_.contains(key); });
  for (const auto &[sip, user] : users_)
    if (user.expires <= std::time(nullptr)) deactivate_aliases(user.id);
  std::erase_if(users_, [](const auto &entry) { return entry.second.expires <= std::time(nullptr); });
  if (now - last_save_ < 200) return;
  last_save_ = now;
  save_status();
}

//------------------------------------------------------------------------------
// Helper: the timers of the file transfers in transfers_: TDC1 (disposition aggregation), TDC2 (file availability)
// and TDC3 with the release intent before it (TS 24.282 clause 13.2.4.5.4.1).
void DataServer::file_transfer_timers(std::uint64_t now, unsigned indication) {
  for (auto &[message, transfer] : transfers_) {
    if (transfer.tdc1 && transfer.tdc1 <= now) send_file_aggregate(message, transfer); // TDC1
    if (transfer.media_plane) continue;
    // TS 24.282 clause 13.2.4.5.4.1: announce the intent to release before TDC2 expires, then TDC3.
    if (indication && !transfer.intent_sent && transfer.expires && transfer.expires <= now + indication)
      release_intent(message, transfer);
    if (transfer.tdc3 && transfer.tdc3 <= now) {
      transfer.tdc3 = 0;
      if (!transfer.extended) {
        const auto initiator = transfer.release_initiator;
        mcdata::FdHttpTermination outcome;
        outcome.conversation = mcdata::parse_uuid(transfer.conversation);
        outcome.message = mcdata::parse_uuid(message);
        outcome.type = mcdata::TerminationType::Response;
        outcome.release = mcdata::ReleaseResponse::Success;
        outcome.file_url = transfer.file_url;
        stop_transmission(message, "no extension was requested");
        if (!initiator.empty()) send_termination(initiator, outcome); // TS 24.282 clause 13.2.6.3.4.3
      }
    }
    if (transfer.expires && transfer.expires <= now) file_expired(message, transfer); // TDC2
  }
}

//------------------------------------------------------------------------------
// Helper: the status file: the users, counters and protection figures, then the communications and procedures in
// progress.
void DataServer::save_status() {
  status_["ready"] = true;
  status_["users"] = Json::object();
  for (const auto &[sip, user] : users_)
    status_["users"][user.id] = {{"client_id", user.client},
                                 {"groups", user.groups},
                                 {"csk_id", user.csk ? Json(user.csk->csb_id) : Json(nullptr)}};
  status_["counters"] = counters_.json();
  Json subscriptions = Json::object();
  for (const auto &[group, sub] : group_subscriptions_) subscriptions[group] = sub.active;
  status_["group_documents"] = {
      {"subscriptions", subscriptions}, {"kept", group_cache_.size()}, {"counters", group_docs_}};
  status_["location"] = location_.status();
  status_["msgstore"] = {{"counters", msgstore_counters_.json()}, {"users", storage_.size()}};
  status_["xml_protection"] = {{"enabled", protects_xml()},
                               {"encrypted", xml_encrypted_},
                               {"decrypted", xml_decrypted_},
                               {"refused", xml_refused_}};
  status_["signalling_protection"] = {{"enabled", protect_signalling()},
                                      {"opened", signalling_opened_},
                                      {"sealed", signalling_sealed_},
                                      {"refused", signalling_refused_}};
  status_["pending_dispositions"] = dispatched_.size();
  status_communications();
  status_procedures();
  write_status(cfg_, status_);
}

//------------------------------------------------------------------------------
// Helper: the status of the media plane sessions, the group priority states (TS 24.282 clause 6.3.7.1), the file
// transfers and the messages stored for redelivery.
void DataServer::status_communications() {
  status_["media_sessions"] = Json::array();
  for (const auto &[dialog, session] : media_)
    status_["media_sessions"].push_back({{"originator", session->originator},
                                         {"target", session->target},
                                         {"owner", session->owner},
                                         {"session", session->session},
                                         {"key", session->key},
                                         {"emergency", session->emergency},
                                         {"imminent", session->imminent},
                                         {"file", session->file},
                                         {"group", session->group},
                                         {"recipients", session->recipients},
                                         {"message_id", session->message_id},
                                         {"originating", session->originating},
                                         {"relayed_bytes", session->relayed_bytes},
                                         {"dialog", dialog},
                                         {"connected", session->endpoint && session->endpoint->connected()}});
  // The in-progress priority states of the groups (TS 24.282 clause 6.3.7.1), which persist until
  // an authorised user cancels them.
  status_["group_priority"] = Json::object();
  for (const auto &[group, state] : group_priority_)
    status_["group_priority"][group] = {
        {"emergency", state.emergency}, {"imminent", state.imminent}, {"originator", state.originator}};
  status_["file_transfers"] = Json::object();
  for (const auto &[message, transfer] : transfers_)
    status_["file_transfers"][message] = {{"originator", transfer.originator},      {"group", transfer.group},
                                          {"file_url", transfer.file_url},          {"recipients", transfer.recipients},
                                          {"downloaded", transfer.downloaded},      {"rejected", transfer.rejected},
                                          {"release_intent", transfer.intent_sent}, {"extended", transfer.extended}};
  status_["stored_for_redelivery"] = Json::array();
  for (const auto &[key, held] : held_)
    if (held.redeliver_at)
      status_["stored_for_redelivery"].push_back(
          {{"user_id", key.first}, {"message_id", key.second}, {"attempts", held.attempts}});
}

//------------------------------------------------------------------------------
// Helper: the status of the functional aliases, the emergency alerts, the IP connectivity sessions, the release
// processes (TS 24.282 clause 13.2.6) and the ad hoc groups.
void DataServer::status_procedures() {
  status_["functional_aliases"] = functional_aliases_.activations();
  status_["emergency_alerts"] = Json::object();
  for (const auto &[group, alerts] : emergency_alerts_)
    for (const auto &[originator, alert] : alerts) status_["emergency_alerts"][group].push_back(originator);
  status_["ipconn_sessions"] = Json::array();
  std::set<std::shared_ptr<IpconSession>> listed_tunnels;
  for (const auto &[dialog, tunnel] : ipcons_)
    if (listed_tunnels.insert(tunnel).second)
      status_["ipconn_sessions"].push_back({{"originator", tunnel->originator},
                                            {"target", tunnel->target},
                                            {"dialog", tunnel->origin_dialog},
                                            {"established", tunnel->established},
                                            {"origin_port", tunnel->origin_socket->port()},
                                            {"target_port", tunnel->target_socket->port()},
                                            {"to_target", tunnel->to_target},
                                            {"to_origin", tunnel->to_origin},
                                            {"bytes", tunnel->bytes},
                                            {"dropped", tunnel->dropped}});
  status_["pending_releases"] = Json::object();
  for (const auto &[key, process] : releases_)
    status_["pending_releases"][key] = {{"initiator", process.initiator},
                                        {"reason", process.reason},
                                        {"tdc3_running", process.tdc3 != 0},
                                        {"extension_requested", process.extension_requested},
                                        {"remaining", process.remaining}};
  status_["adhoc_groups"] = Json::object();
  for (const auto &[id, group] : adhoc_groups_) status_["adhoc_groups"][id] = group.members;
}

//------------------------------------------------------------------------------
// Helper: construct the server from its configuration: the SIP stack.
DataServer::DataServer(Json cfg, bool disable_tls)
    : cfg_(std::move(cfg)), http_(cfg_.at("tls").at("ca_file")), control_(cfg_.at("control_fifo")),
      sip_(sip_config(cfg_, disable_tls), {[this](const SipMessage &received) { return incoming(received); },
                                           [this](std::string_view dialog, SipCallState state, int) {
                                             if (state == SipCallState::disconnected) {
                                               media_released(std::string(dialog));
                                               ipcon_released(std::string(dialog));
                                             }
                                           },
                                           {},
                                           {},
                                           [](std::string_view error) { event("sip_error", {{"reason", error}}); },
                                           {}}),
      core_address_(resolve_ipv4(cfg_.at("trusted_core"))) {
  service_uri_ = cfg_.at("mcdata").at("service_uri").get<std::string>();
  status_ = {{"sip_transport", disable_tls ? "tcp" : "tls"}, {"instance_id", random_id()}, {"role", "mcdata-server"}};
}

//------------------------------------------------------------------------------
// Helper: the run loop: provisions the server's keys, polls SIP, runs the queued tasks and the operator
// commands of the control FIFO, and ticks.
void DataServer::run() {
  if (cfg_.contains("security")) {
    keys_ = std::make_unique<KeyClient>(http_, cfg_.at("security"), service_uri_);
    keys_->provision("", cfg_.at("common").at("client_id"), cfg_.at("common").at("secret"));
  }
  sip_.start();
  event("mcdata_server_started");
  while (!stopping) {
    sip_.poll(std::chrono::milliseconds(5));
    pending_.run();
    for (auto &command : control_.read()) {
      if (command == "quit") stopping = 1;
      // TS 24.282 clause 13.2.4.5.4.1: an operator announces the intent to release a transmission.
      else if (command.starts_with("release-intent ")) {
        const auto id = command.substr(15);
        if (const auto found = transfers_.find(id); found != transfers_.end() && !found->second.intent_sent)
          release_intent(id, found->second);
        else
          event("mcdata_file_stop_unknown", {{"message_id", id}});
      }
      // TS 24.282 clauses 13.2.3.2.4 and 13.2.4.4.1 over the media plane: an operator releases a
      // communication, named by its key or by a dialog of one of its legs, at once
      // or after announcing it to the originator ("query" asks for the remaining data).
      else if (command.starts_with("release-session ") || command.starts_with("release-session-intent ")) {
        const bool intent = command.starts_with("release-session-intent ");
        std::istringstream words(command.substr(intent ? 23 : 16));
        std::string id, word, reason;
        bool query = false;
        words >> id;
        while (words >> word) {
          if (word == "query" && reason.empty())
            query = true;
          else
            reason += (reason.empty() ? "" : " ") + word;
        }
        if (reason.empty()) reason = "released by the MCData server";
        std::string key = id;
        if (const auto leg = media_session(id)) key = leg->key;
        if (const auto tunnel = ipcons_.find(id); tunnel != ipcons_.end()) {
          release_tunnel(tunnel->second, reason, "releases_server");
        } else if (intent ? !release_intent_media(key, {}, reason, query) : !originating_leg(key)) {
          event("mcdata_release_unknown", {{"id", id}});
        } else if (!intent) {
          release_communication(key, reason, "releases_server");
        }
      }
      // TS 24.282 clause 13.2.3.3.4: an operator releases a file transmission by policy.
      else if (command.starts_with("release ")) {
        const auto rest = command.substr(8);
        const auto space = rest.find(' ');
        if (!stop_transmission(rest.substr(0, space),
                               space == std::string::npos ? std::string{} : rest.substr(space + 1)))
          event("mcdata_file_stop_unknown", {{"message_id", rest.substr(0, space)}});
      }
    }
    tick();
  }
  for (int index = 0; index < 20; index++) sip_.poll(std::chrono::milliseconds(10));
  sip_.stop();
}

} // namespace mcx
