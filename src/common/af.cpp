//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

#include "mcx/af.hpp"
#include "mcx/h2.hpp"
#include "mcx/tls_profile.hpp"
#include <algorithm>
#include <atomic>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <functional>
#include <curl/curl.h>
#include <map>
#include <netinet/in.h>
#include <poll.h>
#include <random>
#include <regex>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace mcx::af {
namespace {
std::string trim_slash(std::string s) {
  while (!s.empty() && s.back() == '/') s.pop_back();
  return s;
}
bool valid_cidr(const std::string &cidr) {
  const auto slash = cidr.find('/');
  in_addr a{};
  if (inet_pton(AF_INET, cidr.substr(0, slash).c_str(), &a) != 1) return false;
  if (slash == std::string::npos) return true;
  const auto bits = cidr.substr(slash + 1);
  if (bits.empty() || bits.size() > 2 || !std::all_of(bits.begin(), bits.end(), ::isdigit)) return false;
  return std::stoi(bits) <= 32;
}
std::string bitrate(unsigned kbps) { return std::to_string(kbps) + " Kbps"; }
// TS 29.514 5.6.3.6: an RTCP-only sub-component carries flowUsage RTCP.
Json sub_component(unsigned number, const FlowPair &flow, const char *usage = "NO_INFO") {
  return {{"fNum", number}, {"fDescs", flow_descriptions(flow)}, {"fStatus", "ENABLED"}, {"flowUsage", usage}};
}
std::string random_hex() {
  static std::random_device device;
  static std::mt19937_64 engine(device());
  static std::uint64_t counter = 0;
  char text[40];
  std::snprintf(text, sizeof text, "%016llx%04llx", static_cast<unsigned long long>(engine()),
                static_cast<unsigned long long>(++counter & 0xffff));
  return text;
}
std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}
struct Exchange {
  std::string body;
  std::map<std::string, std::string> headers;
};
size_t on_body(char *p, size_t a, size_t b, void *ctx) {
  auto &s = static_cast<Exchange *>(ctx)->body;
  const size_t n = a * b;
  if (s.size() + n > 1048576) return 0;
  s.append(p, n);
  return n;
}
size_t on_header(char *p, size_t a, size_t b, void *ctx) {
  const size_t n = a * b;
  std::string line(p, n);
  const auto colon = line.find(':');
  if (colon != std::string::npos) {
    auto value = line.substr(colon + 1);
    const auto start = value.find_first_not_of(" \t");
    const auto end = value.find_last_not_of("\r\n \t");
    static_cast<Exchange *>(ctx)->headers[lower(line.substr(0, colon))] =
        start == std::string::npos ? std::string{} : value.substr(start, end - start + 1);
  }
  return n;
}
// The path part of an http URI ("http://host:port/a/b" -> "/a/b"), without a trailing '/'.
std::string uri_path(const std::string &uri) {
  const auto scheme = uri.find("://");
  const auto slash = uri.find('/', scheme == std::string::npos ? 0 : scheme + 3);
  return slash == std::string::npos ? std::string{} : trim_slash(uri.substr(slash));
}
}  // namespace

PcfConfig PcfConfig::parse(const Json &j) {
  PcfConfig c;
  if (!j.is_object()) throw std::runtime_error("pcf must be an object");
  c.enabled = j.value("enabled", false);
  c.pcf_uri = trim_slash(j.value("pcf_uri", std::string{}));
  c.nrf_uri = trim_slash(j.value("nrf_uri", std::string{}));

  // N5 is HTTP/2 only (TS 29.500 5.2.2.1); an old "http2": true is accepted.
  if (j.contains("http2") && !j.at("http2").get<bool>())
    throw std::runtime_error("pcf.http2: N5 uses HTTP/2 only (TS 29.500 5.2.2.1); remove \"http2\": false");
  c.dnn = j.value("dnn", c.dnn);
  if (j.contains("snssai")) {
    const auto &s = j.at("snssai");
    c.sst = s.value("sst", 1);
    c.sd = s.value("sd", std::string{});
  }
  c.af_app_id = j.value("af_app_id", c.af_app_id);
  c.supp_feat = j.value("supp_feat", c.supp_feat);
  c.notif_bind = j.value("notif_bind", c.notif_bind);
  c.notif_uri_base = trim_slash(j.value("notif_uri_base", std::string{}));
  c.ue_subnets = j.value("ue_subnets", std::vector<std::string>{});
  c.audio_bw_kbps = j.value("audio_bw_kbps", c.audio_bw_kbps);
  c.video_bw_kbps = j.value("video_bw_kbps", c.video_bw_kbps);
  c.required = j.value("required", false);
  c.release_on_terminate = j.value("release_on_terminate", false);
  c.timeout_ms = j.value("timeout_ms", c.timeout_ms);
  const auto prio_map = j.value("prio_map", Json::object());
  for (const auto &[name, value] : prio_map.items()) {
    if (name != "normal" && name != "imminent" && name != "emergency")
      throw std::runtime_error("pcf.prio_map keys are normal, imminent and emergency");
    c.prio_map[name] = value.get<std::string>();
  }
  static const std::regex prio("PRIO_([1-9]|1[0-6])");
  for (const auto &[name, value] : c.prio_map)
    if (!value.empty() && !std::regex_match(value, prio))
      throw std::runtime_error("pcf.prio_map values are PRIO_1 .. PRIO_16");
  for (const auto &cidr : c.ue_subnets)
    if (!valid_cidr(cidr)) throw std::runtime_error("invalid pcf.ue_subnets entry " + cidr);
  if (c.sst < 0 || c.sst > 255) throw std::runtime_error("invalid pcf.snssai.sst");
  if (!c.sd.empty() && !std::regex_match(c.sd, std::regex("[0-9a-fA-F]{6}")))
    throw std::runtime_error("invalid pcf.snssai.sd");
  if (!c.audio_bw_kbps || !c.timeout_ms) throw std::runtime_error("invalid pcf bandwidth or timeout");
  if (c.enabled && c.pcf_uri.empty() && c.nrf_uri.empty())
    throw std::runtime_error("pcf.enabled needs pcf_uri or nrf_uri");
  if (c.notif_bind.find(':') == std::string::npos) throw std::runtime_error("pcf.notif_bind is host:port");

  return c;
}

bool ipv4_in_cidr(std::string_view ip, std::string_view cidr) {
  const std::string text(cidr);
  const auto slash = text.find('/');
  in_addr address{}, network{};
  if (inet_pton(AF_INET, std::string(ip).c_str(), &address) != 1) return false;
  if (inet_pton(AF_INET, text.substr(0, slash).c_str(), &network) != 1) return false;
  int bits = 32;
  if (slash != std::string::npos) {
    if (!valid_cidr(text)) return false;
    bits = std::stoi(text.substr(slash + 1));
  }
  const std::uint32_t mask = bits == 0 ? 0 : 0xffffffffu << (32 - bits);
  return (ntohl(address.s_addr) & mask) == (ntohl(network.s_addr) & mask);
}
bool ipv4_in_subnets(std::string_view ip, const std::vector<std::string> &cidrs) {
  return std::any_of(cidrs.begin(), cidrs.end(), [&](const std::string &c) { return ipv4_in_cidr(ip, c); });
}
std::string ip_filter_rule(std::string_view src_ip, std::uint16_t src_port, std::string_view dst_ip, std::uint16_t dst_port) {
  return "permit out 17 from " + std::string(src_ip) + " " + std::to_string(src_port) + " to " + std::string(dst_ip) + " " +
         std::to_string(dst_port);
}
Json flow_descriptions(const FlowPair &f) {
  return Json::array({ip_filter_rule(f.server_ip, f.server_port, f.ue_ip, f.ue_port),
                      ip_filter_rule(f.ue_ip, f.ue_port, f.server_ip, f.server_port)});
}
Json media_components(const PcfConfig &cfg, const MediaFlows &flows) {
  Json audio = {{"medCompN", 1}, {"medType", "AUDIO"},
                {"marBwUl", bitrate(cfg.audio_bw_kbps)}, {"marBwDl", bitrate(cfg.audio_bw_kbps)},
                {"medSubComps", {{"1", sub_component(1, flows.rtp)}, {"2", sub_component(2, flows.rtcp, "RTCP")}}}};
  if (flows.floor) audio["medSubComps"]["3"] = sub_component(3, *flows.floor);
  Json components = {{"1", audio}};
  if (flows.video_rtp) {
    Json video = {{"medCompN", 2}, {"medType", "VIDEO"},
                  {"marBwUl", bitrate(cfg.video_bw_kbps)}, {"marBwDl", bitrate(cfg.video_bw_kbps)},
                  {"medSubComps", {{"1", sub_component(1, *flows.video_rtp)}}}};
    if (flows.video_rtcp) video["medSubComps"]["2"] = sub_component(2, *flows.video_rtcp, "RTCP");
    components["2"] = video;
  }
  return components;
}
std::optional<std::string> reservation_priority(const PcfConfig &cfg, const std::string &priority) {
  const auto it = cfg.prio_map.find(priority);
  if (it == cfg.prio_map.end() || it->second.empty()) return std::nullopt;
  return it->second;
}
Json create_body(const PcfConfig &cfg, const SessionRequest &r, const std::string &notif_uri) {
  Json slice = {{"sst", cfg.sst}};
  if (!cfg.sd.empty()) slice["sd"] = cfg.sd;
  Json data = {{"afAppId", cfg.af_app_id}, {"dnn", cfg.dnn}, {"sliceInfo", slice}, {"ueIpv4", r.ue_ipv4},
               {"notifUri", notif_uri}, {"suppFeat", cfg.supp_feat}, {r.id_attribute, r.mc_id},
               {"medComponents", media_components(cfg, r.flows)},
               {"evSubsc", {{"events", Json::array({{{"event", "FAILED_RESOURCES_ALLOCATION"}},
                                                    {{"event", "SUCCESSFUL_RESOURCES_ALLOCATION"}}})},
                            {"notifUri", notif_uri}}}};
  if (const auto prio = reservation_priority(cfg, r.priority)) data["resPrio"] = *prio;
  return {{"ascReqData", data}};
}
Json update_body(const PcfConfig &cfg, const SessionRequest &before, const SessionRequest &after) {
  Json data = Json::object();
  if (before.flows != after.flows) {
    data["medComponents"] = media_components(cfg, after.flows);
    // A component or sub-component that is gone is removed (RFC 7396 null).
    if (before.flows.video_rtp && !after.flows.video_rtp) data["medComponents"]["2"] = nullptr;
    if (before.flows.floor && !after.flows.floor) data["medComponents"]["1"]["medSubComps"]["3"] = nullptr;
  }
  const auto old_prio = reservation_priority(cfg, before.priority), new_prio = reservation_priority(cfg, after.priority);
  if (old_prio != new_prio) data["resPrio"] = new_prio ? Json(*new_prio) : Json(nullptr);
  if (data.empty()) return nullptr;
  return {{"ascReqData", data}};
}
std::string session_id_from_location(std::string_view location) {
  std::string s(location);
  if (const auto q = s.find_first_of("?#"); q != std::string::npos) s.resize(q);
  s = trim_slash(s);
  const auto slash = s.rfind('/');
  return slash == std::string::npos ? s : s.substr(slash + 1);
}
std::string pcf_from_search_result(const Json &result) {
  for (const auto &instance : result.value("nfInstances", Json::array())) {
    Json services = instance.value("nfServices", Json::array());
    if (services.empty() && instance.contains("nfServiceList"))
      for (const auto &[id, service] : instance.at("nfServiceList").items()) services.push_back(service);
    for (const auto &service : services) {
      if (service.value("serviceName", std::string{}) != "npcf-policyauthorization") continue;
      const auto scheme = service.value("scheme", std::string("http"));
      if (service.contains("apiPrefix")) return trim_slash(service.at("apiPrefix").get<std::string>());
      for (const auto &ep : service.value("ipEndPoints", Json::array()))
        if (ep.contains("ipv4Address"))
          return scheme + "://" + ep.at("ipv4Address").get<std::string>() + ":" + std::to_string(ep.value("port", 80));
      if (service.contains("fqdn")) return scheme + "://" + service.at("fqdn").get<std::string>();
    }
    const auto addresses = instance.value("ipv4Addresses", std::vector<std::string>{});
    if (!addresses.empty()) return "http://" + addresses.front();
  }
  return {};
}

Op Lifecycle::start() {
  if (state_ != State::idle) return Op::none;
  state_ = State::creating;
  return Op::create;
}
Op Lifecycle::change() {
  if (state_ == State::active) {
    state_ = State::updating;
    return Op::update;
  }
  if (state_ == State::creating || state_ == State::updating) dirty_ = true;
  return Op::none;
}
Op Lifecycle::settle() {
  if (stop_wanted_) {
    state_ = State::deleting;
    return Op::remove;
  }
  if (dirty_) {
    dirty_ = false;
    state_ = State::updating;
    return Op::update;
  }
  return Op::none;
}
Op Lifecycle::created(bool ok, std::string id) {
  if (state_ != State::creating) return Op::none;
  if (!ok) {
    dirty_ = false;
    state_ = stop_wanted_ ? State::released : State::failed;
    return Op::none;
  }
  id_ = std::move(id);
  state_ = State::active;
  return settle();
}
Op Lifecycle::updated(bool) {
  if (state_ != State::updating) return Op::none;
  state_ = State::active;
  return settle();
}
Op Lifecycle::removed() {
  if (state_ == State::deleting) state_ = State::released;
  return Op::none;
}
Op Lifecycle::stop() {
  switch (state_) {
  case State::idle:
  case State::failed:
    state_ = State::released;
    return Op::none;
  case State::active:
    state_ = State::deleting;
    return Op::remove;
  case State::creating:
  case State::updating:
    stop_wanted_ = true;
    return Op::none;
  default:
    return Op::none;
  }
}
const char *state_name(Lifecycle::State s) {
  switch (s) {
  case Lifecycle::State::idle: return "idle";
  case Lifecycle::State::creating: return "creating";
  case Lifecycle::State::active: return "active";
  case Lifecycle::State::updating: return "updating";
  case Lifecycle::State::deleting: return "deleting";
  case Lifecycle::State::released: return "released";
  case Lifecycle::State::failed: return "failed";
  }
  return "?";
}
const char *event_name(Event::Kind k) {
  switch (k) {
  case Event::Kind::created: return "pcf_app_session_created";
  case Event::Kind::create_failed: return "pcf_app_session_create_failed";
  case Event::Kind::updated: return "pcf_app_session_updated";
  case Event::Kind::update_failed: return "pcf_app_session_update_failed";
  case Event::Kind::deleted: return "pcf_app_session_deleted";
  case Event::Kind::delete_failed: return "pcf_app_session_delete_failed";
  case Event::Kind::notified: return "pcf_notification";
  case Event::Kind::terminated: return "pcf_termination_requested";
  }
  return "pcf_event";
}

PolicyAuthorizationClient::PolicyAuthorizationClient(PcfConfig cfg) : cfg_(std::move(cfg)) {
  if (cfg_.notif_uri_base.empty()) throw std::runtime_error("pcf.notif_uri_base is not set");
  curl_global_init(CURL_GLOBAL_DEFAULT);
  // The receiver's socket is bound here so that a bad notif_bind fails at startup.
  const auto colon = cfg_.notif_bind.rfind(':');
  const auto host = cfg_.notif_bind.substr(0, colon);
  const int port = std::stoi(cfg_.notif_bind.substr(colon + 1));
  sockaddr_in local{};
  local.sin_family = AF_INET;
  local.sin_port = htons(static_cast<std::uint16_t>(port));
  if (inet_pton(AF_INET, host.c_str(), &local.sin_addr) != 1) throw std::runtime_error("pcf.notif_bind needs an IPv4 address");
  listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  const int on = 1;
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
  if (listen_fd_ < 0 || ::bind(listen_fd_, reinterpret_cast<sockaddr *>(&local), sizeof local) < 0 ||
      ::listen(listen_fd_, 16) < 0) {
    const std::string reason = std::strerror(errno);
    if (listen_fd_ >= 0) ::close(listen_fd_);
    throw std::runtime_error("pcf notification receiver: " + reason);
  }
  worker_ = std::thread([this] { work(); });
  listener_ = std::thread([this] { listen(); });
}
PolicyAuthorizationClient::~PolicyAuthorizationClient() {
  {
    std::lock_guard lock(mutex_);
    stopping_ = true;
  }
  wake_.notify_all();
  if (worker_.joinable()) worker_.join();
  if (listener_.joinable()) listener_.join();
  if (listen_fd_ >= 0) ::close(listen_fd_);
}
std::string PolicyAuthorizationClient::notif_uri(const std::string &notif_id) const {
  return cfg_.notif_uri_base + "/" + notif_id;
}
void PolicyAuthorizationClient::open(const std::string &key, SessionRequest request) {
  if (const auto it = entries_.find(key); it != entries_.end()) {
    refresh(key, request);
    return;
  }
  auto &entry = entries_[key];
  entry.notif_id = random_hex();
  entry.desired = std::move(request);
  by_notif_[entry.notif_id] = key;
  opened_++;
  dispatch(key, entry, entry.life.start());
}
void PolicyAuthorizationClient::refresh(const std::string &key, const SessionRequest &request) {
  const auto it = entries_.find(key);
  if (it == entries_.end() || it->second.desired == request) return;
  it->second.desired = request;
  dispatch(key, it->second, it->second.life.change());
}
void PolicyAuthorizationClient::close(const std::string &key) {
  const auto it = entries_.find(key);
  if (it == entries_.end()) return;
  dispatch(key, it->second, it->second.life.stop());
  if (it->second.life.finished()) {
    by_notif_.erase(it->second.notif_id);
    entries_.erase(it);
  }
}
void PolicyAuthorizationClient::dispatch(const std::string &key, Entry &entry, Op op) {
  while (op == Op::update) {
    // Nothing to send when the change was undone before it could be sent.
    auto body = update_body(cfg_, entry.sent, entry.desired);
    if (!body.is_null()) {
      entry.inflight = entry.desired;
      std::lock_guard lock(mutex_);
      jobs_.push_back({key, Op::update, entry.life.id(), std::move(body)});
      wake_.notify_one();
      return;
    }
    op = entry.life.updated(true);
  }
  if (op == Op::none) return;
  Job job{key, op, entry.life.id(), nullptr};
  if (op == Op::create) {
    entry.inflight = entry.desired;
    job.body = create_body(cfg_, entry.desired, notif_uri(entry.notif_id));
  }
  std::lock_guard lock(mutex_);
  jobs_.push_back(std::move(job));
  wake_.notify_one();
}
std::vector<Event> PolicyAuthorizationClient::poll() {
  std::deque<Result> results;
  std::deque<Notification> notifications;
  {
    std::lock_guard lock(mutex_);
    results.swap(results_);
    notifications.swap(notifications_);
  }
  std::vector<Event> events;
  for (auto &r : results) {
    const auto it = entries_.find(r.key);
    if (it == entries_.end()) continue;
    auto &e = it->second;
    const bool ok = r.error.empty() && r.status >= 200 && r.status < 300;
    Event ev{Event::Kind::created, r.key, e.life.id(), r.error, r.status, r.body};
    if (r.op == Op::create) {
      const auto id = ok ? session_id_from_location(r.location) : std::string{};
      const bool created = ok && !id.empty();
      if (ok && id.empty()) ev.detail = "no Location header in the 201 response";
      ev.kind = created ? Event::Kind::created : Event::Kind::create_failed;
      ev.app_session_id = id;
      created ? created_++ : failed_++;
      if (created) e.sent = e.inflight;
      events.push_back(ev);
      dispatch(r.key, e, e.life.created(created, id));
    } else if (r.op == Op::update) {
      ev.kind = ok ? Event::Kind::updated : Event::Kind::update_failed;
      ok ? updated_++ : failed_++;
      // A refused update is not repeated; the next change is sent against it.
      e.sent = e.inflight;
      events.push_back(ev);
      dispatch(r.key, e, e.life.updated(ok));
    } else if (r.op == Op::remove) {
      ev.kind = ok || r.status == 404 ? Event::Kind::deleted : Event::Kind::delete_failed;
      if (ev.kind == Event::Kind::deleted) deleted_++; else failed_++;
      events.push_back(ev);
      e.life.removed();
    }
    if (e.life.finished()) {
      by_notif_.erase(e.notif_id);
      entries_.erase(it);
    }
  }
  for (auto &n : notifications) {
    if (n.kind == "rejected") {
      events.push_back({Event::Kind::notified, {}, {}, n.body.value("reason", std::string{}), 505, n.body});
      continue;
    }
    const auto found = by_notif_.find(n.notif_id);
    if (found == by_notif_.end()) continue;
    const auto key = found->second;
    auto &e = entries_.at(key);
    if (n.kind == "terminate") {
      terminated_++;
      events.push_back({Event::Kind::terminated, key, e.life.id(), n.body.value("termCause", std::string{}), 0, n.body});
      dispatch(key, e, e.life.terminated());
      if (e.life.finished()) {
        by_notif_.erase(e.notif_id);
        entries_.erase(key);
      }
    } else {
      notified_++;
      std::string what;
      for (const auto &item : n.body.value("evNotifs", Json::array()))
        what += (what.empty() ? "" : ",") + item.value("event", std::string{});
      events.push_back({Event::Kind::notified, key, e.life.id(), what, 0, n.body});
    }
  }

  return events;
}
std::vector<std::string> PolicyAuthorizationClient::keys() const {
  std::vector<std::string> out;
  for (const auto &[key, entry] : entries_) out.push_back(key);
  return out;
}
Json PolicyAuthorizationClient::status() const {
  Json sessions = Json::array();
  std::size_t active = 0;
  for (const auto &[key, e] : entries_) {
    const auto s = e.life.state();
    active += s == Lifecycle::State::active || s == Lifecycle::State::updating;
    sessions.push_back({{"dialog", key}, {"state", state_name(s)}, {"app_session_id", e.life.id()},
                        {"ue_ipv4", e.desired.ue_ipv4}, {"priority", e.desired.priority}});
  }
  return {{"enabled", true}, {"active", active}, {"sessions", sessions}, {"opened", opened_}, {"created", created_},
          {"updated", updated_}, {"deleted", deleted_}, {"failed", failed_}, {"notifications", notified_},
          {"terminations", terminated_}};
}
std::vector<Event> PolicyAuthorizationClient::shutdown(std::chrono::milliseconds wait) {
  for (const auto &key : keys()) close(key);
  std::vector<Event> events;
  const auto deadline = std::chrono::steady_clock::now() + wait;
  while (!entries_.empty() && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto more = poll();
    events.insert(events.end(), more.begin(), more.end());
  }
  return events;
}

std::string PolicyAuthorizationClient::pcf_root() {
  if (!cfg_.pcf_uri.empty()) return cfg_.pcf_uri;
  if (!discovered_.empty()) return discovered_;
  // TS 29.510 6.2.3.2.3.1: Nnrf_NFDiscovery for a PCF offering the service.
  Job query{"", Op::none, "", nullptr};
  auto r = perform(query);
  if (r.error.empty() && r.status == 200) discovered_ = trim_slash(pcf_from_search_result(r.body));
  return discovered_;
}
PolicyAuthorizationClient::Result PolicyAuthorizationClient::perform(const Job &job) {
  Result result{job.key, job.op, 0, {}, {}, nullptr};
  std::string url, method = "POST", type = "application/json", body;
  if (job.op == Op::none) {
    method = "GET";
    url = cfg_.nrf_uri + "/nnrf-disc/v1/nf-instances?target-nf-type=PCF&requester-nf-type=AF"
                         "&service-names=npcf-policyauthorization";
  } else {
    const auto root = pcf_root();
    if (root.empty()) {
      result.error = "no PCF: NRF discovery found none";
      return result;
    }
    url = root + "/npcf-policyauthorization/v1/app-sessions";
    if (job.op == Op::update) {
      method = "PATCH";
      type = "application/merge-patch+json";
      url += "/" + job.app_session_id;
    } else if (job.op == Op::remove) {
      url += "/" + job.app_session_id + "/delete";
    }
    if (!job.body.is_null()) body = job.body.dump();
  }
  if (!curl_) curl_ = curl_easy_init();
  auto *c = static_cast<CURL *>(curl_);
  if (!c) {
    result.error = "curl initialisation failed";
    return result;
  }
  curl_easy_reset(c);
  Exchange exchange;
  curl_slist *headers = nullptr;
  headers = curl_slist_append(headers, "Accept: application/json, application/problem+json");
  if (method != "GET") headers = curl_slist_append(headers, ("Content-Type: " + type).c_str());
  curl_easy_setopt(c, CURLOPT_URL, url.c_str());

  // HTTP/2 only (TS 29.500 5.2.2.1): prior knowledge over cleartext; over TLS
  // negotiated with ALPN, and an HTTP/1.1 answer is refused below.
  curl_easy_setopt(c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "http,https");
  // Over TLS, the 3GPP TLS profile: TS 33.210 clause 6.2 (mcx/tls_profile.hpp).
  curl_easy_setopt(c, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
  curl_easy_setopt(c, CURLOPT_SSL_CIPHER_LIST, tls_profile::tls12_ciphers);
  curl_easy_setopt(c, CURLOPT_SSL_EC_CURVES, tls_profile::groups);
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, static_cast<long>(cfg_.timeout_ms));
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(cfg_.timeout_ms));
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, on_body);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &exchange);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, on_header);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, &exchange);
  if (method == "GET") {
    curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
  } else {
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(c, CURLOPT_COPYPOSTFIELDS, body.c_str());
    if (method != "POST") curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
  }
  const auto code = curl_easy_perform(c);
  curl_slist_free_all(headers);
  if (code != CURLE_OK) {
    result.error = std::string(method) + " " + url + ": " + curl_easy_strerror(code);
    return result;
  }
  long version = 0;
  curl_easy_getinfo(c, CURLINFO_HTTP_VERSION, &version);
  if (version != CURL_HTTP_VERSION_2_0) {
    result.error = std::string(method) + " " + url + ": not answered over HTTP/2 (TS 29.500 5.2.2.1)";
    return result;
  }
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &result.status);
  if (const auto it = exchange.headers.find("location"); it != exchange.headers.end()) result.location = it->second;
  result.body = Json::parse(exchange.body, nullptr, false);
  if (result.body.is_discarded()) result.body = nullptr;
  if (result.status >= 300) {
    result.error = method + " " + url + ": HTTP " + std::to_string(result.status);
    if (result.body.is_object() && result.body.contains("detail"))
      result.error += " " + result.body.at("detail").dump();
  }

  return result;
}
void PolicyAuthorizationClient::work() {
  for (;;) {
    Job job;
    {
      std::unique_lock lock(mutex_);
      wake_.wait(lock, [this] { return stopping_ || !jobs_.empty(); });
      if (stopping_) break;
      job = std::move(jobs_.front());
      jobs_.pop_front();
    }
    Result result;
    try {
      result = perform(job);
    } catch (const std::exception &e) {
      result = {job.key, job.op, 0, {}, e.what(), nullptr};
    }
    std::lock_guard lock(mutex_);
    results_.push_back(std::move(result));
  }
  if (curl_) curl_easy_cleanup(static_cast<CURL *>(curl_));
  curl_ = nullptr;
}
// Npcf_PolicyAuthorization_Notify (TS 29.514 4.2.5): POST {notifUri}/notify
// (EventsNotification) and {notifUri}/terminate (TerminationInfo), answered 204.
int PolicyAuthorizationClient::receive(const std::string &method, std::string path, const std::string &body) {
  const auto base = uri_path(cfg_.notif_uri_base);
  if (const auto q = path.find('?'); q != std::string::npos) path.resize(q);
  if (!path.starts_with(base + "/")) return 404;
  const auto rest = path.substr(base.size() + 1);
  const auto slash = rest.find('/');
  const auto id = rest.substr(0, slash), kind = slash == std::string::npos ? "" : rest.substr(slash + 1);
  if (kind != "notify" && kind != "terminate") return 404;
  if (method != "POST") return 405;
  auto json = Json::parse(body, nullptr, false);
  if (json.is_discarded()) return 400;
  std::lock_guard lock(mutex_);
  notifications_.push_back({id, kind, std::move(json)});
  return 204;
}

// The notification receiver: HTTP/2 over cleartext with prior knowledge only, as
// on the SBI (TS 29.500 5.2.2.1). A connection that does not start with the
// HTTP/2 preface is refused (an HTTP/1.1 request gets 505) and reported.
void PolicyAuthorizationClient::listen() {
  const auto stopping = [this] {
    std::lock_guard lock(mutex_);
    return stopping_;
  };
  const h2::Handler handler = [this](const h2::Request &r) {
    return h2::Response{receive(r.method, r.path, r.body), {}, {}};
  };

  // Each connection is served on its own thread: a PCF may keep a connection open and open others (an HTTP/2 client
  // reuses or pools connections, TS 29.500 clause 5.2.2), so one idle connection must not hold the next notification
  // back. At most max_connections are served at once; a further one waits in the accept queue.
  constexpr std::size_t max_connections = 16;
  struct Served {
    std::thread thread;
    std::shared_ptr<std::atomic<bool>> done;
  };
  std::vector<Served> served;
  const auto reap = [&served] {
    for (auto it = served.begin(); it != served.end();) {
      if (*it->done) {
        it->thread.join();
        it = served.erase(it);
      } else {
        ++it;
      }
    }
  };
  const auto serve = [this, &handler, &stopping](int fd) {
    timeval timeout{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    std::string data;
    char buffer[4096];
    while (data.size() < h2::preface.size() && h2::preface.starts_with(data)) {
      const auto n = ::recv(fd, buffer, sizeof buffer, 0);
      if (n <= 0) break;
      data.append(buffer, static_cast<std::size_t>(n));
    }
    if (!h2::serve(fd, data, handler, stopping) && !data.empty()) {
      if (data.starts_with("POST ") || data.starts_with("GET ") || data.find(" HTTP/1.") != std::string::npos) {
        static const std::string reply =
            "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        (void)::send(fd, reply.data(), reply.size(), MSG_NOSIGNAL);
      }
      std::lock_guard lock(mutex_);
      notifications_.push_back(
          {"", "rejected", {{"reason", "not HTTP/2 (TS 29.500 5.2.2.1): " + data.substr(0, data.find('\r'))}}});
    }
    ::close(fd);
  };
  for (;;) {
    reap();
    if (stopping()) break;
    if (served.size() >= max_connections) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
      continue;
    }
    pollfd p{listen_fd_, POLLIN, 0};
    if (::poll(&p, 1, 200) <= 0) continue;
    const int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (fd < 0) continue;
    auto done = std::make_shared<std::atomic<bool>>(false);
    served.push_back({std::thread([serve, fd, done] {
                        serve(fd);
                        *done = true;
                      }),
                      done});
  }
  // Every connection ends within one poll interval of stopping (h2::serve checks it).
  for (auto &connection : served) connection.thread.join();
}
}  // namespace mcx::af
