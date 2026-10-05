#ifdef NDEBUG
#undef NDEBUG
#endif
// N5 AF (TS 29.514 Npcf_PolicyAuthorization): request bodies, the priority mapping,
// the 5G UE subnet test, the app session state machine, and the HTTP client and
// notification receiver against an in-process PCF, all over HTTP/2 with prior
// knowledge as on the SBI (TS 29.500 5.2.2.1); HTTP/1.1 is refused.
#include "mcx/af.hpp"
#include "mcx/h2.hpp"
#include <curl/curl.h>
#include <arpa/inet.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
using namespace mcx::af;
using namespace std::chrono_literals;

namespace {
MediaFlows flows(const std::string &ue = "12.1.1.5") {
  MediaFlows f;
  f.rtp = {"172.20.0.3", ue, 4000, 40000};
  f.rtcp = {"172.20.0.3", ue, 4001, 40001};
  f.floor = FlowPair{"172.20.0.3", ue, 5000, 50000};
  return f;
}
SessionRequest request(const std::string &priority = "normal") {
  SessionRequest r;
  r.ue_ipv4 = "12.1.1.5";
  r.mc_id = "sip:alice.mcptt@mcx.test";
  r.flows = flows();
  r.priority = priority;
  return r;
}
PcfConfig config() {
  return PcfConfig::parse(Json{{"enabled", true}, {"pcf_uri", "http://oai-pcf:8080/"}, {"notif_uri_base", "http://af:8099/n5"},
                               {"ue_subnets", {"12.1.1.0/24"}}, {"snssai", {{"sst", 1}, {"sd", "FFFFFF"}}}});
}

void test_config() {
  const auto c = config();
  assert(c.enabled && c.pcf_uri == "http://oai-pcf:8080" && c.dnn == "mcptt" && c.af_app_id == "mcptt");
  assert(c.supp_feat == "0" && c.audio_bw_kbps == 41 && !c.required && c.notif_bind == "0.0.0.0:8099");
  assert(c.sst == 1 && c.sd == "FFFFFF");
  const auto disabled = PcfConfig::parse(Json::object());
  assert(!disabled.enabled);
  auto bad = [](Json j) {
    try { PcfConfig::parse(j); } catch (const std::exception &) { return true; }
    return false;
  };
  assert(bad({{"enabled", true}}));  // no PCF and no NRF
  assert(bad({{"ue_subnets", {"12.1.1.0/33"}}}));
  assert(bad({{"ue_subnets", {"not-an-ip"}}}));
  assert(bad({{"prio_map", {{"emergency", "PRIO_17"}}}}));
  assert(bad({{"prio_map", {{"urgent", "PRIO_1"}}}}));
  assert(bad({{"snssai", {{"sst", 1}, {"sd", "12"}}}}));
  assert(bad({{"http2", false}}));  // N5 is HTTP/2 only
  assert(!bad({{"http2", true}}));
  const auto custom = PcfConfig::parse({{"prio_map", {{"normal", "PRIO_1"}, {"emergency", "PRIO_15"}}}});
  assert(custom.prio_map.at("normal") == "PRIO_1" && custom.prio_map.at("imminent") == "PRIO_12" &&
         custom.prio_map.at("emergency") == "PRIO_15");
}

void test_subnets() {
  assert(ipv4_in_cidr("12.1.1.5", "12.1.1.0/24"));
  assert(!ipv4_in_cidr("12.1.2.5", "12.1.1.0/24"));
  assert(ipv4_in_cidr("10.200.3.4", "10.0.0.0/8"));
  assert(ipv4_in_cidr("1.2.3.4", "0.0.0.0/0"));
  assert(ipv4_in_cidr("12.1.1.5", "12.1.1.5"));
  assert(!ipv4_in_cidr("12.1.1.6", "12.1.1.5/32"));
  assert(!ipv4_in_cidr("mcx-server", "0.0.0.0/0"));
  assert(!ipv4_in_cidr("12.1.1.5", "12.1.1.0/x"));
  assert(ipv4_in_subnets("172.20.0.9", {"12.1.1.0/24", "172.20.0.0/16"}));
  assert(!ipv4_in_subnets("172.21.0.9", {"12.1.1.0/24", "172.20.0.0/16"}));
  assert(!ipv4_in_subnets("12.1.1.5", {}));
}

void test_bodies() {
  const auto c = config();
  assert(ip_filter_rule("172.20.0.3", 4000, "12.1.1.5", 40000) == "permit out 17 from 172.20.0.3 4000 to 12.1.1.5 40000");
  const auto fd = flow_descriptions(flows().floor.value());
  assert(fd.size() == 2 && fd[0] == "permit out 17 from 172.20.0.3 5000 to 12.1.1.5 50000" &&
         fd[1] == "permit out 17 from 12.1.1.5 50000 to 172.20.0.3 5000");

  const auto body = create_body(c, request(), "http://af:8099/n5/abc");
  const auto &d = body.at("ascReqData");
  assert(d.at("afAppId") == "mcptt" && d.at("dnn") == "mcptt" && d.at("ueIpv4") == "12.1.1.5");
  assert(d.at("sliceInfo") == Json({{"sst", 1}, {"sd", "FFFFFF"}}));
  assert(d.at("notifUri") == "http://af:8099/n5/abc" && d.at("suppFeat") == "0");
  assert(d.at("mcpttId") == "sip:alice.mcptt@mcx.test");
  assert(!d.contains("resPrio"));  // normal priority: none by default
  const auto &mc = d.at("medComponents").at("1");
  assert(mc.at("medCompN") == 1 && mc.at("medType") == "AUDIO" && mc.at("marBwUl") == "41 Kbps" && mc.at("marBwDl") == "41 Kbps");
  const auto &subs = mc.at("medSubComps");
  assert(subs.size() == 3);
  for (const auto *n : {"1", "2", "3"}) {
    const auto &s = subs.at(n);
    assert(s.at("fNum") == std::stoi(n) && s.at("fStatus") == "ENABLED" && s.at("flowUsage") == (std::string(n) == "2" ? "RTCP" : "NO_INFO") &&
           s.at("fDescs").size() == 2);
  }
  assert(subs.at("1").at("fDescs")[0] == "permit out 17 from 172.20.0.3 4000 to 12.1.1.5 40000");
  assert(subs.at("2").at("fDescs")[1] == "permit out 17 from 12.1.1.5 40001 to 172.20.0.3 4001");
  assert(subs.at("3").at("fDescs")[0] == "permit out 17 from 172.20.0.3 5000 to 12.1.1.5 50000");
  const auto &ev = d.at("evSubsc");
  assert(ev.at("notifUri") == "http://af:8099/n5/abc" && ev.at("events").size() == 2);
  assert(ev.at("events")[0].at("event") == "FAILED_RESOURCES_ALLOCATION");
  assert(ev.at("events")[1].at("event") == "SUCCESSFUL_RESOURCES_ALLOCATION");

  // The priority mapping (TS 29.514 ReservPriority).
  assert(!reservation_priority(c, "normal"));
  assert(reservation_priority(c, "imminent") == "PRIO_12");
  assert(reservation_priority(c, "emergency") == "PRIO_16");
  assert(create_body(c, request("emergency"), "x").at("ascReqData").at("resPrio") == "PRIO_16");
  // MCVideo: mcVideoId and a video component.
  auto video = request();
  video.id_attribute = "mcVideoId";
  video.flows.video_rtp = FlowPair{"172.20.0.3", "12.1.1.5", 6000, 60000};
  video.flows.video_rtcp = FlowPair{"172.20.0.3", "12.1.1.5", 6001, 60001};
  const auto vb = create_body(c, video, "x").at("ascReqData");
  assert(vb.contains("mcVideoId") && !vb.contains("mcpttId"));
  assert(vb.at("medComponents").at("2").at("medType") == "VIDEO" && vb.at("medComponents").at("2").at("medSubComps").size() == 2);
  // No floor control: RTP and RTCP only.
  auto uncontrolled = request();
  uncontrolled.flows.floor.reset();
  assert(create_body(c, uncontrolled, "x").at("ascReqData").at("medComponents").at("1").at("medSubComps").size() == 2);

  // Updates: priority only, media only, nothing.
  assert(update_body(c, request(), request()).is_null());
  const auto up = update_body(c, request(), request("emergency"));
  assert(up == Json({{"ascReqData", {{"resPrio", "PRIO_16"}}}}));
  const auto down = update_body(c, request("emergency"), request());
  assert(down.at("ascReqData").at("resPrio").is_null() && !down.at("ascReqData").contains("medComponents"));
  assert(update_body(c, request("imminent"), request("emergency")).at("ascReqData").at("resPrio") == "PRIO_16");
  auto moved = request();
  moved.flows.rtp.ue_port = 40010;
  const auto media = update_body(c, request(), moved);
  assert(media.at("ascReqData").at("medComponents").at("1").at("medSubComps").at("1").at("fDescs")[0] ==
         "permit out 17 from 172.20.0.3 4000 to 12.1.1.5 40010");
  assert(!media.at("ascReqData").contains("resPrio"));
  assert(update_body(c, request(), uncontrolled).at("ascReqData").at("medComponents").at("1").at("medSubComps").at("3").is_null());

  assert(session_id_from_location("http://pcf:8080/npcf-policyauthorization/v1/app-sessions/42") == "42");
  assert(session_id_from_location("/npcf-policyauthorization/v1/app-sessions/abc-1/") == "abc-1");
  assert(session_id_from_location("abc") == "abc");

  const Json search = {{"nfInstances", {{{"nfInstanceId", "x"}, {"nfType", "PCF"}, {"ipv4Addresses", {"10.0.0.9"}},
                                         {"nfServices", {{{"serviceName", "npcf-smpolicycontrol"}},
                                                         {{"serviceName", "npcf-policyauthorization"}, {"scheme", "http"},
                                                          {"ipEndPoints", {{{"ipv4Address", "10.0.0.9"}, {"port", 8080}}}}}}}}}}};
  assert(pcf_from_search_result(search) == "http://10.0.0.9:8080");
  assert(pcf_from_search_result(Json::object()).empty());
}

void test_lifecycle() {
  using S = Lifecycle::State;
  {  // create, update, delete
    Lifecycle l;
    assert(l.start() == Op::create && l.state() == S::creating);
    assert(l.start() == Op::none);
    assert(l.created(true, "7") == Op::none && l.state() == S::active && l.id() == "7");
    assert(l.change() == Op::update && l.state() == S::updating);
    assert(l.change() == Op::none);  // queued behind the update in flight
    assert(l.updated(true) == Op::update);
    assert(l.updated(true) == Op::none && l.state() == S::active);
    assert(l.stop() == Op::remove && l.state() == S::deleting);
    assert(l.stop() == Op::none);  // idempotent
    assert(l.removed() == Op::none && l.finished());
    assert(l.stop() == Op::none && l.finished());
  }
  {  // hung up while the create is in flight: delete once it is answered
    Lifecycle l;
    l.start();
    assert(l.stop() == Op::none && !l.finished());
    assert(l.created(true, "8") == Op::remove && l.state() == S::deleting);
    l.removed();
    assert(l.finished());
  }
  {  // a change during the create is sent after it
    Lifecycle l;
    l.start();
    l.change();
    assert(l.created(true, "9") == Op::update);
  }
  {  // a stop wins over a pending change
    Lifecycle l;
    l.start();
    l.change();
    l.stop();
    assert(l.created(true, "9") == Op::remove);
  }
  {  // create refused: nothing to delete
    Lifecycle l;
    l.start();
    assert(l.created(false, "") == Op::none && l.state() == S::failed);
    assert(l.change() == Op::none);
    assert(l.stop() == Op::none && l.finished());
  }
  {  // create refused after the leg ended
    Lifecycle l;
    l.start();
    l.stop();
    assert(l.created(false, "") == Op::none && l.finished());
  }
  {  // stopped before it started
    Lifecycle l;
    assert(l.stop() == Op::none && l.finished());
    assert(l.start() == Op::none);
  }
  {  // PCF-initiated termination: the AF deletes (TS 29.514 4.2.5.3)
    Lifecycle l;
    l.start();
    l.created(true, "1");
    assert(l.terminated() == Op::remove);
    assert(l.stop() == Op::none);
  }
  {  // stop while an update is in flight
    Lifecycle l;
    l.start();
    l.created(true, "2");
    l.change();
    assert(l.stop() == Op::none);
    assert(l.updated(false) == Op::remove);
  }
}

int free_port() {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ::bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof a);
  socklen_t n = sizeof a;
  ::getsockname(fd, reinterpret_cast<sockaddr *>(&a), &n);
  ::close(fd);
  return ntohs(a.sin_port);
}

// An HTTP/2 PCF (prior knowledge): 201 with a Location for a create (503 while
// failing), 200 for a PATCH, 204 for a delete; it records "METHOD path body".
struct MockPcf {
  int fd = -1, port = 0;
  std::atomic<bool> stop{false}, fail_create{false};
  std::mutex mutex;
  std::vector<std::string> requests;
  std::thread thread;
  int next = 1;
  MockPcf() {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    assert(::bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof a) == 0);
    socklen_t n = sizeof a;
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&a), &n);
    port = ntohs(a.sin_port);
    ::listen(fd, 8);
    thread = std::thread([this] { run(); });
  }
  ~MockPcf() {
    stop = true;
    thread.join();
    ::close(fd);
  }
  mcx::h2::Response answer(const mcx::h2::Request &r) {
    {
      std::lock_guard lock(mutex);
      requests.push_back(r.method + " " + r.path + " " + r.body);
    }
    if (r.method == "POST" && r.path == "/npcf-policyauthorization/v1/app-sessions") {
      if (fail_create) return {503, {}, {}};
      return {201,
              {{"location", "http://127.0.0.1:" + std::to_string(port) + "/npcf-policyauthorization/v1/app-sessions/s" +
                                std::to_string(next++)},
               {"content-type", "application/json"}},
              "{}"};
    }
    if (r.method == "PATCH") return {200, {{"content-type", "application/json"}}, "{}"};
    return {204, {}, {}};
  }
  void run() {
    const mcx::h2::Handler handler = [this](const mcx::h2::Request &r) { return answer(r); };
    while (!stop) {
      pollfd p{fd, POLLIN, 0};
      if (::poll(&p, 1, 50) <= 0) continue;
      const int c = ::accept(fd, nullptr, nullptr);
      std::string data;
      char buf[4096];
      while (data.size() < mcx::h2::preface.size()) {
        const auto r = ::recv(c, buf, sizeof buf, 0);
        if (r <= 0) break;
        data.append(buf, r);
      }
      mcx::h2::serve(c, data, handler, [this] { return stop.load(); }, 500);
      ::close(c);
    }
  }
  std::vector<std::string> seen() {
    std::lock_guard lock(mutex);
    return requests;
  }
};

std::vector<Event> pump(PolicyAuthorizationClient &client, std::size_t want, std::vector<Event> sofar = {}) {
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (sofar.size() < want && std::chrono::steady_clock::now() < deadline) {
    for (auto &e : client.poll()) sofar.push_back(e);
    std::this_thread::sleep_for(5ms);
  }
  return sofar;
}

int post(int port, const std::string &path, const std::string &body) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  assert(::connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof a) == 0);
  const auto request = "POST " + path + " HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: " +
                       std::to_string(body.size()) + "\r\n\r\n" + body;
  ::send(fd, request.data(), request.size(), 0);
  char buf[512] = {};
  const auto n = ::recv(fd, buf, sizeof buf - 1, 0);
  ::close(fd);
  assert(n > 12);
  return std::atoi(buf + 9);
}

// POSTs over HTTP/2 with prior knowledge, all on one connection, as a PCF's SBI
// client does; the status of each request.
std::vector<long> post_h2(int port, const std::vector<std::pair<std::string, std::string>> &requests) {
  std::vector<long> statuses;
  CURL *c = curl_easy_init();
  assert(c);
  curl_slist *headers = curl_slist_append(nullptr, "Content-Type: application/json");
  for (const auto &[path, body] : requests) {
    const auto url = "http://127.0.0.1:" + std::to_string(port) + path;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, 3000L);
    long status = 0, version = 0;
    assert(curl_easy_perform(c) == CURLE_OK);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_getinfo(c, CURLINFO_HTTP_VERSION, &version);
    assert(version == CURL_HTTP_VERSION_2_0);
    statuses.push_back(status);
  }
  long connects = -1;
  curl_easy_getinfo(c, CURLINFO_NUM_CONNECTS, &connects);
  assert(connects == 0);  // the last request reused the connection
  curl_slist_free_all(headers);
  curl_easy_cleanup(c);
  return statuses;
}

void test_client() {
  MockPcf pcf;
  const int notif = free_port();
  auto cfg = PcfConfig::parse({{"enabled", true}, {"pcf_uri", "http://127.0.0.1:" + std::to_string(pcf.port)}, 
                               {"notif_bind", "127.0.0.1:" + std::to_string(notif)},
                               {"notif_uri_base", "http://127.0.0.1:" + std::to_string(notif) + "/n5"},
                               {"ue_subnets", {"12.1.1.0/24"}}});
  PolicyAuthorizationClient client(cfg);
  assert(client.covers("12.1.1.5") && !client.covers("172.20.0.5"));

  // Create, then a priority upgrade while the create may still be in flight.
  client.open("dialog-1", request());
  client.refresh("dialog-1", request("emergency"));
  auto events = pump(client, 2);
  assert(events.size() == 2 && events[0].kind == Event::Kind::created && events[0].app_session_id == "s1");
  assert(events[1].kind == Event::Kind::updated);
  auto seen = pcf.seen();
  assert(seen.size() == 2);
  assert(seen[0].starts_with("POST /npcf-policyauthorization/v1/app-sessions {"));
  const auto created = Json::parse(seen[0].substr(seen[0].find('{')));
  assert(created.at("ascReqData").at("ueIpv4") == "12.1.1.5");
  const auto notif_uri = created.at("ascReqData").at("notifUri").get<std::string>();
  assert(notif_uri.starts_with("http://127.0.0.1:" + std::to_string(notif) + "/n5/"));
  assert(seen[1] == "PATCH /npcf-policyauthorization/v1/app-sessions/s1 {\"ascReqData\":{\"resPrio\":\"PRIO_16\"}}");
  assert(client.status().at("active") == 1);

  // Notifications over HTTP/2 (TS 29.500 5.2.2.1), three requests on one
  // connection: an event report, a wrong path, then a termination, which the AF
  // answers with a delete.
  const auto path = notif_uri.substr(notif_uri.find("/n5/"));
  const auto answers =
      post_h2(notif, {{path + "/notify", R"({"evSubsUri":"x","evNotifs":[{"event":"FAILED_RESOURCES_ALLOCATION"}]})"},
                      {"/elsewhere/x/notify", "{}"},
                      {path + "/terminate", R"({"termCause":"ALL_SDF_DEACTIVATION","resUri":"x"})"}});
  assert(answers.size() == 3 && answers[0] == 204 && answers[1] == 404 && answers[2] == 204);
  events = pump(client, 3);
  assert(events.size() == 3 && events[0].kind == Event::Kind::notified && events[0].key == "dialog-1" &&
         events[0].detail == "FAILED_RESOURCES_ALLOCATION");
  assert(events[1].kind == Event::Kind::terminated && events[1].detail == "ALL_SDF_DEACTIVATION" &&
         events[2].kind == Event::Kind::deleted);
  // HTTP/1.1 is refused (505) and reported.
  assert(post(notif, path + "/notify", "{}") == 505);
  events = pump(client, 1);
  assert(events.size() == 1 && events[0].kind == Event::Kind::notified && events[0].status == 505);
  // A PCF keeps a connection open while it opens another (TS 29.500 5.2.2): an idle HTTP/2 connection must not hold
  // back a notification on a second one (the receiver otherwise ends an idle connection only after 5 s).
  {
    const int idle = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(static_cast<std::uint16_t>(notif));
    inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    assert(::connect(idle, reinterpret_cast<sockaddr *>(&to), sizeof to) == 0);
    const std::string hello = std::string(mcx::h2::preface) + std::string("\0\0\0\4\0\0\0\0\0", 9);  // empty SETTINGS
    assert(::send(idle, hello.data(), hello.size(), 0) == static_cast<ssize_t>(hello.size()));
    std::this_thread::sleep_for(100ms);
    const auto started = std::chrono::steady_clock::now();
    CURL *c = curl_easy_init();
    const auto url = "http://127.0.0.1:" + std::to_string(notif) + path + "/notify";
    curl_slist *headers = curl_slist_append(nullptr, "Content-Type: application/json");
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, R"({"evSubsUri":"x","evNotifs":[]})");
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, 3000L);
    long status = 0;
    const auto result = curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(c);
    const auto took = std::chrono::steady_clock::now() - started;
    assert(result == CURLE_OK && status == 204 && took < 1500ms);
    ::close(idle);
  }
  assert(pcf.seen().back() == "POST /npcf-policyauthorization/v1/app-sessions/s1/delete ");
  assert(!client.tracking("dialog-1"));
  client.close("dialog-1");  // the leg's own teardown afterwards: nothing more is sent
  std::this_thread::sleep_for(50ms);
  assert(pcf.seen().size() == 3);

  // Hang-up immediately after the confirm: one create, one delete.
  client.open("dialog-2", request());
  client.close("dialog-2");
  client.close("dialog-2");
  events = pump(client, 2);
  assert(events.size() == 2 && events[0].kind == Event::Kind::created && events[1].kind == Event::Kind::deleted);
  assert(pcf.seen().back() == "POST /npcf-policyauthorization/v1/app-sessions/s2/delete ");
  assert(client.keys().empty());

  // A refused create: reported, and no delete follows.
  pcf.fail_create = true;
  client.open("dialog-3", request());
  events = pump(client, 1);
  assert(events.size() == 1 && events[0].kind == Event::Kind::create_failed && events[0].status == 503);
  client.close("dialog-3");
  std::this_thread::sleep_for(50ms);
  assert(pcf.seen().back().starts_with("POST /npcf-policyauthorization/v1/app-sessions {"));
  assert(client.keys().empty());
  pcf.fail_create = false;

  // Shutdown deletes what is left.
  client.open("dialog-4", request());
  pump(client, 1);
  client.shutdown(2s);
  assert(client.keys().empty() && pcf.seen().back() == "POST /npcf-policyauthorization/v1/app-sessions/s3/delete ");
  const auto st = client.status();
  assert(st.at("created") == 3 && st.at("deleted") == 3 && st.at("failed") == 1 && st.at("terminations") == 1);
}

void test_unreachable() {
  // Nothing listens: the create fails within the timeout and the caller is not blocked.
  const int notif = free_port();
  auto cfg = PcfConfig::parse({{"enabled", true}, {"pcf_uri", "http://127.0.0.1:" + std::to_string(free_port())},
                               {"notif_bind", "127.0.0.1:" + std::to_string(notif)}, {"timeout_ms", 300},
                               {"notif_uri_base", "http://127.0.0.1:" + std::to_string(notif)}});
  PolicyAuthorizationClient client(cfg);
  const auto began = std::chrono::steady_clock::now();
  client.open("d", request());
  assert(std::chrono::steady_clock::now() - began < 50ms);
  const auto events = pump(client, 1);
  assert(events.size() == 1 && events[0].kind == Event::Kind::create_failed && !events[0].detail.empty());
}
}  // namespace

int main() {
  test_config();
  test_subnets();
  test_bodies();
  test_lifecycle();
  test_client();
  test_unreachable();
  std::cout << "af tests passed\n";
}
