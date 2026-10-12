//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

#pragma once
// The MC service server in the 5GC AF role on N5 (TS 23.379 / TS 23.280 MC service
// over 5GS, TS 23.289 5.4-5.6): it asks the PCF to authorise QoS for the media of a
// call leg with Npcf_PolicyAuthorization (TS 29.514), whose PCC rule the PCF binds
// to the UE's PDU session (TS 23.503 6.1.3). The flows are the leg's RTP, RTCP and
// floor control (TS 24.380); TS 23.501 5.7.4 standardises 5QI 65 for MCPTT voice
// and 5QI 69 for MC signalling, which the default QoS flow carries, so only the
// media is requested here. The PCF chooses the 5QI and ARP; the AF names the flows,
// the bandwidth and the reservation priority (TS 29.513 clause 7 maps them to QoS at the PCF).
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace mcx::af {
using Json = nlohmann::json;

// The "pcf" block of the mcx-server configuration.
struct PcfConfig {
  bool enabled = false;
  // Static PCF (http://host:port), or empty with nrf_uri for NRF discovery
  // (TS 29.510 Nnrf_NFDiscovery, target-nf-type=PCF).
  std::string pcf_uri, nrf_uri;
  std::string dnn = "mcptt";
  int sst = 1;
  std::string sd;  // empty: no "sd"
  std::string af_app_id = "mcptt";
  std::string supp_feat = "0";
  // Notification receiver (HTTP/2 with prior knowledge): bind address and the URI the PCF is given.
  std::string notif_bind = "0.0.0.0:8099", notif_uri_base;
  // Only legs whose UE address is in one of these IPv4 prefixes are 5G UEs.
  std::vector<std::string> ue_subnets;
  // Maximum requested bandwidth of the audio component, each direction (AMR-WB
  // 23.85 kbit/s with IPv4/UDP/RTP overhead at 50 packets/s is about 41 kbit/s).
  unsigned audio_bw_kbps = 41, video_bw_kbps = 1024;
  // required: a leg whose QoS the PCF does not authorise is released.
  bool required = false;
  // release_on_terminate: a PCF-initiated termination also releases the leg.
  bool release_on_terminate = false;
  unsigned timeout_ms = 2000;
  // Call priority -> ReservPriority (TS 29.514 5.6.3.x: PRIO_1 lowest .. PRIO_16).
  // An empty value sends no resPrio.
  std::map<std::string, std::string> prio_map{{"normal", ""}, {"imminent", "PRIO_12"}, {"emergency", "PRIO_16"}};
  static PcfConfig parse(const Json &);
};

// One media flow of a leg: the server's and the UE's address and port.
struct FlowPair {
  std::string server_ip, ue_ip;
  std::uint16_t server_port = 0, ue_port = 0;
  bool operator==(const FlowPair &) const = default;
};
struct MediaFlows {
  FlowPair rtp, rtcp;
  std::optional<FlowPair> floor;                    // TS 24.380 floor control
  std::optional<FlowPair> video_rtp, video_rtcp;    // MCVideo only
  bool operator==(const MediaFlows &) const = default;
};
// What one app session asks for.
struct SessionRequest {
  std::string ue_ipv4, mc_id;
  std::string id_attribute = "mcpttId";  // "mcVideoId" for an MCVideo server
  MediaFlows flows;
  std::string priority = "normal";       // "normal", "imminent" or "emergency"
  // The Resource-Priority value provisioned for that priority (TS 24.379 clause 6.3.3.1.19), e.g. "mcpttp.15";
  // empty when none is provisioned. Rx derives MCPTT-Identifier and Reservation-Priority from it (TS 29.214
  // annex A.13.2).
  std::string resource_priority;
  bool operator==(const SessionRequest &) const = default;
};

bool ipv4_in_cidr(std::string_view ip, std::string_view cidr);
bool ipv4_in_subnets(std::string_view ip, const std::vector<std::string> &cidrs);
// TS 29.514 FlowDescription: an IPFilterRule (RFC 6733 4.3.1) as TS 29.214 5.4.2.
std::string ip_filter_rule(std::string_view src_ip, std::uint16_t src_port, std::string_view dst_ip, std::uint16_t dst_port);
// Downlink (server to UE) then uplink (UE to server).
Json flow_descriptions(const FlowPair &);
Json media_components(const PcfConfig &, const MediaFlows &);
std::optional<std::string> reservation_priority(const PcfConfig &, const std::string &priority);
// AppSessionContext for Npcf_PolicyAuthorization_Create.
Json create_body(const PcfConfig &, const SessionRequest &, const std::string &notif_uri);
// AppSessionContextUpdateDataPatch (application/merge-patch+json); null when nothing changed.
Json update_body(const PcfConfig &, const SessionRequest &before, const SessionRequest &after);
// The appSessionId: the last path segment of the Location header.
std::string session_id_from_location(std::string_view location);
// The npcf-policyauthorization apiRoot from an NRF SearchResult; empty if none.
std::string pcf_from_search_result(const Json &);

// The life of one app session, independent of HTTP: what to send next.
enum class Op { none, create, update, remove };
class Lifecycle {
public:
  enum class State { idle, creating, active, updating, deleting, released, failed };
  Op start();                         // the leg is up
  Op change();                        // what the session asks for changed
  Op created(bool ok, std::string id);
  Op updated(bool ok);
  Op removed();                       // delete answered (or failed): gone either way
  Op stop();                          // the leg is gone; idempotent
  Op terminated() { return stop(); }  // PCF-initiated (TS 29.514 4.2.5.3): delete
  State state() const { return state_; }
  const std::string &id() const { return id_; }
  bool finished() const { return state_ == State::released; }

private:
  Op settle();
  State state_ = State::idle;
  std::string id_;
  bool dirty_ = false, stop_wanted_ = false;
};
const char *state_name(Lifecycle::State);

struct Event {
  enum class Kind { created, create_failed, updated, update_failed, deleted, delete_failed, notified, terminated };
  Kind kind;
  std::string key, app_session_id, detail;
  long status = 0;
  Json body;
};
const char *event_name(Event::Kind);

// The MC service server as AF towards the policy control of one access (TS 24.379 clause 4.13: Rx for 4G and 5G,
// N5 for 5G): one policy session per call leg whose UE is on that access, keyed by the leg's dialog. Every call
// comes from the owning (SIP) thread; poll() hands the results back to it.
class PolicyClient {
public:
  virtual ~PolicyClient() = default;
  // "pcf" (N5) or "rx": the prefix of the client's events and its status entry.
  virtual const char *interface_name() const = 0;
  virtual const char *event_name(Event::Kind) const = 0;
  // Whether a UE address is on the access this client serves.
  virtual bool covers(std::string_view ue_ip) const = 0;
  // required: a leg whose QoS is not authorised is released; release_on_terminate: so is a leg whose policy
  // session the network terminates.
  virtual bool required() const = 0;
  virtual bool release_on_terminate() const = 0;
  virtual bool tracking(const std::string &key) const = 0;
  virtual void open(const std::string &key, SessionRequest) = 0;
  virtual void refresh(const std::string &key, const SessionRequest &) = 0;
  virtual void close(const std::string &key) = 0;
  virtual std::vector<Event> poll() = 0;
  virtual std::vector<std::string> keys() const = 0;
  virtual Json status() const = 0;
  // Ends every policy session and waits for the answers until the deadline.
  virtual std::vector<Event> shutdown(std::chrono::milliseconds) = 0;
};

// Npcf_PolicyAuthorization client. Every call from the owning (SIP) thread only
// queues work: HTTP runs on a worker thread, the notification receiver on another,
// and poll() hands their results back to the owning thread.
class PolicyAuthorizationClient : public PolicyClient {
public:
  explicit PolicyAuthorizationClient(PcfConfig);
  ~PolicyAuthorizationClient() override;
  PolicyAuthorizationClient(const PolicyAuthorizationClient &) = delete;
  PolicyAuthorizationClient &operator=(const PolicyAuthorizationClient &) = delete;
  const PcfConfig &config() const { return cfg_; }
  const char *interface_name() const override { return "pcf"; }
  const char *event_name(Event::Kind kind) const override { return af::event_name(kind); }
  bool covers(std::string_view ue_ip) const override { return ipv4_in_subnets(ue_ip, cfg_.ue_subnets); }
  bool required() const override { return cfg_.required; }
  bool release_on_terminate() const override { return cfg_.release_on_terminate; }
  bool tracking(const std::string &key) const override { return entries_.contains(key); }
  void open(const std::string &key, SessionRequest) override;
  void refresh(const std::string &key, const SessionRequest &) override;
  void close(const std::string &key) override;
  std::vector<Event> poll() override;
  std::vector<std::string> keys() const override;
  Json status() const override;
  std::vector<Event> shutdown(std::chrono::milliseconds) override;

private:
  struct Entry {
    Lifecycle life;
    SessionRequest desired, sent, inflight;
    std::string notif_id;
  };
  struct Job {
    std::string key;
    Op op;
    std::string app_session_id;
    Json body;
  };
  struct Result {
    std::string key;
    Op op;
    long status = 0;
    std::string location, error;
    Json body;
  };
  struct Notification {
    std::string notif_id, kind;
    Json body;
  };
  void dispatch(const std::string &key, Entry &, Op);
  void work();
  void listen();
  int receive(const std::string &method, std::string path, const std::string &body);
  Result perform(const Job &);
  std::string pcf_root();
  std::string notif_uri(const std::string &notif_id) const;

  PcfConfig cfg_;
  std::map<std::string, Entry> entries_;
  std::map<std::string, std::string> by_notif_;  // notif_id -> key
  std::uint64_t opened_ = 0, created_ = 0, failed_ = 0, deleted_ = 0, updated_ = 0, notified_ = 0, terminated_ = 0;
  std::mutex mutex_;
  std::condition_variable wake_;
  std::deque<Job> jobs_;
  std::deque<Result> results_;
  std::deque<Notification> notifications_;
  bool stopping_ = false;
  std::string discovered_;  // worker thread only
  void *curl_ = nullptr;    // worker thread only
  int listen_fd_ = -1;
  std::thread worker_, listener_;
};
}  // namespace mcx::af
