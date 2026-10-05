// The MC service server in the AF role on Rx (TS 23.379 clause 7.5.2.6, MCPTT-5; TS 23.280 clause 10.11.2a): for
// each active leg of a UE on an EPS access, an Rx session asks the PCRF for the QoS of the leg's media with the
// AA-Request (TS 29.214 clauses 4.4.1 and 4.4.2), and ends with the Session-Termination-Request (clause 4.4.4). The
// AF-Application-Identifier names the MC service (the ICSI, TS 29.214 annex A.13.1 NOTE 3), from which the PCRF
// selects QCI 65 for MCPTT voice (TS 23.379 clause 5.7.3); the call's Resource-Priority gives MCPTT-Identifier and
// Reservation-Priority (annex A.13.2). A UE on another access (WLAN, or 5G with N5) has no Rx session (TS 24.379
// clause 4.13).
//
// Specifications: TS 29.214 V19.3.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19),
// TS 24.379 V19.7.0 (Rel-19), TS 29.229, ETSI TS 183 017, RFC 6733, RFC 8101.
#pragma once

#include "mcx/af.hpp"
#include "mcx/diameter.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx::af {

// TS 29.214 clause 5.6: the Application-Id of Rx.
inline constexpr std::uint32_t rx_application_id = diameter_rx_application_id;

//------------------------------------------------------------------------------
// The "rx" block of the MCPTT and MCVideo server configuration.
struct RxConfig {
  bool enabled = false;
  // The freeDiameter configuration with the PCRF as ConnectPeer; the server's "diameter_config" when absent (one
  // freeDiameter core per process: both must then be the same file).
  std::string diameter_config;
  // RFC 6733 section 6.1: where the AA-Request is routed.
  std::string destination_realm, destination_host;
  // TS 29.214 annex A.13.1 NOTE 3 and annex A.15.1 NOTE 3: the ICSI of the server's MC service (ServiceProfile::icsi)
  // unless configured.
  std::string af_application_identifier;
  // Only legs whose UE address is in one of these IPv4 prefixes are on the EPS (TS 24.379 clause 4.13).
  std::vector<std::string> ue_subnets;
  // Maximum requested bandwidth of the audio and video components, each direction (as the "pcf" block).
  unsigned audio_bw_kbps = 41, video_bw_kbps = 1024;
  bool required = false, release_on_terminate = false;
  unsigned timeout_ms = 2000;
  static RxConfig parse(const Json &);
};

//------------------------------------------------------------------------------
// TS 29.214 clause 5.3.18: one Media-Sub-Component: its flow number, its two Flow-Description values (downlink then
// uplink, clause 5.3.8) and its Flow-Usage (clause 5.3.12).
struct RxSubComponent {
  std::uint32_t flow_number = 0;
  std::string downlink, uplink;
  std::int32_t flow_usage = 0;
  bool operator==(const RxSubComponent &) const = default;
};

//------------------------------------------------------------------------------
// TS 29.214 clause 5.3.16: one Media-Component-Description of a leg.
struct RxMediaComponent {
  std::uint32_t number = 0;
  std::int32_t media_type = 0;
  std::uint32_t max_requested_bandwidth_bps = 0;
  std::vector<RxSubComponent> sub_components;
  bool operator==(const RxMediaComponent &) const = default;
};

//------------------------------------------------------------------------------
// RFC 8101 and TS 29.214 annex A.13.2: a Resource-Priority value of an MC service namespace ("mcpttp" or "mcpttq")
// with its priority 0 to 15, which Reservation-Priority carries.
struct McResourcePriority {
  std::string name_space;
  std::uint32_t reservation_priority = 0;
  bool operator==(const McResourcePriority &) const = default;
};

// TS 29.214 clause 5.3.8: a Flow-Description: "permit out" for downlink (server to UE), "permit in" for uplink.
std::string rx_flow_description(bool uplink, const FlowPair &);
// TS 29.214 clause 4.4.1: the media components of a leg's flows: audio (RTP, RTCP, floor control) and video.
std::vector<RxMediaComponent> rx_media_components(const RxConfig &, const MediaFlows &);
// RFC 8101: the MC namespace and priority of a Resource-Priority value; nothing for another namespace.
std::optional<McResourcePriority> mc_resource_priority(std::string_view value);

//------------------------------------------------------------------------------
// Rx client of the MCPTT or MCVideo server: one Rx session per leg, keyed by the leg's dialog. Every call comes from
// the owning (SIP) thread; freeDiameter's threads only queue answers and PCRF-initiated requests for poll().
class RxClient : public PolicyClient {
public:
  // On the process's freeDiameter core, which must serve Rx.
  RxClient(RxConfig, std::shared_ptr<DiameterCore>);
  ~RxClient() override;
  RxClient(const RxClient &) = delete;
  RxClient &operator=(const RxClient &) = delete;

  const RxConfig &config() const { return cfg_; }

  const char *interface_name() const override { return "rx"; }

  const char *event_name(Event::Kind) const override;

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

  // What crosses from freeDiameter's threads to the owning thread (src/common/rx.cpp).
  struct Shared;

private:
  struct Entry {
    Lifecycle life;
    std::string session_id;
    SessionRequest desired, sent, inflight;
    // TS 29.214 clause 5.4.1: the features the PCRF accepted in the first AA-Answer.
    std::uint32_t features = 0;
  };

  void dispatch(const std::string &key, Entry &, Op);
  void send_aar(const std::string &key, Entry &, bool initial);
  void send_str(const std::string &key, Entry &);

  RxConfig cfg_;
  std::shared_ptr<DiameterCore> core_;
  std::shared_ptr<Shared> shared_;
  std::map<std::string, Entry> entries_;
  std::uint64_t opened_ = 0, created_ = 0, failed_ = 0, deleted_ = 0, updated_ = 0, notified_ = 0, terminated_ = 0;
};

} // namespace mcx::af
