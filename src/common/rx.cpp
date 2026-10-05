// Rx client of the MC service server in the AF role (TS 23.379 clause 7.5.2.6, MCPTT-5): the service information of a
// call leg (media components, flows, MC service priority) and the Rx session of each leg: AA-Request and AA-Answer
// (TS 29.214 clauses 4.4.1 and 4.4.2), Session-Termination-Request (clause 4.4.4), Re-Auth-Request from the PCRF
// (clause 4.4.6.2) and Abort-Session-Request (clause 4.4.6.1).
//
// Specifications: TS 29.214 V19.3.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19), TS 29.229, RFC 6733, RFC 8101.
#include "mcx/rx.hpp"

#include "diameter_core.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <ctime>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace mcx::af {
using namespace diameter;

namespace {

// TS 29.214 clause 5.3.19: Media-Type.
constexpr std::int32_t media_type_audio = 0;
constexpr std::int32_t media_type_video = 1;
// TS 29.214 clause 5.3.12: Flow-Usage.
constexpr std::int32_t flow_usage_no_information = 0;
constexpr std::int32_t flow_usage_rtcp = 1;
// TS 29.214 clause 5.3.11: Flow-Status.
constexpr std::int32_t flow_status_enabled = 2;
constexpr std::int32_t flow_status_removed = 4;
// TS 29.214 clause 5.3.13: the Specific-Action values the AF subscribes to in the initial AA-Request, as the N5
// client subscribes to the resource allocation events.
constexpr std::int32_t indication_of_release_of_bearer = 4;
constexpr std::int32_t indication_of_successful_resources_allocation = 8;
constexpr std::int32_t indication_of_failed_resources_allocation = 9;
// TS 29.214 clause 5.3.31: Rx-Request-Type.
constexpr std::int32_t rx_initial_request = 0;
constexpr std::int32_t rx_update_request = 1;
// RFC 6733 section 8.15: Termination-Cause DIAMETER_LOGOUT.
constexpr std::int32_t termination_cause_logout = 1;
// RFC 6733 section 7.1.2 and 7.1.5: DIAMETER_SUCCESS and DIAMETER_UNKNOWN_SESSION_ID.
constexpr std::uint32_t diameter_success = 2001;
constexpr std::uint32_t diameter_unknown_session_id = 5002;
// TS 29.214 clause 5.4.1 table 5.4.1-1: the feature list and the bits of MCPTT and MCVideo.
constexpr std::uint32_t rx_feature_list_id = 1;
constexpr std::uint32_t feature_mcptt = 1U << 17;
constexpr std::uint32_t feature_mcvideo = 1U << 22;
// RFC 8101 section 3: the MCPTT namespaces have the priorities 0 (lowest) to 15.
constexpr std::uint32_t mc_priority_highest = 15;
// RFC 6733 section 4.4: the longest Session-Id kept.
constexpr std::size_t max_session_id_bytes = 1024;
// The AVP codes read while browsing: RFC 6733 section 7.7 (Experimental-Result-Code), TS 29.214 clause 5.3.13
// (Specific-Action), TS 29.229 clauses 6.3.29 to 6.3.31 (Supported-Features, Feature-List-ID, Feature-List).
constexpr std::uint32_t avp_experimental_result_code = 298;
constexpr std::uint32_t avp_specific_action = 513;
constexpr std::uint32_t avp_supported_features = 628;
constexpr std::uint32_t avp_feature_list_id = 629;
constexpr std::uint32_t avp_feature_list = 630;

//------------------------------------------------------------------------------
// Helper: whether a request is for MCVideo (MCVideo-Identifier, feature MCVideo) or MCPTT.
bool is_mcvideo(const SessionRequest &request) { return request.id_attribute == "mcVideoId"; }

//------------------------------------------------------------------------------
// TS 29.214 clause 5.3.13: the name of a Specific-Action value the AF subscribes to.
std::string specific_action_name(std::int32_t value) {
  switch (value) {
  case indication_of_release_of_bearer: return "INDICATION_OF_RELEASE_OF_BEARER";
  case indication_of_successful_resources_allocation: return "INDICATION_OF_SUCCESSFUL_RESOURCES_ALLOCATION";
  case indication_of_failed_resources_allocation: return "INDICATION_OF_FAILED_RESOURCES_ALLOCATION";
  default: return "Specific-Action " + std::to_string(value);
  }
}

} // namespace

//------------------------------------------------------------------------------
// Helper: reads the "rx" block; the AF-Application-Identifier defaults to the service's ICSI (set by the server).
RxConfig RxConfig::parse(const Json &block) {
  if (!block.is_object()) throw std::runtime_error("rx must be an object");
  RxConfig config;
  config.enabled = block.value("enabled", false);
  config.diameter_config = block.value("diameter_config", std::string{});
  config.destination_realm = block.value("destination_realm", std::string{});
  config.destination_host = block.value("destination_host", std::string{});
  config.af_application_identifier = block.value("af_application_identifier", std::string{});
  config.ue_subnets = block.value("ue_subnets", std::vector<std::string>{});
  config.audio_bw_kbps = block.value("audio_bw_kbps", config.audio_bw_kbps);
  config.video_bw_kbps = block.value("video_bw_kbps", config.video_bw_kbps);
  config.required = block.value("required", false);
  config.release_on_terminate = block.value("release_on_terminate", false);
  config.timeout_ms = block.value("timeout_ms", config.timeout_ms);
  for (const auto &cidr : config.ue_subnets)
    if (cidr.find('/') == std::string::npos || !ipv4_in_cidr(cidr.substr(0, cidr.find('/')), cidr))
      throw std::runtime_error("invalid rx.ue_subnets entry " + cidr);
  if (!config.audio_bw_kbps || !config.video_bw_kbps || !config.timeout_ms)
    throw std::runtime_error("invalid rx bandwidth or timeout");
  if (config.enabled && config.destination_realm.empty())
    throw std::runtime_error("rx.enabled needs destination_realm (RFC 6733 section 6.1)");
  if (config.enabled && config.ue_subnets.empty())
    throw std::runtime_error("rx.enabled needs ue_subnets: the UE addresses on the EPS (TS 24.379 clause 4.13)");
  return config;
}

//------------------------------------------------------------------------------
// TS 29.214 clause 5.3.8: a Flow-Description for one direction of a flow: "in" is uplink (from the UE), "out" is
// downlink (to the UE); UDP, both ports given, no options (the restrictions of clause 5.3.8).
std::string rx_flow_description(bool uplink, const FlowPair &flow) {
  if (uplink)
    return "permit in 17 from " + flow.ue_ip + " " + std::to_string(flow.ue_port) + " to " + flow.server_ip + " " +
           std::to_string(flow.server_port);
  return "permit out 17 from " + flow.server_ip + " " + std::to_string(flow.server_port) + " to " + flow.ue_ip + " " +
         std::to_string(flow.ue_port);
}

//------------------------------------------------------------------------------
// TS 29.214 clause 4.4.1: the media components of a leg: audio (component 1: RTP, RTCP and, for MCPTT, floor control
// (TS 24.380), which TS 23.379 clause 5.7.3 lets share the voice bearer) and video (component 2: RTP and RTCP).
std::vector<RxMediaComponent> rx_media_components(const RxConfig &config, const MediaFlows &flows) {
  const auto sub = [](std::uint32_t number, const FlowPair &flow, std::int32_t usage) {
    return RxSubComponent{number, rx_flow_description(false, flow), rx_flow_description(true, flow), usage};
  };
  RxMediaComponent audio{1,
                         media_type_audio,
                         config.audio_bw_kbps * 1000,
                         {sub(1, flows.rtp, flow_usage_no_information), sub(2, flows.rtcp, flow_usage_rtcp)}};
  if (flows.floor) audio.sub_components.push_back(sub(3, *flows.floor, flow_usage_no_information));
  std::vector<RxMediaComponent> components{audio};
  if (flows.video_rtp) {
    RxMediaComponent video{
        2, media_type_video, config.video_bw_kbps * 1000, {sub(1, *flows.video_rtp, flow_usage_no_information)}};
    if (flows.video_rtcp) video.sub_components.push_back(sub(2, *flows.video_rtcp, flow_usage_rtcp));
    components.push_back(video);
  }
  return components;
}

//------------------------------------------------------------------------------
// RFC 8101 section 3 and RFC 4412 section 3.1: an r-value "namespace.priority" of the MCPTT namespaces "mcpttp" and
// "mcpttq", with the priority 0 to 15 that TS 29.214 annex A.13.2 maps to Reservation-Priority 0 (DEFAULT) to 15.
std::optional<McResourcePriority> mc_resource_priority(std::string_view value) {
  const auto dot = value.rfind('.');
  if (dot == std::string_view::npos) return std::nullopt;
  std::string name_space(value.substr(0, dot));
  std::transform(name_space.begin(), name_space.end(), name_space.begin(),
                 [](unsigned char letter) { return static_cast<char>(std::tolower(letter)); });
  if (name_space != "mcpttp" && name_space != "mcpttq") return std::nullopt;
  const auto digits = value.substr(dot + 1);
  std::uint32_t priority = 0;
  const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), priority);
  if (error != std::errc{} || end != digits.data() + digits.size() || priority > mc_priority_highest)
    return std::nullopt;
  return McResourcePriority{name_space, priority};
}

//------------------------------------------------------------------------------
// Helper: what crosses from freeDiameter's threads to the owning thread: the answers to the client's requests and the
// PCRF's Re-Auth and Abort-Session requests, and the Session-Ids of the client's Rx sessions.
struct RxClient::Shared {
  struct Answer {
    std::string key;
    Op op = Op::none;
    std::uint32_t result = 0; // 0: no answer (timeout or local failure)
    std::uint32_t features = 0;
    std::string detail;
  };

  struct Notice {
    std::string session_id;
    bool abort = false;
    std::string detail;
  };

  RxDictionary *dictionary = nullptr;
  std::mutex mutex;
  std::deque<Answer> answers;
  std::deque<Notice> notices;
  std::map<std::string, std::string> sessions; // Session-Id -> key
  struct disp_hdl *rar_handler = nullptr, *asr_handler = nullptr;
};

namespace {

//------------------------------------------------------------------------------
// Helper: one request in flight; the answer or timeout callback takes it back.
struct Pending {
  std::shared_ptr<RxClient::Shared> shared;
  std::string key;
  Op op = Op::none;
};

//------------------------------------------------------------------------------
// Helper: queues the result of a request for the owning thread.
void queue_answer(Pending &pending, RxClient::Shared::Answer answer) {
  answer.key = pending.key;
  answer.op = pending.op;
  std::lock_guard lock(pending.shared->mutex);
  pending.shared->answers.push_back(std::move(answer));
}

//------------------------------------------------------------------------------
// RFC 6733 sections 7.1 and 7.6: the Result-Code of an answer, or its Experimental-Result-Code.
std::uint32_t answer_result(struct msg *answer, const RxDictionary &dictionary) {
  struct avp *result = nullptr;
  check_fd(fd_msg_search_avp(answer, dictionary.result_code, &result), "find Result-Code");
  if (result) return u32_value(result, "Result-Code");
  struct avp *experimental = nullptr;
  check_fd(fd_msg_search_avp(answer, dictionary.experimental_result, &experimental), "find Experimental-Result");
  if (!experimental) throw std::runtime_error("answer without Result-Code or Experimental-Result");
  return u32_value(child_by_code(experimental, avp_experimental_result_code, 0), "Experimental-Result-Code");
}

//------------------------------------------------------------------------------
// TS 29.214 clause 5.4.1: the Feature-List of the Rx feature list in the answer's Supported-Features; 0 when absent.
std::uint32_t answer_features(struct msg *answer) {
  struct avp *child = nullptr;
  check_fd(fd_msg_browse_internal(answer, MSG_BRW_FIRST_CHILD, reinterpret_cast<msg_or_avp **>(&child), nullptr),
           "browse AVPs");
  while (child) {
    struct avp_hdr *header = nullptr;
    check_fd(fd_msg_avp_hdr(child, &header), "read AVP header");
    if (header->avp_code == avp_supported_features && header->avp_vendor == vendor_3gpp) {
      auto *list_id = child_by_code(child, avp_feature_list_id, vendor_3gpp);
      auto *list = child_by_code(child, avp_feature_list, vendor_3gpp);
      if (list_id && list && u32_value(list_id, "Feature-List-ID") == rx_feature_list_id)
        return u32_value(list, "Feature-List");
    }
    check_fd(fd_msg_browse_internal(child, MSG_BRW_NEXT, reinterpret_cast<msg_or_avp **>(&child), nullptr),
             "browse AVPs");
  }
  return 0;
}

//------------------------------------------------------------------------------
// TS 29.214 clauses 4.4.1, 4.4.2 and 4.4.4: the AA-Answer or Session-Termination-Answer, queued for the owning
// thread; the answer is freed.
void rx_answer_callback(void *opaque, struct msg **answer) {
  std::unique_ptr<Pending> pending(static_cast<Pending *>(opaque));
  RxClient::Shared::Answer result;
  try {
    if (!answer || !*answer) throw std::runtime_error("empty Diameter answer");
    result.result = answer_result(*answer, *pending->shared->dictionary);
    result.features = answer_features(*answer);
  } catch (const std::exception &error) {
    result.detail = error.what();
  }
  if (answer && *answer) {
    (void)fd_msg_free(*answer);
    *answer = nullptr;
  }
  queue_answer(*pending, std::move(result));
}

//------------------------------------------------------------------------------
// Helper: a request that had no answer in time.
void rx_timeout_callback(void *opaque, DiamId_t, size_t, struct msg **) {
  std::unique_ptr<Pending> pending(static_cast<Pending *>(opaque));
  RxClient::Shared::Answer answer;
  answer.detail = "no answer from the PCRF in time";
  queue_answer(*pending, std::move(answer));
}

//------------------------------------------------------------------------------
// Helper: the Session-Id of a received request; empty when it has none.
std::string request_session_id(struct msg *request, const RxDictionary &dictionary) {
  struct avp *session = nullptr;
  if (fd_msg_search_avp(request, dictionary.session_id, &session) != 0 || !session) return {};
  return octets_value(session, "Session-Id", max_session_id_bytes);
}

//------------------------------------------------------------------------------
// TS 29.214 clauses 4.4.6.1 and 4.4.6.2: answers a Re-Auth-Request or Abort-Session-Request from the PCRF:
// DIAMETER_SUCCESS for an Rx session of this client, DIAMETER_UNKNOWN_SESSION_ID otherwise; the Specific-Action
// values (RAR) or the Abort-Cause (ASR) are queued for the owning thread.
int rx_request_callback(struct msg **message, struct avp *, struct session *, void *opaque, enum disp_action *action,
                        bool abort) {
  auto &shared = *static_cast<RxClient::Shared *>(opaque);
  try {
    const auto &dictionary = *shared.dictionary;
    const auto session_id = request_session_id(*message, dictionary);
    RxClient::Shared::Notice notice{session_id, abort, {}};
    if (abort) {
      struct avp *cause = nullptr;
      check_fd(fd_msg_search_avp(*message, dictionary.abort_cause, &cause), "find Abort-Cause");
      notice.detail =
          cause ? "Abort-Cause " + std::to_string(u32_value(cause, "Abort-Cause")) : "Abort-Session-Request";
    } else {
      struct avp *child = nullptr;
      check_fd(fd_msg_browse_internal(*message, MSG_BRW_FIRST_CHILD, reinterpret_cast<msg_or_avp **>(&child), nullptr),
               "browse AVPs");
      while (child) {
        struct avp_hdr *header = nullptr;
        check_fd(fd_msg_avp_hdr(child, &header), "read AVP header");
        if (header->avp_code == avp_specific_action && header->avp_vendor == vendor_3gpp && header->avp_value)
          notice.detail += (notice.detail.empty() ? "" : ",") + specific_action_name(header->avp_value->i32);
        check_fd(fd_msg_browse_internal(child, MSG_BRW_NEXT, reinterpret_cast<msg_or_avp **>(&child), nullptr),
                 "browse AVPs");
      }
    }
    bool known = false;
    {
      std::lock_guard lock(shared.mutex);
      known = shared.sessions.contains(session_id);
      if (known) shared.notices.push_back(std::move(notice));
    }
    check_fd(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, message, 0), "create answer");
    check_fd(fd_msg_add_origin(*message, 0), "add answer origin");
    add_u32(*message, dictionary.result_code, known ? diameter_success : diameter_unknown_session_id);
    *action = DISP_ACT_SEND;
    return 0;
  } catch (...) {
    // freeDiameter answers DIAMETER_UNABLE_TO_COMPLY for a handler that fails.
    return EINVAL;
  }
}

//------------------------------------------------------------------------------
// TS 29.214 clause 4.4.6.2: the PCRF's Re-Auth-Request.
int rx_re_auth_callback(struct msg **message, struct avp *avp, struct session *session, void *opaque,
                        enum disp_action *action) {
  return rx_request_callback(message, avp, session, opaque, action, false);
}

//------------------------------------------------------------------------------
// TS 29.214 clause 4.4.6.1: the PCRF's Abort-Session-Request.
int rx_abort_session_callback(struct msg **message, struct avp *avp, struct session *session, void *opaque,
                              enum disp_action *action) {
  return rx_request_callback(message, avp, session, opaque, action, true);
}

//------------------------------------------------------------------------------
// RFC 6733 section 8.8: a new Session-Id "<DiameterIdentity>;<high 32 bits>;<low 32 bits>": the high part is the
// time the process started, the low part a counter.
std::string new_session_id() {
  static const auto started = static_cast<std::uint32_t>(std::time(nullptr));
  static std::atomic<std::uint32_t> counter{0};
  return std::string(reinterpret_cast<const char *>(fd_g_config->cnf_diamid), fd_g_config->cnf_diamid_len) + ";" +
         std::to_string(started) + ";" + std::to_string(++counter) + ";rx";
}

//------------------------------------------------------------------------------
// Helper: a new Rx request of a command, with the Session-Id first (RFC 6733 section 8.8), the Rx Application-Id in
// the header and as Auth-Application-Id, the origin and the destination.
struct msg *new_rx_request(struct dict_object *command, const RxDictionary &dictionary, const RxConfig &config,
                           const std::string &session_id) {
  struct msg *request = nullptr;
  check_fd(fd_msg_new(command, MSGFL_ALLOC_ETEID, &request), "create Rx request");
  try {
    struct msg_hdr *header = nullptr;
    check_fd(fd_msg_hdr(request, &header), "read Rx request header");
    header->msg_appl = rx_application_id;
    add_octets(request, dictionary.session_id, session_id);
    add_u32(request, dictionary.auth_application_id, rx_application_id);
    check_fd(fd_msg_add_origin(request, 0), "add Diameter origin");
    add_octets(request, dictionary.destination_realm, config.destination_realm);
    if (!config.destination_host.empty()) add_octets(request, dictionary.destination_host, config.destination_host);
  } catch (...) {
    (void)fd_msg_free(request);
    throw;
  }
  return request;
}

//------------------------------------------------------------------------------
// TS 29.214 clause 5.3.16: appends one Media-Component-Description with its sub-components, all enabled.
void add_media_component(struct msg *request, const RxDictionary &dictionary, const RxMediaComponent &component) {
  auto *description = add_group(request, dictionary.media_component_description);
  add_u32(description, dictionary.media_component_number, component.number);
  for (const auto &sub : component.sub_components) {
    auto *group = add_group(description, dictionary.media_sub_component);
    add_u32(group, dictionary.flow_number, sub.flow_number);
    add_octets(group, dictionary.flow_description, sub.downlink);
    add_octets(group, dictionary.flow_description, sub.uplink);
    if (sub.flow_usage != flow_usage_no_information) add_i32(group, dictionary.flow_usage, sub.flow_usage);
  }
  add_i32(description, dictionary.media_type, component.media_type);
  add_u32(description, dictionary.max_requested_bandwidth_ul, component.max_requested_bandwidth_bps);
  add_u32(description, dictionary.max_requested_bandwidth_dl, component.max_requested_bandwidth_bps);
  add_i32(description, dictionary.flow_status, flow_status_enabled);
}

//------------------------------------------------------------------------------
// TS 29.214 clauses 4.4.2 and 5.3.11: a media component or sub-component that the leg no longer has is removed
// (Flow-Status REMOVED).
void add_removed_media(struct msg *request, const RxDictionary &dictionary, const std::vector<RxMediaComponent> &before,
                       const std::vector<RxMediaComponent> &after) {
  for (const auto &old_component : before) {
    const auto now = std::find_if(after.begin(), after.end(),
                                  [&](const RxMediaComponent &item) { return item.number == old_component.number; });
    if (now == after.end()) {
      auto *description = add_group(request, dictionary.media_component_description);
      add_u32(description, dictionary.media_component_number, old_component.number);
      add_i32(description, dictionary.flow_status, flow_status_removed);
      continue;
    }
    for (const auto &old_sub : old_component.sub_components) {
      const bool kept =
          std::any_of(now->sub_components.begin(), now->sub_components.end(),
                      [&](const RxSubComponent &item) { return item.flow_number == old_sub.flow_number; });
      if (kept) continue;
      // The component itself is described again (above); the removed flow is named within a description of its own.
      auto *description = add_group(request, dictionary.media_component_description);
      add_u32(description, dictionary.media_component_number, old_component.number);
      auto *group = add_group(description, dictionary.media_sub_component);
      add_u32(group, dictionary.flow_number, old_sub.flow_number);
      add_i32(group, dictionary.flow_status, flow_status_removed);
    }
  }
}

//------------------------------------------------------------------------------
// Helper: sends a request; its answer or timeout reaches the owning thread through the shared queue.
void send_request(struct msg *request, std::shared_ptr<RxClient::Shared> shared, const std::string &key, Op op,
                  unsigned timeout_ms) {
  auto pending = std::make_unique<Pending>(Pending{std::move(shared), key, op});
  struct timespec deadline{};
  if (::clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
    (void)fd_msg_free(request);
    throw std::runtime_error("cannot read realtime clock");
  }
  deadline.tv_sec += timeout_ms / 1000;
  deadline.tv_nsec += static_cast<long>(timeout_ms % 1000) * 1000000L;
  if (deadline.tv_nsec >= 1000000000L) {
    ++deadline.tv_sec;
    deadline.tv_nsec -= 1000000000L;
  }
  const int result = fd_msg_send_timeout(&request, rx_answer_callback, pending.get(), rx_timeout_callback, &deadline);
  if (result != 0) {
    if (request) (void)fd_msg_free(request);
    fail_fd(result, "send Rx request"); // no callback will run: pending is still ours
  }
  (void)pending.release(); // the callback owns it now
}

} // namespace

//------------------------------------------------------------------------------
// Helper: the client on the shared core, with its handlers for the PCRF's Re-Auth-Request and
// Abort-Session-Request; it starts the core when no other client has.
RxClient::RxClient(RxConfig config, std::shared_ptr<DiameterCore> core)
    : cfg_(std::move(config)), core_(std::move(core)), shared_(std::make_shared<Shared>()) {
  shared_->dictionary = &core_->rx();
  struct disp_when when{};
  when.app = shared_->dictionary->application;
  when.command = shared_->dictionary->rar;
  check_fd(fd_disp_register(rx_re_auth_callback, DISP_HOW_CC, &when, shared_.get(), &shared_->rar_handler),
           "register Re-Auth-Request handler");
  when.command = shared_->dictionary->asr;
  check_fd(fd_disp_register(rx_abort_session_callback, DISP_HOW_CC, &when, shared_.get(), &shared_->asr_handler),
           "register Abort-Session-Request handler");
  core_->start();
}

//------------------------------------------------------------------------------
// Helper: unregisters the handlers; answers still in flight keep the shared state alive.
RxClient::~RxClient() {
  if (shared_->rar_handler) (void)fd_disp_unregister(&shared_->rar_handler, nullptr);
  if (shared_->asr_handler) (void)fd_disp_unregister(&shared_->asr_handler, nullptr);
}

//------------------------------------------------------------------------------
// Helper: the names of the client's events, as those of the N5 client with the prefix "rx".
const char *RxClient::event_name(Event::Kind kind) const {
  switch (kind) {
  case Event::Kind::created: return "rx_session_created";
  case Event::Kind::create_failed: return "rx_session_create_failed";
  case Event::Kind::updated: return "rx_session_updated";
  case Event::Kind::update_failed: return "rx_session_update_failed";
  case Event::Kind::deleted: return "rx_session_terminated";
  case Event::Kind::delete_failed: return "rx_session_termination_failed";
  case Event::Kind::notified: return "rx_re_auth";
  case Event::Kind::terminated: return "rx_abort_session";
  }
  return "rx_event";
}

//------------------------------------------------------------------------------
// TS 29.214 clause 4.4.1: a new Rx session for a leg (an existing one is refreshed).
void RxClient::open(const std::string &key, SessionRequest request) {
  if (entries_.contains(key)) {
    refresh(key, request);
    return;
  }
  auto &entry = entries_[key];
  entry.session_id = new_session_id();
  entry.desired = std::move(request);
  {
    std::lock_guard lock(shared_->mutex);
    shared_->sessions[entry.session_id] = key;
  }
  opened_++;
  dispatch(key, entry, entry.life.start());
}

//------------------------------------------------------------------------------
// TS 29.214 clause 4.4.2: what the leg asks for changed (media, priority).
void RxClient::refresh(const std::string &key, const SessionRequest &request) {
  const auto found = entries_.find(key);
  if (found == entries_.end() || found->second.desired == request) return;
  found->second.desired = request;
  dispatch(key, found->second, found->second.life.change());
}

//------------------------------------------------------------------------------
// TS 29.214 clause 4.4.4: the leg is gone: its Rx session ends.
void RxClient::close(const std::string &key) {
  const auto found = entries_.find(key);
  if (found == entries_.end()) return;
  dispatch(key, found->second, found->second.life.stop());
  if (found->second.life.finished()) {
    std::lock_guard lock(shared_->mutex);
    shared_->sessions.erase(found->second.session_id);
    entries_.erase(found);
  }
}

//------------------------------------------------------------------------------
// Helper: sends what the lifecycle asks for: the initial or an update AA-Request, or the
// Session-Termination-Request; an update that nothing changed any more is not sent.
void RxClient::dispatch(const std::string &key, Entry &entry, Op op) {
  while (op == Op::update && entry.desired == entry.sent) op = entry.life.updated(true);
  try {
    if (op == Op::create || op == Op::update)
      send_aar(key, entry, op == Op::create);
    else if (op == Op::remove)
      send_str(key, entry);
  } catch (const std::exception &error) {
    std::lock_guard lock(shared_->mutex);
    shared_->answers.push_back({key, op, 0, 0, error.what()});
  }
}

//------------------------------------------------------------------------------
// TS 29.214 clauses 4.4.1 and 4.4.2, the AA-Request of clause 5.6.1: the AF-Application-Identifier, the media
// components (with the removed ones on an update), and the call's MC service priority (annex A.13.2 and A.15.2:
// MCPTT-Identifier or MCVideo-Identifier with the Resource-Priority namespace, Reservation-Priority with its
// priority). The initial request also carries the UE address (Framed-IP-Address), the Specific-Action subscriptions
// and the supported features (clause 5.4.1: M flag cleared, so that a PCRF without them still accepts the request);
// a later request uses the MC identifier only when the PCRF accepted the feature.
void RxClient::send_aar(const std::string &key, Entry &entry, bool initial) {
  const auto &dictionary = core_->rx();
  const bool mcvideo = is_mcvideo(entry.desired);
  const auto feature = mcvideo ? feature_mcvideo : feature_mcptt;
  auto *request = new_rx_request(dictionary.aar, dictionary, cfg_, entry.session_id);
  try {
    add_octets(request, dictionary.af_application_identifier, cfg_.af_application_identifier);
    const auto components = rx_media_components(cfg_, entry.desired.flows);
    for (const auto &component : components) add_media_component(request, dictionary, component);
    if (!initial) add_removed_media(request, dictionary, rx_media_components(cfg_, entry.sent.flows), components);
    if (initial) {
      for (const auto action : {indication_of_release_of_bearer, indication_of_successful_resources_allocation,
                                indication_of_failed_resources_allocation})
        add_i32(request, dictionary.specific_action, action);
      auto *features = add_group(request, dictionary.supported_features);
      add_u32(features, dictionary.vendor_id, vendor_3gpp);
      add_u32(features, dictionary.feature_list_id, rx_feature_list_id);
      add_u32(features, dictionary.feature_list, feature);
    }
    const auto priority = mc_resource_priority(entry.desired.resource_priority);
    if (priority) {
      add_u32(request, dictionary.reservation_priority, priority->reservation_priority);
    } else if (!initial && mc_resource_priority(entry.sent.resource_priority)) {
      // TS 29.214 annex A.13.2: back to the lowest priority, DEFAULT (0).
      add_u32(request, dictionary.reservation_priority, 0);
    }
    if (initial) {
      in_addr address{};
      if (::inet_pton(AF_INET, entry.desired.ue_ipv4.c_str(), &address) != 1)
        throw std::runtime_error("UE address is not IPv4: " + entry.desired.ue_ipv4);
      add_octets(request, dictionary.framed_ip_address,
                 std::string_view(reinterpret_cast<const char *>(&address), sizeof address));
    }
    if (priority && (initial || (entry.features & feature)))
      add_octets(request, mcvideo ? dictionary.mcvideo_identifier : dictionary.mcptt_identifier, priority->name_space);
    add_i32(request, dictionary.rx_request_type, initial ? rx_initial_request : rx_update_request);
  } catch (...) {
    (void)fd_msg_free(request);
    throw;
  }
  entry.inflight = entry.desired;
  send_request(request, shared_, key, initial ? Op::create : Op::update, cfg_.timeout_ms);
}

//------------------------------------------------------------------------------
// TS 29.214 clause 4.4.4, the Session-Termination-Request of clause 5.6.3, Termination-Cause DIAMETER_LOGOUT.
void RxClient::send_str(const std::string &key, Entry &entry) {
  const auto &dictionary = core_->rx();
  auto *request = new_rx_request(dictionary.str, dictionary, cfg_, entry.session_id);
  try {
    add_i32(request, dictionary.termination_cause, termination_cause_logout);
  } catch (...) {
    (void)fd_msg_free(request);
    throw;
  }
  send_request(request, shared_, key, Op::remove, cfg_.timeout_ms);
}

//------------------------------------------------------------------------------
// Helper: the answers and the PCRF's requests, as events; the lifecycles move on. An Abort-Session-Request ends the
// Rx session with a Session-Termination-Request (TS 29.214 clause 4.4.6.1).
std::vector<Event> RxClient::poll() {
  std::deque<Shared::Answer> answers;
  std::deque<Shared::Notice> notices;
  {
    std::lock_guard lock(shared_->mutex);
    answers.swap(shared_->answers);
    notices.swap(shared_->notices);
  }
  std::vector<Event> events;
  const auto forget = [&](std::map<std::string, Entry>::iterator found) {
    if (!found->second.life.finished()) return;
    std::lock_guard lock(shared_->mutex);
    shared_->sessions.erase(found->second.session_id);
    entries_.erase(found);
  };
  for (auto &answer : answers) {
    const auto found = entries_.find(answer.key);
    if (found == entries_.end()) continue;
    auto &entry = found->second;
    const bool ok = answer.result == diameter_success;
    Event event{Event::Kind::created, answer.key, entry.session_id, answer.detail, answer.result, nullptr};
    if (answer.op == Op::create) {
      event.kind = ok ? Event::Kind::created : Event::Kind::create_failed;
      ok ? created_++ : failed_++;
      if (ok) {
        entry.sent = entry.inflight;
        entry.features = answer.features;
      }
      events.push_back(event);
      dispatch(answer.key, entry, entry.life.created(ok, entry.session_id));
    } else if (answer.op == Op::update) {
      event.kind = ok ? Event::Kind::updated : Event::Kind::update_failed;
      ok ? updated_++ : failed_++;
      // A refused update is not repeated; the next change is sent against it.
      entry.sent = entry.inflight;
      events.push_back(event);
      dispatch(answer.key, entry, entry.life.updated(ok));
    } else if (answer.op == Op::remove) {
      const bool gone = ok || answer.result == diameter_unknown_session_id;
      event.kind = gone ? Event::Kind::deleted : Event::Kind::delete_failed;
      gone ? deleted_++ : failed_++;
      events.push_back(event);
      entry.life.removed();
    }
    forget(found);
  }
  for (auto &notice : notices) {
    std::string key;
    {
      std::lock_guard lock(shared_->mutex);
      const auto session = shared_->sessions.find(notice.session_id);
      if (session == shared_->sessions.end()) continue;
      key = session->second;
    }
    const auto found = entries_.find(key);
    if (found == entries_.end()) continue;
    auto &entry = found->second;
    if (notice.abort) {
      terminated_++;
      events.push_back({Event::Kind::terminated, key, entry.session_id, notice.detail, 0, nullptr});
      dispatch(key, entry, entry.life.terminated());
      forget(found);
    } else {
      notified_++;
      events.push_back({Event::Kind::notified, key, entry.session_id, notice.detail, 0, nullptr});
    }
  }
  return events;
}

//------------------------------------------------------------------------------
// Helper: the dialogs with an Rx session.
std::vector<std::string> RxClient::keys() const {
  std::vector<std::string> out;
  for (const auto &[key, entry] : entries_) out.push_back(key);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the client's sessions and counters, as the N5 client's.
Json RxClient::status() const {
  Json sessions = Json::array();
  std::size_t active = 0;
  for (const auto &[key, entry] : entries_) {
    const auto state = entry.life.state();
    active += state == Lifecycle::State::active || state == Lifecycle::State::updating;
    sessions.push_back({{"dialog", key},
                        {"state", state_name(state)},
                        {"session_id", entry.session_id},
                        {"ue_ipv4", entry.desired.ue_ipv4},
                        {"priority", entry.desired.priority},
                        {"features", entry.features}});
  }
  return {{"enabled", true},      {"active", active},      {"sessions", sessions},   {"opened", opened_},
          {"created", created_},  {"updated", updated_},   {"terminated", deleted_}, {"failed", failed_},
          {"re_auth", notified_}, {"aborted", terminated_}};
}

//------------------------------------------------------------------------------
// TS 29.214 clause 4.4.4: at shutdown every Rx session ends; the answers are awaited until the deadline.
std::vector<Event> RxClient::shutdown(std::chrono::milliseconds wait) {
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

} // namespace mcx::af
