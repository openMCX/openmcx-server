// Rx client of the MC service server against a PCRF over a real Diameter peer (freeDiameter, TCP): the service
// information of a leg, the initial AA-Request, a Re-Auth-Request, an update AA-Request, an Abort-Session-Request
// and the Session-Termination-Request that follows it; and the pure helpers (flows, media components, Resource-Priority
// mapping, access selection).
//
// Specifications: TS 29.214 V19.3.0 (Rel-19), RFC 6733, RFC 8101.
#include "diameter_core.hpp"
#include "mcx/rx.hpp"

#include <unistd.h>

#include <arpa/inet.h>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using namespace mcx;
using namespace mcx::diameter;

namespace {

constexpr const char *ue_ip = "10.45.0.9";
constexpr const char *server_ip = "192.168.61.40";
constexpr const char *icsi = "urn:urn-7:3gpp-service.ims.icsi.mcptt";
constexpr std::uint32_t feature_mcptt = 1U << 17;

//------------------------------------------------------------------------------
// Fails the test with the message when the value does not hold.
void check(bool value, const std::string &message) {
  if (!value) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Writes the contents to the file at path or fails the test.
void write_file(const fs::path &path, const std::string &contents) {
  std::ofstream out(path);
  if (!out || !(out << contents)) throw std::runtime_error("cannot write " + path.string());
}

//------------------------------------------------------------------------------
// The freeDiameter configuration of one peer: TCP on the loopback address without TLS, connected to one peer.
std::string native_config(const std::string &identity, unsigned port, const std::string &peer, unsigned peer_port) {
  return "Identity = \"" + identity + "\";\nRealm = \"mcx.test\";\nPort = " + std::to_string(port) +
         ";\nSecPort = 0;\nNo_SCTP;\nNo_IPv6;\nNoRelay;\nAppServThreads = 2;\nListenOn = \"127.0.0.1\";\n"
         "ConnectPeer = \"" +
         peer + "\" { ConnectTo = \"127.0.0.1\"; Port = " + std::to_string(peer_port) +
         "; No_TLS; No_SCTP; Realm = \"mcx.test\"; TcTimer = 1; };\n";
}

//------------------------------------------------------------------------------
// The leg of the test: speech, RTCP and floor control between the server and the UE.
af::SessionRequest leg_request() {
  af::SessionRequest request;
  request.ue_ipv4 = ue_ip;
  request.mc_id = "sip:alice@mcx.test";
  request.flows.rtp = {server_ip, ue_ip, 4000, 4400};
  request.flows.rtcp = {server_ip, ue_ip, 4001, 4401};
  request.flows.floor = af::FlowPair{server_ip, ue_ip, 5000, 5400};
  request.priority = "emergency";
  request.resource_priority = "mcpttp.15";
  return request;
}

//------------------------------------------------------------------------------
// TS 29.214 clauses 5.3.8, 4.4.1 and annex A.13.2, TS 24.379 clause 4.13: the flows, the media components, the
// Resource-Priority mapping and the access a UE address is on, without Diameter.
void Clause_4_4_1_ServiceInformation() {
  const af::FlowPair rtp{server_ip, ue_ip, 4000, 4400};
  check(af::rx_flow_description(false, rtp) == "permit out 17 from 192.168.61.40 4000 to 10.45.0.9 4400",
        "downlink Flow-Description");
  check(af::rx_flow_description(true, rtp) == "permit in 17 from 10.45.0.9 4400 to 192.168.61.40 4000",
        "uplink Flow-Description");

  af::RxConfig config;
  auto request = leg_request();
  auto components = af::rx_media_components(config, request.flows);
  check(components.size() == 1 && components[0].number == 1 && components[0].media_type == 0, "one audio component");
  check(components[0].max_requested_bandwidth_bps == 41000, "audio bandwidth in bit/s");
  check(components[0].sub_components.size() == 3, "RTP, RTCP and floor control sub-components");
  check(components[0].sub_components[1].flow_usage == 1, "RTCP sub-component has Flow-Usage RTCP");
  request.flows.video_rtp = af::FlowPair{server_ip, ue_ip, 7000, 7400};
  request.flows.video_rtcp = af::FlowPair{server_ip, ue_ip, 7001, 7401};
  components = af::rx_media_components(config, request.flows);
  check(components.size() == 2 && components[1].number == 2 && components[1].media_type == 1, "video component");

  check(af::mc_resource_priority("mcpttp.15") == af::McResourcePriority{"mcpttp", 15}, "mcpttp.15");
  check(af::mc_resource_priority("MCPTTQ.0") == af::McResourcePriority{"mcpttq", 0}, "mcpttq.0");
  check(!af::mc_resource_priority("mcpttp.16"), "priority above 15 refused");
  check(!af::mc_resource_priority("ets.1"), "other namespace has no MC priority");
  check(!af::mc_resource_priority(""), "no Resource-Priority");

  const auto rx =
      af::RxConfig::parse({{"enabled", true}, {"destination_realm", "mcx.test"}, {"ue_subnets", {"10.45.0.0/16"}}});
  check(af::ipv4_in_subnets(ue_ip, rx.ue_subnets), "UE on the EPS is covered");
  check(!af::ipv4_in_subnets("192.168.1.20", rx.ue_subnets), "UE on WLAN is not covered");
  bool refused = false;
  try {
    (void)af::RxConfig::parse({{"enabled", true}, {"ue_subnets", {"10.45.0.0/16"}}});
  } catch (const std::exception &) {
    refused = true;
  }
  check(refused, "rx.enabled without destination_realm refused");
}

//------------------------------------------------------------------------------
// The AVPs of a message or Grouped AVP with the code and vendor.
std::vector<struct avp *> children(msg_or_avp *parent, std::uint32_t code, std::uint32_t vendor) {
  std::vector<struct avp *> found;
  struct avp *child = nullptr;
  check_fd(fd_msg_browse_internal(parent, MSG_BRW_FIRST_CHILD, reinterpret_cast<msg_or_avp **>(&child), nullptr),
           "browse");
  while (child) {
    struct avp_hdr *header = nullptr;
    check_fd(fd_msg_avp_hdr(child, &header), "header");
    if (header->avp_code == code && header->avp_vendor == vendor) found.push_back(child);
    check_fd(fd_msg_browse_internal(child, MSG_BRW_NEXT, reinterpret_cast<msg_or_avp **>(&child), nullptr), "browse");
  }
  return found;
}

std::uint32_t value_u32(struct avp *avp) { return u32_value(avp, "AVP"); }

std::string value_octets(struct avp *avp) { return octets_value(avp, "AVP", 4096); }

//------------------------------------------------------------------------------
// The fake PCRF's state: the problems it found in the requests, and the Rx session it serves.
struct Pcrf {
  RxDictionary *dictionary = nullptr;
  std::mutex mutex;
  std::string errors, session_id;

  void expect(bool value, const std::string &what) {
    if (value) return;
    std::lock_guard lock(mutex);
    errors += what + "; ";
  }
};

Pcrf pcrf;

//------------------------------------------------------------------------------
// TS 29.214 clause 5.6.1: what the initial and the update AA-Request of the test leg must carry.
void check_aa_request(struct msg *request) {
  const auto type = children(request, 533, vendor_3gpp);
  pcrf.expect(type.size() == 1, "one Rx-Request-Type");
  if (type.size() != 1) return;
  const bool initial = value_u32(type[0]) == 0;
  const auto components = children(request, 517, vendor_3gpp);
  const auto application = children(request, 504, vendor_3gpp);
  pcrf.expect(application.size() == 1 && value_octets(application[0]) == icsi,
              "AF-Application-Identifier is the MCPTT ICSI");
  const auto priority = children(request, 458, vendor_etsi);
  if (initial) {
    const auto address = children(request, 8, 0);
    in_addr expected{};
    ::inet_pton(AF_INET, ue_ip, &expected);
    pcrf.expect(address.size() == 1 &&
                    value_octets(address[0]) == std::string(reinterpret_cast<const char *>(&expected), 4),
                "Framed-IP-Address is the UE address");
    pcrf.expect(components.size() == 1, "one Media-Component-Description");
    if (components.size() == 1) {
      const auto subs = children(components[0], 519, vendor_3gpp);
      pcrf.expect(subs.size() == 3, "three Media-Sub-Components");
      if (!subs.empty()) {
        const auto flows = children(subs[0], 507, vendor_3gpp);
        pcrf.expect(flows.size() == 2 &&
                        value_octets(flows[0]) == "permit out 17 from 192.168.61.40 4000 to 10.45.0.9 4400" &&
                        value_octets(flows[1]) == "permit in 17 from 10.45.0.9 4400 to 192.168.61.40 4000",
                    "speech Flow-Descriptions downlink then uplink");
      }
    }
    pcrf.expect(priority.size() == 1 && value_u32(priority[0]) == 15, "Reservation-Priority 15");
    const auto identifier = children(request, 547, vendor_3gpp);
    pcrf.expect(identifier.size() == 1 && value_octets(identifier[0]) == "mcpttp", "MCPTT-Identifier mcpttp");
    pcrf.expect(children(request, 513, vendor_3gpp).size() == 3, "three Specific-Action subscriptions");
    const auto features = children(request, 628, vendor_3gpp);
    pcrf.expect(features.size() == 1 && value_u32(children(features[0], 630, vendor_3gpp).at(0)) == feature_mcptt,
                "Supported-Features with MCPTT");
  } else {
    pcrf.expect(children(request, 8, 0).empty(), "no Framed-IP-Address in an update");
    pcrf.expect(priority.size() == 1 && value_u32(priority[0]) == 0, "Reservation-Priority back to DEFAULT");
    pcrf.expect(children(request, 547, vendor_3gpp).empty(), "no MCPTT-Identifier without a priority");
    bool floor_removed = false;
    for (auto *component : components)
      for (auto *sub : children(component, 519, vendor_3gpp)) {
        const auto status = children(sub, 511, vendor_3gpp);
        if (value_u32(children(sub, 509, vendor_3gpp).at(0)) == 3 && status.size() == 1 && value_u32(status[0]) == 4)
          floor_removed = true;
      }
    pcrf.expect(floor_removed, "floor control flow removed (Flow-Status REMOVED)");
  }
}

//------------------------------------------------------------------------------
// The fake PCRF adds a 3GPP AVP that the AF only receives, an Unsigned32 or Enumerated value, with or without the M
// flag.
void add_received(struct msg *message, std::uint32_t code, bool mandatory, std::uint32_t value) {
  struct dict_avp_request request{vendor_3gpp, code, nullptr};
  struct dict_object *model = nullptr;
  // Known to the fake PCRF even when the shared Rx dictionary lacks it, so that the AF's handling is what is tested.
  if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE_AND_VENDOR, &request, &model, ENOENT) != 0)
    model = add_avp(code, "PCRF-only AVP", AVP_TYPE_OCTETSTRING, vendor_3gpp, false, false);
  struct avp *avp = nullptr;
  check_fd(fd_msg_avp_new(model, 0, &avp), "new AVP");
  const std::uint32_t network = htonl(value);
  union avp_value storage{};
  storage.os.data = reinterpret_cast<std::uint8_t *>(const_cast<std::uint32_t *>(&network));
  storage.os.len = sizeof network;
  check_fd(fd_msg_avp_setvalue(avp, &storage), "set AVP");
  struct avp_hdr *header = nullptr;
  check_fd(fd_msg_avp_hdr(avp, &header), "AVP header");
  if (mandatory) header->avp_flags |= AVP_FLAG_MANDATORY;
  check_fd(fd_msg_avp_add(message, MSG_BRW_LAST_CHILD, avp), "add AVP");
}

//------------------------------------------------------------------------------
// The fake PCRF sends a Re-Auth-Request (Specific-Action) or an Abort-Session-Request to the AF.
void send_to_af(bool abort) {
  auto &dictionary = *pcrf.dictionary;
  std::string session_id;
  {
    std::lock_guard lock(pcrf.mutex);
    session_id = pcrf.session_id;
  }
  struct msg *request = nullptr;
  check_fd(fd_msg_new(abort ? dictionary.asr : dictionary.rar, MSGFL_ALLOC_ETEID, &request), "new request");
  struct msg_hdr *header = nullptr;
  check_fd(fd_msg_hdr(request, &header), "header");
  header->msg_appl = af::rx_application_id;
  add_octets(request, dictionary.session_id, session_id);
  check_fd(fd_msg_add_origin(request, 0), "origin");
  add_octets(request, dictionary.destination_realm, "mcx.test");
  add_octets(request, dictionary.destination_host, "af.mcx.test");
  add_u32(request, dictionary.auth_application_id, af::rx_application_id);
  if (abort) {
    add_i32(request, dictionary.abort_cause, 0);
  } else {
    add_u32(request, find_required(DICT_AVP, AVP_BY_NAME, "Re-Auth-Request-Type", "Re-Auth-Request-Type"), 0);
    add_i32(request, dictionary.specific_action, 9);
  }
  // The AF's answer (checked through the AF's events) is only freed here.
  check_fd(fd_msg_send(
               &request, [](void *, struct msg **answer) { (void)fd_msg_free(*answer), *answer = nullptr; }, nullptr),
           "send");
}

//------------------------------------------------------------------------------
// The fake PCRF answers an AA-Request (DIAMETER_SUCCESS, the MCPTT feature) after checking it; after the initial one
// it sends a Re-Auth-Request, after the update an Abort-Session-Request.
int aa_request_callback(struct msg **message, struct avp *, struct session *, void *, enum disp_action *action) {
  try {
    struct avp *session = nullptr;
    check_fd(fd_msg_search_avp(*message, pcrf.dictionary->session_id, &session), "Session-Id");
    {
      std::lock_guard lock(pcrf.mutex);
      pcrf.session_id = value_octets(session);
    }
    check_aa_request(*message);
    const bool initial = value_u32(children(*message, 533, vendor_3gpp).at(0)) == 0;
    check_fd(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, message, 0), "answer");
    check_fd(fd_msg_add_origin(*message, 0), "origin");
    add_u32(*message, pcrf.dictionary->result_code, 2001);
    // As the Open5GS PCRF: IP-CAN-Type (TS 29.212, M flag set) and RAT-Type, which the AF does not read; an unknown
    // mandatory AVP in an answer aborts a freeDiameter 1.2.1 process, so the AF's dictionary must know them.
    add_received(*message, 1027, true, 5);     // IP-CAN-Type 3GPP-EPS
    add_received(*message, 1032, false, 1004); // RAT-Type EUTRAN
    if (initial) {
      auto *features = add_group(*message, pcrf.dictionary->supported_features);
      add_u32(features, pcrf.dictionary->vendor_id, vendor_3gpp);
      add_u32(features, pcrf.dictionary->feature_list_id, 1);
      add_u32(features, pcrf.dictionary->feature_list, feature_mcptt);
    }
    *action = DISP_ACT_SEND;
    std::thread([initial] {
      std::this_thread::sleep_for(300ms);
      send_to_af(!initial);
    }).detach();
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "fake PCRF: " << error.what() << '\n';
    return EINVAL;
  }
}

//------------------------------------------------------------------------------
// The fake PCRF answers the Session-Termination-Request: DIAMETER_SUCCESS when every request was as expected,
// DIAMETER_UNABLE_TO_COMPLY (5012) otherwise.
int session_termination_callback(struct msg **message, struct avp *, struct session *, void *,
                                 enum disp_action *action) {
  std::string errors;
  {
    std::lock_guard lock(pcrf.mutex);
    errors = pcrf.errors;
  }
  if (!errors.empty()) std::cerr << "fake PCRF found: " << errors << '\n';
  check_fd(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, message, 0), "answer");
  check_fd(fd_msg_add_origin(*message, 0), "origin");
  add_u32(*message, pcrf.dictionary->result_code, errors.empty() ? 2001 : 5012);
  *action = DISP_ACT_SEND;
  return 0;
}

//------------------------------------------------------------------------------
// Child process: the fake PCRF, until it is terminated.
int run_pcrf(const char *config_path) {
  auto core = start_diameter_core(config_path, {.rx = true});
  pcrf.dictionary = &core->rx();
  struct disp_when when{};
  when.app = pcrf.dictionary->application;
  struct disp_hdl *aa = nullptr, *termination = nullptr;
  when.command = pcrf.dictionary->aar;
  check_fd(fd_disp_register(aa_request_callback, DISP_HOW_CC, &when, nullptr, &aa), "register AAR");
  when.command = pcrf.dictionary->str;
  check_fd(fd_disp_register(session_termination_callback, DISP_HOW_CC, &when, nullptr, &termination), "register STR");
  core->start();
  for (;;) std::this_thread::sleep_for(1s);
}

//------------------------------------------------------------------------------
// Polls the client until an event of the kind comes, or fails after the timeout.
af::Event wait_for(af::RxClient &client, af::Event::Kind kind, std::vector<af::Event> &seen) {
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while (std::chrono::steady_clock::now() < deadline) {
    for (auto &event : client.poll()) {
      seen.push_back(event);
      if (event.kind == kind) return event;
    }
    std::this_thread::sleep_for(20ms);
  }
  throw std::runtime_error(std::string("no ") + client.event_name(kind) + " event");
}

//------------------------------------------------------------------------------
// TS 29.214 clauses 4.4.1, 4.4.2, 4.4.4, 4.4.6.1 and 4.4.6.2: one Rx session through its whole life against the
// fake PCRF.
void Clause_4_4_RxSessionLifecycle(const char *self, const fs::path &base, unsigned port) {
  const auto pcrf_conf = base / "pcrf.conf", af_conf = base / "af.conf";
  write_file(pcrf_conf, native_config("pcrf.mcx.test", port, "af.mcx.test", port + 1));
  write_file(af_conf, native_config("af.mcx.test", port + 1, "pcrf.mcx.test", port));
  const pid_t child = ::fork();
  if (child == 0) {
    ::execl(self, self, "--pcrf", pcrf_conf.c_str(), static_cast<char *>(nullptr));
    _exit(127);
  }
  check(child > 0, "fork fake PCRF failed");
  auto stop = [&] {
    ::kill(child, SIGTERM);
    int status = 0;
    (void)::waitpid(child, &status, 0);
  };
  try {
    auto config = af::RxConfig::parse({{"enabled", true},
                                       {"destination_realm", "mcx.test"},
                                       {"ue_subnets", {"10.45.0.0/16"}},
                                       {"af_application_identifier", icsi}});
    auto core = start_diameter_core(af_conf.string(), {.rx = true});
    af::RxClient client(config, core);
    wait_for_peer({"pcrf.mcx.test"}, 10s, af::rx_application_id);
    std::vector<af::Event> seen;

    client.open("dialog-1", leg_request());
    const auto created = wait_for(client, af::Event::Kind::created, seen);
    check(created.status == 2001, "initial AA-Answer DIAMETER_SUCCESS");
    check(client.status().at("sessions").at(0).at("features") == feature_mcptt, "MCPTT feature accepted");

    const auto re_auth = wait_for(client, af::Event::Kind::notified, seen);
    check(re_auth.detail == "INDICATION_OF_FAILED_RESOURCES_ALLOCATION", "Re-Auth-Request Specific-Action reported");

    auto lowered = leg_request();
    lowered.priority = "normal";
    lowered.resource_priority.clear();
    lowered.flows.floor.reset();
    client.refresh("dialog-1", lowered);
    const auto updated = wait_for(client, af::Event::Kind::updated, seen);
    check(updated.status == 2001, "update AA-Answer DIAMETER_SUCCESS");

    const auto aborted = wait_for(client, af::Event::Kind::terminated, seen);
    check(aborted.detail == "Abort-Cause 0", "Abort-Session-Request reported");
    const auto ended = wait_for(client, af::Event::Kind::deleted, seen);
    check(ended.status == 2001, "Session-Termination-Answer DIAMETER_SUCCESS: every request as expected");
    check(client.keys().empty(), "Rx session forgotten after its termination");
    stop();
  } catch (...) {
    stop();
    throw;
  }
}

} // namespace

int main(int argc, char **argv) {
  if (argc == 3 && std::string(argv[1]) == "--pcrf") return run_pcrf(argv[2]);
  const auto base = fs::temp_directory_path() / ("openmcx-rx-" + std::to_string(::getpid()));
  fs::create_directories(base);
  const unsigned port = 34000 + (::getpid() % 10000) * 2;
  try {
    Clause_4_4_1_ServiceInformation();
    Clause_4_4_RxSessionLifecycle(argv[0], base, port);
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    fs::remove_all(base);
    return 1;
  }
  fs::remove_all(base);
  std::cout << "TS 29.214 Rx session (AAR initial and update, RAR, ASR, STR) completed against a PCRF peer over TCP\n";
  return 0;
}
