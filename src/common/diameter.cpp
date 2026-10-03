// Diameter data management client and server: the Data-Pull-Request and Data-Pull-Answer carrying the MCPTT user
// profile, over freeDiameter with the ConnectTo peer names resolved at start.
//
// Specifications: TS 29.283, RFC 6733.
#include "mcx/diameter.hpp"

#include <netdb.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <freeDiameter/freeDiameter-host.h>
#include <freeDiameter/libfdcore.h>
#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <utility>

namespace mcx {
namespace {

constexpr vendor_id_t vendor_3gpp = 10415;
constexpr application_id_t app_id = diameter_data_management_application_id;
constexpr command_code_t dpr_code = diameter_data_pull_command_code;
constexpr std::size_t max_config_bytes = 1024 * 1024;
constexpr std::size_t max_identity_bytes = 1024;
constexpr std::size_t max_profile_bytes = 1024 * 1024;

//------------------------------------------------------------------------------
// Helper: throws the error of a failed freeDiameter or system operation.
[[noreturn]] void fail_fd(int error, const char *operation) {
  throw std::runtime_error(std::string(operation) + ": " + (error ? std::strerror(error) : "failed"));
}

//------------------------------------------------------------------------------
// Helper: throws unless a freeDiameter result is 0.
void check_fd(int result, const char *operation) {
  if (result != 0) fail_fd(result, operation);
}

//------------------------------------------------------------------------------
// Helper: the whole configuration file, at most 1 MiB.
std::string read_bounded_file(const std::string &path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("cannot open " + path);
  input.seekg(0, std::ios::end);
  const auto size = input.tellg();
  if (size < 0 || static_cast<std::uint64_t>(size) > max_config_bytes)
    throw std::runtime_error("Diameter configuration is too large");
  input.seekg(0);
  return std::string(std::istreambuf_iterator<char>(input), {});
}

//------------------------------------------------------------------------------
// Helper: the Diameter identities of the ConnectPeer entries, the only peers allowed.
std::set<std::string> configured_peers(const std::string &path) {
  const auto text = read_bounded_file(path);
  const std::regex expression(R"peer(ConnectPeer\s*=\s*"([^"]+)")peer");
  std::set<std::string> peers;
  for (std::sregex_iterator it(text.begin(), text.end(), expression), end; it != end; ++it) {
    if (static_cast<std::size_t>((*it)[1].length()) > max_identity_bytes)
      throw std::runtime_error("configured Diameter peer identity is too long");
    peers.insert((*it)[1].str());
  }
  if (peers.empty()) throw std::runtime_error("Diameter configuration has no allowed ConnectPeer");
  return peers;
}

//------------------------------------------------------------------------------
// Helper: whether a host is a numeric IPv4 or IPv6 address.
bool numeric_address(const std::string &host) {
  unsigned char buffer[sizeof(struct in6_addr)];
  return ::inet_pton(AF_INET, host.c_str(), buffer) == 1 || ::inet_pton(AF_INET6, host.c_str(), buffer) == 1;
}

//------------------------------------------------------------------------------
// Helper: the first numeric address of a host name, or empty if it does not resolve.
std::string resolve_address(const std::string &host, bool ipv6) {
  struct addrinfo hints{};
  hints.ai_family = ipv6 ? AF_UNSPEC : AF_INET;
  hints.ai_flags = AI_ADDRCONFIG;
  struct addrinfo *found = nullptr;
  if (::getaddrinfo(host.c_str(), nullptr, &hints, &found) != 0 || !found) return {};
  char text[NI_MAXHOST] = {};
  const int result = ::getnameinfo(found->ai_addr, found->ai_addrlen, text, sizeof(text), nullptr, 0, NI_NUMERICHOST);
  ::freeaddrinfo(found);
  return result == 0 ? std::string(text) : std::string();
}

//------------------------------------------------------------------------------
// Helper: freeDiameter 1.2.1 resolves a ConnectTo host name once, while it parses the
// configuration, and fails the whole configuration when the name does not
// resolve. It keeps connecting to that address for the life of the process,
// so a peer that comes back on another address (a restarted container) is
// never reached again. Each name is therefore resolved here: a name that
// resolves is replaced by its address, and a peer whose name does not resolve
// yet is left without ConnectTo, so it is only accepted when it connects in.
// Both ends of MCPTT-2 connect to each other: when one restarts on a new
// address, it connects to the other with freshly resolved addresses.
std::string resolve_connect_to(const std::string &text) {
  const bool ipv6 = !std::regex_search(text, std::regex(R"re(\bNo_IPv6\s*;)re"));
  const std::regex expression(R"re(ConnectTo\s*=\s*"([^"]*)"\s*;\s*)re");
  std::string out;
  auto last = text.cbegin();
  for (std::sregex_iterator it(text.begin(), text.end(), expression), end; it != end; ++it) {
    const auto &match = *it;
    out.append(last, match[0].first);
    last = match[0].second;
    const auto host = match[1].str();
    if (numeric_address(host)) {
      out.append(match[0].first, match[0].second);
      continue;
    }
    const auto address = resolve_address(host, ipv6);
    if (address.empty()) {
      std::cerr << "Diameter peer address " << host << " does not resolve yet; waiting for the peer to connect\n";
      continue;
    }
    out += "ConnectTo = \"" + address + "\"; ";
  }
  out.append(last, text.cend());
  return out;
}

//------------------------------------------------------------------------------
// Helper: parses the configuration with each ConnectTo name resolved, through a
// private temporary copy that is removed once freeDiameter has read it.
// freeDiameter keeps the file name it was given, so it is pointed back at
// path, which the caller keeps alive.
void parse_configuration(const std::string &path) {
  const auto text = resolve_connect_to(read_bounded_file(path));
  const char *directory = std::getenv("TMPDIR");
  std::string name = std::string(directory && *directory ? directory : "/tmp") + "/mcx-diameter-XXXXXX";
  const int descriptor = ::mkstemp(name.data());
  if (descriptor < 0) fail_fd(errno, "create resolved Diameter configuration");
  std::size_t written = 0;
  while (written < text.size()) {
    const auto result = ::write(descriptor, text.data() + written, text.size() - written);
    if (result <= 0) {
      const int error = errno;
      ::close(descriptor);
      ::unlink(name.c_str());
      fail_fd(error, "write resolved Diameter configuration");
    }
    written += static_cast<std::size_t>(result);
  }
  ::close(descriptor);
  const int result = fd_core_parseconf(name.c_str());
  ::unlink(name.c_str());
  fd_g_config->cnf_file = const_cast<char *>(path.c_str());
  check_fd(result, "parse freeDiameter configuration");
}

//------------------------------------------------------------------------------
// TS 29.283 and RFC 6733: the dictionary objects of the Diameter Data Management application (Data-Pull-Request and
// Data-Pull-Answer and their AVPs) and the base protocol AVPs used.
struct Dictionary {
  struct dict_object *vendor = nullptr;
  struct dict_object *application = nullptr;
  struct dict_object *dpr = nullptr;
  struct dict_object *dpa = nullptr;
  struct dict_object *auth_session_state = nullptr;
  struct dict_object *destination_realm = nullptr;
  struct dict_object *result_code = nullptr;
  struct dict_object *experimental_result = nullptr;
  struct dict_object *experimental_result_code = nullptr;
  struct dict_object *vendor_id = nullptr;
  struct dict_object *user_identifier = nullptr;
  struct dict_object *mcptt_id = nullptr;
  struct dict_object *data_identification = nullptr;
  struct dict_object *data_prefix = nullptr;
  struct dict_object *data_flags = nullptr;
  struct dict_object *data = nullptr;
  struct dict_object *profile_data = nullptr;
  struct dict_object *user_data = nullptr;
};

//------------------------------------------------------------------------------
// Helper: a dictionary object that freeDiameter must already know.
struct dict_object *find_required(enum dict_object_type type, int criteria, const void *value, const char *name) {
  struct dict_object *object = nullptr;
  check_fd(fd_dict_search(fd_g_config->cnf_dict, type, criteria, value, &object, ENOENT), name);
  return object;
}

//------------------------------------------------------------------------------
// TS 29.283: registers a 3GPP vendor-specific AVP with the V and M flags, unless it is already known.
struct dict_object *add_avp(std::uint32_t code, const char *name, enum dict_avp_basetype type) {
  struct dict_avp_request request{vendor_3gpp, code, nullptr};
  struct dict_object *existing = nullptr;
  if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE_AND_VENDOR, &request, &existing, ENOENT) == 0)
    return existing;
  struct dict_avp_data data{code,
                            vendor_3gpp,
                            const_cast<char *>(name),
                            AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY,
                            AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY,
                            type};
  struct dict_object *object = nullptr;
  check_fd(fd_dict_new(fd_g_config->cnf_dict, DICT_AVP, &data, nullptr, &object), name);
  return object;
}

//------------------------------------------------------------------------------
// TS 29.283: registers the 3GPP vendor, the Diameter Data Management application, the Data-Pull-Request and
// Data-Pull-Answer commands (proxiable) and the AVPs User-Identifier (3102), MCPTT-ID (4500), Data-Identification
// (4501), Data-Identification-Prefix (4502), Data-Identification-Flags (4503), MC-Service-User-Profile-Data (4511),
// Data (4513) and User-Data (702).
Dictionary register_dictionary() {
  Dictionary dictionary;
  vendor_id_t vendor_id = vendor_3gpp;
  if (fd_dict_search(fd_g_config->cnf_dict, DICT_VENDOR, VENDOR_BY_ID, &vendor_id, &dictionary.vendor, ENOENT) != 0) {
    struct dict_vendor_data data{vendor_3gpp, const_cast<char *>("3GPP")};
    check_fd(fd_dict_new(fd_g_config->cnf_dict, DICT_VENDOR, &data, nullptr, &dictionary.vendor),
             "register 3GPP vendor");
  }
  application_id_t application_id = app_id;
  if (fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_ID, &application_id,
                     &dictionary.application, ENOENT) != 0) {
    struct dict_application_data data{app_id, const_cast<char *>("3GPP Diameter Data Management")};
    check_fd(fd_dict_new(fd_g_config->cnf_dict, DICT_APPLICATION, &data, dictionary.vendor, &dictionary.application),
             "register Diameter Data Management application");
  }
  struct dict_cmd_data request_data{dpr_code, const_cast<char *>("Data-Pull-Request"),
                                    static_cast<std::uint8_t>(CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE),
                                    static_cast<std::uint8_t>(CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE)};
  check_fd(fd_dict_new(fd_g_config->cnf_dict, DICT_COMMAND, &request_data, dictionary.application, &dictionary.dpr),
           "register Data-Pull-Request");
  struct dict_cmd_data answer_data{dpr_code, const_cast<char *>("Data-Pull-Answer"),
                                   static_cast<std::uint8_t>(CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE),
                                   static_cast<std::uint8_t>(CMD_FLAG_PROXIABLE)};
  check_fd(fd_dict_new(fd_g_config->cnf_dict, DICT_COMMAND, &answer_data, dictionary.application, &dictionary.dpa),
           "register Data-Pull-Answer");

  dictionary.auth_session_state = find_required(DICT_AVP, AVP_BY_NAME, "Auth-Session-State", "find Auth-Session-State");
  dictionary.destination_realm = find_required(DICT_AVP, AVP_BY_NAME, "Destination-Realm", "find Destination-Realm");
  dictionary.result_code = find_required(DICT_AVP, AVP_BY_NAME, "Result-Code", "find Result-Code");
  dictionary.experimental_result =
      find_required(DICT_AVP, AVP_BY_NAME, "Experimental-Result", "find Experimental-Result");
  dictionary.experimental_result_code =
      find_required(DICT_AVP, AVP_BY_NAME, "Experimental-Result-Code", "find Experimental-Result-Code");
  dictionary.vendor_id = find_required(DICT_AVP, AVP_BY_NAME, "Vendor-Id", "find Vendor-Id");
  dictionary.user_identifier = add_avp(3102, "User-Identifier", AVP_TYPE_GROUPED);
  dictionary.mcptt_id = add_avp(4500, "MCPTT-ID", AVP_TYPE_OCTETSTRING);
  dictionary.data_identification = add_avp(4501, "Data-Identification", AVP_TYPE_GROUPED);
  dictionary.data_prefix = add_avp(4502, "Data-Identification-Prefix", AVP_TYPE_UNSIGNED32);
  dictionary.data_flags = add_avp(4503, "Data-Identification-Flags", AVP_TYPE_UNSIGNED64);
  dictionary.profile_data = add_avp(4511, "MC-Service-User-Profile-Data", AVP_TYPE_GROUPED);
  dictionary.data = add_avp(4513, "Data", AVP_TYPE_GROUPED);
  dictionary.user_data = add_avp(702, "User-Data", AVP_TYPE_OCTETSTRING);
  return dictionary;
}

//------------------------------------------------------------------------------
// Helper: the freeDiameter core: initialised with the dictionary and the configuration, advertising the Diameter Data
// Management application, and shut down when destroyed.
class Core {
public:
  explicit Core(const std::string &config_path) : config_path_(config_path) {
    check_fd(fd_core_initialize(), "initialize freeDiameter");
    initialized_ = true;
    try {
      dictionary_ = register_dictionary();
      parse_configuration(config_path_);
      check_fd(fd_disp_app_support(dictionary_.application, dictionary_.vendor, 1, 0),
               "advertise Diameter Data Management application");
    } catch (...) {
      shutdown();
      throw;
    }
  }

  void start() {
    check_fd(fd_core_start(), "start freeDiameter");
    check_fd(fd_core_waitstartcomplete(), "wait for freeDiameter startup");
  }

  ~Core() { shutdown(); }

  Core(const Core &) = delete;
  Core &operator=(const Core &) = delete;

  Dictionary &dictionary() { return dictionary_; }

private:
  void shutdown() noexcept {
    if (!initialized_) return;
    (void)fd_core_shutdown();
    (void)fd_core_wait_shutdown_complete();
    initialized_ = false;
  }

  std::string config_path_;
  bool initialized_ = false;
  Dictionary dictionary_;
};

//------------------------------------------------------------------------------
// Helper: appends an Unsigned32 AVP.
void add_u32(msg_or_avp *parent, struct dict_object *model, std::uint32_t value) {
  struct avp *avp = nullptr;
  check_fd(fd_msg_avp_new(model, 0, &avp), "create Unsigned32 AVP");
  union avp_value storage{};
  storage.u32 = value;
  check_fd(fd_msg_avp_setvalue(avp, &storage), "set Unsigned32 AVP");
  check_fd(fd_msg_avp_add(parent, MSG_BRW_LAST_CHILD, avp), "add AVP");
}

//------------------------------------------------------------------------------
// Helper: appends an Unsigned64 AVP.
void add_u64(msg_or_avp *parent, struct dict_object *model, std::uint64_t value) {
  struct avp *avp = nullptr;
  check_fd(fd_msg_avp_new(model, 0, &avp), "create Unsigned64 AVP");
  union avp_value storage{};
  storage.u64 = value;
  check_fd(fd_msg_avp_setvalue(avp, &storage), "set Unsigned64 AVP");
  check_fd(fd_msg_avp_add(parent, MSG_BRW_LAST_CHILD, avp), "add AVP");
}

//------------------------------------------------------------------------------
// Helper: appends an OctetString AVP.
void add_octets(msg_or_avp *parent, struct dict_object *model, std::string_view value) {
  struct avp *avp = nullptr;
  check_fd(fd_msg_avp_new(model, 0, &avp), "create OctetString AVP");
  union avp_value storage{};
  storage.os.data = reinterpret_cast<std::uint8_t *>(const_cast<char *>(value.data()));
  storage.os.len = value.size();
  check_fd(fd_msg_avp_setvalue(avp, &storage), "set OctetString AVP");
  check_fd(fd_msg_avp_add(parent, MSG_BRW_LAST_CHILD, avp), "add AVP");
}

//------------------------------------------------------------------------------
// Helper: appends an empty Grouped AVP.
struct avp *add_group(msg_or_avp *parent, struct dict_object *model) {
  struct avp *group = nullptr;
  check_fd(fd_msg_avp_new(model, 0, &group), "create Grouped AVP");
  check_fd(fd_msg_avp_add(parent, MSG_BRW_LAST_CHILD, group), "add Grouped AVP");
  return group;
}

//------------------------------------------------------------------------------
// Helper: the first AVP inside a message or Grouped AVP with the given code and vendor, or null.
struct avp *child_by_code(msg_or_avp *parent, std::uint32_t code, std::uint32_t vendor) {
  struct avp *child = nullptr;
  check_fd(fd_msg_browse_internal(parent, MSG_BRW_FIRST_CHILD, reinterpret_cast<msg_or_avp **>(&child), nullptr),
           "browse AVPs");
  while (child != nullptr) {
    struct avp_hdr *header = nullptr;
    check_fd(fd_msg_avp_hdr(child, &header), "read AVP header");
    if (header->avp_code == code && header->avp_vendor == vendor) return child;
    check_fd(fd_msg_browse_internal(child, MSG_BRW_NEXT, reinterpret_cast<msg_or_avp **>(&child), nullptr),
             "browse AVPs");
  }
  return nullptr;
}

//------------------------------------------------------------------------------
// Helper: the value of an Unsigned32 AVP; throws if it is missing.
std::uint32_t u32_value(struct avp *avp, const char *name) {
  struct avp_hdr *header = nullptr;
  if (!avp || fd_msg_avp_hdr(avp, &header) != 0 || !header->avp_value)
    throw std::runtime_error(std::string("missing ") + name);
  return header->avp_value->u32;
}

//------------------------------------------------------------------------------
// Helper: the value of an Unsigned64 AVP; throws if it is missing.
std::uint64_t u64_value(struct avp *avp, const char *name) {
  struct avp_hdr *header = nullptr;
  if (!avp || fd_msg_avp_hdr(avp, &header) != 0 || !header->avp_value)
    throw std::runtime_error(std::string("missing ") + name);
  return header->avp_value->u64;
}

//------------------------------------------------------------------------------
// Helper: the value of an OctetString AVP of at most limit octets; throws if it is missing.
std::string octets_value(struct avp *avp, const char *name, std::size_t limit) {
  struct avp_hdr *header = nullptr;
  if (!avp || fd_msg_avp_hdr(avp, &header) != 0 || !header->avp_value)
    throw std::runtime_error(std::string("missing ") + name);
  if (header->avp_value->os.len > limit) throw std::runtime_error(std::string(name) + " exceeds size limit");
  return {reinterpret_cast<char *>(header->avp_value->os.data), header->avp_value->os.len};
}

//------------------------------------------------------------------------------
// RFC 6733 section 6.6: the Destination-Realm of a request for an MCPTT ID: its domain after the last "@", without
// URI parameters.
std::string realm_for(std::string_view mcptt_id) {
  if (mcptt_id.empty() || mcptt_id.size() > max_identity_bytes ||
      mcptt_id.find_first_of("\r\n\0") != std::string_view::npos)
    throw std::invalid_argument("invalid MCPTT ID");
  const auto at = mcptt_id.rfind('@');
  if (at == std::string_view::npos || at + 1 == mcptt_id.size())
    throw std::invalid_argument("MCPTT ID does not contain a routing realm");
  auto realm = mcptt_id.substr(at + 1);
  const auto terminator = realm.find_first_of(";>?");
  if (terminator != std::string_view::npos) realm = realm.substr(0, terminator);
  if (realm.empty()) throw std::invalid_argument("MCPTT ID has an empty routing realm");
  return std::string(realm);
}

//------------------------------------------------------------------------------
// RFC 6733 section 5.6: waits until one of the allowed peers is in the Open state.
void wait_for_peer(const std::set<std::string> &peers, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  do {
    for (const auto &identity : peers) {
      struct peer_hdr *peer = nullptr;
      if (fd_peer_getbyid(reinterpret_cast<DiamId_t>(const_cast<char *>(identity.data())), identity.size(), 1, &peer) ==
              0 &&
          peer != nullptr) {
        const auto state = fd_peer_get_state(peer);
        if (state == STATE_OPEN || state == STATE_OPEN_NEW) return;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  } while (std::chrono::steady_clock::now() < deadline);
  throw std::runtime_error("Diameter peer did not reach OPEN over SCTP");
}

//------------------------------------------------------------------------------
// Helper: the pending answer of one Data-Pull-Request.
struct PullState {
  std::promise<std::string> promise;
  Dictionary *dictionary = nullptr;
};

//------------------------------------------------------------------------------
// TS 29.283, RFC 6733 sections 7.1 and 7.6: reads the Data-Pull-Answer: with Result-Code 2001 (DIAMETER_SUCCESS) the
// User-Data of its MC-Service-User-Profile-Data, otherwise the Experimental-Result-Code as an error; frees the answer.
void answer_callback(void *opaque, struct msg **answer) {
  std::unique_ptr<std::shared_ptr<PullState>> holder(static_cast<std::shared_ptr<PullState> *>(opaque));
  const auto state = *holder;
  try {
    if (!answer || !*answer) throw std::runtime_error("empty Diameter answer");
    auto &dictionary = *state->dictionary;
    struct msg_hdr *message_header = nullptr;
    check_fd(fd_msg_hdr(*answer, &message_header), "read Diameter answer");
    if (message_header->msg_appl != app_id || message_header->msg_code != dpr_code ||
        (message_header->msg_flags & CMD_FLAG_REQUEST) != 0)
      throw std::runtime_error("unexpected Diameter answer header");
    struct avp *auth = nullptr;
    check_fd(fd_msg_search_avp(*answer, dictionary.auth_session_state, &auth), "find Auth-Session-State");
    if (u32_value(auth, "Auth-Session-State") != 1) throw std::runtime_error("stateful Diameter answer is unsupported");
    struct avp *result = nullptr;
    check_fd(fd_msg_search_avp(*answer, dictionary.result_code, &result), "find Result-Code");
    if (result != nullptr && u32_value(result, "Result-Code") == 2001) {
      struct avp *data = nullptr;
      check_fd(fd_msg_search_avp(*answer, dictionary.data, &data), "find Data");
      if (data == nullptr) throw std::runtime_error("Data-Pull-Answer without Data");
      auto *profile = child_by_code(data, 4511, vendor_3gpp);
      if (profile == nullptr) throw std::runtime_error("Data without MC-Service-User-Profile-Data");
      auto *user_data = child_by_code(profile, 702, vendor_3gpp);
      state->promise.set_value(octets_value(user_data, "User-Data", max_profile_bytes));
    } else {
      struct avp *experimental = nullptr;
      check_fd(fd_msg_search_avp(*answer, dictionary.experimental_result, &experimental), "find Experimental-Result");
      if (experimental == nullptr) throw std::runtime_error("Data-Pull-Answer without a result");
      auto *code = child_by_code(experimental, 298, 0);
      const auto value = u32_value(code, "Experimental-Result-Code");
      throw std::runtime_error("Diameter profile pull failed with result " + std::to_string(value));
    }
  } catch (...) {
    try {
      state->promise.set_exception(std::current_exception());
    } catch (...) {
      // The promise already has its value: nothing waits for this error.
    }
  }
  if (answer && *answer) {
    (void)fd_msg_free(*answer);
    *answer = nullptr;
  }
}

//------------------------------------------------------------------------------
// Helper: fails the pending Data-Pull-Request when no answer came in time.
void timeout_callback(void *opaque, DiamId_t, size_t, struct msg **) {
  std::unique_ptr<std::shared_ptr<PullState>> holder(static_cast<std::shared_ptr<PullState> *>(opaque));
  try {
    (*holder)->promise.set_exception(std::make_exception_ptr(std::runtime_error("Diameter pull timed out")));
  } catch (...) {
    // The promise already has its value: nothing waits for this error.
  }
}

//------------------------------------------------------------------------------
// RFC 6733 section 7.6: an Experimental-Result AVP with the 3GPP Vendor-Id and the code.
void add_experimental_result(struct msg *answer, Dictionary &dictionary, std::uint32_t code) {
  auto *group = add_group(answer, dictionary.experimental_result);
  add_u32(group, dictionary.vendor_id, vendor_3gpp);
  add_u32(group, dictionary.experimental_result_code, code);
}

} // namespace

//------------------------------------------------------------------------------
// Helper: the Diameter profile client: the allowed peers, the core and the request timeout.
class DiameterProfileClient::Impl {
public:
  Impl(std::string config_path, std::chrono::milliseconds timeout)
      : peers(configured_peers(config_path)), core(config_path), timeout(timeout) {
    if (timeout <= std::chrono::milliseconds::zero() || timeout > std::chrono::minutes(1))
      throw std::invalid_argument("Diameter timeout is outside supported bounds");
    core.start();
  }

  // TS 29.283: a Data-Pull-Request (Auth-Session-State NO_STATE_MAINTAINED, the realm of the MCPTT ID,
  // User-Identifier with the MCPTT-ID, Data-Identification with prefix 1 and flag bit 0) and the User-Data of its
  // answer.
  std::string pull(std::string_view mcptt_id) {
    const auto realm = realm_for(mcptt_id);
    wait_for_peer(peers, timeout);
    auto &dictionary = core.dictionary();
    struct msg *request = nullptr;
    check_fd(fd_msg_new(dictionary.dpr, MSGFL_ALLOC_ETEID, &request), "create Data-Pull-Request");
    try {
      check_fd(fd_msg_new_session(request, nullptr, 0), "create Session-Id");
      check_fd(fd_msg_add_origin(request, 0), "add Diameter origin");
      add_u32(request, dictionary.auth_session_state, 1);
      add_octets(request, dictionary.destination_realm, realm);
      auto *user = add_group(request, dictionary.user_identifier);
      add_octets(user, dictionary.mcptt_id, mcptt_id);
      auto *identification = add_group(request, dictionary.data_identification);
      add_u32(identification, dictionary.data_prefix, 1);
      add_u64(identification, dictionary.data_flags, 1);
    } catch (...) {
      (void)fd_msg_free(request);
      throw;
    }
    auto state = std::make_shared<PullState>();
    state->dictionary = &dictionary;
    auto future = state->promise.get_future();
    // freeDiameter calls exactly one of answer_callback and timeout_callback (libfdcore.h, fd_msg_send_timeout: an
    // answer after the timeout is discarded); that callback takes the holder back.
    auto holder = std::make_unique<std::shared_ptr<PullState>>(state);
    struct timespec absolute{};
    if (::clock_gettime(CLOCK_REALTIME, &absolute) != 0) {
      (void)fd_msg_free(request);
      throw std::runtime_error("cannot read realtime clock");
    }
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(timeout);
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(timeout - seconds);
    absolute.tv_sec += seconds.count();
    absolute.tv_nsec += nanoseconds.count();
    if (absolute.tv_nsec >= 1000000000L) {
      ++absolute.tv_sec;
      absolute.tv_nsec -= 1000000000L;
    }
    const int result = fd_msg_send_timeout(&request, answer_callback, holder.get(), timeout_callback, &absolute);
    if (result != 0) {
      if (request) (void)fd_msg_free(request);
      fail_fd(result, "send Data-Pull-Request"); // no callback will run: the holder is still ours
    }
    (void)holder.release(); // the callback owns it now
    if (future.wait_for(timeout + std::chrono::seconds(1)) != std::future_status::ready)
      throw std::runtime_error("freeDiameter did not complete timed request");
    return future.get();
  }

  std::set<std::string> peers;
  Core core;
  std::chrono::milliseconds timeout;
};

using ProfileMap = std::unordered_map<std::string, std::string>;

//------------------------------------------------------------------------------
// Helper: what the Data-Pull-Request handler of a server reads.
struct ServerState {
  Dictionary *dictionary = nullptr;
  // Replaced as a whole by replace_profiles; a request holds the map it read.
  std::mutex *profiles_mutex = nullptr;
  std::shared_ptr<const ProfileMap> *profiles = nullptr;
  const std::set<std::string> *allowed_peers = nullptr;
};

//------------------------------------------------------------------------------
// TS 29.283, RFC 6733 sections 7.1 and 7.6: answers a Data-Pull-Request: DIAMETER_INVALID_AVP_VALUE unless it comes
// from an allowed peer without session state and asks for prefix 1 with flag bit 0, an Experimental-Result 5001 for
// an unknown MCPTT ID, otherwise DIAMETER_SUCCESS with the profile as User-Data.
int data_pull_callback(struct msg **message, struct avp *, struct session *, void *opaque, enum disp_action *action) {
  auto &state = *static_cast<ServerState *>(opaque);
  auto &dictionary = *state.dictionary;
  try {
    DiamId_t source = nullptr;
    size_t source_length = 0;
    check_fd(fd_msg_source_get(*message, &source, &source_length), "read Diameter source");
    const std::string peer(reinterpret_cast<char *>(source), source_length);
    const bool allowed = state.allowed_peers->contains(peer);

    struct avp *auth = nullptr;
    check_fd(fd_msg_search_avp(*message, dictionary.auth_session_state, &auth), "find Auth-Session-State");
    struct avp *user = nullptr;
    check_fd(fd_msg_search_avp(*message, dictionary.user_identifier, &user), "find User-Identifier");
    struct avp *identification = nullptr;
    check_fd(fd_msg_search_avp(*message, dictionary.data_identification, &identification), "find Data-Identification");
    auto *id_avp = child_by_code(user, 4500, vendor_3gpp);
    const auto mcptt_id = octets_value(id_avp, "MCPTT-ID", max_identity_bytes);
    const auto prefix = u32_value(child_by_code(identification, 4502, vendor_3gpp), "Data-Identification-Prefix");
    const auto flags = u64_value(child_by_code(identification, 4503, vendor_3gpp), "Data-Identification-Flags");
    const bool valid = allowed && u32_value(auth, "Auth-Session-State") == 1 && prefix == 1 && (flags & 1U) == 1U;
    std::shared_ptr<const ProfileMap> profiles;
    {
      std::lock_guard lock(*state.profiles_mutex);
      profiles = *state.profiles;
    }
    const auto profile = profiles->find(mcptt_id);

    check_fd(fd_msg_new_answer_from_req(fd_g_config->cnf_dict, message, 0), "create Data-Pull-Answer");
    check_fd(fd_msg_add_origin(*message, 0), "add answer origin");
    add_u32(*message, dictionary.auth_session_state, 1);
    if (!valid) {
      check_fd(fd_msg_rescode_set(*message, const_cast<char *>("DIAMETER_INVALID_AVP_VALUE"),
                                  const_cast<char *>("invalid MCPTT profile request"), nullptr, 0),
               "set invalid request result");
    } else if (profile == profiles->end()) {
      add_experimental_result(*message, dictionary, 5001);
    } else {
      check_fd(fd_msg_rescode_set(*message, const_cast<char *>("DIAMETER_SUCCESS"), nullptr, nullptr, 0),
               "set success result");
      auto *data = add_group(*message, dictionary.data);
      auto *profile_data = add_group(data, dictionary.profile_data);
      add_octets(profile_data, dictionary.user_data, profile->second);
    }
    *action = DISP_ACT_SEND;
    return 0;
  } catch (...) {
    return EINVAL;
  }
}

//------------------------------------------------------------------------------
// Helper: the Diameter profile server: the allowed peers, the profiles served, the core and the handler.
class DiameterProfileServer::Impl {
public:
  Impl(std::string config_path, std::unordered_map<std::string, std::string> profile_values)
      : allowed_peers(configured_peers(config_path)), profiles(checked(std::move(profile_values))), core(config_path) {
    state = ServerState{&core.dictionary(), &profiles_mutex, &profiles, &allowed_peers};
    struct disp_when when{};
    when.app = core.dictionary().application;
    when.command = core.dictionary().dpr;
    check_fd(fd_disp_register(data_pull_callback, DISP_HOW_CC, &when, &state, &handler), "register Data-Pull handler");
    core.start();
  }

  ~Impl() {
    if (handler) (void)fd_disp_unregister(&handler, nullptr);
  }

  static std::shared_ptr<const ProfileMap> checked(ProfileMap values) {
    if (values.empty()) throw std::invalid_argument("no Diameter user profiles configured");
    for (const auto &[identity, profile] : values) {
      (void)realm_for(identity);
      if (profile.empty() || profile.size() > max_profile_bytes)
        throw std::invalid_argument("Diameter user profile size is invalid");
    }
    return std::make_shared<const ProfileMap>(std::move(values));
  }

  void replace(ProfileMap values) {
    auto next = checked(std::move(values));
    std::lock_guard lock(profiles_mutex);
    profiles = std::move(next);
  }

  std::set<std::string> allowed_peers;
  std::mutex profiles_mutex;
  std::shared_ptr<const ProfileMap> profiles;
  Core core;
  ServerState state;
  struct disp_hdl *handler = nullptr;
};

//------------------------------------------------------------------------------
// Helper: a Diameter profile client started on the freeDiameter configuration.
DiameterProfileClient::DiameterProfileClient(std::string native_config_path, std::chrono::milliseconds timeout)
    : impl_(std::make_unique<Impl>(std::move(native_config_path), timeout)) {}

//------------------------------------------------------------------------------
// Helper: stops the freeDiameter core.
DiameterProfileClient::~DiameterProfileClient() = default;

//------------------------------------------------------------------------------
// Helper: move construction and assignment.
DiameterProfileClient::DiameterProfileClient(DiameterProfileClient &&) noexcept = default;
DiameterProfileClient &DiameterProfileClient::operator=(DiameterProfileClient &&) noexcept = default;

//------------------------------------------------------------------------------
// TS 29.283: pulls the MCPTT user profile (User-Data XML, at most 1 MiB) of an MCPTT ID.
std::string DiameterProfileClient::pull(std::string_view mcptt_id) {
  if (!impl_) throw std::logic_error("Diameter client was moved from");
  return impl_->pull(mcptt_id);
}

//------------------------------------------------------------------------------
// Helper: a Diameter profile server started on the freeDiameter configuration with the profiles.
DiameterProfileServer::DiameterProfileServer(std::string native_config_path,
                                             std::unordered_map<std::string, std::string> profiles)
    : impl_(std::make_unique<Impl>(std::move(native_config_path), std::move(profiles))) {}

//------------------------------------------------------------------------------
// Helper: unregisters the handler and stops the freeDiameter core.
DiameterProfileServer::~DiameterProfileServer() = default;

//------------------------------------------------------------------------------
// Helper: replaces the profiles served, as a whole; invalid profiles are refused, keeping the old.
void DiameterProfileServer::replace_profiles(std::unordered_map<std::string, std::string> profiles) {
  if (!impl_) throw std::logic_error("Diameter server was moved from");
  impl_->replace(std::move(profiles));
}

//------------------------------------------------------------------------------
// Helper: move construction and assignment.
DiameterProfileServer::DiameterProfileServer(DiameterProfileServer &&) noexcept = default;
DiameterProfileServer &DiameterProfileServer::operator=(DiameterProfileServer &&) noexcept = default;

} // namespace mcx
