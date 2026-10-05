// The freeDiameter core of a process, shared by its Diameter applications (MCPTT-2's Diameter Data Management and
// Rx), and the helpers that build and read their messages. libfdcore keeps its state in globals, so a process has
// one core: the applications it advertises in its Capabilities-Exchange-Request are chosen before it starts.
//
// Specifications: RFC 6733, TS 29.283, TS 29.214 V19.3.0 (Rel-19), TS 29.229, ETSI TS 183 017.
#pragma once

#include "mcx/diameter.hpp"

#include <chrono>
#include <cstdint>
#include <freeDiameter/freeDiameter-host.h>
#include <freeDiameter/libfdcore.h>
#include <mutex>
#include <set>
#include <string>
#include <string_view>

namespace mcx::diameter {

// RFC 6733 section 5.3.3 and IANA: the vendor ID of 3GPP.
inline constexpr vendor_id_t vendor_3gpp = 10415;
// ETSI TS 183 017 clause 7.3: the vendor ID of ETSI (Reservation-Priority).
inline constexpr vendor_id_t vendor_etsi = 13019;

[[noreturn]] void fail_fd(int error, const char *operation);
void check_fd(int result, const char *operation);
std::string read_bounded_file(const std::string &path);
std::set<std::string> configured_peers(const std::string &path);
void wait_for_peer(const std::set<std::string> &peers, std::chrono::milliseconds timeout,
                   application_id_t application = 0);

struct dict_object *find_required(enum dict_object_type type, int criteria, const void *value, const char *name);
// An AVP with the V flag when it has a vendor and the M flag when it is mandatory, unless it is already known; with
// mandatory_fixed false, the M flag "may" be set (either value is accepted on reception).
struct dict_object *add_avp(std::uint32_t code, const char *name, enum dict_avp_basetype type,
                            vendor_id_t vendor = vendor_3gpp, bool mandatory = true, bool mandatory_fixed = true);
struct dict_object *ensure_vendor(vendor_id_t id, const char *name);
struct dict_object *ensure_application(application_id_t id, const char *name, struct dict_object *vendor);
// A command of an application: the request (R and P flags) or its answer (P flag).
struct dict_object *add_command(struct dict_object *application, command_code_t code, const char *name, bool request);

void add_u32(msg_or_avp *parent, struct dict_object *model, std::uint32_t value);
void add_i32(msg_or_avp *parent, struct dict_object *model, std::int32_t value);
void add_u64(msg_or_avp *parent, struct dict_object *model, std::uint64_t value);
void add_octets(msg_or_avp *parent, struct dict_object *model, std::string_view value);
struct avp *add_group(msg_or_avp *parent, struct dict_object *model);
// The first AVP inside a message or Grouped AVP with the code and vendor, or null.
struct avp *child_by_code(msg_or_avp *parent, std::uint32_t code, std::uint32_t vendor);
std::uint32_t u32_value(struct avp *avp, const char *name);
std::uint64_t u64_value(struct avp *avp, const char *name);
std::string octets_value(struct avp *avp, const char *name, std::size_t limit);

//------------------------------------------------------------------------------
// TS 29.283: the dictionary objects of the Diameter Data Management application (Data-Pull-Request and
// Data-Pull-Answer and their AVPs) and the base protocol AVPs used.
struct DataManagementDictionary {
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

DataManagementDictionary register_data_management_dictionary();

//------------------------------------------------------------------------------
// TS 29.214 clause 5.6 and table 5.3.0.1: the dictionary objects of the Rx application (AA, Session-Termination,
// Re-Auth and Abort-Session commands), its AVPs and the base protocol AVPs used.
struct RxDictionary {
  struct dict_object *vendor = nullptr;
  struct dict_object *application = nullptr;
  struct dict_object *aar = nullptr, *aaa = nullptr, *str = nullptr, *sta = nullptr;
  struct dict_object *rar = nullptr, *raa = nullptr, *asr = nullptr, *asa = nullptr;
  // RFC 6733 and RFC 7155 (Framed-IP-Address).
  struct dict_object *session_id = nullptr, *auth_application_id = nullptr, *destination_realm = nullptr,
                     *destination_host = nullptr, *result_code = nullptr, *experimental_result = nullptr,
                     *experimental_result_code = nullptr, *vendor_id = nullptr, *termination_cause = nullptr,
                     *framed_ip_address = nullptr;
  // TS 29.214 clause 5.3.
  struct dict_object *af_application_identifier = nullptr, *media_component_description = nullptr,
                     *media_component_number = nullptr, *media_sub_component = nullptr, *flow_number = nullptr,
                     *flow_description = nullptr, *flow_usage = nullptr, *flow_status = nullptr, *media_type = nullptr,
                     *max_requested_bandwidth_ul = nullptr, *max_requested_bandwidth_dl = nullptr,
                     *specific_action = nullptr, *rx_request_type = nullptr, *mcptt_identifier = nullptr,
                     *mcvideo_identifier = nullptr, *abort_cause = nullptr;
  // TS 29.229 clause 6.3.29 to 6.3.31.
  struct dict_object *supported_features = nullptr, *feature_list_id = nullptr, *feature_list = nullptr;
  // ETSI TS 183 017 clause 7.3.9.
  struct dict_object *reservation_priority = nullptr;
};

RxDictionary register_rx_dictionary();

} // namespace mcx::diameter

namespace mcx {

//------------------------------------------------------------------------------
// The freeDiameter core of the process: initialised with the dictionaries of the applications it serves and the
// configuration, advertising those applications; started by its first client and shut down when the last client
// releases it.
class DiameterCore {
public:
  DiameterCore(const std::string &config_path, DiameterApplications applications);
  ~DiameterCore();
  DiameterCore(const DiameterCore &) = delete;
  DiameterCore &operator=(const DiameterCore &) = delete;

  // Starts the core; later calls do nothing. A client calls it once its handlers are registered.
  void start();

  const std::string &config_path() const { return config_path_; }

  const DiameterApplications &applications() const { return applications_; }

  diameter::DataManagementDictionary &data_management();
  diameter::RxDictionary &rx();

private:
  void shutdown() noexcept;

  std::string config_path_;
  DiameterApplications applications_;
  bool initialized_ = false;
  std::mutex start_mutex_;
  bool started_ = false;
  diameter::DataManagementDictionary data_management_;
  diameter::RxDictionary rx_;
};

} // namespace mcx
