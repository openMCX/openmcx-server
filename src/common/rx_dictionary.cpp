//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The Rx dictionary: the Rx application, its commands and the AVPs the MC service server sends or may receive as
// AF, registered on the process's freeDiameter core when it serves Rx (src/common/diameter_core.hpp).
//
// Specifications: TS 29.214 V19.3.0 (Rel-19), TS 29.229, TS 29.212, TS 29.061, TS 29.273, ETSI TS 183 017, RFC 6733,
// RFC 4006, RFC 7155, RFC 7683, RFC 7944, RFC 8506, RFC 8583.
#include "diameter_core.hpp"

#include <cerrno>

namespace mcx::diameter {
namespace {

// TS 29.214 clauses 5.6.1 to 5.6.8: the command codes of AA (RFC 7155), Re-Auth, Session-Termination and
// Abort-Session (RFC 6733 sections 8.3.1, 8.4.1 and 8.5.1).
constexpr command_code_t aa_command_code = 265;
constexpr command_code_t re_auth_command_code = 258;
constexpr command_code_t session_termination_command_code = 275;
constexpr command_code_t abort_session_command_code = 274;

//------------------------------------------------------------------------------
// Helper: a command freeDiameter already knows (the base protocol defines Re-Auth, Session-Termination and
// Abort-Session), or a new one of the application.
struct dict_object *find_or_add_command(struct dict_object *application, command_code_t code, const char *name,
                                        bool request) {
  struct dict_object *command = nullptr;
  if (fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, request ? CMD_BY_CODE_R : CMD_BY_CODE_A, &code, &command,
                     ENOENT) == 0)
    return command;
  return add_command(application, code, name, request);
}

//------------------------------------------------------------------------------
// TS 29.214 clauses 5.6.2, 5.6.4, 5.6.6 and 5.6.7: the AVPs a PCRF may send in the AA-Answer, Re-Auth-Request,
// Session-Termination-Answer and Abort-Session-Request that the AF does not read, beyond the base protocol's: their
// codes and vendors (TS 29.214 table 5.3.0.1, TS 29.212, TS 29.061, TS 29.273, RFC 4006, RFC 7683, RFC 7944,
// RFC 8506, RFC 8583). freeDiameter 1.2.1 aborts the process on an unknown AVP with the M flag in an answer
// (fd_msg_parse_or_error), so each is known; each is kept opaque (OctetString, members not parsed) and its M flag
// is not fixed, so that any value and flags a PCRF sends are accepted.
struct ReceivedAvp {
  std::uint32_t code;
  vendor_id_t vendor;
  const char *name;
};

constexpr ReceivedAvp received_avps[] = {
    {301, 0, "DRMP"},
    {443, 0, "Subscription-Id"},
    {449, 0, "Final-Unit-Action"},
    {458, 0, "User-Equipment-Info"},
    {621, 0, "OC-Supported-Features"},
    {623, 0, "OC-OLR"},
    {650, 0, "Load"},
    {653, 0, "User-Equipment-Info-Extension"},
    {18, vendor_3gpp, "3GPP-SGSN-MCC-MNC"},
    {22, vendor_3gpp, "3GPP-User-Location-Info"},
    {23, vendor_3gpp, "3GPP-MS-TimeZone"},
    {29, vendor_3gpp, "TWAN-Identifier"},
    {501, vendor_3gpp, "Access-Network-Charging-Address"},
    {502, vendor_3gpp, "Access-Network-Charging-Identifier"},
    {510, vendor_3gpp, "Flows"},
    {526, vendor_3gpp, "Acceptable-Service-Info"},
    {530, vendor_3gpp, "Sponsored-Connectivity-Data"},
    {541, vendor_3gpp, "Retry-Interval"},
    {548, vendor_3gpp, "Service-Authorization-Info"},
    {569, vendor_3gpp, "NID"},
    {570, vendor_3gpp, "MA-Information"},
    {572, vendor_3gpp, "5GS-RAN-NAS-Release-Cause"},
    {578, vendor_3gpp, "Wireline-User-Location-Info"},
    {583, vendor_3gpp, "Serving-Satellite-Identity"},
    {584, vendor_3gpp, "PC-Session-Recovery-Status"},
    {1027, vendor_3gpp, "IP-CAN-Type"},
    {1032, vendor_3gpp, "RAT-Type"},
    {1050, vendor_3gpp, "AN-GW-Address"},
    {1503, vendor_3gpp, "AN-Trusted"},
    {2805, vendor_3gpp, "UE-Local-IP-Address"},
    {2806, vendor_3gpp, "UDP-Source-Port"},
    {2812, vendor_3gpp, "User-Location-Info-Time"},
    {2819, vendor_3gpp, "RAN-NAS-Release-Cause"},
    {2824, vendor_3gpp, "NetLoc-Access-Support"},
    {2843, vendor_3gpp, "TCP-Source-Port"},
};

//------------------------------------------------------------------------------
// Helper: registers a received-only AVP as opaque, its V flag fixed by its vendor and its M flag free, unless it is
// already known.
void add_received_avp(const ReceivedAvp &received) {
  struct dict_avp_request request{received.vendor, received.code, nullptr};
  struct dict_object *existing = nullptr;
  if (fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE_AND_VENDOR, &request, &existing, ENOENT) == 0) return;
  const std::uint8_t vendor_flag = received.vendor ? AVP_FLAG_VENDOR : 0;
  struct dict_avp_data data{received.code,   received.vendor, const_cast<char *>(received.name),
                            AVP_FLAG_VENDOR, vendor_flag,     AVP_TYPE_OCTETSTRING};
  check_fd(fd_dict_new(fd_g_config->cnf_dict, DICT_AVP, &data, nullptr, &existing), received.name);
}

} // namespace

//------------------------------------------------------------------------------
// TS 29.214 clause 5.6 and table 5.3.0.1: registers the Rx application, its commands and the AVPs the AF sends or
// reads, with the flags of table 5.3.0.1 (M,V; or V only where the M flag must not be set); Supported-Features
// and its members as TS 29.229 clause 6.3.29 to 6.3.31 (V); Reservation-Priority as ETSI TS 183 017 clause 7.3.9
// (vendor ETSI); Framed-IP-Address as RFC 7155 section 4.4.10.5.
RxDictionary register_rx_dictionary() {
  RxDictionary dictionary;
  dictionary.vendor = ensure_vendor(vendor_3gpp, "3GPP");
  (void)ensure_vendor(vendor_etsi, "ETSI");
  dictionary.application = ensure_application(diameter_rx_application_id, "Rx", dictionary.vendor);
  dictionary.aar = find_or_add_command(dictionary.application, aa_command_code, "AA-Request", true);
  dictionary.aaa = find_or_add_command(dictionary.application, aa_command_code, "AA-Answer", false);
  dictionary.rar = find_or_add_command(dictionary.application, re_auth_command_code, "Re-Auth-Request", true);
  dictionary.raa = find_or_add_command(dictionary.application, re_auth_command_code, "Re-Auth-Answer", false);
  dictionary.str = find_or_add_command(dictionary.application, session_termination_command_code,
                                       "Session-Termination-Request", true);
  dictionary.sta = find_or_add_command(dictionary.application, session_termination_command_code,
                                       "Session-Termination-Answer", false);
  dictionary.asr =
      find_or_add_command(dictionary.application, abort_session_command_code, "Abort-Session-Request", true);
  dictionary.asa =
      find_or_add_command(dictionary.application, abort_session_command_code, "Abort-Session-Answer", false);

  dictionary.session_id = find_required(DICT_AVP, AVP_BY_NAME, "Session-Id", "find Session-Id");
  dictionary.auth_application_id =
      find_required(DICT_AVP, AVP_BY_NAME, "Auth-Application-Id", "find Auth-Application-Id");
  dictionary.destination_realm = find_required(DICT_AVP, AVP_BY_NAME, "Destination-Realm", "find Destination-Realm");
  dictionary.destination_host = find_required(DICT_AVP, AVP_BY_NAME, "Destination-Host", "find Destination-Host");
  dictionary.result_code = find_required(DICT_AVP, AVP_BY_NAME, "Result-Code", "find Result-Code");
  dictionary.experimental_result =
      find_required(DICT_AVP, AVP_BY_NAME, "Experimental-Result", "find Experimental-Result");
  dictionary.experimental_result_code =
      find_required(DICT_AVP, AVP_BY_NAME, "Experimental-Result-Code", "find Experimental-Result-Code");
  dictionary.vendor_id = find_required(DICT_AVP, AVP_BY_NAME, "Vendor-Id", "find Vendor-Id");
  dictionary.termination_cause = find_required(DICT_AVP, AVP_BY_NAME, "Termination-Cause", "find Termination-Cause");
  dictionary.framed_ip_address = add_avp(8, "Framed-IP-Address", AVP_TYPE_OCTETSTRING, 0, true);

  dictionary.abort_cause = add_avp(500, "Abort-Cause", AVP_TYPE_INTEGER32);
  dictionary.af_application_identifier = add_avp(504, "AF-Application-Identifier", AVP_TYPE_OCTETSTRING);
  dictionary.flow_description = add_avp(507, "Flow-Description", AVP_TYPE_OCTETSTRING);
  dictionary.flow_number = add_avp(509, "Flow-Number", AVP_TYPE_UNSIGNED32);
  dictionary.flow_status = add_avp(511, "Flow-Status", AVP_TYPE_INTEGER32);
  dictionary.flow_usage = add_avp(512, "Flow-Usage", AVP_TYPE_INTEGER32);
  dictionary.specific_action = add_avp(513, "Specific-Action", AVP_TYPE_INTEGER32);
  dictionary.max_requested_bandwidth_dl = add_avp(515, "Max-Requested-Bandwidth-DL", AVP_TYPE_UNSIGNED32);
  dictionary.max_requested_bandwidth_ul = add_avp(516, "Max-Requested-Bandwidth-UL", AVP_TYPE_UNSIGNED32);
  dictionary.media_component_description = add_avp(517, "Media-Component-Description", AVP_TYPE_GROUPED);
  dictionary.media_component_number = add_avp(518, "Media-Component-Number", AVP_TYPE_UNSIGNED32);
  dictionary.media_sub_component = add_avp(519, "Media-Sub-Component", AVP_TYPE_GROUPED);
  dictionary.media_type = add_avp(520, "Media-Type", AVP_TYPE_INTEGER32);
  dictionary.rx_request_type = add_avp(533, "Rx-Request-Type", AVP_TYPE_INTEGER32, vendor_3gpp, false);
  dictionary.mcptt_identifier = add_avp(547, "MCPTT-Identifier", AVP_TYPE_OCTETSTRING, vendor_3gpp, false);
  dictionary.mcvideo_identifier = add_avp(562, "MCVideo-Identifier", AVP_TYPE_OCTETSTRING, vendor_3gpp, false);
  // TS 29.229 table 6.3.1 and TS 29.214 clause 5.4.1: the M flag of Supported-Features may be set.
  dictionary.supported_features = add_avp(628, "Supported-Features", AVP_TYPE_GROUPED, vendor_3gpp, false, false);
  dictionary.feature_list_id = add_avp(629, "Feature-List-ID", AVP_TYPE_UNSIGNED32, vendor_3gpp, false);
  dictionary.feature_list = add_avp(630, "Feature-List", AVP_TYPE_UNSIGNED32, vendor_3gpp, false);
  dictionary.reservation_priority = add_avp(458, "Reservation-Priority", AVP_TYPE_UNSIGNED32, vendor_etsi, false);
  for (const auto &received : received_avps) add_received_avp(received);
  return dictionary;
}

} // namespace mcx::diameter
