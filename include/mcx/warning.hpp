//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The warning codes and texts of the MC services: the Warning header field texts of TS 24.379 clause 4.4.2
// (MCPTT) and TS 24.281 clause 4.4.2 (MCVideo), carried with warn-code 399.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 3261.

#pragma once
#include "mcx/service.hpp"

#include <stdexcept>
#include <string>
#include <string_view>

namespace mcx {
//------------------------------------------------------------------------------
// TS 24.379 table 4.4.2-2 and TS 24.281 table 4.4.2-2: the reasons the call-handling core refuses or reports
// something with a Warning header field. Each MC service numbers and words them in its own table: TS 24.379
// clause 4.4.2 for MCPTT, TS 24.281 clause 4.4.2 for MCVideo (for example 191 in MCVideo is the invalid location
// target list).
enum class Warning {
  function_not_allowed,                  // code 100 in TS 24.379 and TS 24.281 table 4.4.2-2, with a detailed reason
  service_authorisation_failed,          // code 101 in TS 24.379 and TS 24.281 table 4.4.2-2
  too_many_affiliations,                 // code 102 in TS 24.379 and TS 24.281 table 4.4.2-2
  broadcast_subscription,                // code 105 in TS 24.379 and TS 24.281 table 4.4.2-2
  private_call_not_authorised,           // code 107 in TS 24.379 and TS 24.281 table 4.4.2-2
  declined,                              // code 110 in TS 24.379 and TS 24.281 table 4.4.2-2
  required_members_abandoned,            // code 112 in TS 24.379 and TS 24.281 table 4.4.2-2
  group_disabled,                        // code 115 in TS 24.379 and TS 24.281 table 4.4.2-2
  not_group_member,                      // code 116 in TS 24.379 and TS 24.281 table 4.4.2-2
  prearranged_group_mismatch,            // code 117 in TS 24.379 and TS 24.281 table 4.4.2-2
  chat_group_mismatch,                   // code 118 in TS 24.379 and TS 24.281 table 4.4.2-2
  group_call_initiation_not_authorised,  // code 119 in TS 24.379 and TS 24.281 table 4.4.2-2
  not_affiliated,                        // code 120 in TS 24.379 and TS 24.281 table 4.4.2-2
  group_call_join_not_authorised,        // code 121 in TS 24.379 and TS 24.281 table 4.4.2-2
  too_many_participants,                 // code 122 in TS 24.379 and TS 24.281 table 4.4.2-2
  session_exists,                        // code 123 in TS 24.379 and TS 24.281 table 4.4.2-2
  max_private_calls,                     // code 124 in TS 24.379 and TS 24.281 table 4.4.2-2
  automatic_commencement_not_authorised, // code 125 in TS 24.379 and TS 24.281 table 4.4.2-2
  manual_commencement_not_authorised,    // code 126 in TS 24.379 and TS 24.281 table 4.4.2-2
  not_callable_in_private_call,          // code 127 in TS 24.379 and TS 24.281 table 4.4.2-2
  conference_subscription_not_allowed,   // code 138 in TS 24.379 and TS 24.281 table 4.4.2-2
  integrity_check_failed,                // code 139 in TS 24.379 and TS 24.281 table 4.4.2-2
  no_signing_key, // code 139 in TS 24.379 table 4.4.2-2, with a text of its own (MCVideo: the table text)
  decrypt_failed, // code 140 in TS 24.379 and TS 24.281 table 4.4.2-2
  unknown_user,   // code 141 in TS 24.379 and TS 24.281 table 4.4.2-2
  force_auto_answer_not_authorised,      // code 143 in TS 24.379 and TS 24.281 table 4.4.2-2
  callee_not_authorised,                 // code 144 in TS 24.379 and TS 24.281 table 4.4.2-2
  called_party_unknown,                  // code 145 in TS 24.379 and TS 24.281 table 4.4.2-2
  regrouped,                             // code 148 in TS 24.379 and TS 24.281 table 4.4.2-2
  info_pending,                          // code 149 in TS 24.379 and TS 24.281 table 4.4.2-2
  invalid_mime_combination,              // code 150 in TS 24.379 and TS 24.281 table 4.4.2-2
  call_back_not_authorised,              // code 151 in TS 24.379 table 4.4.2-2 (MCPTT only)
  call_back_cancel_not_authorised,       // code 152 in TS 24.379 table 4.4.2-2 (MCPTT only)
  first_to_answer_none_callable,         // code 153 in TS 24.379 table 4.4.2-2 (MCPTT only)
  ambient_not_authorised,                // code 154 in TS 24.379 (listening) and TS 24.281 (viewing) table 4.4.2-2
  first_to_answer_not_authorised,        // code 156 in TS 24.379 table 4.4.2-2 (MCPTT only)
  remote_group_call_not_authorised,      // code 157 in TS 24.379 table 4.4.2-2 (MCPTT only)
  remote_private_call_not_authorised,    // code 158 in TS 24.379 table 4.4.2-2 (MCPTT only)
  caller_not_permitted,                  // code 159 in TS 24.379 and TS 24.281 table 4.4.2-2
  regroup_create_not_authorised,         // code 160 in TS 24.379 and TS 24.281 table 4.4.2-2
  regroup_remove_not_authorised,         // code 161 in TS 24.379 and TS 24.281 table 4.4.2-2
  group_unknown,                         // code 163 in TS 24.379 and TS 24.281 table 4.4.2-2
  regroup_id_in_use,                     // code 165 in TS 24.379 and TS 24.281 table 4.4.2-2
  preconfigured_use_only,                // code 167 in TS 24.379 and TS 24.281 table 4.4.2-2
  regroup_remove_in_emergency,           // code 169 in TS 24.379 table 4.4.2-2 (MCPTT only)
  transfer_not_authorised,               // code 170 in TS 24.379 table 4.4.2-2 (MCPTT only)
  forwarding_not_authorised,             // code 173 in TS 24.379 table 4.4.2-2 (MCPTT only)
  call_forwarded,                        // code 175 in TS 24.379 table 4.4.2-2 (MCPTT only)
  adhoc_initiation_not_authorised,       // code 185 in TS 24.379 and TS 24.281 table 4.4.2-2
  adhoc_not_supported,                   // code 186 in TS 24.379 and TS 24.281 table 4.4.2-2
  adhoc_participants_unknown,            // code 187 in TS 24.379 and TS 24.281 table 4.4.2-2
  adhoc_participation_not_allowed,       // code 188 in TS 24.379 and TS 24.281 table 4.4.2-2
  adhoc_too_many_participants,           // code 189 in TS 24.379 and TS 24.281 table 4.4.2-2
  adhoc_modify_not_authorised,           // code 190 in TS 24.379 and TS 24.281 table 4.4.2-2
  location_target_invalid,               // code 192 in TS 24.379 table 4.4.2-2, 191 in TS 24.281 table 4.4.2-2
  location_request_not_authorised,       // code 193 in TS 24.379 table 4.4.2-2, 192 in TS 24.281 table 4.4.2-2
  location_configuration_not_authorised, // code 194 in TS 24.379 table 4.4.2-2, 193 in TS 24.281 table 4.4.2-2
  // Added after the table: functional alias to group binding.
  alias_binding_not_authorised,   // code 176 in TS 24.379 and TS 24.281 table 4.4.2-2
  alias_binding_target_unknown,   // code 177 in TS 24.379 and TS 24.281 table 4.4.2-2
  alias_binding_exists,           // code 178 in TS 24.379 and TS 24.281 table 4.4.2-2
  group_selection_not_authorised, // code 155 in TS 24.379 table 4.4.2-2; TS 24.281 clause 9.2.4.3.1 step 3a
  alias_status_not_authorised,    // code 201 in TS 24.379 table 4.4.2-2 (MCPTT only)
};

//------------------------------------------------------------------------------
// TS 24.379 table 4.4.2-2: one row, the 3-digit text code and the explanatory text.
struct WarningEntry {
  int code = 0; // 0: the service does not define this warning
  const char *text = "";
};

//------------------------------------------------------------------------------
// TS 24.379 table 4.4.2-2: the MCPTT code and text of a warning. The MCPTT texts are those the server has always
// sent, so MCPTT behaviour does not change; the MCVideo texts (mcvideo_warning) are TS 24.281 table 4.4.2-2 verbatim.
// Deviations from TS 24.379 table 4.4.2-2, kept on purpose:
// - 123: "joining an ongoing MCPTT group call" instead of the table's "MCPTT session already exists" (the text clients
//   and labs have always matched).
// - 139 no_signing_key: "no XPK for the signatures" is not in the table; it tells a missing signing key apart from a
//   failed check (the table's 139 text is integrity_check_failed's).
// - 169: "user not authorised to remove regroup in an emergency state" as TS 24.379 clause 16.2.3.2 (procedure)
//   words it; the table says "user is not authorised to ...".
// - 185: "user is not authorised to initiate the adhoc group call" as TS 24.379 clause 17.3.2.1.1 words it;
//   the table says "user not authorised to ...".
constexpr WarningEntry mcptt_warning(Warning warning) {
  switch (warning) {
  case Warning::function_not_allowed: return {100, "function not allowed due to "};
  case Warning::service_authorisation_failed: return {101, "service authorisation failed"};
  case Warning::too_many_affiliations: return {102, "too many simultaneous affiliations"};
  case Warning::broadcast_subscription: return {105, "subscription not allowed in a broadcast group call"};
  case Warning::private_call_not_authorised: return {107, "user not authorised to make private calls"};
  case Warning::declined: return {110, "user declined the call invitation"};
  case Warning::required_members_abandoned:
    return {112, "group call abandoned due to required group members not part of the group session"};
  case Warning::group_disabled: return {115, "group is disabled"};
  case Warning::not_group_member: return {116, "user is not part of the MCPTT group"};
  case Warning::prearranged_group_mismatch:
    return {117, "the group identity indicated in the request is a prearranged group"};
  case Warning::chat_group_mismatch: return {118, "the group identity indicated in the request is a chat group"};
  case Warning::group_call_initiation_not_authorised: return {119, "user is not authorised to initiate the group call"};
  case Warning::not_affiliated: return {120, "user is not affiliated to this group"};
  case Warning::group_call_join_not_authorised: return {121, "user is not authorised to join the group call"};
  case Warning::too_many_participants: return {122, "too many participants"};
  case Warning::session_exists: return {123, "joining an ongoing MCPTT group call"}; // deviation, see above
  case Warning::max_private_calls: return {124, "maximum number of private calls reached"};
  case Warning::automatic_commencement_not_authorised:
    return {125, "user not authorised to make private call with automatic commencement"};
  case Warning::manual_commencement_not_authorised:
    return {126, "user not authorised to make private call with manual commencement"};
  case Warning::not_callable_in_private_call: return {127, "user not authorised to be called in private call"};
  case Warning::conference_subscription_not_allowed: return {138, "subscription of conference events not allowed"};
  case Warning::integrity_check_failed: return {139, "integrity protection check failed"};
  case Warning::no_signing_key: return {139, "no XPK for the signatures"}; // deviation, see above
  case Warning::decrypt_failed: return {140, "unable to decrypt XML content"};
  case Warning::unknown_user: return {141, "user unknown to the participating function"};
  case Warning::force_auto_answer_not_authorised: return {143, "not authorised to force auto answer"};
  case Warning::callee_not_authorised: return {144, "user not authorised to call this particular user"};
  case Warning::called_party_unknown: return {145, "unable to determine called party"};
  case Warning::regrouped: return {148, "group is regrouped"};
  case Warning::info_pending: return {149, "SIP INFO request pending"};
  case Warning::invalid_mime_combination: return {150, "invalid combinations of data received in MIME body"};
  case Warning::call_back_not_authorised: return {151, "user not authorised to make a private call call-back request"};
  case Warning::call_back_cancel_not_authorised:
    return {152, "user not authorised to make a private call call-back cancel request"};
  case Warning::first_to_answer_none_callable:
    return {153, "user not authorised to call any of the users requested in the first-to-answer call"};
  case Warning::ambient_not_authorised: return {154, "user not authorised to make ambient listening call"};
  case Warning::first_to_answer_not_authorised: return {156, "user not authorised to originate a first-to-answer call"};
  case Warning::remote_group_call_not_authorised:
    return {157, "user not authorised to request a remotely initiated group call"};
  case Warning::remote_private_call_not_authorised:
    return {158, "user not authorised to request a remotely initiated private call"};
  case Warning::caller_not_permitted: return {159, "user not authorised to be called by this originating user"};
  case Warning::regroup_create_not_authorised: return {160, "user not authorised to request creation of a regroup"};
  case Warning::regroup_remove_not_authorised: return {161, "user not authorised to request removal of a regroup"};
  case Warning::group_unknown: return {163, "the group identity indicated in the request does not exist"};
  case Warning::regroup_id_in_use: return {165, "group ID for regroup already in use"};
  case Warning::preconfigured_use_only: return {167, "call is not allowed on the preconfigured group"};
  case Warning::regroup_remove_in_emergency:
    return {169, "user not authorised to remove regroup in an emergency state"};
  case Warning::transfer_not_authorised: return {170, "user not authorised to make a private call transfer request"};
  case Warning::forwarding_not_authorised:
    return {173, "user not authorised to make a private call forwarding request"};
  case Warning::call_forwarded: return {175, "call is forwarded"};
  case Warning::alias_binding_not_authorised:
    return {176, "user not authorized to request for binding/unbinding of a functional alias with the MCPTT group(s) "
                 "for the MCPTT user"};
  case Warning::alias_binding_target_unknown:
    return {177, "unable to determine target functional alias or group for creating/removing a binding information for "
                 "the MCPTT user"};
  case Warning::alias_binding_exists:
    return {178, "MCPTT group binding already exists with other functional alias for the MCPTT user"};
  case Warning::group_selection_not_authorised: return {155, "user not authorised to change user's selected group"};
  case Warning::alias_status_not_authorised: return {201, "user not authorized to change the functional alias status"};
  case Warning::adhoc_initiation_not_authorised:
    return {185, "user is not authorised to initiate the adhoc group call"};
  case Warning::adhoc_not_supported: return {186, "the MCPTT system do not support adhoc group call"};
  case Warning::adhoc_participants_unknown: return {187, "can't determine the adhoc group participants"};
  case Warning::adhoc_participation_not_allowed: return {188, "user is not allowed to participate in adhoc group call"};
  case Warning::adhoc_too_many_participants:
    return {189, "maximum number of allowed adhoc group participants exceeded"};
  case Warning::adhoc_modify_not_authorised:
    return {190, "user is not authorised to initiate modify adhoc group call participants"};
  case Warning::location_target_invalid: return {192, "invalid location request target client list"};
  case Warning::location_request_not_authorised: return {193, "user not authorized to request location information"};
  case Warning::location_configuration_not_authorised:
    return {194, "user not authorized to request location configuration changes"};
  }
  return {};
}

//------------------------------------------------------------------------------
// TS 24.281 table 4.4.2-2: the MCVideo code and text of a warning, verbatim; {} for a warning MCVideo does not define.
constexpr WarningEntry mcvideo_warning(Warning warning) {
  switch (warning) {
  case Warning::function_not_allowed: return {100, "function not allowed due to "};
  case Warning::service_authorisation_failed: return {101, "service authorisation failed"};
  case Warning::too_many_affiliations: return {102, "too many simultaneous affiliations"};
  case Warning::broadcast_subscription: return {105, "subscription not allowed in a broadcast group call"};
  case Warning::private_call_not_authorised: return {107, "user not authorised to make private calls"};
  case Warning::declined: return {110, "user declined the call invitation"};
  case Warning::required_members_abandoned:
    return {112, "group call abandoned due to required group members not part of the group session"};
  case Warning::group_disabled: return {115, "group is disabled"};
  case Warning::not_group_member: return {116, "user is not part of the MCVideo group"};
  case Warning::prearranged_group_mismatch:
    return {117, "the group identity indicated in the request is a prearranged group"};
  case Warning::chat_group_mismatch: return {118, "the group identity indicated in the request is a chat group"};
  case Warning::group_call_initiation_not_authorised: return {119, "user is not authorised to initiate the group call"};
  case Warning::not_affiliated: return {120, "user is not affiliated to this group"};
  case Warning::group_call_join_not_authorised: return {121, "user is not authorised to join the group call"};
  case Warning::too_many_participants: return {122, "too many participants"};
  case Warning::session_exists: return {123, "MCVideo session already exists"};
  case Warning::max_private_calls: return {124, "maximum number of private calls reached"};
  case Warning::automatic_commencement_not_authorised:
    return {125, "user not authorised to make private call with automatic commencement"};
  case Warning::manual_commencement_not_authorised:
    return {126, "user not authorised to make private call with manual commencement"};
  case Warning::not_callable_in_private_call: return {127, "user not authorised to be called in private call"};
  case Warning::conference_subscription_not_allowed: return {138, "subscription of conference events not allowed"};
  case Warning::integrity_check_failed:
  case Warning::no_signing_key: return {139, "integrity protection check failed"};
  case Warning::decrypt_failed: return {140, "unable to decrypt XML content"};
  case Warning::unknown_user: return {141, "user unknown to the participating function"};
  case Warning::force_auto_answer_not_authorised: return {143, "not authorised to force auto answer"};
  case Warning::callee_not_authorised: return {144, "user not authorised to call this particular user"};
  case Warning::called_party_unknown: return {145, "unable to determine called party"};
  case Warning::regrouped: return {148, "group is regrouped"};
  case Warning::info_pending: return {149, "SIP-INFO request pending"};
  case Warning::invalid_mime_combination: return {150, "invalid combinations of data received in MIME body"};
  case Warning::ambient_not_authorised: return {154, "user not authorised to make ambient viewing call"};
  case Warning::caller_not_permitted: return {159, "user not authorised to be called by this originating user"};
  case Warning::regroup_create_not_authorised: return {160, "user not authorised to request creation of a regroup"};
  case Warning::regroup_remove_not_authorised: return {161, "user not authorised to request removal of a regroup"};
  case Warning::group_unknown: return {163, "the group identity indicated in the request does not exist"};
  case Warning::regroup_id_in_use: return {165, "group ID for regroup already in use"};
  case Warning::preconfigured_use_only: return {167, "call is not allowed on the preconfigured group"};
  case Warning::adhoc_initiation_not_authorised: return {185, "user not authorised to initiate the adhoc group call"};
  case Warning::adhoc_not_supported: return {186, "the MCVideo system do not support adhoc group call"};
  case Warning::adhoc_participants_unknown: return {187, "can't determine the adhoc group participants"};
  case Warning::adhoc_participation_not_allowed: return {188, "user is not allowed to participate in adhoc group call"};
  case Warning::adhoc_too_many_participants:
    return {189, "maximum number of allowed adhoc group participants exceeded"};
  case Warning::adhoc_modify_not_authorised:
    return {190, "user is not authorised to initiate modify adhoc group call participants"};
  case Warning::location_target_invalid: return {191, "Invalid location request target client list"};
  case Warning::location_request_not_authorised: return {192, "user not authorized to request location information"};
  case Warning::location_configuration_not_authorised:
    return {193, "user not authorized to request location configuration changes"};
  case Warning::alias_binding_not_authorised:
    return {176, "user not authorized to request for binding/unbinding of a functional alias with the MCVideo group(s) "
                 "for the MCVideo user"};
  case Warning::alias_binding_target_unknown:
    return {177, "unable to determine target functional alias or group for creating/removing a binding information for "
                 "the MCVideo user"};
  case Warning::alias_binding_exists:
    return {178, "MCVideo group binding already exists with other functional alias for the MCVideo user"};
  // Not in TS 24.281 table 4.4.2-2, but sent by TS 24.281 clause 9.2.4.3.1 step 3a with this text.
  case Warning::group_selection_not_authorised: return {155, "user not authorised to change user's selected group"};
  // TS 24.281 has no first-to-answer, call-back, remotely initiated call,
  // transfer or forwarding request, no emergency regroup removal warning and no
  // functional alias status warning (TS 24.281 clause 20.2.2.2.3 has no step 4B).
  case Warning::call_back_not_authorised:
  case Warning::call_back_cancel_not_authorised:
  case Warning::first_to_answer_none_callable:
  case Warning::first_to_answer_not_authorised:
  case Warning::remote_group_call_not_authorised:
  case Warning::remote_private_call_not_authorised:
  case Warning::regroup_remove_in_emergency:
  case Warning::transfer_not_authorised:
  case Warning::forwarding_not_authorised:
  case Warning::call_forwarded:
  case Warning::alias_status_not_authorised: return {};
  }
  return {};
}

//------------------------------------------------------------------------------
// TS 24.282 table 4.9.2-2: the MCData code and text of a warning, for the procedures shared with the MCPTT and MCVideo
// servers (src/server/parts), as the MCData server has always sent them; {} for any other: the MCData server writes
// its other warnings itself.
constexpr WarningEntry mcdata_warning(Warning warning) {
  switch (warning) {
  case Warning::unknown_user: return {141, "user unknown to the participating function"};
  case Warning::location_target_invalid: return {244, "invalid location request target client list"};
  case Warning::location_request_not_authorised: return {245, "user not authorized to request location information"};
  case Warning::location_configuration_not_authorised:
    return {246, "user not authorized to request location configuration changes"};
  default: return {};
  }
}

//------------------------------------------------------------------------------
// TS 24.379 table 4.4.2-2, TS 24.281 table 4.4.2-2 or TS 24.282 table 4.9.2-2: the code and text of a warning in the
// service's own table.
constexpr WarningEntry warning_entry(const ServiceProfile &service, Warning warning) {
  switch (service.service) {
  case Service::mcptt: return mcptt_warning(warning);
  case Service::mcvideo: return mcvideo_warning(warning);
  case Service::mcdata: return mcdata_warning(warning);
  }
  return {};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.4.2 (table 4.4.2-1) and TS 24.281 clause 4.4.2: "<code> <text>" as carried in a 399 Warning
// header field (TS 24.379 clause 4.4.1, RFC 3261 section 20.43); detail completes 100's "function not allowed due to
// <detailed reason>". A warning the service does not define is a programming error: that service never offers the
// function.
inline std::string warning_text(const ServiceProfile &service, Warning warning, std::string_view detail = {}) {
  const auto entry = warning_entry(service, warning);
  if (!entry.code)
    throw std::logic_error(std::string("warning ") + std::to_string(static_cast<int>(warning)) + " undefined for " +
                           service.name);
  if ((warning == Warning::function_not_allowed) == detail.empty())
    throw std::logic_error("warning 100, and only 100, takes a detailed reason");
  return std::to_string(entry.code) + " " + entry.text + std::string(detail);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.4.1 (TS 24.281 and TS 24.282 likewise) and RFC 3261 section 20.43: a Warning header field
// value: code 399 (miscellaneous warning), the server's host name as warn-agent, and the quoted text.
inline std::string warning_value(std::string_view host, std::string_view text) {
  return "399 " + std::string(host) + " \"" + std::string(text) + "\"";
}
} // namespace mcx
