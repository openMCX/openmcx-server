// Warning header field texts: the MCPTT and MCVideo warning code tables and the texts built from them.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "mcx/warning.hpp"

#include <cassert>
#include <iostream>
#include <set>
#include <string>
using namespace mcx;

//------------------------------------------------------------------------------
// TS 24.379 table 4.4.2-2 and TS 24.281 table 4.4.2-2: the warning texts of the Warning header field (clause 4.4.2)
// for MCPTT and for MCVideo, the "100 function not allowed due to <detailed reason>" text, and the warnings a
// service does not define, which are programming errors.
int main() {
  // Every coded warning mcptt-server sent before the table existed (2026-09-25):
  // the MCPTT table must reproduce each one exactly and add no other.
  // Plus 101, added with MCVideo V1 as TS 24.379 clause 7.3.3 step 6 requires.
  const std::set<std::string> before{
      "101 service authorisation failed",
      "102 too many simultaneous affiliations",
      "105 subscription not allowed in a broadcast group call",
      "107 user not authorised to make private calls",
      "110 user declined the call invitation",
      "112 group call abandoned due to required group members not part of the group session",
      "115 group is disabled",
      "116 user is not part of the MCPTT group",
      "117 the group identity indicated in the request is a prearranged group",
      "118 the group identity indicated in the request is a chat group",
      "119 user is not authorised to initiate the group call",
      "120 user is not affiliated to this group",
      "121 user is not authorised to join the group call",
      "122 too many participants",
      "123 joining an ongoing MCPTT group call",
      "124 maximum number of private calls reached",
      "125 user not authorised to make private call with automatic commencement",
      "126 user not authorised to make private call with manual commencement",
      "127 user not authorised to be called in private call",
      "138 subscription of conference events not allowed",
      "139 no XPK for the signatures",
      "139 integrity protection check failed",
      "140 unable to decrypt XML content",
      "141 user unknown to the participating function",
      "143 not authorised to force auto answer",
      "144 user not authorised to call this particular user",
      "145 unable to determine called party",
      "148 group is regrouped",
      "149 SIP INFO request pending",
      "150 invalid combinations of data received in MIME body",
      "151 user not authorised to make a private call call-back request",
      "152 user not authorised to make a private call call-back cancel request",
      "153 user not authorised to call any of the users requested in the first-to-answer call",
      "154 user not authorised to make ambient listening call",
      "156 user not authorised to originate a first-to-answer call",
      "157 user not authorised to request a remotely initiated group call",
      "158 user not authorised to request a remotely initiated private call",
      "159 user not authorised to be called by this originating user",
      "160 user not authorised to request creation of a regroup",
      "161 user not authorised to request removal of a regroup",
      "163 the group identity indicated in the request does not exist",
      "165 group ID for regroup already in use",
      "167 call is not allowed on the preconfigured group",
      "169 user not authorised to remove regroup in an emergency state",
      "170 user not authorised to make a private call transfer request",
      "173 user not authorised to make a private call forwarding request",
      "175 call is forwarded",
      "185 user is not authorised to initiate the adhoc group call",
      "186 the MCPTT system do not support adhoc group call",
      "187 can't determine the adhoc group participants",
      "188 user is not allowed to participate in adhoc group call",
      "189 maximum number of allowed adhoc group participants exceeded",
      "190 user is not authorised to initiate modify adhoc group call participants",
      "192 invalid location request target client list",
      "193 user not authorized to request location information",
      "194 user not authorized to request location configuration changes"};
  std::set<std::string> now;
  for (int code = 0; code <= static_cast<int>(Warning::location_configuration_not_authorised); ++code)
    if (static_cast<Warning>(code) != Warning::function_not_allowed)
      now.insert(warning_text(mcptt_service, static_cast<Warning>(code)));
  assert(now == before);
  assert(warning_text(mcptt_service, Warning::function_not_allowed, "group call in progress") ==
         "100 function not allowed due to group call in progress");

  // TS 24.281 table 4.4.2-2 numbers some warnings differently from TS 24.379 table 4.4.2-2.
  assert(warning_text(mcvideo_service, Warning::location_target_invalid) ==
         "191 Invalid location request target client list");
  assert(warning_text(mcvideo_service, Warning::location_configuration_not_authorised) ==
         "193 user not authorized to request location configuration changes");
  assert(warning_text(mcvideo_service, Warning::ambient_not_authorised) ==
         "154 user not authorised to make ambient viewing call");
  assert(warning_text(mcvideo_service, Warning::session_exists) == "123 MCVideo session already exists");
  assert(warning_text(mcvideo_service, Warning::adhoc_not_supported) ==
         "186 the MCVideo system do not support adhoc group call");
  // TS 24.281 table 4.4.2-2 and TS 24.379 table 4.4.2-2: the functional alias to group binding warnings.
  // (155 is not in TS 24.281 table 4.4.2-2; TS 24.281 clause 9.2.4.3.1 step 3 uses it.)
  assert(warning_text(mcvideo_service, Warning::alias_binding_exists) ==
         "178 MCVideo group binding already exists with other functional alias for the MCVideo user");
  assert(warning_text(mcptt_service, Warning::alias_binding_not_authorised)
             .starts_with("176 user not authorized to request for binding"));
  assert(warning_text(mcvideo_service, Warning::group_selection_not_authorised) ==
         "155 user not authorised to change user's selected group");
  // TS 24.379 clause 9A.2.2.2.3 step 4B: warning 201, which TS 24.281 clause 20.2.2.2.3 does not send.
  assert(warning_text(mcptt_service, Warning::alias_status_not_authorised) ==
         "201 user not authorized to change the functional alias status");

  // Functions MCVideo does not have, and a 100 without its detailed reason, are programming errors.
  const auto refused = [](auto function) {
    try {
      function();
    } catch (const std::logic_error &) {
      return true;
    }
    return false;
  };
  assert(refused([] { (void)warning_text(mcvideo_service, Warning::transfer_not_authorised); }));
  assert(refused([] { (void)warning_text(mcvideo_service, Warning::call_forwarded); }));
  assert(refused([] { (void)warning_text(mcvideo_service, Warning::alias_status_not_authorised); }));
  assert(refused([] { (void)warning_text(mcptt_service, Warning::function_not_allowed); }));
  assert(refused([] { (void)warning_text(mcptt_service, Warning::not_affiliated, "detail"); }));
  std::cout << "warning tests passed\n";
}
