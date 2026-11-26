//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

#pragma once
// Decisions of the MCData server on service authorisation and the media plane, header only so that they are unit
// tested without the server: the request that uploads a new CSK, the size check of a standalone SDS over MSRP, and the
// one-to-one file distribution whose originator waits for the recipient's answer, and the functional alias a one-to-one
// communication over the media plane called.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 4975.
#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {

// RFC 4975 section 7.3: the MSRP status of a refused SEND (TS 24.582 clause 6.3.1.3 step 3: "the error code 403").
constexpr unsigned msrp_ok = 200;
constexpr unsigned msrp_forbidden = 403;

//------------------------------------------------------------------------------
// TS 24.282 clause 7.3.3 steps 2 and 3 (clause 7.2.2 steps 3 and 4) with TS 33.180 clause 9.2.1.3: a service
// authorisation (a SIP PUBLISH for poc-settings, or the client's REGISTER that a third-party REGISTER carries, clause
// 7.3.2) with a CSK upload (an application/mikey body) is protected with the CSK it uploads. It is opened with that CSK
// when the upload is accepted (authorise_csk), never with the CSK of an earlier binding of the same identity: a client
// that restarted without logging off uploads a new CSK, and the old one cannot open its request.
inline bool uploads_csk(std::string_view method, std::string_view event,
                        const std::vector<std::string_view> &content_types) {
  const bool authorisation = method == "REGISTER" || (method == "PUBLISH" && event == "poc-settings");
  return authorisation &&
         std::ranges::find(content_types, std::string_view("application/mikey")) != content_types.end();
}

//------------------------------------------------------------------------------
// TS 24.582 clause 6.3.1.3 steps 2a and 2b: a group SDS over the media plane is held to both group limits,
// <mcdata-max-data-in-single-request> and <mcdata-on-network-max-data-size-for-SDS>: the smaller of those set (0:
// none set).
inline std::uint64_t tightest_limit(std::uint64_t first, std::uint64_t second) {
  if (!first) return second;
  if (!second) return first;
  return std::min(first, second);
}

//------------------------------------------------------------------------------
// TS 24.582 clause 6.3.1.3 steps 1 to 4: the MSRP status of the SEND of a standalone SDS over the media plane: 403
// above its limit (step 1: <max-data-size-sds-bytes> one-to-one; step 2: the group's), and the procedure stops; else
// 200 (OK) and the message is forwarded. A limit of 0 is none.
inline unsigned standalone_sds_send_status(std::uint64_t payload_bytes, std::uint64_t limit) {
  return limit && payload_bytes > limit ? msrp_forbidden : msrp_ok;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 10.2.5.4.4: the originator of a one-to-one FD over the media plane is answered with the invited
// client's final response. When the invited client's leg ends (it declined, 480 with its warning), the originator's
// INVITE is still unanswered: the communication is not released then (TS 24.282 clause 13.2.2.2.4, "only one
// participant left"), which would end the INVITE with 487 and lose the refusal; the refusal answers it instead.
inline bool release_waits_for_answer(bool leaving_is_originator, bool originator_awaits_answer) {
  return !leaving_is_originator && originator_awaits_answer;
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 9.2.3.4.4 step 6a1, 9.2.4.4.4 and 10.2.5.4.4 step 8a1: a one-to-one SDS or FD over the media plane
// to a functional alias is redirected with 300 (Multiple Choices) to a user that activated it; the originator then
// invites that user with the alias in <called-functional-alias-URI> (clauses 9.2.3.2.3 step 3, 9.2.4.2.3 step 3 and
// 10.2.5.2.3 step 3). The recipient is told which alias was called, as on the signalling plane (clause 9.2.2.4.2 step
// 6A b-ii-D: the element reaches the recipient), in IP connectivity and in an ad hoc group communication (clause
// 24.4.2.2 step 15b-iv): the called alias per recipient (media_deliver), none when the request names none.
inline std::map<std::string, std::string> one_to_one_called_alias(const std::string &recipient,
                                                                  const std::string &called_alias) {
  if (recipient.empty() || called_alias.empty()) return {};
  return {{recipient, called_alias}};
}

} // namespace mcx
