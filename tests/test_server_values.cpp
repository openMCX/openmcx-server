//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The request values of the MCPTT, MCVideo and MCData servers (src/server/request_values.hpp): the Expires header
// field, percent-decoding of URI components, the outcome rule of an implicit affiliation and the configuration
// management documents of a subscription's resource list; and the implicit floor request rules of the MCPTT server
// (src/server/implicit_floor.hpp); the location sent with a call request to the controlling function
// (src/server/talking_location.hpp); whether a group call is still ongoing for a new request
// (src/server/group_session.hpp); which procedure a re-INVITE in a pre-established session's dialog belongs to, the
// SDP answer to a call's re-INVITE in it, and the dialog a priority state change reaches a participant over such a
// session in (src/server/pre_session_rules.hpp).
//
// Specifications: RFC 3261, RFC 3986, RFC 5875, TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19),
// TS 24.484 V19.6.0 (Rel-19).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "group_session.hpp"
#include "implicit_floor.hpp"
#include "pre_session_rules.hpp"
#include "request_values.hpp"
#include "talking_location.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
using namespace mcx;

//------------------------------------------------------------------------------
// RFC 3261 section 20.19: Expires is a decimal number of seconds from 0 to 2**32-1; anything else is refused
// (std::nullopt, answered 400) instead of throwing out of the procedure.
static void Section_20_19_Expires() {
  assert(parse_expires("0") == 0U);
  assert(parse_expires("3600") == 3600U);
  assert(parse_expires("4294967295") == max_expires_s);
  assert(!parse_expires(""));
  assert(!parse_expires("4294967296"));
  assert(!parse_expires("99999999999999999999999"));
  assert(!parse_expires("-1"));
  assert(!parse_expires("60s"));
  assert(!parse_expires(" 60"));
  assert(!parse_expires("abc"));
}

//------------------------------------------------------------------------------
// RFC 3986 section 2.1: '%' with two hexadecimal digits is one octet; a bad or truncated escape is refused.
static void Section_2_1_PercentDecoding() {
  assert(percent_decode("group%40example.com") == "group@example.com");
  assert(percent_decode("a%2Fb%2fc") == "a/b/c");
  assert(percent_decode("plain") == "plain");
  assert(percent_decode("") == "");
  assert(!percent_decode("%zz"));
  assert(!percent_decode("%4"));
  assert(!percent_decode("%"));
  assert(!percent_decode("%4z"));
  assert(!percent_decode("x%g1"));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.11: an implicit affiliation is kept only when the request is finally accepted; a final
// failure or an exception (answered 403 after the guard is gone) cancels it.
static void Clause_9_2_2_3_11_ImplicitAffiliationCancellation() {
  assert(!implicit_affiliation_cancelled(200, false));
  assert(!implicit_affiliation_cancelled(202, false));
  assert(implicit_affiliation_cancelled(200, true));
  assert(implicit_affiliation_cancelled(403, false));
  assert(implicit_affiliation_cancelled(488, false));
  assert(implicit_affiliation_cancelled(302, false));
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step e and TS 37.579-1 table 5.3.2.6.1-1: the entries of one configuration
// subscription name the UE configuration, user profile and service configuration documents, by AUID, XUI and name;
// anything else (another AUID, a node selector, a collection, a bad escape) names none.
static void Clause_6_3_13_3_2_2_ConfigurationDocuments() {
  const auto ue = config_document_reference("org.3gpp.mcptt.ue-config/users/sip%3Aalice%40example.org/"
                                            "urn%3Auuid%3A6e8bc430-9c3a-11d9-9669-0800200c9a66");
  assert(ue && ue->auid == "org.3gpp.mcptt.ue-config" && ue->xui == "sip:alice@example.org" &&
         ue->document == "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66");
  const auto profile = config_document_reference(
      "xcap-root/org.3gpp.mcptt.user-profile/users/sip:alice@example.org/mcptt-user-profile-1.xml");
  assert(profile && profile->auid == "org.3gpp.mcptt.user-profile" && profile->document == "mcptt-user-profile-1.xml");
  const auto service = config_document_reference("org.3gpp.mcptt.service-config/global/service-config.xml");
  assert(service && service->xui.empty() && service->document == "service-config.xml");
  assert(!config_document_reference("org.openmobilealliance.groups/global/byGroupID/sip:g@example.org"));
  assert(!config_document_reference("org.3gpp.mcptt.user-profile/users/sip:a@example.org/p.xml/~~/x"));
  assert(!config_document_reference("org.3gpp.mcptt.ue-config/users/sip:a@example.org/"));
  assert(!config_document_reference("org.3gpp.mcptt.ue-config/users/sip%zz/doc"));
  assert(!config_document_reference("xorg.3gpp.mcptt.service-config/global/service-config.xml"));
  assert(!config_document_reference("org.3gpp.mcptt.service-config/other/service-config.xml"));
}

//------------------------------------------------------------------------------
// TS 24.380 clause 14.3.5: the initial INVITE that initiates a call with floor control is accepted as an implicit
// floor request; a join of an existing chat group call, a rejoin by session identity (clause 6.2.1 item 2), a call
// without floor control and an offer without "mc_implicit_request" are not.
static void Clause_14_3_5_ImplicitFloorAccepted() {
  assert(implicit_floor_accepted(true, true, true));
  assert(!implicit_floor_accepted(false, true, true));
  assert(!implicit_floor_accepted(true, false, true));
  assert(!implicit_floor_accepted(true, true, false));
}

//------------------------------------------------------------------------------
// TS 24.380 clause 14.3.6: "mc_ssrc" returns the offer's "a=ssrc" unless it collides, then a new value; nothing
// without an "a=ssrc".
static void Clause_14_3_6_McSsrc() {
  std::uint32_t next = 40;
  const auto fresh = [&] { return next++; };
  assert(implicit_audio_ssrc(0, {}, fresh) == 0);
  assert(implicit_audio_ssrc(17, {}, fresh) == 17);
  assert(implicit_audio_ssrc(17, {16, 18}, fresh) == 17);
  assert(implicit_audio_ssrc(17, {17, 40}, fresh) == 41); // collision: a new value, itself not in use
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5.2.2 items 1 and 3: with nobody sending media the implicit request is processed as a Floor
// Request; with another talker it is queued when queueing is negotiated (3b), or answered with Floor Taken (3c).
static void Clause_6_3_5_2_2_ImplicitFloorOutcome() {
  assert(implicit_floor_outcome(false, false) == ImplicitFloorOutcome::request);
  assert(implicit_floor_outcome(false, true) == ImplicitFloorOutcome::request);
  assert(implicit_floor_outcome(true, true) == ImplicitFloorOutcome::queue);
  assert(implicit_floor_outcome(true, false) == ImplicitFloorOutcome::taken);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.2.1.3 step 9, 10.1.1.3.1.1 steps 7 and 9, 11.1.1.3.1.1 step 21, 17.3.2.1.1 step 17 and
// TS 24.484 clause 8.3.2.7: the location towards the controlling function.
static void Clause_6_3_2_1_3_TalkingLocation() {
  using enum TalkingLocation;
  constexpr std::string_view ambient = "ambient-listening";
  assert(talking_location_gated("private", ambient) && talking_location_gated("adhoc", ambient) &&
         talking_location_gated(ambient, ambient) && !talking_location_gated("prearranged", ambient) &&
         !talking_location_gated("chat", ambient));
  assert(talking_location_own("prearranged", ambient) && talking_location_own("private", ambient) &&
         !talking_location_own("adhoc", ambient));
  // A private call: the client's location only with "true", implicit or not.
  assert(talking_location(true, true, true, true, true, false, false) == pass);
  assert(talking_location(true, true, false, true, true, false, false) == pass);
  assert(talking_location(true, true, true, false, true, false, false) == withhold);
  // ... the emergency alert's location and clause 13.3.4.2 reports pass as before (not said to be covered).
  assert(talking_location(true, true, true, false, true, true, false) == pass);
  // ... none from the client with an implicit floor request and "true": the function's own, if it has one.
  assert(talking_location(true, true, true, true, false, false, true) == add_own);
  assert(talking_location(true, true, true, true, false, false, false) == none);
  assert(talking_location(true, true, false, true, false, false, true) == none);
  assert(talking_location(true, true, true, false, false, false, true) == none);
  // An on-demand group call: copied with no condition (step 7, the conflict kept), own location as above.
  assert(talking_location(false, true, true, false, true, false, false) == pass);
  assert(talking_location(false, true, true, true, false, false, true) == add_own);
  // An ad hoc call: no own-location branch.
  assert(talking_location(true, false, true, true, false, false, true) == none);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.2 step 9: a group call whose remaining dialogs this server has all ended with its BYE is
// being released and not ongoing: a new request for the group creates a new session (step 14) instead of joining
// it. A call with one dialog not ended by the server is ongoing; a call without dialogs is gone. The members still
// in the released call are waited for, the caller is not.
static void Clause_10_1_1_4_2_GroupCallOngoing() {
  const std::set<std::string> none;
  assert(!group_session_releasing({"d1", "d2"}, none));
  assert(!group_session_releasing({"d1", "d2"}, {"d1"}));
  assert(group_session_releasing({"d1", "d2"}, {"d1", "d2", "other"}));
  assert(group_session_releasing({"d2"}, {"d2"}));
  assert(!group_session_releasing({}, {"d1"}));
  assert(members_to_await({"alice", "bob", "carol"}, "alice") == (std::set<std::string>{"bob", "carol"}));
  assert(members_to_await({"bob"}, "alice") == std::set<std::string>{"bob"});
  assert(members_to_await({}, "alice").empty());
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.2.1.4 and 10.1.1.2.1.5 ("covers both on-demand session and pre-established sessions"), with
// clauses 10.1.1.3.1.3 and 11.1.1.3.1.3: a re-INVITE with MC service information in a pre-established session's
// dialog during a call over it (the cancel of the in-progress emergency or imminent peril state, an upgrade) is the
// call's, for the controlling function; one without, or outside a call, modifies the session (clause 8.3.2.1).
static void Clause_10_1_1_3_1_3_PreSessionReinvite() {
  assert(pre_session_reinvite_kind(true, true) == PreSessionReinvite::call_request);
  assert(pre_session_reinvite_kind(true, false) == PreSessionReinvite::session_modification);
  assert(pre_session_reinvite_kind(false, true) == PreSessionReinvite::session_modification);
  assert(pre_session_reinvite_kind(false, false) == PreSessionReinvite::session_modification);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.3.1.6 and 10.1.1.3.6 with clause 6.3.2.2.5.3: a participant whose call came over its
// pre-established session is told of the call's priority state in the session's dialog; any other in its leg's.
static void Clause_6_3_3_1_6_PriorityReinviteDialog() {
  const std::string leg = "pre-call-1", session = "session-dialog", none;
  assert(priority_reinvite_dialog(leg, session) == session);
  assert(priority_reinvite_dialog(leg, none) == leg);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.4: a re-INVITE is an implicit floor request when it upgrades the call to an emergency or imminent
// peril call with "mc_implicit_request" in a call with floor control; a cancellation ("false") or an offer without
// the attribute is not.
static void Clause_6_4_UpgradeImplicitFloorAccepted() {
  assert(upgrade_implicit_floor_accepted(true, true, true));
  assert(!upgrade_implicit_floor_accepted(false, true, true));
  assert(!upgrade_implicit_floor_accepted(true, false, true));
  assert(!upgrade_implicit_floor_accepted(true, true, false));
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.4.3.6: in 'G: Floor Idle' the implicit floor request of an upgrade is refused (cause #3) when
// the requester is alone in the call, granted otherwise; in 'G: Floor Taken' (clause 6.3.4.4.12) it is the request
// that pre-empts the talker, also with a single participant (the requester itself holding the floor).
static void Clause_6_3_4_3_6_UpgradeFloorOutcome() {
  assert(upgrade_floor_outcome(1, false) == UpgradeFloorOutcome::deny_only_participant);
  assert(upgrade_floor_outcome(0, false) == UpgradeFloorOutcome::deny_only_participant);
  assert(upgrade_floor_outcome(2, false) == UpgradeFloorOutcome::request);
  assert(upgrade_floor_outcome(4, true) == UpgradeFloorOutcome::request);
  assert(upgrade_floor_outcome(1, true) == UpgradeFloorOutcome::request);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.2.1.5.2 with TS 24.380 clauses 14.3.3 to 14.3.6: the answer to a call's re-INVITE in the
// session's dialog is the session's media with the controlling function's floor priority and its acceptance of an
// upgrade's implicit floor request ("mc_implicit_request", "mc_ssrc"); the session's own implicit floor request is not
// echoed for a request the controlling function did not accept.
static void Clause_6_3_2_1_5_2_PreSessionCallAnswer() {
  struct Media {
    bool implicit_request = false, granted = false;
    std::uint32_t granted_audio_ssrc = 0;
    std::optional<std::uint8_t> floor_priority;
    std::uint16_t audio_port = 0;
  };

  Media session;
  session.audio_port = 4000;
  session.floor_priority = 5;
  session.implicit_request = true; // the session was set up with an implicit floor request

  Media accepted;
  accepted.audio_port = 5000;
  accepted.floor_priority = 7;
  accepted.implicit_request = true;
  accepted.granted_audio_ssrc = 1234;
  auto answer = pre_session_call_answer(session, std::optional<Media>(accepted));
  assert(answer.audio_port == 4000); // the session's media, not the call leg's
  assert(answer.floor_priority == 7);
  assert(answer.implicit_request && answer.granted_audio_ssrc == 1234 && !answer.granted);

  Media cancel;
  cancel.floor_priority = 3;
  answer = pre_session_call_answer(session, std::optional<Media>(cancel));
  assert(!answer.implicit_request && answer.granted_audio_ssrc == 0 && answer.floor_priority == 3);

  answer = pre_session_call_answer(session, std::optional<Media>());
  assert(!answer.implicit_request && answer.floor_priority == 5 && answer.audio_port == 4000);
}

//------------------------------------------------------------------------------
int main() {
  Section_20_19_Expires();
  Section_2_1_PercentDecoding();
  Clause_9_2_2_3_11_ImplicitAffiliationCancellation();
  Clause_6_3_13_3_2_2_ConfigurationDocuments();
  Clause_14_3_5_ImplicitFloorAccepted();
  Clause_14_3_6_McSsrc();
  Clause_6_3_5_2_2_ImplicitFloorOutcome();
  Clause_6_3_2_1_3_TalkingLocation();
  Clause_10_1_1_4_2_GroupCallOngoing();
  Clause_10_1_1_3_1_3_PreSessionReinvite();
  Clause_6_3_3_1_6_PriorityReinviteDialog();
  Clause_6_4_UpgradeImplicitFloorAccepted();
  Clause_6_3_4_3_6_UpgradeFloorOutcome();
  Clause_6_3_2_1_5_2_PreSessionCallAnswer();
  std::cout << "server request values: all checks passed\n";
  return 0;
}
