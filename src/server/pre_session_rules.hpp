//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Which procedure a re-INVITE in the dialog of a pre-established session belongs to, the SDP answer to a call's
// re-INVITE sent in it, and the dialog a priority state change reaches a participant of a call over such a session
// in. Used by the MCPTT server (McServer, pre_session.cpp and
// priority.cpp); free of server state, so that the unit tests reach them.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19).
#pragma once

#include <optional>
#include <string>

namespace mcx {

//------------------------------------------------------------------------------
// What a re-INVITE in a pre-established session's dialog asks for.
enum class PreSessionReinvite {
  // TS 24.379 clause 8.3.2.1: a modification of the session (its media, e.g. the implicit floor request).
  session_modification,
  // TS 24.379 clauses 10.1.1.3.1.3, 10.1.2.3.1.2 and 11.1.1.3.1.3 ("This clause covers both on-demand session and
  // pre-established sessions"): a request of the call over the session, with the MC service information of the
  // client's procedure: the cancel of the in-progress emergency (clause 10.1.1.2.1.4 NOTE 2: "The SIP re-INVITE request
  // can be sent within an on-demand session or a pre-established session") or imminent peril state (clause
  // 10.1.1.2.1.5), or an upgrade (clauses 10.1.1.2.1.3, 6.3.2.1.8.5). It goes to the controlling function as the
  // re-INVITE of the call (clause 6.3.2.1.9), not to the session.
  call_request,
};

//------------------------------------------------------------------------------
// A re-INVITE with an application/vnd.3gpp.mcptt-info+xml body (service_info) while a call is over the session
// (call_over_session) is the call's; anything else modifies the session. Outside a call the client cancels the
// group's state by SIP MESSAGE (clause 10.1.1.2.1.4: "otherwise generate a SIP MESSAGE request ... clause 12.1.1.5"),
// so a re-INVITE then is the session's.
inline PreSessionReinvite pre_session_reinvite_kind(bool call_over_session, bool service_info) {
  return call_over_session && service_info ? PreSessionReinvite::call_request
                                           : PreSessionReinvite::session_modification;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.2.1.5.2 (an SDP answer based on the session's) with clause 6.3.2.1.1.2 NOTE 2 (the media as
// negotiated for the session): the SDP answer to a call's re-INVITE in the session's dialog (session: the session's
// media), with what the controlling function's answer to it (call) says of this request: the floor priority it
// negotiated (TS 24.380 clause 14.3.3) and, for the implicit floor request of an upgrade to an emergency or imminent
// peril call (TS 24.379 clause 6.4, clauses 10.1.1.2.1.3 step 7 and 11.1.1.2.1.5 "cover both on-demand session and
// pre-established sessions"), its acceptance: "mc_implicit_request" (TS 24.380 clause 14.3.5: "in responses to the
// SIP request"), "mc_ssrc" (clause 14.3.6) and "mc_granted" (clause 14.3.4). The session's own implicit floor
// request (clause 8.2.2: for the calls the session is used for) is not this request's: without the controlling
// function's acceptance the answer has none (a cancellation, or an upgrade without the attribute). Media: the
// server's MediaDescription (a template, so that this header needs none of its dependencies).
template <typename Media> Media pre_session_call_answer(Media session, const std::optional<Media> &call) {
  session.implicit_request = call && call->implicit_request;
  session.granted = call && call->granted;
  session.granted_audio_ssrc = call ? call->granted_audio_ssrc : 0;
  if (call) session.floor_priority = call->floor_priority;
  return session;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.3.1.6 and 10.1.1.3.6 (the participating function sends the re-INVITE towards the client), with
// clause 6.3.2.2.5.3: a participant whose call came over its pre-established session (by Connect, TS 24.380 clause
// 9.3.2.3.3) has no SIP dialog of the call; the only dialog with its client is the session's, which a priority state
// change of the call goes in (as clause 6.3.2.1.8.5 does for the originator). Otherwise the leg's own dialog.
inline const std::string &priority_reinvite_dialog(const std::string &leg_dialog,
                                                   const std::string &pre_session_dialog) {
  return pre_session_dialog.empty() ? leg_dialog : pre_session_dialog;
}

} // namespace mcx
