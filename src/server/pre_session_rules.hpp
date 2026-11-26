//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Which procedure a re-INVITE in the dialog of a pre-established session belongs to, and the dialog a priority state
// change reaches a participant of a call over such a session in. Used by the MCPTT server (McServer, pre_session.cpp and
// priority.cpp); free of server state, so that the unit tests reach them.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19).
#pragma once

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
// TS 24.379 clauses 6.3.3.1.6 and 10.1.1.3.6 (the participating function sends the re-INVITE towards the client), with
// clause 6.3.2.2.5.3: a participant whose call came over its pre-established session (by Connect, TS 24.380 clause
// 9.3.2.3.3) has no SIP dialog of the call; the only dialog with its client is the session's, which a priority state
// change of the call goes in (as clause 6.3.2.1.8.5 does for the originator). Otherwise the leg's own dialog.
inline const std::string &priority_reinvite_dialog(const std::string &leg_dialog,
                                                   const std::string &pre_session_dialog) {
  return pre_session_dialog.empty() ? leg_dialog : pre_session_dialog;
}

} // namespace mcx
