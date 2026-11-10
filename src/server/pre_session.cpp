//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Pre-established sessions at the participating MCPTT function: establishment (TS 24.379 clause 8.2.2) behind the
// resource sharing condition of clause 8.1A, modification by the client (clause 8.3.2.1) or by this function
// (clause 8.3.2.2, operator command), release by either side (clauses 8.4.2.1 and 8.4.2.2), with ICE (clause 4.9,
// RFC 8445: this function is the controlled agent) and the call setup control state machine of TS 24.380 clause 9.3.2
// started and stopped with the session. Calls over the session (REFER, Connect) build on this (TS 24.379 clauses
// 10.1.1.3.1.2 and 6.3.2.2.5.3; conformance/pre-est-feat.md M2 and M3).
//
// Not implemented: the resource sharing of TS 29.214 over Rx (TS 24.379 clause 8.1A option 2): with
// mcptt.resource_sharing "rx" the session is allowed and its sharing keys are left to the PCC deployment.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 24.229 V19.7.0 (Rel-19), RFC 8445,
// RFC 8839, RFC 3311.

#include "server.hpp"

#include <arpa/inet.h>

namespace mcx {
namespace {

// TS 24.229 table 7.2.13.1: the Resource-Share values and the directionality of a rule.
constexpr std::string_view kResourceShareSupported = "supported";
constexpr std::string_view kBothDirections = "UL-DL";

//------------------------------------------------------------------------------
// Helper: the value of a header field of a SIP message fragment (the client's REGISTER in the message/sip body of a
// third-party REGISTER, TS 24.229 clause 5.4.1.7), or empty.
std::string fragment_header(std::string_view fragment, std::string_view name) {
  const auto head = fragment.substr(0, fragment.find("\r\n\r\n"));
  std::size_t at = 0;
  while (at < head.size()) {
    const auto end = std::min(head.find("\r\n", at), head.size());
    const auto line = head.substr(at, end - at);
    const auto colon = line.find(':');
    if (colon != std::string_view::npos) {
      auto field = line.substr(0, colon);
      while (!field.empty() && field.back() == ' ') field.remove_suffix(1);
      if (field.size() == name.size() &&
          std::equal(field.begin(), field.end(), name.begin(), [](char one, char two) {
            return std::tolower(static_cast<unsigned char>(one)) == std::tolower(static_cast<unsigned char>(two));
          })) {
        auto value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
        return std::string(value);
      }
    }
    at = end + 2;
  }
  return {};
}

//------------------------------------------------------------------------------
// TS 24.229 table 7.9.7-1: the value of a "+g.3gpp.registration-token" feature parameter in a Contact or Feature-Caps
// header field value (quotes and angle brackets removed), or empty.
std::string registration_token(std::string_view value) {
  constexpr std::string_view tag = "+g.3gpp.registration-token=";
  const auto at = value.find(tag);
  if (at == std::string_view::npos) return {};
  auto token = value.substr(at + tag.size());
  token = token.substr(0, token.find_first_of(";,"));
  std::string out;
  for (const char character : token)
    if (character != '"' && character != '<' && character != '>' && character != ' ') out += character;
  return out;
}

//------------------------------------------------------------------------------
// Helper: the numeric host and port of a received datagram's source.
std::pair<std::string, std::uint16_t> source_of(const Datagram &datagram) {
  std::array<char, INET_ADDRSTRLEN> host{};
  inet_ntop(AF_INET, &datagram.source.sin_addr, host.data(), host.size());
  return {host.data(), ntohs(datagram.source.sin_port)};
}

} // namespace

//------------------------------------------------------------------------------
// TS 24.379 clause 8.1A: how resource sharing is supported (mcptt.resource_sharing): "none" refuses pre-established
// sessions; "sip-core" relies on the SIP core's Resource-Share (TS 24.229 clause 7.2.13); "rx" on PCC over Rx.
std::string McServer::resource_sharing_mode() const {
  const auto mode = cfg_.at(svc_.name).value("resource_sharing", std::string("none"));
  if (mode != "none" && mode != "sip-core" && mode != "rx")
    throw std::runtime_error("mcptt.resource_sharing is none, sip-core or rx: TS 24.379 clause 8.1A");
  return mode;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 8.1A: the third-party REGISTER's Resource-Share "supported" (in the client's REGISTER, its
// message/sip body) and the registration token of its Contact, kept for the identity.
void McServer::record_core_registration(const SipMessage &message, const std::string &identity) {
  CoreRegistration registration;
  registration.registration_token = registration_token(get_header(message.headers, "Contact"));
  for (const auto &part : parts_of(message))
    if (part.content_type == "message/sip")
      registration.resource_sharing =
          fragment_header(part.body, "Resource-Share").starts_with(kResourceShareSupported);
  core_registrations_[identity] = registration;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 8.2.2 steps 3 to 5: refuses the session with 403 and warning 100 "function not allowed due to
// pre-established session not supported" when resource sharing is not supported, or the SIP core's registration
// token of the UE does not match the one of the INVITE's Feature-Caps. Returns whether it refused.
bool McServer::pre_session_refused(const SipMessage &message, const User &user, SipResponse &response) {
  const auto mode = resource_sharing_mode();
  std::string reason;
  if (mode == "none") {
    reason = "resource sharing not supported";
  } else if (mode == "sip-core") {
    const auto found = core_registrations_.find(user.sip);
    const auto token = registration_token(get_header(message.headers, "Feature-Caps"));
    if (found == core_registrations_.end() || !found->second.resource_sharing)
      reason = "the SIP core does not support resource sharing";
    else if (token.empty() || token != found->second.registration_token)
      reason = "no binding of the MCPTT ID to the UE's registration token";
  }
  if (reason.empty()) return false;
  response.status_code = 403;
  response.headers = {
      {"Warning", warning_value(warn(Warning::function_not_allowed, "pre-established session not supported"))}};
  event("pre_established_session_refused", {{"user_id", user.id}, {"reason", reason}});
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 8.2.2 steps 7 and 8, TS 24.380 clause 9.3.2.2.2 step 1: the session's media sockets (speech RTP and
// RTCP, floor control) on the next free ports, the URI identifying it, and its state machine.
std::shared_ptr<McServer::PreSession> McServer::make_pre_session(const SipMessage &message, const User &user) {
  auto session = std::make_shared<PreSession>();
  session->dialog = message.dialog_id;
  session->user = user.id;
  session->uri = session_service_ + ";mcptt-pre-session=" + random_id();
  session->local = local_media(cfg_, media_offset());
  while (session->local.floor_ssrc == message.remote_media->floor_ssrc) session->local.floor_ssrc = random_ssrc();
  const auto address = cfg_.at("media").at("bind").get<std::string>();
  session->audio = std::make_unique<UdpSocket>(address, session->local.audio_port);
  session->rtcp = std::make_unique<UdpSocket>(address, session->local.rtcp_port);
  session->floor = std::make_unique<UdpSocket>(address, session->local.floor_port);
  const auto &timers = cfg_.at(svc_.name).value("pre_established_timers", Json::object());
  session->control = std::make_unique<PreEstablishedServer>(
      session->local.floor_ssrc,
      PreEstablishedTimerOptions{timers.value("t55_ms", 2000ULL), timers.value("t56_ms", 2000ULL),
                                 timers.value("c55", 3U), timers.value("c56", 3U)});
  return session;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 8.2.2 steps 6, 9 e and 10 to 12, clause 8.3.2.1 step 2 a, clause 6.3.2.1.2.2: the SDP answer to
// the client's offer: this function's address and ports, its floor control SSRC, the client's codec parameters, the
// offered floor priority and implicit floor request kept (TS 24.380 clauses 14.3.3 and 14.3.5), and the ICE attributes
// (RFC 8839); a new ICE agent when the offer's credentials are new (an ICE restart, RFC 8445 section 9).
void McServer::pre_session_offer(const SipMessage &message, const User &user, SipResponse &response) {
  const auto &session = pre_sessions_.at(message.dialog_id);
  const auto &offer = *message.remote_media;
  const auto previous_ufrag =
      session->remote && session->remote->ice ? session->remote->ice->ufrag : std::string{};
  session->remote = offer;
  session->local.payload_type = offer.payload_type;
  session->local.octet_aligned = offer.octet_aligned;
  session->local.protected_media = offer.protected_media;
  session->local.control = offer.control;
  session->local.floor_priority = offer.floor_priority;
  session->local.implicit_request = offer.implicit_request;
  session->implicit_floor = offer.implicit_request;
  if (offer.ice) {
    // RFC 8445 section 9: new credentials in an offer restart ICE; the same ones keep the running agent.
    if (!session->ice || offer.ice->ufrag != previous_ufrag) {
      IceLocalSockets sockets{session->local.address, session->local.audio_port, session->local.rtcp_port,
                              offer.control == MediaControl::none ? std::uint16_t{0} : session->local.floor_port};
      std::weak_ptr<PreSession> weak = session;
      session->ice = std::make_unique<IceAgent>(
          false, sockets,
          [weak](IceStream stream, unsigned component, std::span<const std::uint8_t> packet, const std::string &host,
                 std::uint16_t port) {
            const auto alive = weak.lock();
            if (!alive) return;
            auto &socket = stream == IceStream::Control ? *alive->floor : component == 2 ? *alive->rtcp : *alive->audio;
            socket.send(packet, host, port);
          });
      session->ice->start(*offer.ice);
    }
    session->local.ice = session->ice->local_description();
  } else {
    // TS 24.379 clause 8.2.1 step 9 asks the client for ICE candidates; without them the session runs on the
    // default addresses.
    session->ice.reset();
    session->local.ice.reset();
  }

  response.status_code = 200;
  response.local_media = session->local;
  response.contact_uri = session->uri;
  response.headers.push_back({"P-Asserted-Identity", "<" + pre_established_uri() + ">"});
  response.headers.push_back({"Supported", "norefersub"});
  if (resource_sharing_mode() == "sip-core") {
    // TS 24.379 clause 8.2.2 step 9 d with TS 24.229 table 7.2.13.1: one rule per m-line, in their order.
    const auto key = random_id().substr(0, 8);
    std::string rules = "\"" + key + "a::" + std::string(kBothDirections);
    if (offer.control != MediaControl::none) rules += "," + key + "c::" + std::string(kBothDirections);
    response.headers.push_back({"Resource-Share", "media-sharing;origin=session-initiator;rules=" + rules +
                                                      "\";timestamp=" + std::to_string(std::time(nullptr))});
  }
  event("pre_established_session_answered",
        {{"user_id", user.id}, {"session_uri", session->uri}, {"ice", static_cast<bool>(session->ice)}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 8.2.2: a "SIP INVITE request for establishing a pre-established session" (clause 6.3.1.1: the
// Request-URI is the PSI identifying pre-established session set-up). Step 1 is met by the Request-URI; step 2 by the
// served user's authorisation; steps 3 to 5 by pre_session_refused; step 6: an offer without the MCPTT speech codec
// (parse_sdp refuses it) gets 488; step 7: no free ports gets 500 (CapacityReached); steps 8 to 12: the session and
// the answer.
void McServer::pre_session_invite(const SipMessage &message, const User &user, SipResponse &response) {
  if (pre_session_refused(message, user, response)) return;
  if (!message.remote_media) {
    response.status_code = 488;
    event("pre_established_session_refused", {{"user_id", user.id}, {"reason", "no acceptable SDP offer"}});
    return;
  }
  auto session = make_pre_session(message, user);
  pre_sessions_[session->dialog] = session;
  try {
    pre_session_offer(message, user, response);
  } catch (...) {
    pre_sessions_.erase(session->dialog);
    throw;
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 9.3.2.2.2 and 9.3.2.3.4: the session's dialog is confirmed (the state machine starts in
// 'G: Pre-established session not in use') or ended (TS 24.379 clauses 8.4.2.1 c and 8.4.2.2: its media plane
// resources are released, 'Start-stop').
void McServer::pre_session_state(const std::shared_ptr<PreSession> &session, SipCallState state) {
  if (state == SipCallState::confirmed && !session->confirmed) {
    session->confirmed = true;
    session->control->started();
    event("pre_established_session_started", {{"user_id", session->user}, {"session_uri", session->uri}});
  } else if (state == SipCallState::disconnected) {
    session->control->stopped();
    event("pre_established_session_released", {{"user_id", session->user}, {"session_uri", session->uri}});
    pre_sessions_.erase(session->dialog);
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.9 (RFC 8445 section 7.3): the sessions' sockets: STUN to their ICE agents; outside a call no
// speech, RTCP or media plane control is relayed (TS 24.380 clause 9.3.2.3.1), so the rest is discarded.
void McServer::pre_session_poll() {
  for (auto &[dialog, session] : pre_sessions_) {
    const std::array<std::pair<UdpSocket *, std::pair<IceStream, unsigned>>, 3> sockets{
        {{session->audio.get(), {IceStream::Audio, 1}},
         {session->rtcp.get(), {IceStream::Audio, 2}},
         {session->floor.get(), {IceStream::Control, 1}}}};
    for (const auto &[socket, component] : sockets) {
      for (int index = 0; index < 32; ++index) {
        auto datagram = socket->receive();
        if (!datagram) break;
        if (session->ice && is_stun_packet(datagram->bytes)) {
          const auto [host, port] = source_of(*datagram);
          session->ice->receive(component.first, component.second, datagram->bytes, host, port);
        } else {
          status_["pre_session_discarded_packets"] = status_.value("pre_session_discarded_packets", 0ULL) + 1;
        }
      }
    }
    if (!session->ice) continue;
    const auto before = session->ice->state();
    session->ice->tick();
    if (session->ice->state() != before && session->ice->state() != IceState::Checking)
      event("pre_established_session_ice",
            {{"user_id", session->user},
             {"state", session->ice->state() == IceState::Completed ? "completed" : "failed"}});
  }
}

//------------------------------------------------------------------------------
// Helper: the sessions an operator command names: a served MCPTT ID's, or every one ("all").
std::vector<std::shared_ptr<McServer::PreSession>> McServer::pre_sessions_of(const std::string &which) const {
  std::vector<std::shared_ptr<PreSession>> out;
  for (const auto &[dialog, session] : pre_sessions_)
    if (session->confirmed && (which == "all" || session->user == which)) out.push_back(session);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 8.3.2.2: this function modifies the session outside a call with an UPDATE or a re-INVITE whose
// offer carries the session's media and, when given, a new floor priority (TS 24.380 clause 14.2.3; TS 37.579-2
// test 5.4 steps 7 and 9). The answer's media reach on_media.
void McServer::pre_session_modify(const std::shared_ptr<PreSession> &session, std::optional<std::uint8_t> priority,
                                  bool update) {
  auto offer = session->local;
  if (priority) offer.floor_priority = priority;
  const auto dialog = session->dialog;
  auto done = [this, dialog, user = session->user, update, priority](const SipResponse &answer) {
    event("pre_established_session_modified",
          {{"user_id", user}, {"method", update ? "UPDATE" : "INVITE"}, {"status", answer.status_code}});
    if (answer.status_code / 100 == 2)
      if (const auto found = pre_sessions_.find(dialog); found != pre_sessions_.end())
        if (priority) found->second->local.floor_priority = priority;
  };
  if (update)
    sip_.update(dialog, offer, done);
  else
    sip_.reinvite(dialog, offer, {}, done);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 8.4.2.2: this function releases the session (step 1 has no call to release yet: calls over
// sessions come with M2 of conformance/pre-est-feat.md); steps 2 to 4: BYE in its dialog; step 5 on its end.
void McServer::pre_session_release(const std::shared_ptr<PreSession> &session) { sip_.bye(session->dialog); }

//------------------------------------------------------------------------------
// The operator's commands (as "mbms-announce"): "pre-session-modify <MCPTT ID|all> [priority=<0..255>] [update]"
// (TS 24.379 clause 8.3.2.2) and "pre-session-release <MCPTT ID|all>" (clause 8.4.2.2).
void McServer::pre_session_command(const std::string &command) {
  std::istringstream words(command);
  std::string verb, which, word;
  words >> verb >> which;
  std::optional<std::uint8_t> priority;
  bool update = false;
  while (words >> word) {
    if (word == "update")
      update = true;
    else if (word.starts_with("priority="))
      priority = static_cast<std::uint8_t>(std::stoul(word.substr(9)));
    else
      throw std::runtime_error("unknown pre-session option: " + word);
  }
  const auto sessions = pre_sessions_of(which);
  if (sessions.empty()) event("pre_session_command_unknown", {{"command", command}});
  for (const auto &session : sessions) {
    if (verb == "pre-session-modify")
      pre_session_modify(session, priority, update);
    else if (verb == "pre-session-release")
      pre_session_release(session);
    else
      throw std::runtime_error("unknown pre-session command: " + verb);
  }
}

} // namespace mcx
