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

#include "mcx/refer.hpp"

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
  // TS 24.379 clause 6.3.2.1.2.2 NOTE and TS 24.380 clause 4.3: this function's media plane control messages to the
  // client carry the floor SSRC the client offered (the Connect and Disconnect as its floor control messages do).
  session->control = std::make_unique<PreEstablishedServer>(
      message.remote_media->floor_ssrc,
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
          [this, weak](IceStream stream, unsigned component, std::span<const std::uint8_t> packet,
                       const std::string &host, std::uint16_t port) {
            const auto alive = weak.lock();
            if (!alive) return;
            // During a call over the session its leg holds the session's speech and control sockets.
            UdpSocket *audio = alive->audio.get(), *floor = alive->floor.get();
            if (!alive->call_leg.empty())
              if (const auto leg = legs_.find(alive->call_leg); leg != legs_.end()) {
                audio = leg->second->audio.get();
                floor = leg->second->floor.get();
              }
            auto *socket = stream == IceStream::Control ? floor : component == 2 ? alive->rtcp.get() : audio;
            if (socket) socket->send(packet, host, port);
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
    // TS 24.380 clause 4.1.2.3: releasing the session releases the call over it; its leg leaves the call.
    if (const auto id = session->call_leg; !id.empty()) {
      pre_session_unbind(session);
      schedule([this, id] { this->state(id, SipCallState::disconnected, 200); });
    }
    pre_sessions_.erase(session->dialog);
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.9 (RFC 8445 section 7.3): the sessions' sockets: STUN to their ICE agents; outside a call no
// speech, RTCP or media plane control is relayed (TS 24.380 clause 9.3.2.3.1), so the rest is discarded.
void McServer::pre_session_poll() {
  std::vector<std::shared_ptr<PreSession>> sessions;
  for (const auto &[dialog, session] : pre_sessions_) sessions.push_back(session);
  for (const auto &session : sessions) {
    const std::array<std::pair<UdpSocket *, std::pair<IceStream, unsigned>>, 3> sockets{
        {{session->audio.get(), {IceStream::Audio, 1}},
         {session->rtcp.get(), {IceStream::Audio, 2}},
         {session->floor.get(), {IceStream::Control, 1}}}};
    for (const auto &[socket, component] : sockets) {
      if (socket == nullptr) continue; // lent to the leg of the call over the session (pre_session_bind)
      for (int index = 0; index < 32; ++index) {
        auto datagram = socket->receive();
        if (!datagram) break;
        if (session->ice && is_stun_packet(datagram->bytes)) {
          const auto [host, port] = source_of(*datagram);
          session->ice->receive(component.first, component.second, datagram->bytes, host, port);
        } else if (component.first == IceStream::Control) {
          // TS 24.380 clause 9.3.2.5.2: the Acknowledge of a Disconnect, after the call left the session.
          try {
            pre_session_control(session, datagram->bytes);
          } catch (const std::exception &error) {
            event("pre_session_control_rejected", {{"reason", error.what()}});
          }
        } else {
          status_["pre_session_discarded_packets"] = status_.value("pre_session_discarded_packets", 0ULL) + 1;
        }
      }
    }
    pre_session_events(session);
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
  std::string refuse;
  while (words >> word) {
    if (word == "update")
      update = true;
    else if (verb == "pre-session-refuse" && (word == "emergency" || word == "imminent"))
      refuse = word;
    else if (word.starts_with("priority="))
      priority = static_cast<std::uint8_t>(std::stoul(word.substr(9)));
    else
      throw std::runtime_error("unknown pre-session option: " + word);
  }
  const auto sessions = pre_sessions_of(which);
  if (sessions.empty()) event("pre_session_command_unknown", {{"command", command}});
  for (const auto &session : sessions) {
    if (verb == "pre-session-refuse")
      session->refuse_next = refuse;
    else if (verb == "pre-session-modify")
      pre_session_modify(session, priority, update);
    else if (verb == "pre-session-release")
      pre_session_release(session);
    else
      throw std::runtime_error("unknown pre-session command: " + verb);
  }
}

//------------------------------------------------------------------------------
// Helper: the pre-established session a Request-URI identifies (TS 24.379 clause 8.2.2 step 8), or none.
std::shared_ptr<McServer::PreSession> McServer::pre_session_by_uri(const std::string &uri) const {
  for (const auto &[dialog, session] : pre_sessions_)
    if (session->uri == uri) return session;
  return nullptr;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 13.3.2 step 6: the session's media plane control messages are protected as its user's floor
// control is: under the user's CSK when the client's floor control is protected (the policy of the call over the
// session, or, outside a call, the group default of mcptt.protect_floor).
bool McServer::pre_session_floor_protected(const PreSession &session) {
  if (!session.call_leg.empty())
    if (const auto leg = legs_.find(session.call_leg); leg != legs_.end() && leg->second->session)
      return floor_protected(*leg->second);
  // Outside a call: protected whenever the user's floor key is there, as the client protects its media plane control
  // under the CSK (TS 24.380 clause 13.3.3); its Acknowledge is read clear or protected (pre_session_control).
  const auto *user = by_id(session.user);
  const auto *keys = user ? floor_keys(*user) : nullptr;
  return keys != nullptr && keys->floor_ready();
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.3 and 13.3.2 step 6: sends a pre-established session call control message on the session's
// media plane control channel (the session's floor socket, or the leg's while a call has it).
void McServer::pre_session_send(PreSession &session, const PreEstablishedMessage &message) {
  if (!session.remote) return;
  auto bytes = encode_pre_established(message);
  if (pre_session_floor_protected(session)) {
    const auto *user = by_id(session.user);
    auto *keys = user ? floor_keys(*user) : nullptr;
    if (!keys || !keys->floor_ready()) throw std::runtime_error("pre-established session control key unavailable");
    bytes = keys->protect_floor(bytes);
  }
  // While a call has the session, its leg holds the session's control socket (pre_session_bind).
  UdpSocket *socket = session.floor.get();
  if (!session.call_leg.empty())
    if (const auto leg = legs_.find(session.call_leg); leg != legs_.end()) socket = leg->second->floor.get();
  if (socket == nullptr) throw std::runtime_error("pre-established session without its control socket");
  try {
    socket->send(bytes, session.remote->floor_address, session.remote->floor_port);
  } catch (const std::exception &error) {
    // A send failure is the call's (the state machine's retransmissions and timers decide), not the server's.
    event("pre_session_control_send_failed", {{"user_id", session.user}, {"reason", error.what()}});
    return;
  }
  event("pre_session_control_sent",
        {{"user_id", session.user},
         {"type", message.type == PreEstablishedMessageType::Connect      ? "Connect"
                  : message.type == PreEstablishedMessageType::Disconnect ? "Disconnect"
                                                                          : "Acknowledge"}});
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2: a pre-established session call control message from the client (an Acknowledge; floor
// control goes to the floor control server): clear, or under the user's CSK.
void McServer::pre_session_control(const std::shared_ptr<PreSession> &session, std::span<const std::uint8_t> bytes) {
  std::vector<std::uint8_t> clear(bytes.begin(), bytes.end());
  if (!is_pre_established_message(clear)) {
    const auto *user = by_id(session->user);
    auto *keys = user ? floor_keys(*user) : nullptr;
    if (!keys) throw std::runtime_error("protected pre-established session control without a CSK");
    clear = keys->unprotect_floor(clear);
    if (!is_pre_established_message(clear)) return; // floor control outside a call: nothing to do
  }
  const auto message = decode_pre_established(clear);
  if (!message || message->type != PreEstablishedMessageType::Acknowledge) return; // TS 24.380 clause 8.3.3.9
  event("pre_session_acknowledge",
        {{"user_id", session->user},
         {"reason_code", static_cast<unsigned>(message->reason_code.value_or(PreEstablishedReasonCode::Accepted))}});
  if (auto disconnect = session->control->receive_acknowledge(*message, monotonic_ms()))
    pre_session_send(*session, *disconnect);
  pre_session_events(session);
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2: the retransmissions due and what the state machine learnt, for the call over the session:
// an accepted Connect confirms the leg (the floor state of its call follows, TS 24.380 clause 6.3; an implicit floor
// request is granted); a refused or unanswered one releases it (clauses 9.3.2.4.7 step 2 d and 9.3.2.4.9).
void McServer::pre_session_events(const std::shared_ptr<PreSession> &session) {
  for (const auto &message : session->control->tick(monotonic_ms())) pre_session_send(*session, message);
  for (const auto event_kind : session->control->take_events()) {
    const auto leg_id = session->call_leg;
    switch (event_kind) {
    case PreEstablishedServerEvent::ConnectAccepted:
      if (!leg_id.empty()) state(leg_id, SipCallState::confirmed, 200);
      break;
    case PreEstablishedServerEvent::ConnectRefused:
    case PreEstablishedServerEvent::ConnectExpired:
      if (!leg_id.empty()) {
        pre_session_unbind(session);
        state(leg_id, SipCallState::disconnected, 480);
      }
      break;
    default:
      break;
    }
  }
}

//------------------------------------------------------------------------------
// The leg of a call over the session takes the session's media: its sockets, ports, floor SSRC and the client's
// negotiated media (TS 24.379 clause 6.3.2.1.1.2: the SDP of the pre-established session).
void McServer::pre_session_bind(const std::shared_ptr<PreSession> &session, const std::shared_ptr<Leg> &leg) {
  leg->pre_session = session->dialog;
  // The leg's port numbers stay those of its own sockets, which the session keeps meanwhile, so that media_offset()
  // still counts them as taken; its floor SSRC becomes the session's (TS 24.380 clause 4.3).
  leg->local.floor_ssrc = session->local.floor_ssrc;
  // Swapped, not moved: the session keeps the leg's own sockets meanwhile, so that neither ever has none (the leg
  // can outlive the call on the session until its end is handled, and the run loop reads every leg's sockets).
  std::swap(leg->audio, session->audio);
  std::swap(leg->floor, session->floor);
  session->call_leg = leg->dialog;
}

//------------------------------------------------------------------------------
// The call left the session: the session's sockets come back (TS 24.380 clause 9.3.2.4.4 step 2: the resources the
// session needs are kept).
void McServer::pre_session_unbind(const std::shared_ptr<PreSession> &session) {
  if (session->call_leg.empty()) return;
  if (const auto leg = legs_.find(session->call_leg); leg != legs_.end()) {
    std::swap(leg->second->audio, session->audio);
    std::swap(leg->second->floor, session->floor);
    leg->second->pre_session.clear();
  } else {
    // The leg went without giving its sockets back: the session's speech and control ports are bound again.
    const auto address = cfg_.at("media").at("bind").get<std::string>();
    session->audio = std::make_unique<UdpSocket>(address, session->local.audio_port);
    session->floor = std::make_unique<UdpSocket>(address, session->local.floor_port);
    event("pre_session_sockets_rebound", {{"user_id", session->user}});
  }
  session->call_leg.clear();
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.6.2.1 (second item): the XML bodies of the REFER entry's hname "body", protected by the client
// under its CSK, opened with the user's key (TS 24.379 clause 6.6.2.4.2).
std::vector<BodyPart> McServer::pre_session_open_parts(const User &user, std::vector<BodyPart> parts) {
  for (auto &part : parts) {
    if (!xmlsec::is_xml_mime(part.content_type) || !xmlsec::is_protected(part.body)) continue;
    const auto key = user_xml_key(user.sip);
    if (!key) throw std::runtime_error("no XPK for the REFER entry's content");
    part.body = xmlsec::decrypt(part.body, *key);
  }
  return parts;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.3.1.2 (prearranged group call), clause 10.1.2.3.2 (chat), clause 11.1.1.3.1.2 (private
// call) and clauses 6.2.4.2 / 11.1.3.2.1.2 (REFER "BYE"): a "SIP REFER request for a pre-established session" to the
// session's URI. Steps 1 to 10: the request is read (a REFER that names no call or leave is 400; an entry whose
// group has no controlling function is 404 with warning 142); steps 13 and 14 (NOTE 11): 200 (OK) with Refer-Sub
// "false" (RFC 4488, no implicit subscription, step 6). The call itself follows (pre_session_call); a leave releases
// the call keeping the session (pre_session_leave, TS 24.380 clause 9.3.2.4.4).
void McServer::pre_session_refer(const SipMessage &message, const User &user, SipResponse &response) {
  const auto session = pre_session_by_uri(message.request_uri);
  if (!session || session->user != user.id || !session->confirmed) {
    response.status_code = 481; // RFC 3515 section 2.4.3: no such session for the REFER
    return;
  }
  PreEstablishedReferRequest refer;
  try {
    refer = parse_pre_established_refer(message.headers, message.parts);
  } catch (const std::exception &error) {
    response.status_code = 400;
    event("pre_session_refer_refused", {{"user_id", user.id}, {"reason", error.what()}});
    return;
  }
  response.status_code = 200;
  response.headers = {{"Refer-Sub", "false"}, {"Supported", "norefersub"}};
  if (refer.leave) {
    if (session->call_leg.empty()) {
      response.status_code = 481;
      response.headers.clear();
      return;
    }
    event("pre_session_leave_requested", {{"user_id", user.id}, {"session_identity", refer.session_identity}});
    schedule([this, dialog = session->dialog] {
      if (const auto found = pre_sessions_.find(dialog); found != pre_sessions_.end()) pre_session_leave(found->second);
    });
    return;
  }
  if (!session->call_leg.empty()) {
    response.status_code = 486; // the session already carries a call (TS 24.380 clause 9.3.2.4)
    response.headers.clear();
    return;
  }
  // Step 10: the controlling function of the group. With the "both" (or controlling) role it is this server; a
  // participating function needs one configured (mcptt.controller or group_controllers).
  const auto &target = refer.entry.target;
  if (role_ == "participating" && group_controller(target).empty()) {
    response.status_code = 404;
    response.headers = {{"Warning", warning_value(warn(Warning::controller_unknown))}};
    return;
  }
  // TS 24.379 clauses 10.1.1.3.1.2 step 8 and 10.1.2.3.2 step 8: an unauthorised emergency or imminent peril request is
  // refused with 403 (the operator's "pre-session-refuse" makes the next one so).
  // TS 24.379 clause 11.1.1.3.1.2 step 5 a: several entries are a first-to-answer call's, or 403 with warning 145.
  if (refer.entry_uris.size() > 1) {
    bool first_to_answer = false;
    for (const auto &part : pre_session_open_parts(user, refer.entry.body))
      if (part.content_type == svc_.info_mime) first_to_answer = parse_service_info_(part.body).session_type == "first-to-answer";
    if (!first_to_answer) {
      response.status_code = 403;
      response.headers = {{"Warning", warning_value(warn(Warning::called_party_unknown))}};
      return;
    }
  }
  if (!session->refuse_next.empty()) {
    for (const auto &part : pre_session_open_parts(user, refer.entry.body))
      if (part.content_type == svc_.info_mime) {
        const auto info = parse_service_info_(part.body);
        if ((session->refuse_next == "emergency" && info.emergency == true) ||
            (session->refuse_next == "imminent" && info.imminent_peril == true)) {
          event("pre_session_refer_refused", {{"user_id", user.id}, {"reason", "unauthorised " + session->refuse_next}});
          session->refuse_next.clear();
          response.status_code = 403;
          response.headers.clear();
          return;
        }
      }
  }
  // TS 24.379 clause 11.1.6.3.1.4 step 14: an ambient listening call's 200 (OK) tells the originator it may release
  // the call (annex D.3, RFC 6809).
  for (const auto &part : pre_session_open_parts(user, refer.entry.body))
    if (part.content_type == svc_.info_mime && parse_service_info_(part.body).session_type == svc_.ambient)
      response.headers.push_back({"Feature-Caps", ambient_release_caps()});
  // TS 24.380 clause 9.3.2.3.2: the session is in use from the REFER on.
  session->control->refer_received();
  std::vector<SipHeader> forwarded;
  session->refer_priority.clear();
  if (const auto priority = get_header(message.headers, "Resource-Priority"); !priority.empty()) {
    forwarded.push_back({"Resource-Priority", std::string(priority)}); // step 18
    session->refer_priority = std::string(priority);
  }
  event("pre_session_refer_accepted", {{"user_id", user.id}, {"target", target}});
  // Handled now, as an INVITE reaching this server would be: the call's fan-out is scheduled ahead of the next
  // tick's supervision of its setup (supervise_session). The 200 (OK) above is sent when this returns, ahead of the
  // INVITEs to the members and of any Connect (steps 14 and 15).
  try {
    pre_session_call(session->dialog, user.id, std::move(refer), std::move(forwarded));
  } catch (const std::exception &error) {
    event("pre_session_call_failed", {{"user_id", user.id}, {"reason", error.what()}});
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.3.1.2 steps 15 to 19 with clause 6.3.2.1.1.2: the INVITE towards the controlling function,
// built from the REFER: the entry's MCPTT-Info with <mcptt-request-uri> set to the entry's target (step 17), the
// session's SDP (the entry's offer where it has one: the implicit floor request of clause 6.4), the Accept-Contact of
// the entry and the Resource-Priority of the REFER (step 18). This server has the controlling role too: the INVITE is
// handled here as the client's own would be, and the answer the controlling function gives comes back as a Connect
// (answer_leg). The leg takes the session's media (pre_session_bind).
void McServer::pre_session_call(const std::string &dialog, const std::string &user_id,
                                PreEstablishedReferRequest refer, std::vector<SipHeader> headers) {
  const auto found = pre_sessions_.find(dialog);
  auto *user = by_id(user_id);
  if (found == pre_sessions_.end() || user == nullptr) return;
  const auto session = found->second;

  SipMessage invite;
  invite.method = "INVITE";
  invite.request_uri = session_service_;
  invite.from_uri = user->sip;
  invite.to_uri = session_service_;
  invite.call_id = invite.dialog_id = "pre-call-" + random_id();
  invite.source_address = core_address_;
  invite.transaction_id = "pre-call";
  invite.headers = refer.entry.headers;
  invite.headers.insert(invite.headers.end(), headers.begin(), headers.end());
  invite.headers.push_back({"P-Asserted-Identity", "<" + user->sip + ">"});
  // TS 24.379 clause 11.1.1.3.1.2 step 16 with clause 6.3.2.1.4: the INVITE of a private call carries the service's
  // Accept-Contact, which a private call's entry does not (11.1.1.2.2.1 step 8).
  if (!accepts_mcptt(invite))
    for (auto &header : refer_accept_contacts(svc_)) invite.headers.push_back(std::move(header));
  auto parts = pre_session_open_parts(*user, refer.entry.body);
  std::optional<MediaDescription> offer;
  bool private_target = false, first_to_answer = false;
  for (auto &part : parts) {
    if (part.content_type == svc_.info_mime) {
      auto info = parse_service_info_(part.body);
      // An ambient listening call is a private call (TS 24.379 clause 11.1.6.3.1.4 step 16).
      private_target = info.session_type == "private" || info.session_type == svc_.ambient;
      first_to_answer = info.session_type == "first-to-answer";
      // Clause 11.1.1.3.1.2 step 16 (clause 6.3.2.1.4): the called user's MCPTT ID; a first-to-answer call names its
      // invitees in the resource list only.
      if (!first_to_answer) info.request_uri = refer.entry.target;
      part.body = service_info_xml_(info);
    } else if (part.content_type == "application/sdp") {
      offer = parse_sdp(part.body);
    }
  }
  // TS 24.379 clause 6.3.2.1.1.2: the session's media; clause 6.4: the implicit floor request of the entry's offer or,
  // without one, of the session.
  auto media = *session->remote;
  media.implicit_request = offer ? offer->implicit_request : session->implicit_floor;
  if (offer && offer->floor_priority) media.floor_priority = offer->floor_priority;
  // TS 24.379 clause 11.1.1.2.2.1 step 8 c i: a private call's offer without a media-floor control section (the call
  // without floor control, clause 11.1.3.1.2: its speech SSRC) or with the I_MESSAGE of end-to-end security.
  if (offer) {
    media.direction = offer->direction; // TS 24.379 clause 6.2.1 item 2c: an ambient listening call's direction
    media.control = offer->control;
    if (offer->control == MediaControl::none) media.audio_ssrc = offer->audio_ssrc;
    if (!offer->key_mgmt.empty()) media.key_mgmt = offer->key_mgmt;
  }
  media.ice.reset();
  invite.remote_media = media;
  invite.parts = std::move(parts);
  invite.parts.insert(invite.parts.begin(), BodyPart{"application/sdp", make_sdp(media, 1)});
  // TS 24.379 clause 11.1.1.3.1.2: the private call's INVITE names the called user in a resource list, as the client's
  // own (clause 11.1.1.2.1.1 step 7).
  if (private_target) invite.parts.push_back({resource_lists_mime, private_call_resource_list(refer.entry.target)});
  // Clause 11.1.1.3.1.2 steps 5 b and 16 a: a first-to-answer call's invitees, one per entry of the REFER's list.
  if (first_to_answer) {
    std::vector<std::string> targets;
    for (const auto &uri : refer.entry_uris) targets.push_back(parse_refer_entry_uri(uri).target);
    invite.parts.push_back({resource_lists_mime, resource_list_xml(targets)});
  }

  SipResponse response;
  response.status_code = 200; // as incoming() starts every answer; the call procedures change it
  pre_session_call_setup_ = true;
  try {
    invite_request(invite, *user, response);
  } catch (...) {
    pre_session_call_setup_ = false;
    throw;
  }
  pre_session_call_setup_ = false;
  const auto leg = legs_.find(invite.dialog_id);
  if (leg == legs_.end()) {
    // Refused before a leg existed (TS 24.380 clause 9.3.2.4.11): Disconnect naming the session.
    const auto cause = response.status_code == 486 ? std::optional{PreEstablishedReasonCause::Busy} : std::nullopt;
    schedule([this, dialog, cause] {
      if (const auto again = pre_sessions_.find(dialog); again != pre_sessions_.end())
        pre_session_send(*again->second, again->second->control->disconnect(monotonic_ms(), cause, again->second->uri));
    });
    event("pre_session_call_refused", {{"user_id", user_id}, {"status", response.status_code}});
    return;
  }
  pre_session_bind(session, leg->second);
  event("pre_session_call", {{"user_id", user_id}, {"leg", invite.dialog_id}, {"target", refer.entry.target}});
  // An answer at once (a chat call joined): its Connect after the REFER's 200 (OK).
  if (!response.deferred && response.status_code >= 200)
    schedule([this, id = invite.dialog_id, response] {
      if (const auto found_leg = legs_.find(id); found_leg != legs_.end()) answer_leg(found_leg->second, response);
    });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.4.10 (the controlling function's 200 (OK): Connect to the originating client with the
// session identity of its Contact, the session type, the warn-text of a Warning 399, the answer state of its
// P-Answer-State and the called party) and clause 9.3.2.4.11 (a failure: Disconnect, the call ends). For any other
// leg, the SIP answer.
void McServer::answer_leg(const std::shared_ptr<Leg> &leg, const SipResponse &response) {
  if (leg->pre_session.empty()) return sip_.answer(leg->dialog, response);
  pre_session_answer(leg, response);
}

void McServer::pre_session_answer(const std::shared_ptr<Leg> &leg, const SipResponse &response) {
  const auto found = pre_sessions_.find(leg->pre_session);
  if (found == pre_sessions_.end()) return;
  const auto session = found->second;
  if (response.status_code / 100 != 2) {
    pre_session_send(*session, session->control->disconnect(monotonic_ms(), std::nullopt, session->uri));
    const auto id = leg->dialog;
    pre_session_unbind(session);
    state(id, SipCallState::disconnected, response.status_code);
    return;
  }
  std::string session_type, called_party;
  for (const auto &part : response.parts)
    if (part.content_type == svc_.info_mime) {
      const auto info = parse_service_info_(part.body);
      session_type = info.session_type;
      called_party = info.called_party;
    }
  std::string warning;
  if (const auto value = std::string(get_header(response.headers, "Warning")); value.starts_with("399")) {
    const auto open = value.find('"'), close = value.rfind('"');
    if (open != std::string::npos && close > open) warning = value.substr(open + 1, close - open - 1);
  }
  // TS 24.379 clause 6.3.2.1.8.5 (clause 10.1.2.3.2, 2xx step 3): a priority call's 2xx gives the client a re-INVITE in
  // the session with the session's SDP and the Resource-Priority of the INVITE sent to the controlling function; the
  // MCPTT-Info of the 2xx carries the call's priority state (TS 24.379 clause 6.2.8.1.16).
  if (!session->refer_priority.empty() && response.headers.end() ==
                                              std::find_if(response.headers.begin(), response.headers.end(),
                                                           [](const SipHeader &header) {
                                                             return header.name == "Warning" &&
                                                                    header.value.find("149") != std::string::npos;
                                                           })) {
    std::vector<BodyPart> info;
    for (const auto &part : response.parts)
      if (part.content_type == svc_.info_mime) info.push_back({part.content_type, part.body});
    try {
      sip_.reinvite(session->dialog, session->local, info,
                    [this, user = session->user](const SipResponse &answer) {
                      event("pre_session_priority_reinvite", {{"user_id", user}, {"status", answer.status_code}});
                    },
                    {{"Resource-Priority", session->refer_priority}});
    } catch (const std::exception &error) {
      event("pre_session_priority_reinvite_failed", {{"user_id", session->user}, {"reason", error.what()}});
    }
    session->refer_priority.clear();
  }
  const auto contact = response.contact_uri.empty() && leg->session ? leg->session->uri : response.contact_uri;
  const bool key_reinvite = leg->session && leg->session->first_to_answer && response.local_media &&
                            !response.local_media->key_mgmt.empty();
  if (session_type.empty() && leg->session)
    session_type = leg->session->private_call ? "private" : leg->session->chat ? "chat" : "prearranged";
  // TS 24.380 clause 8.3.3.3: an ambient listening call's Session Type is 'private' (TS 37.579-2 table 6.2.18.3.3-5).
  if (session_type == svc_.ambient) session_type = "private";
  auto connect = make_originating_connect(contact, session_type, warning,
                                          get_header(response.headers, "P-Answer-State"), called_party);
  // TS 24.380 clause 8.3.4.4 (TS 37.579-1 table 5.5.6.12-1 WITHOUT_FLOORCONTROL): a call without floor control uses
  // the session's speech stream only, control channel 0.
  if (leg->session && leg->session->no_media_control) connect.media_streams = PreEstablishedMediaStreams{1, 0};
  // TS 24.379 clause 11.1.1.3.1.2 (2xx, step 3) with clause 6.3.2.1.8.7: a first-to-answer call's 2xx with the
  // answering invitee's I_MESSAGE: a re-INVITE in the session whose offer, the session's media, carries it; on its
  // 2xx the media plane (the Connect).
  if (key_reinvite) {
    auto offer = session->local;
    offer.key_mgmt = response.local_media->key_mgmt;
    try {
      sip_.reinvite(session->dialog, offer, {},
                    [this, dialog = session->dialog, id = leg->dialog, connect](const SipResponse &answer) {
                      const auto found = pre_sessions_.find(dialog);
                      if (found == pre_sessions_.end() || found->second->call_leg != id) return;
                      if (answer.status_code / 100 == 2) {
                        pre_session_send(*found->second, found->second->control->connect(connect, monotonic_ms()));
                        return;
                      }
                      pre_session_send(*found->second,
                                       found->second->control->disconnect(monotonic_ms(), std::nullopt,
                                                                          found->second->uri));
                      pre_session_unbind(found->second);
                      state(id, SipCallState::disconnected, answer.status_code);
                    });
    } catch (const std::exception &error) {
      event("pre_session_reinvite_failed", {{"user_id", session->user}, {"reason", error.what()}});
      pre_session_send(*session, session->control->disconnect(monotonic_ms(), std::nullopt, session->uri));
      const auto id = leg->dialog;
      pre_session_unbind(session);
      state(id, SipCallState::disconnected, 500);
    }
    return;
  }
  pre_session_send(*session, session->control->connect(connect, monotonic_ms()));
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.4.4: the client left the call keeping the session (REFER "BYE"): the leg leaves its call as
// if its dialog ended, and the session's media come back; 'G: Pre-established session not in use'.
void McServer::pre_session_leave(const std::shared_ptr<PreSession> &session) {
  const auto id = session->call_leg;
  if (id.empty()) return;
  session->control->client_released();
  pre_session_unbind(session);
  state(id, SipCallState::disconnected, 200);
  event("pre_session_call_left", {{"user_id", session->user}, {"session_uri", session->uri}});
}

//------------------------------------------------------------------------------
// TS 24.380 clause 9.3.2.4.5: the controlling function released the call: Disconnect asking for an acknowledgement
// (T56), the session's media back, the leg ends. bye() calls this for a leg over a session.
void McServer::pre_session_end_call(const std::shared_ptr<Leg> &leg) {
  const auto found = pre_sessions_.find(leg->pre_session);
  const auto id = leg->dialog;
  if (found != pre_sessions_.end()) {
    const auto session = found->second;
    pre_session_send(*session, session->control->disconnect(monotonic_ms()));
    pre_session_unbind(session);
  }
  schedule([this, id] { state(id, SipCallState::disconnected, 200); });
}

//------------------------------------------------------------------------------
// RFC 8445 section 7.3 with RFC 7983 section 7: STUN on a leg's socket during a call over the session.
bool McServer::pre_session_leg_stun(const Leg &leg, IceStream stream, const Datagram &datagram) {
  if (leg.pre_session.empty() || !is_stun_packet(datagram.bytes)) return false;
  const auto found = pre_sessions_.find(leg.pre_session);
  if (found != pre_sessions_.end() && found->second->ice) {
    const auto [host, port] = source_of(datagram);
    found->second->ice->receive(stream, 1, datagram.bytes, host, port);
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.2.2.5.3 (automatic commencement: steps 2 to 7, the Connect of TS 24.380 clause 9.3.2.3.3 with
// Answer State 'Unconfirmed', as the controlling function is told by P-Answer-State in step 4; TS 37.579-2 table
// 6.1.1.6.3.3-1) and clause 6.3.2.2.6.3 (manual commencement: steps 2 to 5, a re-INVITE in the session's dialog with
// the call's MCPTT-Info and the session's media, and on its 200 (OK) the Connect of TS 24.380 clause 9.3.2.3.5).
// Clause 6.3.2.2.6.1 1 b and c: the session's media sections are the call's (this server offers them). The leg takes
// the session's media (pre_session_bind) and becomes active on the Acknowledge (pre_session_events).
// TS 24.379 clauses 6.3.2.2.5.3 step 1 and 6.3.2.2.6.3 step 1 (an emergency or imminent peril call, or a
// Priv-Answer-Mode): the member is invited on demand with a Replaces naming the session (Leg::replaces; false).
bool McServer::pre_session_invite_member(const std::shared_ptr<Session> &call, const std::shared_ptr<Leg> &leg,
                                         const User &user, const McpttInfo &info) {
  std::shared_ptr<PreSession> session;
  for (const auto &[dialog, candidate] : pre_sessions_)
    if (candidate->user == user.id && candidate->confirmed && candidate->call_leg.empty() && candidate->remote &&
        candidate->control->state() == PreEstablishedServerState::NotInUse) {
      session = candidate;
      break;
    }
  if (!session) return false;
  // A private call over the session (TS 24.379 clause 11.1.1.3.2 with clause 6.3.2.2.5.3 or 6.3.2.2.6.3), not a
  // video call (MCVideo has its own sessions). With end-to-end security the PCK I_MESSAGE goes in the Connect (TS
  // 24.380 clause 9.3.2.3.3 1 c iv) or the re-INVITE's SDP offer (clause 6.3.2.2.6.3). An ambient listening call's
  // Priv-Answer-Mode "Auto" (clause 11.1.6.3.1.4 step 17) makes it an INVITE with Replaces (clause 11.1.6.2.2.2
  // NOTE).
  if (call->private_call && !call->video_mode.empty()) return false;
  // Clauses 6.3.2.2.5.3 step 1 and 6.3.2.2.6.3 step 1: an emergency or imminent peril call, or a Priv-Answer-Mode (a
  // first-to-answer call's "Manual", TS 24.379 clause 11.1.1.4.1), is an on-demand INVITE (clause 6.3.2.2.5.2 or
  // 6.3.2.2.6.2) with a Replaces naming the session (RFC 3891; replaces_for: S07), which the client ends once it
  // accepts the call. The offer has the session's media parameters (codec, protection; step 1 b), on this server's
  // ports of the leg. Without a SIP core supporting resource sharing, no Resource-Share (step 1 c).
  const auto priv_answer = std::any_of(call->answer_headers.begin(), call->answer_headers.end(),
                                       [](const SipHeader &header) { return header.name == "Priv-Answer-Mode"; });
  if (info.emergency == true || info.imminent_peril == true || priv_answer || call->first_to_answer) {
    const auto ids = sip_.dialog_identifiers(session->dialog);
    if (!ids) return false;
    leg->replaces = replaces_value(replaces_for(*ids));
    leg->local.payload_type = session->local.payload_type;
    leg->local.octet_aligned = session->local.octet_aligned;
    event("pre_session_replaced_invite", {{"user_id", user.id}, {"session_uri", session->uri}});
    return false;
  }
  if (!call->private_call && call->no_media_control) return false;
  leg->dialog = "pre-call-" + random_id();
  leg->remote = session->remote;
  leg->remote->ice.reset();
  pre_session_bind(session, leg);
  add_leg(leg);
  session->control->refer_received(); // 'G: Pre-established session in use' from now on (clause 9.3.2.3.3 step 5)
  bool manual = call->policy.value("answer_mode", "Auto") == "Manual";
  if (call->private_call)
    manual = std::any_of(call->answer_headers.begin(), call->answer_headers.end(), [](const SipHeader &header) {
      return header.name == "Answer-Mode" && header.value == "Manual";
    });
  event("call_fanout", {{"user_id", user.id}, {"session_uri", call->uri}, {"pre_established", true},
                        {"commencement", manual ? "manual" : "automatic"}});
  // TS 24.380 clause 9.3.2.3.3 1 d (NOTE 1): a private call without floor control uses the speech stream only.
  std::optional<PreEstablishedMediaStreams> streams;
  if (call->no_media_control) streams = PreEstablishedMediaStreams{1, 0};
  const auto pck = call->private_call && !call->private_key_mgmt.empty() ? pck_i_message_of(call->private_key_mgmt)
                                                                        : std::vector<std::uint8_t>{};
  auto connect = make_terminating_connect(call->uri, info.session_type, call->private_call ? "" : call->group,
                                          call->initiator, false, pck, streams);
  if (!manual) {
    connect.answer_state = PreEstablishedAnswerState::Unconfirmed;
    pre_session_send(*session, session->control->connect(connect, monotonic_ms()));
    return true;
  }
  // TS 24.380 clause 9.3.2.3.5: the Connect after the re-INVITE's 200 (OK) has no PCK I_MESSAGE (the offer had it).
  connect.pck_i_message.clear();
  auto offer = session->local;
  offer.floor_priority = leg->local.floor_priority;
  if (call->private_call) {
    offer.key_mgmt = call->private_key_mgmt; // TS 24.379 clause 11.1.1.3.2: the caller's I_MESSAGE
    if (call->no_media_control) {
      offer.control = MediaControl::none;
      if (offer.ice) offer.ice->control.clear(); // no media-floor control section, so none of its candidates
      offer.control_removed = true;              // RFC 3264 section 8.2: the session's stream, port 0
    }
  }
  try {
    sip_.reinvite(session->dialog, offer, priority_parts(info),
                  [this, dialog = session->dialog, id = leg->dialog, connect](const SipResponse &response) {
                    const auto found = pre_sessions_.find(dialog);
                    if (found == pre_sessions_.end() || found->second->call_leg != id) return;
                    if (response.status_code / 100 == 2) {
                      pre_session_send(*found->second, found->second->control->connect(connect, monotonic_ms()));
                      return;
                    }
                    // TS 24.379 clause 10.1.1.2.1.2: the user declined (480, warning 110) or the client refused.
                    found->second->control->client_released();
                    pre_session_unbind(found->second);
                    state(id, SipCallState::disconnected, response.status_code);
                  });
  } catch (const std::exception &error) {
    // The session stays without a call; the member's leg fails (the call's setup supervision answers for it).
    event("pre_session_reinvite_failed", {{"user_id", user.id}, {"reason", error.what()}});
    session->control->client_released();
    pre_session_unbind(session);
    schedule([this, id = leg->dialog] { state(id, SipCallState::disconnected, 500); });
  }
  return true;
}

} // namespace mcx
