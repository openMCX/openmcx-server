// Relays of calls, messages, subscriptions and media between the participating and controlling functions of a system (TS 24.379 clause 6.3.2).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19),
// TS 24.281 V19.6.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 6184.

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.2.6: call forwarding of a private call; the caller is asked
// to call the forwarding target, which its follow-up call names with
// call-forwarding-ind (checked against the mapping kept here).
void McServer::forward_private_call(const std::string &caller, const std::string &by, const std::string &target,
                                    const std::string &reason) {
  forwarding_mappings_[caller] = {target, monotonic_ms() + 60000};
  McpttInfo forward;
  forward.calling_user = by;
  forward.service = {{"request-type", "forward-private-call-request"},
                     {"forwarding-reason", reason},
                     {"forwarded-by-mcptt-id", by},
                     {"forwarding-target-id", target},
                     {"forwarding-target-orig-id", target}};
  schedule([this, forward, caller] {
    if (const auto *user = by_id(caller)) relay_service_message(*user, forward);
  });
  event("private_call_forwarded", {{"user_id", caller}, {"by", by}, {"to", target}, {"reason", reason}});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.2.5: on expiry of TNP1 the invitation to the called user is cancelled,
// the caller's INVITE is answered 480 with warning 175, and the caller is asked
// to call the forwarding target.
void McServer::expire_no_answer(const std::shared_ptr<Session> &session) {
  session->no_answer_deadline = 0;
  const auto target = session->private_request.target;
  for (const auto &leg : session_legs(*session)) {
    if (leg->awaiting_answer) {
      leg->awaiting_answer = false;
      SipResponse failure;
      failure.status_code = 480;
      failure.headers = {{"Warning", warning_value(warn(Warning::call_forwarded))}};
      sip_.answer(leg->dialog, failure);
    } else
      sip_.bye(leg->dialog);
  }
  event("no_answer_timer_expired", {{"session_uri", session->uri}, {"user_id", target}});
  forward_private_call(session->initiator, target, session->no_answer_target, "no-answer");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 steps 11c and 11d: the originating participating function checks a
// follow-up transfer or forwarding call against the cached mapping; a controlling function on a
// peer then trusts the indication.
std::string McServer::check_service_mapping(const std::string &id, const SipMessage &message, const McpttInfo &info) {
  const BodyPart *resources = nullptr;
  for (const auto &part : message.parts)
    if (part.content_type == resource_lists_mime) resources = &part;
  for (auto [name, cache, warning] :
       {std::tuple{"call-transfer-ind", &transfer_mappings_, Warning::transfer_not_authorised},
        std::tuple{"call-forwarding-ind", &forwarding_mappings_, Warning::forwarding_not_authorised}}) {
    if (!info.service.contains(name) || info.service.at(name) != "true") continue;
    std::string target;
    try {
      if (resources) target = parse_private_call_target(resources->body);
    } catch (const std::exception &) {
      // No valid target: no mapping matches below.
    }
    const auto found = cache->find(id);
    if (found == cache->end() || found->second.target != target || found->second.deadline < monotonic_ms())
      return warn(warning);
    cache->erase(found);
  }
  return {};
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.3.1 and 11.1.1.3.1.1: the originating participating function passes a
// served user's call request to the controlling function.
SipResponse McServer::relay_outgoing(const SipMessage &message, User &user, const std::string &peer,
                                     const std::string &target) {
  SipResponse response;
  if (!message.remote_media) {
    response.status_code = 488;
    return response;
  }
  // TS 24.379 clause 11.1.2.3.1: an offer without floor control is passed on; the controlling
  // function accepts it only for a private call.
  try {
    validate_remote(user.id, *message.remote_media, true, true);
  } catch (const std::exception &error) {
    event("sdp_rejected", {{"reason", error.what()}});
    response.status_code = 488;
    return response;
  }
  const auto outgoing = message_info(message, svc_);
  // A call request initiated by a listened-to user releases its ambient call
  // relayed here (T12), unless this request is that ambient call.
  if (outgoing.session_type != svc_.ambient) release_relayed_ambient(user.id, ambient_reason("initiated-by"));
  auto relay = make_relay(user.id, peer);
  relay->client_dialog = message.dialog_id;
  relay->client_remote = *message.remote_media;
  relay->ambient_party = outgoing.session_type == svc_.ambient && outgoing.ambient_listening_type == "local-init";
  relay->implicit_group = begin_implicit_affiliation(user, outgoing, false);
  auto headers = route_to(peer, relayed_headers(message.headers));
  headers.push_back({"P-Asserted-Identity", "<" + user.sip + ">"});
  relay->peer_dialog = sip_.invite(
      target, mirror(*message.remote_media, relay->local), application_parts(message.parts),
      [this, weak = std::weak_ptr<Relay>(relay)](const SipResponse &answer) {
        schedule([this, weak, answer] {
          if (auto relay = weak.lock()) relay_answer(relay, answer, false);
        });
      },
      headers);
  add_relay(relay);
  event("call_relayed", {{"user_id", user.id}, {"server", peer}, {"target", target}, {"direction", "originating"}});
  response.status_code = 100;
  response.reason = "Trying";
  response.deferred = true;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.3.2 and 11.1.1.3.2: the terminating participating function passes the
// controlling function's call to the served user.
SipResponse McServer::relay_incoming(const SipMessage &message, const std::string &peer, const User &user) {
  SipResponse response;
  if (!message.remote_media) {
    response.status_code = 488;
    return response;
  }
  if (user.expires <= std::time(nullptr)) {
    response.status_code = 480;
    return response;
  }
  const auto info = message_info(message, svc_);
  if (info.session_type == "private" || info.session_type == "first-to-answer") {
    // TS 24.379 clause 11.1.1.3.2 steps 8 and 9: the called user's own authorisation.
    Json policy;
    try {
      policy = user_profile(user.id).value("private_call", Json::object());
    } catch (const std::exception &) {
      response.status_code = 404;
      return response;
    }
    if (const auto decision = authorize_private_callee(policy, info.calling_user, svc_); !decision) {
      response.status_code = decision.status;
      response.headers = {{"Warning", warning_value(decision.warning)}};
      return response;
    }
  }
  auto relay = make_relay(user.id, peer);
  relay->peer_dialog = message.dialog_id;
  relay->peer_remote = *message.remote_media;
  relay->ambient_party = info.session_type == svc_.ambient && info.ambient_listening_type == "remote-init";
  auto headers = relayed_headers(message.headers);
  if (const auto contact = get_header(message.headers, "Contact"); contact.find("isfocus") != std::string_view::npos) {
    relay->alias = session_alias(peer, header_uri(contact));
    headers.push_back({"Contact", focus_contact_header(relay->alias)});
  }
  auto invite = [this, weak = std::weak_ptr<Relay>(relay), sip = user.sip, parts = application_parts(message.parts),
                 headers] {
    const auto relay = weak.lock();
    if (!relay || relay->ended) return;
    relay->client_dialog = sip_.invite(
        sip, mirror(*relay->peer_remote, relay->local), parts,
        [this, weak](const SipResponse &answer) {
          schedule([this, weak, answer] {
            if (auto relay = weak.lock()) relay_answer(relay, answer, true);
          });
        },
        headers);
    add_relay(relay);
  };
  relays_[relay->peer_dialog] = relay;
  // T12: a call request for a listened-to user, controlled elsewhere, releases its
  // ambient call relayed here first; the invitation waits for that release to reach
  // the client, which would otherwise refuse it as busy.
  if (info.session_type == svc_.ambient || !release_relayed_ambient(user.id, ambient_reason("for"), invite)) invite();
  event("call_relayed", {{"user_id", user.id}, {"server", peer}, {"direction", "terminating"}});
  response.status_code = 100;
  response.reason = "Trying";
  response.deferred = true;
  response.peer_route = "<" + peers_.at(peer).route + ";lr>";
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.3.2.1.5: pass a response to the INVITE sent on one side of a relay to the INVITE
// received on the other side.
void McServer::relay_answer(const std::shared_ptr<Relay> &relay, const SipResponse &response, bool toward_peer) {
  if (relay->ended || response.status_code <= 100) return;
  const auto downstream = toward_peer ? relay->peer_dialog : relay->client_dialog;
  SipResponse answer;
  answer.status_code = response.status_code;
  answer.reason = response.reason;
  answer.headers = relayed_headers(response.headers);
  if (response.status_code >= 300) {
    answer.content_type = response.content_type;
    answer.body = response.body;
    // A redirect (a call to a functional alias, 300) keeps its Contact.
    if (response.status_code < 400)
      if (const auto contact = get_header(response.headers, "Contact"); !contact.empty())
        answer.headers.push_back({"Contact", std::string(contact)});
  } else if (response.status_code >= 200) {
    std::optional<MediaDescription> media;
    try {
      media = sdp_of(response.parts);
    } catch (const std::exception &) {
      // A malformed SDP answer is treated as none, refused below.
    }
    if (!media) {
      event("relay_answer_rejected", {{"user_id", relay->user}, {"reason", "answer without SDP"}});
      answer = {};
      answer.status_code = 500;
    } else {
      (toward_peer ? relay->client_remote : relay->peer_remote) = *media;
      answer.local_media = mirror(*media, relay->local);
      answer.parts = application_parts(response.parts);
      const auto contact = get_header(response.headers, "Contact");
      if (!toward_peer && contact.find("isfocus") != std::string_view::npos) {
        relay->alias = session_alias(relay->peer, header_uri(contact));
        answer.contact_uri = relay->alias;
        answer.focus = true;
      }
    }
  }
  try {
    sip_.answer(downstream, answer);
  } catch (const std::exception &error) {
    event("relay_answer_failed", {{"user_id", relay->user}, {"reason", error.what()}});
  }
  if (answer.status_code >= 200 && !relay->implicit_group.empty())
    end_implicit_affiliation(relay->user, std::exchange(relay->implicit_group, {}), answer.status_code < 300);
  if (answer.status_code >= 300) end_relay(relay);
}

//------------------------------------------------------------------------------
// Helper: a relay ends: both dialogs are released with a SIP BYE (carrying the received BYE body)
// and its ports are freed.
void McServer::end_relay(const std::shared_ptr<Relay> &relay) {
  if (relay->ended) return;
  relay->ended = true;
  std::vector<BodyPart> parts;
  if (!relay->bye_parts.empty()) parts.push_back(relay->bye_parts.front());
  for (const auto &dialog : {relay->client_dialog, relay->peer_dialog}) {
    relays_.erase(dialog);
    if (dialog.empty() || (relay->client_released && dialog == relay->client_dialog)) continue;
    try {
      sip_.bye(dialog, {}, {}, parts);
    } catch (const std::exception &error) {
      event("relay_release_failed", {{"reason", error.what()}});
    }
  }
  // Free the ports now: a pending task may still hold the relay, and the next
  // call (for example after a functional alias redirect) may reuse them.
  relay->audio.reset();
  relay->floor.reset();
  relay->video.reset();
  event("relay_ended", {{"user_id", relay->user}, {"server", relay->peer}});
}

//------------------------------------------------------------------------------
// Helper: every relay of the user ends.
void McServer::end_user_relays(const std::string &id) {
  std::vector<std::shared_ptr<Relay>> found;
  for (const auto &[dialog, relay] : relays_)
    if (relay->user == id) found.push_back(relay);
  for (const auto &relay : found) end_relay(relay);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.2.1.6 and 6.3.2.1.9: an in-dialog request (BYE, re-INVITE, INFO, MESSAGE) on one
// side of a relay, passed to the other side.
SipResponse McServer::relay_request(const SipMessage &message, const std::shared_ptr<Relay> &relay, bool from_peer) {
  SipResponse response;
  response.status_code = 200;
  if ((from_peer ? relay->peer_dialog : relay->client_dialog) != message.dialog_id) {
    response.status_code = 403;
    return response;
  }
  const auto other = from_peer ? relay->client_dialog : relay->peer_dialog;
  auto headers = relayed_headers(message.headers);
  if (!from_peer)
    if (const auto *user = by_id(relay->user)) headers.push_back({"P-Asserted-Identity", "<" + user->sip + ">"});
  if (message.method == "BYE") {
    // Observed before the dialog ends; the BYE body (a <release-reason>) is passed on.
    relay->bye_parts = application_parts(message.parts);
    // The BYE goes on to the other side before this one is answered, so that it
    // reaches the client ahead of any request the answer prompts: after a server
    // release of an ambient call, the controlling function's invitation of the
    // released user (TS 24.281 clause 15.4.3). end_relay's own BYE is then a no-op.
    std::vector<BodyPart> onward;
    if (!relay->bye_parts.empty()) onward.push_back(relay->bye_parts.front());
    try {
      sip_.bye(other, {}, {}, onward);
    } catch (const std::exception &error) {
      event("relay_release_failed", {{"reason", error.what()}});
    }
    return response;
  }
  if (message.method == "INFO" || message.method == "MESSAGE") {
    try {
      sip_.request_in_dialog(other, message.method, message.content_type, message.body, headers,
                             [this, id = message.transaction_id](const SipResponse &answer) {
                               if (answer.status_code < 200) return;
                               SipResponse reply;
                               reply.status_code = answer.status_code;
                               reply.reason = answer.reason;
                               schedule([this, id, reply] { sip_.respond(id, reply); });
                             });
      response.deferred = true;
    } catch (const std::exception &) {
      response.status_code = 481;
    }
    return response;
  }
  if (message.method != "INVITE") {
    response.status_code = 405;
    return response;
  }
  return relay_reinvite(message, relay, from_peer, other, headers);
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.2.1.6 and 6.3.2.1.9: a re-INVITE on one side of a relay. A session refresh is answered on
// its own side; one that changes the call goes on to the other side, whose answer comes back
// (relayed_reinvite_answer).
SipResponse McServer::relay_reinvite(const SipMessage &message, const std::shared_ptr<Relay> &relay, bool from_peer,
                                     const std::string &other, const std::vector<SipHeader> &headers) {
  SipResponse response;
  response.status_code = 200;
  if (!message.remote_media) {
    response.status_code = 488;
    return response;
  }
  if (!from_peer) {
    try {
      validate_remote(relay->user, *message.remote_media, true, true);
    } catch (const std::exception &) {
      response.status_code = 488;
      return response;
    }
  }
  (from_peer ? relay->peer_remote : relay->client_remote) = *message.remote_media;
  const auto parts = application_parts(message.parts);
  const auto &opposite = from_peer ? relay->client_remote : relay->peer_remote;
  if (parts.empty() && opposite) {
    // A session refresh stays on its own side of the relay.
    response.local_media = mirror(*opposite, relay->local);
    return response;
  }
  try {
    sip_.reinvite(
        other, mirror(*message.remote_media, relay->local), parts,
        [this, weak = std::weak_ptr<Relay>(relay), id = message.transaction_id, from_peer](const SipResponse &answer) {
          schedule([this, weak, id, from_peer, answer] {
            sip_.respond(id, relayed_reinvite_answer(answer, weak.lock(), from_peer));
          });
        },
        headers);
    response.deferred = true;
  } catch (const std::exception &) {
    response.status_code = 491;
  }
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.3.2.1.6 and 6.3.2.1.9: the other side's answer to a relayed re-INVITE, as the answer to the
// side that sent it: a refusal is passed on, an accepting answer with its SDP mirrored to the relay's ports.
SipResponse McServer::relayed_reinvite_answer(const SipResponse &answer, const std::shared_ptr<Relay> &relay,
                                              bool from_peer) {
  SipResponse reply;
  reply.status_code = answer.status_code;
  reply.reason = answer.reason;
  reply.headers = relayed_headers(answer.headers);
  if (answer.status_code >= 300) {
    reply.content_type = answer.content_type;
    reply.body = answer.body;
    return reply;
  }
  std::optional<MediaDescription> media;
  try {
    if (relay) media = sdp_of(answer.parts);
  } catch (const std::exception &) {
    // A malformed SDP answer is treated as none (500 below).
  }
  if (!media) {
    // The relay ended while the re-INVITE was out (481, RFC 3261 section 12.2.2), or the other side accepted it
    // without an SDP answer to pass on (500).
    SipResponse refusal;
    refusal.status_code = relay ? 500 : 481;
    return refusal;
  }
  (from_peer ? relay->client_remote : relay->peer_remote) = *media;
  reply.local_media = mirror(*media, relay->local);
  reply.parts = application_parts(answer.parts);
  return reply;
}

//------------------------------------------------------------------------------
// Helper: an out-of-dialog MESSAGE passed to target, without location requests (TS 24.379 clause 13.2.5);
// the final response is relayed back.
SipResponse McServer::relay_message(const SipMessage &message, const std::string &target,
                                    std::vector<SipHeader> headers, std::function<void(int)> done) {
  for (const auto &header : relayed_headers(message.headers)) headers.push_back(header);
  const auto [type, body] = without_location_requests(message.content_type, message.body);
  sip_.request("MESSAGE", target, type, body, headers,
               [this, id = message.transaction_id, done](const SipResponse &answer) {
                 if (answer.status_code < 200) return;
                 if (done) schedule([done, status = answer.status_code] { done(status); });
                 SipResponse reply;
                 reply.status_code = answer.status_code;
                 reply.reason = answer.reason;
                 reply.headers = relayed_headers(answer.headers);
                 reply.content_type = answer.content_type;
                 reply.body = answer.body;
                 schedule([this, id, reply] { sip_.respond(id, reply); });
               });
  SipResponse response;
  response.deferred = true;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.3.3: the participating function passes a conference event subscription on to
// a peer's session and answers it as the controlling function answers it (TS 24.379 clause 10.1.3.4);
// its NOTIFYs return with the session URI replaced by the local alias.
SipResponse McServer::relay_subscription(const SipMessage &message, const User &user, const std::string &alias,
                                         const SessionAlias &target) {
  SipResponse response;
  // RFC 3261 section 20.19: a missing or malformed Expires is a bad request.
  const auto expires = parse_expires(get_header(message.headers, "Expires"));
  if (!expires) {
    response.status_code = 400;
    return response;
  }
  auto relay = std::make_shared<ConferenceRelay>();
  relay->peer = target.peer;
  relay->client_dialog = message.dialog_id;
  relay->alias = alias;
  auto headers = route_to(target.peer, relayed_headers(message.headers));
  headers.push_back({"P-Asserted-Identity", "<" + user.sip + ">"});
  headers.push_back({"Accept", std::string(get_header(message.headers, "Accept"))});
  relay->upstream_dialog = sip_.subscribe(
      target.remote, "conference", static_cast<unsigned>(*expires), headers,
      [this, weak = std::weak_ptr<ConferenceRelay>(relay), id = message.transaction_id](const SipResponse &answer) {
        if (answer.status_code < 200) return;
        schedule([this, weak, id, answer] {
          SipResponse reply;
          reply.status_code = answer.status_code;
          reply.reason = answer.reason;
          reply.headers = relayed_headers(answer.headers);
          if (answer.status_code < 300)
            reply.headers.push_back({"Expires", std::string(get_header(answer.headers, "Expires"))});
          sip_.respond(id, reply);
          const auto relay = weak.lock();
          if (!relay) return;
          if (answer.status_code >= 300) {
            event("conference_relay_rejected", {{"status", answer.status_code}});
            conference_relays_.erase(relay->client_dialog);
            conference_relays_.erase(relay->upstream_dialog);
            return;
          }
          relay->accepted = true;
          for (const auto &[state, parts] : std::exchange(relay->pending, {})) {
            forward_conference(*relay, state, parts);
            if (state.starts_with("terminated")) {
              conference_relays_.erase(relay->client_dialog);
              conference_relays_.erase(relay->upstream_dialog);
            }
          }
        });
      },
      message.content_type, message.body);
  conference_relays_[relay->client_dialog] = relay;
  conference_relays_[relay->upstream_dialog] = relay;
  response.deferred = true;
  return response;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.3.3: a conference event NOTIFY passed to the client, with the session URI
// replaced by the local alias.
void McServer::forward_conference(ConferenceRelay &relay, const std::string &state, std::vector<BodyPart> parts) {
  for (auto &part : parts)
    if (part.content_type == "application/conference-info+xml") {
      auto conference = parse_conference_info(part.body);
      if (!conference.session_uri.empty()) conference.session_uri = relay.alias;
      part.body = conference_info_xml(conference);
    }
  const auto boundary = "mcx-" + random_id();
  try {
    const auto [type, body] = message_body(parts, boundary);
    sip_.notify(relay.client_dialog, "conference", state, type, body);
  } catch (const std::exception &error) {
    event("conference_relay_failed", {{"reason", error.what()}});
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.3.3: an in-dialog request of a relayed conference event subscription; the peer's
// NOTIFY is passed on (held until the subscription is accepted), the client's refresh answered here.
SipResponse McServer::relay_conference(const SipMessage &message, const std::shared_ptr<ConferenceRelay> &relay,
                                       bool from_peer) {
  SipResponse response;
  response.status_code = 200;
  if (!from_peer || message.method != "NOTIFY" || message.dialog_id != relay->upstream_dialog) {
    // The client's refresh or removal is answered here.
    if (message.method == "SUBSCRIBE")
      response.headers = {{"Expires", std::string(get_header(message.headers, "Expires"))}};
    return response;
  }
  const auto state = std::string(get_header(message.headers, "Subscription-State"));
  if (!relay->accepted) {
    relay->pending.emplace_back(state, message.parts);
    return response;
  }
  forward_conference(*relay, state, message.parts);
  if (state.starts_with("terminated")) {
    conference_relays_.erase(relay->client_dialog);
    conference_relays_.erase(relay->upstream_dialog);
  }
  return response;
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 6.4.2 and 6.4.3 (TS 24.581 clauses 6.4.2 and 6.4.3): the participating function
// passes floor (transmission) control messages and RTP media between the client and the peer.
void McServer::relay_packets(Relay &relay, RelayStream stream) {
  const bool floor = stream == RelayStream::floor;
  auto &socket = floor ? relay.floor : stream == RelayStream::video ? relay.video : relay.audio;
  if (!socket) return;
  // A video burst is one picture in several packets (RFC 6184), as at a leg.
  const int burst = stream == RelayStream::video ? 128 : 32;
  for (int index = 0; index < burst; ++index) {
    auto datagram = socket->receive();
    if (!datagram) break;
    if (!relay.client_remote || !relay.peer_remote || relay.ended) continue;
    const auto &client = *relay.client_remote, &remote = *relay.peer_remote;
    if (stream == RelayStream::video && (!client.video || !remote.video)) {
      status_["relay_dropped"] = status_.value("relay_dropped", 0u) + 1;
      continue;
    }
    const auto port = [stream](const MediaDescription &media) -> std::uint16_t {
      return stream == RelayStream::floor   ? media.floor_port
             : stream == RelayStream::video ? media.video->port
                                            : media.audio_port;
    };
    const auto &client_address = floor ? client.floor_address : client.address,
               &remote_address = floor ? remote.floor_address : remote.address;
    // TS 33.180 clauses 9.4.2 and 9.4.5: in a protected call the floor control between the
    // client and this server is under the client's CSK, and between this server and
    // the peer under their SPK. Speech and video are protected end to end and pass unchanged.
    ProtectedCall *csk = nullptr, *spk = nullptr;
    if (floor && client.protected_media) {
      const auto *user = by_id(relay.user);
      const auto peer = peers_.find(relay.peer);
      csk = user ? user->protection.get() : nullptr;
      spk = peer != peers_.end() ? peer->second.spk.get() : nullptr;
      if (!csk || !spk) {
        status_["relay_dropped"] = status_.value("relay_dropped", 0u) + 1;
        continue;
      }
    }
    try {
      if (UdpSocket::matches(datagram->source, client_address, port(client))) {
        const auto plain = csk ? csk->unprotect_floor(datagram->bytes) : datagram->bytes;
        if (floor && refuse_remote_request(relay, *socket, plain, csk)) continue;
        socket->send(csk ? spk->protect_floor(plain) : datagram->bytes, remote_address, port(remote));
      } else if (UdpSocket::matches(datagram->source, remote_address, port(remote)))
        socket->send(csk ? csk->protect_floor(spk->unprotect_floor(datagram->bytes)) : datagram->bytes, client_address,
                     port(client));
      else {
        status_["relay_dropped"] = status_.value("relay_dropped", 0u) + 1;
        continue;
      }
    } catch (const std::exception &error) {
      status_["relay_refused"] = status_.value("relay_refused", 0u) + 1;
      event("relay_floor_refused", {{"user_id", relay.user}, {"reason", error.what()}});
      continue;
    }
    if (csk) status_["relay_rekeyed"] = status_.value("relay_rekeyed", 0u) + 1;
    status_["relay_forwarded"] = status_.value("relay_forwarded", 0u) + 1;
    if (stream == RelayStream::video) status_["relay_video_forwarded"] = status_.value("relay_video_forwarded", 0u) + 1;
  }
}

} // namespace mcx
