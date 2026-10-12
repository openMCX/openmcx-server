//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData IP connectivity: one-to-one IP connectivity sessions at the combined participating and controlling MCData
// function (TS 24.282 clause 20) and the relay of their GRE-in-UDP tunnel (TS 24.582 clause 13.3) (member functions
// of DataServer, declared in data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19).

#include "data_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.282 clauses 20.3.1 and 20.4.2: a one-to-one IP connectivity session. The originator is
// answered only once the called client has accepted (clause 20.4.2, last paragraph), so
// the INVITE is first answered 100 and completed from the called leg's answer.
SipResponse DataServer::ipcon_invite(const SipMessage &request, const User &user, const mcdata::Info &info,
                                     const BodyPart &sdp, const BodyPart *resources) {
  const char *what = "ipconn";
  // TS 24.282 clause 20.4.2 step 2: the IP connectivity feature tag and ICSI in Accept-Contact.
  if (!ipcon_accept_contact(request)) return reject(403, "", user.id, what);
  // TS 24.282 clause 20.3.1 steps 6 and 7 with clause 11.1.
  const auto policy = profile(user.id).value("mcdata", Json::object());
  if (!policy.value("transmit_data", false))
    return reject(403, "200 user not authorised to transmit data", user.id, what);

  // TS 24.282 clause 20.4.2 step 5a: exactly one target in resource-lists.
  std::string target;
  try {
    if (resources) target = parse_private_call_target(resources->body);
  } catch (const std::exception &) {
    target.clear();
  }
  if (target.empty())
    return reject(403, "227 unable to determine targeted user for one-to-one IP Connectivity", user.id, what);
  if (auto redirect = ipcon_alias_redirect(user, info, target)) return *redirect;

  // The one-to-one lists of TS 24.282 clause 11.1, as for the other one-to-one communications.
  if (const auto list = policy.value("targets", Json::array()); !list.empty() && !listed(list, target))
    return reject(403, "229 one-to-one MCData communication not authorised to the targeted user", user.id, what);
  const auto *recipient = by_id(target);
  if (!recipient) return reject(404, "", user.id, what); // TS 24.282 clause 20.3.2 step 4

  // The called user's incoming list (TS 24.282 clause 20.3.2).
  const auto incoming_policy = profile(target).value("mcdata", Json::object());
  // The list applies with one or more entries (as TS 24.282 clause 9.2.3.3 step 4A).
  const auto incoming_list = incoming_policy.value("incoming_from", Json::array());
  if (!incoming_policy.value("incoming_any", false) && !incoming_list.empty() && !listed(incoming_list, user.id))
    return reject(403, "230 one-to-one MCData communication not authorised from this originating user", user.id, what);
  SipResponse response;
  ipconn::TunnelMedia offer;
  try {
    offer = ipconn::parse_tunnel_sdp(sdp.body);
  } catch (const std::exception &error) {
    event("mcdata_ipconn_sdp_rejected", {{"user_id", user.id}, {"reason", error.what()}});
    response.status_code = 488;
    return response;
  }
  auto tunnel = std::make_shared<IpconSession>();
  tunnel->originator = user.id;
  tunnel->target = target;
  tunnel->called_alias = info.called_functional_alias;
  tunnel->origin_dialog = request.dialog_id;
  tunnel->identity = session_identity({});
  tunnel->origin_peer = offer;
  const auto address = tunnel_address();
  tunnel->origin_socket = std::make_unique<UdpSocket>(address, 0);
  tunnel->target_socket = std::make_unique<UdpSocket>(address, 0);

  // TS 24.282 clauses 20.3.0a, 20.4.0a and 20.4.0b: this server's address and ports replace the clients'.
  const auto origin_port = tunnel->origin_socket->port(), target_port = tunnel->target_socket->port();
  tunnel->origin_sdp = ipconn::tunnel_sdp({address, origin_port, origin_port}, 1);
  tunnel->target_sdp = ipconn::tunnel_sdp({address, target_port, target_port}, 1);
  tunnel->deadline = monotonic_ms() + ipconn_config().value("setup_ms", 30000u);
  ipcons_[request.dialog_id] = tunnel;

  // TS 24.282 clause 20.4.1: the called client is invited once this request has its dialog.
  mcdata::Info invited = info;
  invited.request_uri = target;   // TS 24.282 clause 20.4.1 step 8a
  invited.calling_user = user.id; // TS 24.282 clause 20.3.1 step 12
  invited.call_to_functional_alias.reset();

  // TS 24.282 clause 20.3.1 step 16: present an alias only while it is active for the user.
  if (!info.functional_alias.empty() && !alias_active(info.functional_alias, user.id)) invited.functional_alias.clear();
  pending_.push_back([this, tunnel, invited, sip = recipient->sip, originator_sip = user.sip] {
    ipcon_invite_target(tunnel, invited, sip, originator_sip);
  });
  response.status_code = 100;
  response.reason = "Trying";
  response.local_sdp = tunnel->origin_sdp;
  session_contact(response, tunnel->identity, "ipconn"); // the dialog keeps it for the 200 (OK)
  count("ipconn_sessions");
  event("mcdata_ipconn_requested", {{"user_id", user.id},
                                    {"target", target},
                                    {"dialog", request.dialog_id},
                                    {"origin_port", origin_port},
                                    {"target_port", target_port}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 20.4.2 step 2: the request carries the IP connectivity feature tag and ICSI in Accept-Contact.
bool DataServer::ipcon_accept_contact(const SipMessage &request) {
  bool tag = false, icsi = false;
  const auto encoded_icsi = url_encode(mcdata::ipconn_icsi);
  for (const auto &header : request.headers) {
    std::string name = header.name;
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char character) { return std::tolower(character); });
    if (name != "accept-contact") continue;
    if (header.value.find("+g.3gpp.mcdata.ipconn") != std::string::npos) tag = true;
    if (header.value.find(encoded_icsi) != std::string::npos ||
        header.value.find(mcdata::ipconn_icsi) != std::string::npos)
      icsi = true;
  }
  return tag && icsi;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 20.4.2 step 5a1: a target that is a functional alias (indicated or found to be one): the
// originator is sent with 300 (Multiple Choices) to one user that activated it, or refused; nothing for a user.
std::optional<SipResponse> DataServer::ipcon_alias_redirect(const User &user, const mcdata::Info &info,
                                                            const std::string &target) {
  const char *what = "ipconn";
  bool to_alias = info.call_to_functional_alias == true;
  if (!to_alias) {
    // TS 24.282 clause 20.4.2 step 5a1 also covers an entry that is found to be an alias without the indication.
    try {
      to_alias = alias_definition(target).has_value();
    } catch (const std::exception &) {
      to_alias = false;
    }
  }
  if (to_alias) {
    // TS 24.282 clause 20.4.2 step 5a1: the users that activated the alias; one is selected and the
    // originator is sent to it with 300 (Multiple Choices).
    const auto users = alias_users(target, user.id);
    if (users.empty()) return reject(403, "145 unable to determine called party", user.id, what);
    mcdata::Info redirect;
    redirect.request_uri = users.front(); // selection is implementation-specific (clause 20.4.2 NOTE 2)
    SipResponse response;
    response.status_code = 300;
    response.reason = "Multiple Choices";
    response.content_type = mcdata::info_mime;
    response.body = mcdata::info_xml(redirect);
    // Step 5a1 B) I): a Contact with a SIP URI for the MCData session identity.
    response.headers = {{"Contact", "<" + session_identity({}) + ">"}};
    event("mcdata_functional_alias_resolved", {{"user_id", user.id}, {"alias", target}, {"selected", users.front()}});
    return response;
  }

  return std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: the address the tunnel sockets use: the media address when the server has
// one of its own, else its SIP address.
std::string DataServer::tunnel_address() const {
  const auto media = cfg_.at("mcdata").value("media", Json::object()).value("advertise", std::string{});
  return resolve_ipv4(media.empty() ? cfg_.at("sip").at("advertise").get<std::string>() : media);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 20.4.1: the called user is invited.
void DataServer::ipcon_invite_target(const std::shared_ptr<IpconSession> &tunnel, const mcdata::Info &info,
                                     const std::string &sip, const std::string &originator_sip) {
  if (!ipcons_.contains(tunnel->origin_dialog)) return; // the originator gave up
  const std::string icsi = mcdata::ipconn_icsi;
  std::vector<SipHeader> headers{
      {"Accept-Contact", "*;+g.3gpp.mcdata.ipconn;require;explicit"}, // TS 24.282 clause 20.4.1 step 4
      {"Accept-Contact", "*;+g.3gpp.icsi-ref=\"" + url_encode(icsi) + "\";require;explicit"}, // step 5
      {"Referred-By", "<" + originator_sip + ">"},                                            // step 6
      {"Contact", focus_contact(tunnel->identity, "ipconn")},                                 // step 7
      {"P-Asserted-Service", icsi}};                                                          // step 11
  const std::vector<BodyPart> clear{{mcdata::info_mime, mcdata::info_xml(info)}};
  const auto dialog = sip_.invite_sdp(
      sip, tunnel->target_sdp, seal_for(sip, clear),
      [this, tunnel](const SipResponse &response) {
        if (response.status_code >= 200)
          pending_.push_back([this, tunnel, response] { ipcon_target_answered(tunnel, response); });
      },
      headers);
  tunnel->target_dialog = dialog;
  ipcons_[dialog] = tunnel;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 20.4.2: the called client's answer completes the originator's INVITE.
void DataServer::ipcon_target_answered(const std::shared_ptr<IpconSession> &tunnel, const SipResponse &response) {
  if (response.status_code < 200 || !ipcons_.contains(tunnel->origin_dialog)) return;
  SipResponse answer;
  if (response.status_code >= 300) {
    // TS 24.282 clauses 20.3.2 and 20.3.1: the response and its warnings go back to the originator.
    answer.status_code = response.status_code;
    answer.reason = response.reason;
    if (const auto warning = get_header(response.headers, "Warning"); !warning.empty())
      answer.headers.push_back({"Warning", std::string(warning)});
    event("mcdata_ipconn_failed", {{"user_id", tunnel->originator},
                                   {"target", tunnel->target},
                                   {"status", response.status_code},
                                   {"warning", std::string(get_header(response.headers, "Warning"))}});
    ipcons_.erase(tunnel->origin_dialog);
    ipcons_.erase(tunnel->target_dialog);
    sip_.answer(tunnel->origin_dialog, answer);
    return;
  }
  try {
    for (const auto &part : response.parts)
      if (part.content_type.starts_with("application/sdp")) tunnel->target_peer = ipconn::parse_tunnel_sdp(part.body);
    if (!tunnel->target_peer.port) throw std::runtime_error("no tunnel in the answer");
  } catch (const std::exception &error) {
    event("mcdata_ipconn_sdp_rejected", {{"user_id", tunnel->target}, {"reason", error.what()}});
    ipcons_.erase(tunnel->origin_dialog);
    ipcons_.erase(tunnel->target_dialog);
    sip_.bye(tunnel->target_dialog);
    answer.status_code = 488;
    sip_.answer(tunnel->origin_dialog, answer);
    return;
  }
  tunnel->established = true;
  tunnel->established_at = monotonic_ms();
  tunnel->deadline = monotonic_ms() + ipconn_config().value("idle_ms", 300000u);
  answer.status_code = 200;
  answer.local_sdp = tunnel->origin_sdp;

  // TS 24.282 clause 20.3.1: a <mcdata-info> body of the called client's answer (its
  // <application-data>) is copied to the originator.
  for (const auto &part : response.parts)
    if (part.content_type == mcdata::info_mime) answer.parts.push_back(part);
  answer.headers = {{"P-Asserted-Service", mcdata::ipconn_icsi}};
  session_contact(answer, tunnel->identity, "ipconn"); // TS 24.282 clause 6.3.7.1.23 steps 5 and 6
  sip_.answer(tunnel->origin_dialog, answer);
  event("mcdata_ipconn_established",
        {{"user_id", tunnel->originator},
         {"target", tunnel->target},
         {"origin_peer", tunnel->origin_peer.address + ":" + std::to_string(tunnel->origin_peer.port)},
         {"target_peer", tunnel->target_peer.address + ":" + std::to_string(tunnel->target_peer.port)}});
}

//------------------------------------------------------------------------------
// TS 24.582 clause 13.3: the controlling MCData function relays the UDP traffic of the tunnel between its two
// endpoints; a datagram from an unexpected source or not GRE-in-UDP (clause 13.4) is dropped.
void DataServer::ipcon_relay(IpconSession &tunnel, UdpSocket &from, const ipconn::TunnelMedia &sender, UdpSocket &to,
                             const ipconn::TunnelMedia &receiver, std::uint64_t &relayed) {
  for (unsigned budget = 0; budget < 256; ++budget) {
    auto datagram = from.receive();
    if (!datagram) return;
    const auto source_port = sender.source_port.value_or(sender.port);
    bool valid = UdpSocket::matches(datagram->source, sender.address, source_port);
    if (valid) {
      try {
        (void)ipconn::decapsulate(datagram->bytes);
      } catch (const std::exception &) {
        valid = false;
      }
    }
    if (!valid) {
      ++tunnel.dropped;
      count("ipconn_dropped");
      continue;
    }
    to.send(datagram->bytes, receiver.address, receiver.port);
    ++relayed;
    tunnel.bytes += datagram->bytes.size();
    tunnel.deadline = monotonic_ms() + ipconn_config().value("idle_ms", 300000u);
    count("ipconn_packets");
    counters_.add("ipconn_bytes", datagram->bytes.size());
  }
}

//------------------------------------------------------------------------------
// Helper: either client ending its leg ends the tunnel and the other leg.
void DataServer::ipcon_released(const std::string &dialog) {
  const auto found = ipcons_.find(dialog);
  if (found == ipcons_.end()) return;
  const auto tunnel = found->second;
  // A called leg that fails before it is established is answered by its final
  // response (ipcon_target_answered), which carries the status to pass back.
  if (!tunnel->established && dialog == tunnel->target_dialog) return;
  ipcons_.erase(tunnel->origin_dialog);
  ipcons_.erase(tunnel->target_dialog);
  const auto other = dialog == tunnel->origin_dialog ? tunnel->target_dialog : tunnel->origin_dialog;
  if (!other.empty()) sip_.bye(other); // ends the other leg, or cancels it while it is being set up
  event("mcdata_ipconn_released", {{"user_id", tunnel->originator},
                                   {"target", tunnel->target},
                                   {"reason", dialog == tunnel->origin_dialog ? "originator" : "target"},
                                   {"to_target", tunnel->to_target},
                                   {"to_origin", tunnel->to_origin}});
}

} // namespace mcx
