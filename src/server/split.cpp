// The split of an MC server into participating and controlling functions within one MC system, over MCPTT-3
// (TS 23.379 clause 7.5.2.4): routes, peer registration, relays.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the configured peer servers.
const PeerMap &McServer::PartsGlue::peer_table() const { return server_.peers_; }

//------------------------------------------------------------------------------
// Helper: the server controlling a group's calls, empty for this server.
std::string McServer::PartsGlue::registration_group_controller(const std::string &group) {
  return server_.group_controller(group);
}

//------------------------------------------------------------------------------
// Helper: <service>.registration_refresh_ms, every minute by default.
std::uint64_t McServer::PartsGlue::registration_refresh_ms() const {
  return server_.cfg_.at(server_.svc_.name).value("registration_refresh_ms", 60000U);
}

//------------------------------------------------------------------------------
// Helper: every user known here.
void McServer::PartsGlue::each_registration_user(const std::function<void(const PeerUser &)> &visit) {
  for (const auto &[sip, user] : server_.users_) visit(peer_user(user));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3: a participating-only server takes no registration; the PIDF must be one and in this
// service's namespace (TS 24.379 clause 9.3.1); RFC 3261 section 20.19: a missing or malformed Expires is a bad
// request.
std::optional<int> McServer::PartsGlue::registration_refusal(const SipMessage &message, Affiliation &affiliation,
                                                             std::uint64_t &expires_s) {
  if (server_.role_ == "participating") return 403;
  (void)asserted_identity(message);
  std::optional<Affiliation> parsed;
  for (const auto &part : message.parts)
    if (part.content_type == "application/pidf+xml") {
      if (parsed) throw std::runtime_error("duplicate PIDF");
      parsed = parse_affiliation(part.body);
    }
  if (parsed && !server_.own_affiliation(*parsed)) return 403;
  const auto expires = parse_expires(get_header(message.headers, "Expires"));
  if (!parsed || !expires) return 400;
  affiliation = *parsed;
  expires_s = *expires;
  return std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: the user with the public user identity.
std::optional<PeerUser> McServer::PartsGlue::registration_user(const std::string &sip) {
  const auto found = server_.users_.find(sip);
  return found == server_.users_.end() ? std::nullopt : std::optional(peer_user(found->second));
}

//------------------------------------------------------------------------------
// Helper: the user with the MC service ID, live or not.
std::optional<PeerUser> McServer::PartsGlue::registration_user_by_id(const std::string &id) {
  const auto *user = server_.by_id(id);
  return user ? std::optional(peer_user(*user)) : std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3: an affiliation to a group controlled here, of a member of the group (or of a regroup
// the peer vouches for).
bool McServer::PartsGlue::registration_group_allowed(const std::string &group, const std::string &id,
                                                     const std::string &peer) {
  return server_.group_controller(group).empty() &&
         (server_.member(server_.group_profile(group), id) || server_.regroup_vouched(group, peer));
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3: a withdrawn user loses its affiliations and functional aliases, and its calls.
void McServer::PartsGlue::withdraw_peer_user(const std::string &sip, const std::string &id) {
  auto &user = server_.users_.at(sip);
  user.expires = 0;
  user.groups.clear();
  server_.deactivate_functional_aliases(id);
  server_.schedule([this, id] { server_.disconnect_user(id); });
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3: the user's entry, served by the peer; a user moving from another peer loses its calls.
// Its groups change with its affiliations (peer_user_changed).
void McServer::PartsGlue::update_peer_user(const std::string &sip, const Affiliation &affiliation,
                                           const std::string &peer, const std::set<std::string> & /*groups*/,
                                           std::uint64_t expires_s) {
  auto &user = server_.users_[sip];
  if (!user.peer.empty() && user.peer != peer)
    server_.schedule([this, id = affiliation.user_id] { server_.disconnect_user(id); });
  user.id = affiliation.user_id;
  user.client = affiliation.client_id;
  user.sip = sip;
  user.peer = peer;
  user.expires = std::time(nullptr) + static_cast<std::time_t>(expires_s);
  user.subscription = "peer:" + peer;
  user.subscription_expires = user.expires;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.3: the user's affiliations take effect (apply_affiliation).
void McServer::PartsGlue::peer_user_changed(const std::string &sip, const std::optional<PeerUser> & /*previous*/,
                                            std::set<std::string> groups) {
  server_.apply_affiliation(server_.users_.at(sip), std::move(groups));
}

//------------------------------------------------------------------------------
// Helper: the server controlling a group's calls, or empty for this server.
std::string McServer::group_controller(const std::string &group) const {
  // A regroup is controlled where it was created (TS 24.379 clause 16).
  if (const auto regroup = regroups_.find(group); regroup != regroups_.end()) return regroup->second.controller;
  const auto groups = cfg_.at(svc_.name).value("group_controllers", Json::object());
  if (groups.contains(group)) return groups.at(group).get<std::string>();
  return role_ == "participating" ? controller_ : std::string{};
}

//------------------------------------------------------------------------------
// Helper: the server owning the functional aliases this server's users activate:
// mcptt.functional_alias_controller, else as for private calls.
std::string McServer::alias_controller() const {
  const auto owner = cfg_.at(svc_.name).value("functional_alias_controller", std::string{});
  return owner.empty() ? call_controller() : owner;
}

//------------------------------------------------------------------------------
// Helper: a PUBLISH passed to its owning server; the final response is relayed back.
SipResponse McServer::relay_publish(const SipMessage &message, const User &user, const std::string &owner) {
  std::vector<SipHeader> headers =
      route_to(owner, {{"Event", "presence"}, {"P-Asserted-Identity", "<" + user.sip + ">"}});
  for (const auto *name : {"Expires", "SIP-If-Match"})
    if (const auto value = get_header(message.headers, name); !value.empty())
      headers.push_back({name, std::string(value)});
  sip_.publish(peers_.at(owner).service_uri, message.content_type, message.body, headers,
               [this, id = message.transaction_id](const SipResponse &answer) {
                 if (answer.status_code < 200) return;
                 SipResponse reply;
                 reply.status_code = answer.status_code;
                 reply.reason = answer.reason;
                 for (const auto *name : {"Expires", "SIP-ETag", "Min-Expires"})
                   if (const auto value = get_header(answer.headers, name); !value.empty())
                     reply.headers.push_back({name, std::string(value)});
                 schedule([this, id, reply] { sip_.respond(id, reply); });
               });
  SipResponse response;
  response.deferred = true;
  return response;
}

//------------------------------------------------------------------------------
// Helper: the URI of a name-addr header value (inside '<' and '>'), else the value up to its first ';'.
std::string McServer::header_uri(std::string_view value) {
  const auto start = value.find('<'), end = value.find('>');
  if (start == std::string_view::npos || end == std::string_view::npos || end < start)
    return std::string(value.substr(0, value.find(';')));
  return std::string(value.substr(start + 1, end - start - 1));
}

//------------------------------------------------------------------------------
// Helper: the first free offset from media.rtp_port (in steps of two) among the legs and relays.
unsigned McServer::media_offset() const {
  std::set<unsigned> used;
  for (const auto &[dialog, leg] : legs_) used.insert(leg->local.audio_port);
  for (const auto &[dialog, relay] : relays_) used.insert(relay->local.audio_port);
  const unsigned base = cfg_.at("media").at("rtp_port").get<unsigned>();
  for (unsigned offset = 0; offset < 2 * media_slots; offset += 2)
    if (!used.contains(base + offset)) return offset;
  throw CapacityReached();
}

//------------------------------------------------------------------------------
// Helper: the Retry-After (seconds) of the 500 answered when no media ports are free.
unsigned McServer::capacity_retry_after() const { return cfg_.at("media").value("capacity_retry_after_s", 5u); }

//------------------------------------------------------------------------------
// Helper: a relay for a user's call through a peer, with its own audio, floor (and video) ports.
std::shared_ptr<McServer::Relay> McServer::make_relay(const std::string &user, const std::string &peer) {
  auto relay = std::make_shared<Relay>();
  relay->user = user;
  relay->peer = peer;
  const auto offset = media_offset();
  relay->local = local_media(cfg_, offset);
  const auto address = cfg_.at("media").at("bind").get<std::string>();
  relay->audio = std::make_unique<UdpSocket>(address, relay->local.audio_port);
  relay->floor = std::make_unique<UdpSocket>(address, relay->local.floor_port);
  // The service's media besides speech and floor control, with the same offset as the audio, as for a leg.
  relay->video = service_media(relay->local, offset, address);
  return relay;
}

//------------------------------------------------------------------------------
// Helper: a media description with this server's addresses and ports in place of the other side's.
MediaDescription McServer::mirror(MediaDescription media, const MediaDescription &local) {
  media.address = media.floor_address = local.address;
  media.audio_port = local.audio_port;
  media.rtcp_port = local.rtcp_port;
  media.floor_port = local.floor_port;
  if (media.video && local.video) {
    media.video->port = local.video->port;
    media.video->rtcp_port = local.video->rtcp_port;
  }
  return media;
}

//------------------------------------------------------------------------------
// Helper: the SDP of a message's body parts, if it has one.
std::optional<MediaDescription> McServer::sdp_of(const std::vector<BodyPart> &parts) {
  for (const auto &part : parts)
    if (part.content_type.starts_with("application/sdp")) return parse_sdp(part.body);
  return std::nullopt;
}

//------------------------------------------------------------------------------
// Helper: the body parts other than the SDP.
std::vector<BodyPart> McServer::application_parts(const std::vector<BodyPart> &parts) {
  std::vector<BodyPart> result;
  for (const auto &part : parts)
    if (!part.content_type.starts_with("application/sdp")) result.push_back(part);
  return result;
}

//------------------------------------------------------------------------------
// Helper: the headers a relay passes on. The SIP engine adds its own Contact, route and
// session timer headers.
std::vector<SipHeader> McServer::relayed_headers(const std::vector<SipHeader> &headers) {
  static const std::set<std::string> names{
      "accept-contact", "answer-mode", "priv-answer-mode",   "resource-priority", "alert-info",
      "feature-caps",   "warning",     "p-asserted-service", "info-package",      "content-disposition"};
  std::vector<SipHeader> result;
  for (const auto &header : headers) {
    auto name = header.name;
    for (auto &character : name) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    if (names.contains(name)) result.push_back(header);
  }
  return result;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 4.5: the participating function allocates its own MCPTT session identity for one received
// from the controlling function and keeps the mapping (the most recent 1024).
std::string McServer::session_alias(const std::string &peer, const std::string &remote) {
  for (const auto &[alias, target] : session_aliases_)
    if (target.peer == peer && target.remote == remote) return alias;
  // Keep the controlling function's session identifier, so that within one
  // domain the alias is the controlling function's session URI itself.
  const auto marker = remote.find(";mcptt-session=");
  auto alias =
      session_service_ + (marker == std::string::npos ? ";mcptt-session=" + random_id() : remote.substr(marker));
  if (session_aliases_.contains(alias)) alias = session_service_ + ";mcptt-session=" + random_id();
  session_aliases_[alias] = {peer, remote};
  alias_order_.push_back(alias);
  // Beyond the limit the oldest alias no call uses goes; one still in use stays (its call needs it), and so does
  // the new one (last).
  for (auto oldest = alias_order_.begin();
       alias_order_.size() > max_session_aliases && std::next(oldest) != alias_order_.end();)
    if (session_alias_in_use(*oldest))
      ++oldest;
    else {
      session_aliases_.erase(*oldest);
      oldest = alias_order_.erase(oldest);
    }
  return alias;
}

//------------------------------------------------------------------------------
// Helper: whether a relayed call or a relayed conference subscription uses the session alias.
bool McServer::session_alias_in_use(const std::string &alias) const {
  return std::any_of(relays_.begin(), relays_.end(),
                     [&](const auto &entry) { return !entry.second->ended && entry.second->alias == alias; }) ||
         std::any_of(conference_relays_.begin(), conference_relays_.end(),
                     [&](const auto &entry) { return entry.second->alias == alias; });
}

//------------------------------------------------------------------------------
// Helper: a relay is found by the dialog on either side.
void McServer::add_relay(const std::shared_ptr<Relay> &relay) {
  relays_[relay->client_dialog] = relay;
  relays_[relay->peer_dialog] = relay;
}

} // namespace mcx
