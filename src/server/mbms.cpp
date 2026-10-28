//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The participating function's MBMS usage procedures (TS 24.379 clause 14.2, TS 24.281 clause 16.3) over
// pre-activated MBMS bearers ("mbms" block, include/mcx/multicast.hpp): the MBMS bearer announcement sent to each
// served user after service authorisation (TS 24.379 clause 14.2.2.2), the general purpose MBMS subchannel of each
// bearer, the Bearer Announcement message sent over it (TS 24.380 clause 4.1.3.7, clause 8.4.7), and the listening
// status reports on the general purpose subchannel (TS 24.379 clause 14.2.3 step 1 a ii and step 1 b ii). Each
// bearer is an IPv4 host group per subchannel on the lab network: the BM-SC and the radio are emulated, and the
// bearers are configured as activated (TS 24.380 clause 4.1.3.1).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19),
// TS 24.581 V19.2.0 (Rel-19), RFC 3428, RFC 4566, RFC 5761.

#include "mcx/mbms.hpp"

#include "server.hpp"

#include <algorithm>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the service whose MBMS procedures this server follows.
MbmsService McServer::mbms_service() const {
  return svc_.service == Service::mcvideo ? MbmsService::Mcvideo : MbmsService::Mcptt;
}

//------------------------------------------------------------------------------
// Helper: reads the "mbms" block of the service's configuration and opens the socket the general purpose and MBMS
// subchannels are sent from, on the media address. A participating function in the "both" role only: the split
// servers keep unicast.
void McServer::mbms_setup() {
  const auto &service = cfg_.at(svc_.name);
  if (service.contains("multicast"))
    throw std::runtime_error(std::string(svc_.name) + ".multicast is replaced by the MBMS procedures (the mbms block)");
  if (!service.contains("mbms")) return;
  if (role_ != "both") throw std::runtime_error("mbms: needs role both");
  mbms_ = mbms_config(service.at("mbms"));
  mbms_socket_ = std::make_unique<UdpSocket>(cfg_.at("media").at("bind").get<std::string>(), 0);
  mbms_socket_->multicast_sending(mbms_->interface, mbms_->ttl);
  mbms_ssrc_ = random_ssrc();
  status_["mbms_bearers"] = mbms_->bearers.size();
  status_["mbms_announced"] = Json::array();
  status_["mbms_general_purpose"] = Json::array();
  status_["mbms_bearer_announcements"] = 0;
  status_["mbms_conversations"] = Json::array();
  status_["mbms_map_sent"] = 0;
  status_["mbms_unmap_sent"] = 0;
  status_["mbms_control_sent"] = 0;
  status_["multicast_forwarded"] = 0;
  status_["multicast_listening"] = Json::array();
  // TS 24.380 table 11.1.4-2: T15, T16 and T17 and counter C17 (table 11.2-1), here in the mbms block rather than
  // the <fc-timers-counters> of the service configuration (TS 24.484).
  const auto &block = service.at("mbms");
  mbms_timers_.t15 = block.value("t15_ms", mbms_timers_.t15);
  mbms_timers_.t16 = block.value("t16_ms", mbms_timers_.t16);
  mbms_timers_.t17 = block.value("t17_ms", mbms_timers_.t17);
  mbms_timers_.c17 = block.value("c17", mbms_timers_.c17);
  if (!mbms_timers_.t15 || !mbms_timers_.t16 || !mbms_timers_.t17 || !mbms_timers_.c17)
    throw std::runtime_error("mbms: T15, T16, T17 and C17 must be positive");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.2.2.2 step 5 (TS 24.281 clause 16.3.2.2 step 5): the SDP of the announcement. The session's
// c-line is the unspecified address; one media line (port 9, RFC 5761 multiplexing) is the MBMS subchannel for
// media and media control, whose address and port a Map Group To Bearer message gives (step 5 b, NOTE 4); then one
// "m=application" line per bearer, with the host group and port of its general purpose MBMS subchannel (step 5 d).
// For MCVideo an "m=video" line comes first and the "m=audio" line is the separate audio of the subchannel (TS 24.581
// clause 9.3.3.3). With an MSCCK each general purpose line has the "a=key-mgmt" attribute (step 5 d, RFC 4567) with
// the MIKEY-SAKKE I_MESSAGE of the MSCCK to the user (the same key on every bearer).
std::string McServer::mbms_announcement_sdp(const std::string &key_mgmt) const {
  const bool video = mbms_service() == MbmsService::Mcvideo;
  const unsigned pt = mbms_->payload_type;
  std::string sdp = "v=0\r\no=- " + std::to_string(mbms_ssrc_) +
                    " 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n"
                    "t=0 0\r\n";
  if (video) {
    const unsigned vpt = mbms_->video_payload_type;
    sdp += "m=video 9 RTP/AVP " + std::to_string(vpt) + "\r\na=rtpmap:" + std::to_string(vpt) +
           " H264/90000\r\na=fmtp:" + std::to_string(vpt) +
           " profile-level-id=42e01f;packetization-mode=1\r\na=rtcp-mux\r\na=rtcp:9\r\n";
  }
  sdp += "m=audio 9 RTP/AVP " + std::to_string(pt) + "\r\na=rtpmap:" + std::to_string(pt) +
         " AMR-WB/16000/1\r\na=fmtp:" + std::to_string(pt) + " octet-align=" + (mbms_->octet_aligned ? "1" : "0") +
         "\r\na=rtcp-mux\r\na=rtcp:9\r\n";
  for (const auto &bearer : mbms_->bearers)
    sdp += "m=application " + std::to_string(bearer.general_purpose.port) + " udp " + (video ? "MCVideo" : "MCPTT") +
           "\r\nc=IN IP4 " + bearer.general_purpose.address + "/" + std::to_string(mbms_->ttl) + "\r\n" +
           (key_mgmt.empty() ? std::string{} : "a=key-mgmt:mikey " + key_mgmt + "\r\n");
  return sdp;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.2.2.2 step 6 items a to f: the <announcement> of a bearer. Its general purpose subchannel is the
// m=application line after the media line, in the bearers' order (<GPMS>, a media line number counted from 1).
std::vector<MbmsAnnouncement> McServer::mbms_announcements() const {
  std::vector<MbmsAnnouncement> out;
  unsigned line = mbms_service() == MbmsService::Mcvideo ? 3 : 2;
  for (const auto &bearer : mbms_->bearers) {
    MbmsAnnouncement announcement;
    announcement.tmgi = bearer.tmgi;
    announcement.qci = bearer.qci;
    announcement.frequency = bearer.frequency;
    announcement.service_areas = bearer.service_areas;
    announcement.gpms = line++;
    announcement.report_suspension = bearer.report_suspension;
    out.push_back(std::move(announcement));
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.2.2.2 (TS 24.281 clause 16.3.2.2): the MBMS bearer announcement to a served user, a SIP
// MESSAGE to the public user identity of its registration (step 2) with the Accept-Contact and P-Asserted-Service
// of the service (steps 3 and 4), the SDP with Content-Disposition "render" (step 5), the MBMS usage information
// with every bearer's <announcement> (step 6), the MBMS public service identity in P-Asserted-Identity (step 7: the
// service's PSI, where the client sends its reports) and the MC service information naming the user (step 8).
void McServer::mbms_announce(const User &user) {
  if (!mbms_ || !mbms_->serves(user.id)) return;
  // Step 5 d i to v: the MSCCK encapsulated to the user's UID, signed by this function's PSI.
  std::string key_mgmt;
  if (mbms_->mscck) {
    if (!mbms_signalling_keys()) return;
    key_mgmt = keys_->wrap_key(user.id, *mbms_mscck_);
  }
  McpttInfo info;
  info.request_uri = user.id;
  MbmsUsageInfo usage;
  usage.announcements = mbms_announcements();
  std::vector<BodyPart> parts{{svc_.info_mime, service_info_xml_(info)},
                              {mbms_usage_type(mbms_service()).mime, mbms_usage_xml(usage, mbms_service())},
                              {"application/sdp", mbms_announcement_sdp(key_mgmt), {}, "render"}};
  const auto boundary = "mcx-" + random_id();
  sip_.request("MESSAGE", user.sip, "multipart/mixed; boundary=" + boundary, multipart_body(parts, boundary),
               user_route(user, {{"P-Asserted-Service", svc_.icsi},
                                 {"P-Asserted-Identity", "<" + session_service_ + ">"},
                                 {"Accept-Contact", feature_accept()}}),
               [this, id = user.id](const SipResponse &response) {
                 if (response.status_code < 200) return;
                 event("mbms_announced", {{"user_id", id}, {"status", response.status_code}});
                 if (response.status_code >= 300) return;
                 mbms_announced_.insert(id);
                 publish_mbms_status();
                 if (mbms_->musik)
                   if (const auto *found = by_id(id)) mbms_musik_download(*found);
               });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 13.1 and TS 33.180 clause 9.2.2 and annex H.3: the MSCCK and the MuSiK of this function, made by
// the key management client on first use (TS 24.379 clause 14.2.2.1 steps 1 to 3), with the SRTCP contexts they key
// (TS 33.180 clauses 9.4.5 and 9.4.6, the MSCCK and the MuSiK as KFC). False without key management.
bool McServer::mbms_signalling_keys() {
  if (!keys_) {
    event("mbms_keys_unavailable", {{"reason", "no key management client"}});
    return false;
  }
  const bool video = mbms_service() == MbmsService::Mcvideo;
  try {
    if (mbms_->mscck && !mbms_mscck_) {
      mbms_mscck_ = keys_->make_signalling_key(5);
      mbms_control_keys_ = std::make_unique<ProtectedCall>(video);
      mbms_control_keys_->set_floor(*mbms_mscck_);
    }
    if (mbms_->musik && !mbms_musik_) {
      mbms_musik_ = keys_->make_signalling_key(6);
      mbms_floor_keys_ = std::make_unique<ProtectedCall>(video);
      mbms_floor_keys_->set_floor(*mbms_musik_);
    }
  } catch (const std::exception &error) {
    event("mbms_keys_unavailable", {{"reason", error.what()}});
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 13.3.2 (step for the general purpose subchannel) and TS 24.379 clause 14.2.2.2 NOTE 6: with an
// MSCCK, an MBMS subchannel control message is sent as SRTCP under it (MKI: the MSCCK-ID), over the general purpose
// subchannel and over the bearer's subchannels. The Bearer Announcement message has no SSRC for an SRTCP context and
// is sent clear (docs/3GPP_CORRECTION_CANDIDATES.md M17).
std::vector<std::uint8_t> McServer::mbms_protect_control(std::vector<std::uint8_t> packet) {
  if (!mbms_control_keys_ || (packet[0] & 0x1f) == static_cast<std::uint8_t>(SubchannelMessageType::Announcement))
    return packet;
  return mbms_control_keys_->protect_floor(packet);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.2.2.5 (TS 24.281 clause 16.3.2.5): the default MuSiK download, a SIP MESSAGE with the MBMS usage
// information (<mbms-defaultMuSiK-download> without groups: every group of the user, step 5 b) and the MIKEY-SAKKE
// I_MESSAGE of the MuSiK to the user in an application/mikey body (step 6). A 200 response makes the download
// successful; a user without it keeps unicast floor control.
void McServer::mbms_musik_download(const User &user) {
  if (!mbms_signalling_keys() || !mbms_musik_) return;
  MbmsUsageInfo usage;
  usage.musik_download = MusikDownload{false, {}};
  const std::vector<BodyPart> parts{{mbms_usage_type(mbms_service()).mime, mbms_usage_xml(usage, mbms_service())},
                                    {"application/mikey", keys_->wrap_key(user.id, *mbms_musik_)}};
  const auto boundary = "mcx-" + random_id();
  sip_.request("MESSAGE", user.sip, "multipart/mixed; boundary=" + boundary, multipart_body(parts, boundary),
               user_route(user, {{"P-Asserted-Service", svc_.icsi},
                                 {"P-Asserted-Identity", "<" + session_service_ + ">"},
                                 {"Accept-Contact", feature_accept()}}),
               [this, id = user.id](const SipResponse &response) {
                 if (response.status_code < 200) return;
                 event("mbms_musik_downloaded", {{"user_id", id}, {"status", response.status_code}});
                 if (response.status_code < 300)
                   mbms_musik_users_.insert(id);
                 else
                   mbms_musik_users_.erase(id);
                 publish_mbms_status();
               });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 4.1.3.7 and clause 8.4.7 (TS 24.581 clause 9.3.7): every bearer_announcement_ms, the Bearer
// Announcement message (the bearer's TMGI, monitoring active) goes over each bearer's general purpose subchannel; a
// client acknowledges it with a listening status report (TS 24.380 clause 10.3.6).
void McServer::mbms_tick(std::uint64_t now) {
  if (!mbms_) return;
  mbms_conversation_tick(now);
  if (mbms_->bearer_announcement_ms == 0 || now < mbms_next_announcement_) return;
  mbms_next_announcement_ = now + mbms_->bearer_announcement_ms;
  for (const auto &bearer : mbms_->bearers) {
    SubchannelMessage announcement;
    announcement.service = mbms_service();
    announcement.type = SubchannelMessageType::Announcement;
    announcement.tmgis = {bearer.tmgi};
    announcement.monitoring = true;
    send_general_purpose(encode_subchannel(announcement), bearer);
    status_["mbms_bearer_announcements"] = status_.value("mbms_bearer_announcements", 0u) + 1;
  }
}

//------------------------------------------------------------------------------
// Helper: a message over a bearer's general purpose subchannel.
void McServer::send_general_purpose(std::span<const std::uint8_t> packet, const MbmsBearerConfig &bearer) {
  const auto bytes = mbms_protect_control({packet.begin(), packet.end()});
  mbms_socket_->send(bytes, bearer.general_purpose.address, bearer.general_purpose.port);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.2.3 step 1 a ii and step 1 b ii: a listening status report on the general purpose subchannel
// of the TMGIs it names; "listening" is taken from a user the bearers are announced to, for announced TMGIs only.
// NOTE 2: "not-listening" on the general purpose subchannel also ends the listening to the MBMS subchannels of its
// sessions. Returns why a report is refused, or empty.
std::string McServer::mbms_general_purpose_status(const User &user, const MbmsListeningStatus &status) {
  if (!mbms_) return "MBMS not configured";
  if (!mbms_->serves(user.id)) return "user not served over MBMS";
  for (const auto &tmgi : status.tmgis)
    if (!mbms_->bearer(tmgi)) return "TMGI " + tmgi + " not announced";
  auto &listened = mbms_general_purpose_[user.id];
  for (const auto &tmgi : status.tmgis) {
    if (status.listening && *status.general_purpose)
      listened.insert(tmgi);
    else
      listened.erase(tmgi);
  }
  if (listened.empty()) {
    mbms_general_purpose_.erase(user.id);
    if (!*status.general_purpose) {
      std::erase_if(multicast_listening_, [&](const auto &entry) { return entry.first == user.id; });
      publish_multicast_listening();
    }
  }
  event("mbms_general_purpose",
        {{"user_id", user.id}, {"listening", status.listening && *status.general_purpose}, {"tmgis", status.tmgis}});
  publish_mbms_status();
  return {};
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 8.4.4 to 8.4.6 (TS 24.581 clauses 9.3.4 to 9.3.6): a subchannel control message of a
// conversation, with this function's SSRC, the group and, for Map Group To Bearer, the TMGI and the MBMS
// subchannel: the media line of the announcement's SDP (the first) and the subchannel's host group and port, floor
// control on the same port (Floor m-line Number 0, RFC 5761 multiplexing).
SubchannelMessage McServer::mbms_message(SubchannelMessageType type, const MbmsConversation &conversation) const {
  SubchannelMessage message;
  message.service = mbms_service();
  message.type = type;
  message.ssrc = mbms_ssrc_;
  message.group = conversation.group;
  if (type == SubchannelMessageType::MapGroup) {
    message.tmgis = {conversation.bearer->tmgi};
    MbmsSubchannel channel;
    channel.media_line = 1;
    channel.address = conversation.channel.address;
    channel.media_port = conversation.channel.port;
    if (mbms_service() == MbmsService::Mcvideo) {
      // TS 24.581 clause 9.3.3.3: the video m-line and port, the separate audio m-line and its port.
      channel.audio_line = 2;
      channel.audio_port = static_cast<std::uint16_t>(conversation.channel.port + 2);
    }
    message.subchannel = channel;
  }
  return message;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 10.2.2.2 (TS 24.581 clause 10.2.2.2): the conversation of a group session uses an MBMS subchannel
// when the floor is granted or media flows and served participants listen to the general purpose subchannel of a
// bearer with a free subchannel (the decision is the function's, NOTE): the bearer with the most such listeners is
// taken, a subchannel of its pool allocated, Map Group To Bearer sent over its general purpose subchannel (step 2)
// and T15 and T16 started (steps 3 and 4). Without a free subchannel the conversation stays on unicast (the
// insufficient capacity case). Private, ad hoc and ambient calls and calls without floor control stay on unicast.
// Returns the conversation's subchannel, or none (also while it is being unmapped).
const MulticastDestination *McServer::mbms_conversation_start(const Session &session) {
  if (!mbms_ || session.private_call || session.adhoc || session.no_media_control || !session.ambient.empty())
    return nullptr;
  if (const auto found = mbms_conversations_.find(session.uri); found != mbms_conversations_.end())
    return found->second.t17 ? nullptr : &found->second.channel;
  const MbmsBearerConfig *chosen = nullptr;
  std::size_t best = 0;
  const auto legs = session_legs(session);
  for (const auto &bearer : mbms_->bearers) {
    const auto listeners = std::ranges::count_if(legs, [&](const auto &leg) {
      const auto found = mbms_general_purpose_.find(leg->user);
      return mbms_->serves(leg->user) && found != mbms_general_purpose_.end() && found->second.contains(bearer.tmgi);
    });
    if (static_cast<std::size_t>(listeners) > best) {
      best = static_cast<std::size_t>(listeners);
      chosen = &bearer;
    }
  }
  if (!chosen) return nullptr;
  const auto free = std::ranges::find_if(chosen->subchannels, [&](const auto &channel) {
    return std::ranges::none_of(mbms_conversations_, [&](const auto &entry) {
      return entry.second.channel.address == channel.address && entry.second.channel.port == channel.port;
    });
  });
  if (free == chosen->subchannels.end()) {
    event("mbms_no_capacity", {{"session_uri", session.uri}, {"tmgi", chosen->tmgi}});
    return nullptr;
  }
  auto &conversation = mbms_conversations_[session.uri];
  conversation.group = session.group;
  conversation.session_uri = session.uri;
  conversation.bearer = chosen;
  conversation.channel = *free;
  const auto now = monotonic_ms();
  conversation.t15 = now + mbms_timers_.t15;
  mbms_map(conversation, now);
  event("mbms_conversation_started", {{"session_uri", session.uri},
                                      {"tmgi", chosen->tmgi},
                                      {"subchannel", free->address + ":" + std::to_string(free->port)}});
  publish_mbms_status();
  return &conversation.channel;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 10.2.3.5 steps 3 and 4: an RTP media packet (or, TS 24.380 clause 10.2.3.2 to 10.2.3.4, a floor
// control message) over the conversation's MBMS subchannel restarts T15.
void McServer::send_subchannel(std::span<const std::uint8_t> packet, const Session &session, bool video) {
  auto &conversation = mbms_conversations_.at(session.uri);
  // An MCVideo subchannel's audio goes to the port two above its video (mbms_message).
  const bool separate_audio = mbms_service() == MbmsService::Mcvideo && !video;
  mbms_socket_->send(packet, conversation.channel.address,
                     static_cast<std::uint16_t>(conversation.channel.port + (separate_audio ? 2 : 0)));
  conversation.t15 = monotonic_ms() + mbms_timers_.t15;
  const char *counter = video ? "multicast_video_forwarded" : "multicast_forwarded";
  status_[counter] = status_.value(counter, 0u) + 1;
}

//------------------------------------------------------------------------------
// TS 24.380 clause 10.2.2.2 step 2 and clause 10.2.3.7: Map Group To Bearer over the bearer's general purpose
// subchannel; T16 (re)started.
void McServer::mbms_map(MbmsConversation &conversation, std::uint64_t now) {
  send_general_purpose(encode_subchannel(mbms_message(SubchannelMessageType::MapGroup, conversation)),
                       *conversation.bearer);
  conversation.t16 = now + mbms_timers_.t16;
  status_["mbms_map_sent"] = status_.value("mbms_map_sent", 0u) + 1;
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 10.2.3.6 step 2, 10.2.3.8 and 10.2.3.9: Unmap Group To Bearer over the conversation's MBMS
// subchannel, T17 (re)started and C17 counted. Map Group To Bearer is no longer repeated once the conversation is
// being unmapped (docs/3GPP_CORRECTION_CANDIDATES.md M12), and its listeners get unicast again at once: their
// "not-listening" reports follow.
void McServer::mbms_unmap(MbmsConversation &conversation, std::uint64_t now) {
  mbms_socket_->send(mbms_protect_control(encode_subchannel(mbms_message(SubchannelMessageType::UnmapGroup, conversation))),
                     conversation.channel.address, conversation.channel.port);
  status_["mbms_unmap_sent"] = status_.value("mbms_unmap_sent", 0u) + 1;
  conversation.t15 = conversation.t16 = 0;
  conversation.t17 = now + mbms_timers_.t17;
  ++conversation.c17;
  std::erase_if(multicast_listening_, [&](const auto &entry) { return entry.second == conversation.session_uri; });
  publish_multicast_listening();
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 10.2.3.6 step 1 b, 10.2.3.9 step 2, 10.2.3.10 and 10.2.3.11 step 3: the state machine instance
// is released (back to 'Start-stop'); its subchannel returns to the pool.
void McServer::mbms_release(const std::string &session_uri, const char *reason) {
  mbms_conversations_.erase(session_uri);
  std::erase_if(multicast_listening_, [&](const auto &entry) { return entry.second == session_uri; });
  publish_multicast_listening();
  event("mbms_conversation_released", {{"session_uri", session_uri}, {"reason", reason}});
  publish_mbms_status();
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 10.2.3.6 to 10.2.3.11: the timers of each conversation, and the release of its group call.
void McServer::mbms_conversation_tick(std::uint64_t now) {
  std::vector<std::pair<std::string, const char *>> released;
  for (auto &[uri, conversation] : mbms_conversations_) {
    const bool current = std::ranges::any_of(sessions_, [&](const auto &entry) { return entry.second->uri == uri; });
    if (!current) {
      // Clause 10.2.3.11: Unmap Group To Bearer once, the timers stopped, the instance released.
      mbms_socket_->send(
          mbms_protect_control(encode_subchannel(mbms_message(SubchannelMessageType::UnmapGroup, conversation))),
          conversation.channel.address, conversation.channel.port);
      status_["mbms_unmap_sent"] = status_.value("mbms_unmap_sent", 0u) + 1;
      released.emplace_back(uri, "group call released");
      continue;
    }
    if (conversation.t16 && now >= conversation.t16) mbms_map(conversation, now);
    if (conversation.t15 && now >= conversation.t15) {
      // Clause 10.2.3.6: without a listener the instance is released; otherwise Unmap Group To Bearer.
      const bool listened =
          std::ranges::any_of(multicast_listening_, [&](const auto &entry) { return entry.second == uri; });
      if (!listened) {
        released.emplace_back(uri, "T15 expired, no listener");
        continue;
      }
      mbms_unmap(conversation, now);
    }
    if (conversation.t17 && now >= conversation.t17) {
      // Clauses 10.2.3.8 and 10.2.3.9: repeated until C17 reaches its upper limit, then released.
      const bool last = conversation.c17 >= mbms_timers_.c17;
      mbms_unmap(conversation, now);
      if (last) released.emplace_back(uri, "T17 expired C17 times");
    }
  }
  for (const auto &[uri, reason] : released) mbms_release(uri, reason);
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 10.2.3.2 and 10.2.3.3 (TS 24.581 clauses 10.2.3.2 and 10.2.3.3): a Floor Idle or Floor Taken
// (Transmission Idle or Media Transmission Notification) destined to a participant listening to the conversation's
// subchannel goes over the subchannel instead of by unicast, once for every listener of one arbitration outcome
// (the same kind within 200 ms is a copy; a later one, such as the floor state told to a late joiner, goes again, as
// clause 4.1.3.3 allows): with this function's SSRC (the Map Group To Bearer header's), the conversation's message
// sequence number and the acknowledgement bit '0'; T15 restarts. The Floor Ack the participating function would send
// towards the controlling function (step 4) is internal to a server in the "both" role. Returns whether it was taken.
bool McServer::mbms_control(Leg &leg, const std::string &kind,
                            const std::function<std::vector<std::uint8_t>(std::uint32_t, std::uint16_t)> &encode) {
  if (!mbms_) return false;
  // TS 24.380 clause 13.3.2: protected floor control goes over the subchannel as SRTCP under the MuSiK, for a user
  // that took the MuSiK download (TS 24.379 clause 14.2.2.5); otherwise it stays unicast.
  const bool protect = floor_protected(leg);
  if (protect && (!mbms_floor_keys_ || !mbms_musik_users_.contains(leg.user))) return false;
  const bool listener = mbms_service() == MbmsService::Mcvideo ? multicast_video_leg(leg) : multicast_leg(leg);
  if (!listener) return false;
  const auto found = mbms_conversations_.find(leg.session->uri);
  if (found == mbms_conversations_.end() || found->second.t17) return false;
  auto &conversation = found->second;
  const auto now = monotonic_ms();
  constexpr std::uint64_t same_outcome_ms = 200;
  if (conversation.last_control == kind && now - conversation.last_control_ms < same_outcome_ms) return true;
  conversation.last_control = kind;
  conversation.last_control_ms = now;
  // RFC 5761: the control messages share the subchannel's media port (Floor m-line Number 0).
  auto bytes = encode(mbms_ssrc_, ++conversation.control_sequence);
  if (protect) bytes = mbms_floor_keys_->protect_floor(bytes);
  mbms_socket_->send(bytes, conversation.channel.address, conversation.channel.port);
  conversation.t15 = now + mbms_timers_.t15;
  status_["mbms_control_sent"] = status_.value("mbms_control_sent", 0u) + 1;
  return true;
}

//------------------------------------------------------------------------------
// Helper: the status shows whom the bearers were announced to, and who listens to which general purpose subchannel.
void McServer::publish_mbms_status() {
  status_["mbms_announced"] = Json(std::vector<std::string>(mbms_announced_.begin(), mbms_announced_.end()));
  auto listening = Json::array();
  for (const auto &[user, tmgis] : mbms_general_purpose_)
    listening.push_back({{"user_id", user}, {"tmgis", std::vector<std::string>(tmgis.begin(), tmgis.end())}});
  status_["mbms_general_purpose"] = std::move(listening);
  status_["mbms_musik_users"] = Json(std::vector<std::string>(mbms_musik_users_.begin(), mbms_musik_users_.end()));
  if (mbms_mscck_) status_["mbms_mscck_id"] = mbms_mscck_->csb_id;
  if (mbms_musik_) status_["mbms_musik_id"] = mbms_musik_->csb_id;
  auto conversations = Json::array();
  for (const auto &[uri, conversation] : mbms_conversations_)
    conversations.push_back({{"session_uri", uri},
                             {"group", conversation.group},
                             {"tmgi", conversation.bearer->tmgi},
                             {"subchannel", conversation.channel.address + ":" + std::to_string(conversation.channel.port)}});
  status_["mbms_conversations"] = std::move(conversations);
}

} // namespace mcx
