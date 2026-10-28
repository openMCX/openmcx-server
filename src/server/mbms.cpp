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
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.2.2.2 step 5 (TS 24.281 clause 16.3.2.2 step 5): the SDP of the announcement. The session's
// c-line is the unspecified address; one media line (port 9, RFC 5761 multiplexing) is the MBMS subchannel for
// media and media control, whose address and port a Map Group To Bearer message gives (step 5 b, NOTE 4); then one
// "m=application" line per bearer, with the host group and port of its general purpose MBMS subchannel (step 5 d).
// For MCVideo the media line is "m=video" (TS 24.581 clause 9.3.3.3: the audio is combined with the video).
std::string McServer::mbms_announcement_sdp() const {
  const bool video = mbms_service() == MbmsService::Mcvideo;
  const unsigned pt = mbms_->payload_type;
  std::string sdp = "v=0\r\no=- " + std::to_string(mbms_ssrc_) +
                    " 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n"
                    "t=0 0\r\n";
  if (video)
    sdp += "m=video 9 RTP/AVP " + std::to_string(pt) + "\r\na=rtpmap:" + std::to_string(pt) +
           " H264/90000\r\na=fmtp:" + std::to_string(pt) + " profile-level-id=42e01f;packetization-mode=1\r\n";
  else
    sdp += "m=audio 9 RTP/AVP " + std::to_string(pt) + "\r\na=rtpmap:" + std::to_string(pt) +
           " AMR-WB/16000/1\r\na=fmtp:" + std::to_string(pt) + " octet-align=" + (mbms_->octet_aligned ? "1" : "0") +
           "\r\n";
  sdp += "a=rtcp-mux\r\na=rtcp:9\r\n";
  for (const auto &bearer : mbms_->bearers)
    sdp += "m=application " + std::to_string(bearer.general_purpose.port) + " udp " + (video ? "MCVideo" : "MCPTT") +
           "\r\nc=IN IP4 " + bearer.general_purpose.address + "/" + std::to_string(mbms_->ttl) + "\r\n";
  return sdp;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.2.2.2 step 6 items a to f: the <announcement> of a bearer. Its general purpose subchannel is the
// m=application line after the media line, in the bearers' order (<GPMS>, a media line number counted from 1).
std::vector<MbmsAnnouncement> McServer::mbms_announcements() const {
  std::vector<MbmsAnnouncement> out;
  unsigned line = 2;
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
  McpttInfo info;
  info.request_uri = user.id;
  MbmsUsageInfo usage;
  usage.announcements = mbms_announcements();
  std::vector<BodyPart> parts{{svc_.info_mime, service_info_xml_(info)},
                              {mbms_usage_type(mbms_service()).mime, mbms_usage_xml(usage, mbms_service())},
                              {"application/sdp", mbms_announcement_sdp(), {}, "render"}};
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
               });
}

//------------------------------------------------------------------------------
// TS 24.380 clause 4.1.3.7 and clause 8.4.7 (TS 24.581 clause 9.3.7): every bearer_announcement_ms, the Bearer
// Announcement message (the bearer's TMGI, monitoring active) goes over each bearer's general purpose subchannel; a
// client acknowledges it with a listening status report (TS 24.380 clause 10.3.6).
void McServer::mbms_tick(std::uint64_t now) {
  if (!mbms_ || mbms_->bearer_announcement_ms == 0 || now < mbms_next_announcement_) return;
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
  mbms_socket_->send(packet, bearer.general_purpose.address, bearer.general_purpose.port);
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
    if (!*status.general_purpose)
      std::erase_if(multicast_listening_, [&](const auto &entry) { return entry.first == user.id; });
  }
  event("mbms_general_purpose",
        {{"user_id", user.id}, {"listening", status.listening && *status.general_purpose}, {"tmgis", status.tmgis}});
  publish_mbms_status();
  return {};
}

//------------------------------------------------------------------------------
// Helper: the status shows whom the bearers were announced to, and who listens to which general purpose subchannel.
void McServer::publish_mbms_status() {
  status_["mbms_announced"] = Json(std::vector<std::string>(mbms_announced_.begin(), mbms_announced_.end()));
  auto listening = Json::array();
  for (const auto &[user, tmgis] : mbms_general_purpose_)
    listening.push_back({{"user_id", user}, {"tmgis", std::vector<std::string>(tmgis.begin(), tmgis.end())}});
  status_["mbms_general_purpose"] = std::move(listening);
}

} // namespace mcx
