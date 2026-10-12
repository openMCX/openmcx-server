//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Video media of the MCVideo server: the H.264 video ports of a leg or relay, the video part of a group call's SDP
// answer, and the relay of the transmitting participant's video to the other participants (TS 24.581 clause 6.3)
// or to a recording (members of McvideoServer).
//
// Specifications: TS 24.581 V19.2.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 23.281 V19.10.0 (Rel-19).

#include "mcvideo_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.281 clause 6.2.1: an MCVideo leg or relay has audio, H.264 video and the transmission control channel (in
// place of floor control, unless the call has no media plane control, TS 24.281 clause 10.2.3); its video is at
// media.video_port with the same offset as the audio. Returns the video socket.
std::unique_ptr<UdpSocket> McvideoServer::service_media(MediaDescription &local, unsigned offset,
                                                        const std::string &address) {
  if (local.control != MediaControl::none) local.control = MediaControl::transmission;
  VideoMedia video;
  video.port = static_cast<std::uint16_t>(cfg_.at("media").at("video_port").get<unsigned>() + offset);
  video.rtcp_port = static_cast<std::uint16_t>(video.port + 1);
  local.video = video;
  return std::make_unique<UdpSocket>(address, video.port);
}

//------------------------------------------------------------------------------
// TS 24.581 clause 14.3.5: the answer accepts the originator's implicit Transmission Request, which is arbitrated
// once its leg is active (TS 24.281 clause 6.4); the video takes the offer's payload type.
void McvideoServer::answer_service_media(Leg &leg, const MediaDescription &remote, bool creating) {
  leg.local.implicit_request = creating && remote.implicit_request;
  if (leg.local.video && remote.video) leg.local.video->payload_type = remote.video->payload_type;
}

//------------------------------------------------------------------------------
// TS 24.581 clause 6.3.4.4.5: the video packets that arrived on a leg's video port, up to 128 per run loop; a
// rejected packet is counted and reported.
void McvideoServer::service_media_packets(Leg &leg) {
  for (int index = 0; leg.video && index < 128; index++) {
    auto datagram = leg.video->receive();
    if (!datagram) break;
    try {
      video_packet(leg, *datagram);
    } catch (const std::exception &error) {
      status_["media_rejected_packets"] = status_.value("media_rejected_packets", 0ULL) + 1;
      event("media_rejected", {{"reason", error.what()}});
    }
  }
}

//------------------------------------------------------------------------------
// TS 24.581 clause 6.3.4.4.5: RTP media from the permitted participant is forwarded by the media
// distribution function (TS 23.281 clause 6.2.2.3.3): the granted user's H.264 video goes to every
// other participant unchanged, with the SSRC the Transmission Granted assigned (TS 24.581 clause 9.2.5).
void McvideoServer::video_packet(Leg &leg, const Datagram &datagram) {
  const auto session = leg.session;
  const bool open = session->no_media_control;
  if (!eligible(leg) || !leg.remote->video ||
      !UdpSocket::matches(datagram.source, leg.remote->address, leg.remote->video->port)) {
    status_["media_dropped"] = status_.value("media_dropped", 0u) + 1;
    return;
  }

  // TS 24.581 clauses 6.3.5.3.8 and 6.3.5.4.6: video from a participant without permission is not forwarded.
  if (!open && session->arbitrator->owner() != leg.user) {
    status_["media_dropped"] = status_.value("media_dropped", 0u) + 1;
    if (datagram.bytes.size() > 12) unpermitted_media(leg); // RTP media with payload
    return;
  }
  auto packet = decode_rtp(datagram.bytes);

  // Under transmission control the granted SSRC; without it, the one the party offered.
  const auto expected = open ? leg.remote->video->ssrc : leg.video_ssrc;
  if (packet.ssrc != expected || packet.payload_type != leg.remote->video->payload_type)
    throw std::runtime_error("video RTP negotiation mismatch");
  session->last_media = monotonic_ms();
  if (!open) session->arbitrator->media_received(leg.user, session->last_media);
  if (leg.local.protected_media) {
    // TS 24.281 clause 4.7.1: SRTP under the GMK or PCK, which the server does not hold, so
    // the packet is relayed unchanged to receivers with the same protected profile.
    // The server neither records nor rewrites it (pull and push stay clear).
    if (session->recording) throw std::runtime_error("protected video cannot be recorded");
    // RTP header, AES-GCM tag and at least the PCK's 4-byte MKI (a GMK adds the ROC and
    // GUK-ID), with a payload byte: small H.264 units such as the parameter sets are short.
    if (datagram.bytes.size() < 12 + 16 + 4 + 1) throw std::runtime_error("truncated protected media");
    for (auto &[id, dst] : legs_) {
      if (dst.get() == &leg || dst->session != session || !eligible(*dst) || !dst->video || !dst->remote->video ||
          !dst->receiving)
        continue;
      if (!dst->local.protected_media || dst->remote->video->payload_type != leg.remote->video->payload_type)
        throw std::runtime_error("protected video profile mismatch");
      dst->video->send(datagram.bytes, dst->remote->address, dst->remote->video->port);
      status_["video_forwarded"] = status_.value("video_forwarded", 0u) + 1;
    }
    return;
  }
  if (session->recording) {
    // TS 24.281 clause 13.2.3.2.3 step 5: the pushed video is saved rather than distributed.
    if (!session->recording_start) session->recording_start = session->last_media;
    write_record(*session->recording, session->last_media - session->recording_start, packet);
    ++session->recorded;
    status_["video_recorded"] = status_.value("video_recorded", 0u) + 1;
    return;
  }
  const auto payload = packet.payload;
  for (auto &[id, dst] : legs_) {
    if (dst.get() == &leg || dst->session != session || !eligible(*dst) || !dst->video || !dst->remote->video ||
        !dst->receiving)
      continue;
    packet.payload_type = dst->remote->video->payload_type;
    packet.payload = relay_payload(payload, RtpCodec::h264, false, false);
    dst->video->send(encode_rtp(packet), dst->remote->address, dst->remote->video->port);
    status_["video_forwarded"] = status_.value("video_forwarded", 0u) + 1;
  }
}

} // namespace mcx
