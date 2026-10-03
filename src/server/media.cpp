// Media relay of audio (TS 24.380 clause 6.3, floor control; TS 24.581 clause 6.3, transmission control). The
// MCVideo server relays the video (src/mcvideo/video_media.cpp).
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19).

#include "server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.380 clauses 6.3.4.4.5 and 6.3.5.5.6: RTP media from the floor participant in 'U: permitted' is
// forwarded to the other participants; media from any other participant is dropped (clause 6.3.5.4.6).
void McServer::audio_packet(Leg &leg, const Datagram &datagram) {
  const auto session = leg.session;
  // Without floor control both parties speak at once (TS 24.379 clause 11.1.2).
  const bool open = session->no_media_control;
  if (!eligible(leg) || (!open && session->arbitrator->owner() != leg.user) ||
      !UdpSocket::matches(datagram.source, leg.remote->address, leg.remote->audio_port)) {
    status_["media_dropped"] = status_.value("media_dropped", 0u) + 1;
    return;
  }
  auto packet = decode_rtp(datagram.bytes);
  // Under floor control the SSRC of the Floor Granted; without it, the one the
  // party's SDP announced, if it announced one.
  const bool ssrc_ok =
      open ? !leg.remote->audio_ssrc || packet.ssrc == leg.remote->audio_ssrc : packet.ssrc == leg.audio_ssrc;
  if (!ssrc_ok || packet.payload_type != leg.remote->payload_type) throw std::runtime_error("RTP negotiation mismatch");
  session->last_media = monotonic_ms();
  if (!open) session->arbitrator->media_received(leg.user, session->last_media);
  if (leg.floor_retries) leg.floor_retries->cancel(FloorType::Granted);
  if (leg.local.protected_media) {
    if (datagram.bytes.size() < 40) throw std::runtime_error("truncated protected media");
    for (auto &[id, dst] : legs_) {
      if (dst.get() == &leg || dst->session != session || !eligible(*dst)) continue;
      if (!dst->local.protected_media || dst->remote->payload_type != leg.remote->payload_type ||
          dst->remote->octet_aligned != leg.remote->octet_aligned)
        throw std::runtime_error("protected media profile mismatch");
      dst->audio->send(datagram.bytes, dst->remote->address, dst->remote->audio_port);
      status_["media_forwarded"] = status_.value("media_forwarded", 0u) + 1;
    }
    return;
  }
  const auto payload = packet.payload;
  (void)unpack_amr_wb(payload, leg.remote->octet_aligned); // malformed speech is refused even with no receiver
  for (auto &[id, dst] : legs_) {
    if (dst.get() == &leg || dst->session != session || !eligible(*dst)) continue;
    packet.payload_type = dst->remote->payload_type;
    packet.payload = relay_payload(payload, RtpCodec::amr_wb, leg.remote->octet_aligned, dst->remote->octet_aligned);
    dst->audio->send(encode_rtp(packet), dst->remote->address, dst->remote->audio_port);
    status_["media_forwarded"] = status_.value("media_forwarded", 0u) + 1;
  }
}

} // namespace mcx
