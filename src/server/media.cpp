//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Media relay of audio (TS 24.380 clause 6.3, floor control; TS 24.581 clause 6.3, transmission control), with one
// copy over the MBMS subchannel of the conversation for the participants listening to it (TS 24.380 clause
// 10.2.3.5, src/server/mbms.cpp). The MCVideo server relays the video (src/mcvideo/video_media.cpp).
//
// Specifications: TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19).

#include "server.hpp"

#include <utility>

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.380 clauses 6.3.4.4.5 and 6.3.5.5.6: RTP media from the floor participant in 'U: permitted' is
// forwarded to the other participants; media from any other participant is dropped and revoked (clauses 6.3.5.3.8
// and 6.3.5.4.6).
void McServer::audio_packet(Leg &leg, const Datagram &datagram) {
  const auto session = leg.session;
  // Without floor control both parties speak at once (TS 24.379 clause 11.1.2).
  const bool open = session->no_media_control;
  if (!eligible(leg) || !UdpSocket::matches(datagram.source, leg.remote->address, leg.remote->audio_port)) {
    status_["media_dropped"] = status_.value("media_dropped", 0u) + 1;
    return;
  }
  if (!open && session->arbitrator->owner() != leg.user) {
    status_["media_dropped"] = status_.value("media_dropped", 0u) + 1;
    if (datagram.bytes.size() > 12) unpermitted_media(leg); // RTP media with payload
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
  // TS 24.380 clause 10.2.3.5: the participants listening to the conversation's MBMS subchannel share one copy sent
  // over it; the others get theirs by unicast (its NOTE).
  const auto *subchannel = mbms_conversation_start(*session);
  bool multicast_sent = false;
  if (leg.local.protected_media) {
    if (datagram.bytes.size() < 40) throw std::runtime_error("truncated protected media");
    for (auto &[id, dst] : legs_) {
      if (dst.get() == &leg || dst->session != session || !eligible(*dst)) continue;
      if (!dst->local.protected_media || dst->remote->payload_type != leg.remote->payload_type ||
          dst->remote->octet_aligned != leg.remote->octet_aligned)
        throw std::runtime_error("protected media profile mismatch");
      if (subchannel && multicast_leg(*dst)) {
        // The SRTP of a group call is protected with the group's GMK (TS 33.180 clause 7.4.2), the same for every
        // receiver: one copy serves them all.
        if (!std::exchange(multicast_sent, true)) send_subchannel(datagram.bytes, *session);
        continue;
      }
      dst->audio->send(datagram.bytes, dst->remote->address, dst->remote->audio_port);
      status_["media_forwarded"] = status_.value("media_forwarded", 0u) + 1;
    }
    return;
  }
  const auto payload = packet.payload;
  (void)unpack_amr_wb(payload, leg.remote->octet_aligned); // malformed speech is refused even with no receiver
  for (auto &[id, dst] : legs_) {
    if (dst.get() == &leg || dst->session != session || !eligible(*dst)) continue;
    if (subchannel && multicast_leg(*dst)) {
      if (std::exchange(multicast_sent, true)) continue;
      packet.payload_type = mbms_->payload_type;
      packet.payload = relay_payload(payload, RtpCodec::amr_wb, leg.remote->octet_aligned, mbms_->octet_aligned);
      send_subchannel(encode_rtp(packet), *session);
      continue;
    }
    packet.payload_type = dst->remote->payload_type;
    packet.payload = relay_payload(payload, RtpCodec::amr_wb, leg.remote->octet_aligned, dst->remote->octet_aligned);
    dst->audio->send(encode_rtp(packet), dst->remote->address, dst->remote->audio_port);
    status_["media_forwarded"] = status_.value("media_forwarded", 0u) + 1;
  }
}

//------------------------------------------------------------------------------
// TS 24.380 clauses 6.3.5.4.6 and 6.3.5.3.8 (TS 24.581 clauses 6.3.5.4.6 and 6.3.5.3.8): RTP media from a
// participant without permission is not forwarded (the caller drops it). While another participant has the floor,
// or after this participant's own Floor Release while the floor is idle, it gets a Floor Revoke (Transmission
// Revoke) with cause #3 (No permission to send a Media Burst) and enters 'U: not permitted but sends media'
// (clause 6.3.5.7.2), with T8 (TS 24.581: T3) started.
void McServer::unpermitted_media(Leg &leg) {
  const auto now = monotonic_ms();
  if (leg.sends_without_permission) {
    leg.unpermitted_media_ms = now;
    return;
  }
  if (!leg.session->arbitrator->owner() && !leg.released_floor) return;
  leg.sends_without_permission = true;
  leg.unpermitted_revoke_ms = leg.unpermitted_media_ms = now;
  send_notice(leg, {FloorNoticeKind::Revoke, leg.user, leg.user, 3});
  event("unpermitted_media_revoked", {{"user_id", leg.user}, {"session_uri", leg.session->uri}});
}

//------------------------------------------------------------------------------
// TS 24.380 clause 6.3.5.7.3 (TS 24.581 clause 6.3.5.7.3): on T8 (Floor Revoke; TS 24.581: T3) expiry the Floor
// Revoke with cause #3 is sent again and T8 restarted. How often and when to give up is an implementation option
// (clause 6.3.5.7.3 NOTE): it is sent again only while the participant still sends media.
void McServer::unpermitted_media_tick(const Session &session, std::uint64_t now) {
  std::optional<std::uint64_t> t8;
  for (const auto &leg : session_legs(session)) {
    if (!leg->sends_without_permission) continue;
    if (!t8) t8 = std::max<std::uint64_t>(floor_options().revoke_retry_ms, 1);
    if (now - leg->unpermitted_revoke_ms < *t8) continue;
    const bool still_sending = leg->unpermitted_media_ms > leg->unpermitted_revoke_ms;
    leg->unpermitted_revoke_ms = now;
    if (still_sending) send_notice(*leg, {FloorNoticeKind::Revoke, leg->user, leg->user, 3});
  }
}

} // namespace mcx
