//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCVideo server of OpenMCX: the controlling and participating MCVideo functions (TS 24.281) on the shared MC
// server core (McServer, src/server/server.hpp), with the transmission control server of TS 24.581 as its media
// plane control, the H.264 video relay, video push to and pull from this server with its recordings, and the
// MCVideo-only rules of the core's service hooks.
//
// The class is declared here; its member functions are defined in the files of this directory.
//
// Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 23.281 V19.10.0 (Rel-19),
// TS 24.484 V19.6.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19).
#pragma once

#include "mcx/transmission.hpp"
#include "server.hpp"

namespace mcx {
//------------------------------------------------------------------------------
// TS 24.281: the MCVideo server: the shared core with the MCVideo service profile and transmission control
// (TS 24.581).
class McvideoServer final : public McServer {
  // ---- MCVideo transmission control server (transmission_control.cpp): TS 24.581 clause 6.3 ----
  void send_transmission_notice(Leg &leg, const FloorNotice &notice);

  bool reception_control() const { return cfg_.at(svc_.name).value("reception_control", false); }

  void send_transmission(const mcx::transmission::Packet &packet, Leg &leg);

  void transmission_notification(Leg &leg, const std::string &transmitter);

  Leg *transmitter_leg(const std::shared_ptr<Session> &session);

  std::vector<FloorField> transmitter_fields(const std::shared_ptr<Session> &session);

  void transmission_packet(Leg &leg, const Datagram &datagram);

  void remote_transmission(Leg &leg, const mcx::transmission::Packet &packet);

  // ---- Video relay (video_media.cpp): TS 24.581 clause 6.3 ----
  void video_packet(Leg &leg, const Datagram &datagram);

  // ---- Video recordings (recording.cpp): TS 24.281 clauses 13.2.3.2.3 and 12.2.3.2.5 ----
  static void write_record(std::ostream &out, std::uint64_t offset, const RtpPacket &packet);

  static std::vector<std::pair<std::uint64_t, RtpPacket>> read_recording(const std::filesystem::path &path);

  std::filesystem::path recordings_dir() const;

  std::string recording_url_base() const;

  std::filesystem::path recording_of(const std::string &url) const;

  // ---- Video push and pull with this server (video_push_pull.cpp): TS 24.281 clauses 13.2.3 and 12.2.3 ----
  SipResponse server_video_invite(const SipMessage &message, const User &user, const McpttInfo &info);

  void send_push_url(const std::shared_ptr<Session> &session, const Leg &leg);

  void stream_tick(const std::shared_ptr<Session> &session, std::uint64_t now);

  // video_push_pull.cpp: rejects a server video call INVITE with the status and Warning.
  SipResponse server_video_rejected(SipResponse &response, const User &user, const McpttInfo &info, int status,
                                    const std::string &warning = {});
  // video_push_pull.cpp: TS 24.281 clauses 13.2.3.2.3 step 5 and 12.2.3.2.5 step 2, the video file.
  std::optional<SipResponse> open_server_video(Session &session, const User &user, const McpttInfo &info, bool push,
                                               SipResponse &response);

  // ---- Service hooks of McServer (here, mcvideo_server.cpp, transmission_control.cpp, video_media.cpp and
  // video_push_pull.cpp) ----
  //------------------------------------------------------------------------------
  // TS 24.581 clauses 6.3.4 and 6.3.5: a media plane control packet is a transmission control message.
  void media_control_packet(Leg &leg, const Datagram &datagram) override { transmission_packet(leg, datagram); }

  //------------------------------------------------------------------------------
  // TS 24.581 clauses 9.2.5 to 9.2.10: a floor arbitration outcome is sent as a transmission control message.
  void media_control_notice(Leg &leg, const FloorNotice &notice) override { send_transmission_notice(leg, notice); }

  bool refuse_remote_request(Relay &relay, UdpSocket &socket, std::span<const std::uint8_t> plain,
                             ProtectedCall *csk) override;

  void check_service_media(const MediaDescription &media, bool uncontrolled_allowed) const override;

  //------------------------------------------------------------------------------
  // TS 24.281 clause 6.4: the implicit Transmission Request of an MCVideo call is answered with the service's part
  // of the answer (answer_service_media, TS 24.581 clause 14.3.5).
  void accept_implicit_floor_request(Leg & /*leg*/, const MediaDescription & /*remote*/, bool /*initiates*/) override {}

  std::unique_ptr<UdpSocket> service_media(MediaDescription &local, unsigned offset,
                                           const std::string &address) override;

  void answer_service_media(Leg &leg, const MediaDescription &remote, bool creating) override;

  void service_media_packets(Leg &leg) override;

  bool initial_service_state(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session) override;

  //------------------------------------------------------------------------------
  // TS 24.281 clause 12.2.3.2.5 step 2: a one-from-server video pull streams its recording.
  void service_session_tick(const std::shared_ptr<Session> &session, std::uint64_t now) override {
    if (session->server_video == "stream") stream_tick(session, now);
  }

  [[nodiscard]] bool video_one_to_one(const std::string &session_type) const override;

  std::optional<SipResponse> service_invite(const SipMessage &message, const User &user,
                                            const McpttInfo &info) override;

  [[nodiscard]] Json service_user_profile(Json profile, const std::string &id) const override;

  [[nodiscard]] Json service_members(Json group) const override;

  //------------------------------------------------------------------------------
  // TS 24.281 clause 6.2.1 has no SDP direction rule for an ambient viewing call.
  [[nodiscard]] std::optional<std::string> ambient_direction_refusal(const MediaDescription & /*media*/,
                                                                     const std::string & /*type*/) const override {
    return std::nullopt;
  }

  //------------------------------------------------------------------------------
  // TS 33.180 clause 5.1.2: the token's subject is the MCPTT ID; an MCVideo server binds the token's MCVideo ID
  // (the "mcvideo_id" claim) instead, whatever the subject.
  [[nodiscard]] bool token_subject_valid(const Json & /*claims*/) const override { return true; }

public:
  McvideoServer(Json cfg, bool disable_tls);
};
} // namespace mcx
