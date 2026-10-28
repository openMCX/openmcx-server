//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MCPTT server of OpenMCX: the controlling and participating MCPTT functions (TS 24.379) on the shared MC
// server core (McServer, src/server/server.hpp), with the floor control server of TS 24.380 as its media plane
// control and the MCPTT-only rules of the core's service hooks.
//
// The class is declared here; its member functions are defined in the files of this directory.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 29.283.
#pragma once

#include "server.hpp"

namespace mcx {
//------------------------------------------------------------------------------
// TS 24.379: the MCPTT server: the shared core with the MCPTT service profile and floor control (TS 24.380).
class McpttServer final : public McServer {
  // ---- Floor control server (floor_control.cpp): TS 24.380 clause 6.3.5 ----
  void floor_packet(Leg &leg, const Datagram &datagram);

  // floor_packet() (floor_control.cpp): TS 24.380 clauses 6.3.5.3.4 and 6.3.5.4.4, a Floor Request; implicit: an
  // implicit floor request (TS 24.380 clause 6.3.5.2.2, initial_service_state).
  void floor_request(Leg &leg, const std::shared_ptr<Session> &session, MediaPlaneController &arbitrator,
                     std::uint8_t priority, bool implicit = false);

  void send_floor_notice(Leg &leg, const FloorNotice &notice);

  // ---- Service hooks of McServer (here and mcptt_server.cpp) ----
  //------------------------------------------------------------------------------
  // TS 24.380 clause 6.3.5: a media plane control packet is a floor control message.
  void media_control_packet(Leg &leg, const Datagram &datagram) override { floor_packet(leg, datagram); }

  //------------------------------------------------------------------------------
  // TS 24.380 clause 6.3.5: a floor arbitration outcome is sent as a floor control message.
  void media_control_notice(Leg &leg, const FloorNotice &notice) override { send_floor_notice(leg, notice); }

  //------------------------------------------------------------------------------
  // TS 24.380 clause 6.4.2: the participating MCPTT function passes floor control messages on unchanged.
  bool refuse_remote_request(Relay & /*relay*/, UdpSocket & /*socket*/, std::span<const std::uint8_t> /*plain*/,
                             ProtectedCall * /*csk*/) override {
    return false;
  }

  void check_service_media(const MediaDescription &media, bool uncontrolled_allowed) const override;

  void accept_implicit_floor_request(Leg &leg, const MediaDescription &remote, bool initiates) override;

  //------------------------------------------------------------------------------
  // TS 24.379 clause 6.2.1: an MCPTT call carries speech and floor control only.
  std::unique_ptr<UdpSocket> service_media(MediaDescription & /*local*/, unsigned /*offset*/,
                                           const std::string & /*address*/) override {
    return nullptr;
  }

  //------------------------------------------------------------------------------
  // TS 24.379 clause 10.1.1.4.2: the answer to an MCPTT group call's SDP offer has no service part of its own.
  void answer_service_media(Leg & /*leg*/, const MediaDescription & /*remote*/, bool /*creating*/) override {}

  //------------------------------------------------------------------------------
  // TS 24.379 clause 6.2.1: an MCPTT leg has no media besides speech (no video socket, so never called).
  void service_media_packets(Leg & /*leg*/) override {}

  bool initial_service_state(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session) override;

  //------------------------------------------------------------------------------
  // TS 24.379 clause 6.3.8: the core supervises an MCPTT call alone.
  void service_session_tick(const std::shared_ptr<Session> & /*session*/, std::uint64_t /*now*/) override {}

  //------------------------------------------------------------------------------
  // TS 24.379 clause 11.1.1: the MCPTT private calls are "private" and "first-to-answer" only.
  [[nodiscard]] bool video_one_to_one(const std::string & /*session_type*/) const override { return false; }

  //------------------------------------------------------------------------------
  // TS 24.379 clause 10.1.1.4.2: an INVITE that is no private, ambient listening or ad hoc call is a group call.
  std::optional<SipResponse> service_invite(const SipMessage & /*message*/, const User & /*user*/,
                                            const McpttInfo & /*info*/) override {
    return std::nullopt;
  }

  //------------------------------------------------------------------------------
  // TS 24.484: the MCPTT user profile is the whole document.
  [[nodiscard]] Json service_user_profile(Json profile, const std::string & /*id*/) const override { return profile; }

  //------------------------------------------------------------------------------
  // TS 24.481: the MCPTT settings of a group are the whole document.
  [[nodiscard]] Json service_members(Json group) const override { return group; }

  [[nodiscard]] std::optional<std::string> ambient_direction_refusal(const MediaDescription &media,
                                                                     const std::string &type) const override;

  [[nodiscard]] bool token_subject_valid(const Json &claims) const override;

public:
  McpttServer(Json cfg, bool disable_tls);
};
} // namespace mcx
