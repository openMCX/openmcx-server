// One-to-server video push and one-from-server video pull, with this server as the far end (member functions
// of McvideoServer).
//
// Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).

#include "mcvideo_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// Helper: reject the INVITE of a server video call: set the status and the Warning, report the rejection and
// return the response.
SipResponse McvideoServer::server_video_rejected(SipResponse &response, const User &user, const McpttInfo &info,
                                                 int status, const std::string &warning) {
  response.status_code = status;
  if (!warning.empty()) response.headers = {{"Warning", "399 mcx \"" + warning + "\""}};
  event("server_video_rejected",
        {{"user_id", user.id}, {"session_type", info.session_type}, {"status", status}, {"warning", warning}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 13.2.3.2.3 step 5 and clause 12.2.3.2.5 step 2: the file a pushed video is saved to, or the
// recording a pulled video is read from. Returns the rejection, or nothing.
std::optional<SipResponse> McvideoServer::open_server_video(Session &session, const User &user, const McpttInfo &info,
                                                            bool push, SipResponse &response) {
  const auto reject = [&](int status, const std::string &warning = {}) {
    return server_video_rejected(response, user, info, status, warning);
  };
  if (push) {
    // TS 24.281 clause 13.2.3.2.3 step 5: the pushed video is saved to a file.
    const auto id = random_id();
    std::string hex;
    for (unsigned char byte : id) {
      static const char digits[] = "0123456789abcdef";
      hex += digits[byte >> 4];
      hex += digits[byte & 15];
    }
    hex = hex.substr(0, 32);
    std::filesystem::create_directories(recordings_dir());
    session.recording = std::make_shared<std::ofstream>(recordings_dir() / hex, std::ios::binary | std::ios::trunc);
    if (!*session.recording) return reject(500);
    session.recording_url = recording_url_base() + hex;
  } else {
    // TS 24.281 clause 12.2.3.2.5 step 2: the media comes from the file the URL names.
    const auto path = recording_of(info.video_pull_url);
    if (path.empty()) return reject(404, warn(Warning::function_not_allowed, "no such video"));
    try {
      session.playback = read_recording(path);
    } catch (const std::exception &) {
      return reject(500);
    }
    if (session.playback.empty()) return reject(404, warn(Warning::function_not_allowed, "empty video"));
    session.recording_url = info.video_pull_url;
  }
  return std::nullopt;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 13.2.3.1.4 with clause 13.2.3.2.3, and clause 12.2.3.1.4 with clause 12.2.3.2.5: set up a
// one-to-server video push or one-from-server video pull call. This server is the participating and
// controlling function and the far end of the call. The <allow-private-call> ruleset is not checked and commencement is
// automatic; TS 24.484 has no element authorising these calls, so the project
// profile's "allow_video_push_to_server" and "allow_video_pull_from_server" do.
SipResponse McvideoServer::server_video_invite(const SipMessage &message, const User &user, const McpttInfo &info) {
  SipResponse response;
  const bool push = info.session_type == "one-to-server video push";
  const auto reject = [&](int status, const std::string &warning = {}) {
    return server_video_rejected(response, user, info, status, warning);
  };
  if (legs_.contains(message.dialog_id)) return reject(403); // no re-INVITE of such a call
  if (info.client_id != user.client || (!info.calling_user.empty() && info.calling_user != user.id) ||
      !info.calling_group.empty() || !accepts_mcptt(message))
    return reject(403);
  if (message.request_uri != cfg_.at(svc_.name).at("service_uri").get<std::string>()) return reject(404);
  if (!message.remote_media || !message.remote_media->video) return reject(488);
  try {
    validate_remote(user.id, *message.remote_media);
  } catch (const std::exception &) {
    return reject(488);
  }
  if (message.remote_media->protected_media)
    return reject(403, warn(Warning::function_not_allowed, "protected server video"));
  bool authorised = false;
  try {
    authorised =
        user_profile(user.id).value(push ? "allow_video_push_to_server" : "allow_video_pull_from_server", false);
  } catch (const std::exception &) {
    // No user profile: not authorised.
  }
  if (!authorised)
    return reject(403, warn(Warning::function_not_allowed,
                            push ? "video push to server not authorised" : "video pull from server not authorised"));
  auto session = std::make_shared<Session>();
  session->private_call = true;
  session->group = "private:" + random_id();
  session->uri = session_service_ + ";mcptt-session=" + random_id();
  session->initiator = user.id;
  session->created = session->last_media = session->normal_since = monotonic_ms();
  session->members = {user.id};
  // No call policy of its own: the defaults of the private call timers apply.
  session->policy = Json::object();
  session->server_video = push ? "record" : "stream";
  session->arbitrator = make_media_control(session->members, floor_options());
  session->no_media_control = message.remote_media->control == MediaControl::none;
  auto leg = make_leg(user.id, session);
  if (!session->no_media_control && leg->local.floor_ssrc == message.remote_media->floor_ssrc) return reject(488);
  // The recording file is made last, so that no rejection above leaves an empty one behind.
  if (auto refused = open_server_video(*session, user, info, push, response)) return *refused;
  leg->dialog = message.dialog_id;
  leg->origin = true;
  leg->incoming_offer = true;
  leg->remote = *message.remote_media;
  leg->local.payload_type = message.remote_media->payload_type;
  leg->local.octet_aligned = message.remote_media->octet_aligned;
  leg->local.queueing = leg->local.queueing && message.remote_media->queueing;
  leg->local.floor_priority.reset();
  if (leg->local.video && message.remote_media->video)
    leg->local.video->payload_type = message.remote_media->video->payload_type;
  // The pushing client asks to transmit in its offer (TS 24.581 clause 6.2.1), granted once
  // the call is up; for a pull only the server sends video.
  leg->local.implicit_request = push && message.remote_media->implicit_request;
  leg->local.direction = push ? "recvonly" : "sendonly";
  response.status_code = 200;
  response.local_media = leg->local;
  response.contact_uri = session->uri;
  response.focus = true;
  McpttInfo answer;
  answer.session_type = info.session_type;
  answer.calling_user = user.id;
  response.parts = service_parts(answer);
  sessions_[session->group] = session;
  add_leg(leg);
  event("server_video_created", {{"user_id", user.id},
                                 {"session_type", info.session_type},
                                 {"url", session->recording_url},
                                 {"packets", session->playback.size()},
                                 {"session_uri", session->uri}});
  return response;
}

//------------------------------------------------------------------------------
// TS 24.281 clause 13.2.3.2.3: the URL of the recording goes to the pushing client in a SIP INFO
// (RFC 6086) of the call's dialog, once the call is up.
void McvideoServer::send_push_url(const std::shared_ptr<Session> &session, const Leg &leg) {
  McpttInfo info;
  info.video_push_url = session->recording_url;
  sip_.request_in_dialog(
      leg.dialog, "INFO", svc_.info_mime, service_info_xml_(info),
      {{"Info-Package", std::string(svc_.feature_tag) + "-info"}, {"Content-Disposition", "Info-Package"}});
  event("video_push_url_sent", {{"user_id", leg.user}, {"url", session->recording_url}});
}

//------------------------------------------------------------------------------
// TS 24.281 clause 12.2.3.2.5 step 2: the recording is sent as it was received, paced by its offsets.
void McvideoServer::stream_tick(const std::shared_ptr<Session> &session, std::uint64_t now) {
  Leg *leg = nullptr;
  for (auto &candidate : session_legs(*session))
    if (candidate->active && eligible(*candidate)) leg = candidate.get();
  if (!leg || !leg->video || !leg->remote || !leg->remote->video) return;
  if (!session->playback_start) session->playback_start = now;
  while (session->playback_next < session->playback.size() &&
         session->playback[session->playback_next].first <= now - session->playback_start) {
    auto packet = session->playback[session->playback_next++].second;
    packet.payload_type = leg->remote->video->payload_type;
    leg->video->send(encode_rtp(packet), leg->remote->address, leg->remote->video->port);
    session->last_media = now;
    status_["video_streamed"] = status_.value("video_streamed", 0u) + 1;
  }
  if (session->playback_next == session->playback.size() && !session->playback.empty()) {
    event("server_video_streamed",
          {{"user_id", leg->user}, {"packets", session->playback.size()}, {"url", session->recording_url}});
    session->playback.clear(); // sent once; the client releases the call (TS 24.281 clause 12.2.2.6)
  }
}

//------------------------------------------------------------------------------
// TS 24.281 clauses 12.2.3 and 13.2.3: a one-to-one video pull or push is a private call
// (TS 24.281 clauses 10.2.2.3 and 10.2.2.4.2) whose <session-type> names it; an MCVideo server only.
bool McvideoServer::video_one_to_one(const std::string &session_type) const {
  return session_type == "one-to-one video pull" || session_type == "one-to-one video push";
}

//------------------------------------------------------------------------------
// TS 24.281 clauses 12.2.3.2.5 and 13.2.3.2.3: an INVITE for a video pull from or push to this server goes to
// server_video_invite(); any other is not a call type of the MCVideo service alone.
std::optional<SipResponse> McvideoServer::service_invite(const SipMessage &message, const User &user,
                                                         const McpttInfo &info) {
  if (info.session_type == "one-to-server video push" || info.session_type == "one-from-server video pull")
    return server_video_invite(message, user, info);
  return std::nullopt;
}

} // namespace mcx
