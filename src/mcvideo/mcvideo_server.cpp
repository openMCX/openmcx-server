// The MCVideo server: its construction and the MCVideo-only rules of the shared core's service hooks: the SDP of
// an MCVideo call, the start of a newly active leg, and the MCVideo parts of the user profile and group documents
// (members of McvideoServer).
//
// Specifications: TS 24.281 V19.6.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19),
// TS 24.481 V19.3.0 (Rel-19).

#include "mcvideo_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.281: construct the MCVideo server on the shared core with the MCVideo service profile. It reads user
// profiles from the CMS (MCVideo-2 is not used), so it runs without "diameter_config".
McvideoServer::McvideoServer(Json cfg, bool disable_tls) : McServer(mcvideo_service, std::move(cfg), disable_tls) {}

//------------------------------------------------------------------------------
// TS 24.281 clauses 6.2.1 and 6.3.2: an MCVideo call has transmission control and H.264 video, and a private call
// may have no transmission control (TS 24.281 clause 10.2.3). TS 24.281 clause 6.4: an MCVideo call's originator
// may request transmission implicitly.
void McvideoServer::check_service_media(const MediaDescription &media, bool /*implicit_allowed*/,
                                        bool /*uncontrolled_allowed*/) const {
  if (!media.video.has_value() || media.control == MediaControl::floor)
    throw std::runtime_error("media of another MC service");
}

//------------------------------------------------------------------------------
// TS 24.281 clause 13.2.3.2.3: the pushing client of a one-to-server video push learns the URL of its recording.
// TS 24.281 clause 6.4: the originator's implicit Transmission Request, or the pulled callee's in its answer
// (TS 24.281 clause 12.2.2.2), is arbitrated once its leg is active, when nobody transmits. Returns true when the
// leg has been told its state.
bool McvideoServer::initial_service_state(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session) {
  if (session->server_video == "record" && leg->origin) send_push_url(session, *leg);
  if (session->no_media_control) return false; // nothing to arbitrate (TS 24.281 clause 10.2.3)
  const auto owner = session->arbitrator->owner();
  // The originator's implicit request (TS 24.281 clause 6.4), or the pulled callee's in
  // its answer (TS 24.281 clause 12.2.2.2): the one whose video the call carries.
  const bool implicit =
      (leg->origin && leg->local.implicit_request) ||
      (!leg->origin && session->video_mode == "one-to-one video pull" && leg->remote && leg->remote->implicit_request);
  if (!implicit || owner || !leg->remote) return false;
  notices(*session,
          session->arbitrator->request(leg->user, monotonic_ms(), 0, leg->local.queueing && leg->remote->queueing, 0));
  event("transmission_requested", {{"user_id", leg->user}, {"implicit", true}});
  return true;
}

//------------------------------------------------------------------------------
// TS 24.484: the MCVideo user profile: the rulesets under "mcvideo", keyed like the MCPTT ones and naming MCVideo
// IDs. Absent rulesets authorise nothing.
Json McvideoServer::service_user_profile(Json profile, const std::string &id) const {
  auto view = profile.value("mcvideo", Json::object());
  view[svc_.id_claim] = id;
  return view;
}

//------------------------------------------------------------------------------
// TS 24.481 with TS 24.281 clause 8.2.2: an MCVideo group's settings name MCVideo IDs:
// the GMS serves them under "mcvideo" (members, priority_policy, call_policy, ...),
// and they replace the MCPTT ones the rest of the core reads. A group without
// MCVideo members has none.
Json McvideoServer::service_members(Json group) const {
  const auto video = group.value("mcvideo", Json::object());
  group["members"] = video.value("members", Json::array());
  for (const auto &[key, value] : video.items())
    if (key != "members") group[key] = value;
  for (const auto *key : {"priority_policy", "call_policy", "floor_priority_caps", "user_priorities"})
    if (!video.contains(key)) group.erase(key); // MCPTT settings name MCPTT IDs
  return group;
}

} // namespace mcx
