//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The shared core of the MCPTT and MCVideo servers of OpenMCX: the controlling and participating functions
// common to MCPTT (TS 24.379) and MCVideo (TS 24.281) on TS 23.280, driving the media plane control of a call
// through MediaPlaneController, and the security of both (TS 33.180). The MCPTT server (src/mcptt, floor
// control of TS 24.380) and the MCVideo server (src/mcvideo, transmission control of TS 24.581, video push and
// pull, recording) derive from McServer, pass their service profile and implement its service hooks.
//
// The class is declared here; its member functions are defined in the files of this directory,
// one per topic.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19),
// TS 24.581 V19.2.0 (Rel-19), TS 23.379 V19.11.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19), TS 24.481 V19.3.0 (Rel-19),
// TS 24.484 V19.6.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 24.545, TS 29.283, RFC 3891, RFC 5359, RFC 5874.
#pragma once

#include "mcx/adhoc_call.hpp"
#include "mcx/admission.hpp"
#include "mcx/af.hpp"
#include "mcx/diameter.hpp"
#include "mcx/floor.hpp"
#include "mcx/http.hpp"
#include "mcx/key_client.hpp"
#include "mcx/key_documents.hpp"
#include "mcx/location.hpp"
#include "mcx/mbms.hpp"
#include "mcx/mbms_usage.hpp"
#include "mcx/media.hpp"
#include "mcx/multicast.hpp"
#include "mcx/private_call.hpp"
#include "mcx/protected_call.hpp"
#include "mcx/runtime.hpp"
#include "mcx/rx.hpp"
#include "mcx/seal_location.hpp"
#include "mcx/video.hpp"
#include "mcx/warning.hpp"
#include "mcx/xml_security.hpp"
#include "parts/alias_registry.hpp"
#include "parts/common_services.hpp"
#include "parts/counters.hpp"
#include "parts/location_service.hpp"
#include "parts/message_parts.hpp"
#include "parts/peer_registration.hpp"
#include "parts/peers.hpp"
#include "parts/program.hpp"
#include "parts/served_users.hpp"
#include "parts/task_queue.hpp"
#include "request_values.hpp"

#include <atomic>
#include <csignal>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <set>
#include <span>
#include <thread>
#include <utility>

namespace mcx {
class McServer {
protected:
  //------------------------------------------------------------------------------
  // A service authorised user: the binding of MCPTT ID, MCPTT client ID and public user identity
  // (TS 24.379 clause 7.3.3 step 5a), and the user's affiliated groups (TS 24.379 clause 9.2.2.2.2).
  // The shared served user (parts/served_users.hpp; peer: the participating server of a user served elsewhere, over
  // MCPTT-3, TS 23.379 clause 7.5.2.4), with the core's own: the p-id of the affiliation PUBLISH being handled, for
  // the NOTIFY it triggers (TS 24.379 clause 9.2.2.2.5 step 3d, TS 24.281 clause 8.2.2.2.5 step 3d), the floor and
  // media keys of its calls, and the end of its affiliation status subscription.
  struct User : ServedUser {
    std::string handled_pid;
    std::shared_ptr<ProtectedCall> protection;
    std::int64_t subscription_expires = 0;
  };

  //------------------------------------------------------------------------------
  // A participant's subscription to the conference event package of its call (TS 24.379 clause 10.1.3.4.1).
  struct ConferenceSubscription {
    std::string user, dialog;
    std::int64_t expires = 0;
    std::uint32_t version = 0;
  };

  //------------------------------------------------------------------------------
  // The priority call conditions of a call at the controlling function: the in-progress emergency and
  // imminent peril states and the emergency alerts (TS 24.379 clause 6.3.3.1).
  struct PriorityState {
    bool emergency = false, imminent = false;
    std::set<std::string> emergency_users, imminent_users, alerts;
    std::uint64_t emergency_deadline = 0;
    Json profile = Json::object();
    std::map<std::string, EmergencyLocation> alert_locations;
  };

  //------------------------------------------------------------------------------
  // A call at the controlling function: a group call (TS 24.379 clause 10.1.1.4) or a private call
  // (TS 24.379 clause 11.1.1.4), and for MCVideo their counterparts of TS 24.281.
  struct Session {
    // For a private call, group is an internal key ("private:<id>") that can
    // never collide with a group URI; target is the called MCPTT ID.
    std::string group, uri, initiator;
    bool private_call = false;
    PrivateCallRequest private_request;
    // First-to-answer call (TS 24.379 clause 11.1.1): every permitted invitee rings;
    // the first to answer becomes private_request.target and the others are
    // cancelled or released with "not selected for call".
    bool first_to_answer = false, progress_sent = false;
    // MCVideo one-to-one video push or pull (TS 24.281 clauses 13.2 and 12.2): a private call
    // whose <session-type> the callee also receives; the pushing caller, or the
    // pulled callee, is the one that transmits. Empty for any other private call.
    std::string video_mode;
    // A one-to-server video push or a one-from-server video pull (TS 24.281 clauses
    // 13.2.3.2.3 and 12.2.3.2.5): the server itself records the pushed video ("record"), or
    // streams a recording ("stream"), named by recording_url.
    std::string server_video, recording_url;
    std::shared_ptr<std::ofstream> recording;
    std::uint64_t recording_start = 0;
    unsigned recorded = 0;
    std::vector<std::pair<std::uint64_t, RtpPacket>> playback; // offset (ms), packet
    std::size_t playback_next = 0;
    std::uint64_t playback_start = 0;
    // The target was admitted outside the <PrivateCall> list: a transferred,
    // forwarded or functional-alias call (TS 24.379 clause 11.1.1.3.1.1 steps 11c to 11e).
    bool list_exempt = false;
    // Announced transfer (TS 24.379 clause 11.1.8.2.3): a call to the target carrying
    // <transfer-announced-ind>, whose answer returns the target's dialog as
    // <replaces-header-value>; and the transferred user's call that replaces it
    // (the Replaces value of RFC 3891 passed on to the target).
    bool transfer_announced = false;
    std::string replaces_value, replaces_header;
    // Ambient listening call (TS 24.379 clause 11.1.6), also a private_call session:
    // the ambient listening type ("remote-init" or "local-init"), the listening
    // and listened-to MCPTT IDs, and once a release is triggered by the server
    // (TS 24.379 clause 11.1.6.4.3), the <release-reason> for the listening user's BYE.
    std::string ambient, listening, listened_to, ambient_release_reason;
    bool ambient_released = false;
    // What waits for the listened-to user's dialog to end in a server release: the
    // invitation of that user to the call that triggered it.
    std::vector<std::function<void()>> after_release;
    // The invitation of a private call waits for such a release; setup is not
    // supervised until it is sent.
    bool invitation_deferred = false;
    // End-to-end protection with a PCK (TS 33.180 clause 7.2.2): the caller's I_MESSAGE is
    // passed unchanged to the callee (TS 24.379 clause 6.3.2.1.1.1 step 4, applied by clause
    // 6.3.2.2.1); the server never holds the PCK and relays the SRTP as it is. Floor control
    // uses each user's CSK.
    bool protected_private = false;
    std::string private_key_mgmt;
    std::vector<std::string> invitees;
    // Private call priority (TS 24.379 clauses 11.1.1.4.3 to 11.1.1.4.6): the controlling
    // function's cache of the in-progress emergency private call state and alerts.
    PriorityState priority;
    std::vector<SipHeader> answer_headers;
    int failure_status = 0;
    std::string failure_warning;
    // A callee leg found no free media ports: the caller gets 500 with Retry-After (see CapacityReached).
    bool capacity_reached = false;
    // Call forwarding on no answer (TS 24.379 clause 6.3.2.5): timer TNP1's expiry and
    // the forwarding target of the called user.
    std::uint64_t no_answer_deadline = 0;
    std::string no_answer_target;
    Json policy;
    std::vector<std::string> members;
    std::unique_ptr<MediaPlaneController> arbitrator; // floor or transmission control
    // A private call without media plane control: an MCVideo call without
    // transmission control (TS 24.281 clause 10.2.3) or an MCPTT call without floor control
    // (TS 24.379 clause 11.1.2). Both parties send at once, nothing is arbitrated, and only
    // the clients end the call (TS 24.379 clause 11.1.4.1 NOTE).
    bool no_media_control = false;
    std::set<std::string> dialogs, late_entry_pending;
    std::uint64_t created = 0, last_media = 0, last_policy_check = 0;
    bool established = false;
    // Broadcast group call (TS 24.379 clause 4.12): only the initiator transmits and
    // the call ends when that transmission completes.
    bool broadcast = false, broadcast_transmitted = false, broadcast_released = false;
    // Chat group call (TS 24.379 clause 10.1.2): members join individually; the
    // controlling function never invites and there is no initiator policy.
    bool chat = false;
    // Ad hoc group call (TS 24.379 clause 17): group is a server-generated ad hoc
    // group identity; members are the initiator plus the listed invitees,
    // implicitly affiliated for the life of the call.
    bool adhoc = false;
    // Ad hoc participant criteria (TS 24.379 clause 17.4.6) and the users that matched them at
    // the last evaluation.
    std::string criteria;
    std::set<std::string> criteria_matches;
    // TS 24.379 clauses 17.4.5.2.1 steps 4a and 5a: users invited or removed by a modification (clause 17.2.6),
    // which the criteria do not remove or invite again.
    std::set<std::string> manual_invites, manual_removals;
    // Functional aliases (TS 24.379 clause 9A): the initiator's active alias presented to the
    // other participants, and for a call to an alias, the called alias.
    std::string initiator_alias, called_alias;
    std::map<std::string, std::string> participant_aliases;
    // Broadcast group hierarchy (TS 23.379 clause 10.6.2.5.2; project profile, as TS
    // 24.379 clause 4.12 defines no stage-3 procedure): "group-broadcast" delivers via
    // the subordinate groups, "user-broadcast" to the group's users. Fan-out
    // waits until the users of preempted calls have left them.
    std::string hierarchy;
    std::vector<std::string> subordinate_groups;
    std::set<std::string> awaiting_users;
    std::uint64_t awaiting_since = 0;
    bool awaiting_fanout = false;
    // Broadcast override (TS 23.379 clause 10.6.2.5 NOTE 3): users listed in
    // call_policy.broadcast_overriders who have taken over the transmission.
    std::set<std::string> broadcast_overriders;
    std::uint64_t normal_since = 0;
    std::map<std::string, ConferenceSubscription> subscriptions;
  };

  //------------------------------------------------------------------------------
  // One user's dialog in a call, with its media and its floor (or transmission) control channel towards
  // the floor participant (TS 24.380 clause 6.3.5, TS 24.581 clause 6.3).
  struct Leg {
    std::string dialog, user;
    std::shared_ptr<Session> session;
    std::uint8_t granted_priority = 0;
    MediaDescription local;
    std::optional<MediaDescription> remote;
    std::unique_ptr<UdpSocket> audio, floor, video; // video: MCVideo only
    bool active = false, origin = false, fanned_out = false, floor_granted = false, incoming_offer = false;
    bool awaiting_answer = false;
    // Put on hold by its user (RFC 5359 section 2.1, for an announced transfer, TS 24.379
    // clause 11.1.8.2.3 step 1): no media or floor control is sent to or taken from it.
    bool held = false;
    SipResponse answer;
    std::optional<McpttInfo> pending_priority_info;

    //------------------------------------------------------------------------------
    // A priority state change queued for the participant's re-INVITE (TS 24.379 clauses 6.3.3.1.6,
    // 6.3.3.1.10 and 6.3.3.1.15).
    struct PriorityNotification {
      McpttInfo info;
      std::vector<SipHeader> headers;
    };

    std::deque<PriorityNotification> priority_notifications;
    bool priority_notification_pending = false;
    std::uint64_t priority_notification_retry = 0;
    std::uint32_t audio_ssrc = random_ssrc();
    std::uint32_t video_ssrc = random_ssrc(); // assigned with the transmission grant (TS 24.581 clause 9.2.5)
    // MCVideo reception control (TS 24.581 clause 4.1.1.2): whether this participant accepted
    // the current transmission (Receive Media Request) and gets its video relayed.
    bool receiving = true;
    std::uint16_t floor_sequence = 0;
    std::unique_ptr<FloorAckRetry> floor_retries;
    // TS 24.380 clause 6.3.5.7 (TS 24.581 clause 6.3.5.7): 'U: not permitted but sends media', entered with a
    // Floor Revoke cause #3 and left on Floor Release (Transmission End Request) or a grant; T8 (TS 24.581: T3)
    // repeats the revoke. released_floor: the participant left 'U: permitted' with its own Floor Release, for
    // clause 6.3.5.3.8.
    bool sends_without_permission = false, released_floor = false;
    std::uint64_t unpermitted_revoke_ms = 0, unpermitted_media_ms = 0;
  };

  //------------------------------------------------------------------------------
  // A group member's subscription to the group's GKTP document, its group key (TS 24.481 clause 7.7).
  struct KeySubscription {
    std::string user, group, dialog;
    std::int64_t expires = 0;
    std::uint32_t key_id = 0;
    std::uint64_t next_poll = 0;
    bool pending = false;
  };

  std::map<std::string, KeySubscription> key_subscriptions_;
  // How often the GKTP document of a key subscription is polled at the GMS (a local choice; TS 24.481 clause 7.7
  // gives no interval).
  static constexpr std::uint64_t key_poll_ms = 5000;
  std::unique_ptr<KeyClient> keys_;
  // The MC service this server provides (TS 24.379 or TS 24.281): the profile its program passes, which the
  // configuration's "service" ("mcptt", the default, or "mcvideo") must name.
  const ServiceProfile &svc_;

  // ---- Service information (service_info.cpp): the MCPTT or MCVideo profile ----
  static const ServiceProfile &configured_service(const ServiceProfile &served, const Json &cfg);

  [[nodiscard]] std::string feature_accept() const;

  [[nodiscard]] std::string icsi_accept() const;

  [[nodiscard]] std::string service_tags() const;

  std::unique_ptr<MediaPlaneController> make_media_control(std::vector<std::string> members,
                                                           const FloorArbitratorOptions &options) const;

  [[nodiscard]] std::string warn(Warning warning, std::string_view detail = {}) const;

  // TS 24.379 clause 4.4.1 (TS 24.281 clause 4.4.1): a Warning header field value from this server, with its host
  // name (the SIP advertised host) as warn-agent.
  [[nodiscard]] std::string warning_value(std::string_view text) const {
    return mcx::warning_value(cfg_.at("sip").at("advertise").get<std::string>(), text);
  }

  [[nodiscard]] Affiliation service_affiliation(const std::string &user, const std::string &client) const {
    return mcx::service_affiliation(svc_, user, client, random_id());
  }

  [[nodiscard]] bool own_affiliation(const Affiliation &affiliation) const;

  [[nodiscard]] std::string service_info_xml_(const McpttInfo &info) const { return service_info_xml(info, svc_); }

  [[nodiscard]] McpttInfo parse_service_info_(std::string_view xml) const { return parse_service_info(xml, svc_); }

  [[nodiscard]] std::vector<BodyPart> service_parts(const McpttInfo &info) const { return info_parts(info, svc_); }

  Json cfg_, status_;
  HttpClient http_;
  // TS 33.180 annex B.11.2: the access tokens of the users, checked against IdMS's keys.
  AccessTokens tokens_;
  Control control_;
  // The process's freeDiameter core, shared by MCPTT-2 and Rx (src/common/diameter_core.hpp); null when neither
  // is configured.
  std::shared_ptr<DiameterCore> diameter_core_;
  // MCPTT-2 (TS 23.379 clause 7.5.2.3, TS 29.283); an MCVideo server reads the profile from the CMS instead
  // (MCVideo-2 is not used), so it runs without "diameter_config".
  std::unique_ptr<DiameterProfileClient> diameter_;
  SipEngine sip_;
  std::map<std::string, User> users_;
  std::map<std::string, std::shared_ptr<Leg>> legs_;
  std::map<std::string, std::shared_ptr<Session>> sessions_;
  TaskQueue pending_;
  std::uint64_t last_save_ = 0;
  unsigned next_port_ = 0;
  std::string core_address_, session_service_;
  std::map<std::string, PriorityState> priorities_;
  // AF role towards policy control (TS 24.379 clause 4.13; src/server/policy.cpp): N5 for 5G access (TS 29.514,
  // "pcf" block) and Rx for EPS access (TS 29.214, MCPTT-5, "rx" block). An active leg whose UE is on one of their
  // accesses has a policy session with that client, keyed by the leg's dialog; any other leg (WLAN) has none.
  std::vector<std::unique_ptr<af::PolicyClient>> policy_clients_;
  std::uint64_t policy_checked_ = 0;
  static std::shared_ptr<DiameterCore> start_diameter_core_for(const Json &cfg);
  void policy_start();
  af::PolicyClient *policy_client_for(const Leg &leg) const;
  std::optional<af::SessionRequest> policy_request(const Leg &leg) const;
  void policy_open(const Leg &leg);
  void policy_event(af::PolicyClient &client, const af::Event &result);
  void policy_tick(std::uint64_t now);
  void policy_stop();
  // Functional alias activation state (TS 24.379 clause 9A.2.2.3.2): alias -> MCPTT
  // IDs in activation order. The server both serves the user and owns aliases.
  AliasRegistry functional_aliases_;
  // The "take-over-possible" functional alias status (TS 24.379 clause 3.1, TS 24.281 clause 3.1): user -> the aliases
  // whose activation it asked for and that it may take over, until its next request for them.
  std::map<std::string, std::set<std::string>> alias_takeover_possible_;

  //------------------------------------------------------------------------------
  // Functional alias status subscriptions (TS 24.379 clauses 9A.2.2.2.4 and 9A.2.2.3.4, TS 24.281
  // clauses 20.2.2.2.4 and 20.2.2.3.4), by dialog: the subscriber, and either the user whose
  // aliases or the alias whose users it follows.
  struct AliasSubscription {
    std::string subscriber, user, alias;
    std::int64_t expires = 0;
  };

  std::map<std::string, AliasSubscription> alias_subscriptions_;

  // Split servers (TS 24.379 clause 9A.2.2.2.2): the functional alias information entries of each served user whose
  // aliases another server owns: user -> alias -> status ("activating", "activated", "deactivating"), the client's
  // p-id-fa, the take-over request and the current p-id-fa of the status change passed on (clause 9A.2.2.2.6 step 7).
  struct ServedAlias {
    std::string status, publish_id, onward_id;
    bool take_over = false;
  };

  std::map<std::string, std::map<std::string, ServedAlias>> served_aliases_;

  // This server's subscriptions to the owning server (TS 24.379 clause 9A.2.2.2.7): dialog -> user and alias.
  struct AliasUpstream {
    std::string user, alias;
  };

  std::map<std::string, AliasUpstream> alias_upstream_;

  // The owning server's subscriptions from serving servers (TS 24.379 clause 9A.2.2.3.4): dialog -> alias and user.
  struct PeerAliasSubscription {
    std::string alias, user;
    bool ended = false;
  };

  std::map<std::string, PeerAliasSubscription> peer_alias_subscriptions_;
  // Functional alias to group bindings (TS 24.379 clause 9A.4.2.3.2, TS 24.281 clause 20.4.2.3.2):
  // user -> group -> alias. One alias per group; an alias may be bound to several groups.
  std::map<std::string, std::map<std::string, std::string>> alias_bindings_;

  //------------------------------------------------------------------------------
  // Ad hoc group emergency alerts (TS 24.379 clause 12.1A.3): by generated ad hoc
  // group identity; recipients are the users currently meeting the criteria.
  struct AdhocAlert {
    std::string initiator, client, criteria;
    std::set<std::string> recipients;
    std::optional<EmergencyLocation> location;
    std::uint64_t last_check = 0;
  };

  std::map<std::string, AdhocAlert> adhoc_alerts_;

  //------------------------------------------------------------------------------
  // Transfer and forwarding authorisations cached for the follow-up private call
  // (TS 24.379 clause 11.1.1.3.1.1 steps 11c and 11d): calling user -> {target, deadline}.
  struct CachedMapping {
    std::string target;
    std::uint64_t deadline = 0;
  };

  std::map<std::string, CachedMapping> transfer_mappings_, forwarding_mappings_;

  //------------------------------------------------------------------------------
  // The <ric-app-level-priority> of a remotely initiated call request relayed to
  // a served remote user, keyed by that user: the group or user to be called, and
  // the Resource-Priority its follow-up call may carry (TS 24.379 clauses 10.1.5.2.2
  // step 2b and 11.1.7.2.2 step 3b).
  struct RicPriority {
    std::string target, value;
    std::uint64_t deadline = 0;
  };

  std::map<std::string, RicPriority> ric_priorities_;

  //------------------------------------------------------------------------------
  // Server roles and direct peering over MCPTT-3 (TS 23.379 clause 7.5.2.4; TS 24.379 separates participating and
  // controlling procedures). mcptt.role is "both" (combined, the default), "participating" or "controlling". The
  // peers (parts/peers.hpp) are the other participating and controlling servers of this system.
  using Peer = ServicePeer;

  std::string role_ = "both", controller_;
  std::map<std::string, Peer> peers_;

  //------------------------------------------------------------------------------
  // A call this participating function relays between a served user and a
  // controlling function on a peer (TS 24.379 clauses 10.1.1.3 and 11.1.1.3). Speech and
  // floor packets pass unchanged through one port pair, and for MCVideo the video
  // through a third port (TS 24.581 clause 6.4); each side's SDP is the other side's
  // description at those ports.
  struct Relay {
    std::string user, peer, client_dialog, peer_dialog;
    // The session alias presented to the client for the controlling function's session URI, if any.
    std::string alias;
    MediaDescription local;
    std::optional<MediaDescription> client_remote, peer_remote;
    std::unique_ptr<UdpSocket> audio, floor, video;
    std::vector<BodyPart> bye_parts;
    // A group the user was implicitly affiliated to for this call (TS 24.379 clause 9.2.2.2.12).
    std::string implicit_group;
    bool ended = false;
    // T12: an ambient listening or viewing call relayed for its listened-to or
    // viewed-to user, whom a call request controlled elsewhere may take away
    // (TS 24.379 clause 11.1.6.4.3, TS 24.281 clause 15.4.3); what waits for its release.
    bool ambient_party = false, ambient_releasing = false, client_released = false;
    std::vector<std::function<void()>> after_release;
  };

  std::map<std::string, std::shared_ptr<Relay>> relays_; // by either dialog

  //------------------------------------------------------------------------------
  // A peer controlling function's session URI, presented to local clients as a
  // session URI of this server so that the SIP core routes it here (project mechanism for the
  // participating function of TS 24.379 clauses 10.1.1.3 and 11.1.1.3).
  struct SessionAlias {
    std::string peer, remote;
  };

  std::map<std::string, SessionAlias> session_aliases_;
  std::deque<std::string> alias_order_;
  // At most this many session aliases are kept (a local limit); the oldest not in use by a call goes first.
  static constexpr std::size_t max_session_aliases = 1024;

  bool session_alias_in_use(const std::string &alias) const;

  //------------------------------------------------------------------------------
  // A conference event subscription passed to a peer's controlling function (TS 24.379 clause 10.1.3.3).
  struct ConferenceRelay {
    std::string peer, client_dialog, upstream_dialog, alias;
    // NOTIFYs that arrive before the client's SUBSCRIBE has been answered.
    bool accepted = false;
    std::vector<std::pair<std::string, std::vector<BodyPart>>> pending;
  };

  std::map<std::string, std::shared_ptr<ConferenceRelay>> conference_relays_; // by either dialog

  // ---- Participating and controlling functions (split.cpp): MCPTT-3, TS 23.379 clause 7.5.2.4 ----
  std::string peer_at(const std::string &address) const { return mcx::peer_at(peers_, address); }

  static std::string address_of(const std::string &host) { return mcx::address_of(host); }

  static bool peer_media(const Peer &peer, const std::string &address) { return mcx::peer_media(peer, address); }

  std::vector<SipHeader> route_to(const std::string &peer, std::vector<SipHeader> headers = {}) const {
    return peer_route(peers_, peer, std::move(headers));
  }

  std::vector<SipHeader> user_route(const User &user, std::vector<SipHeader> headers = {}) const {
    return user.peer.empty() ? headers : route_to(user.peer, std::move(headers));
  }

  std::string group_controller(const std::string &group) const;

  // Private, first-to-answer, ambient listening and ad hoc calls are controlled
  // by the calling user's server; a participating-only server uses its controller.
  std::string call_controller() const { return role_ == "participating" ? controller_ : std::string{}; }

  std::string alias_controller() const;

  static std::string header_uri(std::string_view value);

  // TS 24.379 clause 9.2.2.2.6: the user's registration with the controlling servers (parts/peer_registration.hpp).
  void register_with_controllers(const User &user, bool withdraw = false, bool refresh = false) {
    peer_registration_.publish(peer_user(user), withdraw, refresh);
  }

  // Helper: a user as peer registration sees it; its affiliations are current while its subscription lasts.
  static PeerUser peer_user(const User &user) {
    return {user.id,
            user.client,
            user.sip,
            user.peer,
            user.expires,
            user.groups,
            !user.subscription.empty() && user.subscription_expires > std::time(nullptr)};
  }

  unsigned media_offset() const;
  // The media port pairs one server hands out from media.rtp_port (offsets 0 to 98 in steps of two): one per leg or
  // relay, so at most 25 private calls.
  static constexpr unsigned media_slots = 50;

  // No free media ports: answered with 500 and Retry-After (TS 24.379 clause 11.1.1.3.1.1 step 1, clause
  // 10.1.1.3.1.1), not with the 403 of a refused request.
  struct CapacityReached : std::runtime_error {
    CapacityReached() : std::runtime_error("call capacity reached") {}
  };

  // No binding of the requesting public user identity to an MC service ID, or an expired one: answered with 404 and
  // Warning 141 (TS 24.379 clause 10.1.1.3.1.1 step 2a and the other originating procedures, TS 24.281
  // clause 10.1.1.3.1.1), not with the 403 of a refused request.
  struct UnknownUser : std::runtime_error {
    UnknownUser() : std::runtime_error("service authorization required") {}
  };

  // The Retry-After of that answer, in seconds: media.capacity_retry_after_s, default 5.
  unsigned capacity_retry_after() const;

  std::shared_ptr<Relay> make_relay(const std::string &user, const std::string &peer);

  static MediaDescription mirror(MediaDescription media, const MediaDescription &local);

  static std::optional<MediaDescription> sdp_of(const std::vector<BodyPart> &parts);

  static std::vector<BodyPart> application_parts(const std::vector<BodyPart> &parts);

  static std::vector<SipHeader> relayed_headers(const std::vector<SipHeader> &headers);

  std::string session_alias(const std::string &peer, const std::string &remote);

  std::string focus_contact_header(const std::string &uri) const { return "<" + uri + ">;isfocus" + service_tags(); }

  void add_relay(const std::shared_ptr<Relay> &relay);

  // ---- Affiliation (affiliation.cpp): TS 24.379 clause 9.2.2 ----
  unsigned affiliation_limit(const std::string &id);

  bool affiliation_limit_reached(const User &user, const McpttInfo &info);

  SipResponse &too_many_affiliations(SipResponse &response, const User &user);

  std::string begin_implicit_affiliation(User &user, const McpttInfo &info, bool alert);

  void end_implicit_affiliation(const std::string &id, const std::string &group, bool accepted);

  // ---- Requester authorisation (priority.cpp): TS 24.379 clause 6.3.3.1 ----
  Json requester_rules(const User &user, const char *section);

  std::string service_request_refusal(const User &user, const McpttInfo &info);

  void remember_service_mapping(const std::string &id, const McpttInfo &info);

  void remember_ric_priority(const std::string &remote, const std::string &target, const McpttInfo &info);

  bool ric_priority(const std::string &user, const std::string &target, const std::string &requested,
                    const Json &values);

  // ---- Relays between participating and controlling functions (split_relay.cpp): TS 24.379 clause 6.3.2 ----
  void forward_private_call(const std::string &caller, const std::string &by, const std::string &target,
                            const std::string &reason);

  void expire_no_answer(const std::shared_ptr<Session> &session);

  std::string check_service_mapping(const std::string &id, const SipMessage &message, const McpttInfo &info);

  SipResponse relay_outgoing(const SipMessage &message, User &user, const std::string &peer, const std::string &target);

  SipResponse relay_incoming(const SipMessage &message, const std::string &peer, const User &user);

  void relay_answer(const std::shared_ptr<Relay> &relay, const SipResponse &response, bool toward_peer);

  void end_relay(const std::shared_ptr<Relay> &relay);

  void end_user_relays(const std::string &id);

  SipResponse relay_request(const SipMessage &message, const std::shared_ptr<Relay> &relay, bool from_peer);

  SipResponse relay_reinvite(const SipMessage &message, const std::shared_ptr<Relay> &relay, bool from_peer,
                             const std::string &other, const std::vector<SipHeader> &headers);

  SipResponse relayed_reinvite_answer(const SipResponse &answer, const std::shared_ptr<Relay> &relay, bool from_peer);

  SipResponse relay_message(const SipMessage &message, const std::string &target, std::vector<SipHeader> headers,
                            std::function<void(int)> done = {});

  SipResponse relay_subscription(const SipMessage &message, const User &user, const std::string &alias,
                                 const SessionAlias &target);

  void forward_conference(ConferenceRelay &relay, const std::string &state, std::vector<BodyPart> parts);

  SipResponse relay_conference(const SipMessage &message, const std::shared_ptr<ConferenceRelay> &relay,
                               bool from_peer);
  //------------------------------------------------------------------------------
  // The streams a relay passes on: TS 24.380 clauses 6.4.2 and 6.4.3, TS 24.581 clauses 6.4.2 and 6.4.3.
  enum class RelayStream { audio, floor, video };

  void relay_packets(Relay &relay, RelayStream stream);

  // ---- Priority call conditions (priority.cpp): TS 24.379 clause 6.3.3.1 ----
  const PriorityState &call_priority(const Session &session);

  static bool priority_allowed(const Json &policy, const char *key, const std::string &id);

  static const char *priority_name(const PriorityState &state);

  std::vector<SipHeader> priority_headers(const Json &policy, const PriorityState &state) const;

  void populate_priority(McpttInfo &info, const PriorityState &state) const;

  static std::optional<EmergencyLocation> message_location(const SipMessage &message);

  std::vector<BodyPart> priority_parts(const McpttInfo &info, const PriorityState *state = nullptr) const;

  void priority_message(User &target, McpttInfo info);

  void send_priority_notification(const std::shared_ptr<Leg> &leg);

  // TS 24.379 clause 10.1.1.4.7 step 6: what an emergency request did to the group's in-progress emergency state.
  enum class EmergencyChange { none, new_state, additional };
  void priority_fanout(const std::string &group, const std::string &sender, McpttInfo change, bool alert_only = false,
                       EmergencyChange emergency = EmergencyChange::none);
  static EmergencyChange emergency_change(const McpttInfo &info, bool was_emergency, bool is_emergency);

  SipResponse &broadcast_priority_refused(SipResponse &response);

  bool validate_priority(const SipMessage &message, const User &user, const Json &profile, McpttInfo &info,
                         SipResponse &response, std::optional<McpttInfo> &correction, bool alert_only = false);

  void apply_priority(const std::string &group, const std::string &user, const McpttInfo &info, const Json &profile,
                      std::optional<EmergencyLocation> location = {});

  void negotiate_priority(Leg &leg, const Json &profile, std::optional<std::uint8_t> offer);

  FloorArbitratorOptions floor_options() const;

  // TS 24.379 clause 6.3.3.1.19 (TS 24.281 likewise) and TS 24.380 clause 11: the values of the service's service
  // configuration document (TS 24.484 clauses 8.4 and 9.4) from the CMS, refreshed every 30 seconds.
  Json service_config_ = Json::object();
  std::uint64_t service_config_at_ = 0;
  void refresh_service_config(std::uint64_t now);

  Json service_resource_priority() const { return service_config_.value("resource_priority", Json::object()); }

  void schedule(std::function<void()> task) { pending_.push_back(std::move(task)); }

  // ---- Users, groups and policies (users.cpp) ----
  Json internal(const std::string &role, const std::string &path) {
    return common_document(http_, cfg_.at("common"), role, path);
  }

  User &authenticated(const SipMessage &message);

  // The user with the MCPTT ID (or MCVideo ID), whether its service authorisation lasts or not.
  User *by_id(const std::string &id) { return served_by_id(users_, id, false); }

  Json group_profile(const std::string &id);

  Json with_protection(Json group) const;

  bool member(const Json &group, const std::string &id);

  static bool policy_allows_listed(const Json &policy, const char *key, const std::string &id);

  bool policy_allows(const Json &policy, const char *key, const std::string &id) const;

  // ---- Affiliation (affiliation.cpp): TS 24.379 clause 9.2.2 ----
  bool affiliated(const std::string &id, const std::string &group);

  bool sufficient_affiliation(const std::string &group, const std::vector<std::string> &members, const Json &policy,
                              bool include_required);

  bool accepts_mcptt(const SipMessage &message) const;

  //------------------------------------------------------------------------------
  // TS 24.379 clauses 9.2.2.3.6 and 9.2.2.3.7: a group member who joins a chat group,
  // starts an emergency or imminent peril group call, or sends an emergency
  // alert while unaffiliated is affiliated implicitly. The returned guard undoes
  // the affiliation unless the request is finally accepted (clause 9.2.2.3.11).
  struct ImplicitAffiliation {
    McServer *server = nullptr;
    std::string user, group;
    const SipResponse *response = nullptr;
    // Exceptions in flight when the guard was made: more at its end means the request failed with an exception,
    // which incoming() answers 403 after this guard is gone.
    int exceptions_at_start = std::uncaught_exceptions();
    ImplicitAffiliation() = default;
    ImplicitAffiliation(const ImplicitAffiliation &) = delete;
    ImplicitAffiliation &operator=(const ImplicitAffiliation &) = delete;

    ~ImplicitAffiliation() {
      if (!server || !response) return;
      if (!implicit_affiliation_cancelled(response->status_code, std::uncaught_exceptions() > exceptions_at_start))
        return;
      if (auto *served = server->by_id(user)) {
        served->groups.erase(group);
        event("implicit_affiliation_cancelled", {{"user_id", user}, {"group_id", group}});
      }
    }
  };

  bool implicitly_affiliate(User &user, const std::string &group, const Json &profile, const SipResponse &response,
                            ImplicitAffiliation &guard);

  // ---- Functional aliases (functional_alias.cpp): TS 24.379 clause 9A, TS 24.281 clause 20 ----
  bool is_functional_alias(const std::string &id);

  bool functional_alias_active(const std::string &alias, const std::string &id) const {
    return functional_aliases_.active(alias, id);
  }

  std::vector<std::string> functional_alias_users(const std::string &alias) const {
    return functional_aliases_.users(alias);
  }

  SipResponse functional_alias_publish(const SipMessage &message, const User &user, const McpttInfo &info,
                                       const std::string &body);

  void deactivate_functional_aliases(const std::string &id);

  // ---- Functional aliases on split servers (functional_alias_split.cpp): TS 24.379 clauses 9A.2.2.2.6, 9A.2.2.2.7
  // and 9A.2.2.3.3 to 9A.2.2.3.5 ----
  bool aliases_owned_elsewhere() const;

  SipResponse served_alias_publish(const SipMessage &message, const User &user, const McpttInfo &info,
                                   const std::string &body);

  void send_alias_onward(const std::string &id, const std::string &alias, bool activation);

  void onward_alias_answered(const std::string &id, const std::string &alias, bool activation, const std::string &pid,
                             int code);

  bool alias_takeover_offered(const std::string &id, const std::string &alias);

  void subscribe_alias_owner(const std::string &id, const std::string &alias);

  void unsubscribe_alias_owner(const std::string &id, const std::string &alias);

  SipResponse owner_alias_notify(const SipMessage &message);

  void deactivate_served_aliases(const std::string &id);

  SipResponse owned_alias_publish(const SipMessage &message, const std::string &peer);

  SipResponse owned_alias_subscribe(const SipMessage &message, const std::string &peer);

  void notify_peer_alias(const std::string &dialog, const std::string &publish_id = {});

  SipResponse alias_subscribe(const SipMessage &message, const User &user, const McpttInfo &info,
                              const std::string &req_type);

  static const BodyPart *resource_lists_part(const SipMessage &message);

  std::string conference_alias(const Session &session, const std::string &user) const;

  std::string alias_binding_refusal(const User &user, const SipMessage &message, const McpttInfo &info);

  SipResponse alias_binding_message(const SipMessage &message, const User &user, const McpttInfo &info);

  const char *alias_user_list() const { return mcx::alias_user_list(svc_.service); }

  void notify_alias_status(const std::string &dialog, const std::string &publish_id = {});

  void alias_status_changed(const std::set<std::string> &users, const std::set<std::string> &aliases,
                            const std::string &publisher = {}, const std::string &publish_id = {});

  // ---- Affiliation (affiliation.cpp): TS 24.379 clause 9.2.2 ----
  void apply_affiliation(User &user, std::set<std::string> groups);

  // TS 24.379 clause 9.2.2.3.3 step 10 a0: of the groups the user leaves, those it may not leave.
  std::set<std::string> deaffiliation_forbidden(const User &user, const std::set<std::string> &leaving);

  void notify(User &user);

  // ---- Group calls (group_call.cpp): TS 24.379 clause 10.1 ----
  std::string pre_established_uri() const;

  void validate_remote(const std::string &user, const MediaDescription &media, bool implicit_allowed = false,
                       bool uncontrolled_allowed = false);

  std::shared_ptr<Leg> make_leg(const std::string &id, const std::shared_ptr<Session> &session);

  bool current_session(const std::shared_ptr<Session> &session) const;

  std::vector<std::shared_ptr<Leg>> session_legs(const Session &session) const;

  bool has_leg(const Session &session, const std::string &id) const;

  void add_leg(const std::shared_ptr<Leg> &leg);

  std::string focus_contact(const Session &session) const { return "<" + session.uri + ">;isfocus" + service_tags(); }

  void invite_member(const std::shared_ptr<Session> &session, const std::string &id);

  void prepare_broadcast_hierarchy(Session &session, const Json &profile, const std::string &type,
                                   const std::string &initiator);

  bool preempt_lower_priority_participant(const std::shared_ptr<Session> &session, const Json &profile,
                                          const std::string &joiner, const McpttInfo &info);

  bool in_priority(const std::string &group) const;

  void invite_chat_members(const std::shared_ptr<Session> &session);

  void fanout(const std::shared_ptr<Session> &session, const std::string &origin);

  void complete_setup(const std::shared_ptr<Session> &session);

  void notify_conference(const std::shared_ptr<Session> &session, bool ending = false);

  void notify_key(const std::string &dialog);

  bool floor_protected(const Leg &leg) const { return leg.session->policy.value("protect_floor", false); }

  ProtectedCall *floor_keys(const User &user) const;

  bool floor_key_ready(const Leg &leg);

  void stop_unkeyed_leg(Leg &leg, const std::string &reason);

  void transmit_floor(Leg &leg, const FloorPacket &packet);

  // ---- Regroup (regroup.cpp): TS 24.379 clause 16 ----
  //------------------------------------------------------------------------------
  // TS 24.379 clause 16: a regroup using a preconfigured group. The controlling
  // function of the preconfigured group creates it and holds it. For a group
  // regroup (clause 16.2) the controlling function of each constituent group is a
  // non-controlling function for it and marks its own group regrouped; for a
  // user regroup (clause 16.3) the participating function of each member notifies it
  // and considers it affiliated. Every function involved keeps the same record.
  // TS 24.379 clauses 16.2.2.4 step 3 b) and d), 16.2.3.1 step 4 c) and e) and 16.2.4.1 step 7 b) and d) (TS 24.281
  // clause 21 likewise): what a regroup request carries on, function to function and on to each member: its MC
  // service information body and all its Accept-Contact and Reject-Contact header fields.
  struct RegroupCarry {
    std::string info;               // the application/vnd.3gpp.mcptt-info+xml (or MCVideo) body, if any
    std::vector<SipHeader> contact; // the Accept-Contact and Reject-Contact header fields, in order
  };

  struct RegroupState {
    std::string preconfigured;       // the group whose configuration the regroup takes
    std::string creator;             // the MCPTT ID that asked for it
    std::vector<std::string> groups; // the constituent groups of a group regroup
    std::vector<std::string> users;  // the members of a user regroup, as far as this function knows them
    // The members of a user regroup considered affiliated with it without
    // asking (TS 24.379 clause 16.3.2.4 step 3h); at the controlling function, those whose
    // participating function accepted the regroup.
    std::set<std::string> affiliated;
    std::string controller;   // the peer controlling the regroup, empty when this server does
    bool controlling = false; // this server created the regroup
    bool temporary = false;   // a temporary group formed by the GMS (TS 24.481 clause 6.3.14)
    // The members of a group regroup told of it here, so that its removal still
    // reaches them after their affiliation to it has gone (the call on a removed
    // temporary group can release them before this function sees the removal).
    std::set<std::string> told;
    RegroupCarry carry; // of the request that created the regroup
  };

  std::map<std::string, RegroupState> regroups_; // by temporary group identity
  std::map<std::string, std::string> regrouped_; // constituent group -> temporary group identity
  std::set<std::string> creating_regroups_;      // identities waiting for other functions to answer

  // The controlling function of a constituent group, empty when it is this one.
  // TS 24.379 clause 16.2.3.1 step 4a: that function is the non-controlling function of the regroup.
  std::string non_controlling(const std::string &group) const { return group_controller(group); }

  bool is_regrouped(const std::string &group) const { return regrouped_.contains(group); }

  bool regroup_vouched(const std::string &regroup, const std::string &peer) const;

  bool regroup_identity_taken(const std::string &id);

  const std::string *regroup_part(const SipMessage &message) const;

  std::vector<SipHeader> function_headers(const std::string &peer) const;

  SipResponse regroup_message(const SipMessage &message, User &user, const std::string &body);

  SipResponse regroup_create(const SipMessage &message, User &user, const Regroup &regroup);

  //------------------------------------------------------------------------------
  // A group regroup being created: the answers of the non-controlling functions awaited
  // (TS 24.379 clause 16.2.3.1 steps 4 to 7).
  struct PendingRegroup {
    std::string transaction, creator, warning;
    Regroup regroup;
    RegroupCarry carry;
    std::size_t outstanding = 0;
    bool failed = false;
    std::vector<std::string> accepted; // the non-controlling functions that said yes
  };

  void regroup_answered(const std::shared_ptr<PendingRegroup> &pending, const std::string &owner, int status,
                        const std::string &warning);

  RegroupState &regroup_store(const Regroup &regroup, const std::string &creator, bool controlling,
                              const std::string &controller = {}, const RegroupCarry &carry = {});

  RegroupCarry regroup_carry(const SipMessage &message) const;

  void send_regroup(const std::string &uri, const Regroup &regroup, const RegroupCarry &carry,
                    std::vector<SipHeader> headers, bool to_user, SipResponseHandler handler = {});

  //------------------------------------------------------------------------------
  // TS 24.379 clause 16.3.3.1: the controlling function of the preconfigured group offers a user
  // regroup to the participating function of each member, and creates it once
  // any of them has accepted.
  struct PendingUserRegroup {
    std::string transaction, creator;
    Regroup regroup;
    RegroupCarry carry;
    std::size_t outstanding = 0;
    std::vector<std::string> local; // members served by this server's own participating function
    std::set<std::string> accepted; // members whose participating function accepted
  };

  SipResponse regroup_user_create(const SipMessage &message, const User &user, const Regroup &regroup);

  void regroup_user_answered(const std::shared_ptr<PendingUserRegroup> &pending, const std::vector<std::string> &ids,
                             int status);

  SipResponse regroup_user_finish(const PendingUserRegroup &pending);

  SipResponse regroup_from_function(const std::string &peer, const std::string &body, const RegroupCarry &carry);

  void regroup_relayed(const std::string &peer, const std::string &body);

  void regroup_discard(const std::string &id, const RegroupState state);

  SipResponse regroup_remove(const User &user, const Regroup &regroup, const RegroupCarry &carry);

  void regroup_teardown(const std::string &id, const RegroupState state, const std::string &by,
                        const RegroupCarry &carry = {});

  bool regroup_decide_remove(const std::string &id);

  void regroup_member_added(const std::string &user, const std::string &group);

  void end_group_calls(const std::string &group);

  void regroup_notify(const Regroup &regroup, bool created, const std::set<std::string> &was_told = {},
                      const RegroupCarry &carry = {});

  void regroup_user_notify(Regroup notice, const std::vector<std::string> &ids, bool created,
                           const RegroupCarry &carry = {});

  // ---- Private calls (private_call.cpp): TS 24.379 clause 11.1 ----
  Json user_profile(const std::string &id);

  Json callee_private_policy(const std::string &id);

  std::optional<std::string> protected_private_refusal(const User &user, const MediaDescription &media,
                                                       bool first_to_answer) const;

  std::optional<std::string> kms_redirect(const std::string &mikey, const std::string &callee) const;

  std::optional<std::string> protected_callee_refusal(const User &callee) const;

  Json private_call_policy() const;

  std::size_t private_calls(const std::string &id, const Session *except = nullptr) const;

  bool in_call(const std::string &id) const;

  // ---- Ambient listening and viewing (ambient.cpp): TS 24.379 clause 11.1.6, TS 24.281 clause 15 ----
  SipResponse ambient_invite(const SipMessage &message, const User &user, const McpttInfo &info);

  void ambient_floor(const std::shared_ptr<Session> &session, Leg &joined);

  void release_ambient(const std::shared_ptr<Session> &session, const std::string &reason);

  std::shared_ptr<Session> releasing_ambient(const std::vector<std::string> &users);

  void release_ambient_listening(const Session &session);

  std::string ambient_release_caps() const;

  std::string ambient_reason(const char *kind) const;

  void release_listened_to(const std::string &id, const std::string &reason);

  bool release_relayed_ambient(const std::string &id, const std::string &reason, std::function<void()> then = {});

  std::shared_ptr<Relay> releasing_relay(const std::vector<std::string> &users);

  void ambient_bye_from_participant(const SipMessage &message);

  // ---- Private calls (private_call.cpp): TS 24.379 clause 11.1 ----
  SipResponse private_invite(const SipMessage &message, const User &user, const McpttInfo &info);

  void invite_private_target(const std::shared_ptr<Session> &session, const std::string &target);

  bool private_resource_priority_allowed(const SipMessage &message, const PriorityState &state,
                                         bool emergency_requested) const;

  SipResponse private_reinvite(const SipMessage &message, const User &user, McpttInfo info,
                               const std::shared_ptr<Leg> &leg);

  void select_first_answer(const std::shared_ptr<Session> &session, const std::shared_ptr<Leg> &winner);

  void release_not_selected(Leg &leg);

  void revalidate_private(const std::shared_ptr<Session> &session);

  // ---- Ad hoc group calls and alerts (adhoc.cpp): TS 24.379 clauses 17 and 12.1A ----
  Json adhoc_call_policy() const;

  unsigned session_policy_timeout(const char *key, unsigned fallback) const;

  std::string adhoc_group_identity() const;

  std::shared_ptr<Leg> incoming_leg(const SipMessage &message, const User &user,
                                    const std::shared_ptr<Session> &session);

  SipResponse adhoc_invite(const SipMessage &message, const User &user, const McpttInfo &info);

  void invite_adhoc_member(const std::shared_ptr<Session> &session, const std::string &id);

  std::vector<std::string> resolve_participant_criteria(const std::string &text, const std::string &initiator);

  void add_adhoc_participant(const std::shared_ptr<Session> &session, const std::string &id);

  void remove_adhoc_participant(const std::shared_ptr<Session> &session, const std::string &id);

  void apply_participant_criteria(const std::shared_ptr<Session> &session);

  SipResponse adhoc_modify(const SipMessage &message, const User &user, const McpttInfo &info,
                           const std::shared_ptr<Leg> &leg);

  void send_adhoc_alert(const AdhocAlert &alert, const std::string &group, const std::string &target, bool active);

  void update_adhoc_alert(const std::string &group);

  void send_adhoc_alert_receipt(const std::string &group, const std::string &id, const std::string &client, bool active,
                                const std::string &criteria);

  SipResponse adhoc_alert_message(const SipMessage &message, const User &user, const McpttInfo &info);

  // ---- Services relayed by SIP MESSAGE (private_services.cpp): TS 24.379 clauses 10.1.5 and 11.1.5 to 11.1.9 ----
  void relay_service_message(const User &target, McpttInfo info, bool keep_request_uri = false);

  SipResponse private_service_message(const SipMessage &message, const User &user, McpttInfo info);

  // ---- Ad hoc group calls (adhoc.cpp): TS 24.379 clause 17 ----
  void revalidate_adhoc(const std::shared_ptr<Session> &session);

  // ---- Group document subscriptions (group_documents.cpp): TS 24.481 clause 6.3.13 ----
  // This server is the SIP front of the GMS: its PSI is the subscription proxy
  // function's (clause 6.3.13.3.2) and the PSI for accessing documents (clause 6.3.13.3.3). The
  // GMS itself is reached over HTTP: a change of a group document shows as a new
  // entity tag in its internal view, and is notified as an xcap-diff of RFC 5874.
  //------------------------------------------------------------------------------
  // A subscription received as the subscription proxy function (TS 24.481 clause 6.3.13.3.2).
  struct DocSubscription {
    std::string subscriber;                   // the authenticated identity: an MCPTT ID
    std::map<std::string, std::string> etags; // group ID -> entity tag last notified ("" before)
    std::int64_t expires = 0;
    bool pending = false, initial = true;
    bool server = false; // an MCS server of this system (clause 6.3.13.2.2), which may follow any group
    std::uint64_t next_poll = 0;
  };

  std::map<std::string, DocSubscription> doc_subscriptions_;

  Counters docsub_counters_{"subscriptions", "notifies", "refused"};

  void docsub_count(const char *key) { docsub_counters_.add(key); }

  static constexpr const char *groups_auid = "org.openmobilealliance.groups/global/byGroupID/";

  std::string xcap_root() const;

  static std::vector<std::string> subscribed_groups(const std::string &list);

  bool group_exists(const std::string &group);

  bool subscription_allowed(const std::string &group, const std::string &identity);

  Json docsub_status() const;

  SipResponse doc_subscribe(const SipMessage &message, const std::string &identity,
                            const std::vector<std::string> &groups, bool server = false);

  bool is_mcs_server(const std::string &identity) const;

  static std::string xcap_diff(const std::string &root,
                               const std::vector<std::tuple<std::string, std::string, std::string>> &docs);

  void notify_documents(const std::string &dialog);

  void end_doc_subscription(const std::string &dialog);

  void docsub_tick(std::uint64_t now);

  // ---- Location from the SEAL location management server (seal_location.cpp): TS 24.545 ----
  // This server is a VAL server of TS 24.545 (V19.4.0): it subscribes to users'
  // location at its system's location management server (clause 6.2.6.1.2), is notified
  // of it (clause 6.2.7) and asks for it on demand (clause 6.2.8.1). Having no HTTP listener, it receives the
  // notifications on a long-poll channel at the location management server, read
  // by a thread of its own.
  //------------------------------------------------------------------------------
  // The long-poll channel of the location notifications (TS 24.545 clause 6.2.7).
  struct SealChannel {
    std::mutex mutex;
    std::deque<std::string> received;
    std::atomic<bool> running{true};
  };

  std::shared_ptr<SealChannel> seal_channel_;

  void seal_stop_channel();
  std::string seal_subscription_;
  Json seal_status_ = {
      {"subscription", ""}, {"notifications", 0}, {"positions", Json::object()}, {"history", Json::object()}};

  std::string seal_root() const;

  HttpResponse seal_post(const std::string &path, const std::string &body);

  static std::vector<std::string> comma_list(const std::string &text);

  void seal_record(const seal::Answer &answer, const char *how);

  void seal_subscribe(const std::string &users, unsigned interval, unsigned expiry);

  void seal_unsubscribe();

  void seal_locate(const std::string &users, bool history);

  void seal_command(const std::string &command);

  void seal_tick();

  // ---- Temporary groups formed by the GMS (temporary_groups.cpp): TS 24.481 clauses 6.3.14 and 6.3.15 ----
  // The GMS combines groups into a temporary group: its document lists the
  // constituent groups (<on-network-temporary>), and each constituent group's
  // document names the temporary group (<on-network-regrouped>), whichever
  // system's GMS holds it. This server reads both from its GMS and applies them
  // as a group regroup (TS 24.379 clause 16), with the temporary group's own
  // document as its configuration: the function controlling the temporary group
  // holds it, the function controlling each constituent group marks that group
  // regrouped (warning 148), and each tells the affiliated members of its own
  // constituent groups. A call on the temporary group is a group regroup call
  // (TS 24.379 clause 10.1.2.4.1 steps 5 and 6b). When the GMS removes the documents, the
  // temporary group ends, and its call with it.
  std::uint64_t next_temporary_poll_ = 0;

  void temporary_tick(std::uint64_t now);

  // A common service that did not answer is not polled for a while, so that the
  // document subscriptions do not hold this server up while it restarts.
  std::map<std::string, std::uint64_t> service_down_until_;

  bool service_down(const std::string &role) const;

  void service_failed(const std::string &role);

  // ---- Configuration management document subscriptions (configuration.cpp): TS 24.484 clause 6.3.13 ----
  // This server is also the SIP front of the CMS: its PSI serves as the PSI for
  // performing the CMS's subscription proxy function. A user subscribes to several
  // configuration management documents at once (its UE configuration and user profile
  // documents, the service configuration), whose entity tags are read from the CMS.
  //------------------------------------------------------------------------------
  // A user's subscription to configuration management documents (TS 24.484 clause 6.3.13.3.2.2).
  struct ConfigSubscription {
    std::string subscriber;
    // AUID, XUI and document name of each followed document -> entity tag last notified.
    std::map<std::tuple<std::string, std::string, std::string>, std::string> etags;
    std::int64_t expires = 0;
    bool pending = false, initial = true;
    std::uint64_t next_poll = 0;
  };

  std::map<std::string, ConfigSubscription> config_subscriptions_;
  Counters configsub_counters_{"subscriptions", "notifies", "refused"};
  // The documents one configuration subscription follows at most.
  static constexpr std::size_t max_config_documents = 8;

  static std::vector<ConfigDocument> subscribed_configuration(const std::string &list);

  std::map<std::tuple<std::string, std::string, std::string>, std::string>
  followed_configuration(const std::string &identity, const std::vector<ConfigDocument> &documents,
                         const ConfigSubscription *current);

  SipResponse config_subscribe(const SipMessage &message, const std::string &identity,
                               const std::vector<ConfigDocument> &documents);

  void notify_configuration(const std::string &dialog);

  // ---- The shared service parts (src/server/parts): location (TS 24.379 clause 13, TS 24.281 clause 18) ----
  //------------------------------------------------------------------------------
  // The host of this server's service parts (service_parts.cpp, location.cpp, split.cpp): the users, peers,
  // service information and protection the shared procedures need, called per request.
  class PartsGlue final : public LocationHost, public PeerRegistrationHost {
  public:
    explicit PartsGlue(McServer &server) : server_(server) {}

    // ServiceHost (service_parts.cpp).
    std::vector<BodyPart> seal_for_client(const std::string &sip, std::vector<BodyPart> parts) override;
    std::vector<BodyPart> seal_for_peer(const std::string &peer, std::vector<BodyPart> parts) override;
    [[nodiscard]] bool peer_known(const std::string &peer) const override;
    [[nodiscard]] std::string peer_uri(const std::string &peer) const override;
    [[nodiscard]] std::vector<SipHeader> route_to(const std::string &peer,
                                                  std::vector<SipHeader> headers) const override;
    [[nodiscard]] std::string service_uri() const override;
    Json common_document(const std::string &role, const std::string &path) override;
    void send_message(const std::string &uri, const std::string &type, const std::string &body,
                      const std::vector<SipHeader> &headers, SipResponseHandler handler) override;
    void publish(const std::string &uri, const std::string &type, const std::string &body,
                 const std::vector<SipHeader> &headers, SipResponseHandler handler) override;
    void respond(const std::string &transaction, const SipResponse &response) override;
    void schedule(std::function<void()> task) override;
    // LocationHost (location.cpp).
    [[nodiscard]] Json location_settings() const override;

    [[nodiscard]] std::string location_warning(std::string_view text) const override {
      return server_.warning_value(text);
    }

    Json location_profile(const std::string &id) override;
    std::optional<LocationUser> location_user_by_id(const std::string &id) override;
    std::optional<LocationUser> location_user_by_sip(const std::string &sip) override;
    void each_location_user(const std::function<void(const std::string &id, const std::string &peer)> &visit) override;
    bool location_group_member(const std::string &group, const std::string &id) override;
    std::vector<std::string> location_alias_users(const std::string &alias) override;
    LocationInfo location_info(const SipMessage &message, const BodyPart &info_part) override;
    std::vector<BodyPart> location_info_parts(const LocationInfo &info) override;
    // PeerRegistrationHost (split.cpp).
    [[nodiscard]] const PeerMap &peer_table() const override;
    std::string registration_group_controller(const std::string &group) override;
    [[nodiscard]] std::uint64_t registration_refresh_ms() const override;
    void each_registration_user(const std::function<void(const PeerUser &)> &visit) override;
    std::optional<int> registration_refusal(const SipMessage &message, Affiliation &affiliation,
                                            std::uint64_t &expires_s) override;
    std::optional<PeerUser> registration_user(const std::string &sip) override;
    std::optional<PeerUser> registration_user_by_id(const std::string &id) override;
    bool registration_group_allowed(const std::string &group, const std::string &id, const std::string &peer) override;
    void withdraw_peer_user(const std::string &sip, const std::string &id) override;
    void update_peer_user(const std::string &sip, const Affiliation &affiliation, const std::string &peer,
                          const std::set<std::string> &groups, std::uint64_t expires_s) override;
    void peer_user_changed(const std::string &sip, const std::optional<PeerUser> &previous,
                           std::set<std::string> groups) override;

  private:
    McServer &server_;
  };

  PartsGlue parts_glue_{*this};
  LocationService location_{parts_glue_, svc_, core_location_traits};
  PeerRegistration peer_registration_{parts_glue_, svc_};

  std::string own_service_uri() const { return cfg_.at(svc_.name).at("service_uri"); }

  // TS 24.379 clause 13.2.5: a request relayed to a client, without location requests and configurations.
  std::pair<std::string, std::string> without_location_requests(const std::string &type, const std::string &body);

  // ---- SIP dispatch (sip_dispatch.cpp) ----
  SipResponse incoming(const SipMessage &message);

  void send_priority_correction(std::string_view dialog);

  // ---- SIP dialog state (server.cpp) ----
  void state(std::string_view dialog, SipCallState state, int code);

  // ---- Disconnection and floor control notices (notices.cpp): TS 24.380 clause 6.3 ----
  void disconnect_user(const std::string &id, const std::shared_ptr<Session> &only = {});

  void send_notice(Leg &leg, const FloorNotice &notice);

  void notices(const Session &session, const std::vector<FloorNotice> &floor_notices);

  static bool reachable_via_hierarchy(const Session &session, const User &user);

  bool regroup_affiliated(const User &user, const std::string &group) const;

  bool eligible(const Leg &leg);

  // ---- Media relay (media.cpp): TS 24.380 clause 6.3, TS 24.581 clause 6.3 ----
  void audio_packet(Leg &leg, const Datagram &datagram);

  void unpermitted_media(Leg &leg);

  void unpermitted_media_tick(const Session &session, std::uint64_t now);

  // ---- MBMS listening status reports (multicast.cpp): TS 24.379 clauses 14.2.3 and 14.2.4 ----
  [[nodiscard]] bool multicast_leg(const Leg &leg) const;

  [[nodiscard]] bool multicast_video_leg(const Leg &leg) const;

  [[nodiscard]] const std::string *mbms_usage_part(const SipMessage &message) const;

  SipResponse mbms_usage_message(const SipMessage &message, const User &user, const std::string &body);

  [[nodiscard]] std::string multicast_listening_refusal(const User &user, const MbmsListeningStatus &status) const;

  void publish_multicast_listening();

  // The users whose latest listening status report for a session is "listening" (MC service ID, session URI;
  // TS 24.379 clause 14.2.3).
  std::set<std::pair<std::string, std::string>> multicast_listening_;

  // ---- MBMS bearers (mbms.cpp): TS 24.379 clause 14.2, TS 24.281 clause 16.3, TS 24.380 clause 10 ----
  [[nodiscard]] MbmsService mbms_service() const;

  void mbms_setup();

  [[nodiscard]] std::string mbms_announcement_sdp() const;

  [[nodiscard]] std::vector<MbmsAnnouncement> mbms_announcements() const;

  void mbms_announce(const User &user);

  void mbms_tick(std::uint64_t now);

  void send_general_purpose(std::span<const std::uint8_t> packet, const MbmsBearerConfig &bearer);

  std::string mbms_general_purpose_status(const User &user, const MbmsListeningStatus &status);

  void publish_mbms_status();

  // TS 24.380 clause 10.2 (TS 24.581 clause 10.2): the participating function's MBMS subchannel control state
  // machine of a conversation in 'M: A conversation is active': its group and session, the bearer and the MBMS
  // subchannel allocated from its pool (the host group's tmgi is the bearer's), and timers T15 (Conversation), T16
  // (Map Group To Bearer) and T17 (Unmap Group To Bearer) with counter C17, as deadlines (0: not running).
  struct MbmsConversation {
    std::string group, session_uri;
    const MbmsBearerConfig *bearer = nullptr;
    MulticastDestination channel;
    std::uint64_t t15 = 0, t16 = 0, t17 = 0;
    unsigned c17 = 0;
  };
  struct MbmsTimers {
    std::uint64_t t15 = 30000, t16 = 500, t17 = 200;
    unsigned c17 = 3;
  };

  [[nodiscard]] SubchannelMessage mbms_message(SubchannelMessageType type, const MbmsConversation &conversation) const;

  const MulticastDestination *mbms_conversation_start(const Session &session);

  void send_subchannel(std::span<const std::uint8_t> packet, const Session &session, bool video = false);

  void mbms_map(MbmsConversation &conversation, std::uint64_t now);

  void mbms_unmap(MbmsConversation &conversation, std::uint64_t now);

  void mbms_release(const std::string &session_uri, const char *reason);

  void mbms_conversation_tick(std::uint64_t now);

  MbmsTimers mbms_timers_;
  std::map<std::string, MbmsConversation> mbms_conversations_;

  // The "mbms" block, the socket of the general purpose and MBMS subchannels and the SSRC of this participating
  // function on them; none when not configured. The users the bearers were announced to, and the TMGIs whose general
  // purpose subchannel each user reported listening to (TS 24.379 clause 14.2.3).
  std::optional<MbmsConfig> mbms_;
  std::unique_ptr<UdpSocket> mbms_socket_;
  std::uint32_t mbms_ssrc_ = 0;
  std::uint64_t mbms_next_announcement_ = 0;
  std::set<std::string> mbms_announced_;
  std::map<std::string, std::set<std::string>> mbms_general_purpose_;

  // ---- XML integrity protection (xml_protection.cpp): TS 24.379 clause 6.6.3, TS 33.180 clause 9.3.5 ----
  // Each XML body of a message is signed with HMAC-SHA256 under the integrity key of
  // the hop's XPK, in an application/vnd.3gpp.mcptt-signed+xml body; on receipt the
  // signatures are verified before anything is decrypted (TS 24.379 clause 6.6.1.4), and removed.
  static constexpr const char *signed_mime = "application/vnd.3gpp.mcptt-signed+xml";
  static constexpr const char *signed_ns = "urn:3gpp:ns:mcpttSignedDoc:1.0";
  unsigned xml_signed_ = 0, xml_verified_ = 0;

  bool integrity_protection() const;

  bool signable_part(const std::string &type) const;

  std::vector<BodyPart> sign_parts(std::vector<BodyPart> parts, const xmlsec::Key &key);

  std::vector<BodyPart> verify_parts(std::vector<BodyPart> parts, const std::optional<xmlsec::Key> &key);

  // ---- XML confidentiality protection (xml_protection.cpp): TS 24.379 clause 6.6.2, TS 33.180 clause 9.3.4 ----
  // The XML elements and attribute URIs of TS 24.379 clause 4.8 are encrypted with the XPK of
  // the hop: the client's CSK towards a client, the SPK towards a peer server. The
  // SIP engine applies it to every message, just before sending and on receipt.
  unsigned xml_encrypted_ = 0, xml_decrypted_ = 0, xml_refused_ = 0;

  bool xml_protection() const;

  bool mcptt_xml_part(const std::string &type) const;

  // TS 24.379 clause 4.8, TS 24.281 clause 4.8: the sensitive data in this server's service's names.
  const xmlsec::Profile &mcptt_xml_profile() const { return xmlsec::signalling_profile(svc_.info_prefix); }

  static std::string bare_uri(std::string uri);

  std::optional<xmlsec::Key> user_xml_key(const std::string &sip) const;

  std::optional<xmlsec::Key> peer_xml_key(const std::string &peer, bool sending) const;

  std::vector<BodyPart> protect_outgoing(const SipTransmission &transmission, std::vector<BodyPart> parts);

  std::optional<xmlsec::Key> key_by_id(const SipTransmission &transmission, std::uint32_t id) const;

  std::vector<BodyPart> protect_incoming(const SipTransmission &transmission, std::vector<BodyPart> parts);

  // ---- Split of the call procedures (private_call, adhoc, private_services, ambient, video_push_pull) ----
  // The invitees of a private or first-to-answer call that pass the terminating checks (TS 24.379 clause
  // 11.1.1.3.2), the rejection of the last one that did not, and the forwarding on no answer of the callee.
  struct PrivateCallees {
    std::vector<std::string> reachable;
    PrivateCallDecision last_rejection{480, ""};
    std::string no_answer_target;
    unsigned no_answer_timeout = 0;
  };

  // private_call.cpp: rejects a private call INVITE with the status and Warning.
  SipResponse private_call_rejected(SipResponse &response, const User &user, int status,
                                    const std::string &warning = {});
  // private_call.cpp: TS 24.379 clause 11.1.1.3.1.1 steps 3 to 8, the caller and the resource list.
  std::optional<SipResponse> private_invite_admission(const SipMessage &message, const User &user,
                                                      const McpttInfo &info, SipResponse &response,
                                                      const BodyPart *&resources);
  // private_call.cpp: TS 24.379 clause 11.1.1.3.1.1 steps 11A and 12, the invitees of a first-to-answer call.
  std::optional<SipResponse> first_to_answer_invitees(const User &user, const McpttInfo &info,
                                                      const BodyPart &resources, SipResponse &response,
                                                      std::vector<std::string> &invitees, bool &list_exempt);
  // private_call.cpp: TS 24.379 clause 11.1.1.3.1.1 steps 9 to 11, the called user of a private call.
  std::optional<SipResponse> private_call_target(const SipMessage &message, const User &user, const McpttInfo &info,
                                                 const BodyPart &resources, SipResponse &response,
                                                 PrivateCallRequest &request, std::vector<std::string> &invitees,
                                                 bool &list_exempt);
  // private_call.cpp: TS 24.379 clause 11.1.1.3.1.1 steps 11c and 11d, the transfer or forwarding mapping.
  std::optional<SipResponse> private_call_mapping_refusal(const User &user, const McpttInfo &info,
                                                          const PrivateCallRequest &request, SipResponse &response,
                                                          Json &caller_policy);
  // private_call.cpp: TS 24.379 clause 11.1.8.2.2, the call a transferred call replaces (RFC 3891).
  std::optional<SipResponse> private_call_replaced(const std::string &replaces, const User &user, const McpttInfo &info,
                                                   bool first_to_answer, const PrivateCallRequest &request,
                                                   SipResponse &response, std::shared_ptr<Session> &replaced);
  // private_call.cpp: TS 24.379 clauses 6.3.3.1.13.1 and 6.3.3.1.13.2, emergency call and alert authorisation.
  std::optional<SipResponse> private_call_emergency(const SipMessage &message, const User &user, const McpttInfo &info,
                                                    bool first_to_answer, const PrivateCallRequest &request,
                                                    std::vector<std::string> &invitees, SipResponse &response,
                                                    PriorityState &priority, std::optional<McpttInfo> &correction);
  // private_call.cpp: TS 24.379 clause 11.1.1.3.1.1 steps 1 and 14, Resource-Priority, media and KMS.
  std::optional<SipResponse> private_call_media_refusal(const SipMessage &message, const User &user,
                                                        const McpttInfo &info, bool first_to_answer,
                                                        const PrivateCallRequest &request,
                                                        const PriorityState &priority, SipResponse &response);
  // private_call.cpp: TS 24.379 clause 11.1.1.3.2 steps 4 to 11, one invitee at the terminating function.
  std::optional<SipResponse> private_invitee_check(const SipMessage &message, const User &user, const McpttInfo &info,
                                                   bool first_to_answer, const std::string &target, unsigned limit,
                                                   const Session *replaced, SipResponse &response,
                                                   PrivateCallees &callees);
  // private_call.cpp: TS 24.379 clause 11.1.1.4.1, the session of a private or first-to-answer call.
  std::shared_ptr<Session> make_private_session(const SipMessage &message, const User &user, const McpttInfo &info,
                                                bool first_to_answer, bool list_exempt, const BodyPart &resources,
                                                const PrivateCallRequest &request, const PriorityState &priority,
                                                const std::shared_ptr<Session> &replaced, const std::string &replaces,
                                                const PrivateCallees &callees, const Json &policy);
  // private_call.cpp: TS 24.379 clause 11.1.1.4.2, the caller's leg and provisional answer.
  std::optional<SipResponse> private_caller_answer(const SipMessage &message, const User &user, const McpttInfo &info,
                                                   bool first_to_answer, const PrivateCallRequest &request,
                                                   const PriorityState &priority,
                                                   const std::optional<McpttInfo> &correction,
                                                   const std::shared_ptr<Session> &session, SipResponse &response);
  // private_call.cpp: TS 24.379 clause 11.1.1.4.1, invite the invitees once ambient or relayed calls end.
  void schedule_private_invitations(const std::shared_ptr<Session> &session);
  // private_call.cpp: rejects a private call re-INVITE, with the unchanged state when asked.
  SipResponse private_priority_rejected(SipResponse &response, const User &user, const McpttInfo &info,
                                        const PriorityState &state, int status, const std::string &warning,
                                        bool with_state = false);
  // private_call.cpp: RFC 5359 section 2.1, hold and resume of a private call.
  std::optional<SipResponse> private_hold_resume(const SipMessage &message, const User &user, const McpttInfo &info,
                                                 const std::shared_ptr<Leg> &leg, const Session &session);
  // private_call.cpp: TS 24.379 clauses 11.1.1.4.3 and 11.1.1.4.4 step 3, emergency upgrade or cancellation.
  std::optional<SipResponse> private_priority_request(const SipMessage &message, const User &user,
                                                      const McpttInfo &info, const Session &session,
                                                      SipResponse &response, PriorityState &next,
                                                      std::optional<McpttInfo> &correction);
  // private_call.cpp: TS 24.379 clauses 11.1.1.4.5 and 11.1.1.4.6, re-INVITE the other party.
  void notify_private_priority_change(const Session &session, const std::shared_ptr<Leg> &leg, const User &user,
                                      const McpttInfo &info, const std::vector<SipHeader> &headers);
  // adhoc.cpp: rejects an ad hoc group call INVITE with the status and Warning.
  SipResponse adhoc_rejected(SipResponse &response, const User &user, int status, const std::string &warning = {});
  // adhoc.cpp: TS 24.379 clause 17.4.4.1.1, rejoin an ad hoc group call by its session identity.
  SipResponse adhoc_rejoin(const SipMessage &message, const User &user, const McpttInfo &info, SipResponse &response,
                           McpttInfo &answer);
  // adhoc.cpp: TS 24.379 clause 17.4.2.2 steps 7A and 7B, a call on the ad hoc group of an emergency alert.
  std::optional<SipResponse> adhoc_alert_group_join(const SipMessage &message, const User &user, const McpttInfo &info,
                                                    SipResponse &response, McpttInfo &answer);
  // adhoc.cpp: TS 24.379 clause 17.4.2.2 steps 7A and 12, the listed invitees.
  std::optional<SipResponse> adhoc_listed_invitees(const SipMessage &message, const User &user, const McpttInfo &info,
                                                   bool alert_group, SipResponse &response,
                                                   std::vector<std::string> &invitees);
  // adhoc.cpp: TS 24.379 clause 17.4.2.2 steps 3B to 3D, priority and Resource-Priority.
  std::optional<SipResponse> adhoc_priority(const SipMessage &message, const User &user, const McpttInfo &info,
                                            const Json &adhoc_policy, SipResponse &response, PriorityState &priority);
  // adhoc.cpp: TS 24.379 clause 17.4.2.2 steps 12b and 12c, functional aliases and participant criteria.
  std::optional<SipResponse> adhoc_resolve_invitees(const User &user, const McpttInfo &info, bool has_criteria,
                                                    const Json &service_policy, SipResponse &response,
                                                    std::vector<std::string> &invitees,
                                                    std::map<std::string, std::string> &via_alias);
  // adhoc.cpp: TS 24.379 clause 17.4.2.2 steps 10 to 16, the session of a new ad hoc group call.
  std::shared_ptr<Session> make_adhoc_session(const User &user, const McpttInfo &info, bool alert_group,
                                              bool has_criteria, const PriorityState &priority,
                                              const std::vector<std::string> &invitees,
                                              const std::map<std::string, std::string> &via_alias);
  // adhoc.cpp: TS 24.379 clause 17.4.2.1.1, invite the listed users of a new ad hoc group call.
  void schedule_adhoc_invitations(const std::shared_ptr<Session> &session, const std::vector<std::string> &invitees);
  // private_services.cpp: rejects a service request relayed by SIP MESSAGE.
  SipResponse private_service_rejected(SipResponse &response, const User &user, int status, const std::string &warning);
  // private_services.cpp: TS 24.379 clause 10.1.5.4, relay a remotely initiated group call request or response.
  SipResponse relay_remote_group_call(const User &user, McpttInfo &info, const std::string &target,
                                      const User &recipient, const std::string &service_type);
  // private_services.cpp: TS 24.379 clause 10.1.4.4, TS 24.281 clause 9.2.4.4, relay a group selection change.
  SipResponse relay_group_selection_change(const User &user, McpttInfo &info, const std::string &target,
                                           const User &recipient, const std::string &service_type);
  // private_services.cpp: TS 24.379 clauses 11.1.5.4 to 11.1.9.4, authorise a private call service request.
  std::optional<SipResponse> authorize_private_service(const User &user, McpttInfo &info, const std::string &target,
                                                       const Json &policy, const std::string &type,
                                                       SipResponse &response);
  // ambient.cpp: rejects an ambient listening call INVITE with the status and Warning.
  SipResponse ambient_rejected(SipResponse &response, const User &user, int status, const std::string &warning = {});
  // ambient.cpp: TS 24.379 clause 11.1.6.3.1.1 steps 4 to 8, the type, listed user and caller's ruleset.
  std::optional<SipResponse> ambient_caller_checks(const SipMessage &message, const User &user, const std::string &type,
                                                   SipResponse &response, PrivateCallRequest &request);
  // ambient.cpp: TS 24.379 clause 11.1.6.3.1.1 step 9, the media offer.
  std::optional<SipResponse> ambient_media_refusal(const SipMessage &message, const User &user, const std::string &type,
                                                   SipResponse &response);
  // ambient.cpp: TS 24.379 clause 11.1.6.3.2.1 steps 4 and 5, the invited user.
  std::optional<SipResponse> ambient_callee_refusal(const SipMessage &message, const User &user,
                                                    const PrivateCallRequest &request, SipResponse &response);
  // ambient.cpp: TS 24.379 clause 11.1.6.3.1.1 step 13, the session of an ambient listening call.
  std::shared_ptr<Session> make_ambient_session(const SipMessage &message, const User &user, const std::string &type,
                                                const PrivateCallRequest &request, const Json &policy);
  // ---- end of split ----

  // ---- Run loop (server.cpp) ----
  void tick();

  // ---- Split of incoming(), tick(), state(), floor_packet() (sip_dispatch.cpp, server.cpp, floor_control.cpp) ----
  // incoming() (sip_dispatch.cpp). Each procedure answers in `response`, the answer incoming() returns; the ones
  // returning bool return true when `response` is final, false when the request goes on to the next procedure.
  // TS 24.379 clauses 6.6.1.4 and 6.6.2.4.2: refusal of content that cannot be verified or decrypted.
  void refuse_unprotectable(const SipMessage &message, SipResponse &response);
  // A request from a peer MCPTT/MCVideo server (TS 24.379 clauses 13, 16).
  bool peer_request(const SipMessage &message, const std::string &peer, const std::string &event_name,
                    SipResponse &response);
  // TS 24.379 clauses 9.2.2.3.3 and 9A.2.2.3: affiliation or functional alias PUBLISH from a peer server.
  bool peer_presence_publish(const SipMessage &message, const std::string &peer, SipResponse &response);
  // The terminating participating function: an INVITE or MESSAGE from a peer for a user served here.
  bool terminating_request(const SipMessage &message, const std::string &peer, SipResponse &response);
  // TS 24.379 clause 7.3.3: service authorisation (PUBLISH of poc-settings).
  void service_authorization(const SipMessage &message, SipResponse &response);
  // TS 24.379 clause 7.3.5: log-off (PUBLISH of poc-settings with Expires 0).
  void service_log_off(const SipMessage &message, SipResponse &response);
  // TS 24.379 clause 7.3.5 steps 3 and 4, clause 7.3.3 step 8: the end of a served user's service settings and the
  // removal of its binding.
  void remove_binding(std::map<std::string, User>::iterator found, const char *reason);
  [[nodiscard]] std::optional<SipResponse> plain_reinvite(const SipMessage &message, const User &user);
  // TS 24.379 clause 7.3.2: service authorisation by third-party REGISTER.
  void third_party_register(const SipMessage &message, SipResponse &response);
  // TS 24.379 clause 7.2.1 with clause 6.6.1.4: open the bodies of a client's REGISTER that uploads no CSK with the
  // CSK held for the public user identity.
  bool open_register_parts(const std::string &identity, std::vector<BodyPart> &parts, SipResponse &response);
  // TS 24.379 clause 6.6.2: accept the uploaded CSK and open the protected parts with it.
  bool open_with_uploaded_csk(const SipMessage &message, SipMessage &opened,
                              std::optional<keying::KeyMessage> &uploaded, std::string &uploader,
                              SipResponse &response);
  // TS 24.379 clause 7.3.3: bind the service authorised user.
  void bind_authorized_user(const Json &claims, const McpttInfo &info, const std::string &asserted,
                            std::map<std::string, User>::iterator old, std::string_view match, bool unknown_etag,
                            const std::optional<keying::KeyMessage> &uploaded, const std::string &uploader,
                            const std::string &profile, SipResponse &response);
  // TS 24.481 clause 6.3.13.2.2: an MCS server of this system subscribes to group documents.
  void server_document_subscribe(const SipMessage &message, const std::string &identity, SipResponse &response);
  // A request from an authenticated served user, dispatched by method and event package.
  void user_request(const SipMessage &message, User &user, const std::string &event_name, SipResponse &response);
  // TS 24.481 and TS 24.484 clauses 6.3.13.3.2.2: a client's group or configuration document subscription.
  bool client_document_subscribe(const SipMessage &message, const User &user, SipResponse &response);
  // RFC 6665 section 4.2.1.2: a refresh (or end) of a group or configuration document subscription in its dialog;
  // a resource list in it is the modified list of group documents (TS 24.481 clauses 6.3.13.2.1, 6.3.13.2.2).
  bool refresh_document_subscription(const SipMessage &message, SipResponse &response);
  // Local limits of this server on the document and key subscriptions it accepts (TS 24.481 and TS 24.484 give
  // none): at most max_subscription_s per subscription and max_subscriptions of each kind; a refresh without
  // Expires lasts default_subscription_s.
  static constexpr std::uint64_t max_subscription_s = 3600;
  static constexpr std::uint64_t default_subscription_s = 3600;
  static constexpr std::size_t max_subscriptions = 256;
  // The duration a re-SUBSCRIBE asks for (default_subscription_s without Expires), or std::nullopt when its
  // Expires is malformed (RFC 3261 section 20.19).
  static std::optional<std::uint64_t> refreshed_expires(const SipMessage &message);
  // TS 24.481 clause 7.7: a group member's subscription to the group's GKTP document.
  void key_subscribe(const SipMessage &message, const User &user, SipResponse &response);
  // TS 24.379 clause 10.1.3.4.1: subscription to the conference event package of a call.
  void conference_subscribe(const SipMessage &message, const User &user, SipResponse &response);
  // TS 24.379 clause 9A.2.2: functional alias status determination subscription.
  bool alias_status_subscribe(const SipMessage &message, const User &user, SipResponse &response);
  // TS 24.379 clause 9.2.1.3: subscription to the user's affiliation status.
  void affiliation_subscribe(const SipMessage &message, User &user, const std::string &event_name,
                             SipResponse &response);
  // TS 24.379 clause 9.2.2.2.3: affiliation status change (or functional alias activation) from a client.
  void affiliation_publish(const SipMessage &message, User &user, SipResponse &response);
  // SIP MESSAGE from a served user.
  void user_message(const SipMessage &message, User &user, SipResponse &response);
  // A SIP MESSAGE for a group or call controlled elsewhere goes on to the controlling function.
  bool message_to_controller(const SipMessage &message, User &user, const McpttInfo &info, SipResponse &response);
  // TS 24.379 clauses 12.1.3.1 to 12.1.3.3: group emergency alert and emergency state change.
  void group_alert_message(const SipMessage &message, User &user, McpttInfo &info, SipResponse &response);
  // INVITE from a served user or a peer function: call setup and re-INVITE.
  void invite_request(const SipMessage &message, User &user, SipResponse &response);
  // TS 24.379 clause 6.3.2: a call controlled elsewhere is relayed there.
  bool invite_to_controller(const SipMessage &message, User &user, const McpttInfo &info, SipResponse &response);
  // TS 24.379 clauses 10.1.1.4.2 and 10.1.2.4.1: the controlling function receives a group call request.
  void group_invite(const SipMessage &message, User &user, McpttInfo &info, SipResponse &response);
  // The group call a request joins, by session URI or group.
  bool find_group_session(const SipMessage &message, const McpttInfo &info, bool session_addressed,
                          std::shared_ptr<Session> &session, SipResponse &response);
  // TS 24.379 clause 10.1.2.4.1 steps 5, 5a and 6b: the constituent group of a call to a group regroup.
  bool regroup_constituent_allowed(const User &user, const McpttInfo &info, std::string &calling_constituent,
                                   SipResponse &response);
  // TS 24.379 clause 10.1.2.4.1 step 6: affiliation (or implicit affiliation) of the caller.
  bool group_call_affiliated(User &user, const McpttInfo &info, bool chat_request,
                             const std::string &calling_constituent, ImplicitAffiliation &implicit,
                             SipResponse &response);
  // TS 24.379 clauses 4.4.2 and 10.1.2.4.1 steps 4b and 4c: membership, call type and group restrictions.
  bool group_call_type_allowed(const User &user, const McpttInfo &info, const Json &profile, bool chat_request,
                               SipResponse &response);
  // The SDP offer and media protection of a group call request.
  bool group_media_acceptable(const SipMessage &message, const User &user, const Json &profile, SipResponse &response);
  // Media protection, call policy and required affiliated members of a group call request.
  bool group_call_admitted(const SipMessage &message, const User &user, const McpttInfo &info,
                           const std::shared_ptr<Session> &session, const Json &profile, const Json &admission_policy,
                           SipResponse &response);
  // TS 24.379 clause 10.1.1.4.7: a re-INVITE of a joined participant changing the call's priority.
  void priority_reinvite(const SipMessage &message, const User &user, McpttInfo &info,
                         const std::shared_ptr<Session> &session, const Json &profile, std::shared_ptr<Leg> leg,
                         std::optional<McpttInfo> &correction, SipResponse &response);
  // TS 24.379 clause 4.12: broadcast, duplicate and capacity checks of a new participant.
  bool group_join_allowed(const User &user, const McpttInfo &info, const std::shared_ptr<Session> &session,
                          const Json &profile, const Json &admission_policy, bool chat_request, bool broadcast_request,
                          SipResponse &response);
  // A new group call session, not yet published.
  std::shared_ptr<Session> create_group_session(const User &user, const McpttInfo &info, const Json &profile,
                                                const Json &admission_policy, const std::string &group_type,
                                                bool hierarchy, bool broadcast_request, bool chat_request);
  // The caller's leg of a group call from its SDP offer (nullptr when refused).
  std::shared_ptr<Leg> group_call_leg(const SipMessage &message, const User &user, const McpttInfo &info,
                                      const std::shared_ptr<Session> &session, const Json &profile, bool creating,
                                      const std::optional<McpttInfo> &correction, SipResponse &response);
  // The answer to a group call request; publishes the session and its leg.
  void answer_group_invite(const SipMessage &message, const User &user, McpttInfo &info,
                           const std::shared_ptr<Session> &session, const Json &profile,
                           const std::shared_ptr<Leg> &leg, bool creating, bool session_addressed,
                           SipResponse &response);
  // state() (server.cpp): a confirmed leg becomes active.
  void leg_confirmed(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session);
  // TS 24.380 clause 6.3.4: the floor (or transmission) state told to a newly active leg (a scheduled task).
  void initial_floor_state(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session);
  // TS 24.379 clause 6.3.8.1: a disconnected leg leaves its call.
  void leg_disconnected(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session, int code);
  // TS 24.379 clause 6.3.8.1: remove the departed leg and release the call if due (a scheduled task).
  void release_departed_leg(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session);
  // tick() (server.cpp): TS 24.379 clause 6.3.3.1.16, expiry of TNG2.
  void expire_emergency_states(std::uint64_t now);
  // TS 24.379 clause 12.1A: ad hoc group emergency alert supervision.
  void supervise_adhoc_alerts(std::uint64_t now);
  // The fan-out of a call waiting for preempted members.
  void resume_preempted_fanouts(std::uint64_t now);
  // The supervision of one call in the tick.
  void supervise_session(const std::string &group, const std::shared_ptr<Session> &session, std::uint64_t now);
  // TS 24.379 clauses 6.3.8.1 and 6.3.8.2: late entry and the release timers of an established call.
  void supervise_call_timers(const std::string &group, const std::shared_ptr<Session> &session, std::uint64_t now);
  // Late entry: invite the members pending it.
  void invite_late_entries(const std::shared_ptr<Session> &session);
  // The policy revalidation of a group call.
  void revalidate_group_call(const std::string &group, const std::shared_ptr<Session> &session, std::uint64_t now);
  // TS 24.380 clause 8.2.13: retransmission of floor messages awaiting a Floor Ack.
  void retry_floor_messages(std::uint64_t now);
  // Expiry of affiliation subscriptions and service authorisations; registration refresh.
  void expire_users(std::uint64_t now);
  // The status file.
  void save_status(std::uint64_t now);
  // The calls in the status file.
  void save_sessions_status();
  // One call in the status file.
  Json session_status(const std::string &group, const std::shared_ptr<Session> &session);
  // McServer() (server.cpp): the SDP answer of a leg this server offered.
  void media_answered(std::string_view dialog, const MediaDescription &media);
  // ---- end of split ----

  // ---- Service hooks: where the MCPTT server (src/mcptt) and the MCVideo server (src/mcvideo) differ ----
  // Each is called per request, per call or leg event, or per media plane control packet; never per media packet.
  //------------------------------------------------------------------------------
  // TS 24.380 clause 6.3.5, TS 24.581 clauses 6.3.4 and 6.3.5: a media plane control packet from a client on a
  // leg's floor port: a floor control message (MCPTT) or a transmission control message (MCVideo).
  virtual void media_control_packet(Leg &leg, const Datagram &datagram) = 0;

  //------------------------------------------------------------------------------
  // TS 24.380 clause 6.3.5, TS 24.581 clauses 9.2.5 to 9.2.10: a floor arbitration outcome sent to a participant
  // as the service's media plane control message (send_notice has checked that the leg has the channel).
  virtual void media_control_notice(Leg &leg, const FloorNotice &notice) = 0;

  //------------------------------------------------------------------------------
  // TS 24.380 clause 6.4.2, TS 24.581 clause 6.4.2: the participating function's check of a media plane control
  // packet its client sends through a relay; true when it was answered here and is not passed on.
  virtual bool refuse_remote_request(Relay &relay, UdpSocket &socket, std::span<const std::uint8_t> plain,
                                     ProtectedCall *csk) = 0;

  //------------------------------------------------------------------------------
  // TS 24.379 clauses 6.2.1 and 11.1.2, TS 24.281 clauses 6.2.1, 6.4 and 10.2.3: the service's rules for a
  // client's SDP: its media plane control, video, and implicit request; throws when the SDP breaks them.
  virtual void check_service_media(const MediaDescription &media, bool implicit_allowed,
                                   bool uncontrolled_allowed) const = 0;

  //------------------------------------------------------------------------------
  // TS 24.281 clause 6.2.1: the service's media of a new leg or relay besides speech and floor control (MCVideo:
  // transmission control and H.264 video at media.video_port with the leg's port offset); its video socket.
  virtual std::unique_ptr<UdpSocket> service_media(MediaDescription &local, unsigned offset,
                                                   const std::string &address) = 0;

  //------------------------------------------------------------------------------
  // TS 24.581 clause 14.3.5, TS 24.281 clause 6.2.1: the service's part of the answer to a group call's SDP offer.
  virtual void answer_service_media(Leg &leg, const MediaDescription &remote, bool creating) = 0;

  //------------------------------------------------------------------------------
  // TS 24.581 clause 6.3.4.4.5: the media of a leg besides speech (MCVideo video), read in the run loop once per
  // loop and leg that has a video socket; the packets are handled without further virtual calls.
  virtual void service_media_packets(Leg &leg) = 0;

  //------------------------------------------------------------------------------
  // TS 24.281 clauses 6.4 and 13.2.3.2.3: the service's start of a newly active leg (MCVideo: the URL of a pushed
  // recording and the originator's implicit Transmission Request); true when the leg has been told its state.
  virtual bool initial_service_state(const std::shared_ptr<Leg> &leg, const std::shared_ptr<Session> &session) = 0;

  //------------------------------------------------------------------------------
  // TS 24.281 clause 12.2.3.2.5 step 2: the service's supervision of one call in the tick (MCVideo: the stream of
  // a recording).
  virtual void service_session_tick(const std::shared_ptr<Session> &session, std::uint64_t now) = 0;

  //------------------------------------------------------------------------------
  // TS 24.281 clauses 12.2.3 and 13.2.3: whether a <session-type> is a one-to-one video pull or push, a private
  // call of the MCVideo service.
  [[nodiscard]] virtual bool video_one_to_one(const std::string &session_type) const = 0;

  //------------------------------------------------------------------------------
  // TS 24.281 clauses 12.2.3.2.5 and 13.2.3.2.3: an INVITE of a call type only the service has (MCVideo: video
  // pull from and push to this server); nothing when the INVITE is a group call request.
  virtual std::optional<SipResponse> service_invite(const SipMessage &message, const User &user,
                                                    const McpttInfo &info) = 0;

  //------------------------------------------------------------------------------
  // TS 24.484: the service's part of a user profile from the configuration management server.
  [[nodiscard]] virtual Json service_user_profile(Json profile, const std::string &id) const = 0;

  //------------------------------------------------------------------------------
  // TS 24.481 with TS 24.281 clause 8.2.2: the service's settings of a group document from the GMS.
  [[nodiscard]] virtual Json service_members(Json group) const = 0;

  //------------------------------------------------------------------------------
  // TS 24.379 clause 11.1.6.3.1.1 step 9: the service's rule for the SDP direction of an ambient call; the
  // Warning text of a refusal, or nothing.
  [[nodiscard]] virtual std::optional<std::string> ambient_direction_refusal(const MediaDescription &media,
                                                                             const std::string &type) const = 0;

  //------------------------------------------------------------------------------
  // TS 33.180 clause 5.1.2: whether an access token's subject fits the service's user ID claim.
  [[nodiscard]] virtual bool token_subject_valid(const Json &claims) const = 0;

  McServer(const ServiceProfile &service, Json cfg, bool disable_tls);

public:
  McServer(const McServer &) = delete;
  McServer &operator=(const McServer &) = delete;

  // The SEAL polling thread is detached; it ends after its current long poll.
  virtual ~McServer() {
    if (seal_channel_) seal_channel_->running = false;
  }

  void run();
};
} // namespace mcx
