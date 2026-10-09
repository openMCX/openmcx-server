// The SIP bodies of the MC services: the MCPTT and MCVideo service information (mcptt-info, mcvideo-info), location,
// functional alias and affiliation PIDF, conference event, regroup, resource-lists and multipart bodies, the user
// profile and group document fields the clients read, and the SDP of the audio, video, floor or transmission
// control and MSRP media.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19),
// TS 24.380 V19.2.0 (Rel-19), TS 24.581 V19.2.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19),
// TS 24.484 V19.6.0 (Rel-19), TS 26.281 V19.0.0 (Rel-19), TS 24.229, TS 23.032, RFC 2045, RFC 2046, RFC 3420,
// RFC 4566, RFC 4567, RFC 4575, RFC 4826, RFC 5366, RFC 5547, RFC 5875, RFC 6184.

#pragma once
#include "mcx/service.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mcx {
// TS 24.379 annex E.2, annex F.1 and annex F.3: the MCPTT ICSI and the MIME types of the mcptt-info and
// location-info bodies.
inline constexpr const char *mcptt_icsi = mcptt_service.icsi;
inline constexpr const char *mcptt_mime = mcptt_service.info_mime;
inline constexpr const char *mcptt_location_mime = mcptt_service.location_mime;

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.3: the <CurrentCoordinate> of an emergency location <Report>.
struct EmergencyLocation {
  // Unsigned decimal representation of each TS 23.032 clause 6.1 encoded 24-bit field.
  std::uint32_t latitude = 0, longitude = 0;
};

//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2: the MCPTT location-info body, or with mcdata the MCData one (TS 24.282 annex D.4,
// urn:3gpp:ns:mcdataLocationInfo:1.0); the parser accepts either namespace.
std::string emergency_location_xml(const EmergencyLocation &location, bool mcdata = false);
//------------------------------------------------------------------------------
// TS 24.379 annex F.3, TS 24.281 annex F.3, TS 24.282 annex D.4: the same document in the service's namespace
// (urn:3gpp:ns:mcvideoLocationInfo:1.0 for MCVideo, that of emergency_location_xml(location, true) for MCData).
std::string service_location_xml(const EmergencyLocation &location, const ServiceProfile &service);
//------------------------------------------------------------------------------
// TS 24.379 annex F.3.2, TS 24.282 annex D.4, TS 24.281 annex F.3: reads an Emergency <Report> that carries exactly
// a <CurrentCoordinate>.
EmergencyLocation parse_emergency_location(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.379 annex F.1 and TS 24.281 annex F.1: the <mcptt-Params> (or <mcvideo-Params>) of the MC service
// information document, with their <anyExt> extensions.
struct McpttInfo {
  std::string access_token, session_type, request_uri, calling_user, client_id;
  std::string calling_group;
  std::optional<bool> emergency, imminent_peril, alert, broadcast;
  std::string originated_by;
  std::optional<bool> alert_received;
  std::optional<bool> emergency_received;
  // First-to-answer call (TS 24.379 clause 11.1.1): the answering MCPTT ID in the 200
  // OK, and the <anyExt> <release-reason> of a BYE ("not selected for call").
  std::string called_party, release_reason;
  // Ambient listening call (TS 24.379 clause 11.1.6, <anyExt>): "remote-init" when the
  // listening user initiates the call, "local-init" when the listened-to user does.
  std::string ambient_listening_type;
  // MCVideo (TS 24.281 annex F.1): <video-pull-url>, the recording a one-from-server
  // video pull asks for (a contentType in <mcvideo-Params>), and <video-push-url>, where
  // the server records a one-to-server video push (an <anyExt> anyURI, sent in INFO).
  std::string video_pull_url, video_push_url;
  // <associated-group-id>: for a user- or group-broadcast group call, the group
  // through which the invited user is affiliated (project profile; TS 24.379
  // clause 4.12 defines no stage-3 procedure for broadcast group hierarchies).
  std::string associated_group;
  // Ad hoc group call priority (TS 24.379 clause 17, <anyExt> booleans):
  // <adhoc-emergency-ind>, <adhoc-alert-ind>, <adhoc-grp-emg-alert-grp-ind>.
  std::optional<bool> adhoc_emergency, adhoc_alert, adhoc_emergency_alert_group, adhoc_alert_received;
  // <anyExt><call-participants-criterias>: comma-separated ad hoc participant criteria.
  std::string participant_criteria;
  // Functional aliases (TS 24.379 clause 9A, <anyExt>): the caller's <functional-alias-URI>,
  // the <called-functional-alias-URI> and <call-to-functional-alias-ind>.
  std::string functional_alias, called_functional_alias;
  std::optional<bool> call_to_functional_alias;
  // Location (TS 24.379 clauses 6.3.2.4.1, 6.3.2.4.2 and 13.3.3.2, <anyExt>): <emergency-alert-area-ind>,
  // <group-geo-area-ind> (with <associated-group-id>), and the functional alias
  // whose users' location is requested (<location-of-functional-alias-URI>).
  std::optional<bool> emergency_alert_area, group_geo_area;
  std::string location_of_functional_alias;
  // <PrivateCallKMSURI> with its <uri-entry>: the KMS URI of the MCPTT ID (TS 24.379 clause 11.1.1.3.2 step 4a b iii).
  std::string private_call_kms_uri;
  // Plain-text <anyExt> elements of the private call services (TS 24.379
  // clauses 11.1.5 to 11.1.9), keyed by element name: request-type, response-type,
  // urgency-ind, time-of-request, notify-remote-user, ric-app-level-priority,
  // ric-commencement-mode, remotely-initiated-call-outcome, call-transfer-ind, transfer-call-outcome,
  // transfer-announced-ind, replaces-header-value,
  // call-forwarding-ind, forwarding-reason, forwarded-by-mcptt-id,
  // forwarding-target-id, forwarding-target-orig-id, forwarding-call-outcome.
  std::map<std::string, std::string> service;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.3.1.2: per-user functional alias information: the aliases a
// client requests to activate, refresh or deactivate, and the take-over flag.
struct FunctionalAliasRequest {
  std::string user_id, client_id, publish_id;
  std::vector<std::string> aliases;
  bool take_over = false;
  // MCData (TS 24.282 clause 22.3.1, urn:3gpp:ns:mcdataPresInfoFA:1.0) or MCVideo
  // (TS 24.281 clause 20.3.1, urn:3gpp:ns:mcvideoPresInfoFA:1.0) instead of MCPTT.
  bool mcdata = false, mcvideo = false;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.1.2 with the syntax of clause 9A.3.1.2 (TS 24.282 clause 22.3.1, TS 24.281 clause
// 20.3.1): writes a functional alias status change request.
std::string functional_alias_xml(const FunctionalAliasRequest &request);
//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.2.3 with the syntax of clause 9A.3.1.2: reads a functional alias status change request.
FunctionalAliasRequest parse_functional_alias(std::string_view xml);
//------------------------------------------------------------------------------
// Helper: true when a PIDF document carries the functional alias extension namespace.
bool is_functional_alias_pidf(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.3.1.2, TS 24.281 clause 20.3.1.2: the functional alias status in a NOTIFY:
// per-user information (entity the user, tuple id the client ID, one <functionalAlias
// functionalAliasID status> per alias) or per-functional alias information (entity and
// tuple id the alias, one <functionalAlias user> per user that activated it).
struct FunctionalAliasStatus {
  struct Entry {
    std::string alias, user, status; // status: activating, activated, deactivating, take-over-possible
  };

  std::string entity, tuple_id, publish_id;
  bool per_alias = false;
  std::vector<Entry> entries;
  bool mcdata = false, mcvideo = false;
};

//------------------------------------------------------------------------------
// TS 24.379 clause 9A.2.2.3.5 and clause 9A.2.1.3 with the syntax of clause 9A.3.1.2: writes a functional alias
// status notification or determination.
std::string functional_alias_status_xml(const FunctionalAliasStatus &status);
//------------------------------------------------------------------------------
// TS 24.379 clause 9A.3.1.2: reads a functional alias status notification or determination.
FunctionalAliasStatus parse_functional_alias_status(std::string_view xml);
//------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 11: granted rights of an MCPTT user profile document (TS 24.484 clause 8.3), or of
// an MCVideo or MCData one (TS 24.484 clauses 9.3 and 10.3): the names of the boolean elements set to true in
// the actions of its <cp:ruleset>, directly or in their <anyExt>, for client-side
// authorisation checks.
std::set<std::string> parse_profile_actions(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.484 clause 9.3: the MCVideo user profile document as the MCVideo client
// reads it: its identity and index, private call targets, groups and granted rights.
struct McvideoProfile {
  std::string user_id;
  unsigned profile_index = 1;
  std::vector<std::string> private_call_targets, groups;
  std::set<std::string> actions;
};

//------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1: reads an MCVideo user profile.
McvideoProfile parse_mcvideo_profile(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.484 clause 10.3: the MCData user profile document as the MCData client
// reads it: its identity and index and its granted rights.
struct McdataProfile {
  std::string user_id;
  unsigned profile_index = 1;
  std::set<std::string> actions;
};

//------------------------------------------------------------------------------
// TS 24.484 clause 10.3.2.1: reads an MCData user profile.
McdataProfile parse_mcdata_profile(std::string_view xml);
//------------------------------------------------------------------------------
// TS 24.484 clause 8.3.2.1 item 4 and clause 9.3.2.1 item 4: the "user-profile-index" of an MCPTT or MCVideo user
// profile; 1 when absent.
unsigned parse_profile_index(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.484 clauses 8.4.2.1 items 9 to 11, 9.4.2.1 and 10.4.2.1 item 4 (in the <anyExt> of <on-network>): the
// Resource-Priority header field values of an MCPTT, MCVideo or MCData service configuration document, by level
// ("emergency", "imminent", "normal"), each "<namespace>.<priority>" (RFC 4412 with RFC 8101).
std::map<std::string, std::string> parse_service_resource_priorities(std::string_view xml);
//------------------------------------------------------------------------------
// TS 24.481 clause 7.2.4.2: <preconfigured-group-use-only> of a group document (<list-service>): calls on
// the group are not allowed (TS 24.379 clause 10.1.5.2.1 step 1A, warning 167 of TS 24.379 table 4.4.2-2).
bool group_preconfigured_use_only(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.282 clause 14.2.1 with TS 24.481 clause 7.2.4.2: <mcdata-allow-enhanced-status> and the operational values of
// <mcdata-enhanced-status-operational-values> in a group document, by "id".
struct EnhancedStatusValues {
  bool allowed = false;
  std::vector<std::pair<std::string, std::string>> values; // id, operational value
};

//------------------------------------------------------------------------------
// TS 24.282 clause 14.2.1: reads the enhanced status values of a group document.
EnhancedStatusValues group_enhanced_status(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1.2: the affiliation PIDF of one client, its groups and their status.
struct Affiliation {
  std::string user_id, client_id, publication_id;
  std::vector<std::string> groups;
  std::vector<std::string> statuses;
  // MCData affiliation (TS 24.282 clause 8.4.1, urn:3gpp:ns:mcdataPresInfo:1.0) or
  // MCVideo affiliation (TS 24.281 clause 8.3.1, urn:3gpp:ns:mcvideoPresInfo:1.0)
  // instead of MCPTT (urn:3gpp:ns:mcpttPresInfo:1.0); at most one is set.
  bool mcdata = false;
  bool mcvideo = false;
};

//------------------------------------------------------------------------------
// RFC 2046 section 5.1: one part of a multipart body, its content type, body and Content-ID.
struct BodyPart {
  std::string content_type, body;
  // The Content-ID of the part (RFC 2045), without angle brackets: the target of a
  // cid URL, such as a signature's reference (TS 24.379 clause 6.6.3.1).
  std::string content_id = {};
};

//------------------------------------------------------------------------------
// RFC 4575 with TS 24.379 clause 10.1.3.6.1.2: a <user> of a conference-info document, its endpoint, status and
// functional alias.
struct ConferenceUser {
  std::string user_id, endpoint_uri, status = "connected", functional_alias;
};

//------------------------------------------------------------------------------
// RFC 4575 with TS 24.379 clause 10.1.3.6.1.2: a conference-info document.
struct ConferenceInfo {
  // TS 24.379 uses group_id as conference-info@entity. session_uri is the
  // optional RFC 4575 conf-uris participation URI, not the entity attribute.
  std::string session_uri, group_id;
  std::uint32_t version = 0;
  bool full = true, deleted = false;
  std::vector<ConferenceUser> users;
};

//------------------------------------------------------------------------------
// RFC 4575 with TS 24.379 clause 10.1.3.6.1.2: writes a conference-info document (full, partial or deleted).
std::string conference_info_xml(const ConferenceInfo &info);
//------------------------------------------------------------------------------
// RFC 4575 with TS 24.379 clause 10.1.3.6.1.2: reads a conference-info document.
ConferenceInfo parse_conference_info(std::string_view xml);
//------------------------------------------------------------------------------
// TS 24.380 clause 14 and TS 24.581 clauses 12 and 14: the media plane control channel of a call's "m=application"
// section: MCPTT floor control ("udp MCPTT") or MCVideo transmission control ("udp MCVideo"); or none, for an MCVideo
// private call without transmission control (TS 24.281 clause 10.2.3), which has audio
// and video only, or an MCPTT private call without floor control (TS 24.379
// clause 11.1.2), which has audio only.
enum class MediaControl { floor, transmission, none };

//------------------------------------------------------------------------------
// TS 24.281 clause 6.2.1 step 3: the "m=video" section of an MCVideo call: H.264 of
// TS 26.281 clause 4, RTP payload format of IETF RFC 6184.
struct VideoMedia {
  std::uint16_t port = 0, rtcp_port = 0;
  std::uint8_t payload_type = 97;
  std::uint32_t ssrc = 0;
  // RFC 6184 section 8.1: profile_idc, constraint flags and level_idc in hex. The default
  // is Constrained Baseline Profile Level 3.1, what the OpenH264 encoder sends
  // (include/mcx/video.hpp); TS 26.281 clause 4.1.1 recommends Constrained High Profile.
  std::string profile_level_id = "42e01f";
  unsigned packetization_mode = 1;
  std::string direction = "sendrecv";
};

//------------------------------------------------------------------------------
// TS 24.379 clause 6.2.1 and clause 6.2.2, TS 24.380 clause 14 (MCPTT), TS 24.281 clause 6.2.1 and TS 24.581
// clause 14 (MCVideo): the media of an SDP offer or answer: audio, video, and the floor or transmission control
// channel.
struct MediaDescription {
  MediaControl control = MediaControl::floor;
  std::optional<VideoMedia> video; // MCVideo only
  // MCVideo transmission control (TS 24.581 clause 12.1.2): mc_granted, and the
  // mc_audio_ssrc and mc_video_ssrc an answer grants to the offerer.
  bool granted = false;
  std::uint32_t granted_audio_ssrc = 0, granted_video_ssrc = 0;
  std::string address, floor_address;
  std::uint16_t audio_port = 0, rtcp_port = 0, floor_port = 0;
  std::uint8_t payload_type = 96;
  std::uint32_t floor_ssrc = 0, audio_ssrc = 0;
  bool octet_aligned = false, protected_media = false, queueing = false;
  bool implicit_request = false;
  // RFC 4867 section 8.1 "mode-set" of the AMR-WB format: the codec modes (0 to 8) the peer accepts; empty when the
  // peer gives none (every mode). TS 26.179 clause 4.1.3: support all modes, offer no particular mode set.
  std::vector<std::uint8_t> mode_set;
  // Audio direction attribute (RFC 4566): "sendrecv", or "sendonly"/"recvonly"
  // in an ambient listening call (TS 24.379 clause 6.2.1 step 2c).
  std::string direction = "sendrecv";
  std::optional<std::uint8_t> floor_priority;
  // RFC 4567 "a=key-mgmt:mikey": the base64 MIKEY-SAKKE I_MESSAGE carrying a PCK
  // (TS 24.379 clause 11.1.1.2.1.1 step 11; in the answer of a first-to-answer call).
  std::string key_mgmt;
};

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.3.2 and clause 10.2.5.2, TS 24.582: the MCData media plane offers and answers an
// "m=message" section carrying MSRP. The MCPTT MediaDescription above
// describes audio and floor control, so file and short data streams have their own.
struct MsrpMedia {
  std::string address, path;     // "a=path" holds one MSRP URI
  std::string setup = "actpass"; // "actpass" in an offer, "active" or "passive" in an answer
  std::string direction = "sendonly";
  std::uint16_t port = 0;
  std::vector<std::string> accept_types;
  bool secure = false; // "TCP/TLS/MSRP"
  // RFC 5547 attributes of a file transfer (TS 24.282 clause 10.2.5.2.1 step 1g).
  std::string file_selector, file_date, file_description;
  // RFC 4567 "a=key-mgmt:mikey": the PCK of a one-to-one communication
  // (TS 24.282 clause 9.2.3.2.1 step 2, clause 9.2.4.2.1 step 2, clause 10.2.5.2.1 step 2).
  std::string key_mgmt;
};

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.3.2.1 and clause 10.2.5.2.1 with TS 24.582: writes the MCData SDP, an "m=message" section
// carrying MSRP.
std::string msrp_sdp(const MsrpMedia &media, std::uint64_t session_id);
//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.3.2.1 and clause 10.2.5.2.1 with TS 24.582: reads the MCData SDP.
MsrpMedia parse_msrp_sdp(std::string_view sdp);

//------------------------------------------------------------------------------
// Helper: escapes text for an XML attribute or element.
std::string xml_escape(std::string_view value);
//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: the MC service information document of a service:
// <mcpttinfo> or <mcvideoinfo>, carried in McpttInfo for either.
std::string service_info_xml(const McpttInfo &info, const ServiceProfile &service);
//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2 and TS 24.281 annex F.1.2: reads an <mcpttinfo> or <mcvideoinfo> document.
McpttInfo parse_service_info(std::string_view xml, const ServiceProfile &service);
//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2: writes the <mcpttinfo> document.
std::string mcptt_info_xml(const McpttInfo &info);
//------------------------------------------------------------------------------
// TS 24.379 annex F.1.2: reads an <mcpttinfo> document.
McpttInfo parse_mcptt_info(std::string_view xml);
// RFC 4826: the MIME type of a resource list.
inline constexpr const char *resource_lists_mime = "application/resource-lists+xml";
//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.2.1.1 step 8 with RFC 5366: the list naming the single called MCPTT ID of a private call.
std::string private_call_resource_list(std::string_view target);
//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.1 step 9: the called party of a private call. Rejects anything but exactly one SIP
// entry (warning 145 of TS 24.379 table 4.4.2-2).
std::string parse_private_call_target(std::string_view xml);
//------------------------------------------------------------------------------
// TS 24.379 clause 17.2.2.1.1 step 11 with RFC 5366: the list of invited MCPTT IDs for an ad hoc group call.
std::string resource_list_xml(const std::vector<std::string> &targets);
//------------------------------------------------------------------------------
// RFC 4826 with RFC 5366: all entries across every list, duplicates removed in order; at most 64 entries.
std::vector<std::string> parse_resource_list_targets(std::string_view xml);
//------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13 with RFC 5875: resource lists of relative XCAP references.
std::string xcap_resource_list(const std::vector<std::string> &references);
//------------------------------------------------------------------------------
// RFC 5875 with RFC 4826: reads the XCAP references of a resource list (at most 64).
std::vector<std::string> parse_xcap_resource_list(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.379 clause 16 with annex F.7: a regroup using a preconfigured group. The
// regroup takes its whole configuration from the preconfigured group and is
// addressed by a temporary group identity of its own.
struct Regroup {
  std::string action;      // "create" or "remove"
  std::string regroup_uri; // the temporary group identity
  std::string preconfigured_group;
  std::vector<std::string> groups; // the constituent groups of a group regroup (clause 16.2)
  std::vector<std::string> users;  // the constituent users of a user regroup (clause 16.3)
};

// TS 24.379 annex F.7.4: the MCPTT regroup MIME type.
inline constexpr const char *regroup_mime = "application/vnd.3gpp.mcptt-regroup+xml";
//------------------------------------------------------------------------------
// TS 24.379 annex F.7.4, TS 24.281 clause 21 with annex F.6 (annex F.6.4): the MCVideo regroup body is the same with
// the service's prefix, application/vnd.3gpp.mcvideo-regroup+xml, <mcvideoregroup>, <mcvideoregroup-Params> and
// <mcvideo-regroup-uri>, in the same namespace.
std::string regroup_mime_of(const ServiceProfile &service);
//------------------------------------------------------------------------------
// TS 24.379 annex F.7.2 (TS 24.281 annex F.6.2, TS 24.282 annex D.6.2): writes a regroup document.
std::string regroup_xml(const Regroup &regroup, const ServiceProfile &service = mcptt_service);
//------------------------------------------------------------------------------
// TS 24.379 annex F.7.2 and annex F.7.3 (TS 24.281 annex F.6, TS 24.282 annex D.6): reads a regroup document.
Regroup parse_regroup(std::string_view xml, const ServiceProfile &service = mcptt_service);
//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1.2 (TS 24.282 clause 8.4.1, TS 24.281 clause 8.3.1): writes the affiliation PIDF of one
// client, as a request (TS 24.379 clause 9.2.1.2) or, with notification set, as in a notification (TS 24.379
// clause 9.2.2.2.5).
std::string affiliation_xml(const Affiliation &affiliation, bool notification);
//------------------------------------------------------------------------------
// TS 24.379 clause 9.3.1.2 (TS 24.282 clause 8.4.1, TS 24.281 clause 8.3.1): reads an affiliation PIDF.
Affiliation parse_affiliation(std::string_view xml);
//------------------------------------------------------------------------------
// TS 24.379 clause 7.2.3 with clause 7.4.1.2.2: writes the application/poc-settings+xml of a client.
std::string poc_settings_xml(std::string_view client_id, unsigned profile_index = 0);
//------------------------------------------------------------------------------
// Helper: the emergency location of a multipart body (the location-info MIME part), if any.
std::optional<EmergencyLocation> parse_emergency_location_parts(const std::vector<BodyPart> &parts);
//------------------------------------------------------------------------------
// RFC 2046 section 5.1.1 with RFC 5621: writes a multipart body with the given boundary.
std::string multipart_body(const std::vector<BodyPart> &parts, std::string_view boundary);
//------------------------------------------------------------------------------
// RFC 3261 section 7.4 with RFC 5621: the Content-Type and body of a request carrying the parts: one part as it is,
// several as a multipart/mixed body with the given boundary.
std::pair<std::string, std::string> message_body(const std::vector<BodyPart> &parts, std::string_view boundary);
//------------------------------------------------------------------------------
// RFC 2046 section 5.1.1 with RFC 5621: splits a multipart body into its parts; any other type is a single part.
std::vector<BodyPart> parse_body_parts(std::string_view type, std::string_view body);

//------------------------------------------------------------------------------
// RFC 2046 section 5.1.1 (with RFC 2045 section 5.1 quoting): the "boundary" parameter of a multipart Content-Type,
// without its quotes; throws when it is missing, duplicated or invalid.
std::string multipart_boundary(std::string_view type);
//------------------------------------------------------------------------------
// RFC 3420: the body parts of a SIP request carried in a message/sip body (TS 24.229: the
// REGISTER request sent by the UE, inside a third-party REGISTER).
std::vector<BodyPart> parse_sip_fragment_parts(std::string_view message);
//------------------------------------------------------------------------------
// TS 24.379 clause 6.2.1 and clause 6.2.2 with TS 24.380 clause 14.2 and clause 14.3 (MCPTT), TS 24.281 clause
// 6.2.1 and clause 6.2.2 with TS 24.581 clause 12.1.2 (MCVideo): writes the SDP offer or answer.
std::string make_sdp(const MediaDescription &media, std::uint64_t session_id);
//------------------------------------------------------------------------------
// TS 24.379 clause 6.2.1 and clause 6.2.2 with TS 24.380 clause 14.2 and clause 14.3 (MCPTT), TS 24.281 clause
// 6.2.1 with TS 24.581 clause 12.1.2 (MCVideo): reads an SDP offer or answer.
MediaDescription parse_sdp(std::string_view sdp);

//------------------------------------------------------------------------------
// TS 26.179 clause 4.1.3 with RFC 4867 section 8.1: the AMR-WB mode to send with when the client would use `wanted`:
// `wanted` if the peer's mode-set allows it (or gives none), else the highest allowed mode below it, else the lowest
// allowed mode.
int amr_wb_send_mode(int wanted, const std::vector<std::uint8_t> &mode_set);
} // namespace mcx
