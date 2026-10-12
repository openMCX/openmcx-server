//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData application content: the mcdata-info XML body (TS 24.282 annex D.1), the control of communications storage
// body (annex D.7) and the binary signalling and payload messages of clause 15, coded with the MONP rules of
// TS 24.379 annex I.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.582 V19.0.0 (Rel-19), RFC 4122,
// RFC 5322, RFC 5547.

#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mcx::mcdata {
// TS 24.282 annex D.1, annex E.1, annex E.2: the MIME types of the mcdata-info body, of the signalling messages and
// of the payload messages.
inline constexpr const char *info_mime = "application/vnd.3gpp.mcdata-info+xml";
// TS 24.282 annex D.1: the namespace of <mcdatainfo>.
inline constexpr const char *info_ns = "urn:3gpp:ns:mcdataInfo:1.0";
inline constexpr const char *signalling_mime = "application/vnd.3gpp.mcdata-signalling";
inline constexpr const char *payload_mime = "application/vnd.3gpp.mcdata-payload";
// The file itself, carried in MSRP SEND requests (TS 24.582 clause 7.1.2.1).
inline constexpr const char *file_mime = "application/vnd.3gpp.mcdata-file";
// TS 24.282 annex D.4: the location-info body.
inline constexpr const char *location_mime = "application/vnd.3gpp.mcdata-location-info+xml";
// ICSI values (TS 24.282 annex C.2, annex C.3 (SDS), annex C.4 (FD), annex C.5 (IP connectivity)).
inline constexpr const char *icsi = "urn:urn-7:3gpp-service.ims.icsi.mcdata";
inline constexpr const char *sds_icsi = "urn:urn-7:3gpp-service.ims.icsi.mcdata.sds";
inline constexpr const char *fd_icsi = "urn:urn-7:3gpp-service.ims.icsi.mcdata.fd";
inline constexpr const char *ipconn_icsi = "urn:urn-7:3gpp-service.ims.icsi.mcdata.ipconn";

//------------------------------------------------------------------------------
// TS 24.282 annex D.1: the <mcdatainfo><mcdata-Params> subset used by service authorisation and SDS.
struct Info {
  std::string access_token, request_type, request_uri, calling_user, called_party, calling_group, client_id;
  // <mcdata-controller-psi>: the controlling function, or the absolute URI of the
  // media storage function in an "msf-disc-res" (TS 24.282 clause 10.2.1.3.4 step 7d ii).
  std::string controller_psi;
  // <anyExt> elements.
  std::string functional_alias, called_functional_alias, associated_group;
  std::optional<bool> call_to_functional_alias;
  bool multiple_devices = false;
  // Application priority: <user-requested-priority> from the originating client,
  // delivered as <used-priority> by the controlling function (TS 24.282 clause 9.2.2.4.1.1 step 5c).
  std::optional<unsigned> user_requested_priority, used_priority;
  // Ad hoc group data communication (TS 24.282 clause 24): <comn-participants-criteria>,
  // a comma-separated list of criteria for the participant list.
  std::string participant_criteria;
  // Emergency alert (TS 24.282 clause 16): <alert-ind>, <originated-by>, and the <anyExt>
  // <emergency-ind>, <alert-ind-rcvd> and <mc-org> elements.
  std::optional<bool> alert, emergency, imminent_peril, alert_received;
  std::string originated_by, organization;
  // Location (TS 24.282 clauses 6.3.7.1.6, 6.3.7.1.7, 17.3.3.2, <anyExt>): <emergency-alert-area-ind>,
  // <group-geo-area-ind> (with <associated-group-id>) and <location-of-functional-alias-URI>.
  std::optional<bool> emergency_alert_area, group_geo_area;
  std::string location_of_functional_alias;
  // Control of communications storage (TS 24.282 clause 21.3, <anyExt>):
  // <store-all-private-comms-in-msgstore>, <store-all-group-comms-in-msgstore>, and
  // <store-specific-private-comms-in-msgstore> / <store-specific-group-comms-in-msgstore>
  // ("enable" or "disable").
  std::optional<bool> store_all_private, store_all_group;
  std::string store_specific_private, store_specific_group;
  // <mc-service-auth-result> in <anyExt>.
  std::optional<bool> service_auth_result;
};

//------------------------------------------------------------------------------
// TS 24.282 annex D.1: the application/vnd.3gpp.mcdata-info+xml body of the information.
std::string info_xml(const Info &info);
//------------------------------------------------------------------------------
// TS 24.282 annex D.1: the information of an application/vnd.3gpp.mcdata-info+xml body.
Info parse_info(std::string_view xml);

// application/vnd.3gpp.mcdata-msgstore-ctrl-request+xml (TS 24.282 annex D.7): the users and
// groups whose communications are to be stored, or no longer stored.
inline constexpr const char *msgstore_ctrl_mime = "application/vnd.3gpp.mcdata-msgstore-ctrl-request+xml";

//------------------------------------------------------------------------------
// TS 24.282 annex D.7: the content of a control of communications storage request.
struct MsgStoreControl {
  std::vector<std::string> enable_groups, enable_private, disable_groups, disable_private;
};

//------------------------------------------------------------------------------
// TS 24.282 annex D.7: the application/vnd.3gpp.mcdata-msgstore-ctrl-request+xml body of the request.
std::string msgstore_control_xml(const MsgStoreControl &control);
//------------------------------------------------------------------------------
// TS 24.282 annex D.7: the request of an application/vnd.3gpp.mcdata-msgstore-ctrl-request+xml body.
MsgStoreControl parse_msgstore_control(std::string_view xml);

//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.9 and clause 15.2.10: Conversation ID and Message ID, UUIDs of RFC 4122.
using Uuid = std::array<std::uint8_t, 16>;
//------------------------------------------------------------------------------
// RFC 4122 section 4.4: a random (version 4) UUID.
Uuid random_uuid();
//------------------------------------------------------------------------------
// RFC 4122 section 3: the 8-4-4-4-12 lower-case hex text of a UUID.
std::string uuid_text(const Uuid &id);
//------------------------------------------------------------------------------
// RFC 4122 section 3: the UUID of its text.
Uuid parse_uuid(std::string_view text);

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.2-1: the message type values (bits 1-6).
enum class MessageType : std::uint8_t {
  SdsSignalling = 0x01,
  FdSignalling = 0x02,
  DataPayload = 0x03,
  SdsNotification = 0x05,
  FdNotification = 0x06,
  SdsOffNetwork = 0x07,
  SdsOffNetworkNotification = 0x08,
  FdNetworkNotification = 0x09,
  CommunicationRelease = 0x0a,
  DeferredListRequest = 0x0b,
  DeferredListResponse = 0x0c,
  FdHttpTermination = 0x0d,
  GroupEmergencyAlert = 0x11,
  GroupEmergencyAlertAck = 0x12,
  GroupEmergencyAlertCancel = 0x13,
  GroupEmergencyAlertCancelAck = 0x14,
};
//------------------------------------------------------------------------------
// TS 24.282 table 15.2.3-1: SDS disposition request type; None means the IE is absent.
enum class DispositionRequest : std::uint8_t { None = 0, Delivery = 1, Read = 2, DeliveryAndRead = 3 };
//------------------------------------------------------------------------------
// TS 24.282 table 15.2.5-1: SDS disposition notification type.
enum class DispositionNotification : std::uint8_t {
  Undelivered = 1,
  Delivered = 2,
  Read = 3,
  DeliveredAndRead = 4,
  PreventedBySystem = 5,
};
//------------------------------------------------------------------------------
// TS 24.282 table 15.2.13-2: Payload content type.
enum class ContentType : std::uint8_t {
  Text = 1,
  Binary = 2,
  Hyperlinks = 3,
  FileUrl = 4,
  Location = 5,
  EnhancedStatus = 6,
  Interworking = 7,
  LocationAltitude = 8,
  LocationTimestamp = 9,
  CodedText = 10,
};

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.2.1: SDS SIGNALLING PAYLOAD. Optional TLV-E IEs this implementation does
// not interpret are kept as their value octets.
struct SdsSignalling {
  std::uint64_t date_time = 0; // seconds since 1970-01-01 UTC, 40 bits
  Uuid conversation{}, message{};
  std::optional<Uuid> in_reply_to;
  std::optional<std::uint8_t> application_id;
  DispositionRequest disposition = DispositionRequest::None;
  // 0x53 is the Application metadata container IE (TS 24.282 clause 15.2.28).
  std::optional<std::string> extended_application_id, user_location, sender, application_metadata;
};

//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.13: a Payload IE, its content type and data.
struct Payload {
  ContentType type = ContentType::Text;
  std::string data;
};

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.4.1: DATA PAYLOAD with clear Payload IEs; the protected form (IEI 7A) is
// refused because MCData payload protection is not implemented.
struct DataPayload {
  std::vector<Payload> payloads;
};
//------------------------------------------------------------------------------
// TS 24.282 table 15.2.6-1: FD disposition notification type.
enum class FdNotificationType : std::uint8_t {
  Accepted = 1,
  Rejected = 2,
  Completed = 3,
  Deferred = 4,
};
//------------------------------------------------------------------------------
// TS 24.282 table 15.2.18-1: notification type of an FD NETWORK NOTIFICATION.
enum class FdNetworkNotificationType : std::uint8_t { Expired = 1, Deleted = 2 };

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.3.1: FD SIGNALLING PAYLOAD: the file URL in a Payload IE with content type
// FILEURL, with the optional Metadata (clause 15.2.17), FD disposition request type
// (clause 15.2.4, half-octet IEI 9-) and Mandatory download (clause 15.2.16, IEI A-) IEs.
struct FdSignalling {
  std::uint64_t date_time = 0;
  Uuid conversation{}, message{};
  std::optional<Uuid> in_reply_to;
  std::optional<std::uint8_t> application_id;
  bool completion_requested = false; // FILE DOWNLOAD COMPLETED UPDATE
  bool mandatory_download = false;   // MANDATORY DOWNLOAD
  // Payload IE, content type FILEURL. It is absent when the file travels over the
  // media plane (TS 24.282 clause 15.1.3.1 makes the Payload IE optional; clause 6.2.2.3 omits it).
  std::string file_url;
  std::optional<std::string> metadata, extended_application_id, user_location, sender, application_metadata;
};

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.6.1: FD NOTIFICATION.
struct FdNotification {
  FdNotificationType type = FdNotificationType::Accepted;
  std::uint64_t date_time = 0;
  Uuid conversation{}, message{};
  std::optional<std::uint8_t> application_id;
  std::optional<std::string> extended_application_id, sender;
};

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.9.1: FD NETWORK NOTIFICATION, sent by the network to a client.
struct FdNetworkNotification {
  FdNetworkNotificationType type = FdNetworkNotificationType::Expired;
  std::uint64_t date_time = 0;
  Uuid conversation{}, message{};
  std::optional<std::uint8_t> application_id;
};

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.22-1: the type of an FD HTTP TERMINATION message. Only the request
// and the response are used by file distribution over HTTP.
enum class TerminationType : std::uint8_t {
  Request = 1,
  Response = 2,
  TransmissionStopped = 3,
  IntentToRelease = 4,
  ExtensionRequest = 5,
  ExtensionResponse = 6,
  AuthorisedUserRequest = 7,
};
//------------------------------------------------------------------------------
// TS 24.282 table 15.2.23-1: the server's answer to a termination request.
enum class ReleaseResponse : std::uint8_t { Success = 1, Failed = 2 };
//------------------------------------------------------------------------------
// TS 24.282 table 15.2.21-1: the server's answer to a request to extend a communication.
enum class ExtensionResponse : std::uint8_t { Accepted = 1, Rejected = 2 };

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.20-1: the type of a COMMUNICATION RELEASE message.
enum class CommReleaseType : std::uint8_t {
  IntentToRelease = 1,
  ExtensionRequest = 2,
  ExtensionResponse = 3,
  AuthUserReleaseRequest = 4,
};

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.10.1: COMMUNICATION RELEASE: release of a communication over the media plane,
// carried in SIP INFO requests of the g.3gpp.mcdata-com-release package (TS 24.282 clauses 13.2.4 to
// 13.2.6). The Data query type IE (clause 15.2.19) asks for the remaining amount of data.
struct CommunicationRelease {
  CommReleaseType type = CommReleaseType::IntentToRelease;
  bool remaining_data_query = false;
  std::optional<ExtensionResponse> extension;
};

// TS 24.282 annex H.1.2.4: the name of the communication release info package.
inline constexpr const char *com_release_package = "g.3gpp.mcdata-com-release";

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.13.1: FD HTTP TERMINATION: release of a file distribution over HTTP.
struct FdHttpTermination {
  Uuid conversation{}, message{};
  TerminationType type = TerminationType::Request;
  std::optional<std::uint8_t> application_id;
  std::optional<ReleaseResponse> release;
  std::optional<ExtensionResponse> extension;
  std::string file_url; // Payload IE, content type FILEURL
  std::optional<std::string> extended_application_id;
};

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.5.1: SDS NOTIFICATION.
struct SdsNotification {
  DispositionNotification type = DispositionNotification::Delivered;
  std::uint64_t date_time = 0;
  Uuid conversation{}, message{};
  std::optional<std::uint8_t> application_id;
  std::optional<std::string> extended_application_id, sender;
};

//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.2: the Message type of a message. Here and below, the binary encodings of TS 24.282
// clause 15.1.1 and TS 24.379 annex I (std::string used as a byte container). Decoders reject truncated, reserved,
// protected, duplicated and unknown content.
MessageType message_type(std::string_view bytes);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.2.1: encodes a SDS SIGNALLING PAYLOAD message.
std::string encode(const SdsSignalling &sds);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.4.1: encodes a DATA PAYLOAD message.
std::string encode(const DataPayload &data);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.5.1: encodes a SDS NOTIFICATION message.
std::string encode(const SdsNotification &notification);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.3.1: encodes a FD SIGNALLING PAYLOAD message.
std::string encode(const FdSignalling &fd);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.6.1: encodes a FD NOTIFICATION message.
std::string encode(const FdNotification &notification);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.9.1: encodes a FD NETWORK NOTIFICATION message.
std::string encode(const FdNetworkNotification &notification);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.13.1: encodes a FD HTTP TERMINATION message.
std::string encode(const FdHttpTermination &termination);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.10.1: encodes a COMMUNICATION RELEASE message.
std::string encode(const CommunicationRelease &release);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.2.1: decodes a SDS SIGNALLING PAYLOAD message.
SdsSignalling decode_sds_signalling(std::string_view bytes);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.4.1: decodes a DATA PAYLOAD message.
DataPayload decode_data_payload(std::string_view bytes);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.5.1: decodes a SDS NOTIFICATION message.
SdsNotification decode_sds_notification(std::string_view bytes);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.3.1: decodes a FD SIGNALLING PAYLOAD message.
FdSignalling decode_fd_signalling(std::string_view bytes);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.6.1: decodes a FD NOTIFICATION message.
FdNotification decode_fd_notification(std::string_view bytes);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.9.1: decodes a FD NETWORK NOTIFICATION message.
FdNetworkNotification decode_fd_network_notification(std::string_view bytes);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.13.1: decodes a FD HTTP TERMINATION message.
FdHttpTermination decode_fd_http_termination(std::string_view bytes);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.10.1: decodes a COMMUNICATION RELEASE message.
CommunicationRelease decode_communication_release(std::string_view bytes);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.17: Metadata IE attributes: the RFC 5547 file-selector plus the
// file-description and file-availability attributes.
std::string file_metadata(const std::string &name, std::uint64_t size, const std::string &type,
                          const std::string &description, std::uint64_t available_until,
                          const std::string &sha256_hex = {});
//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.17: the file-availability of the metadata, in seconds since 1970.
std::optional<std::uint64_t> metadata_availability(std::string_view metadata);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.17, RFC 5547: the size of the file-selector.
std::optional<std::uint64_t> metadata_size(std::string_view metadata);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.17, RFC 5547: the name of the file-selector.
std::string metadata_name(std::string_view metadata);
//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.17, RFC 5547: the hash selector value of the file selector, as lower-case hex without the
// separators, and empty when the metadata carries no SHA-256 hash.
std::string metadata_sha256(std::string_view metadata);
//------------------------------------------------------------------------------
// RFC 5322 section 3.3: date-time, as the file-availability attribute uses (TS 24.282 clause 15.2.17).
std::string date_time_5322(std::uint64_t seconds);
} // namespace mcx::mcdata
