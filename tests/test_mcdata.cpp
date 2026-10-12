//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData codecs: the binary messages and information elements of TS 24.282 clause 15, UUIDs, the
// mcdata-info, affiliation, functional alias, location and storage control XML documents, and the
// multipart bodies that carry them.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19).

#include "mcx/mcdata.hpp"
#include "mcx/protocol.hpp"

#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>

using namespace mcx;
using namespace mcx::mcdata;

//------------------------------------------------------------------------------
// Ends the test with a failure, printing message, when ok is false.
static void check(bool ok, const char *message) {
  if (!ok) {
    std::cerr << "FAILED: " << message << '\n';
    std::exit(1);
  }
}

//------------------------------------------------------------------------------
// Ends the test with a failure when fn does not throw: the input must be refused.
static void rejects(const std::function<void()> &fn, const char *message) {
  try {
    fn();
  } catch (const std::exception &) {
    return;
  }
  std::cerr << "FAILED to reject: " << message << '\n';
  std::exit(1);
}

//------------------------------------------------------------------------------
// The octets values as a string.
static std::string bytes(std::initializer_list<int> values) {
  std::string out;
  for (int value : values) out += static_cast<char>(value);
  return out;
}

//------------------------------------------------------------------------------
// A UUID of 16 consecutive octet values starting at first.
static Uuid ids(int first) {
  Uuid id;
  for (int index = 0; index < 16; ++index) id[index] = static_cast<std::uint8_t>(first + index);
  return id;
}

//------------------------------------------------------------------------------
// The octets of ids(first) as a string.
static std::string uuid_bytes(int first) {
  std::string out;
  for (int index = 0; index < 16; ++index) out += static_cast<char>(first + index);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15 message coding, annex D XML documents and annex E MIME bodies, with the MCData
// procedures that use them.
int main() {
  // TS 24.282 clause 15.1.2.1, table 15.1.2.1-1: SDS SIGNALLING PAYLOAD: type 01, 5-octet time, conversation,
  // message, then InReplyTo (21), Application ID (22), disposition (8-, type 1)
  // and the sender MCData user ID (51, TLV-E).
  SdsSignalling signalling;
  signalling.date_time = 0x0102030405ULL;
  signalling.conversation = ids(0x10);
  signalling.message = ids(0x20);
  signalling.in_reply_to = ids(0x30);
  signalling.application_id = 7;
  signalling.disposition = DispositionRequest::DeliveryAndRead;
  signalling.sender = "sip:a@x";
  const auto expected = bytes({0x01, 0x01, 0x02, 0x03, 0x04, 0x05}) + uuid_bytes(0x10) + uuid_bytes(0x20) +
                        bytes({0x21}) + uuid_bytes(0x30) + bytes({0x22, 0x07, 0x83, 0x51, 0x00, 0x07}) + "sip:a@x";
  check(encode(signalling) == expected, "SDS SIGNALLING PAYLOAD encoding");
  const auto decoded = decode_sds_signalling(expected);
  check(decoded.date_time == signalling.date_time && decoded.conversation == signalling.conversation &&
            decoded.message == signalling.message && decoded.in_reply_to == signalling.in_reply_to &&
            decoded.application_id == 7 && decoded.disposition == DispositionRequest::DeliveryAndRead &&
            decoded.sender == "sip:a@x",
        "SDS SIGNALLING PAYLOAD decoding");
  check(message_type(expected) == MessageType::SdsSignalling, "message type");
  SdsSignalling minimal;
  minimal.conversation = ids(1);
  minimal.message = ids(2);
  check(encode(minimal).size() == 38 && decode_sds_signalling(encode(minimal)).disposition == DispositionRequest::None,
        "mandatory-only SDS SIGNALLING PAYLOAD");
  rejects([&] { decode_sds_signalling(expected.substr(0, 20)); }, "truncated signalling");
  rejects([&] { decode_sds_signalling(bytes({0x41}) + expected.substr(1)); }, "protected message (bit 7)");
  rejects([&] { decode_sds_signalling(bytes({0x81}) + expected.substr(1)); }, "authenticated message (bit 8)");
  rejects([&] { decode_sds_signalling(encode(minimal) + bytes({0x84})); }, "reserved disposition request");
  rejects([&] { decode_sds_signalling(encode(minimal) + bytes({0x22, 1, 0x22, 2})); }, "duplicate IE");
  rejects([&] { decode_sds_signalling(encode(minimal) + bytes({0x99, 0})); }, "unknown IE");
  rejects([&] { decode_sds_signalling(encode(minimal) + bytes({0x51, 0x00, 0x09, 'x'})); }, "TLV-E beyond message");
  rejects([&] { message_type(bytes({0x04})); }, "reserved message type");
  SdsSignalling late = minimal;
  late.date_time = 1ULL << 40;
  rejects([&] { (void)encode(late); }, "date and time over 40 bits");

  // TS 24.282 clause 15.1.4.1, table 15.1.4.1-1 and clause 15.2.13: DATA PAYLOAD: type 03, number of payloads, Payload IE 78 with
  // a 2-octet length covering the content type octet and the data.
  DataPayload data;
  data.payloads = {{ContentType::Text, "Hi"}, {ContentType::Binary, std::string("\0\1", 2)}};
  const auto payload = bytes({0x03, 0x02, 0x78, 0x00, 0x03, 0x01, 'H', 'i', 0x78, 0x00, 0x03, 0x02, 0x00, 0x01});
  check(encode(data) == payload, "DATA PAYLOAD encoding");
  const auto payload_copy = decode_data_payload(payload);
  check(payload_copy.payloads.size() == 2 && payload_copy.payloads[0].data == "Hi" &&
            payload_copy.payloads[1].type == ContentType::Binary &&
            payload_copy.payloads[1].data == std::string("\0\1", 2),
        "DATA PAYLOAD decoding");
  rejects([&] { decode_data_payload(bytes({0x03, 0x03}) + payload.substr(2)); }, "payload count mismatch");
  rejects([&] { decode_data_payload(bytes({0x03, 0x01, 0x7a, 0x00, 0x01, 0x00})); }, "protected payload");
  rejects([&] { decode_data_payload(bytes({0x03, 0x01, 0x78, 0x00, 0x02, 0x0b, 'x'})); }, "reserved content type");
  rejects([&] { decode_data_payload(bytes({0x03, 0x01, 0x78, 0x00, 0x03, 0x05, 1, 2})); }, "short location");
  rejects([&] { decode_data_payload(bytes({0x03, 0x00})); }, "zero payloads");
  rejects([&] { (void)encode(DataPayload{}); }, "encoding zero payloads");

  // TS 24.282 clause 15.1.5.1, table 15.1.5.1-1: SDS NOTIFICATION: type 05, notification type, time, IDs, sender.
  SdsNotification sds_notification;
  sds_notification.type = DispositionNotification::Read;
  sds_notification.date_time = 5;
  sds_notification.conversation = ids(0x10);
  sds_notification.message = ids(0x20);
  sds_notification.sender = "sip:b@x";
  const auto notification =
      bytes({0x05, 0x03, 0, 0, 0, 0, 5}) + uuid_bytes(0x10) + uuid_bytes(0x20) + bytes({0x51, 0x00, 0x07}) + "sip:b@x";
  check(encode(sds_notification) == notification, "SDS NOTIFICATION encoding");
  const auto notification_copy = decode_sds_notification(notification);
  check(notification_copy.type == DispositionNotification::Read &&
            notification_copy.message == sds_notification.message && notification_copy.sender == "sip:b@x",
        "SDS NOTIFICATION decoding");
  // TS 24.282 clause 15.2.5, table 15.2.5-1: UNDELIVERED is notification type 1.
  sds_notification.type = DispositionNotification::Undelivered;
  check(encode(sds_notification)[1] == 0x01 &&
            decode_sds_notification(encode(sds_notification)).type == DispositionNotification::Undelivered,
        "SDS NOTIFICATION UNDELIVERED coding");
  rejects([&] { decode_sds_notification(bytes({0x05, 0x06}) + notification.substr(2)); }, "reserved notification type");
  rejects([&] { decode_sds_notification(payload); }, "wrong message type");

  // TS 24.282 clause 15.1.3.1, table 15.1.3.1-1: FD SIGNALLING PAYLOAD: type 02, FILEURL payload, half-octet IEs.
  FdSignalling fd;
  fd.date_time = 7;
  fd.conversation = ids(0x30);
  fd.message = ids(0x40);
  fd.completion_requested = true;
  fd.mandatory_download = true;
  fd.file_url = "https://content/f";
  fd.metadata = file_metadata("a.txt", 5, "text/plain", "note", 1790000000, std::string(64, 'a'));
  const auto fd_bytes = bytes({0x02, 0, 0, 0, 0, 7}) + uuid_bytes(0x30) + uuid_bytes(0x40) +
                        bytes({0x91, 0xa1, 0x78, 0x00, 0x12, 0x04}) + "https://content/f" +
                        bytes({0x79, 0x00, static_cast<int>(fd.metadata->size())}) + *fd.metadata;
  check(encode(fd) == fd_bytes, "FD SIGNALLING PAYLOAD encoding");
  const auto fd_copy = decode_fd_signalling(fd_bytes);
  check(fd_copy.file_url == fd.file_url && fd_copy.completion_requested && fd_copy.mandatory_download &&
            fd_copy.message == fd.message && fd_copy.metadata == fd.metadata,
        "FD SIGNALLING PAYLOAD decoding");
  check(metadata_size(*fd.metadata) == 5 && metadata_name(*fd.metadata) == "a.txt" &&
            metadata_availability(*fd.metadata) == 1790000000 && metadata_sha256(*fd.metadata) == std::string(64, 'a'),
        "Metadata IE file selector, hash and availability");
  // TS 24.282 clause 15.2.17 (Metadata), RFC 5547 hash-selector: upper-case hex byte pairs; RFC 5322 date-time.
  check(fd.metadata->find(" hash:sha-256:AA:AA:") != std::string::npos &&
            fd.metadata->find("file-availability:Mon, 21 Sep 2026 14:13:20 +0000") != std::string::npos,
        "Metadata IE hash and date-time syntax");
  check(date_time_5322(0) == "Thu, 01 Jan 1970 00:00:00 +0000", "RFC 5322 date-time of the epoch");
  check(metadata_availability(file_metadata("a", 1, "", "", 0)) == std::nullopt &&
            metadata_sha256(file_metadata("a", 1, "", "", 0)).empty(),
        "Metadata IE without availability or hash");
  // FD using the media plane carries no Payload IE, which TS 24.282 table 15.1.3.1-1 makes optional:
  // the file travels over MSRP instead of being named by a URL (TS 24.282 clause 6.2.2.3).
  {
    FdSignalling media_plane;
    media_plane.date_time = 7;
    media_plane.conversation = ids(0x30);
    media_plane.message = ids(0x40);
    media_plane.mandatory_download = true;
    const auto encoded = encode(media_plane);
    const auto copy = decode_fd_signalling(encoded);
    check(copy.file_url.empty() && !copy.metadata && copy.mandatory_download &&
              encoded.find(static_cast<char>(0x78)) == std::string::npos,
          "FD SIGNALLING PAYLOAD of a media plane transfer carries no Payload IE");
  }
  rejects([&] { decode_fd_signalling(fd_bytes.substr(0, 38) + bytes({0x78, 0x00, 0x02, 0x01, 'x'})); },
          "FD payload that is not FILEURL");
  rejects([&] { decode_fd_signalling(fd_bytes + bytes({0x92})); }, "duplicated FD disposition request type");
  rejects([&] { decode_fd_signalling(fd_bytes.substr(0, 38) + bytes({0x93, 0x78, 0x00, 0x02, 0x04, 'u'})); },
          "reserved FD disposition request type value");

  // TS 24.282 clause 15.1.6.1: FD NOTIFICATION, and clause 15.1.9.1: FD NETWORK NOTIFICATION.
  FdNotification note;
  note.type = FdNotificationType::Completed;
  note.date_time = 3;
  note.conversation = ids(0x30);
  note.message = ids(0x40);
  const auto fd_note = bytes({0x06, 0x03, 0, 0, 0, 0, 3}) + uuid_bytes(0x30) + uuid_bytes(0x40);
  check(encode(note) == fd_note, "FD NOTIFICATION encoding");
  check(decode_fd_notification(fd_note).type == FdNotificationType::Completed, "FD NOTIFICATION decoding");
  rejects([&] { decode_fd_notification(bytes({0x06, 0x05}) + fd_note.substr(2)); }, "reserved FD notification type");
  FdNetworkNotification expiry;
  expiry.type = FdNetworkNotificationType::Expired;
  expiry.date_time = 3;
  expiry.conversation = ids(0x30);
  expiry.message = ids(0x40);
  check(encode(expiry) == bytes({0x09, 0x01, 0, 0, 0, 0, 3}) + uuid_bytes(0x30) + uuid_bytes(0x40),
        "FD NETWORK NOTIFICATION encoding");
  check(decode_fd_network_notification(encode(expiry)).type == FdNetworkNotificationType::Expired,
        "FD NETWORK NOTIFICATION decoding");
  check(message_type(encode(fd)) == MessageType::FdSignalling && message_type(fd_note) == MessageType::FdNotification,
        "FD message types 02 and 06");

  // TS 24.282 clause 15.1.13.1, table 15.1.13.1-1: FD HTTP TERMINATION: no date and time, one FILEURL
  // payload, and the half-octet Release Response Type IE (clause 15.2.23) in the response.
  FdHttpTermination release;
  release.conversation = ids(0x30);
  release.message = ids(0x40);
  release.type = TerminationType::Request;
  release.file_url = "https://content/f";
  const auto termination =
      bytes({0x0d}) + uuid_bytes(0x30) + uuid_bytes(0x40) + bytes({0x01, 0x78, 0x00, 0x12, 0x04}) + "https://content/f";
  check(encode(release) == termination, "FD HTTP TERMINATION request encoding");
  const auto release_copy = decode_fd_http_termination(termination);
  check(release_copy.type == TerminationType::Request && release_copy.file_url == release.file_url &&
            !release_copy.release && release_copy.message == release.message,
        "FD HTTP TERMINATION request decoding");
  release.type = TerminationType::Response;
  release.release = ReleaseResponse::Success;
  const auto answered = decode_fd_http_termination(encode(release));
  check(encode(release)[33] == 0x02 && answered.release == ReleaseResponse::Success &&
            answered.type == TerminationType::Response,
        "FD HTTP TERMINATION response with RELEASE SUCCESS");
  rejects([&] { decode_fd_http_termination(bytes({0x0d}) + uuid_bytes(0x30) + uuid_bytes(0x40) + bytes({0x08})); },
          "reserved termination information type");
  rejects([&] { decode_fd_http_termination(termination + bytes({0xd3})); }, "reserved release response type");
  check(message_type(termination) == MessageType::FdHttpTermination, "FD HTTP TERMINATION message type 0d");

  // TS 24.282 clause 15.1.10.1, table 15.1.10.1-1: COMMUNICATION RELEASE: the message type 0a, the Comm
  // release Information type octet (clause 15.2.20), and the half-octet Data query type (IEI B, clause 15.2.19)
  // and Extension response type (IEI C, clause 15.2.21) IEs.
  CommunicationRelease intent;
  intent.type = CommReleaseType::IntentToRelease;
  intent.remaining_data_query = true;
  check(encode(intent) == bytes({0x0a, 0x01, 0xb1}), "COMMUNICATION RELEASE intent with data query encoding");
  const auto intent_copy = decode_communication_release(bytes({0x0a, 0x01, 0xb1}));
  check(intent_copy.type == CommReleaseType::IntentToRelease && intent_copy.remaining_data_query &&
            !intent_copy.extension,
        "COMMUNICATION RELEASE intent decoding");
  CommunicationRelease extension;
  extension.type = CommReleaseType::ExtensionResponse;
  extension.extension = ExtensionResponse::Rejected;
  check(encode(extension) == bytes({0x0a, 0x03, 0xc2}), "COMMUNICATION RELEASE extension response encoding");
  check(decode_communication_release(bytes({0x0a, 0x03, 0xc1})).extension == ExtensionResponse::Accepted,
        "COMMUNICATION RELEASE extension response decoding");
  check(encode(CommunicationRelease{CommReleaseType::AuthUserReleaseRequest, false, {}}) == bytes({0x0a, 0x04}),
        "COMMUNICATION RELEASE AUTH USER RELEASE REQ encoding");
  check(message_type(bytes({0x0a, 0x02})) == MessageType::CommunicationRelease,
        "COMMUNICATION RELEASE message type 0a");
  rejects([&] { decode_communication_release(bytes({0x0a, 0x05})); }, "reserved comm release information type");
  rejects([&] { decode_communication_release(bytes({0x0a, 0x01, 0xb2})); }, "reserved data query type");
  rejects([&] { decode_communication_release(bytes({0x0a, 0x03, 0xc3})); }, "reserved extension response type");
  rejects([&] { decode_communication_release(bytes({0x0a, 0x01, 0xb1, 0xb1})); }, "a repeated data query type");
  rejects([&] { decode_communication_release(bytes({0x0a, 0x01, 0xe1})); }, "an unknown IE");
  rejects([&] { decode_communication_release(bytes({0x0a})); }, "a truncated COMMUNICATION RELEASE");

  // UUIDs (RFC 4122 section 4.1).
  const auto id = random_uuid();
  check((id[6] >> 4) == 4 && (id[8] & 0xc0) == 0x80, "UUID version and variant");
  check(parse_uuid(uuid_text(id)) == id, "UUID text round trip");
  check(uuid_text(ids(0)) == "00010203-0405-0607-0809-0a0b0c0d0e0f", "UUID text layout");
  rejects([&] { parse_uuid("00010203040506070809-0a0b0c0d0e0f00"); }, "misplaced UUID hyphens");

  // TS 24.282 annex D.1: mcdata-info.
  Info info;
  info.request_type = "one-to-one-sds";
  info.calling_user = "sip:alice@mcx.test";
  info.client_id = "urn:uuid:1";
  info.call_to_functional_alias = false;
  info.associated_group = "sip:g@mcx.test";
  const auto xml = info_xml(info);
  check(
      xml.find(
          "<mcdatainfo xmlns=\"urn:3gpp:ns:mcdataInfo:1.0\"><mcdata-Params><request-type>one-to-one-sds</request-type>"
          "<mcdata-calling-user-id type=\"Normal\"><mcdataURI>sip:alice@mcx.test</mcdataURI></mcdata-calling-user-id>"
          "<mcdata-client-id type=\"Normal\"><mcdataString>urn:uuid:1</mcdataString></mcdata-client-id><anyExt>"
          "<call-to-functional-alias-ind>false</call-to-functional-alias-ind>"
          "<associated-group-id>sip:g@mcx.test</associated-group-id></anyExt>") != std::string::npos,
      "mcdata-info encoding and schema order");
  const auto parsed = parse_info(xml);
  check(parsed.request_type == info.request_type && parsed.calling_user == info.calling_user &&
            parsed.client_id == info.client_id && parsed.call_to_functional_alias == false &&
            parsed.associated_group == info.associated_group,
        "mcdata-info decoding");
  auto encrypted = xml;
  encrypted.replace(encrypted.find("type=\"Normal\""), 13, "type=\"Encrypted\"");
  rejects([&] { parse_info(encrypted); }, "encrypted content");
  rejects([&] { parse_info("<mcdatainfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"/>"); }, "MCPTT namespace");
  rejects([&] { parse_info("<!DOCTYPE x><mcdatainfo xmlns=\"urn:3gpp:ns:mcdataInfo:1.0\"/>"); }, "DTD");
  // Application priority (TS 24.282 clause 9.2.2.2.1 step 2b-ii-C, clause 9.2.2.4.1.1 step 5c).
  Info prioritised;
  prioritised.request_type = "group-sds";
  prioritised.user_requested_priority = 5;
  const auto prioritised_xml = info_xml(prioritised);
  check(prioritised_xml.find("<anyExt><user-requested-priority>5</user-requested-priority></anyExt>") !=
                std::string::npos &&
            parse_info(prioritised_xml).user_requested_priority == 5u && !parse_info(prioritised_xml).used_priority,
        "user-requested-priority");
  prioritised.user_requested_priority.reset();
  prioritised.used_priority = 7;
  check(parse_info(info_xml(prioritised)).used_priority == 7u, "used-priority");
  auto bad_priority = prioritised_xml;
  bad_priority.replace(bad_priority.find(">5<"), 3, ">-5<");
  rejects([&] { parse_info(bad_priority); }, "negative priority");
  // Ad hoc group SDS (TS 24.282 clause 9.2.2.2.1 step 3A).
  Info adhoc;
  adhoc.request_type = "ad-hoc-group-sds";
  adhoc.client_id = "urn:uuid:1";
  adhoc.participant_criteria = "affiliated:sip:g@mcx.test";
  const auto adhoc_xml = info_xml(adhoc);
  check(
      adhoc_xml.find("<request-type>ad-hoc-group-sds</request-type>") != std::string::npos &&
          adhoc_xml.find(
              "<anyExt><comn-participants-criteria>affiliated:sip:g@mcx.test</comn-participants-criteria></anyExt>") !=
              std::string::npos &&
          parse_info(adhoc_xml).participant_criteria == adhoc.participant_criteria,
      "ad hoc group SDS request and criteria");
  Info bad;
  bad.request_type = "one to one";
  rejects([&] { (void)info_xml(bad); }, "request type with spaces");

  // TS 24.282 clause 8.4.1: MCData affiliation shares the PIDF structure in its own namespace.
  Affiliation affiliation{"sip:alice@mcx.test", "urn:uuid:1", "p1", {"sip:g@mcx.test"}, {}, true};
  const auto pidf = affiliation_xml(affiliation, false);
  check(pidf.find("urn:3gpp:ns:mcdataPresInfo:1.0") != std::string::npos && parse_affiliation(pidf).mcdata &&
            parse_affiliation(pidf).groups == affiliation.groups,
        "MCData affiliation PIDF");
  affiliation.mcdata = false;
  check(!parse_affiliation(affiliation_xml(affiliation, false)).mcdata, "MCPTT affiliation PIDF");

  // TS 24.282 clause 22.3.1: MCData functional alias status change PIDF (urn:3gpp:ns:mcdataPresInfoFA:1.0).
  FunctionalAliasRequest alias{"sip:alice@mcx.test", "urn:uuid:1", "p9", {"sip:desk@mcx.test"}, true, true};
  const auto alias_xml = functional_alias_xml(alias);
  const auto alias_copy = parse_functional_alias(alias_xml);
  check(alias_xml.find("urn:3gpp:ns:mcdataPresInfoFA:1.0") != std::string::npos &&
            alias_xml.find("mcpttPresInfoFA") == std::string::npos && is_functional_alias_pidf(alias_xml) &&
            alias_copy.mcdata && alias_copy.take_over && alias_copy.aliases == alias.aliases &&
            alias_copy.publish_id == "p9",
        "MCData functional alias PIDF");
  alias.mcdata = false;
  check(!parse_functional_alias(functional_alias_xml(alias)).mcdata, "MCPTT functional alias PIDF");
  auto mixed = alias_xml;
  mixed.replace(mixed.find("</status>"), 9, "<x xmlns=\"urn:3gpp:ns:mcpttPresInfoFA:1.0\"/></status>");
  rejects([&] { parse_functional_alias(mixed); }, "mixed MCPTT and MCData functional alias namespaces");

  // Emergency alert elements (TS 24.282 clause 16.2, annex D.1) and the MCData location body (annex D.4).
  Info alert_info;
  alert_info.request_uri = "sip:g@mcx.test";
  alert_info.alert = true;
  alert_info.originated_by = "sip:alice@mcx.test";
  alert_info.client_id = "urn:uuid:1";
  alert_info.alert_received = true;
  alert_info.organization = "Fire & Rescue";
  const auto alert_xml = info_xml(alert_info);
  check(alert_xml.find("<alert-ind type=\"Normal\"><mcdataBoolean>true</mcdataBoolean></alert-ind>"
                       "<originated-by type=\"Normal\"><mcdataURI>sip:alice@mcx.test</mcdataURI></originated-by>"
                       "<mcdata-client-id") != std::string::npos &&
            alert_xml.find("<anyExt><alert-ind-rcvd>true</alert-ind-rcvd><mc-org>Fire &amp; Rescue</mc-org>") !=
                std::string::npos,
        "emergency alert elements and schema order");
  const auto alert_copy = parse_info(alert_xml);
  check(alert_copy.alert == true && alert_copy.originated_by == alert_info.originated_by &&
            alert_copy.alert_received == true && !alert_copy.emergency && alert_copy.organization == "Fire & Rescue",
        "emergency alert elements decoding");
  // The priority indications of a group communication (TS 24.282 clause 6.2.8.1.1, clause 6.2.8.1.9,
  // annex D.1).
  Info priority_info;
  priority_info.request_type = "group-sds-session";
  priority_info.request_uri = "sip:g@mcx.test";
  priority_info.emergency = true;
  priority_info.alert = false;
  const auto emergency_xml = info_xml(priority_info);
  check(emergency_xml.find("<anyExt><emergency-ind>true</emergency-ind></anyExt>") != std::string::npos &&
            parse_info(emergency_xml).emergency == true && !parse_info(emergency_xml).imminent_peril,
        "emergency group communication indication");
  priority_info.emergency.reset();
  priority_info.alert.reset();
  priority_info.imminent_peril = true;
  const auto imminent_xml = info_xml(priority_info);
  check(imminent_xml.find("<anyExt><imminentperil-ind>true</imminentperil-ind></anyExt>") != std::string::npos &&
            parse_info(imminent_xml).imminent_peril == true && !parse_info(imminent_xml).emergency,
        "imminent peril group communication indication");
  priority_info.imminent_peril = false;
  check(parse_info(info_xml(priority_info)).imminent_peril == false,
        "cancelling an imminent peril group communication");
  const auto location = emergency_location_xml({12, 34}, true);
  check(location.find("urn:3gpp:ns:mcdataLocationInfo:1.0") != std::string::npos &&
            parse_emergency_location(location).latitude == 12 && parse_emergency_location(location).longitude == 34 &&
            emergency_location_xml({12, 34}).find("mcpttLocationInfo") != std::string::npos,
        "MCData and MCPTT location bodies");

  // Binary MCData parts survive the multipart envelope (TS 24.282 annex E.1, annex E.2).
  const auto body = multipart_body({{info_mime, xml}, {signalling_mime, expected}, {payload_mime, payload}}, "b1");
  const auto parts = parse_body_parts("multipart/mixed; boundary=b1", body);
  check(parts.size() == 3 && parts[1].body == expected && parts[2].body == payload, "binary multipart parts");
  {
    // TS 24.282 clause 6.3.7.1.6, clause 6.3.7.1.7 and clause 17.3.3.2: the <emergency-alert-area-ind>,
    // <group-geo-area-ind> and <location-of-functional-alias-URI> elements.
    mcx::mcdata::Info area;
    area.request_uri = "sip:alice@example.org";
    area.associated_group = "sip:group@example.org";
    area.group_geo_area = true;
    area.emergency_alert_area = false;
    area.location_of_functional_alias = "sip:medic@example.org";
    const auto back = mcx::mcdata::parse_info(mcx::mcdata::info_xml(area));
    check(back.group_geo_area == true && back.emergency_alert_area == false &&
              back.location_of_functional_alias == "sip:medic@example.org",
          "MCData location indications round trip");
  }
  {
    // TS 24.282 clause 21.3 and annex D.7: control of communications storage.
    mcx::mcdata::Info ctrl;
    ctrl.request_type = "store-comms-in-msgstore-ctrl-req";
    ctrl.store_all_private = true;
    ctrl.store_specific_group = "enable";
    const auto back = mcx::mcdata::parse_info(mcx::mcdata::info_xml(ctrl));
    check(back.store_all_private == true && !back.store_all_group && back.store_specific_group == "enable" &&
              back.store_specific_private.empty(),
          "storage control elements round trip");
    ctrl.store_specific_private = "maybe";
    bool refused = false;
    try {
      (void)mcx::mcdata::info_xml(ctrl);
    } catch (const std::exception &) {
      refused = true;
    }
    check(refused, "storageCtrlType is enable or disable");
    mcx::mcdata::MsgStoreControl list{{"sip:g1@example.org"}, {"sip:bob@example.org"}, {}, {"sip:carol@example.org"}};
    const auto xml = mcx::mcdata::msgstore_control_xml(list);
    const auto parsed = mcx::mcdata::parse_msgstore_control(xml);
    check(parsed.enable_groups == list.enable_groups && parsed.enable_private == list.enable_private &&
              parsed.disable_private == list.disable_private && parsed.disable_groups.empty() &&
              xml.find("urn:3gpp:ns:msgstoreControlRequest:1.0") != std::string::npos,
          "msgstore-ctrl-request round trip");
  }
  std::cout << "MCData codec tests passed\n";
}
