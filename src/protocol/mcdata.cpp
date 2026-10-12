//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData coding: the application/vnd.3gpp.mcdata-info+xml body (TS 24.282 annex D.1), the communication storage
// control body (annex D.7), the binary MCData signalling and payload messages of TS 24.282 clause 15 with the MONP
// coding rules of TS 24.379 annex I, UUIDs, and the file Metadata attributes (RFC 5547, RFC 5322).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), RFC 4122, RFC 5547, RFC 5322.

#include "mcx/mcdata.hpp"

#include "mcx/protocol.hpp"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/rand.h>

#include <cctype>
#include <cstdio>
#include <ctime>
#include <memory>
#include <set>
#include <stdexcept>

namespace mcx::mcdata {
namespace {
constexpr std::size_t max_xml = 65536;
using Doc = std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)>;

//------------------------------------------------------------------------------
// Helper: refuses a malformed MCData body or message.
[[noreturn]] void invalid(const std::string &message) { throw std::runtime_error("MCData: " + message); }

//------------------------------------------------------------------------------
// Helper: parses an XML body; bodies with a DTD, entities, NUL bytes or over 64 KiB are refused.
Doc document(std::string_view body) {
  if (body.empty() || body.size() > max_xml || body.find('\0') != body.npos)
    invalid("empty, oversized or binary XML body");
  if (body.find("<!DOCTYPE") != body.npos || body.find("<!ENTITY") != body.npos)
    invalid("DTD and XML entities are unsupported");
  Doc doc(xmlReadMemory(body.data(), static_cast<int>(body.size()), "mcdata.xml", nullptr,
                        XML_PARSE_NONET | XML_PARSE_NOBLANKS | XML_PARSE_NOERROR | XML_PARSE_NOWARNING),
          xmlFreeDoc);
  if (!doc || doc->intSubset || doc->extSubset) invalid("invalid XML document");
  return doc;
}

//------------------------------------------------------------------------------
// Helper: whether the node is the element `name` in the mcdata-info namespace.
bool is(xmlNode *node, const char *name) {
  return node && node->type == XML_ELEMENT_NODE && xmlStrEqual(node->name, BAD_CAST name) && node->ns &&
         xmlStrEqual(node->ns->href, BAD_CAST info_ns);
}

//------------------------------------------------------------------------------
// Helper: the text content of an element.
std::string text(xmlNode *node) {
  xmlChar *value = xmlNodeGetContent(node);
  std::string out = value ? reinterpret_cast<char *>(value) : "";
  xmlFree(value);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the value of an attribute, empty when absent.
std::string attribute(xmlNode *node, const char *key) {
  xmlChar *value = xmlGetProp(node, BAD_CAST key);
  std::string out = value ? reinterpret_cast<char *>(value) : "";
  xmlFree(value);
  return out;
}

//------------------------------------------------------------------------------
// Helper: the child element `name` of the parent, or null; a duplicate is refused.
xmlNode *child(xmlNode *parent, const char *name) {
  xmlNode *found = nullptr;
  for (auto node = parent ? parent->children : nullptr; node; node = node->next)
    if (is(node, name)) {
      if (found) invalid(std::string("duplicate <") + name + ">");
      found = node;
    }
  return found;
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.1.2: a contentType element: one wrapper element, "Normal" protection only.
std::string content(xmlNode *node, const char *wrapper) {
  if (!node) return {};
  const auto type = attribute(node, "type");
  if (type == "Encrypted") invalid("encrypted MCData XML content is not implemented");
  if (!type.empty() && type != "Normal") invalid("unknown XML protection type");
  xmlNode *value = nullptr;
  for (auto candidate = node->children; candidate; candidate = candidate->next)
    if (candidate->type == XML_ELEMENT_NODE) {
      if (value || !is(candidate, wrapper))
        invalid(std::string("unexpected content wrapper in <") + reinterpret_cast<const char *>(node->name) + ">");
      value = candidate;
    }
  if (!value) invalid("missing content wrapper");
  return text(value);
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.1.2: an xs:boolean element ("true", "false", "1" or "0"), or nothing when absent.
std::optional<bool> boolean(xmlNode *node) {
  if (!node) return std::nullopt;
  const auto value = text(node);
  if (value == "true" || value == "1") return true;
  if (value == "false" || value == "0") return false;
  invalid("invalid boolean");
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.1.2: a priority element, xs:nonNegativeInteger, bounded to 0..65535 here.
std::optional<unsigned> priority(xmlNode *node) {
  if (!node) return std::nullopt;
  const auto value = text(node);
  if (value.empty() || value.size() > 5 || value.find_first_not_of("0123456789") != value.npos ||
      std::stoul(value) > 65535)
    invalid("invalid priority");
  return static_cast<unsigned>(std::stoul(value));
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.1.2: a contentType element with type="Normal" and its wrapper; nothing for an empty value.
std::string wrapped(const char *name, const char *wrapper, const std::string &value) {
  if (value.empty()) return {};
  return std::string("<") + name + " type=\"Normal\"><" + wrapper + ">" + xml_escape(value) + "</" + wrapper + "></" +
         name + ">";
}

//------------------------------------------------------------------------------
// Helper: a request-type or response-type value: at most 64 lower-case letters, digits and hyphens.
void check_token(const std::string &value, const char *what) {
  if (value.size() > 64 || value.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-") != value.npos)
    invalid(std::string("invalid ") + what);
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.1: reads a message coded with the MONP rules of TS 24.379 annex I.2.
struct Reader {
  std::string_view bytes;
  std::size_t at = 0;

  bool done() const { return at == bytes.size(); }

  std::uint8_t octet() {
    if (at >= bytes.size()) invalid("truncated message");
    return static_cast<std::uint8_t>(bytes[at++]);
  }

  std::string take(std::size_t count) {
    if (bytes.size() - at < count) invalid("truncated message");
    std::string out(bytes.substr(at, count));
    at += count;
    return out;
  }

  Uuid uuid() {
    Uuid id;
    for (auto &byte : id) byte = octet();
    return id;
  }

  // TS 24.282 clause 15.2.8: the Date and time value, 5 octets of seconds since 1970-01-01 UTC.
  std::uint64_t date_time() {
    std::uint64_t value = 0;
    for (int index = 0; index < 5; ++index) value = value << 8 | octet();
    return value;
  }

  // TS 24.379 annex I.2.2.2: the value of a TLV-E information element, after its IEI (a two-octet length).
  std::string tlv_e() { // after the IEI
    const std::size_t length = std::size_t(octet()) << 8 | octet();
    return take(length);
  }
};

//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.8: writes the Date and time value in 5 octets.
void put_date_time(std::string &out, std::uint64_t value) {
  if (value >> 40) invalid("date and time exceeds 40 bits");
  for (int shift = 32; shift >= 0; shift -= 8) out += static_cast<char>((value >> shift) & 0xff);
}

//------------------------------------------------------------------------------
// TS 24.282 clauses 15.2.9 to 15.2.11: writes a Conversation ID or Message ID, a 16-octet UUID.
void put_uuid(std::string &out, const Uuid &id) { out.append(reinterpret_cast<const char *>(id.data()), id.size()); }

//------------------------------------------------------------------------------
// TS 24.379 annex I.2.2.2: writes a TLV-E information element (IEI, two-octet length, value).
void put_tlv_e(std::string &out, std::uint8_t iei, std::string_view value) {
  if (value.size() > 0xffff) invalid("information element exceeds 65535 octets");
  out += static_cast<char>(iei);
  out += static_cast<char>(value.size() >> 8);
  out += static_cast<char>(value.size() & 0xff);
  out += value;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.2: reads the Message type; bits 7 and 8 mark protected and authenticated messages
// (TS 33.180), which are refused.
MessageType read_type(Reader &in, MessageType expected) {
  const auto octet = in.octet();
  // TS 24.282 table 15.2.2-1, bits 7 and 8: protected and authenticated messages (TS 33.180).
  if (octet & 0xc0) invalid("protected or authenticated MCData messages are not implemented");
  if (static_cast<MessageType>(octet) != expected) invalid("unexpected message type");
  return expected;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.2.1: an information element is not present more than once in a message.
void once(std::set<std::uint8_t> &seen, std::uint8_t iei) {
  if (!seen.insert(iei).second) invalid("duplicate information element");
}

// TS 24.282 tables 15.1.2.1-1 to 15.1.13.1-1: the information element identifiers.
constexpr std::uint8_t iei_in_reply_to = 0x21, iei_application_id = 0x22, iei_disposition = 0x8,
                       iei_extended_application_id = 0x7d, iei_user_location = 0x7e, iei_sender = 0x51,
                       iei_application_metadata = 0x53, iei_payload = 0x78, iei_protected_payload = 0x7a,
                       iei_file_metadata = 0x79, iei_completion_request = 0x9, iei_mandatory_download = 0xa,
                       iei_extension_response = 0xc, iei_release_response = 0xd, iei_data_query = 0xb;
} // namespace

//------------------------------------------------------------------------------
// TS 24.282 annex D.1: writes an application/vnd.3gpp.mcdata-info+xml body: <mcdata-Params> and the elements of
// its <anyExt>.
std::string info_xml(const Info &info) {
  check_token(info.request_type, "request type");
  std::string out =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><mcdatainfo xmlns=\"" + std::string(info_ns) + "\"><mcdata-Params>";
  out += wrapped("mcdata-access-token", "mcdataString", info.access_token);
  if (!info.request_type.empty()) out += "<request-type>" + info.request_type + "</request-type>";
  out += wrapped("mcdata-request-uri", "mcdataURI", info.request_uri);
  out += wrapped("mcdata-calling-user-id", "mcdataURI", info.calling_user);
  out += wrapped("mcdata-called-party-id", "mcdataURI", info.called_party);
  out += wrapped("mcdata-calling-group-id", "mcdataURI", info.calling_group);
  if (info.alert) out += wrapped("alert-ind", "mcdataBoolean", *info.alert ? "true" : "false");
  out += wrapped("originated-by", "mcdataURI", info.originated_by);
  out += wrapped("mcdata-client-id", "mcdataString", info.client_id);
  out += wrapped("mcdata-controller-psi", "mcdataURI", info.controller_psi);
  std::string ext;
  const auto plain = [&](const char *name, std::optional<bool> value) {
    if (value) ext += std::string("<") + name + ">" + (*value ? "true" : "false") + "</" + name + ">";
  };
  plain("emergency-ind", info.emergency);
  plain("imminentperil-ind", info.imminent_peril);
  plain("alert-ind-rcvd", info.alert_received);
  if (!info.organization.empty()) ext += "<mc-org>" + xml_escape(info.organization) + "</mc-org>";
  if (info.call_to_functional_alias)
    ext += std::string("<call-to-functional-alias-ind>") + (*info.call_to_functional_alias ? "true" : "false") +
           "</call-to-functional-alias-ind>";
  ext += wrapped("functional-alias-URI", "mcdataURI", info.functional_alias);
  if (info.multiple_devices) ext += wrapped("multiple-devices-ind", "mcdataBoolean", "true");
  ext += wrapped("called-functional-alias-URI", "mcdataURI", info.called_functional_alias);
  if (!info.associated_group.empty())
    ext += "<associated-group-id>" + xml_escape(info.associated_group) + "</associated-group-id>";
  if (info.user_requested_priority)
    ext += "<user-requested-priority>" + std::to_string(*info.user_requested_priority) + "</user-requested-priority>";
  if (info.used_priority) ext += "<used-priority>" + std::to_string(*info.used_priority) + "</used-priority>";
  if (!info.participant_criteria.empty())
    ext += "<comn-participants-criteria>" + xml_escape(info.participant_criteria) + "</comn-participants-criteria>";
  plain("emergency-alert-area-ind", info.emergency_alert_area);
  plain("group-geo-area-ind", info.group_geo_area);
  ext += wrapped("location-of-functional-alias-URI", "mcdataURI", info.location_of_functional_alias);
  plain("store-all-private-comms-in-msgstore", info.store_all_private);
  plain("store-all-group-comms-in-msgstore", info.store_all_group);
  for (const auto &[name, value] : {std::pair{"store-specific-private-comms-in-msgstore", &info.store_specific_private},
                                    std::pair{"store-specific-group-comms-in-msgstore", &info.store_specific_group}}) {
    if (value->empty()) continue;
    if (*value != "enable" && *value != "disable") invalid("storageCtrlType is enable or disable");
    ext += std::string("<") + name + ">" + *value + "</" + name + ">";
  }
  plain("mc-service-auth-result", info.service_auth_result);
  if (!ext.empty()) out += "<anyExt>" + ext + "</anyExt>";
  out += "</mcdata-Params></mcdatainfo>";
  if (out.size() > max_xml) invalid("mcdata-info body too large");

  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.7: <msgstore-ctrl-command-list> with <enable> and <disable> lists.
std::string msgstore_control_xml(const MsgStoreControl &control) {
  const auto list = [](const char *name, const std::vector<std::string> &groups,
                       const std::vector<std::string> &users) {
    if (groups.empty() && users.empty()) return std::string{};
    std::string out = std::string("<") + name + ">";
    for (const auto &group : groups) out += "<group>" + xml_escape(group) + "</group>";
    for (const auto &user : users) out += "<private>" + xml_escape(user) + "</private>";
    return out + "</" + name + ">";
  };
  auto out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><msgstore-ctrl-command-list "
             "xmlns=\"urn:3gpp:ns:msgstoreControlRequest:1.0\">" +
             list("enable", control.enable_groups, control.enable_private) +
             list("disable", control.disable_groups, control.disable_private) + "</msgstore-ctrl-command-list>";
  if (out.size() > max_xml) invalid("msgstore-ctrl-request body too large");
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.7.3: reads a <msgstore-ctrl-command-list>: the groups and users for which storing in the
// message store is enabled or disabled.
MsgStoreControl parse_msgstore_control(std::string_view xml) {
  constexpr const char *ns = "urn:3gpp:ns:msgstoreControlRequest:1.0";
  const auto in_ns = [&](xmlNode *node, const char *name) {
    return node && node->type == XML_ELEMENT_NODE && xmlStrEqual(node->name, BAD_CAST name) && node->ns &&
           xmlStrEqual(node->ns->href, BAD_CAST ns);
  };
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!in_ns(root, "msgstore-ctrl-command-list")) invalid("wrong msgstore-ctrl-request root or namespace");
  MsgStoreControl out;
  for (auto node = root->children; node; node = node->next) {
    const bool enable = in_ns(node, "enable");
    if (!enable && !in_ns(node, "disable")) continue; // unknown elements are ignored (TS 24.282 annex D.7.3)
    for (auto entry = node->children; entry; entry = entry->next) {
      const bool group = in_ns(entry, "group");
      if (!group && !in_ns(entry, "private")) continue;
      auto value = text(entry);
      if (value.empty() || value.size() > 256) invalid("empty or oversized identity in msgstore-ctrl-request");
      (enable ? (group ? out.enable_groups : out.enable_private) : (group ? out.disable_groups : out.disable_private))
          .push_back(value);
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 annex D.1.3: reads an application/vnd.3gpp.mcdata-info+xml body.
Info parse_info(std::string_view xml) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "mcdatainfo")) invalid("wrong mcdata-info root or namespace");
  auto params = child(root, "mcdata-Params");
  Info info;
  if (!params) return info;
  info.access_token = content(child(params, "mcdata-access-token"), "mcdataString");
  if (auto type = child(params, "request-type")) info.request_type = text(type);
  check_token(info.request_type, "request type");
  info.request_uri = content(child(params, "mcdata-request-uri"), "mcdataURI");
  info.calling_user = content(child(params, "mcdata-calling-user-id"), "mcdataURI");
  info.called_party = content(child(params, "mcdata-called-party-id"), "mcdataURI");
  info.calling_group = content(child(params, "mcdata-calling-group-id"), "mcdataURI");
  info.client_id = content(child(params, "mcdata-client-id"), "mcdataString");
  info.controller_psi = content(child(params, "mcdata-controller-psi"), "mcdataURI");
  if (auto alert = child(params, "alert-ind")) {
    const auto value = content(alert, "mcdataBoolean");
    if (value != "true" && value != "false" && value != "1" && value != "0") invalid("invalid alert-ind");
    info.alert = value == "true" || value == "1";
  }
  info.originated_by = content(child(params, "originated-by"), "mcdataURI");
  if (auto ext = child(params, "anyExt")) {
    info.call_to_functional_alias = boolean(child(ext, "call-to-functional-alias-ind"));
    info.functional_alias = content(child(ext, "functional-alias-URI"), "mcdataURI");
    info.called_functional_alias = content(child(ext, "called-functional-alias-URI"), "mcdataURI");
    info.multiple_devices = content(child(ext, "multiple-devices-ind"), "mcdataBoolean") == "true";
    if (auto group = child(ext, "associated-group-id")) info.associated_group = text(group);
    info.user_requested_priority = priority(child(ext, "user-requested-priority"));
    info.used_priority = priority(child(ext, "used-priority"));
    if (auto criteria = child(ext, "comn-participants-criteria")) info.participant_criteria = text(criteria);
    info.emergency = boolean(child(ext, "emergency-ind"));
    info.imminent_peril = boolean(child(ext, "imminentperil-ind"));
    info.alert_received = boolean(child(ext, "alert-ind-rcvd"));
    if (auto organization = child(ext, "mc-org")) info.organization = text(organization);
    info.emergency_alert_area = boolean(child(ext, "emergency-alert-area-ind"));
    info.group_geo_area = boolean(child(ext, "group-geo-area-ind"));
    info.location_of_functional_alias = content(child(ext, "location-of-functional-alias-URI"), "mcdataURI");
    info.store_all_private = boolean(child(ext, "store-all-private-comms-in-msgstore"));
    info.store_all_group = boolean(child(ext, "store-all-group-comms-in-msgstore"));
    for (const auto &[name, value] :
         {std::pair{"store-specific-private-comms-in-msgstore", &info.store_specific_private},
          std::pair{"store-specific-group-comms-in-msgstore", &info.store_specific_group}})
      if (auto node = child(ext, name)) {
        *value = text(node);
        if (*value != "enable" && *value != "disable") invalid("storageCtrlType is enable or disable");
      }
    info.service_auth_result = boolean(child(ext, "mc-service-auth-result"));
  }

  return info;
}

//------------------------------------------------------------------------------
// RFC 4122 section 4.4: a random (version 4) UUID, for Conversation IDs and Message IDs (TS 24.282 clause 15.2.9).
Uuid random_uuid() {
  Uuid id;
  if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1)
    throw std::runtime_error("random UUID generation failed");
  id[6] = static_cast<std::uint8_t>((id[6] & 0x0f) | 0x40);
  id[8] = static_cast<std::uint8_t>((id[8] & 0x3f) | 0x80);
  return id;
}

//------------------------------------------------------------------------------
// RFC 4122 section 3: a UUID in its textual form, lower-case hexadecimal with hyphens.
std::string uuid_text(const Uuid &id) {
  static const char *hex = "0123456789abcdef";
  std::string out;
  for (std::size_t index = 0; index < id.size(); ++index) {
    if (index == 4 || index == 6 || index == 8 || index == 10) out += '-';
    out += hex[id[index] >> 4];
    out += hex[id[index] & 15];
  }
  return out;
}

//------------------------------------------------------------------------------
// RFC 4122 section 3: a UUID from its textual form (36 characters).
Uuid parse_uuid(std::string_view text) {
  Uuid id{};
  std::size_t nibbles = 0;
  const auto nibble = [](char digit) -> int {
    if (digit >= '0' && digit <= '9') return digit - '0';
    if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
    if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
    return -1;
  };
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (text[index] == '-' && (index == 8 || index == 13 || index == 18 || index == 23)) continue;
    const int value = nibble(text[index]);
    if (value < 0 || nibbles >= 32) invalid("invalid UUID");
    id[nibbles / 2] = static_cast<std::uint8_t>(id[nibbles / 2] << 4 | value);
    ++nibbles;
  }
  if (nibbles != 32 || text.size() != 36) invalid("invalid UUID");
  return id;
}

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.2-1: the Message type of a message; reserved values and protected messages are refused.
MessageType message_type(std::string_view bytes) {
  if (bytes.empty()) invalid("empty message");
  const auto octet = static_cast<std::uint8_t>(bytes[0]);
  if (octet & 0xc0) invalid("protected or authenticated MCData messages are not implemented");
  switch (octet) {
  case 0x01:
  case 0x02:
  case 0x03:
  case 0x05:
  case 0x06:
  case 0x07:
  case 0x08:
  case 0x09:
  case 0x0a:
  case 0x0b:
  case 0x0c:
  case 0x0d:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14: return static_cast<MessageType>(octet);
  default: invalid("reserved message type");
  }
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.2.1: encodes an SDS SIGNALLING PAYLOAD message (table 15.1.2.1-1).
std::string encode(const SdsSignalling &sds) {
  std::string out(1, static_cast<char>(MessageType::SdsSignalling));
  put_date_time(out, sds.date_time);
  put_uuid(out, sds.conversation);
  put_uuid(out, sds.message);
  if (sds.in_reply_to) {
    out += static_cast<char>(iei_in_reply_to);
    put_uuid(out, *sds.in_reply_to);
  }
  if (sds.application_id) {
    out += static_cast<char>(iei_application_id);
    out += static_cast<char>(*sds.application_id);
  }
  if (sds.disposition != DispositionRequest::None) {
    if (static_cast<std::uint8_t>(sds.disposition) > 3) invalid("reserved SDS disposition request type");
    out += static_cast<char>(iei_disposition << 4 | static_cast<std::uint8_t>(sds.disposition));
  }
  if (sds.extended_application_id) put_tlv_e(out, iei_extended_application_id, *sds.extended_application_id);
  if (sds.user_location) put_tlv_e(out, iei_user_location, *sds.user_location);
  if (sds.sender) put_tlv_e(out, iei_sender, *sds.sender);
  if (sds.application_metadata) put_tlv_e(out, iei_application_metadata, *sds.application_metadata);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.2.1: decodes an SDS SIGNALLING PAYLOAD message (table 15.1.2.1-1).
SdsSignalling decode_sds_signalling(std::string_view bytes) {
  Reader in{bytes};
  read_type(in, MessageType::SdsSignalling);
  SdsSignalling sds;
  sds.date_time = in.date_time();
  sds.conversation = in.uuid();
  sds.message = in.uuid();
  std::set<std::uint8_t> seen;
  while (!in.done()) {
    const auto iei = in.octet();
    if (iei >> 4 == iei_disposition) {
      once(seen, iei_disposition);
      const auto value = iei & 0x0f;
      if (value < 1 || value > 3) invalid("reserved SDS disposition request type");
      sds.disposition = static_cast<DispositionRequest>(value);
      continue;
    }
    once(seen, iei);
    switch (iei) {
    case iei_in_reply_to: sds.in_reply_to = in.uuid(); break;
    case iei_application_id: sds.application_id = in.octet(); break;
    case iei_extended_application_id: sds.extended_application_id = in.tlv_e(); break;
    case iei_user_location: sds.user_location = in.tlv_e(); break;
    case iei_sender: sds.sender = in.tlv_e(); break;
    case iei_application_metadata: sds.application_metadata = in.tlv_e(); break;
    default: invalid("unknown SDS SIGNALLING PAYLOAD information element");
    }
  }

  return sds;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.4.1: encodes a DATA PAYLOAD message: the Number of payloads (clause 15.2.12) and a
// Payload IE per payload (clause 15.2.13).
std::string encode(const DataPayload &data) {
  if (data.payloads.empty() || data.payloads.size() > 255) invalid("number of payloads must be 1 to 255");
  std::string out(1, static_cast<char>(MessageType::DataPayload));
  out += static_cast<char>(data.payloads.size());
  for (const auto &payload : data.payloads) {
    const auto type = static_cast<std::uint8_t>(payload.type);
    if (type < 1 || type > 10) invalid("reserved payload content type");
    put_tlv_e(out, iei_payload, std::string(1, static_cast<char>(type)) + payload.data);
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.4.1: decodes a DATA PAYLOAD message; protected payloads are refused.
DataPayload decode_data_payload(std::string_view bytes) {
  Reader in{bytes};
  read_type(in, MessageType::DataPayload);
  const auto count = in.octet();
  if (count == 0) invalid("number of payloads must be 1 to 255");
  DataPayload data;
  while (!in.done()) {
    const auto iei = in.octet();
    if (iei == iei_protected_payload) invalid("protected MCData payloads are not implemented");
    if (iei != iei_payload) invalid("unknown DATA PAYLOAD information element");
    const auto value = in.tlv_e();
    if (value.empty()) invalid("payload without content type");
    const auto type = static_cast<std::uint8_t>(value[0]);
    if (type < 1 || type > 10) invalid("reserved payload content type");
    Payload payload{static_cast<ContentType>(type), value.substr(1)};
    // TS 24.282 table 15.2.13-3 fixed sizes.
    if ((payload.type == ContentType::Location && payload.data.size() != 6) ||
        (payload.type == ContentType::LocationAltitude && payload.data.size() != 2) ||
        (payload.type == ContentType::CodedText && payload.data.size() < 2))
      invalid("invalid payload length for its content type");
    data.payloads.push_back(std::move(payload));
  }
  if (data.payloads.size() != count) invalid("number of payloads does not match the Payload IEs");
  return data;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.5.1: encodes an SDS NOTIFICATION message (table 15.1.5.1-1).
std::string encode(const SdsNotification &notification) {
  const auto type = static_cast<std::uint8_t>(notification.type);
  if (type < 1 || type > 5) invalid("reserved SDS disposition notification type");
  std::string out(1, static_cast<char>(MessageType::SdsNotification));
  out += static_cast<char>(type);
  put_date_time(out, notification.date_time);
  put_uuid(out, notification.conversation);
  put_uuid(out, notification.message);
  if (notification.application_id) {
    out += static_cast<char>(iei_application_id);
    out += static_cast<char>(*notification.application_id);
  }
  if (notification.extended_application_id)
    put_tlv_e(out, iei_extended_application_id, *notification.extended_application_id);
  if (notification.sender) put_tlv_e(out, iei_sender, *notification.sender);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.5.1: decodes an SDS NOTIFICATION message (table 15.1.5.1-1).
SdsNotification decode_sds_notification(std::string_view bytes) {
  Reader in{bytes};
  read_type(in, MessageType::SdsNotification);
  SdsNotification notification;
  const auto type = in.octet();
  if (type < 1 || type > 5) invalid("reserved SDS disposition notification type");
  notification.type = static_cast<DispositionNotification>(type);
  notification.date_time = in.date_time();
  notification.conversation = in.uuid();
  notification.message = in.uuid();
  std::set<std::uint8_t> seen;
  while (!in.done()) {
    const auto iei = in.octet();
    once(seen, iei);
    switch (iei) {
    case iei_application_id: notification.application_id = in.octet(); break;
    case iei_extended_application_id: notification.extended_application_id = in.tlv_e(); break;
    case iei_sender: notification.sender = in.tlv_e(); break;
    default: invalid("unknown SDS NOTIFICATION information element");
    }
  }
  return notification;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.3.1: encodes an FD SIGNALLING PAYLOAD message (table 15.1.3.1-1).
std::string encode(const FdSignalling &fd) {
  std::string out(1, static_cast<char>(MessageType::FdSignalling));
  put_date_time(out, fd.date_time);
  put_uuid(out, fd.conversation);
  put_uuid(out, fd.message);
  if (fd.in_reply_to) {
    out += static_cast<char>(iei_in_reply_to);
    put_uuid(out, *fd.in_reply_to);
  }
  if (fd.application_id) {
    out += static_cast<char>(iei_application_id);
    out += static_cast<char>(*fd.application_id);
  }

  // TS 24.282 clauses 15.2.4 and 15.2.16: half-octet IEIs with the single defined value 1.
  if (fd.completion_requested) out += static_cast<char>(iei_completion_request << 4 | 1);
  if (fd.mandatory_download) out += static_cast<char>(iei_mandatory_download << 4 | 1);
  // The Payload IE is optional: FD using the media plane carries the file itself
  // over MSRP instead of a URL (TS 24.282 clause 15.1.3.1 with clause 6.2.2.3).
  if (!fd.file_url.empty())
    put_tlv_e(out, iei_payload, std::string(1, static_cast<char>(ContentType::FileUrl)) + fd.file_url);
  if (fd.metadata) put_tlv_e(out, iei_file_metadata, *fd.metadata);
  if (fd.extended_application_id) put_tlv_e(out, iei_extended_application_id, *fd.extended_application_id);
  if (fd.user_location) put_tlv_e(out, iei_user_location, *fd.user_location);
  if (fd.sender) put_tlv_e(out, iei_sender, *fd.sender);
  if (fd.application_metadata) put_tlv_e(out, iei_application_metadata, *fd.application_metadata);

  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.3.1: decodes an FD SIGNALLING PAYLOAD message (table 15.1.3.1-1).
FdSignalling decode_fd_signalling(std::string_view bytes) {
  Reader in{bytes};
  read_type(in, MessageType::FdSignalling);
  FdSignalling fd;
  fd.date_time = in.date_time();
  fd.conversation = in.uuid();
  fd.message = in.uuid();
  std::set<std::uint8_t> seen;
  bool payload = false;
  while (!in.done()) {
    const auto iei = in.octet();
    if (iei >> 4 == iei_completion_request || iei >> 4 == iei_mandatory_download) {
      once(seen, iei >> 4);
      if ((iei & 0x0f) != 1) invalid("reserved FD half-octet information element value");
      (iei >> 4 == iei_completion_request ? fd.completion_requested : fd.mandatory_download) = true;
      continue;
    }
    once(seen, iei);
    switch (iei) {
    case iei_in_reply_to: fd.in_reply_to = in.uuid(); break;
    case iei_application_id: fd.application_id = in.octet(); break;
    case iei_payload: {
      const auto value = in.tlv_e();
      // TS 24.282 clause 10.2.1.2.1 steps 3 and 4: exactly one Payload IE, of content type FILEURL.
      if (value.empty() || static_cast<std::uint8_t>(value[0]) != static_cast<std::uint8_t>(ContentType::FileUrl))
        invalid("an FD SIGNALLING PAYLOAD carries one FILEURL payload");
      fd.file_url = value.substr(1);
      payload = true;
      break;
    }
    case iei_file_metadata: fd.metadata = in.tlv_e(); break;
    case iei_extended_application_id: fd.extended_application_id = in.tlv_e(); break;
    case iei_user_location: fd.user_location = in.tlv_e(); break;
    case iei_sender: fd.sender = in.tlv_e(); break;
    case iei_application_metadata: fd.application_metadata = in.tlv_e(); break;
    case iei_protected_payload: invalid("protected MCData payloads are not implemented");
    default: invalid("unknown FD SIGNALLING PAYLOAD information element");
    }
  }
  if (payload && fd.file_url.empty()) invalid("an FD SIGNALLING PAYLOAD carries one FILEURL payload");

  return fd;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.6.1: encodes an FD NOTIFICATION message (table 15.1.6.1-1).
std::string encode(const FdNotification &notification) {
  const auto type = static_cast<std::uint8_t>(notification.type);
  if (type < 1 || type > 4) invalid("reserved FD disposition notification type");
  std::string out(1, static_cast<char>(MessageType::FdNotification));
  out += static_cast<char>(type);
  put_date_time(out, notification.date_time);
  put_uuid(out, notification.conversation);
  put_uuid(out, notification.message);
  if (notification.application_id) {
    out += static_cast<char>(iei_application_id);
    out += static_cast<char>(*notification.application_id);
  }
  if (notification.extended_application_id)
    put_tlv_e(out, iei_extended_application_id, *notification.extended_application_id);
  if (notification.sender) put_tlv_e(out, iei_sender, *notification.sender);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.6.1: decodes an FD NOTIFICATION message (table 15.1.6.1-1).
FdNotification decode_fd_notification(std::string_view bytes) {
  Reader in{bytes};
  read_type(in, MessageType::FdNotification);
  FdNotification notification;
  const auto type = in.octet();
  if (type < 1 || type > 4) invalid("reserved FD disposition notification type");
  notification.type = static_cast<FdNotificationType>(type);
  notification.date_time = in.date_time();
  notification.conversation = in.uuid();
  notification.message = in.uuid();
  std::set<std::uint8_t> seen;
  while (!in.done()) {
    const auto iei = in.octet();
    once(seen, iei);
    switch (iei) {
    case iei_application_id: notification.application_id = in.octet(); break;
    case iei_extended_application_id: notification.extended_application_id = in.tlv_e(); break;
    case iei_sender: notification.sender = in.tlv_e(); break;
    default: invalid("unknown FD NOTIFICATION information element");
    }
  }
  return notification;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.9.1: encodes an FD NETWORK NOTIFICATION message (table 15.1.9.1-1).
std::string encode(const FdNetworkNotification &notification) {
  const auto type = static_cast<std::uint8_t>(notification.type);
  if (type < 1 || type > 2) invalid("reserved FD notification type");
  std::string out(1, static_cast<char>(MessageType::FdNetworkNotification));
  out += static_cast<char>(type);
  put_date_time(out, notification.date_time);
  put_uuid(out, notification.conversation);
  put_uuid(out, notification.message);
  if (notification.application_id) {
    out += static_cast<char>(iei_application_id);
    out += static_cast<char>(*notification.application_id);
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.9.1: decodes an FD NETWORK NOTIFICATION message (table 15.1.9.1-1).
FdNetworkNotification decode_fd_network_notification(std::string_view bytes) {
  Reader in{bytes};
  read_type(in, MessageType::FdNetworkNotification);
  FdNetworkNotification notification;
  const auto type = in.octet();
  if (type < 1 || type > 2) invalid("reserved FD notification type");
  notification.type = static_cast<FdNetworkNotificationType>(type);
  notification.date_time = in.date_time();
  notification.conversation = in.uuid();
  notification.message = in.uuid();
  std::set<std::uint8_t> seen;
  while (!in.done()) {
    const auto iei = in.octet();
    once(seen, iei);
    if (iei != iei_application_id) invalid("unknown FD NETWORK NOTIFICATION information element");
    notification.application_id = in.octet();
  }
  return notification;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.13.1: encodes an FD HTTP TERMINATION message (table 15.1.13.1-1).
std::string encode(const FdHttpTermination &termination) {
  const auto type = static_cast<std::uint8_t>(termination.type);
  if (type < 1 || type > 7) invalid("reserved termination information type");
  std::string out(1, static_cast<char>(MessageType::FdHttpTermination));
  put_uuid(out, termination.conversation);
  put_uuid(out, termination.message);
  out += static_cast<char>(type);
  if (termination.application_id) {
    out += static_cast<char>(iei_application_id);
    out += static_cast<char>(*termination.application_id);
  }
  if (termination.extension) {
    const auto value = static_cast<std::uint8_t>(*termination.extension);
    if (value < 1 || value > 2) invalid("reserved extension response type");
    out += static_cast<char>(iei_extension_response << 4 | value);
  }
  if (termination.release) {
    const auto value = static_cast<std::uint8_t>(*termination.release);
    if (value < 1 || value > 2) invalid("reserved release response type");
    out += static_cast<char>(iei_release_response << 4 | value);
  }

  // The Payload IE is optional: FD using the media plane carries the file itself
  // over MSRP instead of a URL (TS 24.282 clause 15.1.3.1 with clause 6.2.2.3).
  if (!termination.file_url.empty())
    put_tlv_e(out, iei_payload, std::string(1, static_cast<char>(ContentType::FileUrl)) + termination.file_url);
  if (termination.extended_application_id)
    put_tlv_e(out, iei_extended_application_id, *termination.extended_application_id);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.10.1: encodes a COMMUNICATION RELEASE message (table 15.1.10.1-1).
std::string encode(const CommunicationRelease &release) {
  const auto type = static_cast<std::uint8_t>(release.type);
  if (type < 1 || type > 4) invalid("reserved comm release information type");
  std::string out(1, static_cast<char>(MessageType::CommunicationRelease));
  out += static_cast<char>(type);
  // Type 1 IEs: the IEI in the high nibble and the value in the low one (TS 24.282 clauses 15.2.19 and 15.2.21).
  if (release.remaining_data_query) out += static_cast<char>(iei_data_query << 4 | 1);
  if (release.extension) {
    const auto value = static_cast<std::uint8_t>(*release.extension);
    if (value < 1 || value > 2) invalid("reserved extension response type");
    out += static_cast<char>(iei_extension_response << 4 | value);
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.10.1: decodes a COMMUNICATION RELEASE message (table 15.1.10.1-1).
CommunicationRelease decode_communication_release(std::string_view bytes) {
  Reader in{bytes};
  read_type(in, MessageType::CommunicationRelease);
  CommunicationRelease release;
  const auto type = in.octet();
  if (type < 1 || type > 4) invalid("reserved comm release information type");
  release.type = static_cast<CommReleaseType>(type);
  std::set<std::uint8_t> seen;
  while (!in.done()) {
    const auto iei = in.octet();
    const auto value = iei & 0x0f;
    once(seen, iei >> 4);
    if (iei >> 4 == iei_data_query) {
      if (value != 1) invalid("reserved data query type");
      release.remaining_data_query = true;
    } else if (iei >> 4 == iei_extension_response) {
      if (value < 1 || value > 2) invalid("reserved extension response type");
      release.extension = static_cast<ExtensionResponse>(value);
    } else {
      invalid("unknown COMMUNICATION RELEASE information element");
    }
  }
  return release;
}

//------------------------------------------------------------------------------
// TS 24.282 clause 15.1.13.1: decodes an FD HTTP TERMINATION message (table 15.1.13.1-1).
FdHttpTermination decode_fd_http_termination(std::string_view bytes) {
  Reader in{bytes};
  read_type(in, MessageType::FdHttpTermination);
  FdHttpTermination termination;
  termination.conversation = in.uuid();
  termination.message = in.uuid();
  const auto type = in.octet();
  if (type < 1 || type > 7) invalid("reserved termination information type");
  termination.type = static_cast<TerminationType>(type);
  std::set<std::uint8_t> seen;
  while (!in.done()) {
    const auto iei = in.octet();
    if (iei >> 4 == iei_release_response || iei >> 4 == iei_extension_response) {
      once(seen, iei >> 4);
      const auto value = iei & 0x0f;
      if (value < 1 || value > 2) invalid("reserved release or extension response type");
      if (iei >> 4 == iei_release_response)
        termination.release = static_cast<ReleaseResponse>(value);
      else
        termination.extension = static_cast<ExtensionResponse>(value);
      continue;
    }
    once(seen, iei);
    switch (iei) {
    case iei_application_id: termination.application_id = in.octet(); break;
    case iei_payload: {
      const auto value = in.tlv_e();
      if (value.empty() || static_cast<std::uint8_t>(value[0]) != static_cast<std::uint8_t>(ContentType::FileUrl))
        invalid("an FD HTTP TERMINATION carries a FILEURL payload");
      termination.file_url = value.substr(1);
      break;
    }
    case iei_extended_application_id: termination.extended_application_id = in.tlv_e(); break;
    default: invalid("unknown FD HTTP TERMINATION information element");
    }
  }

  return termination;
}

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.17-1: the Metadata IE is a concatenation of text attributes. The file
// selector follows IETF RFC 5547 and file-availability an IETF RFC 5322 date-time: this writes that date-time
// (RFC 5322 section 3.3) in UTC.
std::string date_time_5322(std::uint64_t seconds) {
  const auto when = static_cast<std::time_t>(seconds);
  std::tm parts{};
  if (!gmtime_r(&when, &parts)) return {};
  static constexpr const char *days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static constexpr const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  char out[48];
  // Fixed C locale spelling, as RFC 5322 section 3.3 requires.
  std::snprintf(out, sizeof(out), "%s, %02d %s %04d %02d:%02d:%02d +0000", days[parts.tm_wday], parts.tm_mday,
                months[parts.tm_mon], parts.tm_year + 1900, parts.tm_hour, parts.tm_min, parts.tm_sec);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.17-1: the Metadata IE contents: the RFC 5547 file-selector (name, type, size, and the
// SHA-256 hash), the file-description and the file-availability.
std::string file_metadata(const std::string &name, std::uint64_t size, const std::string &type,
                          const std::string &description, std::uint64_t available_until,
                          const std::string &sha256_hex) {
  std::string out = "file-selector:name:\"" + name + "\" type:" + (type.empty() ? "application/octet-stream" : type) +
                    " size:" + std::to_string(size);
  if (sha256_hex.size() == 64 && sha256_hex.find_first_not_of("0123456789abcdef") == std::string::npos) {
    // RFC 5547 hash-selector: upper-case hex byte pairs separated by colons.
    out += " hash:sha-256:";
    for (std::size_t at = 0; at < sha256_hex.size(); at += 2) {
      if (at) out += ':';
      out += static_cast<char>(std::toupper(static_cast<unsigned char>(sha256_hex[at])));
      out += static_cast<char>(std::toupper(static_cast<unsigned char>(sha256_hex[at + 1])));
    }
  }
  if (!description.empty()) out += "\r\nfile-description:" + description;
  if (available_until) out += "\r\nfile-availability:" + date_time_5322(available_until);
  return out;
}

namespace {
//------------------------------------------------------------------------------
// Helper: the value of the Metadata attribute line starting with `name`, empty when absent.
std::string metadata_attribute(std::string_view metadata, std::string_view name) {
  for (std::size_t at = 0; at < metadata.size();) {
    const auto end = metadata.find("\r\n", at);
    const auto line = metadata.substr(at, end == std::string_view::npos ? std::string_view::npos : end - at);
    if (line.starts_with(name)) return std::string(line.substr(name.size()));
    if (end == std::string_view::npos) break;
    at = end + 2;
  }
  return {};
}
} // namespace

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.17-1: the file-availability of a Metadata IE, in seconds since the epoch.
std::optional<std::uint64_t> metadata_availability(std::string_view metadata) {
  const auto value = metadata_attribute(metadata, "file-availability:");
  if (value.empty()) return std::nullopt;
  // Seconds since the epoch are accepted as well as the RFC 5322 date-time.
  if (value.find_first_not_of("0123456789") == std::string::npos) return std::stoull(value);
  std::tm parts{};
  if (!strptime(value.c_str(), "%a, %d %b %Y %H:%M:%S", &parts)) return std::nullopt;
  const auto when = timegm(&parts);
  if (when < 0) return std::nullopt;
  return static_cast<std::uint64_t>(when);
}

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.17-1: the SHA-256 hash in the RFC 5547 file-selector of a Metadata IE, in lower-case hex.
std::string metadata_sha256(std::string_view metadata) {
  const auto selector = metadata_attribute(metadata, "file-selector:");
  const auto at = selector.find("hash:sha-256:");
  if (at == std::string::npos) return {};
  const auto value = selector.substr(at + 13, selector.find(' ', at) - at - 13);
  std::string digest;
  for (const char character : value) {
    if (character == ':') continue;
    if (!std::isxdigit(static_cast<unsigned char>(character))) return {};
    digest += static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  }
  return digest.size() == 64 ? digest : std::string{};
}

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.17-1: the size in the RFC 5547 file-selector of a Metadata IE.
std::optional<std::uint64_t> metadata_size(std::string_view metadata) {
  const auto selector = metadata_attribute(metadata, "file-selector:");
  const auto at = selector.find("size:");
  if (at == std::string::npos) return std::nullopt;
  const auto digits = selector.substr(at + 5, selector.find(' ', at) - at - 5);
  if (digits.empty() || digits.find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
  return std::stoull(digits);
}

//------------------------------------------------------------------------------
// TS 24.282 table 15.2.17-1: the name in the RFC 5547 file-selector of a Metadata IE.
std::string metadata_name(std::string_view metadata) {
  const auto selector = metadata_attribute(metadata, "file-selector:");
  const auto at = selector.find("name:\"");
  if (at == std::string::npos) return {};
  const auto end = selector.find('"', at + 6);
  return end == std::string::npos ? std::string{} : selector.substr(at + 6, end - at - 6);
}
} // namespace mcx::mcdata
