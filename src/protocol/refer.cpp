//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The SIP REFER of a call over a pre-established session (include/mcx/refer.hpp): the escaped headers portion of the
// resource list entry with its hname "body", the Refer-To, Target-Dialog and Replaces header field values.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 37.579-1 V18.1.0 (Rel-18), RFC 3261, RFC 3515, RFC 4488,
// RFC 4538, RFC 2392, RFC 5366, RFC 5368, RFC 3891, RFC 2046.

#include "mcx/refer.hpp"

#include "protocol_internal.hpp"

#include <algorithm>
#include <cctype>

namespace mcx {
namespace {

// RFC 5366 section 4 bounds nothing; the participating function reads at most this many entries (as
// parse_resource_list_targets bounds an ad hoc list by its body size).
constexpr std::size_t kMaximumEntries = 64;

// RFC 3261 section 19.1.1: the hname of the message body in the headers portion of a SIP URI.
constexpr std::string_view kBodyHname = "body";

//------------------------------------------------------------------------------
// RFC 3261 section 25.1: unreserved (alphanum / mark) and hnv-unreserved characters stay as they are in an hname or
// hvalue.
bool header_safe(unsigned char character) {
  static constexpr std::string_view mark = "-_.!~*'()";
  static constexpr std::string_view hnv_unreserved = "[]/?:+$";
  return std::isalnum(character) || mark.find(static_cast<char>(character)) != std::string_view::npos ||
         hnv_unreserved.find(static_cast<char>(character)) != std::string_view::npos;
}

//------------------------------------------------------------------------------
// Helper: the value of a hexadecimal digit.
int hex_value(char digit) {
  if (digit >= '0' && digit <= '9') return digit - '0';
  if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
  if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
  return -1;
}

//------------------------------------------------------------------------------
// Helper: case-insensitive comparison of header field names and option tags.
bool same_token(std::string_view left, std::string_view right) {
  return std::ranges::equal(left, right, [](unsigned char one, unsigned char two) {
    return std::tolower(one) == std::tolower(two);
  });
}

//------------------------------------------------------------------------------
// Helper: the first header field value with the name (or its compact form), or empty.
std::string_view header_value(const std::vector<SipHeader> &headers, std::string_view name,
                              std::string_view compact = {}) {
  for (const auto &header : headers)
    if (same_token(header.name, name) || (!compact.empty() && same_token(header.name, compact))) return header.value;
  return {};
}

//------------------------------------------------------------------------------
// RFC 3261 section 25.1: the generic parameters of a header field value after its first item: name and value
// (without quotes), names in lower case.
std::vector<std::pair<std::string, std::string>> parameters(std::string_view list) {
  std::vector<std::pair<std::string, std::string>> out;
  for (const auto &item : tokens(list, ';')) {
    const auto trimmed = trim(item);
    if (trimmed.empty()) continue;
    const auto equals = trimmed.find('=');
    auto value = equals == std::string::npos ? std::string{} : trim(trimmed.substr(equals + 1));
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') value = value.substr(1, value.size() - 2);
    out.emplace_back(lower(trim(trimmed.substr(0, equals))), value);
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: splits "first;param=value;..." into its first item and the parameter list.
std::pair<std::string, std::string> first_item(std::string_view value) {
  const auto semicolon = value.find(';');
  return {trim(value.substr(0, semicolon)),
          semicolon == std::string_view::npos ? std::string{} : std::string(value.substr(semicolon + 1))};
}

//------------------------------------------------------------------------------
// RFC 4538 section 7 and RFC 3891 section 6.1: a Call-ID (RFC 3261 section 25.1: word [ "@" word ]).
void check_call_id(std::string_view call_id) {
  if (call_id.empty() || call_id.size() > 256 || call_id.find_first_of(" \t;,\r\n<>\"") != std::string_view::npos)
    invalid("invalid Call-ID in a dialog identifier");
}

//------------------------------------------------------------------------------
// RFC 3261 section 25.1: a tag (token).
void check_tag(std::string_view tag) {
  if (tag.empty() || tag.size() > 256 || tag.find_first_of(" \t;,=\r\n<>\"") != std::string_view::npos)
    invalid("invalid tag in a dialog identifier");
}

//------------------------------------------------------------------------------
// Helper: the root <resource-lists> of a REFER body and its <entry> elements' "uri" attributes, in order.
std::vector<std::string> entry_uris(std::string_view xml) {
  auto doc = document(xml);
  auto root = xmlDocGetRootElement(doc.get());
  if (!is(root, "resource-lists", resource_lists_ns)) invalid("wrong resource-lists namespace");
  std::vector<std::string> out;
  for (auto list = root->children; list; list = list->next) {
    if (list->type != XML_ELEMENT_NODE) continue;
    if (!is(list, "list", resource_lists_ns)) invalid("unexpected resource-lists element");
    for (auto entry = list->children; entry; entry = entry->next) {
      if (entry->type != XML_ELEMENT_NODE) continue;
      if (!is(entry, "entry", resource_lists_ns)) invalid("unsupported resource-list member");
      if (out.size() == kMaximumEntries) invalid("REFER resource list names too many entries");
      out.push_back(attr(entry, "uri"));
    }
  }
  if (out.empty()) invalid("REFER resource list names no entry: TS 24.379 clause 10.1.1.3.1.2");
  return out;
}

} // namespace

//------------------------------------------------------------------------------
// RFC 3261 section 19.1.1 and section 25.1: escapes an hname or hvalue.
std::string escape_uri_header(std::string_view value) {
  static constexpr char digits[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(value.size());
  for (const unsigned char character : value) {
    if (header_safe(character)) {
      out += static_cast<char>(character);
    } else {
      out += '%';
      out += digits[character >> 4];
      out += digits[character & 0x0f];
    }
  }
  return out;
}

//------------------------------------------------------------------------------
// RFC 3261 section 19.1.2: decodes the escapes of an hname or hvalue.
std::string unescape_uri_header(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (value[index] != '%') {
      out += value[index];
      continue;
    }
    if (index + 2 >= value.size() || hex_value(value[index + 1]) < 0 || hex_value(value[index + 2]) < 0)
      invalid("malformed escape in a SIP URI header: RFC 3261 section 25.1");
    out += static_cast<char>((hex_value(value[index + 1]) << 4) | hex_value(value[index + 2]));
    index += 2;
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.2.2.1 steps 3 a and b, clause 11.1.1.2.2.1 step 8.
std::vector<SipHeader> refer_accept_contacts(const ServiceProfile &service) {
  return {{"Accept-Contact", feature_accept(service)}, {"Accept-Contact", icsi_accept(service)}};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.2.2.1 step 3 with NOTE 1, TS 37.579-1 table 5.5.2.12-2, RFC 3261 section 19.1.1.
std::string refer_entry_uri(const ReferEntry &entry, std::string_view boundary) {
  conference_uri(entry.target, true);
  if (entry.target.find('?') != std::string::npos) invalid("REFER target already has a headers portion");
  std::string uri = entry.target;
  char separator = '?';
  const auto append = [&](std::string_view name, std::string_view value) {
    uri += separator;
    uri += escape_uri_header(name);
    uri += '=';
    uri += escape_uri_header(value);
    separator = '&';
  };
  for (const auto &header : entry.headers) {
    if (same_token(header.name, kBodyHname) || same_token(header.name, "Content-Type"))
      invalid("the REFER entry's body and Content-Type are its parts");
    append(header.name, header.value);
  }
  if (!entry.body.empty()) {
    append("Content-Type", "multipart/mixed;boundary=" + std::string(boundary));
    append(kBodyHname, multipart_body(entry.body, boundary));
  }
  return uri;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 10.1.1.3.1.2 step 9 and 11.1.1.3.1.2, RFC 3261 section 19.1.1: reads the entry's "uri".
ReferEntry parse_refer_entry_uri(std::string_view uri) {
  ReferEntry entry;
  const auto question = uri.find('?');
  entry.target = std::string(uri.substr(0, question));
  conference_uri(entry.target, true);
  if (question == std::string_view::npos) return entry;

  std::string content_type, body;
  bool has_body = false;
  for (const auto &field : tokens(uri.substr(question + 1), '&')) {
    if (field.empty()) continue;
    const auto equals = field.find('=');
    if (equals == std::string::npos || equals == 0) invalid("SIP URI header without a value: RFC 3261 section 25.1");
    auto name = unescape_uri_header(field.substr(0, equals));
    auto value = unescape_uri_header(field.substr(equals + 1));
    if (same_token(name, kBodyHname)) {
      if (has_body) invalid("two hname \"body\" parameters in a REFER entry");
      body = std::move(value);
      has_body = true;
    } else if (same_token(name, "Content-Type")) {
      content_type = std::move(value);
    } else {
      entry.headers.push_back({std::move(name), std::move(value)});
    }
  }

  if (has_body) {
    if (content_type.empty()) invalid("REFER entry body without a Content-Type: RFC 3261 section 19.1.1");
    entry.body = parse_body_parts(content_type, body);
  }
  return entry;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.2.2.1 step 3 with RFC 5366: one <list> with the single <entry>.
std::string refer_resource_list(std::string_view entry_uri) {
  return refer_resource_list_of({std::string(entry_uri)});
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.2.2.1 step 8 with RFC 5366: one <list> with an <entry> per URI.
std::string refer_resource_list_of(const std::vector<std::string> &entry_uris) {
  if (entry_uris.empty() || entry_uris.size() > kMaximumEntries) invalid("REFER resource list of 1 to 64 entries");
  std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><resource-lists xmlns=\"" +
                    std::string(resource_lists_ns) + "\"><list>";
  for (const auto &uri : entry_uris) {
    conference_uri(uri, true);
    out += "<entry uri=\"" + xml_escape(uri) + "\"/>";
  }
  out += "</list></resource-lists>";
  bounded(out);
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.3.1.2 step 9: the single entry.
std::string parse_refer_resource_list(std::string_view xml) {
  auto uris = entry_uris(xml);
  if (uris.size() != 1) invalid("REFER resource list names more than one entry");
  return std::move(uris.front());
}

//------------------------------------------------------------------------------
// TS 24.379 clause 11.1.1.3.1.2 (first-to-answer): every entry.
std::vector<std::string> refer_resource_list_entries(std::string_view xml) { return entry_uris(xml); }

//------------------------------------------------------------------------------
// RFC 2392 section 2: "cid:" and the addr-spec of the Content-ID, %-escaped where it is not a URL character.
std::string cid_refer_to(std::string_view content_id) {
  if (content_id.empty() || content_id.find_first_of("<> \t\r\n\"") != std::string_view::npos)
    invalid("invalid Content-ID for a cid URL");
  // RFC 2392 section 2: the url-addr-spec keeps its "@"; the other characters a URL cannot hold are %-escaped.
  auto escaped = escape_uri_header(content_id);
  for (auto at = escaped.find("%40"); at != std::string::npos; at = escaped.find("%40", at + 1))
    escaped.replace(at, 3, "@");
  return "<cid:" + escaped + ">";
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.2.4.2 steps 6 and 7, 6.2.5.2 steps 6 and 7, TS 37.579-1 table 5.5.2.12-1 (METHOD-BYE).
std::string bye_refer_to(std::string_view session_identity) {
  conference_uri(session_identity, true);
  if (session_identity.find_first_of("?>") != std::string_view::npos) invalid("session identity with headers");
  return "<" + std::string(session_identity) + ";method=BYE>";
}

//------------------------------------------------------------------------------
// RFC 3515 section 2.1: Refer-To = name-addr / addr-spec, then refer-params; RFC 2392 section 2 for "cid:".
ReferTo parse_refer_to(std::string_view value) {
  auto text = trim(value);
  std::string address;
  if (const auto open = text.find('<'); open != std::string::npos) {
    const auto close = text.find('>', open);
    if (close == std::string::npos) invalid("Refer-To without closing '>': RFC 3515 section 2.1");
    address = text.substr(open + 1, close - open - 1);
  } else {
    // An addr-spec: its parameters would be header parameters (RFC 3261 section 20.10); the URI ends there.
    address = first_item(text).first;
  }
  ReferTo refer_to;
  if (address.size() > 4 && same_token(std::string_view(address).substr(0, 4), "cid:")) {
    refer_to.content_id = unescape_uri_header(std::string_view(address).substr(4));
    if (refer_to.content_id.empty()) invalid("empty cid URL in Refer-To");
    return refer_to;
  }
  const auto headers = address.find('?');
  const auto [uri, uri_parameters] = first_item(std::string_view(address).substr(0, headers));
  for (const auto &[name, parameter] : parameters(uri_parameters))
    if (name == "method") refer_to.method = parameter;
  // The other URI parameters stay with the URI: only "method" is a property of the reference (RFC 3261
  // section 19.1.1).
  std::string rest;
  for (const auto &item : tokens(uri_parameters, ';'))
    if (!item.empty() && lower(trim(item.substr(0, item.find('=')))) != "method") rest += ";" + trim(item);
  refer_to.uri = uri + rest;
  conference_uri(refer_to.uri, true);
  return refer_to;
}

//------------------------------------------------------------------------------
// RFC 4538 section 7: target-dialog = callid *(SEMI td-param), with local-tag and remote-tag.
std::string target_dialog_value(const DialogIdentifiers &dialog) {
  check_call_id(dialog.call_id);
  check_tag(dialog.local_tag);
  check_tag(dialog.remote_tag);
  return dialog.call_id + ";local-tag=" + dialog.local_tag + ";remote-tag=" + dialog.remote_tag;
}

//------------------------------------------------------------------------------
// RFC 4538 section 7: reads callid, local-tag and remote-tag; other td-params are ignored.
DialogIdentifiers parse_target_dialog(std::string_view value) {
  const auto [call_id, rest] = first_item(value);
  DialogIdentifiers dialog{call_id, {}, {}};
  for (const auto &[name, parameter] : parameters(rest)) {
    if (name == "local-tag") dialog.local_tag = parameter;
    if (name == "remote-tag") dialog.remote_tag = parameter;
  }
  check_call_id(dialog.call_id);
  check_tag(dialog.local_tag);
  check_tag(dialog.remote_tag);
  return dialog;
}

//------------------------------------------------------------------------------
// RFC 3891 section 6.1: replaces = callid *(SEMI replaces-param), with to-tag, from-tag and early-only.
std::string replaces_value(const ReplacesValue &replaces) {
  check_call_id(replaces.call_id);
  check_tag(replaces.to_tag);
  check_tag(replaces.from_tag);
  return replaces.call_id + ";to-tag=" + replaces.to_tag + ";from-tag=" + replaces.from_tag +
         (replaces.early_only ? ";early-only" : "");
}

//------------------------------------------------------------------------------
// RFC 3891 section 6.1: reads a Replaces value.
ReplacesValue parse_replaces(std::string_view value) {
  const auto [call_id, rest] = first_item(value);
  ReplacesValue replaces{call_id, {}, {}, false};
  for (const auto &[name, parameter] : parameters(rest)) {
    if (name == "to-tag") replaces.to_tag = parameter;
    if (name == "from-tag") replaces.from_tag = parameter;
    if (name == "early-only") replaces.early_only = true;
  }
  check_call_id(replaces.call_id);
  check_tag(replaces.to_tag);
  check_tag(replaces.from_tag);
  return replaces;
}

//------------------------------------------------------------------------------
// RFC 3891 section 3: the to-tag is the recipient's tag, the from-tag the sender's.
ReplacesValue replaces_for(const DialogIdentifiers &own_dialog, bool early_only) {
  return {own_dialog.call_id, own_dialog.remote_tag, own_dialog.local_tag, early_only};
}

//------------------------------------------------------------------------------
// RFC 3891 section 3: "the to-tag parameter is compared to the local tag, and the from-tag parameter is compared to
// the remote tag".
bool replaces_names(const ReplacesValue &replaces, const DialogIdentifiers &own_dialog) noexcept {
  return replaces.call_id == own_dialog.call_id && replaces.to_tag == own_dialog.local_tag &&
         replaces.from_tag == own_dialog.remote_tag;
}

//------------------------------------------------------------------------------
// RFC 4488 section 4: Refer-Sub "false" and the "norefersub" option tag in Supported (compact form "k").
bool refer_without_subscription(const std::vector<SipHeader> &headers) noexcept {
  try {
    if (!same_token(trim(first_item(header_value(headers, "Refer-Sub")).first), "false")) return false;
    for (const auto &header : headers)
      if (same_token(header.name, "Supported") || same_token(header.name, "k"))
        for (const auto &tag : tokens(header.value, ','))
          if (same_token(trim(tag), "norefersub")) return true;
  } catch (...) {
    return false; // an unreadable header field asks for nothing
  }
  return false;
}

//------------------------------------------------------------------------------
// TS 24.379 clauses 6.2.4.2 steps 4 to 8, 10.1.2.2.2.1 steps 2 and 8 to 10, 11.1.1.2.2.1 steps 2 to 7 (and the
// file header on "multiple-refer").
std::vector<SipHeader> pre_established_refer_headers(std::string_view refer_to, const DialogIdentifiers &session,
                                                     const ServiceProfile &service) {
  std::vector<SipHeader> headers{{"Refer-To", std::string(refer_to)},
                                 {"Refer-Sub", "false"},
                                 {"Supported", "norefersub"},
                                 {"Target-Dialog", target_dialog_value(session)},
                                 {"P-Preferred-Service", service.icsi}};
  headers.push_back({"Require", "multiple-refer"}); // every REFER over the session (the file header)
  return headers;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.2.2.2.1 steps 2 and 3: the resource list part named by the cid URL.
BodyPart refer_resource_list_part(const ReferEntry &entry, std::string_view content_id, std::string_view boundary) {
  return {resource_lists_mime, refer_resource_list(refer_entry_uri(entry, boundary)), std::string(content_id)};
}

BodyPart refer_resource_list_part(const std::vector<ReferEntry> &entries, std::string_view content_id,
                                  std::string_view boundary) {
  if (entries.empty()) invalid("REFER resource list without an entry");
  std::vector<std::string> uris;
  for (const auto &entry : entries) uris.push_back(refer_entry_uri(entry, boundary));
  return {resource_lists_mime, refer_resource_list_of(uris), std::string(content_id)};
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.3.1.2 conditions 1 to 3 (a call), clause 11.1.3.2.1.2 (method "BYE").
PreEstablishedReferRequest parse_pre_established_refer(const std::vector<SipHeader> &headers,
                                                       const std::vector<BodyPart> &parts) {
  const auto value = header_value(headers, "Refer-To", "r");
  if (value.empty()) invalid("REFER without Refer-To: RFC 3515 section 2.4.1");
  const auto refer_to = parse_refer_to(value);
  PreEstablishedReferRequest request;
  if (refer_to.content_id.empty()) {
    if (!same_token(refer_to.method, "BYE")) invalid("REFER for a pre-established session names no call to start");
    request.leave = true;
    request.session_identity = refer_to.uri;
    return request;
  }
  const auto part = std::ranges::find_if(parts, [&](const BodyPart &candidate) {
    return candidate.content_id == refer_to.content_id && same_token(candidate.content_type, resource_lists_mime);
  });
  if (part == parts.end())
    invalid("REFER Refer-To names no application/resource-lists+xml body: TS 24.379 clause 10.1.1.3.1.2");
  request.entry_uris = entry_uris(part->body);
  request.entry = parse_refer_entry_uri(request.entry_uris.front());
  return request;
}

} // namespace mcx
