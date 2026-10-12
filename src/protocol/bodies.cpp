//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Multipart SIP message bodies: writing and reading multipart/mixed and multipart/related, and the body of a
// message/sip fragment.
//
// Specifications: RFC 2046, RFC 2387, RFC 5621, RFC 3420, RFC 3261.

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// RFC 2046 section 5.1.1 with RFC 5621: writes a multipart body of 1 to 8 parts with the given boundary, each with
// its Content-Type and optional Content-ID; rejects a boundary, header or part that would break the framing.
std::string multipart_body(const std::vector<BodyPart> &parts, std::string_view boundary) {
  if (boundary.empty() || boundary.size() > 70 ||
      boundary.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != boundary.npos)
    invalid("invalid MIME boundary");
  if (parts.empty() || parts.size() > 8) invalid("invalid MIME part count");
  std::string out;
  for (const auto &part : parts) {
    if (part.content_type.find_first_of("\r\n") != part.content_type.npos ||
        part.body.find("\r\n--" + std::string(boundary)) != part.body.npos)
      invalid("unsafe MIME header or delimiter");
    if (part.content_id.find_first_of("\r\n<>") != part.content_id.npos) invalid("unsafe MIME Content-ID");
    out += "--" + std::string(boundary) + "\r\nContent-Type: " + part.content_type +
           (part.content_id.empty() ? std::string{} : "\r\nContent-ID: <" + part.content_id + ">") + "\r\n\r\n" +
           part.body + "\r\n";
  }
  out += "--" + std::string(boundary) + "--\r\n";
  bounded_envelope(out);
  return out;
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.4 with RFC 5621: the Content-Type and body of a request carrying the parts: one part as it is,
// several as a multipart/mixed body with the given boundary.
std::pair<std::string, std::string> message_body(const std::vector<BodyPart> &parts, std::string_view boundary) {
  if (parts.size() == 1 && parts.front().content_id.empty()) return {parts.front().content_type, parts.front().body};
  return {"multipart/mixed; boundary=" + std::string(boundary), multipart_body(parts, boundary)};
}

//------------------------------------------------------------------------------
// RFC 3420: reads the body parts of a message/sip (or message/sipfrag) body: its Content-Type (or compact "c")
// header and the body after the blank line, which parse_body_parts() splits.
std::vector<BodyPart> parse_sip_fragment_parts(std::string_view message) {
  bounded_envelope(message);
  const auto end = message.find("\r\n\r\n");
  if (end == message.npos || end > 8192) invalid("invalid message/sip body");
  std::string content_type;
  for (auto line : tokens(message.substr(0, end), '\n')) {
    const auto colon = line.find(':');
    if (colon == line.npos) continue;
    const auto name = lower(trim(line.substr(0, colon)));
    if (name == "content-type" || name == "c") {
      if (!content_type.empty()) invalid("duplicate content type in message/sip");
      content_type = trim(line.substr(colon + 1));
    }
  }
  const auto body = message.substr(end + 4);
  if (content_type.empty()) {
    if (!trim(body).empty()) invalid("message/sip body without a content type");
    return {};
  }
  return parse_body_parts(content_type, body);
}

//------------------------------------------------------------------------------
// RFC 2046 section 5.1.1 (with RFC 2045 section 5.1 quoting): the "boundary" parameter of a multipart Content-Type,
// without its quotes; a value that opens a quote without closing it is refused.
std::string multipart_boundary(std::string_view type) {
  // RFC 2046 section 5.1.1: a boundary has 1 to 70 characters.
  constexpr std::size_t max_boundary = 70;
  const auto fields = tokens(type, ';');
  std::string boundary;
  bool found = false;
  for (std::size_t index = 1; index < fields.size(); ++index) {
    const auto eq = fields[index].find('=');
    if (eq == std::string::npos || lower(trim(fields[index].substr(0, eq))) != "boundary") continue;
    if (found) invalid("duplicate MIME boundary");
    found = true;
    boundary = trim(fields[index].substr(eq + 1));
    if (boundary.starts_with('"') || boundary.ends_with('"')) {
      if (boundary.size() < 2 || !boundary.starts_with('"') || !boundary.ends_with('"'))
        invalid("unbalanced MIME boundary quotes");
      boundary = boundary.substr(1, boundary.size() - 2);
    }
  }
  if (boundary.empty() || boundary.size() > max_boundary || boundary.find_first_of("\r\n\"") != boundary.npos)
    invalid("missing/invalid MIME boundary");
  return boundary;
}

//------------------------------------------------------------------------------
// RFC 2046 section 5.1.1 with RFC 5621: splits a multipart/mixed or multipart/related body into its parts (at most
// 8), with their content type and Content-ID; any other type is returned as a single part.
std::vector<BodyPart> parse_body_parts(std::string_view type, std::string_view body) {
  bounded_envelope(body);
  auto fields = tokens(type, ';');
  if (fields.empty()) invalid("missing MIME type");
  auto main = lower(fields[0]);
  if (main != "multipart/mixed" && main != "multipart/related") return {{main, std::string(body)}};
  const std::string marker = "--" + multipart_boundary(type);

  // RFC 2046 section 5.1.1: a preamble may precede the first delimiter; PJSIP writes a CRLF.
  std::size_t pos = body.starts_with("\r\n") ? 2 : 0;
  std::vector<BodyPart> out;
  while (pos < body.size()) {
    if (body.substr(pos, marker.size()) != marker) invalid("missing MIME delimiter");
    pos += marker.size();
    if (body.substr(pos, 2) == "--") {
      if (!trim(body.substr(pos + 2)).empty() || out.empty()) invalid("invalid MIME epilogue");
      return out;
    }
    if (body.substr(pos, 2) != "\r\n") invalid("invalid MIME delimiter line");
    pos += 2;
    auto end = body.find("\r\n\r\n", pos);
    if (end == body.npos || end - pos > 2048) invalid("invalid MIME headers");
    std::string content_type, content_id;
    for (auto header : tokens(body.substr(pos, end - pos), '\n')) {
      auto colon = header.find(':');
      if (colon == header.npos) invalid("invalid MIME header");
      const auto name = lower(trim(header.substr(0, colon)));
      if (name == "content-type") {
        if (!content_type.empty()) invalid("duplicate MIME content type");
        content_type = lower(trim(header.substr(colon + 1)));
        content_type = trim(content_type.substr(0, content_type.find(';')));
      } else if (name == "content-id") {
        content_id = trim(header.substr(colon + 1));
        if (content_id.size() >= 2 && content_id.front() == '<' && content_id.back() == '>')
          content_id = content_id.substr(1, content_id.size() - 2);
      }
    }
    if (content_type.empty()) invalid("missing MIME content type");
    pos = end + 4;
    end = body.find("\r\n" + marker, pos);
    if (end == body.npos) invalid("unclosed MIME part");
    out.push_back({content_type, std::string(body.substr(pos, end - pos)), content_id});
    if (out.size() > 8) invalid("too many MIME parts");
    pos = end + 2;
  }
  invalid("unclosed multipart body");
}

} // namespace mcx
