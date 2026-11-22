//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SIP engine helpers over pjsip: text, URI, header and body conversions, configuration checks, get_header.
//
// Specifications: RFC 3261, RFC 4028, RFC 2046, RFC 5621, RFC 4566.

#include "sip_impl.hpp"

#include <arpa/inet.h>

#include <atomic>
#include <ctime>
#include <sstream>

namespace mcx {

namespace sip_detail {

//------------------------------------------------------------------------------
// Helper: a non-owning pj_str_t view of a string (pjsip does not modify it).
[[nodiscard]] pj_str_t pj_view(std::string_view value) {
  return pj_str_t{const_cast<char *>(value.data()), static_cast<pj_ssize_t>(value.size())};
}

//------------------------------------------------------------------------------
// Helper: copies a pj_str_t into a std::string (empty when null).
[[nodiscard]] std::string string_from(const pj_str_t &value) {
  return value.ptr == nullptr || value.slen <= 0 ? std::string{}
                                                 : std::string(value.ptr, static_cast<std::size_t>(value.slen));
}

//------------------------------------------------------------------------------
// Helper: the pjlib text of a status code.
[[nodiscard]] std::string status_error(pj_status_t status) {
  std::array<char, PJ_ERR_MSG_SIZE> buffer{};
  pj_strerror(status, buffer.data(), buffer.size());
  return std::string(buffer.data());
}

//------------------------------------------------------------------------------
// Helper: throws std::runtime_error naming the operation when a pjlib status is not PJ_SUCCESS.
void require_success(pj_status_t status, std::string_view operation) {
  if (status != PJ_SUCCESS) {
    throw std::runtime_error(std::string(operation) + ": " + status_error(status));
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 19.1: prints a URI in Request-URI form (empty when null).
[[nodiscard]] std::string print_uri(const pjsip_uri *uri) {
  if (uri == nullptr) {
    return {};
  }
  std::array<char, PJSIP_MAX_URL_SIZE> buffer{};
  const int length = pjsip_uri_print(PJSIP_URI_IN_REQ_URI, uri, buffer.data(), buffer.size());
  return length > 0 ? std::string(buffer.data(), static_cast<std::size_t>(length)) : std::string{};
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.4: prints a message body, growing the buffer up to kMaximumSipBodyBytes.
[[nodiscard]] std::string print_body(pjsip_msg_body *body) {
  if (body == nullptr) {
    return {};
  }
  if (body->print_body != nullptr) {
    std::vector<char> buffer(4096);
    while (buffer.size() <= kMaximumSipBodyBytes) {
      const int length = body->print_body(body, buffer.data(), buffer.size());
      if (length >= 0) {
        return std::string(buffer.data(), static_cast<std::size_t>(length));
      }
      buffer.resize(buffer.size() * 2U);
    }
    throw std::invalid_argument("SIP body exceeds parser bound");
  }
  if (body->data == nullptr || body->len > kMaximumSipBodyBytes) {
    throw std::invalid_argument("SIP body is unavailable or exceeds parser bound");
  }
  return std::string(static_cast<const char *>(body->data), body->len);
}

//------------------------------------------------------------------------------
// RFC 3261 section 20.15: prints a Content-Type media type with its parameters.
[[nodiscard]] std::string print_media_type(const pjsip_media_type &type) {
  std::array<char, 512> buffer{};
  const int length = pjsip_media_type_print(buffer.data(), buffer.size(), &type);
  return length > 0 ? std::string(buffer.data(), static_cast<std::size_t>(length)) : std::string{};
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.3: collects every header field of a message as name and value (leading whitespace of the
// value removed).
[[nodiscard]] std::vector<SipHeader> collect_headers(pjsip_msg *message) {
  std::vector<SipHeader> headers;
  if (message == nullptr) {
    return headers;
  }
  for (pjsip_hdr *header = message->hdr.next; header != &message->hdr; header = header->next) {
    std::array<char, PJSIP_MAX_PKT_LEN> buffer{};
    const int length = pjsip_hdr_print_on(header, buffer.data(), buffer.size());
    if (length <= 0) {
      continue;
    }
    const std::string_view line(buffer.data(), static_cast<std::size_t>(length));
    const auto separator = line.find(':');
    if (separator == std::string_view::npos) {
      continue;
    }
    std::size_t value_start = separator + 1U;
    while (value_start < line.size() && (line[value_start] == ' ' || line[value_start] == '\t')) {
      ++value_start;
    }
    headers.push_back({std::string(line.substr(0, separator)), std::string(line.substr(value_start))});
  }
  return headers;
}

//------------------------------------------------------------------------------
// RFC 3261 section 20.20: returns the URI of a From or To style header without display name or tag.
[[nodiscard]] std::string bare_header_uri(pjsip_msg *message, pjsip_hdr_e type) {
  auto *header = static_cast<pjsip_from_hdr *>(pjsip_msg_find_hdr(message, type, nullptr));
  return header == nullptr ? std::string{} : print_uri(header->uri);
}

//------------------------------------------------------------------------------
// RFC 3261 section 20.8: returns the Call-ID of a message.
[[nodiscard]] std::string call_id_from(pjsip_msg *message) {
  auto *header = static_cast<pjsip_cid_hdr *>(pjsip_msg_find_hdr(message, PJSIP_H_CALL_ID, nullptr));
  return header == nullptr ? std::string{} : string_from(header->id);
}

//------------------------------------------------------------------------------
// RFC 3261 section 20.15: returns the Content-Type of a message body (empty without body).
[[nodiscard]] std::string content_type_from(pjsip_msg *message) {
  return message != nullptr && message->body != nullptr ? print_media_type(message->body->content_type) : std::string{};
}

//------------------------------------------------------------------------------
// RFC 3261 section 20.15: builds a message body of the given Content-Type (parsed and checked for CR/LF) in the
// pool; returns null for an empty content type.
[[nodiscard]] pjsip_msg_body *make_text_body(pj_pool_t *pool, std::string_view content_type, std::string_view body) {
  if (content_type.empty()) {
    return nullptr;
  }
  if (body.size() > kMaximumSipBodyBytes) {
    throw std::invalid_argument("SIP body exceeds configured bound");
  }
  if (content_type.find_first_of("\r\n") != std::string_view::npos) {
    throw std::invalid_argument("invalid SIP content type");
  }

  auto header_name = pj_view("Content-Type");
  char *header_value = static_cast<char *>(pj_pool_alloc(pool, content_type.size() + 1U));
  std::memcpy(header_value, content_type.data(), content_type.size());
  header_value[content_type.size()] = '\0';
  auto *parsed =
      static_cast<pjsip_ctype_hdr *>(pjsip_parse_hdr(pool, &header_name, header_value, content_type.size(), nullptr));
  if (parsed == nullptr || parsed->type != PJSIP_H_CONTENT_TYPE) {
    throw std::invalid_argument("invalid SIP content type");
  }

  auto type = parsed->media.type;
  auto subtype = parsed->media.subtype;
  auto text = pj_view(body);
  auto *result = pjsip_msg_body_create(pool, &type, &subtype, &text);
  if (result == nullptr) {
    throw std::runtime_error("could not create SIP message body");
  }
  pjsip_media_type_cp(pool, &result->content_type, &parsed->media);
  return result;
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.3: creates a header field in the pool, parsed when pjsip knows it, otherwise generic;
// rejects CR/LF injection.
[[nodiscard]] pjsip_hdr *create_header(pj_pool_t *pool, const SipHeader &header) {
  if (header.name.empty() || header.name.find_first_of("\r\n") != std::string::npos ||
      header.value.find_first_of("\r\n") != std::string::npos) {
    throw std::invalid_argument("invalid SIP header");
  }
  auto name = pj_view(header.name);
  char *value = static_cast<char *>(pj_pool_alloc(pool, header.value.size() + 1U));
  std::memcpy(value, header.value.data(), header.value.size());
  value[header.value.size()] = '\0';
  auto *parsed = static_cast<pjsip_hdr *>(pjsip_parse_hdr(pool, &name, value, header.value.size(), nullptr));
  if (parsed == nullptr) {
    auto header_value = pj_view(header.value);
    parsed = reinterpret_cast<pjsip_hdr *>(pjsip_generic_string_hdr_create(pool, &name, &header_value));
  }
  return parsed;
}

//------------------------------------------------------------------------------
// Helper: appends one header field to an outgoing message.
void add_header(pjsip_tx_data *data, const SipHeader &header) {
  pjsip_msg_add_hdr(data->msg, create_header(data->pool, header));
}

//------------------------------------------------------------------------------
// RFC 3261 section 20.10: appends header fields to an outgoing message; a single Contact override replaces the
// generated Contact.
void add_headers(pjsip_tx_data *data, const std::vector<SipHeader> &headers) {
  bool contact_seen = false;
  for (const auto &header : headers) {
    if (ascii_equal(header.name, "Contact")) {
      if (contact_seen) throw std::invalid_argument("duplicate Contact override");
      contact_seen = true;
      while (pjsip_msg_find_remove_hdr(data->msg, PJSIP_H_CONTACT, nullptr)) {}
    }
    add_header(data, header);
  }
}

//------------------------------------------------------------------------------
// RFC 3261 sections 7.3.1, 20.32 and 20.37: adds a server's own header fields to its answer to an initial INVITE, or to
// its initial INVITE: option tags of a Supported or Require header field join the message's header field of that name
// (the "timer" tag pjsip's session timer may have put in Require already stays once); any other header field is added
// unless the message already has one of that name.
void add_answer_headers(pjsip_tx_data *data, const std::vector<SipHeader> &headers) {
  for (const auto &header : headers) {
    const bool require = ascii_equal(header.name, "Require");
    if (require || ascii_equal(header.name, "Supported")) {
      auto *supported = static_cast<pjsip_generic_array_hdr *>(
          pjsip_msg_find_hdr(data->msg, require ? PJSIP_H_REQUIRE : PJSIP_H_SUPPORTED, nullptr));
      if (supported == nullptr) {
        add_header(data, header);
        continue;
      }
      std::istringstream tags(header.value);
      for (std::string tag; std::getline(tags, tag, ',');) {
        tag.erase(0, tag.find_first_not_of(" \t"));
        tag.erase(tag.find_last_not_of(" \t") + 1);
        if (tag.empty()) continue;
        bool present = false;
        for (unsigned i = 0; i < supported->count; ++i)
          present = present || pj_stricmp2(&supported->values[i], tag.c_str()) == 0;
        if (present) continue;
        if (supported->count >= PJ_ARRAY_SIZE(supported->values)) throw std::runtime_error("too many option tags");
        pj_strdup2(data->pool, &supported->values[supported->count++], tag.c_str());
      }
      continue;
    }
    auto name = pj_view(header.name);
    if (pjsip_msg_find_hdr_by_name(data->msg, &name, nullptr) == nullptr) add_header(data, header);
  }
}

//------------------------------------------------------------------------------
// RFC 4566: parses SDP text into a pjmedia session allocated in the pool.
[[nodiscard]] pjmedia_sdp_session *parse_sdp_text(pj_pool_t *pool, const std::string &text) {
  char *mutable_text = static_cast<char *>(pj_pool_alloc(pool, text.size() + 1U));
  std::memcpy(mutable_text, text.data(), text.size());
  mutable_text[text.size()] = '\0';
  pjmedia_sdp_session *session = nullptr;
  require_success(pjmedia_sdp_parse(pool, mutable_text, text.size(), &session), "parse local SDP");
  return session;
}

//------------------------------------------------------------------------------
// RFC 4566: parses the local SDP built from the media description, with the dialog's origin (see SdpOrigin).
[[nodiscard]] pjmedia_sdp_session *parse_local_sdp(pj_pool_t *pool, const MediaDescription &media,
                                                   const SdpOrigin &origin) {
  return parse_sdp_text(pool, make_sdp(media, origin.id, origin.version));
}

//------------------------------------------------------------------------------
// RFC 2046 section 5.1.3, RFC 5621 and RFC 2392: builds a multipart/mixed body of the parts in the pool, each with
// its Content-ID when it has one.
[[nodiscard]] pjsip_msg_body *make_multipart_body(pj_pool_t *pool, const std::vector<BodyPart> &parts) {
  pjsip_media_type multipart_type{};
  multipart_type.type = pj_view("multipart");
  multipart_type.subtype = pj_view("mixed");
  auto *multipart = pjsip_multipart_create(pool, &multipart_type, nullptr);
  if (multipart == nullptr) throw std::bad_alloc();
  for (const auto &part : parts) {
    auto *entry = pjsip_multipart_create_part(pool);
    if (entry == nullptr) throw std::bad_alloc();
    entry->body = make_text_body(pool, part.content_type, part.body);
    if (!part.content_id.empty()) {
      auto name = pj_view("Content-ID");
      const auto value_text = "<" + part.content_id + ">";
      pj_str_t value{};
      pj_strdup2_with_null(pool, &value, value_text.c_str());
      pj_list_push_back(&entry->hdr, pjsip_generic_string_hdr_create(pool, &name, &value));
    }
    require_success(pjsip_multipart_add_part(pool, multipart, entry), "add SIP multipart part");
  }
  return multipart;
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.4 and RFC 5621: the body of an answer without SDP: one part as a plain body of its own type,
// several as multipart/mixed with the boundary.
[[nodiscard]] pjsip_msg_body *make_parts_body(pj_pool_t *pool, const std::vector<BodyPart> &parts,
                                              std::string_view boundary) {
  if (parts.size() == 1 && parts.front().content_id.empty())
    return make_text_body(pool, parts.front().content_type, parts.front().body);
  return make_text_body(pool, "multipart/mixed; boundary=" + std::string(boundary), multipart_body(parts, boundary));
}

//------------------------------------------------------------------------------
// RFC 5621 and RFC 2046 section 5.1.3: builds a multipart/mixed body with the SDP first, then the given parts; the SDP
// alone is a plain application/sdp body (RFC 3261 section 7.4).
[[nodiscard]] pjsip_msg_body *make_body_with_sdp(pj_pool_t *pool, const std::string &sdp,
                                                 const std::vector<BodyPart> &parts) {
  if (parts.empty()) return make_text_body(pool, "application/sdp", sdp);
  std::vector<BodyPart> all{{"application/sdp", sdp}};
  all.insert(all.end(), parts.begin(), parts.end());
  return make_multipart_body(pool, all);
}

//------------------------------------------------------------------------------
// RFC 5621: builds an INVITE body from the local SDP, with the dialog's origin (see SdpOrigin), and the given parts
// (see make_body_with_sdp).
[[nodiscard]] pjsip_msg_body *make_invite_body(pj_pool_t *pool, const MediaDescription &media,
                                               const std::vector<BodyPart> &parts, const SdpOrigin &origin) {
  return make_body_with_sdp(pool, make_sdp(media, origin.id, origin.version), parts);
}

} // namespace sip_detail

} // namespace mcx
