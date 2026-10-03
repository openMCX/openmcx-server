// SIP engine helpers over pjsip: text, URI, header and body conversions, configuration checks, get_header.
//
// Specifications: RFC 3261, RFC 4028, RFC 2046, RFC 5621, RFC 4566.

#include "sip_impl.hpp"

namespace mcx {
namespace sip_detail {

//------------------------------------------------------------------------------
// RFC 3261 section 7.3.1: compares header field names case-insensitively (ASCII only).
[[nodiscard]] bool ascii_equal(std::string_view left, std::string_view right) noexcept {
  if (left.size() != right.size()) {
    return false;
  }
  for (std::size_t index = 0; index < left.size(); ++index) {
    const auto left_character = static_cast<unsigned char>(left[index]);
    const auto right_character = static_cast<unsigned char>(right[index]);
    if (std::tolower(left_character) != std::tolower(right_character)) {
      return false;
    }
  }
  return true;
}

//------------------------------------------------------------------------------
// Helper: returns an ASCII lower-case copy of a value.
[[nodiscard]] std::string ascii_lower(std::string_view value) {
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  return result;
}

//------------------------------------------------------------------------------
// Helper: true when both a username and a password are configured for digest authentication.
[[nodiscard]] bool has_credentials(const SipConfig &config) noexcept {
  return !config.username.empty() && !config.password.empty();
}

namespace {
//------------------------------------------------------------------------------
// RFC 3261 section 19.1.1: the user part and what follows the '@' of a SIP URI identity; throws when the user or
// host is missing.
std::pair<std::string_view, std::string_view> split_identity(std::string_view identity) {
  const auto colon = identity.find(':');
  const auto at = identity.find('@', colon == std::string_view::npos ? 0U : colon + 1U);
  if (colon == std::string_view::npos || at == std::string_view::npos || at <= colon + 1U) {
    throw std::invalid_argument("SIP identity must contain a user and host");
  }
  return {identity.substr(colon + 1U, at - colon - 1U), identity.substr(at + 1U)};
}
} // namespace

//------------------------------------------------------------------------------
// RFC 3261 section 19.1.1: returns the user part of a SIP URI identity; throws when user or host is missing.
[[nodiscard]] std::string identity_user(std::string_view identity) {
  return std::string(split_identity(identity).first);
}

//------------------------------------------------------------------------------
// RFC 3261 section 19.1.1: returns the home domain of an identity, the host of its SIP URI without port or
// parameters.
[[nodiscard]] std::string identity_domain(std::string_view identity) {
  auto host = split_identity(identity).second;
  host = host.substr(0, host.find_first_of(";?>"));
  if (host.starts_with('['))
    host = host.substr(0, host.find(']') + 1U);
  else
    host = host.substr(0, host.find(':'));
  if (host.empty()) throw std::invalid_argument("SIP identity must contain a user and host");
  return std::string(host);
}

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
// RFC 4028 section 4 and RFC 3261 section 26.2: checks the SIP configuration: session expiry of at least
// 90 seconds (the Min-SE floor), mandatory peer certificate verification, SIPS or TLS core URI (explicit TCP
// only for debug), a SIP URI identity and complete TLS material.
void validate_config(const SipConfig &config) {
  if (config.session_expires < 90) throw std::invalid_argument("SIP session expiry must be at least 90 seconds");
  if (config.tls.enabled && !config.tls.verify_server) {
    throw std::invalid_argument("SIP peer certificate verification is mandatory");
  }
  if (config.listen_address.empty() || config.advertise_address.empty() || config.listen_port == 0 ||
      config.core_uri.empty() || config.identity.empty() || config.username.empty() != config.password.empty()) {
    throw std::invalid_argument("SIP runtime identity and transport configuration is incomplete");
  }
  const auto core_uri = ascii_lower(config.core_uri);
  if (config.tls.enabled && !core_uri.starts_with("sips:") &&
      !(core_uri.starts_with("sip:") && core_uri.find(";transport=tls") != std::string::npos)) {
    throw std::invalid_argument("SIP core URI must select TLS transport");
  }
  if (!config.tls.enabled && (!core_uri.starts_with("sip:") || !core_uri.ends_with(";transport=tcp"))) {
    throw std::invalid_argument("Debug SIP core URI must explicitly select TCP");
  }
  const auto identity = ascii_lower(config.identity);
  if (!identity.starts_with("sip:") && !identity.starts_with("sips:")) {
    throw std::invalid_argument("SIP identity must be a SIP URI");
  }
  (void)identity_user(config.identity);
  if (config.tls.enabled &&
      (config.tls.ca_file.empty() || config.tls.cert_file.empty() || config.tls.key_file.empty())) {
    throw std::invalid_argument("SIP TLS CA, certificate, and private key are required");
  }
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
// RFC 4566: parses the local SDP built from the media description (session version 1).
[[nodiscard]] pjmedia_sdp_session *parse_local_sdp(pj_pool_t *pool, const MediaDescription &media) {
  return parse_sdp_text(pool, make_sdp(media, 1));
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
// RFC 5621 and RFC 2046 section 5.1.3: builds a multipart/mixed body with the SDP first, then the given parts.
[[nodiscard]] pjsip_msg_body *make_body_with_sdp(pj_pool_t *pool, const std::string &sdp,
                                                 const std::vector<BodyPart> &parts) {
  std::vector<BodyPart> all{{"application/sdp", sdp}};
  all.insert(all.end(), parts.begin(), parts.end());
  return make_multipart_body(pool, all);
}

//------------------------------------------------------------------------------
// RFC 5621: builds an INVITE multipart/mixed body from the local SDP (session version 1) and the given parts.
[[nodiscard]] pjsip_msg_body *make_invite_body(pj_pool_t *pool, const MediaDescription &media,
                                               const std::vector<BodyPart> &parts) {
  return make_body_with_sdp(pool, make_sdp(media, 1), parts);
}

} // namespace sip_detail

//------------------------------------------------------------------------------
// RFC 3261 section 7.3.1: returns the value of the first header field with the name (case-insensitive), or empty.
std::string_view get_header(const std::vector<SipHeader> &headers, std::string_view name) noexcept {
  for (const auto &header : headers) {
    if (ascii_equal(header.name, name)) {
      return header.value;
    }
  }
  return {};
}

} // namespace mcx
