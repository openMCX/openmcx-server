//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The ICE attributes of the SDP of a pre-established session (RFC 8839, TS 24.379 clauses 4.9, 8.2.1 and 8.2.2): the
// "a=candidate" lines, the "a=ice-ufrag", "a=ice-pwd", "a=ice-lite" and "a=ice-options" attributes; make_sdp and
// parse_sdp (sdp.cpp) call these.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 37.579-1 V18.1.0 (Rel-18), RFC 8839, RFC 8445.

#include "protocol_internal.hpp"

#include <algorithm>
#include <cctype>
#include <ostream>

namespace mcx {
namespace {

// RFC 8839 section 5.1: foundation = 1*32ice-char; component-id = 1*3DIGIT (at most 256, RFC 8445 section 5.1.1.1);
// priority = 1*10DIGIT (a 32-bit value, RFC 8445 section 5.1.2).
constexpr std::size_t kFoundationMaximum = 32;
constexpr unsigned kComponentMaximum = 256;
// RFC 8839 section 5.4: ice-ufrag = 4*256ice-char, ice-pwd = 22*256ice-char.
constexpr std::size_t kUfragMinimum = 4, kPwdMinimum = 22, kCredentialMaximum = 256;
// The components of the sections of an MCPTT SDP (TS 37.579-1 table 5.5.3.1.1-1): RTP and RTCP for the audio, one
// for the media plane control channel.
constexpr unsigned kAudioComponents = 2, kControlComponents = 1;

//------------------------------------------------------------------------------
// RFC 8839 section 5.1: ice-char = ALPHA / DIGIT / "+" / "/".
bool ice_chars(std::string_view text) {
  return !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char character) {
    return std::isalnum(character) || character == '+' || character == '/';
  });
}

//------------------------------------------------------------------------------
// RFC 4566 section 9 token, for the transport and candidate type extensions of RFC 8839 section 5.1.
bool sdp_token(std::string_view text) {
  static constexpr std::string_view extra = "!#$%&'*+-.^_`{|}~";
  return !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char character) {
    return std::isalnum(character) || extra.find(static_cast<char>(character)) != std::string_view::npos;
  });
}

//------------------------------------------------------------------------------
// RFC 8839 section 5.1 connection-address (RFC 4566): an IPv4 or IPv6 address or an FQDN, checked for its characters.
void connection_address(std::string_view text) {
  if (text.empty() || text.size() > 255 || !std::all_of(text.begin(), text.end(), [](unsigned char character) {
        return std::isalnum(character) || character == '.' || character == ':' || character == '-';
      }))
    invalid("invalid ICE candidate address: RFC 8839 section 5.1");
}

//------------------------------------------------------------------------------
// Helper: a decimal field of at most `digits` digits and value `maximum`.
std::uint64_t decimal(std::string_view text, std::size_t digits, std::uint64_t maximum, const char *what) {
  if (text.empty() || text.size() > digits ||
      !std::all_of(text.begin(), text.end(), [](unsigned char character) { return std::isdigit(character); }))
    invalid(what);
  const auto value = std::stoull(std::string(text));
  if (value > maximum) invalid(what);
  return value;
}

//------------------------------------------------------------------------------
// RFC 8839 section 5.4: checks an ICE username fragment and password.
void check_credentials(std::string_view ufrag, std::string_view pwd) {
  if (ufrag.size() < kUfragMinimum || ufrag.size() > kCredentialMaximum || !ice_chars(ufrag))
    invalid("invalid ice-ufrag: RFC 8839 section 5.4");
  if (pwd.size() < kPwdMinimum || pwd.size() > kCredentialMaximum || !ice_chars(pwd))
    invalid("invalid ice-pwd: RFC 8839 section 5.4");
}

//------------------------------------------------------------------------------
// Helper: checks the candidates of a section against its number of components.
void check_components(const std::vector<IceCandidate> &candidates, unsigned components) {
  for (const auto &candidate : candidates)
    if (candidate.component == 0 || candidate.component > components)
      invalid("ICE candidate for a component the media section does not have");
}

//------------------------------------------------------------------------------
// Helper: a credential seen at session or media level; one value for the whole SDP (see IceDescription).
void set_credential(std::string &held, std::string_view value) {
  if (!held.empty() && held != value)
    invalid("different ICE credentials per media section are not supported: RFC 8839 section 5.4");
  held = std::string(value);
}

} // namespace

//------------------------------------------------------------------------------
// RFC 8839 section 5.1: foundation component-id transport priority connection-address port "typ" cand-type
// ["raddr" rel-addr] ["rport" rel-port].
std::string ice_candidate_value(const IceCandidate &candidate) {
  if (candidate.foundation.size() > kFoundationMaximum || !ice_chars(candidate.foundation))
    invalid("invalid ICE foundation: RFC 8839 section 5.1");
  if (candidate.component == 0 || candidate.component > kComponentMaximum) invalid("invalid ICE component-id");
  if (!sdp_token(candidate.transport) || !sdp_token(candidate.type)) invalid("invalid ICE transport or type");
  connection_address(candidate.address);
  if (!candidate.port) invalid("ICE candidate without a port");
  std::string out = candidate.foundation + ' ' + std::to_string(candidate.component) + ' ' + candidate.transport +
                    ' ' + std::to_string(candidate.priority) + ' ' + candidate.address + ' ' +
                    std::to_string(candidate.port) + " typ " + candidate.type;
  if (!candidate.related_address.empty()) {
    connection_address(candidate.related_address);
    out += " raddr " + candidate.related_address + " rport " + std::to_string(candidate.related_port);
  }
  return out;
}

//------------------------------------------------------------------------------
// RFC 8839 section 5.1: reads a candidate; cand-extensions after the related address are ignored (section 5.1:
// "SHOULD ignore" unknown ones).
IceCandidate parse_ice_candidate(std::string_view value) {
  const auto fields = tokens(value, ' ');
  if (fields.size() < 8 || fields[6] != "typ") invalid("malformed ICE candidate: RFC 8839 section 5.1");
  IceCandidate candidate;
  candidate.foundation = fields[0];
  if (candidate.foundation.size() > kFoundationMaximum || !ice_chars(candidate.foundation))
    invalid("invalid ICE foundation: RFC 8839 section 5.1");
  candidate.component = static_cast<unsigned>(decimal(fields[1], 3, kComponentMaximum, "invalid ICE component-id"));
  if (candidate.component == 0) invalid("invalid ICE component-id");
  if (!sdp_token(fields[2])) invalid("invalid ICE transport");
  candidate.transport = fields[2];
  candidate.priority = static_cast<std::uint32_t>(decimal(fields[3], 10, UINT32_MAX, "invalid ICE priority"));
  connection_address(fields[4]);
  candidate.address = fields[4];
  candidate.port = static_cast<std::uint16_t>(decimal(fields[5], 5, 65535, "invalid ICE port"));
  if (!sdp_token(fields[7])) invalid("invalid ICE candidate type");
  candidate.type = fields[7];
  for (std::size_t index = 8; index + 1 < fields.size(); index += 2) {
    if (fields[index] == "raddr") {
      connection_address(fields[index + 1]);
      candidate.related_address = fields[index + 1];
    } else if (fields[index] == "rport") {
      candidate.related_port = static_cast<std::uint16_t>(decimal(fields[index + 1], 5, 65535, "invalid ICE rport"));
    }
  }
  return candidate;
}

namespace protocol_detail {

//------------------------------------------------------------------------------
// RFC 8839 sections 5.4 to 5.6: the session-level ICE attributes (credentials, "ice-lite", "ice-options").
void write_ice_session(std::ostream &out, const IceDescription &ice) {
  check_credentials(ice.ufrag, ice.pwd);
  check_components(ice.audio, kAudioComponents);
  check_components(ice.control, kControlComponents);
  if (ice.lite) out << "a=ice-lite\r\n";
  if (!ice.options.empty()) {
    out << "a=ice-options:";
    for (std::size_t index = 0; index < ice.options.size(); ++index) {
      if (!ice_chars(ice.options[index])) invalid("invalid ice-options tag: RFC 8839 section 5.6");
      out << (index ? " " : "") << ice.options[index];
    }
    out << "\r\n";
  }
  out << "a=ice-ufrag:" << ice.ufrag << "\r\na=ice-pwd:" << ice.pwd << "\r\n";
}

//------------------------------------------------------------------------------
// RFC 8839 section 5.1: the "a=candidate" lines of a media section.
void write_ice_candidates(std::ostream &out, const std::vector<IceCandidate> &candidates) {
  for (const auto &candidate : candidates) out << "a=candidate:" << ice_candidate_value(candidate) << "\r\n";
}

//------------------------------------------------------------------------------
// RFC 8839 sections 5.1 and 5.4 to 5.6: reads an ICE attribute of the session or of the "audio" or "application"
// section; returns whether the line was one.
bool parse_ice_attribute(std::string_view line, std::string_view section, IceSdpState &state) {
  const auto attribute = line.substr(2);
  if (attribute.starts_with("candidate:")) {
    auto candidate = parse_ice_candidate(attribute.substr(10));
    if (section == "audio")
      state.ice.audio.push_back(std::move(candidate));
    else if (section == "application")
      state.ice.control.push_back(std::move(candidate));
    else
      invalid("ICE candidate outside an audio or application section: RFC 8839 section 5.1");
    state.seen = true;
  } else if (attribute.starts_with("ice-ufrag:")) {
    set_credential(state.ice.ufrag, trim(attribute.substr(10)));
    state.seen = true;
  } else if (attribute.starts_with("ice-pwd:")) {
    set_credential(state.ice.pwd, trim(attribute.substr(8)));
    state.seen = true;
  } else if (attribute == "ice-lite") {
    // RFC 8839 section 5.3: a session-level attribute only.
    if (!section.empty()) invalid("ice-lite at media level: RFC 8839 section 5.3");
    state.ice.lite = true;
    state.seen = true;
  } else if (attribute.starts_with("ice-options:")) {
    for (const auto &tag : tokens(attribute.substr(12), ' ')) {
      if (!ice_chars(tag)) invalid("invalid ice-options tag: RFC 8839 section 5.6");
      state.ice.options.push_back(tag);
    }
    state.seen = true;
  } else {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
// RFC 8839 section 5.4: an SDP with ICE attributes has the credentials; the candidates fit the sections. With
// without_credentials (SdpReadOptions::ice_without_credentials), an SDP whose ICE attributes have neither credential
// is read without ICE; one credential alone is still refused.
std::optional<IceDescription> finish_ice(const IceSdpState &state, bool without_credentials) {
  if (!state.seen) return std::nullopt;
  if (without_credentials && state.ice.ufrag.empty() && state.ice.pwd.empty()) return std::nullopt;
  check_credentials(state.ice.ufrag, state.ice.pwd);
  check_components(state.ice.audio, kAudioComponents);
  check_components(state.ice.control, kControlComponents);
  return state.ice;
}

} // namespace protocol_detail
} // namespace mcx
