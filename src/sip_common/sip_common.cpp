//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The SIP engine's stack-independent helpers (the engine is in src/sip/): ASCII header name comparison, SIP identities, the configuration checks, the Contact target and
// service feature tags, the SDP origin of a dialog, and get_header.
//
// Specifications: RFC 3261, RFC 3264, RFC 3840, RFC 4028, RFC 4566, RFC 5626, TS 24.229 V19.7.0 (Rel-19),
// TS 24.379 V19.7.0 (Rel-19), TS 33.203 V19.1.0 (Rel-19).

#include "sip_common.hpp"

#include "mcx/ims_aka.hpp"
#include "mcx/protocol.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <ctime>
#include <sstream>
#include <stdexcept>

namespace mcx {
namespace sip_detail {
namespace {
//------------------------------------------------------------------------------
// RFC 4566 section 5.2: the <sess-id> of the "o=" line is unique for each new session description (an NTP-like
// number, then counted up); a dialog keeps its origin in its later offers and answers (RFC 3264 section 8).
// TS 37.579-2 table 6.2.23.3.3-6: the answer of a call replacing a pre-established session has another sess-id.
std::uint64_t next_sdp_session_id() {
  static std::atomic<std::uint64_t> next{static_cast<std::uint64_t>(std::time(nullptr))};
  return next++;
}

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

//------------------------------------------------------------------------------
// Helper: whether text is a numeric IPv4 or IPv6 address.
bool numeric_address(const std::string &text) {
  unsigned char address[16];
  return inet_pton(text.find(':') != std::string::npos ? AF_INET6 : AF_INET, text.c_str(), address) == 1;
}

//------------------------------------------------------------------------------
// RFC 3264 section 8: an SDP description without its "o=" line, to tell whether a new SDP differs from the previous.
std::string without_origin(const std::string &sdp) {
  std::string out;
  std::size_t start = 0;
  while (start < sdp.size()) {
    auto end = sdp.find('\n', start);
    end = end == std::string::npos ? sdp.size() : end + 1;
    if (sdp.compare(start, 2, "o=") != 0) out.append(sdp, start, end - start);
    start = end;
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 33.203 clause 7.1 and TS 24.229 clause 5.1.1.2.2: an IMS AKA configuration: no TLS (IPsec protects the hop),
// no digest password, the ISIM's private user identity and keys, a numeric P-CSCF address (the SAs bind IP
// addresses) and a numeric own address (Via and Contact name the address bound to the SAs, NOTE 1), and a protected
// server port other than 5060 and 5061 and the unprotected port ("The ports port_us and port_uc are different from the
// standard SIP ports 5060 and 5061").
void validate_aka_config(const SipConfig &config) {
  const auto &aka = config.aka;
  if (config.tls.enabled || !config.password.empty())
    throw std::invalid_argument("IMS AKA replaces TLS and the digest password of the SIP hop");
  if (config.listen_address.empty() || config.identity.empty() || aka.impi.empty() || aka.pcscf_port == 0 ||
      aka.unprotected_port == 0)
    throw std::invalid_argument("IMS AKA configuration is incomplete (sip.isim.impi, sip.pcscf)");
  if (!numeric_address(config.advertise_address) || !numeric_address(aka.pcscf_address))
    throw std::invalid_argument("IMS AKA needs numeric addresses of the UE and the P-CSCF");
  if (config.listen_port == 0 || config.listen_port == 5060 || config.listen_port == 5061 ||
      config.listen_port == aka.unprotected_port)
    throw std::invalid_argument("the IMS AKA protected server port must not be 5060, 5061 or the unprotected port");
  if (aka.impi.find_first_of("\"\r\n") != std::string::npos) throw std::invalid_argument("invalid IMPI");
  (void)aka::key_from_hex(aka.k);
  // TS 34.108 clause 8.1.2: the test algorithm uses K alone.
  if (aka.algorithm != "milenage" && aka.algorithm != "test")
    throw std::invalid_argument("unknown ISIM algorithm (milenage or test)");
  if (aka.algorithm == "milenage" || !aka.opc.empty()) (void)aka::key_from_hex(aka.opc);
  if (aka.res_length < 4 || aka.res_length > 16) throw std::invalid_argument("ISIM RES length must be 4 to 16 bytes");
  // RFC 5626 section 4.4.2: a flow over UDP is kept alive with STUN, which this engine does not send.
  if (aka.udp && !config.outbound_instance.empty())
    throw std::invalid_argument("SIP outbound (RFC 5626) over UDP is not supported: no STUN keepalives");
  (void)aka::amf_from_hex(aka.amf);
  const auto identity = ascii_lower(config.identity);
  if (!identity.starts_with("sip:")) throw std::invalid_argument("SIP identity must be a sip: URI");
  (void)identity_user(config.identity);
}
} // namespace

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
// RFC 4028 section 4 and RFC 3261 section 26.2: checks the SIP configuration: session expiry of at least
// 90 seconds (the Min-SE floor), mandatory peer certificate verification, SIPS or TLS core URI (explicit TCP
// only for debug), a SIP URI identity and complete TLS material.
void validate_config(const SipConfig &config) {
  if (config.session_expires < 90) throw std::invalid_argument("SIP session expiry must be at least 90 seconds");
  if (config.aka.enabled) return validate_aka_config(config);
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
// RFC 3264 section 8 and RFC 4566 section 5.2: see SdpOrigin.
const SdpOrigin &next_sdp_origin(SdpOrigin &origin, const MediaDescription &media) {
  if (origin.id == 0) {
    origin.id = next_sdp_session_id();
    origin.version = 1;
    origin.last = without_origin(make_sdp(media, origin.id, origin.version));
    return origin;
  }
  auto described = without_origin(make_sdp(media, origin.id, origin.version));
  if (described != origin.last) {
    ++origin.version;
    origin.last = std::move(described);
  }
  return origin;
}

//------------------------------------------------------------------------------
// RFC 4566 section 5.2: takes <sess-id> and <sess-version> from the "o=" line of an SDP written by the caller.
void record_sdp_text(SdpOrigin &origin, const std::string &sdp) {
  const auto at = sdp.find("o=");
  if (at == std::string::npos) return;
  std::istringstream line(sdp.substr(at + 2, sdp.find('\n', at) - at - 2));
  std::string user;
  std::uint64_t id = 0, version = 0;
  if (line >> user >> id >> version) {
    origin.id = id;
    origin.version = version;
    origin.last = without_origin(sdp);
  }
}

//------------------------------------------------------------------------------
// RFC 3261 section 20.10: "if the URI contains a comma, question mark or semicolon, the URI MUST be enclosed in angle
// brackets"; a URI in angle brackets (or with a display name) is kept as it is.
std::string name_addr(std::string_view uri) {
  if (uri.find('<') != std::string_view::npos) return std::string(uri);
  return "<" + std::string(uri) + ">";
}

//------------------------------------------------------------------------------
// RFC 3261 sections 8.1.1.8 and 19.1.1, RFC 5626 section 5.4: this endpoint's own Contact URI: the identity's user at
// the advertised address and listening port, with the transport (tls, or udp or tcp without TLS), and ;ob for an
// outbound client. IMS uses no SIPS (TS 24.229).
std::string contact_target(const SipConfig &config) {
  return "sip:" + identity_user(config.identity) + "@" + config.advertise_address + ":" +
         std::to_string(config.listen_port) +
         (config.tls.enabled ? ";transport=tls"
          : config.aka.udp   ? ";transport=udp"
                             : ";transport=tcp") +
         (config.outbound_instance.empty() ? "" : ";ob");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 7.2.1, TS 24.281 clause 7.2.1 and TS 24.282 clause 7.2.1: the media feature tags and the
// g.3gpp.icsi-ref ICSI values of the configured services for the Contact header field (RFC 3840).
std::string service_tags(const SipConfig &config) {
  std::string tags = std::string(";+") + config.service->feature_tag;
  std::string icsis = config.service->icsi_encoded;
  for (const auto *other : config.other_services) {
    tags += std::string(";+") + other->feature_tag;
    icsis += std::string(",") + other->icsi_encoded;
  }
  return tags + ";+g.3gpp.icsi-ref=\"" + icsis + "\"";
}
} // namespace sip_detail

//------------------------------------------------------------------------------
// RFC 3261 section 7.3.1: returns the value of the first header field with the name (case-insensitive), or empty.
std::string_view get_header(const std::vector<SipHeader> &headers, std::string_view name) noexcept {
  for (const auto &header : headers) {
    if (sip_detail::ascii_equal(header.name, name)) {
      return header.value;
    }
  }
  return {};
}

} // namespace mcx
