//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The SIP engine's stack-independent helpers (sip_common.cpp), shared by its pjproject implementation (src/sip/) and
// its reSIProcate one (src/sip_resip/).
//
// Private to the SIP engine: include/mcx/sip.hpp is its interface.
//
// Specifications: RFC 3261, RFC 3264, RFC 3840, RFC 4028, RFC 4566, RFC 5626, TS 24.229 V19.7.0 (Rel-19),
// TS 24.379 V19.7.0 (Rel-19), TS 33.203 V19.1.0 (Rel-19).
#pragma once

#include "mcx/protocol.hpp"
#include "mcx/sip.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace mcx::sip_detail {
// Helper: the largest SIP message body printed or accepted, in bytes.
inline constexpr std::size_t kMaximumSipBodyBytes = 1024U * 1024U;

//------------------------------------------------------------------------------
// RFC 3261 section 7.3.1: compares header field names case-insensitively (ASCII only).
[[nodiscard]] bool ascii_equal(std::string_view left, std::string_view right) noexcept;

//------------------------------------------------------------------------------
// Helper: returns an ASCII lower-case copy of a value.
[[nodiscard]] std::string ascii_lower(std::string_view value);

//------------------------------------------------------------------------------
// Helper: true when both a username and a password are configured for digest authentication.
[[nodiscard]] bool has_credentials(const SipConfig &config) noexcept;

//------------------------------------------------------------------------------
// RFC 3261 section 19.1.1: returns the user part of a SIP URI identity; throws when user or host is missing.
[[nodiscard]] std::string identity_user(std::string_view identity);

//------------------------------------------------------------------------------
// RFC 3261 section 19.1.1: the home domain of an identity: the host of its SIP URI, without port or parameters.
[[nodiscard]] std::string identity_domain(std::string_view identity);

//------------------------------------------------------------------------------
// RFC 4028 section 4 and RFC 3261 section 26.2: checks the SIP configuration (session expiry, TLS and identity, or IMS
// AKA); throws std::invalid_argument.
void validate_config(const SipConfig &config);

//------------------------------------------------------------------------------
// RFC 3261 section 20.10: a URI as the value of a To or From header field: in angle brackets (a name-addr) unless it
// already is one, so that its URI parameters (";mcptt-pre-established", ";mcptt-session=...") stay with the URI
// instead of being read as header field parameters.
[[nodiscard]] std::string name_addr(std::string_view uri);

//------------------------------------------------------------------------------
// RFC 3261 sections 8.1.1.8 and 19.1.1, RFC 5626 section 5.4: this endpoint's own Contact URI (SipEngine::contact_target).
[[nodiscard]] std::string contact_target(const SipConfig &config);

//------------------------------------------------------------------------------
// TS 24.379 clause 7.2.1 and RFC 3840: the media feature tags and g.3gpp.icsi-ref of the configured services.
[[nodiscard]] std::string service_tags(const SipConfig &config);

//------------------------------------------------------------------------------
// RFC 3264 section 8 and RFC 4566 section 5.2: the "o=" line of the SDP this side sends in one dialog. The first SDP
// takes a new <sess-id> with <sess-version> 1; every later SDP (re-INVITE or UPDATE offer, answer to one) keeps the
// <sess-id> and increments the <sess-version> by one when its description differs from the previous one, else keeps it.
struct SdpOrigin {
  std::uint64_t id = 0;
  std::uint64_t version = 0;
  std::string last; // the previous description without its "o=" line
};

// The origin of the next SDP built from `media` in the dialog of `origin` (updated in place).
const SdpOrigin &next_sdp_origin(SdpOrigin &origin, const MediaDescription &media);
// Records an SDP the caller wrote itself (its "o=" line) as the dialog's last SDP.
void record_sdp_text(SdpOrigin &origin, const std::string &sdp);
} // namespace mcx::sip_detail
