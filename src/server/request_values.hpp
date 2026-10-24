//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Values the server procedures read from a SIP request, parsed without throwing: the Expires header field
// (RFC 3261 section 20.19) and percent-encoded URI components (RFC 3986 section 2.1). A malformed value gives
// std::nullopt, so that the procedure answers 400 instead of failing with an exception. Also the outcome rule of
// an implicit affiliation (TS 24.379 clause 9.2.2.3.11) and the configuration management documents a subscription's
// resource list names (TS 24.484 clause 6.3.13.3.2.2). Used by the MCPTT and MCVideo servers (McServer) and the
// MCData server (DataServer); free of server state, so that the unit tests reach them.
//
// Specifications: RFC 3261, RFC 3986, RFC 5875, TS 24.379 V19.7.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace mcx {

// RFC 3261 section 20.19: Expires is "an integral number of seconds (in decimal) between 0 and (2**32)-1".
constexpr std::uint64_t max_expires_s = 4294967295ULL;

//------------------------------------------------------------------------------
// RFC 3261 section 20.19 (delta-seconds, section 25.1): the value of an Expires header field, or std::nullopt
// when it is empty, not a decimal number or above 2**32-1.
inline std::optional<std::uint64_t> parse_expires(std::string_view text) {
  if (text.empty()) return std::nullopt;
  std::uint64_t value = 0;
  for (const char digit : text) {
    if (digit < '0' || digit > '9') return std::nullopt;
    value = value * 10 + static_cast<std::uint64_t>(digit - '0');
    if (value > max_expires_s) return std::nullopt;
  }
  return value;
}

//------------------------------------------------------------------------------
// RFC 3986 section 2.1: the value of one hexadecimal digit, or -1.
inline int hex_digit_value(char digit) {
  if (digit >= '0' && digit <= '9') return digit - '0';
  if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
  if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
  return -1;
}

//------------------------------------------------------------------------------
// RFC 3986 section 2.1: a percent-decoded URI component, or std::nullopt when a '%' is not followed by two
// hexadecimal digits.
inline std::optional<std::string> percent_decode(std::string_view text) {
  constexpr std::size_t escape_length = 3; // '%' HEXDIG HEXDIG
  constexpr int bits_per_hex_digit = 4;
  std::string decoded;
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (text[index] != '%') {
      decoded += text[index];
      continue;
    }
    if (index + escape_length > text.size()) return std::nullopt;
    const int high = hex_digit_value(text[index + 1]);
    const int low = hex_digit_value(text[index + 2]);
    if (high < 0 || low < 0) return std::nullopt;
    decoded += static_cast<char>((high << bits_per_hex_digit) | low);
    index += escape_length - 1;
  }
  return decoded;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step e with RFC 5875: a configuration management document an <entry> of a
// configuration subscription's resource list names: its AUID, its XUI (empty for a document of the global tree) and
// its name, percent-decoded.
struct ConfigDocument {
  std::string auid, xui, document;
};

//------------------------------------------------------------------------------
// TS 24.484 clauses 7.4.2.2, 8.2.2.2, 8.3.2.2, 8.4.2.2, 9.2.2.2, 9.3.2.2, 9.4.2.2, 10.2.2.2, 10.3.2.2 and 10.4.2.2:
// the AUIDs of the configuration management documents (clause 6.3.13.3.2.2 step e: "an application usage
// identifying a configuration management document").
inline bool config_auid(std::string_view auid) {
  for (const std::string_view known :
       {"org.3gpp.mcs.location-user-config", "org.3gpp.mcptt.ue-config", "org.3gpp.mcptt.user-profile",
        "org.3gpp.mcptt.service-config", "org.3gpp.mcvideo.ue-config", "org.3gpp.mcvideo.user-profile",
        "org.3gpp.mcvideo.service-config", "org.3gpp.mcdata.ue-config", "org.3gpp.mcdata.user-profile",
        "org.3gpp.mcdata.service-config"})
    if (auid == known) return true;
  return false;
}

//------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step e with RFC 5875 section 4: the document a resource list entry names, as
// "<AUID>/users/<XUI>/<document>" or "<AUID>/global/<document>" (relative to the XCAP root; a path before the AUID
// is passed over); std::nullopt for an entry that names no whole configuration management document (another AUID, a
// node selector, a collection, a malformed percent-encoding).
inline std::optional<ConfigDocument> config_document_reference(std::string_view entry) {
  const auto at = entry.find("org.3gpp.");
  if (at == std::string_view::npos || (at > 0 && entry[at - 1] != '/')) return std::nullopt;
  entry = entry.substr(at);
  const auto slash = entry.find('/');
  if (slash == std::string_view::npos || !config_auid(entry.substr(0, slash))) return std::nullopt;
  ConfigDocument out{std::string(entry.substr(0, slash)), {}, {}};
  auto rest = entry.substr(slash + 1);
  constexpr std::string_view global = "global/", users = "users/";
  std::string_view xui;
  if (rest.substr(0, global.size()) == global) {
    rest = rest.substr(global.size());
  } else if (rest.substr(0, users.size()) == users) {
    rest = rest.substr(users.size());
    const auto end = rest.find('/');
    if (end == std::string_view::npos || end == 0) return std::nullopt;
    xui = rest.substr(0, end);
    rest = rest.substr(end + 1);
  } else {
    return std::nullopt;
  }
  if (rest.empty() || rest.find('/') != std::string_view::npos) return std::nullopt;
  const auto document = percent_decode(rest);
  const auto user = percent_decode(xui);
  if (!document || document->empty() || !user || (!xui.empty() && user->empty())) return std::nullopt;
  out.xui = *user;
  out.document = *document;
  return out;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 9.2.2.3.11: an implicit affiliation made for a request (clause 9.2.2.3.7) is cancelled unless
// the request is finally accepted: when its answer is 300 or above, or when it fails with an exception (which the
// server answers 403 once the affiliation's guard is gone).
constexpr bool implicit_affiliation_cancelled(int status_code, bool failed_with_exception) {
  constexpr int first_failure_status = 300;
  return failed_with_exception || status_code >= first_failure_status;
}

} // namespace mcx
