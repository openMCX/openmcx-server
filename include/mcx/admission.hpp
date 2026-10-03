// Admission checks of the controlling function: the Accept-Contact feature selection of an MC service request.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 3841.
#pragma once
#include "mcx/service.hpp"

#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.2 step 3 (or the same check of TS 24.281): controlling-function feature selection: whether
// the Accept-Contact header fields carry the service's media feature tag and the g.3gpp.icsi-ref with its ICSI. Parse
// complete parameter names and complete feature values; never accept a substring in another tag. Multiple header
// fields and quoted comma-separated ICSI value lists are valid.
inline bool has_service_accept_contact(const std::vector<std::string> &headers, const ServiceProfile &service) {
  const std::string feature_tag = service.feature_tag;
  const auto trim = [](std::string_view value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return std::string{};
    return std::string(value.substr(start, value.find_last_not_of(" \t\r\n") - start + 1));
  };
  const auto lower = [](std::string value) {
    for (auto &character : value) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    return value;
  };
  const auto hex = [](char digit) -> int {
    if (digit >= '0' && digit <= '9') return digit - '0';
    if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
    if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
    return -1;
  };
  bool feature = false, icsi = false;
  for (const auto &header : headers) {
    std::vector<std::string> parameters;
    std::size_t start = 0;
    bool quoted = false, escaped = false;
    for (std::size_t index = 0; index < header.size(); ++index) {
      const auto character = header[index];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (quoted && character == '\\') {
        escaped = true;
        continue;
      }
      if (character == '"') quoted = !quoted;
      if (!quoted && (character == ';' || character == ',')) {
        parameters.push_back(trim(std::string_view(header).substr(start, index - start)));
        start = index + 1;
      }
    }
    if (quoted || escaped) return false;
    parameters.push_back(trim(std::string_view(header).substr(start)));
    for (const auto &parameter : parameters) {
      const auto equals = parameter.find('=');
      auto name = lower(trim(std::string_view(parameter).substr(0, equals)));
      if (name.starts_with('+')) name.erase(0, 1);
      if (name != feature_tag && name != "g.3gpp.icsi-ref") continue;
      std::string value = equals == std::string::npos ? "" : trim(std::string_view(parameter).substr(equals + 1));
      if (value.size() >= 2 && value.front() == '"' && value.back() == '"') value = value.substr(1, value.size() - 2);
      if (name == feature_tag) {
        if (equals == std::string::npos || lower(value) == "true") feature = true;
        continue;
      }
      std::string decoded;
      for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] == '%' && index + 2 < value.size() && hex(value[index + 1]) >= 0 &&
            hex(value[index + 2]) >= 0) {
          decoded.push_back(static_cast<char>((hex(value[index + 1]) << 4) | hex(value[index + 2])));
          index += 2;
        } else
          decoded.push_back(value[index]);
      }
      std::size_t pos = 0;
      while (pos <= decoded.size()) {
        const auto comma = decoded.find(',', pos);
        if (trim(std::string_view(decoded).substr(pos, comma == std::string::npos ? comma : comma - pos)) ==
            service.icsi)
          icsi = true;
        if (comma == std::string::npos) break;
        pos = comma + 1;
      }
    }
  }
  return feature && icsi;
}

//------------------------------------------------------------------------------
// TS 24.379 clause 10.1.1.4.2 step 3: the feature selection of has_service_accept_contact for MCPTT.
inline bool has_mcptt_accept_contact(const std::vector<std::string> &headers) {
  return has_service_accept_contact(headers, mcptt_service);
}
} // namespace mcx
