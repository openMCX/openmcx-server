// JSON storage of the MIKEY-SAKKE key material: hex encoding and the JSON conversions of the KMS key periods, public
// parameters, authority secrets and user key sets.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), RFC 6507, RFC 6508.
#pragma once
#include "mcx/keying.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace mcx::keying {
//------------------------------------------------------------------------------
// Helper: the lower-case hex encoding of bytes.
inline std::string hex(std::span<const std::uint8_t> value) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(value.size() * 2);
  for (auto octet : value) {
    out += digits[octet >> 4];
    out += digits[octet & 15];
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: the bytes of a hex string (at most 65536 digits); throws on an odd length or a non-hex digit.
inline Bytes unhex(std::string_view value) {
  if (value.size() % 2 || value.size() > 65536) throw std::invalid_argument("invalid hex key length");
  const auto nibble = [](char digit) -> unsigned {
    if (digit >= '0' && digit <= '9') return digit - '0';
    if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
    if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
    throw std::invalid_argument("invalid hex key");
  };
  Bytes out;
  out.reserve(value.size() / 2);
  for (size_t index = 0; index < value.size(); index += 2)
    out.push_back((nibble(value[index]) << 4) | nibble(value[index + 1]));
  return out;
}

//------------------------------------------------------------------------------
// Helper: a key period as JSON.
inline void to_json(nlohmann::json &json, const Period &period) {
  json = {{"kms_uri", period.kms_uri}, {"seconds", period.seconds}, {"offset", period.offset}};
}

//------------------------------------------------------------------------------
// Helper: a key period from JSON.
inline void from_json(const nlohmann::json &json, Period &period) {
  json.at("kms_uri").get_to(period.kms_uri);
  json.at("seconds").get_to(period.seconds);
  json.at("offset").get_to(period.offset);
}

//------------------------------------------------------------------------------
// Helper: the public parameters of a KMS as JSON.
inline void to_json(nlohmann::json &json, const PublicParameters &parameters) {
  json = {{"period", parameters.period},
          {"authentication_key", hex(parameters.authentication_key)},
          {"encryption_key", hex(parameters.encryption_key)}};
}

//------------------------------------------------------------------------------
// Helper: the public parameters of a KMS from JSON.
inline void from_json(const nlohmann::json &json, PublicParameters &parameters) {
  json.at("period").get_to(parameters.period);
  parameters.authentication_key = unhex(json.at("authentication_key").get<std::string>());
  parameters.encryption_key = unhex(json.at("encryption_key").get<std::string>());
}

//------------------------------------------------------------------------------
// Helper: a KMS authority with its secrets as JSON.
inline void to_json(nlohmann::json &json, const Authority &authority) {
  json = {{"public_parameters", authority.public_parameters},
          {"authentication_secret", hex(authority.authentication_secret)},
          {"encryption_secret", hex(authority.encryption_secret)}};
}

//------------------------------------------------------------------------------
// Helper: a KMS authority with its secrets from JSON.
inline void from_json(const nlohmann::json &json, Authority &authority) {
  json.at("public_parameters").get_to(authority.public_parameters);
  authority.authentication_secret = unhex(json.at("authentication_secret").get<std::string>());
  authority.encryption_secret = unhex(json.at("encryption_secret").get<std::string>());
}

//------------------------------------------------------------------------------
// Helper: a user's key set as JSON.
inline void to_json(nlohmann::json &json, const IdentityKeys &keys) {
  json = {{"uri", keys.uri},
          {"period_number", keys.period_number},
          {"signing_pair", hex(keys.signing_pair)},
          {"receiver_secret", hex(keys.receiver_secret)}};
}

//------------------------------------------------------------------------------
// Helper: a user's key set from JSON.
inline void from_json(const nlohmann::json &json, IdentityKeys &keys) {
  json.at("uri").get_to(keys.uri);
  json.at("period_number").get_to(keys.period_number);
  keys.signing_pair = unhex(json.at("signing_pair").get<std::string>());
  keys.receiver_secret = unhex(json.at("receiver_secret").get<std::string>());
}
} // namespace mcx::keying
