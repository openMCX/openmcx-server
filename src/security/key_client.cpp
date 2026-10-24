//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Key management client: provisioning from the Home KMS over HTTPS, and the CSK, PCK and GMK MIKEY-SAKKE exchanges
// with their replay and epoch checks.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), RFC 6509,
// RFC 4648.
#include "mcx/key_client.hpp"

#include "mcx/key_documents.hpp"
#include "mcx/security.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>

namespace mcx {
namespace {
constexpr std::uint64_t ntp_epoch = 2208988800ULL;
constexpr std::size_t maximum_cache_entries = 4096;

//------------------------------------------------------------------------------
// Helper: throws the given error when a condition fails.
void require(bool condition, const char *what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Helper: the current time in NTP seconds (since 1900-01-01).
std::uint64_t now_ntp() {
  const auto now =
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  require(now >= 0, "invalid system time");
  return static_cast<std::uint64_t>(now) + ntp_epoch;
}

//------------------------------------------------------------------------------
// Helper: one octet of the key parameter wire profile (TS 33.180 annex E.6.1 and clause 8.5.4 assign no IEI or
// algorithm numbers).
std::uint8_t profile_byte(const nlohmann::json &profile, const char *field) {
  const auto &value = profile.at(field);
  require(value.is_number_integer(), "key parameter profile must contain integers");
  const auto number = value.get<std::int64_t>();
  require(number >= 0 && number <= 255, "key parameter profile byte out of range");
  return static_cast<std::uint8_t>(number);
}

//------------------------------------------------------------------------------
// Helper: base64 (RFC 4648 section 4) of a MIKEY I_MESSAGE.
std::string encode_base64(std::span<const std::uint8_t> bytes) {
  require(bytes.size() <= 65535, "oversized MIKEY");
  std::string text(4 * ((bytes.size() + 2) / 3) + 1, '\0');
  const auto length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(text.data()), bytes.data(), bytes.size());
  require(length >= 0, "base64 encoding failed");
  text.resize(length);
  return text;
}

//------------------------------------------------------------------------------
// Helper: strict, canonical base64 (RFC 4648 section 4) decoding of a MIKEY I_MESSAGE.
keying::Bytes decode_base64(std::string_view text) {
  require(!text.empty() && text.size() <= 87380 && text.size() % 4 == 0, "invalid MIKEY base64 length");
  const auto is_character = [](char character) {
    return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
           (character >= '0' && character <= '9') || character == '+' || character == '/';
  };
  const std::size_t padding = text.ends_with("==") ? 2 : text.ends_with("=") ? 1 : 0;
  for (std::size_t index = 0; index < text.size() - padding; ++index)
    require(is_character(text[index]), "invalid MIKEY base64 alphabet");
  keying::Bytes output(text.size() / 4 * 3);
  const auto count = EVP_DecodeBlock(output.data(), reinterpret_cast<const unsigned char *>(text.data()), text.size());
  require(count >= 0 && static_cast<std::size_t>(count) >= padding, "invalid MIKEY base64");
  output.resize(count - padding);
  require(output.size() <= 65535 && encode_base64(output) == text, "noncanonical MIKEY base64");
  return output;
}

//------------------------------------------------------------------------------
// Helper: wipes and empties a secret string.
void clear(std::string &value) {
  OPENSSL_cleanse(value.data(), value.size());
  value.clear();
}

//------------------------------------------------------------------------------
// Helper: wipes the private keys (SSK, PVT and RSK) of an identity.
void clear_identity(keying::IdentityKeys &id) {
  OPENSSL_cleanse(id.signing_pair.data(), id.signing_pair.size());
  OPENSSL_cleanse(id.receiver_secret.data(), id.receiver_secret.size());
  id = {};
}

//------------------------------------------------------------------------------
// Helper: an unambiguous replay cache key of an identity and a key identifier.
std::string cache_key(std::string_view identity, std::uint32_t id) {
  return std::to_string(identity.size()) + ":" + std::string(identity) + ":" + std::to_string(id);
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.3.3 and 5.2.2: the state of the key management client: its KMS, credentials, KMS certificate,
// identity keys and the caches of received keys.
struct KeyClient::Impl {
  const HttpClient &http;
  std::string kms_uri, user_uri, account_uri, bearer;
  // The key management client of an MC server or the GMS: its IdMS, OAuth client credentials and scope, and when its
  // access token expires (Unix seconds).
  std::string issuer, client_id, client_secret, client_scope;
  std::uint64_t bearer_expiry = 0;
  keying::KeyParameterWireProfile profile;
  keying::PublicParameters parameters;
  keying::IdentityKeys identity;
  bool provisioned = false;
  mutable std::mutex mutex;
  std::map<std::string, std::uint64_t> received_csks;
  std::map<std::string, keying::KeyMessage> received_groups;

  struct CurrentGroup {
    std::uint32_t id;
    std::uint64_t activation;
  };

  std::map<std::string, CurrentGroup> current_groups;
  // Retain ordering information after secret material expires. Removing it
  // would allow a still-authentic old epoch to reset media replay contexts.
  std::set<std::string> retired_group_ids;

  // Helper: checks the KMS URIs and identity and reads the key parameter wire profile.
  Impl(const HttpClient &client, const nlohmann::json &security, std::string user, std::string account)
      : http(client), kms_uri(security.at("kms_uri").get<std::string>()), user_uri(std::move(user)),
        account_uri(account.empty() ? user_uri : std::move(account)), profile{} {
    require(kms_uri.starts_with("https://") && kms_uri.size() > 8 &&
                kms_uri.find_first_of("\r\n\t?#") == std::string::npos && kms_uri.find('@') == std::string::npos,
            "KMS must be a direct HTTPS URI without credentials, query or fragment");
    while (kms_uri.ends_with('/')) kms_uri.pop_back();
    require(kms_uri.size() > 8 && !user_uri.empty() && user_uri.size() <= 65535 &&
                user_uri.find_first_of("\r\n") == std::string::npos && user_uri.find('\0') == std::string::npos,
            "invalid KMS or service identity");
    const auto &wire = security.at("key_parameter_profile");
    profile = {profile_byte(wire, "message_type"), profile_byte(wire, "algorithm"),
               profile_byte(wire, "key_parameters_iei"), profile_byte(wire, "encrypted_payload_iei")};
    require(profile.algorithm == 1, "only DP_AES_128_GCM is supported");
  }

  // Helper: wipes the credentials, identity keys and received group keys.
  ~Impl() {
    clear(bearer);
    clear(client_secret);
    clear_identity(identity);
    for (auto &[unused, key] : received_groups) OPENSSL_cleanse(key.key.data(), key.key.size());
  }

  // TS 33.180 annexes D.2.3 and D.2.4: the request URI of a KMS operation ("init" or "keyprov") at the configured KMS.
  std::string request_uri(std::string_view operation) const {
    // TS 33.180 annex D.2.4: the key provisioning request names the identity: the user's MCPTT ID or, for its MCData
    // client, its MCData ID; the public service identity of an MC server, or the GMS URI.
    if (operation == "keyprov") return kms_uri + "/keymanagement/identity/v1/keyprov/" + url_encode(user_uri);
    return kms_uri + "/keymanagement/identity/v1/" + std::string(operation);
  }

  // RFC 6749 section 4.4 (TS 33.180 clause 5.3.3 step 1): the access token of an MC server's or the GMS's key
  // management client, from the token endpoint of the IdMS's discovery document (OpenID Connect Discovery 1.0
  // section 3), authenticated with HTTP Basic (RFC 6749 section 2.3.1), when there is none or it expires within 30 s.
  void renew_token() {
    if (client_id.empty()) return;
    const auto unix_now = now_ntp() - ntp_epoch;
    if (!bearer.empty() && unix_now + 30 < bearer_expiry) return;
    const auto discovery = http.request("GET", issuer + "/.well-known/openid-configuration");
    require(discovery.status == 200, "IdMS discovery unavailable");
    const auto document = nlohmann::json::parse(discovery.body);
    const auto endpoint = document.at("token_endpoint").get<std::string>();
    require(document.at("issuer") == issuer && endpoint.starts_with("https://"), "invalid IdMS discovery document");
    const auto response =
        http.request("POST", endpoint, "grant_type=client_credentials&scope=" + url_encode(client_scope),
                     {{"Content-Type", "application/x-www-form-urlencoded"}, {"Accept", "application/json"}},
                     url_encode(client_id), url_encode(client_secret));
    require(response.status == 200, "client credentials grant refused");
    const auto answer = nlohmann::json::parse(response.body);
    const auto token = answer.at("access_token").get<std::string>();
    const auto lifetime = answer.at("expires_in").get<std::int64_t>();
    require(!token.empty() && token.find_first_of("\r\n") == std::string::npos && lifetime > 0,
            "invalid client credentials token");
    clear(bearer);
    bearer = token;
    bearer_expiry = unix_now + static_cast<std::uint64_t>(lifetime);
  }

  // TS 33.180 clause 5.3.3 steps 1 and 2: a POST request for key material, authenticated with the access token;
  // returns the KMS response XML.
  std::string fetch(std::string_view operation) const {
    const std::map<std::string, std::string> headers{
        {"Accept", "application/xml"}, {"Cache-Control", "no-store"}, {"Authorization", "Bearer " + bearer}};
    const auto response = http.request("POST", request_uri(operation), {}, headers);
    require(response.status == 200, "KMS provisioning HTTP request rejected");
    require(!response.body.empty() && response.body.size() <= 262144, "invalid KMS response size");
    return response.body;
  }

  // TS 33.180 clause 5.3.3 (annexes D.2.3 and D.2.4): KMSInit and KMSKeyProv. The identity is replaced only once
  // every response and the key validation succeed.
  void refresh() {
    renew_token();
    require(!bearer.empty(), "KMS credentials have not been provisioned");
    // Keep existing identity until both authenticated responses and key validation succeed.
    const auto init = fetch("init");
    // The init request names no identity: the KMS answers for the token's user.
    const auto public_parameters = keying::parse_kms_init(init, account_uri, kms_uri, request_uri("init"), now_ntp());
    const auto keyprov = fetch("keyprov");
    auto next_identity =
        keying::parse_kms_keyprov(keyprov, public_parameters, user_uri, request_uri("keyprov"), now_ntp());
    try {
      keying::validate_identity(public_parameters, next_identity, now_ntp());
    } catch (...) {
      clear_identity(next_identity);
      throw;
    }
    clear_identity(identity);
    parameters = public_parameters;
    identity = std::move(next_identity);
    provisioned = true;
  }

  // TS 33.180 clause 5.2.7.3: the public parameters of a KMS URI: the Home KMS; null otherwise.
  keying::KmsLookup lookup() const {
    return [this](std::string_view uri) -> const keying::PublicParameters * {
      return uri == parameters.period.kms_uri ? &parameters : nullptr;
    };
  }

  // TS 33.180 annex F.2.1.1: re-provisions the identity keys when the key period has changed.
  void ensure_provisioned(std::uint64_t now) {
    require(provisioned, "KMS identity has not been provisioned");
    const auto &period = parameters.period;
    require(period.seconds != 0 && period.offset < period.seconds && now >= period.offset, "invalid KMS key period");
    if (identity.period_number != (now - period.offset) / period.seconds) refresh();
  }

  // Helper: the Unix time at which the key period of the identity keys ends.
  std::uint64_t identity_expiry_unix() const {
    const auto &period = parameters.period;
    return (identity.period_number + 1) * period.seconds + period.offset - ntp_epoch;
  }

  // TS 33.180 annex E.6.10: forgets the replay entries and group keys past their expiry time, wiping the keys.
  void remove_expired(std::uint64_t now_unix) {
    std::erase_if(received_csks, [&](const auto &entry) { return entry.second <= now_unix; });
    for (auto cached = received_groups.begin(); cached != received_groups.end();) {
      // A cached GMK always has its properties (open_group requires them); one without is dropped, not read.
      const auto &properties = cached->second.properties;
      if (!properties || (properties->expiry_unix_seconds && properties->expiry_unix_seconds <= now_unix)) {
        OPENSSL_cleanse(cached->second.key.data(), cached->second.key.size());
        cached = received_groups.erase(cached);
      } else
        ++cached;
    }
  }
};

//------------------------------------------------------------------------------
// Helper: a key management client for the configured KMS and the user (and account) URI.
KeyClient::KeyClient(const HttpClient &http, const nlohmann::json &security, std::string user_uri,
                     std::string account_uri)
    : impl_(std::make_unique<Impl>(http, security, std::move(user_uri), std::move(account_uri))) {}

//------------------------------------------------------------------------------
// Helper: wipes the secrets.
KeyClient::~KeyClient() = default;

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.3: provisions the identity keys with the user's access token.
void KeyClient::provision(const std::string &token) {
  std::lock_guard lock(impl_->mutex);
  require(!token.empty() && token.find_first_of("\r\n") == std::string::npos, "invalid bearer token");
  require(impl_->client_id.empty(), "the key management client of a server has its own access token");
  clear(impl_->bearer);
  impl_->bearer = token;
  impl_->refresh();
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.3.2 and 5.3.3: provisions the identity keys of an MC server or the GMS with the access token
// of its own OAuth client (Impl::renew_token).
void KeyClient::provision_client(const std::string &issuer, const std::string &client_id, const std::string &secret,
                                 const std::string &scope) {
  std::lock_guard lock(impl_->mutex);
  require(issuer.starts_with("https://") && !client_id.empty() && !secret.empty() && !scope.empty() &&
              (issuer + client_id + secret + scope).find_first_of("\r\n") == std::string::npos,
          "invalid key management client credentials");
  clear(impl_->bearer);
  clear(impl_->client_secret);
  impl_->issuer = issuer;
  while (impl_->issuer.ends_with('/')) impl_->issuer.pop_back();
  impl_->client_id = client_id;
  impl_->client_secret = secret;
  impl_->client_scope = scope;
  impl_->bearer_expiry = 0;
  impl_->refresh();
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.3: an MC server's key management client, from its configuration.
void provision_server_keys(KeyClient &keys, const nlohmann::json &cfg) {
  const auto &common = cfg.at("common");
  const auto &client = cfg.at("security").at("key_client");
  keys.provision_client(common.value("issuer", common.value("idms", std::string{})), client.at("client_id"),
                        client.at("secret"), client.at("scope"));
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.7.3: whether a certificate is held for the KMS URI.
bool KeyClient::knows_kms(std::string_view kms_uri) const {
  std::lock_guard lock(impl_->mutex);
  return impl_->provisioned && impl_->lookup()(kms_uri) != nullptr;
}

//------------------------------------------------------------------------------
// The URI of the KMS that keys an identity: this user's KMS.
std::string KeyClient::kms_uri_of(std::string_view /*identity*/) const {
  std::lock_guard lock(impl_->mutex);
  require(impl_->provisioned, "KMS identity has not been provisioned");
  return impl_->parameters.period.kms_uri;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.4 and annex E.4: creates a CSK (purpose tag 2) with its key parameters (valid to the end of the
// identity key period) and the MIKEY-SAKKE I_MESSAGE to the recipient, base64 encoded.
std::pair<keying::KeyMessage, std::string> KeyClient::make_csk(std::string_view recipient) {
  std::lock_guard lock(impl_->mutex);
  auto now = now_ntp();
  impl_->ensure_provisioned(now);
  now = now_ntp();
  keying::KeyMessage key;
  key.ntp_seconds = now;
  std::array<unsigned char, 4> id{};
  require(RAND_priv_bytes(key.key.data(), key.key.size()) == 1 &&
              RAND_bytes(key.random.data(), key.random.size()) == 1 && RAND_bytes(id.data(), id.size()) == 1,
          "CSK random generation failed");
  key.csb_id =
      0x20000000U |
      ((std::uint32_t(id[0]) << 24 | std::uint32_t(id[1]) << 16 | std::uint32_t(id[2]) << 8 | id[3]) & 0x0fffffffU);
  key.properties = keying::KeyProperties{2, 1, now - ntp_epoch, impl_->identity_expiry_unix(), {}, {}};
  keying::require_active(key, {}, now - ntp_epoch);
  const auto message = keying::create_mikey(impl_->parameters, impl_->identity, recipient, key, &impl_->profile);
  return {key, encode_base64(message)};
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.4 and annex E.4: opens a CSK upload I_MESSAGE: the key must be an active CSK that expires within
// the identity key period, and each CSK is accepted once.
keying::KeyMessage KeyClient::accept_csk(std::string_view sender, std::string_view encoded) {
  const auto message = decode_base64(encoded);
  std::lock_guard lock(impl_->mutex);
  auto now = now_ntp();
  impl_->ensure_provisioned(now);
  now = now_ntp();
  auto key = keying::open_mikey(impl_->parameters, impl_->identity, sender, message, now, 300, &impl_->profile);
  require((key.csb_id >> 28) == 2 && key.properties && key.properties->type == 2, "received key is not a CSK");
  keying::require_active(key, {}, now - ntp_epoch);
  require(key.properties->expiry_unix_seconds != 0 &&
              key.properties->expiry_unix_seconds <= impl_->identity_expiry_unix(),
          "CSK lifetime exceeds identity key period");
  impl_->remove_expired(now - ntp_epoch);
  const auto identity = cache_key(sender, key.csb_id);
  require(!impl_->received_csks.contains(identity), "duplicate or replayed CSK");
  require(impl_->received_csks.size() < maximum_cache_entries, "CSK replay cache capacity reached");
  impl_->received_csks.emplace(identity, key.properties->expiry_unix_seconds);
  return key;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 7.2.2 and annex E.3, TS 24.379 clause 11.1.1.2.1.1 step 11: creates a PCK and the MIKEY-SAKKE
// I_MESSAGE to the recipient, encapsulated under the recipient's KMS.
std::pair<keying::KeyMessage, std::string> KeyClient::make_pck(std::string_view recipient,
                                                               std::string_view recipient_kms) {
  std::lock_guard lock(impl_->mutex);
  auto now = now_ntp();
  impl_->ensure_provisioned(now);
  now = now_ntp();
  keying::KeyMessage key;
  key.ntp_seconds = now;
  std::array<unsigned char, 4> id{};
  require(RAND_priv_bytes(key.key.data(), key.key.size()) == 1 &&
              RAND_bytes(key.random.data(), key.random.size()) == 1 && RAND_bytes(id.data(), id.size()) == 1,
          "PCK random generation failed");
  // TS 24.379 clause 11.1.1.2.1.1 step 11c: the four most significant bits are "0001".
  key.csb_id =
      0x10000000U |
      ((std::uint32_t(id[0]) << 24 | std::uint32_t(id[1]) << 16 | std::uint32_t(id[2]) << 8 | id[3]) & 0x0fffffffU);
  // TS 24.379 clause 6.2.8.3.9: a KMS URI given for the recipient (<PrivateCallKMSURI>)
  // must be one this client holds a certificate for.
  const auto *kms = recipient_kms.empty() ? &impl_->parameters : impl_->lookup()(recipient_kms);
  require(kms != nullptr, "no certificate for the recipient's KMS");
  const auto message = keying::create_mikey(impl_->parameters, *kms, impl_->identity, recipient, key);
  return {key, encode_base64(message)};
}

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5: signs a payload as an Authenticated Payload of the identity.
keying::Bytes KeyClient::authenticate(std::uint8_t type, std::span<const std::uint8_t> original) {
  std::lock_guard lock(impl_->mutex);
  auto now = now_ntp();
  impl_->ensure_provisioned(now);
  now = now_ntp();
  return keying::authenticate_payload(impl_->parameters, impl_->identity, now, type, original);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5: verifies an Authenticated Payload from the sender.
keying::AuthenticatedPayload KeyClient::open_authenticated(std::string_view sender,
                                                           std::span<const std::uint8_t> message) {
  std::lock_guard lock(impl_->mutex);
  auto now = now_ntp();
  impl_->ensure_provisioned(now);
  now = now_ntp();
  return keying::open_authenticated(impl_->lookup(), sender, message, now);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2: the CSB-ID (K-ID) of a base64 I_MESSAGE, not authenticated.
std::uint32_t KeyClient::key_id(std::string_view encoded) { return keying::mikey_csb_id(decode_base64(encoded)); }

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the initiator (IDRi) of a base64 I_MESSAGE, not authenticated.
std::string KeyClient::initiator(std::string_view encoded) { return keying::mikey_initiator(decode_base64(encoded)); }

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the initiator KMS URI (IDRkmsi) of a base64 I_MESSAGE, not authenticated.
std::string KeyClient::initiator_kms(std::string_view encoded) {
  return keying::mikey_initiator_kms(decode_base64(encoded));
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the receiver (IDRr) and receiver KMS URI (IDRkmsr) of a base64 I_MESSAGE, not
// authenticated.
std::pair<std::string, std::string> KeyClient::receiver(std::string_view encoded) {
  return keying::mikey_receiver(decode_base64(encoded));
}

//------------------------------------------------------------------------------
// TS 33.180 clause 7.2.2 and annex E.3: opens a PCK I_MESSAGE from the expected (or any) initiator, keyed by any KMS
// whose certificate is held; each PCK is accepted once within the timestamp window.
std::pair<keying::KeyMessage, std::string> KeyClient::accept_pck(std::string_view expected, std::string_view encoded) {
  const auto message = decode_base64(encoded);
  const auto sender = keying::mikey_initiator(message);
  require(expected.empty() || sender == expected, "unexpected MIKEY sender");
  std::lock_guard lock(impl_->mutex);
  auto now = now_ntp();
  impl_->ensure_provisioned(now);
  now = now_ntp();
  constexpr std::uint32_t skew = 300;
  auto key = keying::open_mikey(impl_->parameters, impl_->lookup(), impl_->identity, sender, message, now, skew);
  require((key.csb_id >> 28) == 1 && !key.properties, "received key is not a PCK");
  // A replayed I_MESSAGE stays fresh for the timestamp window; remember it that long.
  impl_->remove_expired(now - ntp_epoch);
  const auto identity = cache_key("pck:" + sender, key.csb_id);
  require(!impl_->received_csks.contains(identity), "duplicate or replayed PCK");
  require(impl_->received_csks.size() < maximum_cache_entries, "PCK replay cache capacity reached");
  impl_->received_csks.emplace(identity, key.ntp_seconds - ntp_epoch + 2 * skew);
  return {key, sender};
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.7.2 and 7.4.2 and annex E.2, TS 24.481 clause 7.7: opens the GMK of a group's GKTP document
// from the GMS, checks its key parameters and that it advances the group's key epoch, and returns it with the GMK-ID:
// the CSB-ID of the I_MESSAGE is the user's GUK-ID, the GMK-ID masked with the user's GUK-ID salt (TS 33.180 clause
// 5.2.3, annex F.1.3), and that salt is removed again.
keying::KeyMessage KeyClient::open_group(std::string_view gms, std::string_view group, std::string_view xml) {
  require(!group.empty(), "missing group identity");
  std::lock_guard lock(impl_->mutex);
  auto now = now_ntp();
  impl_->ensure_provisioned(now);
  now = now_ntp();

  const auto message = keying::parse_gktp_document(xml, group);
  auto key =
      keying::open_mikey(impl_->parameters, impl_->lookup(), impl_->identity, gms, message, now, 300, &impl_->profile);
  require((key.csb_id >> 28) == 0 && key.properties && key.properties->type == 0, "received key is not a GMK");
  // A GMK not yet active is kept: ProtectedCall uses it from its Activation Time (TS 33.180 annex E.6.4).
  keying::require_unexpired(key, group, now - ntp_epoch);
  key.csb_id ^= derive_guk_id(key.key, 0, impl_->user_uri);

  impl_->remove_expired(now - ntp_epoch);
  const auto id = cache_key(group, key.csb_id);
  const auto found = impl_->received_groups.find(id);
  const auto current = impl_->current_groups.find(std::string(group));
  require(!impl_->retired_group_ids.contains(id), "retired GMK epoch replayed");
  if (found != impl_->received_groups.end()) {
    require(current != impl_->current_groups.end() && current->second.id == key.csb_id,
            "cached GMK is no longer current");
    const auto &previous = found->second;
    require(CRYPTO_memcmp(previous.key.data(), key.key.data(), key.key.size()) == 0 && previous.random == key.random &&
                previous.properties == key.properties,
            "GMK-ID collision or changed key parameters");
    // A repeated authenticated SIP notification is idempotent; it cannot reset
    // lifetime or install changed material under an existing key identifier.
    return previous;
  }

  const auto activation =
      key.properties->activation_unix_seconds ? key.properties->activation_unix_seconds : key.ntp_seconds - ntp_epoch;
  if (current != impl_->current_groups.end()) {
    require(current->second.id != key.csb_id, "expired GMK-ID reused");
    require(activation > current->second.activation, "GMK activation does not advance current epoch");
    require(impl_->retired_group_ids.size() < maximum_cache_entries, "retired GMK cache capacity reached");
  } else {
    require(impl_->current_groups.size() < maximum_cache_entries, "group epoch cache capacity reached");
  }

  require(impl_->received_groups.size() < maximum_cache_entries, "GMK cache capacity reached");
  impl_->received_groups.emplace(id, key);
  if (current != impl_->current_groups.end()) {
    impl_->retired_group_ids.emplace(cache_key(group, current->second.id));
    auto previous = impl_->received_groups.find(cache_key(group, current->second.id));
    if (previous != impl_->received_groups.end()) {
      OPENSSL_cleanse(previous->second.key.data(), previous->second.key.size());
      impl_->received_groups.erase(previous);
    }
    current->second = {key.csb_id, activation};
  } else
    impl_->current_groups.emplace(std::string(group), Impl::CurrentGroup{key.csb_id, activation});
  return key;
}
} // namespace mcx
