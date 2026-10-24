//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Key management client: provisioning from the Home KMS over HTTPS, and the CSK, PCK and GMK MIKEY-SAKKE exchanges.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19).
#pragma once
#include "mcx/http.hpp"
#include "mcx/keying.hpp"

#include <memory>
#include <utility>

namespace mcx {
//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.3 and annex D: the key management client, with verified direct-HTTPS provisioning. All
// failures throw; no clear fallback. HttpClient must outlive this object. Public operations are serialized
// internally.
class KeyClient {
public:
  // account_uri is the identity the access token was issued to (the MCPTT ID) when user_uri is another of the user's
  // MC service IDs, such as the MCData ID.
  KeyClient(const HttpClient &http, const nlohmann::json &security, std::string user_uri, std::string account_uri = {});
  ~KeyClient();
  KeyClient(const KeyClient &) = delete;
  KeyClient &operator=(const KeyClient &) = delete;
  // TS 33.180 clause 5.3.3: provisions the identity keys with the user's access token.
  void provision(const std::string &token);
  // TS 33.180 clauses 5.3.2 and 5.3.3: provisions the identity keys of an MC server or the GMS, as a confidential
  // OAuth client of the IdMS (issuer) with its own access token from the client credentials grant (RFC 6749 section
  // 4.4), renewed before it expires; scope is its key management scope.
  void provision_client(const std::string &issuer, const std::string &client_id, const std::string &secret,
                        const std::string &scope);
  // The KMS URI whose key material serves an identity: this user's KMS.
  std::string kms_uri_of(std::string_view identity) const;
  // TS 33.180 clause 5.2.7.3: whether this client holds the certificate of a KMS (its own).
  bool knows_kms(std::string_view kms_uri) const;
  // TS 33.180 clause 5.4 and annex E.4: creates a CSK and the MIKEY-SAKKE I_MESSAGE to the recipient, base64 encoded.
  std::pair<keying::KeyMessage, std::string> make_csk(std::string_view recipient);
  // TS 33.180 clause 5.4 and annex E.4: opens a CSK upload I_MESSAGE from the sender.
  keying::KeyMessage accept_csk(std::string_view sender, std::string_view encoded);
  // TS 33.180 clause 5.6 and annex E.3: a PCK with a PCK-ID whose purpose tag is 1, encapsulated to the recipient's
  // UID and signed by this user, without key parameters.
  std::pair<keying::KeyMessage, std::string> make_pck(std::string_view recipient, std::string_view recipient_kms = {});
  // TS 33.180 clause 7.2.2 and annex E.3: authenticates an I_MESSAGE carrying a PCK from its initiator (IDRi). When
  // expected is empty the initiator is taken from the message and returned.
  std::pair<keying::KeyMessage, std::string> accept_pck(std::string_view expected, std::string_view encoded);
  // TS 33.180 clause 8.5.5: signs a payload as this user.
  keying::Bytes authenticate(std::uint8_t type, std::span<const std::uint8_t> original);
  // TS 33.180 clause 8.5.5: verifies a payload signed by sender.
  keying::AuthenticatedPayload open_authenticated(std::string_view sender, std::span<const std::uint8_t> message);
  // TS 33.180 clause 5.2.2: the CSB-ID (PCK-ID) of a base64 I_MESSAGE, not authenticated.
  static std::uint32_t key_id(std::string_view encoded);
  // TS 33.180 annex E.1.2: the initiator (IDRi) of a base64 I_MESSAGE, not authenticated.
  static std::string initiator(std::string_view encoded);
  // TS 33.180 annex E.1.2: the initiator KMS (IDRkmsi), and the receiver (IDRr) and receiver KMS (IDRkmsr), of a
  // base64 I_MESSAGE, not authenticated.
  static std::string initiator_kms(std::string_view encoded);
  static std::pair<std::string, std::string> receiver(std::string_view encoded);
  // TS 33.180 clauses 5.7.2 and 7.4.2 and annex E.2, TS 24.481 clause 7.7: verifies group binding and the lifetime of
  // the key parameters (TS 33.180 annex E.6), then converts the received recipient GUK-ID to the GMK-ID. Thus the
  // returned csb_id is the GMK-ID, not the wire GUK-ID.
  keying::KeyMessage open_group(std::string_view gms, std::string_view group, std::string_view xml);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.3: provisions an MC server's identity keys with its key management client (the configuration's
// security.key_client: client_id, secret, scope) at the IdMS of its common section (issuer, else idms).
void provision_server_keys(KeyClient &keys, const nlohmann::json &cfg);
} // namespace mcx
