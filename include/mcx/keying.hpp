//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MIKEY-SAKKE keying: the MC key periods and UIDs, KMS authority and user key issue, ECCSI signatures, SAKKE key
// encapsulation, MIKEY-SAKKE I_MESSAGEs with the key parameters extension, and the MCData protected and authenticated
// payloads.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), RFC 3830,
// RFC 6043, RFC 6509, RFC 6507, RFC 6508.
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcx::keying {
using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// TS 33.180 annex F.2.1.1: the key period of a KMS (its length and offset, in seconds) that enters the UID.
struct Period {
  std::string kms_uri;
  std::uint32_t seconds = 2592000;
  std::uint32_t offset = 0;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.5: the public parameters of a KMS certificate: the key period, the KPAK (RFC 6507) and Z_T
// (RFC 6508).
struct PublicParameters {
  Period period;
  Bytes authentication_key;
  Bytes encryption_key;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.1.1: a KMS: its public parameters and master secrets (RFC 6507, RFC 6508).
struct Authority {
  PublicParameters public_parameters;
  Bytes authentication_secret;
  Bytes encryption_secret;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.6: the KMS provisioned key set of a user for one key period: SSK and PVT (RFC 6507) and RSK
// (RFC 6508).
struct IdentityKeys {
  std::string uri;
  std::uint64_t period_number = 0;
  Bytes signing_pair; // wolfCrypt serialization of SSK and PVT; never send to peers.
  Bytes receiver_secret;
};

//------------------------------------------------------------------------------
// TS 33.180 annex E.6: the key parameters of a key, carried in the MIKEY general extension payload.
struct KeyProperties {
  std::uint8_t type = 0;    // TS 33.180 table E.6.11-1: GMK=0, PCK=1, CSK=2, SPK=3.
  std::uint32_t status = 1; // TS 33.180 table E.6.9-1: bit zero: not revoked; bit one: security gateway.
  std::uint64_t activation_unix_seconds = 0;
  std::uint64_t expiry_unix_seconds = 0;
  std::string text;
  std::vector<std::string> groups;
  bool operator==(const KeyProperties &) const = default;
};

//------------------------------------------------------------------------------
// TS 33.180 annex E.6 leaves the Key Parameters IEI numeric assignment unspecified. An explicitly agreed
// interoperability profile supplies these outer wire values. It cannot be advertised as an independently qualified
// standard profile.
struct KeyParameterWireProfile {
  std::uint8_t message_type;
  std::uint8_t algorithm;
  std::uint8_t key_parameters_iei;
  std::uint8_t encrypted_payload_iei;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2 and annex E.1.2: the key a MIKEY-SAKKE I_MESSAGE carries: the key (TGK), RAND, CSB-ID, the
// timestamp and the key parameters.
struct KeyMessage {
  std::array<std::uint8_t, 16> key{};
  std::array<std::uint8_t, 16> random{};
  std::uint32_t csb_id = 0;
  std::uint64_t ntp_seconds = 0;
  std::optional<KeyProperties> properties;
};

//------------------------------------------------------------------------------
// TS 33.180 annex F.2.1.1: the MIKEY-SAKKE UID of an identity for the key period of the given time. Time is seconds
// since 1900-01-01 (NTP), without the fractional word.
std::string uid(std::string_view identity, const Period &period, std::uint64_t time);

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.3.1.1 and 5.3.5: creates the KMS master secrets and the public keys of its certificate.
Authority create_authority(const Period &period);

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.6: the KMS provisioned key set of a user for the key period of the given time.
IdentityKeys issue(const Authority &authority, std::string_view uri, std::uint64_t time);

//------------------------------------------------------------------------------
// RFC 6507 and RFC 6508: validates provisioned identity keys for the UID of the key period of the given time.
void validate_identity(const PublicParameters &parameters, const IdentityKeys &id, std::uint64_t time);

//------------------------------------------------------------------------------
// RFC 6507: an ECCSI signature of a message by the identity for its key period.
Bytes sign(const PublicParameters &parameters, const IdentityKeys &id, std::uint64_t time,
           std::span<const std::uint8_t> message);

//------------------------------------------------------------------------------
// RFC 6507: verifies an ECCSI signature of a message by the UID of a URI for the key period of the given time.
bool verify(const PublicParameters &parameters, std::string_view uri, std::uint64_t time,
            std::span<const std::uint8_t> message, std::span<const std::uint8_t> signature);

//------------------------------------------------------------------------------
// RFC 6508: SAKKE encapsulation of a 128-bit key (the SSV) to the UID of the recipient.
Bytes encapsulate(const PublicParameters &parameters, std::string_view recipient, std::uint64_t time,
                  std::span<const std::uint8_t, 16> key);

//------------------------------------------------------------------------------
// RFC 6508: recovers the 128-bit key of SAKKE Encapsulated Data with the RSK of the identity for its key period.
std::array<std::uint8_t, 16> decapsulate(const PublicParameters &parameters, const IdentityKeys &id, std::uint64_t time,
                                         std::span<const std::uint8_t> data);

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2 and annex E.1.2: a MIKEY-SAKKE I_MESSAGE from an initiator and to a receiver keyed by the same
// KMS, with the common fields and the default crypto-session map. Key properties and SIP GKTP transport must be
// supplied by the caller before claiming complete group provisioning.
Bytes create_mikey(const PublicParameters &parameters, const IdentityKeys &sender, std::string_view recipient,
                   const KeyMessage &key, const KeyParameterWireProfile *profile = nullptr);

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2: opens a MIKEY-SAKKE I_MESSAGE signed under the receiver's own KMS.
KeyMessage open_mikey(const PublicParameters &parameters, const IdentityKeys &recipient, std::string_view sender,
                      std::span<const std::uint8_t> message, std::uint64_t now, std::uint32_t skew = 300,
                      const KeyParameterWireProfile *profile = nullptr);

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.2.7.3 and 11.1.2.2: the initiator and the responder keyed by different KMSs. The SAKKE
// encapsulation uses the responder's KMS (IDRkmsr) and the ECCSI signature the initiator's (IDRkmsi). A receiver
// resolves the initiator's KMS URI to that KMS's public parameters (its own, or another KMS certificate it holds);
// an unknown KMS is refused.
using KmsLookup = std::function<const PublicParameters *(std::string_view kms_uri)>;

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.2.2 and 5.2.7.3 and annex E.1.2, RFC 6509: a MIKEY-SAKKE I_MESSAGE signed under the initiator's
// KMS (parameters) and encapsulated under the receiver's KMS (rp).
Bytes create_mikey(const PublicParameters &parameters, const PublicParameters &rp, const IdentityKeys &sender,
                   std::string_view recipient, const KeyMessage &key, const KeyParameterWireProfile *profile = nullptr);

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.2.2 and 5.2.7.3 and annex E.1.2: opens a MIKEY-SAKKE I_MESSAGE, the signing KMS (IDRkmsi)
// resolved through the lookup.
KeyMessage open_mikey(const PublicParameters &parameters, const KmsLookup &lookup, const IdentityKeys &recipient,
                      std::string_view sender, std::span<const std::uint8_t> message, std::uint64_t now,
                      std::uint32_t skew = 300, const KeyParameterWireProfile *profile = nullptr);

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the initiator's KMS URI (IDRkmsi) of an I_MESSAGE, read without authenticating it.
std::string mikey_initiator_kms(std::span<const std::uint8_t> message);

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the receiver (IDRr) and receiver KMS URI (IDRkmsr) of an I_MESSAGE, not authenticated.
std::pair<std::string, std::string> mikey_receiver(std::span<const std::uint8_t> message);

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.4: the MCData Protected Payload message, AES-128-GCM under a DPCK derived from the DPPK (the
// PCK, GMK or CSK) by annex F.1.5. TS 33.180 V19.4.0 assigns no numeric algorithm ID or Payload IEI, so the wire
// profile supplies them.
struct ProtectedPayload {
  std::uint8_t message_type = 0; // TS 24.282 table 15.2.2-1 with bit 7 (0x40) set
  std::uint64_t unix_seconds = 0;
  std::uint32_t payload_id = 0;
  std::uint8_t sequence = 0;
  std::uint32_t dppk_id = 0;
  Bytes plain;
};

//------------------------------------------------------------------------------
// TS 33.180 clauses 8.5.4.1 (table 8.5.4.1-1) and 8.5.4.2 (table 8.5.4.2-1): seals a Protected Payload message.
Bytes seal_payload(const ProtectedPayload &message, std::span<const std::uint8_t, 16> dppk,
                   const KeyParameterWireProfile &profile);

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.4.1: the DPPK-ID, readable before decryption so that the receiver can select the key.
std::uint32_t payload_key_id(std::span<const std::uint8_t> data);

//------------------------------------------------------------------------------
// TS 33.180 clauses 8.5.4.1 and 8.5.4.2: decrypts and authenticates a Protected Payload message.
ProtectedPayload open_payload(std::span<const std::uint8_t> data, std::span<const std::uint8_t, 16> dppk,
                              const KeyParameterWireProfile &profile);

//------------------------------------------------------------------------------
// TS 33.180 table 8.5.4.1-1 NOTE 2: data longer than one Protected Payload message holds (65535 octets) as a series of
// messages with one random Payload ID and consecutive Payload sequence numbers; at most 256 messages.
Bytes seal_series(std::span<const std::uint8_t> plain, std::uint8_t type, std::span<const std::uint8_t, 16> dppk,
                  std::uint32_t dppk_id, const KeyParameterWireProfile &profile, std::size_t chunk = 60000);

//------------------------------------------------------------------------------
// TS 33.180 table 8.5.4.1-1 NOTE 2: opens a series sealed under one DPPK: every message must carry that DPPK-ID, the
// message type, one Payload ID and the next sequence number.
Bytes open_series(std::span<const std::uint8_t> data, std::uint8_t type, std::span<const std::uint8_t, 16> dppk,
                  const KeyParameterWireProfile &profile);

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5 (tables 8.5.5-1 and 8.5.5-2): an Authenticated Payload - the original payload, the algorithm,
// the Signing Data (the signer's UID and KMS URI) and an ECCSI signature over everything before the signature value.
// TS 33.180 V19.4.0 assigns none of the IEIs and no algorithm number, so these are local values; the message type
// octet in front, with bit 8 set (clause 8.5.1), is also local, since table 8.5.5-1 has none.
struct AuthenticatedPayload {
  std::uint8_t message_type = 0;
  Bytes original;
  std::string signer_uid, signer_kms;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5: the local algorithm number and IEIs of the Authenticated Payload (TS 33.180 assigns none).
inline constexpr std::uint8_t eccsi_algorithm = 1, original_payload_iei = 0x71, signing_data_iei = 0x72,
                              signing_uid_iei = 0x73, signing_kms_iei = 0x74, signature_iei = 0x75;

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5: an Authenticated Payload of the original payload, signed by the signer.
Bytes authenticate_payload(const PublicParameters &parameters, const IdentityKeys &signer, std::uint64_t now,
                           std::uint8_t type, std::span<const std::uint8_t> original);

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5: verifies that sender signed it, under the receiver's own KMS: the Signing UID must be the
// sender's UID for the current or the previous key period, and the signature must verify with it.
AuthenticatedPayload open_authenticated(const PublicParameters &own, std::string_view sender,
                                        std::span<const std::uint8_t> message, std::uint64_t now);

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.5: the same, for a signer keyed by another KMS: the Signing KMS URI selects its parameters.
AuthenticatedPayload open_authenticated(const KmsLookup &lookup, std::string_view sender,
                                        std::span<const std::uint8_t> message, std::uint64_t now);

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the initiator (IDRi) of an I_MESSAGE, read without authenticating it. A receiver that learns
// its peer only from the message (TS 24.379 clause 11.1.1.2.1.1 step 2 a) to c), on the SIP 200 (OK) response)
// converts it to a UID and must then authenticate the message with open_mikey.
std::string mikey_initiator(std::span<const std::uint8_t> message);

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2: the CSB-ID of an I_MESSAGE (the key identifier), read without authenticating it.
std::uint32_t mikey_csb_id(std::span<const std::uint8_t> message);

//------------------------------------------------------------------------------
// TS 33.180 annex E.6: a key may be used only if its Status (annex E.6.9) is not revoked, between its Activation Time
// (annex E.6.4) and its Expiry Time (annex E.6.10), and, for a GMK, for one of its MC Group IDs (annex E.6.3).
void require_active(const KeyMessage &key, std::string_view group, std::uint64_t now);

//------------------------------------------------------------------------------
// As require_active, but a key whose Activation Time is still to come passes: it is kept for that time (annex E.6.4,
// a GMK sent ahead of a key change, TS 24.481 clause 7.7.8).
void require_unexpired(const KeyMessage &key, std::string_view group, std::uint64_t now);
} // namespace mcx::keying
