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
#include <stdexcept>
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
  std::uint8_t algorithm; // DP_AES_128_GCM (TS 33.180 table 8.5.4.2-1)
  std::uint8_t key_parameters_iei;
  std::uint8_t encrypted_payload_iei;
  // DP_AES_256_GCM (TS 33.180 table 8.5.4.2-2), which TS 33.180 assigns no code either: only an agreed profile that
  // names its value sends or accepts it; without one, DP_AES_256_GCM is neither sent nor accepted.
  std::optional<std::uint8_t> algorithm_256{};
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2 and annex E.1.2: the key a MIKEY-SAKKE I_MESSAGE carries: the key (TGK), RAND, CSB-ID, the
// timestamp and the key parameters. RAND is variable (RFC 3830 section 6.11, "RAND len ... SHOULD be at least 16");
// OpenMCX writes 16 octets. The timestamp is kept as full NTP seconds (all eras); the wire carries the low 32 bits.
struct KeyMessage {
  std::array<std::uint8_t, 16> key{};
  Bytes random = Bytes(16);
  std::uint32_t csb_id = 0;
  std::uint64_t ntp_seconds = 0;
  std::optional<KeyProperties> properties;
};

//------------------------------------------------------------------------------
// RFC 5905 section 6: the full NTP seconds of the 32-bit seconds field of an NTP-UTC timestamp (RFC 3830 section 6.6,
// TS 33.180 annex E.1.2), which holds the era offset only. The era comes from "external means", the local clock
// (now, full NTP seconds): the era that puts the timestamp nearest to now (adjacent eras within 68 years).
std::uint64_t ntp_from_wire(std::uint32_t seconds, std::uint64_t now);

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
// RFC 3830 section 5.4: the allowable clock skew of a received I_MESSAGE's timestamp, "which is set by the local
// policy"; it also bounds how long the replay cache remembers a message. Configurable (security.mikey_clock_skew_s);
// 300 s is the default pending maintainer choice (no spec value).
constexpr std::uint32_t default_mikey_clock_skew_s = 300;

//------------------------------------------------------------------------------
// TS 33.180 clause 5.2.2: opens a MIKEY-SAKKE I_MESSAGE signed under the receiver's own KMS.
KeyMessage open_mikey(const PublicParameters &parameters, const IdentityKeys &recipient, std::string_view sender,
                      std::span<const std::uint8_t> message, std::uint64_t now,
                      std::uint32_t skew = default_mikey_clock_skew_s,
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
                      std::uint32_t skew = default_mikey_clock_skew_s,
                      const KeyParameterWireProfile *profile = nullptr);

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the initiator's KMS URI (IDRkmsi) of an I_MESSAGE, read without authenticating it.
std::string mikey_initiator_kms(std::span<const std::uint8_t> message);

//------------------------------------------------------------------------------
// TS 33.180 annex E.1.2: the receiver (IDRr) and receiver KMS URI (IDRkmsr) of an I_MESSAGE, not authenticated.
std::pair<std::string, std::string> mikey_receiver(std::span<const std::uint8_t> message);

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.4: the MCData Protected Payload message, AES-GCM under a DPCK derived from the DPPK (the
// PCK, GMK or CSK) by annex F.1.5. TS 33.180 V19.4.0 assigns no numeric algorithm ID or Payload IEI, so the wire
// profile supplies them.
//
// TS 33.180 clause 8.5.4.2: the two algorithms. E.1.1: "The GMK, PCK, CSK and MuSiK shall be 16 octets in length", so
// annex F.1.5 gives a 128-bit DPCK for every DPPK ("Where the DPPK is 128-bits, the DPCK shall be 128-bits") except
// for the CSK that protects MCData signalling (MCData signalling parameters, Data signalling payload, End to end
// security parameters) between client and server, where DP_AES_256_GCM takes "the entire output of the KDF".
enum class PayloadAlgorithm : std::uint8_t { aes_128_gcm, aes_256_gcm };

struct ProtectedPayload {
  std::uint8_t message_type = 0; // TS 24.282 table 15.2.2-1 with bit 7 (0x40) set
  std::uint64_t unix_seconds = 0;
  std::uint32_t payload_id = 0;
  std::uint8_t sequence = 0;
  std::uint32_t dppk_id = 0;
  Bytes plain;
  // Sealing: the algorithm to use; opening: the algorithm the message names. TS 33.180 table 8.5.4.1-1 NOTE 6: the
  // signalling algorithm "defaults to DP_AES_128_GCM ... if not present".
  PayloadAlgorithm algorithm = PayloadAlgorithm::aes_128_gcm;
};

//------------------------------------------------------------------------------
// TS 33.180 clauses 8.5.4.1 (table 8.5.4.1-1) and 8.5.4.2 (tables 8.5.4.2-1 and 8.5.4.2-2): seals a Protected Payload
// message; DP_AES_256_GCM only under a CSK (DPPK-ID purpose tag 2, annex G) and with the profile's code for it.
Bytes seal_payload(const ProtectedPayload &message, std::span<const std::uint8_t, 16> dppk,
                   const KeyParameterWireProfile &profile);

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.4.1: the DPPK-ID, readable before decryption so that the receiver can select the key.
std::uint32_t payload_key_id(std::span<const std::uint8_t> data);

//------------------------------------------------------------------------------
// TS 33.180 clauses 8.5.4.1 and 8.5.4.2: decrypts and authenticates a Protected Payload message. csk_signalling: the
// message protects MCData signalling under the CSK (annex F.1.5, last paragraph), the only use in which
// DP_AES_256_GCM is accepted; any other message names DP_AES_128_GCM.
ProtectedPayload open_payload(std::span<const std::uint8_t> data, std::span<const std::uint8_t, 16> dppk,
                              const KeyParameterWireProfile &profile, bool csk_signalling = false);

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

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.10 ("the time in UTC at which the associated key shall no longer be used"; "A value of 0 shall
// imply the key shall not expire") and annex E.6.9 (Status bit 0: not revoked), checked at each use of a key accepted
// earlier: throws once the key may no longer be used. A key without Key Parameters has no Expiry time: it passes.
// Inline, for the header-only users of keys (ProtectedCall).
inline void require_in_use(const KeyMessage &key, std::uint64_t now) {
  if (!key.properties) return;
  if (!(key.properties->status & 1)) throw std::runtime_error("key revoked");
  if (key.properties->expiry_unix_seconds && now >= key.properties->expiry_unix_seconds)
    throw std::runtime_error("key expired");
}
} // namespace mcx::keying
