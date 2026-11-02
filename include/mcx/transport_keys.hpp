//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The KM client's transport key (TrK) and integrity key (InK) for KMS traffic: the pre-provisioned keys with their
// 32-bit identifiers, which key protects what (the TrK for confidentiality; the InK for integrity, or the TrK when no
// InK is present), the keys derived from them and the AES key wrap of key material.
//
// Only the parts the specifications define are here. Not implemented until the specifications define them (reported
// as specification defects): the text form of the TrK-ID and Signature-ID elements of KMS messages (TS 33.180 D.3.5.3
// types them xsd:string) and the 128-bit key of AES-128-GCM under the 256-bit TrK.
// The wrap of key material whose length is not a multiple of 64 bits (the 257-octet RSK, the 65-octet PVT) is not
// defined by TS 33.180 either (clause 9.3.4.2 names only RFC 3394); wrap_key_material() implements the reading of the
// ETSI test suite for TS 37.579 (maintainer decision 2026-11-01), not a 3GPP rule, and is reported as a spec defect.
// The KMS documents (include/mcx/key_documents.hpp) use these keys for the signed and TrK-wrapped KMS exchange.
//
// Specifications: TS 33.180 V19.5.0 (Rel-19) clauses 5.3.2, 5.3.3, 5.11.1, 9.3.3, annexes D and F.1.4; RFC 3394.
#pragma once
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace mcx::transport {
//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.3: "The TrK and InK are initially distributed via an out-of-band mechanism along with their
// 32-bit identifiers"; clause 9.3.3: the key is the XPK and its identifier the XPK-ID.
struct Xpk {
  std::vector<std::uint8_t> key;
  std::uint32_t id = 0;

  // Clause 5.11.1: the key does not outlive its holder in memory.
  ~Xpk() { OPENSSL_cleanse(key.data(), key.size()); }
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.2: the keys pre-provisioned to the KM client of one MC service user (P0 of annex F.1.4).
struct TransportKeys {
  std::optional<Xpk> trk;
  std::optional<Xpk> ink;
  std::string user;
};

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.2 ("pre-provisioned"): reads the keys of a KM client's configuration, an object with optional
// "trk" and "ink" members, each {"file": <path>, "id": <32-bit identifier>}; the file holds the key in hexadecimal
// (the out-of-band format is local, clause 5.3.3). The TrK is 256 bits (clause 9.3.3); the InK 128 or 256 bits (the
// two XPK sizes of annex F.1.4). Clause 5.11.1: the TrK and InK "shall be stored in a protected state within the UE"
// (the method is out of scope); OpenMCX's method: a key file that is not a regular file readable and writable by its
// owner only is refused (checked on the descriptor it is read from). An empty
// or absent object gives no keys.
TransportKeys load(const nlohmann::json &cfg, const std::string &user);

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.2: the keys pre-provisioned for one MC service user from a security configuration whose
// "transport_keys" member is an object keyed by the exact MC service user URI (values as for load()); the entry of
// exactly that URI, none without one: another user's entry is never used.
TransportKeys load_for(const nlohmann::json &security, const std::string &user);

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.3: "confidentiality protection shall use the 256-bit TrK as the XPK and the TrK-ID as the
// XPK-ID"; nothing without a TrK.
std::optional<Xpk> confidentiality_xpk(const TransportKeys &keys);

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.2 and annexes D.2.2 and D.3.1: integrity protection with the InK when one is present, otherwise
// with the TrK ("If the InK-ID is not provided ... then the TrK shall be used for integrity protection"); nothing
// without either.
std::optional<Xpk> integrity_xpk(const TransportKeys &keys);

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.3 and annex F.1.4: the confidentiality key (FC 0x51) and the integrity key (FC 0x52) derived from
// an XPK for the user, as long as the XPK.
std::vector<std::uint8_t> confidentiality_key(const Xpk &xpk, const std::string &user);
std::vector<std::uint8_t> integrity_key(const Xpk &xpk, const std::string &user);

//------------------------------------------------------------------------------
// TS 33.180 annex D.1: HMAC-SHA256 with a signature length of 256 bits under the integrity key of the XPK.
std::vector<std::uint8_t> mac(const Xpk &xpk, const std::string &user, std::string_view data);

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.4.2 and annex D.3.3.2 (kw-aes256, RFC 3394 with the default initial value) under a 256-bit
// key: wraps key material of at least 128 bits whose length is a multiple of 64 bits (RFC 3394 section 2); any other
// length is refused.
std::vector<std::uint8_t> wrap(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> key_material);

//------------------------------------------------------------------------------
// RFC 3394 section 2.2.2: unwraps and checks the integrity of wrapped key material (at least 24 octets, a multiple of
// 8); throws when the check fails.
std::vector<std::uint8_t> unwrap(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> wrapped);

//------------------------------------------------------------------------------
// Key material of any length (the 32-octet SSK, the 65-octet PVT, the 257-octet RSK of TS 33.180 D.3.3.2) under
// kw-aes256. TS 33.180 V19.5.0 clause 9.3.4.2 ("The AES-256 key wrap algorithm as defined in RFC 3394 [34] shall be
// supported") and TS 37.579-1 V18.1.0 table 5.5.4.10.8-1 (EncryptionAlgorithm "AES256") give no padding rule for
// lengths RFC 3394 cannot wrap (a spec defect, reported). This is the rule of the ETSI test suite for TS 37.579
// (MCX_SecurityFunctions.ttcn f_MCX_XML_EncryptKey, "padding according to ... xmlenc-core1 clause 5.2.1"), the test
// system's reading and not a 3GPP rule (maintainer decision 2026-11-01): n = 8 - (length mod 8) octets are appended,
// 1 <= n <= 8 (a whole block when the length is already a multiple of 8), n - 1 zero octets and then one octet of
// value n; the result is wrapped with RFC 3394. At least 8 octets of key material (RFC 3394: two 64-bit blocks).
std::vector<std::uint8_t> wrap_key_material(std::span<const std::uint8_t> kek,
                                            std::span<const std::uint8_t> key_material);

//------------------------------------------------------------------------------
// The reverse of wrap_key_material(): RFC 3394 unwrap with its integrity check, then the last octet n must be 1 to 8
// and the n octets are removed. The other n - 1 padding octets are not checked (xmlenc-core1 5.2.1: arbitrary).
// Throws on any failure.
std::vector<std::uint8_t> unwrap_key_material(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> wrapped);
} // namespace mcx::transport
