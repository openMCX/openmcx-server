//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Media and RTCP protection: the MIKEY PRF, the SRTP/SRTCP master key and salt derivation for PCK, GMK and CSK, the
// GUK-ID, and SRTP/SRTCP streams.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), RFC 3830, RFC 6043, RFC 3711, RFC 7714, RFC 4771.
#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace mcx {
//------------------------------------------------------------------------------
// TS 33.180 clauses 7.4.1, 7.4.2 and 9.4.6: the SRTP (or SRTCP) master key (16 bytes) and master salt (12 bytes) of a
// crypto session, its MKI and its profile options.
struct SecurityMaterial {
  std::array<std::uint8_t, 28> master_key_salt{};
  std::vector<std::uint8_t> mki;
  bool media = false;        // SRTP allowed; a CSK protects SRTCP only (TS 33.180 annex E.4.1).
  bool transmit_roc = false; // RCCm3 ROC in every packet (TS 33.180 table E.2.2-1); not in the PCK profile.
};

//------------------------------------------------------------------------------
// RFC 3830 section 4.1.2 with PRF-HMAC-SHA-256 (RFC 6043 section 6.1), as TS 33.180 clause 7.4.1 requires: the MIKEY
// PRF.
std::vector<std::uint8_t> mikey_prf(std::span<const std::uint8_t> key, std::span<const std::uint8_t> label,
                                    std::size_t length);

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.3 and clause 7.4.2: the GUK-ID, the GMK-ID XOR the User Salt of the MC service user ID.
std::uint32_t derive_guk_id(std::span<const std::uint8_t> gmk, std::uint32_t gmk_id, std::string_view user);

//------------------------------------------------------------------------------
// TS 33.180 clause 7.4.2 and annex E.2.2: TGK = GMK, CSB-ID = GUK-ID, CS-ID 4 (MCPTT) or 5 (MCVideo); the MKI is GMK-ID
// || GUK-ID and the ROC is sent in every packet. The CS-IDs of TS 33.180 table E.1.3-1 differ by service: with mcvideo,
// the MCVideo group call (5), MCVideo private call (2 and 3) and CSK SRTCP for MCVideo (8).
SecurityMaterial derive_group_security(std::span<const std::uint8_t> key, std::span<const std::uint8_t> random,
                                       std::uint32_t gmk_id, std::uint32_t guk_id, bool mcvideo = false);

//------------------------------------------------------------------------------
// TS 33.180 clause 7.4.1 and annex E.3.2: TGK = PCK, CSB-ID = PCK-ID, CS-ID 0 for the stream from the initiator and 1
// for the stream from the receiver (2 and 3 for MCVideo); the MKI is the 32-bit PCK-ID.
SecurityMaterial derive_private_security(std::span<const std::uint8_t> key, std::span<const std::uint8_t> random,
                                         std::uint32_t pck_id, bool from_initiator, bool mcvideo = false);

//------------------------------------------------------------------------------
// TS 33.180 clauses 9.4.5 and 9.4.6 and annex E.4.2: the SRTCP master key and salt for floor, transmission and media
// control: CS-ID 6 (MCPTT) or 8 (MCVideo); the MKI is the 32-bit key ID. Not implemented: MuSiK SRTCP protection
// (CS-ID 7 and 9, TS 33.180 clause 9.2.2), which only MBMS uses.
SecurityMaterial derive_floor_security(std::span<const std::uint8_t> key, std::span<const std::uint8_t> random,
                                       std::uint32_t id, bool mcvideo = false);

//------------------------------------------------------------------------------
// TS 33.180 clauses 7.5 and 9.4.8: SRTP and SRTCP protection with AEAD_AES_128_GCM (RFC 7714) for one SSRC and key
// epoch per object. Instances are not thread-safe. Outbound RTP must advance in sequence order (modulo 65536);
// inbound can reorder.
class SecureStream {
public:
  SecureStream(SecurityMaterial material, std::uint32_t ssrc);
  ~SecureStream();
  SecureStream(const SecureStream &) = delete;
  SecureStream &operator=(const SecureStream &) = delete;
  // TS 33.180 clause 7.5.2: protects an outbound RTP packet (SRTP).
  std::vector<std::uint8_t> protect_rtp(std::span<const std::uint8_t> packet);
  // TS 33.180 clause 7.5.2: verifies and decrypts an inbound SRTP packet.
  std::vector<std::uint8_t> unprotect_rtp(std::span<const std::uint8_t> packet);
  // TS 33.180 clause 9.4.7: protects an outbound RTCP compound packet (SRTCP).
  std::vector<std::uint8_t> protect_rtcp(std::span<const std::uint8_t> packet);
  // TS 33.180 clause 9.4.7: verifies and decrypts an inbound SRTCP packet.
  std::vector<std::uint8_t> unprotect_rtcp(std::span<const std::uint8_t> packet);
  // RFC 3711 sections 3.4 and 8.1: the stream goes on under a new master key (same profile and MKI length); its
  // SRTCP index continues and its replay lists stay (security.cpp). A failed re-key breaks the stream: it refuses
  // every later packet in both directions.
  void rekey(const SecurityMaterial &material);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
} // namespace mcx
