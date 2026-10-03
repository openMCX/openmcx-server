// Media and RTCP protection: the MIKEY PRF, the SRTP/SRTCP master key and salt derivation for PCK, GMK and CSK/SPK,
// the GUK-ID, and SRTP/SRTCP with AEAD_AES_128_GCM, MKI and the RCCm3 ROC.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), RFC 3830, RFC 6043, RFC 3711, RFC 7714, RFC 4771, RFC 3550.
#include "mcx/security.hpp"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <srtp2/srtp.h>

#include <algorithm>
#include <climits>
#include <mutex>
#include <stdexcept>

namespace mcx {
namespace {
using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// Helper: appends a 32-bit value in network byte order.
void put32(Bytes &buffer, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) buffer.push_back(value >> shift);
}

//------------------------------------------------------------------------------
// Helper: reads a 32-bit network-order value.
std::uint32_t get32(std::span<const std::uint8_t> bytes) {
  return (std::uint32_t(bytes[0]) << 24) | (std::uint32_t(bytes[1]) << 16) | (std::uint32_t(bytes[2]) << 8) | bytes[3];
}

//------------------------------------------------------------------------------
// Helper: HMAC-SHA-256 (32 bytes).
Bytes hmac(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
  Bytes out(32);
  unsigned length = 0;
  if (key.size() > INT_MAX ||
      !HMAC(EVP_sha256(), key.data(), int(key.size()), data.data(), data.size(), out.data(), &length) || length != 32)
    throw std::runtime_error("HMAC-SHA256 failed");
  return out;
}

//------------------------------------------------------------------------------
// RFC 3550 appendix A.2: the validity checks of a compound RTCP packet (version 2, lengths that add up, padding only
// in the last packet).
void validate_rtcp(std::span<const std::uint8_t> packet) {
  for (std::size_t offset = 0; offset < packet.size();) {
    if (packet.size() - offset < 4 || (packet[offset] >> 6) != 2)
      throw std::invalid_argument("invalid RTCP compound header");
    const auto size = 4U * (1U + (std::size_t(packet[offset + 2]) << 8) + packet[offset + 3]);
    if (size < 8 || size > packet.size() - offset) throw std::invalid_argument("invalid RTCP length");
    if ((packet[offset] & 0x20) && (offset + size != packet.size() || packet.back() == 0 || packet.back() > size - 4))
      throw std::invalid_argument("invalid RTCP padding");
    offset += size;
  }
}

//------------------------------------------------------------------------------
// Helper: throws on a libsrtp failure (authentication, replay or packet processing).
void require(srtp_err_status_t result) {
  if (result != srtp_err_status_ok)
    throw std::runtime_error("SRTP authentication, replay or packet processing failure: " + std::to_string(result));
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 7.4.1, 7.4.2 and 9.4.6: the SRTP (or SRTCP) master key (16 bytes) and master salt (12 bytes)
// from the MIKEY TGK, RAND, CSB-ID and CS-ID (TS 33.180 table E.1.3-1) with the key derivation of RFC 3830 section
// 4.1.3 (constants 0x2AD01C64 and 0x39A2C14B) and the PRF-HMAC-SHA-256 of RFC 6043 section 6.1.
SecurityMaterial derive(std::span<const std::uint8_t> key, std::span<const std::uint8_t> random, std::uint32_t id,
                        std::uint8_t cs) {
  if ((key.size() != 16 && key.size() != 32) || random.size() < 16 || random.size() > 255)
    throw std::invalid_argument("invalid MIKEY TGK or RAND size");
  SecurityMaterial result;
  for (auto [constant, offset, length] : {std::array<std::uint32_t, 3>{0x2ad01c64, 0, 16}, {0x39a2c14b, 16, 12}}) {
    Bytes label;
    put32(label, constant);
    label.push_back(cs);
    put32(label, id);
    label.insert(label.end(), random.begin(), random.end());
    auto output = mikey_prf(key, label, length);
    std::copy(output.begin(), output.end(), result.master_key_salt.begin() + offset);
    OPENSSL_cleanse(output.data(), output.size());
  }
  return result;
}
} // namespace

//------------------------------------------------------------------------------
// RFC 3830 section 4.1.2 with PRF-HMAC-SHA-256 (RFC 6043 section 6.1), as TS 33.180 clause 7.4.1 requires: the
// MIKEY PRF, the XOR of the P-functions of each 256-bit block of the key.
Bytes mikey_prf(std::span<const std::uint8_t> key, std::span<const std::uint8_t> label, std::size_t length) {
  if (key.empty() || length > 65536) throw std::invalid_argument("invalid MIKEY PRF size");
  Bytes output(length, 0);
  for (std::size_t start = 0; start < key.size(); start += 32) {
    auto block = key.subspan(start, std::min<std::size_t>(32, key.size() - start));
    Bytes chain(label.begin(), label.end());
    for (std::size_t pos = 0; pos < length; pos += 32) {
      chain = hmac(block, chain);
      Bytes input = chain;
      input.insert(input.end(), label.begin(), label.end());
      auto digest = hmac(block, input);
      for (std::size_t index = 0; index < std::min<std::size_t>(32, length - pos); ++index)
        output[pos + index] ^= digest[index];
      OPENSSL_cleanse(digest.data(), digest.size());
      OPENSSL_cleanse(input.data(), input.size());
    }
    OPENSSL_cleanse(chain.data(), chain.size());
  }
  return output;
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.3 and clause 7.4.2: the GUK-ID, the GMK-ID XOR the User Salt (the 28 least significant bits
// of the KDF of TS 33.220 annex B with FC = 0x50, P0 = the MC service user ID of the sender, keyed with the GMK).
std::uint32_t derive_guk_id(std::span<const std::uint8_t> gmk, std::uint32_t gmk_id, std::string_view user) {
  if ((gmk.size() != 16 && gmk.size() != 32) || user.empty() || user.size() > 65535 || (gmk_id >> 28) != 0)
    throw std::invalid_argument("invalid GMK or sender identity");
  Bytes input{0x50};
  input.insert(input.end(), user.begin(), user.end());
  input.push_back(user.size() >> 8);
  input.push_back(user.size());
  auto digest = hmac(gmk, input);
  return gmk_id ^ (get32(std::span(digest).last(4)) & 0x0fffffff);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 7.4.2 and annex E.2.2: TGK = GMK, CSB-ID = GUK-ID, CS-ID 4 (MCPTT) or 5 (MCVideo); the MKI is
// GMK-ID || GUK-ID and the ROC is sent in every packet (table E.2.2-1, RCCm3).
SecurityMaterial derive_group_security(std::span<const std::uint8_t> key, std::span<const std::uint8_t> random,
                                       std::uint32_t gmk_id, std::uint32_t guk_id, bool mcvideo) {
  if ((gmk_id >> 28) != 0 || (guk_id >> 28) != 0) throw std::invalid_argument("GMK/GUK purpose tag must be zero");
  auto out = derive(key, random, guk_id, mcvideo ? 5 : 4);
  put32(out.mki, gmk_id);
  put32(out.mki, guk_id);
  out.media = out.transmit_roc = true;
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 7.4.1 and annex E.3.2: TGK = PCK, CSB-ID = PCK-ID, CS-ID 0 for the stream from the initiator and
// 1 for the stream from the receiver (2 and 3 for MCVideo); the MKI is the 32-bit PCK-ID.
SecurityMaterial derive_private_security(std::span<const std::uint8_t> key, std::span<const std::uint8_t> random,
                                         std::uint32_t pck_id, bool from_initiator, bool mcvideo) {
  if ((pck_id >> 28) != 1) throw std::invalid_argument("PCK purpose tag must be one");
  auto out = derive(key, random, pck_id, (from_initiator ? 0 : 1) + (mcvideo ? 2 : 0));
  put32(out.mki, pck_id);
  out.media = true;
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 9.4.5 and 9.4.6 and annex E.4.2: the SRTCP master key and salt for floor, transmission and media
// control from the KFC: CS-ID 6 (MCPTT) or 8 (MCVideo); the MKI is the 32-bit KFC-ID.
SecurityMaterial derive_floor_security(std::span<const std::uint8_t> key, std::span<const std::uint8_t> random,
                                       std::uint32_t id, bool mcvideo) {
  // A CSK (purpose tag 2) between a client and its server, or an SPK (3) between
  // servers, which TS 33.180 clause 9.4.5 uses the same way as the KFC.
  if ((id >> 28) != 2 && (id >> 28) != 3) throw std::invalid_argument("floor key purpose tag must be two or three");
  auto out = derive(key, random, id, mcvideo ? 8 : 6);
  put32(out.mki, id);
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 7.5 and clause 9.4.8: one SRTP/SRTCP context pair (outbound and inbound) for one SSRC and key
// epoch, with AEAD_AES_128_GCM (RFC 7714), the MKI and, for group media, the RCCm3 ROC (RFC 4771).
struct SecureStream::Impl {
  SecurityMaterial material;
  std::uint32_t ssrc;
  srtp_t outbound = nullptr, inbound = nullptr;
  bool sent_rtp = false;
  std::uint16_t last_sequence = 0;

  // TS 33.180 tables E.2.2-1, E.3.2-1 and E.4.2-1: an AEAD_AES_128_GCM policy with a 16-byte tag, no key
  // derivation rate, and the master key selected by its MKI.
  srtp_t create() {
    srtp_policy_t policy{};
    srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy.rtp);
    srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy.rtcp);
    policy.ssrc.type = ssrc_specific;
    policy.ssrc.value = ssrc;
    policy.window_size = 128;
    policy.allow_repeat_tx = 0;
    srtp_master_key_t key{};
    key.key = material.master_key_salt.data();
    key.mki_id = material.mki.data();
    key.mki_size = material.mki.size();
    srtp_master_key_t *keys[] = {&key};
    policy.keys = keys;
    policy.num_master_keys = 1;
    srtp_t ctx = nullptr;
    require(srtp_create(&ctx, &policy));
    return ctx;
  }

  // Helper: checks the MKI length of the profile and creates both contexts.
  Impl(SecurityMaterial value, std::uint32_t id) : material(std::move(value)), ssrc(id) {
    if (material.mki.size() != (material.transmit_roc ? 8U : 4U) || (material.transmit_roc && !material.media))
      throw std::invalid_argument("invalid MCPTT MKI length");
    static std::once_flag once;
    static srtp_err_status_t initialized = srtp_err_status_fail;
    std::call_once(once, [] { initialized = srtp_init(); });
    require(initialized);
    outbound = create();
    try {
      inbound = create();
    } catch (...) {
      srtp_dealloc(outbound);
      throw;
    }
  }

  // Helper: frees both contexts and wipes the master key and salt.
  ~Impl() {
    if (outbound) srtp_dealloc(outbound);
    if (inbound) srtp_dealloc(inbound);
    OPENSSL_cleanse(material.master_key_salt.data(), material.master_key_salt.size());
  }

  // TS 33.180 clause 7.5.2 (and RFC 4771 for the ROC): protects or unprotects one RTP or RTCP packet; a received ROC
  // is verified in a disposable context before it changes the inbound state.
  Bytes process(std::span<const std::uint8_t> packet, bool rtcp, bool protect) {
    if (!rtcp && !material.media) throw std::invalid_argument("CSK is restricted to SRTCP");
    const std::size_t minimum = rtcp ? 8 : 12;
    if (packet.size() < minimum || packet.size() > 65535 || (packet[0] >> 6) != 2 ||
        get32(packet.subspan(rtcp ? 4 : 8, 4)) != ssrc)
      throw std::invalid_argument("invalid RTP/RTCP header or SSRC");
    if (rtcp && protect) validate_rtcp(packet);
    const auto sequence = std::uint16_t((std::uint16_t(packet[2]) << 8) | packet[3]);
    if (!rtcp && protect && sent_rtp) {
      const auto distance = std::uint16_t(sequence - last_sequence);
      if (distance == 0 || distance >= 32768)
        throw std::invalid_argument("outbound RTP sequences must advance monotonically");
    }
    Bytes bytes(packet.begin(), packet.end());
    std::uint32_t roc = 0;
    if (!protect && !rtcp && !material.transmit_roc && bytes.size() < minimum + 16 + material.mki.size())
      throw std::invalid_argument("truncated SRTP");
    if (!protect && !rtcp && material.transmit_roc) {
      if (bytes.size() < minimum + 16 + material.mki.size() + 4) throw std::invalid_argument("truncated SRTP");
      roc = get32(std::span(bytes).last(4));
      bytes.resize(bytes.size() - 4);
      // Validate the transmitted ROC in a disposable context first. A forged
      // ROC must not change the persistent replay window or rollover state.
      auto verifier = create();
      int trial_length = bytes.size();
      auto trial = bytes;
      auto result = srtp_set_stream_roc(verifier, ssrc, roc);
      if (result == srtp_err_status_ok) result = srtp_unprotect_mki(verifier, trial.data(), &trial_length, 1);
      srtp_dealloc(verifier);
      require(result);
      require(srtp_set_stream_roc(inbound, ssrc, roc));
    }
    int length = bytes.size();
    if (protect) bytes.resize(bytes.size() + SRTP_MAX_TRAILER_LEN + material.mki.size() + 4);
    srtp_err_status_t result;
    if (rtcp)
      result = protect ? srtp_protect_rtcp_mki(outbound, bytes.data(), &length, 1, 0)
                       : srtp_unprotect_rtcp_mki(inbound, bytes.data(), &length, 1);
    else
      result = protect ? srtp_protect_mki(outbound, bytes.data(), &length, 1, 0)
                       : srtp_unprotect_mki(inbound, bytes.data(), &length, 1);
    require(result);
    bytes.resize(length);
    if (rtcp && !protect) validate_rtcp(bytes);
    if (protect && !rtcp) {
      if (material.transmit_roc) {
        require(srtp_get_stream_roc(outbound, ssrc, &roc));
        put32(bytes, roc);
      }
      last_sequence = sequence;
      sent_rtp = true;
    }
    return bytes;
  }
};

//------------------------------------------------------------------------------
// Helper: a protected stream for one SSRC with the given key material.
SecureStream::SecureStream(SecurityMaterial material, std::uint32_t ssrc)
    : impl_(std::make_unique<Impl>(std::move(material), ssrc)) {}

//------------------------------------------------------------------------------
// Helper: frees the SRTP contexts.
SecureStream::~SecureStream() = default;

//------------------------------------------------------------------------------
// TS 33.180 clause 7.5.2: protects an outbound RTP packet (SRTP).
Bytes SecureStream::protect_rtp(std::span<const std::uint8_t> packet) { return impl_->process(packet, false, true); }

//------------------------------------------------------------------------------
// TS 33.180 clause 7.5.2: verifies and decrypts an inbound SRTP packet.
Bytes SecureStream::unprotect_rtp(std::span<const std::uint8_t> packet) { return impl_->process(packet, false, false); }

//------------------------------------------------------------------------------
// TS 33.180 clause 9.4.7: protects an outbound RTCP compound packet (SRTCP).
Bytes SecureStream::protect_rtcp(std::span<const std::uint8_t> packet) { return impl_->process(packet, true, true); }

//------------------------------------------------------------------------------
// TS 33.180 clause 9.4.7: verifies and decrypts an inbound SRTCP packet.
Bytes SecureStream::unprotect_rtcp(std::span<const std::uint8_t> packet) { return impl_->process(packet, true, false); }
} // namespace mcx
