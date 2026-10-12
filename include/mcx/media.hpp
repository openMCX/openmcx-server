//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Media plane: AMR-WB speech coding and its RTP payload format, RTP packets, SRTP protection and 16 kHz mono PCM16 WAV
// files, as used by the MCPTT and MCVideo media distribution and the test clients.
//
// Specifications: TS 26.281 V19.0.0 (Rel-19), RFC 3550, RFC 3711, RFC 4867, RFC 6184.
#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace mcx {

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.2: the AMR-WB speech encoder and decoder (the MCPTT codec of TS 26.179), on RFC 4867
// section 5.3 storage frames.
class AmrWbCodec {
public:
  AmrWbCodec();
  ~AmrWbCodec() noexcept;

  AmrWbCodec(const AmrWbCodec &) = delete;
  AmrWbCodec &operator=(const AmrWbCodec &) = delete;
  AmrWbCodec(AmrWbCodec &&) = delete;
  AmrWbCodec &operator=(AmrWbCodec &&) = delete;

  // Encodes 20 ms of 16 kHz PCM (320 samples) in AMR-WB mode 0 to 8 as an RFC 4867 section 5.3 storage frame.
  [[nodiscard]] std::vector<std::uint8_t> encode(std::span<const std::int16_t> pcm, int mode = 0);
  // Decodes an RFC 4867 section 5.3 storage frame into 320 PCM samples.
  [[nodiscard]] std::vector<std::int16_t> decode(std::span<const std::uint8_t> storage_frame);

private:
  void *encoder_ = nullptr;
  void *decoder_ = nullptr;
};

//------------------------------------------------------------------------------
// RFC 3711 section 3.2: the outbound and inbound SRTP cryptographic contexts of one SSRC (AES_CM_128_HMAC_SHA1_80).
class SrtpContext {
public:
  SrtpContext(std::span<const std::uint8_t> master_key, std::uint32_t ssrc);
  ~SrtpContext() noexcept;

  SrtpContext(const SrtpContext &) = delete;
  SrtpContext &operator=(const SrtpContext &) = delete;
  SrtpContext(SrtpContext &&) = delete;
  SrtpContext &operator=(SrtpContext &&) = delete;

  // RFC 3711 section 3.3: encrypts and authenticates an RTP packet of this SSRC.
  [[nodiscard]] std::vector<std::uint8_t> protect_rtp(std::span<const std::uint8_t> rtp_packet);
  // RFC 3711 section 3.3: authenticates, replay-checks and decrypts an SRTP packet of this SSRC.
  [[nodiscard]] std::vector<std::uint8_t> unprotect_rtp(std::span<const std::uint8_t> srtp_packet);

private:
  void *outbound_ = nullptr;
  void *inbound_ = nullptr;
  std::uint32_t ssrc_ = 0;
};

//------------------------------------------------------------------------------
// RFC 4867 sections 4.3 and 4.4: packs one storage frame as a single-frame AMR-WB RTP payload, in bandwidth-efficient
// or octet-aligned mode.
[[nodiscard]] std::vector<std::uint8_t> pack_amr_wb(std::span<const std::uint8_t> storage_frame,
                                                    bool octet_aligned = false);

//------------------------------------------------------------------------------
// RFC 4867 sections 4.3 and 4.4: unpacks a single-frame AMR-WB RTP payload into a storage frame.
[[nodiscard]] std::vector<std::uint8_t> unpack_amr_wb(std::span<const std::uint8_t> payload,
                                                      bool octet_aligned = false);

//------------------------------------------------------------------------------
// TS 26.281 clauses 4.1.1 and 4.1.2: the codec of an RTP stream a relay forwards: the MCPTT and MCVideo audio of
// TS 26.179 and TS 26.281 clause 4.1.2, or the MCVideo video (H.264) of TS 26.281 clause 4.1.1.
enum class RtpCodec { amr_wb, h264 };

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.2: the payload a media distribution function sends to one destination: AMR-WB is repacked from
// the sender's framing to the destination's (RFC 4867 octet-aligned or bandwidth-efficient); any other payload, such
// as H.264 (RFC 6184), goes on unchanged.
[[nodiscard]] std::vector<std::uint8_t> relay_payload(std::span<const std::uint8_t> payload, RtpCodec codec,
                                                      bool from_octet_aligned, bool to_octet_aligned);

//------------------------------------------------------------------------------
// RFC 3550 section 5.1: the fields of an RTP packet with the fixed header only.
struct RtpPacket {
  std::uint8_t payload_type = 96;
  bool marker = false;
  std::uint16_t sequence = 0;
  std::uint32_t timestamp = 0;
  std::uint32_t ssrc = 0;
  std::vector<std::uint8_t> payload;

  bool operator==(const RtpPacket &) const = default;
};

//------------------------------------------------------------------------------
// RFC 3550 section 5.1: encodes an RTP packet with the fixed header only (no padding, extension or CSRC).
[[nodiscard]] std::vector<std::uint8_t> encode_rtp(const RtpPacket &packet);

//------------------------------------------------------------------------------
// RFC 3550 section 5.1: decodes an RTP packet, skipping the CSRC list, the header extension and the padding.
[[nodiscard]] RtpPacket decode_rtp(std::span<const std::uint8_t> packet);

//------------------------------------------------------------------------------
// Helper: reads a 16 kHz mono PCM16 WAV file (bounded in size).
[[nodiscard]] std::vector<std::int16_t> read_wav(const std::filesystem::path &path);

//------------------------------------------------------------------------------
// Helper: writes a 16 kHz mono PCM16 WAV file.
void write_wav(const std::filesystem::path &path, std::span<const std::int16_t> pcm);

} // namespace mcx
