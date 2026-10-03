// Media plane: AMR-WB speech coding and its RTP payload format, RTP packets, SRTP protection with libsrtp2 and
// 16 kHz mono PCM16 WAV files, as used by the MCPTT and MCVideo media distribution and the test clients.
//
// Specifications: TS 26.281 V19.0.0 (Rel-19), RFC 3550, RFC 3711, RFC 4867, RFC 6184.

#include "mcx/media.hpp"

#include <srtp2/srtp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <mutex>
#include <opencore-amrwb/dec_if.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <vo-amrwbenc/enc_if.h>

namespace mcx {
namespace {

constexpr std::size_t kPcmSamplesPerFrame = 320;
constexpr std::size_t kMaximumRtpPacketBytes = 65'535;
constexpr std::size_t kMaximumRtpPayloadBytes = kMaximumRtpPacketBytes - 12;
constexpr std::size_t kSrtpAuthenticationTagBytes = 10;
constexpr std::size_t kSrtpMasterKeyBytes = 30;
constexpr std::size_t kMaximumWavFileBytes = 64U * 1024U * 1024U;
constexpr std::size_t kMaximumWavDataBytes = 32U * 1024U * 1024U;

// RFC 4867 table 1a: number of speech bits for each AMR-WB frame type.
constexpr std::array<int, 16> kAmrWbFrameBits{132, 177, 253, 285, 317, 365, 397, 461, 477, 40, -1, -1, -1, -1, 0, 0};

struct FrameInfo {
  std::uint8_t frame_type;
  bool good_quality;
  std::size_t speech_bits;
  std::size_t speech_bytes;
};

//------------------------------------------------------------------------------
// Helper: reads bit `bit_index` of a byte string, most significant bit first.
[[nodiscard]] bool get_bit(std::span<const std::uint8_t> bytes, std::size_t bit_index) {
  return (bytes[bit_index / 8] & static_cast<std::uint8_t>(0x80U >> (bit_index % 8))) != 0;
}

//------------------------------------------------------------------------------
// Helper: sets bit `bit_index` of a byte string, most significant bit first, when `value` is true.
void set_bit(std::span<std::uint8_t> bytes, std::size_t bit_index, bool value) {
  if (value) {
    bytes[bit_index / 8] |= static_cast<std::uint8_t>(0x80U >> (bit_index % 8));
  }
}

//------------------------------------------------------------------------------
// RFC 4867 table 1a: the speech bits of an AMR-WB frame type; reserved frame types are refused.
[[nodiscard]] FrameInfo frame_info(std::uint8_t frame_type, bool good_quality) {
  if (frame_type >= kAmrWbFrameBits.size() || kAmrWbFrameBits[frame_type] < 0) {
    throw std::invalid_argument("reserved AMR-WB frame type");
  }
  const auto bits = static_cast<std::size_t>(kAmrWbFrameBits[frame_type]);
  return FrameInfo{frame_type, good_quality, bits, (bits + 7U) / 8U};
}

//------------------------------------------------------------------------------
// RFC 4867 section 5.3: checks an AMR-WB storage-format speech frame (a header octet with FT and Q, then the
// speech bits padded to an octet).
[[nodiscard]] FrameInfo validate_storage_frame(std::span<const std::uint8_t> frame) {
  if (frame.empty()) {
    throw std::invalid_argument("empty AMR-WB storage frame");
  }
  const std::uint8_t header = frame.front();
  const auto info = frame_info(static_cast<std::uint8_t>((header >> 3U) & 0x0fU), (header & 0x04U) != 0);
  if (frame.size() != info.speech_bytes + 1U) {
    throw std::invalid_argument("incorrect AMR-WB storage-frame size");
  }
  return info;
}

//------------------------------------------------------------------------------
// RFC 4867 section 5.3: the storage frame with the header's padding bits and the speech padding bits set to
// zero.
[[nodiscard]] std::vector<std::uint8_t> canonical_storage_frame(std::span<const std::uint8_t> frame,
                                                                const FrameInfo &info) {
  std::vector<std::uint8_t> canonical(info.speech_bytes + 1U, 0);
  canonical[0] = static_cast<std::uint8_t>((info.frame_type << 3U) | (info.good_quality ? 0x04U : 0U));
  std::copy(frame.begin() + 1, frame.end(), canonical.begin() + 1);
  const std::size_t final_bits = info.speech_bits % 8U;
  if (final_bits != 0U) {
    canonical.back() &= static_cast<std::uint8_t>(0xffU << (8U - final_bits));
  }
  return canonical;
}

//------------------------------------------------------------------------------
// Helper: reads a 16-bit value in network byte order.
[[nodiscard]] std::uint16_t read_be16(const std::uint8_t *data) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8U) | static_cast<std::uint16_t>(data[1]));
}

//------------------------------------------------------------------------------
// Helper: reads a 32-bit value in network byte order.
[[nodiscard]] std::uint32_t read_be32(const std::uint8_t *data) {
  return (static_cast<std::uint32_t>(data[0]) << 24U) | (static_cast<std::uint32_t>(data[1]) << 16U) |
         (static_cast<std::uint32_t>(data[2]) << 8U) | static_cast<std::uint32_t>(data[3]);
}

//------------------------------------------------------------------------------
// Helper: appends a 16-bit value in network byte order.
void append_be16(std::vector<std::uint8_t> &bytes, std::uint16_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

//------------------------------------------------------------------------------
// Helper: appends a 32-bit value in network byte order.
void append_be32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 16U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

//------------------------------------------------------------------------------
// Helper: initializes libsrtp2 once per process.
void ensure_srtp_initialized() {
  static std::once_flag initialized;
  static srtp_err_status_t result = srtp_err_status_fail;
  std::call_once(initialized, [] { result = srtp_init(); });
  if (result != srtp_err_status_ok) {
    throw std::runtime_error("could not initialize libsrtp2");
  }
}

//------------------------------------------------------------------------------
// RFC 3711 sections 4.1.1 and 4.2.1: an SRTP and SRTCP policy for AES-CM 128-bit encryption and an 80-bit
// HMAC-SHA1 tag, for one SSRC, with a replay window of 128 packets (section 3.3.2).
[[nodiscard]] srtp_policy_t make_srtp_policy(std::span<const std::uint8_t> master_key, std::uint32_t ssrc) {
  srtp_policy_t policy{};
  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
  policy.ssrc.type = ssrc_specific;
  policy.ssrc.value = ssrc;
  policy.key = const_cast<unsigned char *>(master_key.data());
  policy.window_size = 128;
  policy.allow_repeat_tx = 0;
  policy.next = nullptr;
  return policy;
}

//------------------------------------------------------------------------------
// RFC 3550 section 5.1: checks the fixed header size, version 2 and the SSRC of a packet of this context.
void validate_rtp_identity(std::span<const std::uint8_t> packet, std::uint32_t ssrc, const char *kind) {
  if (packet.size() < 12U || packet.size() > kMaximumRtpPacketBytes || (packet[0] >> 6U) != 2U) {
    throw std::invalid_argument(std::string("invalid ") + kind + " packet header");
  }
  if (read_be32(packet.data() + 8U) != ssrc) {
    throw std::invalid_argument(std::string(kind) + " packet has an unexpected SSRC");
  }
}

//------------------------------------------------------------------------------
// Helper: reads a 16-bit little-endian value (WAV).
[[nodiscard]] std::uint16_t read_le16(const std::uint8_t *data) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) | (static_cast<std::uint16_t>(data[1]) << 8U));
}

//------------------------------------------------------------------------------
// Helper: reads a 32-bit little-endian value (WAV).
[[nodiscard]] std::uint32_t read_le32(const std::uint8_t *data) {
  return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8U) |
         (static_cast<std::uint32_t>(data[2]) << 16U) | (static_cast<std::uint32_t>(data[3]) << 24U);
}

//------------------------------------------------------------------------------
// Helper: appends a 16-bit little-endian value (WAV).
void append_le16(std::vector<std::uint8_t> &bytes, std::uint16_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value));
  bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
}

//------------------------------------------------------------------------------
// Helper: appends a 32-bit little-endian value (WAV).
void append_le32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value));
  bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 16U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
}

//------------------------------------------------------------------------------
// Helper: whether a RIFF chunk carries this four-character identifier.
[[nodiscard]] bool chunk_id_is(const std::uint8_t *data, const char (&id)[5]) {
  return std::equal(data, data + 4, reinterpret_cast<const std::uint8_t *>(id));
}

} // namespace

//------------------------------------------------------------------------------
// Helper: opens the AMR-WB encoder (vo-amrwbenc) and decoder (opencore-amrwb); both or neither.
AmrWbCodec::AmrWbCodec() : encoder_(E_IF_init()), decoder_(D_IF_init()) {
  if (encoder_ == nullptr || decoder_ == nullptr) {
    if (encoder_ != nullptr) {
      E_IF_exit(encoder_);
      encoder_ = nullptr;
    }
    if (decoder_ != nullptr) {
      D_IF_exit(decoder_);
      decoder_ = nullptr;
    }
    throw std::runtime_error("could not initialize AMR-WB codec");
  }
}

//------------------------------------------------------------------------------
// Helper: releases the AMR-WB encoder and decoder.
AmrWbCodec::~AmrWbCodec() noexcept {
  if (encoder_ != nullptr) {
    E_IF_exit(encoder_);
  }
  if (decoder_ != nullptr) {
    D_IF_exit(decoder_);
  }
}

//------------------------------------------------------------------------------
// RFC 3711 section 3.2: opens the outbound and inbound SRTP cryptographic contexts of one SSRC from a 30-byte
// master key and salt (AES_CM_128_HMAC_SHA1_80).
SrtpContext::SrtpContext(std::span<const std::uint8_t> master_key, std::uint32_t ssrc) : ssrc_(ssrc) {
  if (master_key.size() != kSrtpMasterKeyBytes) {
    throw std::invalid_argument("AES_CM_128_HMAC_SHA1_80 requires a 30-byte master key");
  }
  ensure_srtp_initialized();
  auto outbound_policy = make_srtp_policy(master_key, ssrc);
  srtp_t outbound = nullptr;
  if (srtp_create(&outbound, &outbound_policy) != srtp_err_status_ok) {
    throw std::runtime_error("could not create outbound SRTP context");
  }
  outbound_ = outbound;

  auto inbound_policy = make_srtp_policy(master_key, ssrc);
  srtp_t inbound = nullptr;
  if (srtp_create(&inbound, &inbound_policy) != srtp_err_status_ok) {
    srtp_dealloc(outbound);
    outbound_ = nullptr;
    throw std::runtime_error("could not create inbound SRTP context");
  }
  inbound_ = inbound;
}

//------------------------------------------------------------------------------
// Helper: releases the two SRTP contexts.
SrtpContext::~SrtpContext() noexcept {
  if (outbound_ != nullptr) {
    (void)srtp_dealloc(reinterpret_cast<srtp_t>(outbound_));
  }
  if (inbound_ != nullptr) {
    (void)srtp_dealloc(reinterpret_cast<srtp_t>(inbound_));
  }
}

//------------------------------------------------------------------------------
// RFC 3711 section 3.3: encrypts and authenticates an RTP packet of this SSRC.
std::vector<std::uint8_t> SrtpContext::protect_rtp(std::span<const std::uint8_t> rtp_packet) {
  validate_rtp_identity(rtp_packet, ssrc_, "RTP");
  if (rtp_packet.size() > kMaximumRtpPacketBytes - kSrtpAuthenticationTagBytes) {
    throw std::invalid_argument("RTP packet is too large for SRTP authentication tag");
  }
  std::vector<std::uint8_t> protected_packet(rtp_packet.size() + SRTP_MAX_TRAILER_LEN);
  std::copy(rtp_packet.begin(), rtp_packet.end(), protected_packet.begin());
  int length = static_cast<int>(rtp_packet.size());
  const auto result = srtp_protect(reinterpret_cast<srtp_t>(outbound_), protected_packet.data(), &length);
  if (result != srtp_err_status_ok || length < 0 || static_cast<std::size_t>(length) > protected_packet.size()) {
    throw std::runtime_error("SRTP protection failed");
  }
  protected_packet.resize(static_cast<std::size_t>(length));
  return protected_packet;
}

//------------------------------------------------------------------------------
// RFC 3711 section 3.3: authenticates, replay-checks (section 3.3.2) and decrypts an SRTP packet of this SSRC;
// the result must be a valid RTP packet.
std::vector<std::uint8_t> SrtpContext::unprotect_rtp(std::span<const std::uint8_t> srtp_packet) {
  validate_rtp_identity(srtp_packet, ssrc_, "SRTP");
  std::vector<std::uint8_t> plain(srtp_packet.begin(), srtp_packet.end());
  int length = static_cast<int>(plain.size());
  const auto result = srtp_unprotect(reinterpret_cast<srtp_t>(inbound_), plain.data(), &length);
  if (result != srtp_err_status_ok || length < 0 || static_cast<std::size_t>(length) > plain.size()) {
    throw std::runtime_error("SRTP authentication or replay check failed");
  }
  plain.resize(static_cast<std::size_t>(length));
  (void)decode_rtp(plain);
  return plain;
}

//------------------------------------------------------------------------------
// Helper: encodes 20 ms of 16 kHz PCM (320 samples) in AMR-WB mode 0 to 8 as an RFC 4867 section 5.3 storage frame.
std::vector<std::uint8_t> AmrWbCodec::encode(std::span<const std::int16_t> pcm, int mode) {
  if (pcm.size() != kPcmSamplesPerFrame) {
    throw std::invalid_argument("AMR-WB encoding requires exactly 320 PCM samples");
  }
  if (mode < 0 || mode > 8) {
    throw std::invalid_argument("AMR-WB encoding mode must be from 0 through 8");
  }

  static_assert(sizeof(short) == sizeof(std::int16_t));
  std::array<short, kPcmSamplesPerFrame> input{};
  std::copy(pcm.begin(), pcm.end(), input.begin());
  std::array<unsigned char, 64> encoded{};
  const int encoded_size = E_IF_encode(encoder_, mode, input.data(), encoded.data(), 0);
  if (encoded_size <= 0 || static_cast<std::size_t>(encoded_size) > encoded.size()) {
    throw std::runtime_error("AMR-WB encoder failed");
  }
  std::vector<std::uint8_t> frame(encoded.begin(), encoded.begin() + encoded_size);
  const auto info = validate_storage_frame(frame);
  if (info.frame_type != static_cast<std::uint8_t>(mode)) {
    throw std::runtime_error("AMR-WB encoder returned an unexpected frame type");
  }
  return frame;
}

//------------------------------------------------------------------------------
// Helper: decodes an RFC 4867 section 5.3 storage frame into 320 PCM samples; a speech frame with Q=0 is
// decoded as a bad frame.
std::vector<std::int16_t> AmrWbCodec::decode(std::span<const std::uint8_t> storage_frame) {
  const auto info = validate_storage_frame(storage_frame);
  const auto canonical = canonical_storage_frame(storage_frame, info);
  std::array<unsigned char, 64> encoded{};
  std::copy(canonical.begin(), canonical.end(), encoded.begin());
  std::array<short, kPcmSamplesPerFrame> decoded{};
  const int bad_frame = !info.good_quality && info.frame_type <= 9U ? 1 : 0;
  D_IF_decode(decoder_, encoded.data(), decoded.data(), bad_frame);
  return std::vector<std::int16_t>(decoded.begin(), decoded.end());
}

//------------------------------------------------------------------------------
// RFC 4867 sections 4.3 and 4.4: packs one storage frame as a single-frame AMR-WB RTP payload, in
// bandwidth-efficient or octet-aligned mode, with CMR=15 (no mode request) and F=0.
std::vector<std::uint8_t> pack_amr_wb(std::span<const std::uint8_t> storage_frame, bool octet_aligned) {
  const auto info = validate_storage_frame(storage_frame);
  if (octet_aligned) {
    const auto canonical = canonical_storage_frame(storage_frame, info);
    std::vector<std::uint8_t> payload;
    payload.reserve(storage_frame.size() + 1U);
    payload.push_back(0xf0); // CMR=15 and four reserved zero bits.
    payload.insert(payload.end(), canonical.begin(), canonical.end());
    return payload;
  }

  const std::size_t meaningful_bits = 4U + 6U + info.speech_bits;
  std::vector<std::uint8_t> payload((meaningful_bits + 7U) / 8U, 0);
  for (std::size_t bit = 0; bit < 4; ++bit) {
    set_bit(payload, bit, true); // CMR=15.
  }
  // F=0 at bit 4. FT occupies bits 5..8 and Q is bit 9.
  for (std::size_t bit = 0; bit < 4; ++bit) {
    set_bit(payload, 5U + bit, (info.frame_type & (0x08U >> bit)) != 0);
  }
  set_bit(payload, 9U, info.good_quality);
  for (std::size_t bit = 0; bit < info.speech_bits; ++bit) {
    set_bit(payload, 10U + bit, get_bit(storage_frame.subspan(1), bit));
  }
  return payload;
}

//------------------------------------------------------------------------------
// RFC 4867 sections 4.3 and 4.4: unpacks a single-frame AMR-WB RTP payload (bandwidth-efficient or
// octet-aligned) into a storage frame; compound payloads are refused.
std::vector<std::uint8_t> unpack_amr_wb(std::span<const std::uint8_t> payload, bool octet_aligned) {
  if (octet_aligned) {
    if (payload.size() < 2U) {
      throw std::invalid_argument("truncated octet-aligned AMR-WB payload");
    }
    if ((payload[1] & 0x80U) != 0) {
      throw std::invalid_argument("compound AMR-WB payload is unsupported");
    }
    const auto info = frame_info(static_cast<std::uint8_t>((payload[1] >> 3U) & 0x0fU), (payload[1] & 0x04U) != 0);
    if (payload.size() != info.speech_bytes + 2U) {
      throw std::invalid_argument("incorrect octet-aligned AMR-WB payload size");
    }
    return canonical_storage_frame(payload.subspan(1), info);
  }

  if (payload.size() < 2U) {
    throw std::invalid_argument("truncated bandwidth-efficient AMR-WB payload");
  }
  if (get_bit(payload, 4)) {
    throw std::invalid_argument("compound AMR-WB payload is unsupported");
  }
  std::uint8_t frame_type = 0;
  for (std::size_t bit = 0; bit < 4; ++bit) {
    frame_type = static_cast<std::uint8_t>((frame_type << 1U) | (get_bit(payload, 5U + bit) ? 1U : 0U));
  }
  const bool good_quality = get_bit(payload, 9);
  const auto info = frame_info(frame_type, good_quality);
  const std::size_t meaningful_bits = 10U + info.speech_bits;
  const std::size_t expected_size = (meaningful_bits + 7U) / 8U;
  if (payload.size() != expected_size) {
    throw std::invalid_argument("incorrect bandwidth-efficient AMR-WB payload size");
  }
  std::vector<std::uint8_t> frame(info.speech_bytes + 1U, 0);
  frame[0] = static_cast<std::uint8_t>((frame_type << 3U) | (good_quality ? 0x04U : 0U));
  for (std::size_t bit = 0; bit < info.speech_bits; ++bit) {
    set_bit(std::span<std::uint8_t>(frame).subspan(1), bit, get_bit(payload, 10U + bit));
  }
  return frame;
}

//------------------------------------------------------------------------------
// RFC 3550 section 5.1: encodes an RTP packet with the fixed header only (no padding, extension or CSRC).
std::vector<std::uint8_t> encode_rtp(const RtpPacket &packet) {
  if (packet.payload_type > 127U) {
    throw std::invalid_argument("RTP payload type must fit in seven bits");
  }
  if (packet.payload.size() > kMaximumRtpPayloadBytes) {
    throw std::invalid_argument("RTP payload is too large");
  }
  std::vector<std::uint8_t> encoded;
  encoded.reserve(12U + packet.payload.size());
  encoded.push_back(0x80); // Version 2, no padding, extension, or CSRC entries.
  encoded.push_back(static_cast<std::uint8_t>((packet.marker ? 0x80U : 0U) | packet.payload_type));
  append_be16(encoded, packet.sequence);
  append_be32(encoded, packet.timestamp);
  append_be32(encoded, packet.ssrc);
  encoded.insert(encoded.end(), packet.payload.begin(), packet.payload.end());
  return encoded;
}

//------------------------------------------------------------------------------
// RFC 3550 section 5.1: decodes an RTP packet, skipping the CSRC list, the header extension (section 5.3.1)
// and the padding.
RtpPacket decode_rtp(std::span<const std::uint8_t> packet) {
  if (packet.size() < 12U || packet.size() > kMaximumRtpPacketBytes) {
    throw std::invalid_argument("invalid RTP packet size");
  }
  if ((packet[0] >> 6U) != 2U) {
    throw std::invalid_argument("unsupported RTP version");
  }
  const bool has_padding = (packet[0] & 0x20U) != 0;
  const bool has_extension = (packet[0] & 0x10U) != 0;
  const std::size_t csrc_count = packet[0] & 0x0fU;
  std::size_t payload_offset = 12U;
  const std::size_t csrc_bytes = csrc_count * 4U;
  if (csrc_bytes > packet.size() - payload_offset) {
    throw std::invalid_argument("truncated RTP CSRC list");
  }
  payload_offset += csrc_bytes;

  if (has_extension) {
    if (packet.size() - payload_offset < 4U) {
      throw std::invalid_argument("truncated RTP extension header");
    }
    const std::size_t extension_words = read_be16(packet.data() + payload_offset + 2U);
    payload_offset += 4U;
    if (extension_words > (packet.size() - payload_offset) / 4U) {
      throw std::invalid_argument("truncated RTP extension body");
    }
    payload_offset += extension_words * 4U;
  }

  std::size_t payload_end = packet.size();
  if (has_padding) {
    const std::size_t padding_bytes = packet.back();
    if (padding_bytes == 0U || padding_bytes > payload_end - payload_offset) {
      throw std::invalid_argument("invalid RTP padding");
    }
    payload_end -= padding_bytes;
  }

  RtpPacket decoded;
  decoded.payload_type = static_cast<std::uint8_t>(packet[1] & 0x7fU);
  decoded.marker = (packet[1] & 0x80U) != 0;
  decoded.sequence = read_be16(packet.data() + 2U);
  decoded.timestamp = read_be32(packet.data() + 4U);
  decoded.ssrc = read_be32(packet.data() + 8U);
  decoded.payload.assign(packet.begin() + static_cast<std::ptrdiff_t>(payload_offset),
                         packet.begin() + static_cast<std::ptrdiff_t>(payload_end));
  return decoded;
}

//------------------------------------------------------------------------------
// Helper: reads a 16 kHz mono PCM16 WAV file (bounded in size).
std::vector<std::int16_t> read_wav(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    throw std::runtime_error("could not open WAV file: " + path.string());
  }
  const std::streampos end = input.tellg();
  if (end < 0 || static_cast<std::uintmax_t>(end) > kMaximumWavFileBytes) {
    throw std::invalid_argument("WAV file is too large");
  }
  const auto file_size = static_cast<std::size_t>(end);
  if (file_size < 12U) {
    throw std::invalid_argument("truncated WAV RIFF header");
  }
  std::vector<std::uint8_t> bytes(file_size);
  input.seekg(0);
  if (!input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
    throw std::runtime_error("could not read WAV file: " + path.string());
  }
  if (!chunk_id_is(bytes.data(), "RIFF") || !chunk_id_is(bytes.data() + 8U, "WAVE")) {
    throw std::invalid_argument("WAV file has invalid RIFF signature");
  }
  const std::uint64_t declared_size = static_cast<std::uint64_t>(read_le32(bytes.data() + 4U)) + 8U;
  if (declared_size != bytes.size()) {
    throw std::invalid_argument("WAV RIFF size does not match file size");
  }

  bool found_format = false;
  bool found_data = false;
  std::uint16_t format = 0;
  std::uint16_t channels = 0;
  std::uint32_t sample_rate = 0;
  std::uint32_t byte_rate = 0;
  std::uint16_t block_align = 0;
  std::uint16_t bits_per_sample = 0;
  std::span<const std::uint8_t> pcm_bytes;
  std::size_t offset = 12U;
  while (offset < bytes.size()) {
    if (bytes.size() - offset < 8U) {
      throw std::invalid_argument("truncated WAV chunk header");
    }
    const auto chunk_size = static_cast<std::size_t>(read_le32(bytes.data() + offset + 4U));
    const std::size_t chunk_start = offset + 8U;
    if (chunk_size > bytes.size() - chunk_start) {
      throw std::invalid_argument("truncated WAV chunk body");
    }
    const auto chunk = std::span<const std::uint8_t>(bytes).subspan(chunk_start, chunk_size);
    if (chunk_id_is(bytes.data() + offset, "fmt ")) {
      if (found_format || chunk.size() < 16U) {
        throw std::invalid_argument("invalid or duplicate WAV fmt chunk");
      }
      found_format = true;
      format = read_le16(chunk.data());
      channels = read_le16(chunk.data() + 2U);
      sample_rate = read_le32(chunk.data() + 4U);
      byte_rate = read_le32(chunk.data() + 8U);
      block_align = read_le16(chunk.data() + 12U);
      bits_per_sample = read_le16(chunk.data() + 14U);
    } else if (chunk_id_is(bytes.data() + offset, "data")) {
      if (found_data || chunk.size() > kMaximumWavDataBytes) {
        throw std::invalid_argument("invalid, duplicate, or oversized WAV data chunk");
      }
      found_data = true;
      pcm_bytes = chunk;
    }
    const std::size_t padding = chunk_size & 1U;
    if (padding > bytes.size() - chunk_start - chunk_size) {
      throw std::invalid_argument("missing WAV chunk padding");
    }
    offset = chunk_start + chunk_size + padding;
  }
  if (!found_format || !found_data) {
    throw std::invalid_argument("WAV file requires fmt and data chunks");
  }
  if (format != 1U || channels != 1U || sample_rate != 16'000U || byte_rate != 32'000U || block_align != 2U ||
      bits_per_sample != 16U) {
    throw std::invalid_argument("WAV must be 16 kHz mono PCM16");
  }
  if ((pcm_bytes.size() & 1U) != 0) {
    throw std::invalid_argument("WAV PCM16 data has an odd byte count");
  }

  std::vector<std::int16_t> pcm(pcm_bytes.size() / 2U);
  for (std::size_t index = 0; index < pcm.size(); ++index) {
    pcm[index] = static_cast<std::int16_t>(read_le16(pcm_bytes.data() + index * 2U));
  }
  return pcm;
}

//------------------------------------------------------------------------------
// Helper: writes a 16 kHz mono PCM16 WAV file.
void write_wav(const std::filesystem::path &path, std::span<const std::int16_t> pcm) {
  if (pcm.size() > kMaximumWavDataBytes / sizeof(std::int16_t)) {
    throw std::invalid_argument("PCM input is too large for bounded WAV output");
  }
  const auto data_bytes = static_cast<std::uint32_t>(pcm.size() * sizeof(std::int16_t));
  std::vector<std::uint8_t> bytes;
  bytes.reserve(44U + data_bytes);
  bytes.insert(bytes.end(), {'R', 'I', 'F', 'F'});
  append_le32(bytes, 36U + data_bytes);
  bytes.insert(bytes.end(), {'W', 'A', 'V', 'E'});
  bytes.insert(bytes.end(), {'f', 'm', 't', ' '});
  append_le32(bytes, 16U);
  append_le16(bytes, 1U);
  append_le16(bytes, 1U);
  append_le32(bytes, 16'000U);
  append_le32(bytes, 32'000U);
  append_le16(bytes, 2U);
  append_le16(bytes, 16U);
  bytes.insert(bytes.end(), {'d', 'a', 't', 'a'});
  append_le32(bytes, data_bytes);
  for (const auto sample : pcm) {
    append_le16(bytes, static_cast<std::uint16_t>(sample));
  }

  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    throw std::runtime_error("could not write WAV file: " + path.string());
  }
  output.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!output) {
    throw std::runtime_error("could not write WAV file: " + path.string());
  }
  output.close();
  if (!output) {
    throw std::runtime_error("could not finalize WAV file: " + path.string());
  }
}

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.2: the payload a media distribution function sends to one destination: AMR-WB (the MCPTT
// codec, also used for MCVideo audio) is repacked from the sender's RFC 4867 framing to the destination's; any
// other payload, such as H.264 (RFC 6184), goes on unchanged.
std::vector<std::uint8_t> relay_payload(std::span<const std::uint8_t> payload, RtpCodec codec, bool from_octet_aligned,
                                        bool to_octet_aligned) {
  if (codec != RtpCodec::amr_wb) return {payload.begin(), payload.end()};
  return pack_amr_wb(unpack_amr_wb(payload, from_octet_aligned), to_octet_aligned);
}
} // namespace mcx
