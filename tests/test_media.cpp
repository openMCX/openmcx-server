//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Media handling: the AMR-WB RTP payload format, RTP packet coding, SRTP protection, the AMR-WB codec
// and the PCM16 WAV adapter.
//
// Specifications: RFC 4867 (AMR-WB RTP payload format), RFC 3550 (RTP), RFC 3711 (SRTP), RFC 6184 (H.264 RTP
// payload format).

#include "mcx/media.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <numbers>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int failures = 0;

//------------------------------------------------------------------------------
// Records a failed check with its message.
void check(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

//------------------------------------------------------------------------------
// Records a failed check unless the function throws an Exception.
template <typename Exception = std::exception, typename Function>
void check_throws(Function &&function, const std::string &message) {
  try {
    function();
    check(false, message + " (did not throw)");
  } catch (const Exception &) {
  } catch (...) {
    check(false, message + " (wrong exception type)");
  }
}

//------------------------------------------------------------------------------
// A unique path in the temporary directory for a test fixture.
std::filesystem::path temporary_path(const std::string &suffix) {
  const auto nonce = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  return std::filesystem::temp_directory_path() / ("openmcx-media-" + std::to_string(nonce) + suffix);
}

//------------------------------------------------------------------------------
// Writes the bytes to a fixture file; throws when it cannot.
void write_bytes(const std::filesystem::path &path, std::span<const std::uint8_t> bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output || (!bytes.empty() && !output.write(reinterpret_cast<const char *>(bytes.data()),
                                                  static_cast<std::streamsize>(bytes.size())))) {
    throw std::runtime_error("could not create media test fixture");
  }
}

//------------------------------------------------------------------------------
// RFC 4867 sections 4.3 and 4.4: one AMR-WB storage-format frame packed in bandwidth-efficient and
// octet-aligned mode against independently packed literals, the relay repacking between the two modes, H.264
// (RFC 6184) passed on unchanged, and the NO_DATA frame in both modes.
void test_rfc4867_literals() {
  std::vector<std::uint8_t> storage(18, 0);
  storage[0] = 0x04;     // AMR-WB 6.60 kbit/s, good frame.
  storage[1] = 0x80;     // Literal d(0)=1.
  storage.back() = 0x10; // Literal d(131)=1; low four bits are storage padding.

  std::vector<std::uint8_t> bandwidth_expected(18, 0);
  bandwidth_expected[0] = 0xf0;
  bandwidth_expected[1] = 0x60;
  bandwidth_expected.back() = 0x04;
  const auto bandwidth = mcx::pack_amr_wb(storage);
  check(bandwidth == bandwidth_expected, "bandwidth-efficient payload matches independently packed RFC 4867 bits");
  check(mcx::unpack_amr_wb(bandwidth) == storage, "bandwidth-efficient payload recovers storage-format frame");

  std::vector<std::uint8_t> octet_expected(19, 0);
  octet_expected[0] = 0xf0;
  octet_expected[1] = 0x04;
  octet_expected[2] = 0x80;
  octet_expected.back() = 0x10;
  const auto octet = mcx::pack_amr_wb(storage, true);
  check(octet == octet_expected, "octet-aligned payload matches literal CMR, ToC, and speech octets");
  check(mcx::unpack_amr_wb(octet, true) == storage, "octet-aligned payload recovers storage-format frame");

  // A media distribution function repacks AMR-WB per destination and passes
  // H.264 (RFC 6184) on untouched.
  check(mcx::relay_payload(bandwidth, mcx::RtpCodec::amr_wb, false, true) == octet_expected,
        "relay repacks bandwidth-efficient AMR-WB to octet-aligned");
  check(mcx::relay_payload(octet, mcx::RtpCodec::amr_wb, true, false) == bandwidth_expected,
        "relay repacks octet-aligned AMR-WB to bandwidth-efficient");
  const std::vector<std::uint8_t> nal{0x65, 0x88, 0x84, 0x00, 0x33, 0xff}; // an IDR slice NAL unit
  check(mcx::relay_payload(nal, mcx::RtpCodec::h264, false, true) == nal, "relay passes H.264 unchanged");
  check_throws([&] { (void)mcx::relay_payload(nal, mcx::RtpCodec::amr_wb, false, false); },
               "relay refuses a payload that is not AMR-WB as speech");

  const std::array<std::uint8_t, 1> no_data_frame{0x7c};
  const std::array<std::uint8_t, 2> no_data_bandwidth{0xf7, 0xc0};
  const std::array<std::uint8_t, 2> no_data_octet{0xf0, 0x7c};
  check(mcx::pack_amr_wb(no_data_frame) ==
            std::vector<std::uint8_t>(no_data_bandwidth.begin(), no_data_bandwidth.end()),
        "bandwidth-efficient NO_DATA frame has the literal ten-bit payload");
  check(mcx::unpack_amr_wb(no_data_bandwidth) == std::vector<std::uint8_t>(no_data_frame.begin(), no_data_frame.end()),
        "bandwidth-efficient NO_DATA literal parses");
  check(mcx::pack_amr_wb(no_data_frame, true) == std::vector<std::uint8_t>(no_data_octet.begin(), no_data_octet.end()),
        "octet-aligned NO_DATA frame has no speech bytes");
}

//------------------------------------------------------------------------------
// RFC 4867 sections 4.3 and 4.4: empty, reserved, truncated and overlong frames are rejected; padding
// and reserved bits are ignored on reception and canonicalized; a reserved CMR is ignored; a compound payload
// and excess octet-aligned data are rejected by the single-frame API.
void test_amr_payload_rejection() {
  check_throws([&] { (void)mcx::pack_amr_wb({}); }, "empty AMR-WB frame is rejected");

  const std::array<std::uint8_t, 1> reserved_ft{0x54}; // FT=10.
  check_throws([&] { (void)mcx::pack_amr_wb(reserved_ft); }, "reserved AMR-WB frame type is rejected");

  std::vector<std::uint8_t> truncated(17, 0);
  truncated[0] = 0x04;
  check_throws([&] { (void)mcx::pack_amr_wb(truncated); }, "truncated AMR-WB speech frame is rejected");

  std::vector<std::uint8_t> excess(19, 0);
  excess[0] = 0x04;
  check_throws([&] { (void)mcx::pack_amr_wb(excess); }, "overlong AMR-WB speech frame is rejected");

  std::vector<std::uint8_t> nonzero_frame_padding(18, 0);
  nonzero_frame_padding[0] = 0x87;
  nonzero_frame_padding.back() = 0x01;
  std::vector<std::uint8_t> canonical_frame(18, 0);
  canonical_frame[0] = 0x04;
  check(mcx::pack_amr_wb(nonzero_frame_padding) == mcx::pack_amr_wb(canonical_frame),
        "storage-format padding is ignored and canonicalized when packetized");

  const std::array<std::uint8_t, 2> invalid_cmr{0x97, 0xc0};
  check(mcx::unpack_amr_wb(invalid_cmr) == std::vector<std::uint8_t>({0x7c}),
        "reserved AMR-WB CMR is ignored on reception");

  const std::array<std::uint8_t, 2> compound_toc{0xf8, 0x40};
  check_throws([&] { (void)mcx::unpack_amr_wb(compound_toc); },
               "compound bandwidth-efficient payload is rejected by single-frame API");

  const std::array<std::uint8_t, 2> invalid_payload_padding{0xf7, 0xc1};
  check(mcx::unpack_amr_wb(invalid_payload_padding) == std::vector<std::uint8_t>({0x7c}),
        "bandwidth-efficient payload padding is ignored on reception");

  const std::array<std::uint8_t, 2> octet_reserved_bits{0xf1, 0x7f};
  check(mcx::unpack_amr_wb(octet_reserved_bits, true) == std::vector<std::uint8_t>({0x7c}),
        "octet-aligned reserved and ToC padding bits are ignored and canonicalized");

  std::vector<std::uint8_t> octet_speech_padding(19, 0);
  octet_speech_padding[0] = 0xf0;
  octet_speech_padding[1] = 0x04;
  octet_speech_padding.back() = 0x0f;
  check(mcx::unpack_amr_wb(octet_speech_padding, true) == canonical_frame,
        "octet-aligned speech padding is ignored and canonicalized");

  const std::array<std::uint8_t, 3> octet_excess{0xf0, 0x7c, 0x00};
  check_throws([&] { (void)mcx::unpack_amr_wb(octet_excess, true); }, "excess octet-aligned speech data is rejected");
}

//------------------------------------------------------------------------------
// RFC 3550 section 5.1: the RTP fixed header against a literal packet, sequence number wrap, CSRC
// list, header extension (section 5.3.1) and padding skipped in the payload, and malformed or oversized
// packets rejected.
void test_rtp_literals_and_bounds() {
  mcx::RtpPacket packet;
  packet.payload_type = 96;
  packet.marker = true;
  packet.sequence = 0x1234;
  packet.timestamp = 0x01020304;
  packet.ssrc = 0xaabbccdd;
  packet.payload = {0x11, 0x22};

  const std::vector<std::uint8_t> expected{0x80, 0xe0, 0x12, 0x34, 0x01, 0x02, 0x03,
                                           0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22};
  check(mcx::encode_rtp(packet) == expected, "RTP encoder matches literal network-byte-order packet");
  check(mcx::decode_rtp(expected) == packet, "RTP literal round trips through parser");

  packet.sequence = 0xffff;
  check(mcx::decode_rtp(mcx::encode_rtp(packet)).sequence == 0xffff, "RTP sequence 65535 is preserved before wrap");
  packet.sequence = 0;
  check(mcx::decode_rtp(mcx::encode_rtp(packet)).sequence == 0, "RTP sequence zero is preserved after wrap");

  const std::vector<std::uint8_t> extended{0xb1, 0x60, 0x00, 0x07, 0x00, 0x00, 0x01, 0x40, 0x12, 0x34,
                                           0x56, 0x78, 0xca, 0xfe, 0xba, 0xbe, 0xbe, 0xef, 0x00, 0x01,
                                           0x10, 0x20, 0x30, 0x40, 0xaa, 0xbb, 0x00, 0x02};
  const auto parsed = mcx::decode_rtp(extended);
  check(parsed.sequence == 7 && parsed.timestamp == 320 && parsed.ssrc == 0x12345678,
        "RTP parser reads fixed header with CSRC, extension, and padding present");
  check(parsed.payload == std::vector<std::uint8_t>({0xaa, 0xbb}),
        "RTP parser excludes CSRC, extension, and padding from payload");

  check_throws([&] { (void)mcx::decode_rtp(std::span<const std::uint8_t>(expected).first(11)); },
               "truncated fixed RTP header is rejected");
  auto wrong_version = expected;
  wrong_version[0] = 0x40;
  check_throws([&] { (void)mcx::decode_rtp(wrong_version); }, "non-v2 RTP is rejected");
  const std::array<std::uint8_t, 12> truncated_csrc{0x81, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  check_throws([&] { (void)mcx::decode_rtp(truncated_csrc); }, "truncated RTP CSRC list is rejected");
  const std::array<std::uint8_t, 16> truncated_extension{0x90, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xef, 0, 1};
  check_throws([&] { (void)mcx::decode_rtp(truncated_extension); }, "truncated RTP extension body is rejected");
  auto zero_padding = expected;
  zero_padding[0] |= 0x20;
  zero_padding.back() = 0;
  check_throws([&] { (void)mcx::decode_rtp(zero_padding); }, "zero RTP padding count is rejected");
  auto excessive_padding = expected;
  excessive_padding[0] |= 0x20;
  excessive_padding.back() = 0x7f;
  check_throws([&] { (void)mcx::decode_rtp(excessive_padding); },
               "RTP padding longer than available payload is rejected");

  packet.payload_type = 128;
  check_throws([&] { (void)mcx::encode_rtp(packet); }, "RTP payload type above seven bits is rejected");
  packet.payload_type = 96;
  packet.payload.resize(65'524);
  check_throws([&] { (void)mcx::encode_rtp(packet); }, "oversized RTP payload is rejected");
}

//------------------------------------------------------------------------------
// RFC 3711 section 3.3: SRTP with AES-CM-128 and an 80-bit HMAC-SHA1 authentication tag encrypts and
// authenticates; section 3.3.2: a replayed packet is rejected, and a packet failing authentication does not
// update the replay list; a master key and salt shorter than 30 bytes are rejected.
void test_srtp_round_trip_authentication_and_replay() {
  std::array<std::uint8_t, 30> key{};
  for (std::size_t index = 0; index < key.size(); ++index) {
    key[index] = static_cast<std::uint8_t>(index * 7U + 3U);
  }

  mcx::RtpPacket packet;
  packet.payload_type = 96;
  packet.marker = true;
  packet.sequence = 41;
  packet.timestamp = 12'800;
  packet.ssrc = 0x11223344;
  packet.payload = {0xf0, 0x40, 0x00, 0x00};
  const auto plain = mcx::encode_rtp(packet);

  mcx::SrtpContext sender(key, packet.ssrc);
  mcx::SrtpContext receiver(key, packet.ssrc);
  const auto protected_packet = sender.protect_rtp(plain);
  check(protected_packet != plain && protected_packet.size() == plain.size() + 10U,
        "SRTP AES-CM-128 adds an 80-bit authentication tag");
  check(!std::equal(plain.begin() + 12, plain.end(), protected_packet.begin() + 12),
        "SRTP encrypts RTP payload bytes rather than only appending authentication");
  check(receiver.unprotect_rtp(protected_packet) == plain, "SRTP authenticates and decrypts a protected RTP packet");
  check_throws([&] { (void)receiver.unprotect_rtp(protected_packet); }, "SRTP receiver rejects a replayed RTP packet");

  packet.sequence = 42;
  const auto authentic = sender.protect_rtp(mcx::encode_rtp(packet));
  auto tampered = authentic;
  tampered.back() ^= 0x01;
  check_throws([&] { (void)receiver.unprotect_rtp(tampered); },
               "SRTP receiver rejects a packet with a changed authentication tag");
  check(receiver.unprotect_rtp(authentic) == mcx::encode_rtp(packet),
        "failed authentication does not poison SRTP replay state");

  check_throws([&] { mcx::SrtpContext invalid(std::span<const std::uint8_t>(key).first(29), packet.ssrc); },
               "SRTP rejects a master key shorter than 30 bytes");
}

//------------------------------------------------------------------------------
// The AMR-WB codec in all nine speech modes: storage frame size and mode, packetization in both
// RFC 4867 modes, decoded energy; SPEECH_LOST and NO_DATA concealment kept apart in the decoder state; invalid
// input rejected.
void test_real_codec_all_modes_and_loss() {
  std::array<std::int16_t, 320> pcm{};
  for (std::size_t index = 0; index < pcm.size(); ++index) {
    const double phase = 2.0 * std::numbers::pi * 440.0 * static_cast<double>(index) / 16000.0;
    pcm[index] = static_cast<std::int16_t>(std::sin(phase) * 12000.0);
  }

  constexpr std::array<std::size_t, 9> storage_sizes{18, 24, 33, 37, 41, 47, 51, 59, 61};
  mcx::AmrWbCodec codec;
  std::vector<std::uint8_t> last_frame;
  for (int mode = 0; mode <= 8; ++mode) {
    const auto frame = codec.encode(pcm, mode);
    check(frame.size() == storage_sizes[static_cast<std::size_t>(mode)],
          "AMR-WB encoder returns exact storage-frame size for mode " + std::to_string(mode));
    check(((frame.front() >> 3) & 0x0f) == mode, "AMR-WB encoder marks requested mode " + std::to_string(mode));
    check(mcx::unpack_amr_wb(mcx::pack_amr_wb(frame)) == frame,
          "bandwidth-efficient packetization preserves mode " + std::to_string(mode));
    check(mcx::unpack_amr_wb(mcx::pack_amr_wb(frame, true), true) == frame,
          "octet-aligned packetization preserves mode " + std::to_string(mode));
    const auto decoded = codec.decode(frame);
    check(decoded.size() == 320, "AMR-WB decoder returns one 20 ms frame for mode " + std::to_string(mode));
    long long energy = 0;
    for (const auto sample : decoded) {
      energy += std::abs(static_cast<int>(sample));
    }
    check(energy > 1000, "AMR-WB decoded signal has measurable energy for mode " + std::to_string(mode));
    last_frame = frame;
  }

  const std::array<std::uint8_t, 1> speech_lost{0x74};
  const std::array<std::uint8_t, 1> no_data{0x7c};
  mcx::AmrWbCodec loss_decoder;
  mcx::AmrWbCodec no_data_decoder;
  (void)loss_decoder.decode(last_frame);
  (void)no_data_decoder.decode(last_frame);
  const auto concealed_loss = loss_decoder.decode(speech_lost);
  const auto concealed_no_data = no_data_decoder.decode(no_data);
  check(concealed_loss.size() == 320 && concealed_no_data.size() == 320,
        "AMR-WB loss indications each produce one concealed frame");
  const std::array<std::uint8_t, 6> sid_frame{0x4c, 0, 0, 0, 0, 0};
  check(loss_decoder.decode(sid_frame) != no_data_decoder.decode(sid_frame),
        "SPEECH_LOST is preserved in decoder state instead of being collapsed into NO_DATA");

  check_throws([&] { (void)codec.encode(std::span<const std::int16_t>(pcm).first(319)); },
               "AMR-WB encoder rejects PCM not exactly 320 samples");
  check_throws([&] { (void)codec.encode(pcm, 9); }, "AMR-WB encoder rejects non-speech mode");
  check_throws([&] { (void)codec.decode(std::span<const std::uint8_t>(last_frame).first(2)); },
               "AMR-WB decoder rejects truncated storage frame");
}

//------------------------------------------------------------------------------
// The PCM16 WAV adapter: round trip of signed samples; missing chunks, a sample rate other than
// 16 kHz and an oversized data chunk rejected; a write failure reported.
void test_wav_round_trip_and_malformed_chunks() {
  const auto wav_path = temporary_path(".wav");
  std::vector<std::int16_t> pcm(320);
  for (std::size_t index = 0; index < pcm.size(); ++index) {
    pcm[index] = static_cast<std::int16_t>(static_cast<int>(index) * 73 - 11000);
  }
  mcx::write_wav(wav_path, pcm);
  check(mcx::read_wav(wav_path) == pcm, "PCM16 WAV adapter round trips signed samples");
  std::filesystem::remove(wav_path);

  const auto malformed_path = temporary_path("-bad.wav");
  const std::array<std::uint8_t, 12> truncated{'R', 'I', 'F', 'F', 36, 0, 0, 0, 'W', 'A', 'V', 'E'};
  write_bytes(malformed_path, truncated);
  check_throws([&] { (void)mcx::read_wav(malformed_path); }, "WAV without fmt and data chunks is rejected");

  const std::array<std::uint8_t, 44> wrong_rate{
      'R', 'I', 'F',  'F',  36, 0, 0,    0,    'W', 'A', 'V', 'E', 'f', 'm', 't', ' ', 16,  0,   0, 0, 1, 0,
      1,   0,   0x40, 0x1f, 0,  0, 0x80, 0x3e, 0,   0,   2,   0,   16,  0,   'd', 'a', 't', 'a', 0, 0, 0, 0};
  write_bytes(malformed_path, wrong_rate);
  check_throws([&] { (void)mcx::read_wav(malformed_path); }, "WAV sample rate other than 16 kHz is rejected");

  const std::array<std::uint8_t, 44> oversized_data_claim{
      'R', 'I', 'F',  'F',  36, 0, 0, 0,    'W', 'A', 'V', 'E', 'f', 'm', 't', ' ', 16,  0,   0,    0,    1,    0,
      1,   0,   0x80, 0x3e, 0,  0, 0, 0x7d, 0,   0,   2,   0,   16,  0,   'd', 'a', 't', 'a', 0xff, 0xff, 0xff, 0x7f};
  write_bytes(malformed_path, oversized_data_claim);
  check_throws([&] { (void)mcx::read_wav(malformed_path); },
               "oversized or truncated WAV data chunk is rejected before allocation");
  std::filesystem::remove(malformed_path);

  if (std::filesystem::exists("/dev/full")) {
    check_throws<std::runtime_error>([&] { mcx::write_wav("/dev/full", pcm); },
                                     "WAV flush or close failure is reported");
  }
}

} // namespace

//------------------------------------------------------------------------------
// Runs every media test and reports the number of failures.
int main() {
  test_rfc4867_literals();
  test_amr_payload_rejection();
  test_rtp_literals_and_bounds();
  test_srtp_round_trip_authentication_and_replay();
  test_real_codec_all_modes_and_loss();
  test_wav_round_trip_and_malformed_chunks();

  if (failures != 0) {
    std::cerr << failures << " media test(s) failed\n";
    return 1;
  }
  std::cout << "all media tests passed\n";
  return 0;
}
