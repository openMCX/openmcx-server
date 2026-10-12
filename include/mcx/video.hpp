//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCVideo media (TS 26.281 clause 4.1.1): H.264 video, carried in RTP with the payload format of RFC 6184 in
// packetization mode 1.
//
// Specifications: TS 26.281 V19.0.0 (Rel-19), RFC 6184, RFC 3550, RFC 5104.
#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace mcx::video {

//------------------------------------------------------------------------------
// Helper: a picture in I420 (planar YUV 4:2:0): width x height luma, half-size chroma.
struct Frame {
  unsigned width = 0, height = 0;
  std::vector<std::uint8_t> y, u, v;
  bool operator==(const Frame &) const = default;
};

//------------------------------------------------------------------------------
// Helper: the lab has no camera: a deterministic moving pattern of bars and a gradient, different for every index.
[[nodiscard]] Frame test_pattern(unsigned width, unsigned height, std::uint32_t index);

//------------------------------------------------------------------------------
// Helper: FNV-1a over the three planes: equal pictures have equal checksums.
[[nodiscard]] std::uint32_t checksum(const Frame &frame);

// RFC 6184: a NAL unit without its H.264 annex B start code.
using Nal = std::vector<std::uint8_t>;
using AccessUnit = std::vector<Nal>; // the NAL units of one picture

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.1: the encoder settings.
struct EncoderOptions {
  unsigned width = 320, height = 240; // 240p, the TS 26.281 clause 4.1.1 minimum
  unsigned frame_rate = 15;
  unsigned bitrate = 300000;        // bit/s
  unsigned key_frame_interval = 30; // frames between IDR pictures
};

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.1: H.264 Constrained Baseline Profile Level 3.1 (profile-level-id 42e01f) from OpenH264.
// Deviation from TS 26.281 clause 4.1.1: the Constrained High Profile encoding it recommends ("should") is not
// produced, and CHP decoders decode this profile.
class Encoder {
public:
  explicit Encoder(const EncoderOptions &options = {});
  ~Encoder();
  Encoder(const Encoder &) = delete;
  Encoder &operator=(const Encoder &) = delete;
  // The access unit of the picture: SPS and PPS precede every IDR picture. An
  // empty result means the rate control skipped the picture.
  AccessUnit encode(const Frame &frame, std::uint64_t timestamp_ms);
  // The next picture is an IDR picture (RFC 5104 FIR/PLI, or a new receiver).
  void request_key_frame();

  [[nodiscard]] const EncoderOptions &options() const { return options_; }

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  EncoderOptions options_;
};

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.1: an H.264 (AVC) decoder (OpenH264).
class Decoder {
public:
  Decoder();
  ~Decoder();
  Decoder(const Decoder &) = delete;
  Decoder &operator=(const Decoder &) = delete;
  // The decoded picture of an access unit, or nothing while the decoder waits for
  // what it needs (for example an IDR picture after a loss).
  std::optional<Frame> decode(const AccessUnit &unit);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

//------------------------------------------------------------------------------
// RFC 6184 section 5.1: one RTP payload of the stream and whether it ends the access unit (the RTP marker bit).
struct Payload {
  std::vector<std::uint8_t> bytes;
  bool marker = false;
  bool operator==(const Payload &) const = default;
};

//------------------------------------------------------------------------------
// RFC 6184 section 6.3 (packetization mode 1): a NAL unit that fits goes in a Single NAL Unit packet (section 5.6), a
// larger one is split into FU-A fragments (section 5.8).
[[nodiscard]] std::vector<Payload> packetize(const AccessUnit &unit, std::size_t max_payload = 1200);

//------------------------------------------------------------------------------
// RFC 6184 section 6.3 (packetization mode 1), the receiving side: Single NAL Unit, STAP-A (section 5.7.1) and FU-A
// packets become access units, completed by the marker bit or a new timestamp. A sequence gap discards the access
// unit it damages. Other packet types (MTAP, FU-B, reserved) are refused.
class Depacketizer {
public:
  // The access units this packet completes: usually none or one, two when it
  // ends one and a previous one lacked its marker.
  std::vector<AccessUnit> push(std::uint16_t sequence, std::uint32_t timestamp, bool marker,
                               std::span<const std::uint8_t> payload);

  [[nodiscard]] unsigned lost_units() const { return lost_; }

private:
  AccessUnit unit_;
  Nal fragment_;
  bool in_fragment_ = false, damaged_ = false, started_ = false;
  std::uint16_t next_sequence_ = 0;
  std::uint32_t timestamp_ = 0;
  unsigned lost_ = 0;
};

//------------------------------------------------------------------------------
// RFC 6184 section 5.2 (H.264 table 7-1): the NAL unit type: 5 is an IDR slice, 7 an SPS, 8 a PPS.
[[nodiscard]] inline unsigned nal_type(const Nal &nal) { return nal.empty() ? 0 : nal.front() & 0x1fU; }

//------------------------------------------------------------------------------
// RFC 6184 section 5.2: whether the access unit carries an IDR slice (NAL unit type 5).
[[nodiscard]] bool is_key_frame(const AccessUnit &unit);

} // namespace mcx::video
