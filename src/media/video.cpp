// MCVideo media: H.264 (AVC) encoding and decoding with OpenH264 (TS 26.281 clause 4.1.1) and its RTP payload
// format in packetization mode 1 (RFC 6184).
//
// Specifications: TS 26.281 V19.0.0 (Rel-19), RFC 6184, RFC 3550.

#include "mcx/video.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <wels/codec_api.h>

namespace mcx::video {
namespace {
constexpr std::uint8_t fu_a = 28, stap_a = 24;

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.1: refuses picture sizes outside what the codec supports here (even sizes up to 1080p).
void check_size(unsigned width, unsigned height) {
  if (!width || !height || width % 2 || height % 2 || width > 1920 || height > 1088)
    throw std::invalid_argument("unsupported picture size");
}

//------------------------------------------------------------------------------
// Helper: the length of the H.264 annex B start code (00 00 01 or 00 00 00 01) at `data`, or 0.
std::size_t start_code_length(const std::uint8_t *data, std::size_t size) {
  if (size >= 4 && !data[0] && !data[1] && !data[2] && data[3] == 1) return 4;
  if (size >= 3 && !data[0] && !data[1] && data[2] == 1) return 3;
  return 0;
}
} // namespace

//------------------------------------------------------------------------------
// Helper: a moving colour-bar test picture in I420, for tests and the test client.
Frame test_pattern(unsigned width, unsigned height, std::uint32_t index) {
  check_size(width, height);
  Frame frame{width, height, std::vector<std::uint8_t>(std::size_t(width) * height),
              std::vector<std::uint8_t>(std::size_t(width / 2) * (height / 2)),
              std::vector<std::uint8_t>(std::size_t(width / 2) * (height / 2))};
  // Eight vertical bars that move two pixels per frame over a luma gradient.
  for (unsigned row = 0; row < height; ++row)
    for (unsigned col = 0; col < width; ++col) {
      const unsigned bar = ((col + 2 * index) * 8 / width) % 8;
      frame.y[std::size_t(row) * width + col] = static_cast<std::uint8_t>(16 + bar * 28 + row * 16 / height);
    }
  for (unsigned row = 0; row < height / 2; ++row)
    for (unsigned col = 0; col < width / 2; ++col) {
      const unsigned bar = ((2 * col + 2 * index) * 8 / width) % 8;
      frame.u[std::size_t(row) * (width / 2) + col] = static_cast<std::uint8_t>(64 + bar * 16);
      frame.v[std::size_t(row) * (width / 2) + col] = static_cast<std::uint8_t>(192 - bar * 16);
    }
  return frame;
}

//------------------------------------------------------------------------------
// Helper: the FNV-1a hash of the three planes of a picture, to compare pictures end to end.
std::uint32_t checksum(const Frame &frame) {
  std::uint32_t hash = 2166136261u;
  for (const auto *plane : {&frame.y, &frame.u, &frame.v})
    for (const auto byte : *plane) hash = (hash ^ byte) * 16777619u;
  return hash;
}

//------------------------------------------------------------------------------
// Helper: whether the access unit carries an IDR slice (NAL unit type 5, RFC 6184 section 5.2).
bool is_key_frame(const AccessUnit &unit) {
  return std::any_of(unit.begin(), unit.end(), [](const Nal &nal) { return nal_type(nal) == 5; });
}

struct Encoder::Impl {
  ISVCEncoder *encoder = nullptr;

  ~Impl() {
    if (encoder) {
      encoder->Uninitialize();
      WelsDestroySVCEncoder(encoder);
    }
  }
};

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.1: opens an OpenH264 encoder for real-time camera video, Constrained Baseline Profile
// (CAVLC) level 3.1, single slice, one reference frame. Deviation from TS 26.281 clause 4.1.1: the Constrained
// High Profile it recommends ("should") is not produced; CHP decoders decode this profile.
Encoder::Encoder(const EncoderOptions &options) : impl_(std::make_unique<Impl>()), options_(options) {
  check_size(options.width, options.height);
  if (!options.frame_rate || options.frame_rate > 60 || !options.bitrate)
    throw std::invalid_argument("unsupported frame rate or bitrate");
  if (WelsCreateSVCEncoder(&impl_->encoder) || !impl_->encoder) throw std::runtime_error("H.264 encoder unavailable");
  SEncParamExt params{};
  impl_->encoder->GetDefaultParams(&params);
  params.iUsageType = CAMERA_VIDEO_REAL_TIME;
  params.iPicWidth = static_cast<int>(options.width);
  params.iPicHeight = static_cast<int>(options.height);
  params.iTargetBitrate = static_cast<int>(options.bitrate);
  params.iMaxBitrate = static_cast<int>(options.bitrate * 2);
  params.iRCMode = RC_BITRATE_MODE;
  params.fMaxFrameRate = static_cast<float>(options.frame_rate);
  params.iSpatialLayerNum = 1;
  params.iTemporalLayerNum = 1;
  params.uiIntraPeriod = options.key_frame_interval;
  params.iNumRefFrame = 1;
  params.bEnableFrameSkip = false;   // one access unit per picture, so every frame can be checked
  params.iEntropyCodingModeFlag = 0; // CAVLC: Constrained Baseline
  params.eSpsPpsIdStrategy = CONSTANT_ID;
  params.iMultipleThreadIdc = 1;
  auto &layer = params.sSpatialLayers[0];
  layer.iVideoWidth = params.iPicWidth;
  layer.iVideoHeight = params.iPicHeight;
  layer.fFrameRate = params.fMaxFrameRate;
  layer.iSpatialBitrate = params.iTargetBitrate;
  layer.iMaxSpatialBitrate = params.iMaxBitrate;
  layer.uiProfileIdc = PRO_BASELINE;
  layer.uiLevelIdc = LEVEL_3_1;
  layer.sSliceArgument.uiSliceMode = SM_SINGLE_SLICE;
  if (impl_->encoder->InitializeExt(&params)) throw std::runtime_error("H.264 encoder configuration refused");
  int format = videoFormatI420;
  impl_->encoder->SetOption(ENCODER_OPTION_DATAFORMAT, &format);
}

//------------------------------------------------------------------------------
// Helper: the OpenH264 encoder is released by Impl.
Encoder::~Encoder() = default;

//------------------------------------------------------------------------------
// Helper: the next picture is an IDR picture (after an RFC 5104 FIR or PLI, or for a new receiver).
void Encoder::request_key_frame() { impl_->encoder->ForceIntraFrame(true); }

//------------------------------------------------------------------------------
// Helper: encodes one I420 picture into an access unit of NAL units without their H.264 annex B start codes.
AccessUnit Encoder::encode(const Frame &frame, std::uint64_t timestamp_ms) {
  if (frame.width != options_.width || frame.height != options_.height ||
      frame.y.size() != std::size_t(frame.width) * frame.height || frame.u.size() != frame.y.size() / 4 ||
      frame.v.size() != frame.y.size() / 4)
    throw std::invalid_argument("picture does not match the encoder");
  SSourcePicture picture{};
  picture.iColorFormat = videoFormatI420;
  picture.iPicWidth = static_cast<int>(frame.width);
  picture.iPicHeight = static_cast<int>(frame.height);
  picture.iStride[0] = static_cast<int>(frame.width);
  picture.iStride[1] = picture.iStride[2] = static_cast<int>(frame.width / 2);
  // OpenH264 reads the planes only.
  picture.pData[0] = const_cast<unsigned char *>(frame.y.data());
  picture.pData[1] = const_cast<unsigned char *>(frame.u.data());
  picture.pData[2] = const_cast<unsigned char *>(frame.v.data());
  picture.uiTimeStamp = static_cast<long long>(timestamp_ms);
  SFrameBSInfo info{};
  if (impl_->encoder->EncodeFrame(&picture, &info) != cmResultSuccess)
    throw std::runtime_error("H.264 encoding failed");
  AccessUnit unit;
  if (info.eFrameType == videoFrameTypeSkip || info.eFrameType == videoFrameTypeInvalid) return unit;
  for (int layer_index = 0; layer_index < info.iLayerNum; ++layer_index) {
    const auto &layer = info.sLayerInfo[layer_index];
    const std::uint8_t *cursor = layer.pBsBuf;
    for (int nal_index = 0; nal_index < layer.iNalCount; ++nal_index) {
      const auto length = static_cast<std::size_t>(layer.pNalLengthInByte[nal_index]);
      const auto skip = start_code_length(cursor, length);
      if (!skip || skip >= length) throw std::runtime_error("H.264 encoder output without a start code");
      unit.emplace_back(cursor + skip, cursor + length);
      cursor += length;
    }
  }
  return unit;
}

struct Decoder::Impl {
  ISVCDecoder *decoder = nullptr;

  ~Impl() {
    if (decoder) {
      decoder->Uninitialize();
      WelsDestroyDecoder(decoder);
    }
  }
};

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.1: opens an OpenH264 decoder for an AVC bitstream, error concealment off.
Decoder::Decoder() : impl_(std::make_unique<Impl>()) {
  if (WelsCreateDecoder(&impl_->decoder) || !impl_->decoder) throw std::runtime_error("H.264 decoder unavailable");
  SDecodingParam params{};
  params.sVideoProperty.eVideoBsType = VIDEO_BITSTREAM_AVC;
  params.eEcActiveIdc = ERROR_CON_DISABLE; // a damaged picture is not shown; the next IDR recovers
  if (impl_->decoder->Initialize(&params)) throw std::runtime_error("H.264 decoder configuration refused");
}

//------------------------------------------------------------------------------
// Helper: the OpenH264 decoder is released by Impl.
Decoder::~Decoder() = default;

//------------------------------------------------------------------------------
// Helper: decodes one access unit into an I420 picture, or nothing when no picture is ready or it is damaged.
std::optional<Frame> Decoder::decode(const AccessUnit &unit) {
  std::vector<std::uint8_t> stream;
  for (const auto &nal : unit) {
    if (nal.empty()) throw std::invalid_argument("empty NAL unit");
    stream.insert(stream.end(), {0, 0, 0, 1});
    stream.insert(stream.end(), nal.begin(), nal.end());
  }
  if (stream.empty()) return std::nullopt;
  unsigned char *planes[3] = {};
  SBufferInfo info{};
  const auto state = impl_->decoder->DecodeFrameNoDelay(stream.data(), static_cast<int>(stream.size()), planes, &info);
  if (state != dsErrorFree || info.iBufferStatus != 1) return std::nullopt;
  const auto &buffer = info.UsrData.sSystemBuffer;
  Frame frame{static_cast<unsigned>(buffer.iWidth), static_cast<unsigned>(buffer.iHeight), {}, {}, {}};
  const auto copy = [](const unsigned char *from, int stride, unsigned width, unsigned height,
                       std::vector<std::uint8_t> &to) {
    to.resize(std::size_t(width) * height);
    for (unsigned row = 0; row < height; ++row)
      std::memcpy(to.data() + std::size_t(row) * width, from + std::size_t(row) * stride, width);
  };
  copy(planes[0], buffer.iStride[0], frame.width, frame.height, frame.y);
  copy(planes[1], buffer.iStride[1], frame.width / 2, frame.height / 2, frame.u);
  copy(planes[2], buffer.iStride[1], frame.width / 2, frame.height / 2, frame.v);
  return frame;
}

//------------------------------------------------------------------------------
// RFC 6184 section 6.3 (packetization mode 1): a NAL unit that fits goes in a Single NAL Unit packet
// (section 5.6), a larger one in FU-A fragments (section 5.8); the marker bit is set on the last packet of the
// access unit (section 5.1).
std::vector<Payload> packetize(const AccessUnit &unit, std::size_t max_payload) {
  if (max_payload < 16) throw std::invalid_argument("RTP payload too small for H.264");
  std::vector<Payload> out;
  for (const auto &nal : unit) {
    if (nal.empty() || nal.front() & 0x80U) throw std::invalid_argument("invalid NAL unit");
    if (nal.size() <= max_payload) {
      out.push_back({nal, false}); // Single NAL Unit packet (RFC 6184 section 5.6)
      continue;
    }
    // FU-A (RFC 6184 section 5.8): the indicator keeps F and NRI, the header the type; the NAL
    // header byte itself is not repeated in the fragments.
    const std::uint8_t indicator = static_cast<std::uint8_t>((nal.front() & 0xe0U) | fu_a);
    const std::uint8_t type = nal.front() & 0x1fU;
    for (std::size_t offset = 1; offset < nal.size();) {
      const auto chunk = std::min(max_payload - 2, nal.size() - offset);
      std::uint8_t header = type;
      if (offset == 1) header |= 0x80U;                  // S
      if (offset + chunk == nal.size()) header |= 0x40U; // E
      Payload fragment{{indicator, header}, false};
      fragment.bytes.insert(fragment.bytes.end(), nal.begin() + static_cast<std::ptrdiff_t>(offset),
                            nal.begin() + static_cast<std::ptrdiff_t>(offset + chunk));
      out.push_back(std::move(fragment));
      offset += chunk;
    }
  }
  if (!out.empty()) out.back().marker = true;
  return out;
}

//------------------------------------------------------------------------------
// RFC 6184 section 6.3 (packetization mode 1), receiving side: rebuilds access units from Single NAL Unit
// (section 5.6), STAP-A (section 5.7.1) and FU-A (section 5.8) packets; an access unit with a lost packet is
// dropped and counted.
std::vector<AccessUnit> Depacketizer::push(std::uint16_t sequence, std::uint32_t timestamp, bool marker,
                                           std::span<const std::uint8_t> payload) {
  if (payload.empty() || payload[0] & 0x80U) throw std::invalid_argument("invalid H.264 RTP payload");
  std::vector<AccessUnit> done;
  // A new timestamp starts a new access unit; a previous one without its marker
  // is complete only if nothing was lost (RFC 6184 section 5.1 allows a missing marker).
  if (started_ && timestamp != timestamp_) {
    if (!unit_.empty() && !damaged_ && !in_fragment_)
      done.push_back(std::move(unit_));
    else if (!unit_.empty() || in_fragment_ || damaged_)
      ++lost_;
    unit_.clear();
    fragment_.clear();
    in_fragment_ = damaged_ = false;
  }
  if (started_ && sequence != next_sequence_) {
    // A lost packet damages the access unit it belonged to.
    damaged_ = true;
    fragment_.clear();
    in_fragment_ = false;
  }
  started_ = true;
  next_sequence_ = static_cast<std::uint16_t>(sequence + 1);
  timestamp_ = timestamp;
  const std::uint8_t type = payload[0] & 0x1fU;
  if (type >= 1 && type <= 23) {
    unit_.emplace_back(payload.begin(), payload.end());
  } else if (type == stap_a) {
    for (std::size_t offset = 1; offset < payload.size();) {
      if (offset + 2 > payload.size()) throw std::invalid_argument("truncated STAP-A");
      const std::size_t size = (std::size_t(payload[offset]) << 8) | payload[offset + 1];
      offset += 2;
      if (!size || offset + size > payload.size()) throw std::invalid_argument("invalid STAP-A NAL unit size");
      unit_.emplace_back(payload.begin() + static_cast<std::ptrdiff_t>(offset),
                         payload.begin() + static_cast<std::ptrdiff_t>(offset + size));
      offset += size;
    }
  } else if (type == fu_a) {
    if (payload.size() < 3) throw std::invalid_argument("truncated FU-A");
    const bool start = payload[1] & 0x80U, end = payload[1] & 0x40U;
    if (start && end) throw std::invalid_argument("FU-A with both start and end");
    if (start) {
      fragment_ = {static_cast<std::uint8_t>((payload[0] & 0xe0U) | (payload[1] & 0x1fU))};
      in_fragment_ = true;
    } else if (!in_fragment_) {
      damaged_ = true; // a continuation whose start was lost
    }
    if (in_fragment_) fragment_.insert(fragment_.end(), payload.begin() + 2, payload.end());
    if (end && in_fragment_) {
      unit_.push_back(std::move(fragment_));
      fragment_.clear();
      in_fragment_ = false;
    }
  } else {
    throw std::invalid_argument("H.264 RTP packet type not allowed in packetization mode 1");
  }
  if (marker) {
    if (!damaged_ && !in_fragment_ && !unit_.empty())
      done.push_back(std::move(unit_));
    else
      ++lost_;
    unit_.clear();
    fragment_.clear();
    in_fragment_ = damaged_ = false;
    started_ = true;
    timestamp_ = timestamp + 1; // the next packet, whatever its timestamp, starts afresh
  }
  return done;
}

} // namespace mcx::video
