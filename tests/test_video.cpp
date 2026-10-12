//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCVideo media: the H.264 encoder and decoder, the RTP payload format (packetization mode 1) and the test pattern.
//
// Specifications: TS 26.281 V19.0.0 (Rel-19), RFC 6184.

#ifdef NDEBUG
#undef NDEBUG
#endif
#include "mcx/video.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <set>
#include <stdexcept>

using namespace mcx::video;

namespace {
//------------------------------------------------------------------------------
// True when the action throws std::invalid_argument (a refused input).
template <typename Action> bool refused(Action action) {
  try {
    action();
  } catch (const std::invalid_argument &) {
    return true;
  }
  return false;
}
} // namespace

//------------------------------------------------------------------------------
// TS 26.281 clause 4.1.1 and clause 4.1.3: H.264 at 240p through RTP; RFC 6184 section 5.7.1 (STAP-A), section 5.8
// (FU-A) and section 6.3 (non-interleaved mode): fragmentation, reassembly, loss and the refused packet types.
int main() {
  // The test pattern differs per index and is deterministic.
  const auto first = test_pattern(320, 240, 0);
  assert(first.y.size() == 320 * 240 && first.u.size() == 160 * 120 && first.v.size() == 160 * 120);
  assert(checksum(first) == checksum(test_pattern(320, 240, 0)));
  assert(checksum(first) != checksum(test_pattern(320, 240, 1)));
  assert(refused([] { (void)test_pattern(321, 240, 0); }));

  // TS 26.281 clause 4.1.1: H.264 at 240p. The first picture is an IDR with SPS and PPS
  // (Constrained Baseline, profile_idc 66, level_idc 31), and a decoder shows each
  // picture at the source size.
  Encoder encoder;
  Decoder decoder, reference;
  std::set<std::uint32_t> sums;
  unsigned decoded = 0, keys = 0;
  for (std::uint32_t index = 0; index < 45; ++index) {
    const auto unit = encoder.encode(test_pattern(320, 240, index), index * 66);
    assert(!unit.empty());
    if (index == 0) {
      assert(nal_type(unit[0]) == 7 && unit[0].size() > 3 && unit[0][1] == 66 && unit[0][3] == 31);
      assert(is_key_frame(unit));
    }
    if (is_key_frame(unit)) ++keys;
    // Through RTP: packetized at a small MTU so that FU-A is used, then reassembled.
    const auto payloads = packetize(unit, 300);
    assert(payloads.back().marker &&
           std::count_if(payloads.begin(), payloads.end(), [](const Payload &payload) { return payload.marker; }) == 1);
    Depacketizer depacketizer;
    std::vector<AccessUnit> units;
    std::uint16_t sequence = 1000;
    for (const auto &payload : payloads)
      for (auto &access_unit : depacketizer.push(sequence++, index * 6000, payload.marker, payload.bytes))
        units.push_back(std::move(access_unit));
    assert(units.size() == 1 && units[0] == unit);
    const auto picture = decoder.decode(units[0]);
    assert(picture && picture->width == 320 && picture->height == 240);
    // What the receiver shows equals what the sender's own decoder reconstructs.
    const auto local = reference.decode(unit);
    assert(local && checksum(*local) == checksum(*picture));
    sums.insert(checksum(*picture));
    ++decoded;
  }
  assert(decoded == 45 && sums.size() > 40);
  assert(keys == 2); // the IDR period is 30 pictures
  encoder.request_key_frame();
  assert(is_key_frame(encoder.encode(test_pattern(320, 240, 45), 3000)));

  // FU-A: start and end bits, the indicator keeps NRI, and the NAL header is rebuilt.
  const Nal big(1000, 0x5a);
  Nal idr = big;
  idr[0] = 0x65;
  const auto fragments = packetize({idr}, 400);
  assert(fragments.size() == 3 && fragments[0].bytes[0] == 0x7c && fragments[0].bytes[1] == 0x85 &&
         fragments[1].bytes[1] == 0x05 && fragments[2].bytes[1] == 0x45 && fragments[2].marker);

  // A lost fragment discards that access unit only; the next one is delivered.
  {
    Depacketizer depacketizer;
    assert(depacketizer.push(1, 100, false, fragments[0].bytes).empty());
    assert(depacketizer.push(3, 100, true, fragments[2].bytes).empty()); // fragment 2 lost
    assert(depacketizer.lost_units() == 1);
    const Nal small{0x41, 1, 2, 3};
    const auto next = depacketizer.push(4, 200, true, small);
    assert(next.size() == 1 && next[0] == AccessUnit{small});
  }
  // STAP-A (RFC 6184 section 5.7.1) carries several NAL units.
  {
    Depacketizer depacketizer;
    const std::vector<std::uint8_t> stap{0x78, 0, 2, 0x67, 0x42, 0, 3, 0x68, 0xce, 0x38};
    const auto units = depacketizer.push(7, 300, true, stap);
    assert(units.size() == 1 && units[0].size() == 2 && units[0][0] == Nal({0x67, 0x42}) &&
           units[0][1] == Nal({0x68, 0xce, 0x38}));
  }
  // An access unit without its marker ends at the next timestamp.
  {
    Depacketizer depacketizer;
    const Nal nine{0x41, 9}, eight{0x41, 8};
    assert(depacketizer.push(1, 100, false, nine).empty());
    const auto units = depacketizer.push(2, 200, true, eight);
    assert(units.size() == 2 && units[0] == AccessUnit{nine} && units[1] == AccessUnit{eight});
  }
  // Mode 1 excludes MTAP and FU-B; the forbidden bit and truncated packets are refused.
  {
    Depacketizer depacketizer;
    const auto mtap = std::vector<std::uint8_t>{0x1a, 0, 0, 0};
    assert(refused([&] { (void)depacketizer.push(1, 1, true, mtap); })); // MTAP16
    const auto fu_b = std::vector<std::uint8_t>{0x1d, 0x85, 1};
    assert(refused([&] { (void)depacketizer.push(2, 1, true, fu_b); })); // FU-B
    const auto forbidden = std::vector<std::uint8_t>{0xc1, 1};
    assert(refused([&] { (void)depacketizer.push(3, 1, true, forbidden); })); // F bit
    const auto stap = std::vector<std::uint8_t>{0x78, 0, 9, 1};
    assert(refused([&] { (void)depacketizer.push(4, 1, true, stap); })); // STAP-A size
    const auto both = std::vector<std::uint8_t>{0x7c, 0xc5, 1};
    assert(refused([&] { (void)depacketizer.push(5, 1, true, both); })); // FU-A S and E
  }
  const AccessUnit one{Nal{0x41}};
  assert(refused([&] { (void)packetize(one, 8); }));
  std::cout << "video tests passed\n";
}
