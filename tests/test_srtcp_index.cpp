//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The SRTCP index of the first packets a sender protects (RFC 3711 section 3.4), with the libsrtp the build links:
// "The SRTCP index MUST be set to zero before the first SRTCP packet is sent, and MUST be incremented by one, modulo
// 2^31, after each SRTCP packet is sent." Without OpenMCX's libsrtp patch (dependencies/libsrtp; an older development
// image) the test is skipped (exit 77), as libsrtp 2.8.1 starts at 1.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19); RFC 3711, RFC 7714.
#include "mcx/security.hpp"

#include <srtp2/srtp.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// Fails the test with the message why when the condition yes does not hold.
void check(bool yes, const char *why) {
  if (!yes) throw std::runtime_error(why);
}

//------------------------------------------------------------------------------
// RFC 7714 section 9 (and RFC 3711 section 3.4): the 32-bit E flag and SRTCP index word of an AEAD SRTCP packet,
// which precedes the MKI (here 4 octets, TS 33.180 clause 9.4.6) at the end of the packet.
std::uint32_t index_word(const Bytes &packet, std::size_t mki_length) {
  const auto at = packet.size() - mki_length - 4;
  return (std::uint32_t(packet[at]) << 24) | (std::uint32_t(packet[at + 1]) << 16) |
         (std::uint32_t(packet[at + 2]) << 8) | packet[at + 3];
}

int main() {
#ifndef SRTP_OPENMCX_SRTCP_INDEX_ZERO
  std::cout << "skipped: libsrtp without OpenMCX's patch (dependencies/libsrtp), its first SRTCP index is 1\n";
  return 77;
#else
  try {
    const Bytes key{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
        random{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    // TS 33.180 clause 9.4.6: floor control SRTCP under the CSK, MKI = CSK-ID (4 octets).
    const auto floor = mcx::derive_floor_security(key, random, 0x20000001);
    mcx::SecureStream sender(floor, 0x12345678), receiver(floor, 0x12345678);
    // An RTCP APP packet (RFC 3550 section 6.7, TS 24.380 clause 8.1.2) of five words.
    const Bytes rtcp{0x80, 0xcc, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78, 0x4d, 0x43,
                     0x50, 0x54, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    const auto first = sender.protect_rtcp(rtcp), second = sender.protect_rtcp(rtcp);
    // The E flag (encrypted, RFC 7714 section 9.1) and the index: 0 for the first packet, then 1.
    check(index_word(first, floor.mki.size()) == 0x80000000u, "first SRTCP packet must carry index 0");
    check(index_word(second, floor.mki.size()) == 0x80000001u, "second SRTCP packet must carry index 1");
    // A receiver accepts index 0 (its replay window starts there) and the packets in order.
    check(receiver.unprotect_rtcp(first) == rtcp, "SRTCP index 0 accepted");
    check(receiver.unprotect_rtcp(second) == rtcp, "SRTCP index 1 accepted");
    std::cout << "srtcp index tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
#endif
}
