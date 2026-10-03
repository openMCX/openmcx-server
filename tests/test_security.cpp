// Media security: MIKEY key derivation of the SRTP and SRTCP master keys from the GMK, PCK and CSK, and SRTP and
// SRTCP protection and replay protection with those keys (TS 33.180 clauses 7.4, 7.5, 9.4 and annexes E, F).
//
// Specifications: TS 33.180 V19.4.0 (Rel-19); RFC 3830, RFC 6043, RFC 3711, RFC 4771.
#include "mcx/security.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// Fails the test with the message why when the condition yes does not hold.
void check(bool yes, const char *why) {
  if (!yes) throw std::runtime_error(why);
}

//------------------------------------------------------------------------------
// Checks that the action throws: an invalid, tampered or replayed packet must be refused.
template <class Action> void rejects(Action action) {
  bool threw = false;
  try {
    action();
  } catch (const std::exception &) {
    threw = true;
  }
  check(threw, "invalid/replayed packet accepted");
}

//------------------------------------------------------------------------------
// Decodes a string of hexadecimal digit pairs into bytes.
Bytes hex(const char *text) {
  Bytes bytes;
  while (*text) {
    unsigned value;
    if (sscanf(text, "%2x", &value) != 1) throw std::runtime_error("hex");
    bytes.push_back(value);
    text += 2;
  }
  return bytes;
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 7.4.1, 7.4.2 and 9.4.6: the MIKEY PRF (RFC 6043 section 6.1) and the SRTP and SRTCP master
// key and salt derived from the PCK, GMK and CSK with the CS-ID of TS 33.180 table E.1.3-1, against known answers;
// then SRTP and SRTCP protection (TS 33.180 clauses 7.5.2 and 9.4.7): the MKI position, AEAD tag, ROC
// (RFC 4771), tamper, replay, wrong-key and wrong-direction rejection.
int main() {
  try {
    // Published IETF TLS WG P_SHA256 vector, also maintained in Botan:
    // https://github.com/randombit/botan/blob/master/src/tests/data/kdf/tls_prf.vec
    // With a <=256-bit secret this is exactly RFC6043's MIKEY PRF expansion.
    check(
        mcx::mikey_prf(hex("9bbe436ba940f017b17652849a71db35"),
                       hex("74657374206c6162656ca0ba9f936cda311827a6f796ffd5198c"), 100) ==
            hex("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022"
                "f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"),
        "published P_SHA256 expansion vector");
    const auto key = hex("000102030405060708090a0b0c0d0e0f"), random = hex("101112131415161718191a1b1c1d1e1f");
    // TS 33.180 clause 7.4.2 and annex E.2.2 (CS-ID 4), independently calculated with Python hmac: RFC 3830
    // sections 4.1.2 and 4.1.3 with RFC 6043 section 6.1.
    auto group = mcx::derive_group_security(key, random, 0x00112233, 0x01234567);
    check(Bytes(group.master_key_salt.begin(), group.master_key_salt.end()) ==
              hex("18a5a1722f04f99ff70fe6dd335e4d253aedc785703ef6cc1a852fb1"),
          "MIKEY key/salt known answer");
    // TS 33.180 clause 7.4.2: the MKI is GMK-ID || GUK-ID and the ROC is transmitted.
    check(group.mki == hex("0011223301234567") && group.transmit_roc, "group profile");
    // TS 33.180 clause 9.4.6: the MKI is the 32-bit key identifier, without ROC.
    auto floor = mcx::derive_floor_security(key, random, 0x20000001);
    check(floor.mki == hex("20000001") && !floor.transmit_roc, "floor profile");
    // TS 33.180 annex F.1.3: the User Salt for GUK-ID generation.
    check(mcx::derive_guk_id(key, 0x00112233, "sip:alice@example.org") == 0x027cef1b,
          "Annex F sender user salt known answer");
    // TS 33.180 clause 7.4.1 and annex E.3.2, independently calculated as above: CS-ID 0 from the
    // initiator, 1 from the receiver; MKI is the PCK-ID and no ROC is transmitted.
    auto initiator = mcx::derive_private_security(key, random, 0x10000001, true);
    auto receiver = mcx::derive_private_security(key, random, 0x10000001, false);
    check(Bytes(initiator.master_key_salt.begin(), initiator.master_key_salt.end()) ==
              hex("1304a8afefd01e46077cb28fc5a4990b31890b87e3fc8b3529782403"),
          "PCK initiator key/salt known answer");
    check(Bytes(receiver.master_key_salt.begin(), receiver.master_key_salt.end()) ==
              hex("b28a66353a8d9ecbf106d753438f54541c95f2d87731d7efa53108d9"),
          "PCK receiver key/salt known answer");
    check(initiator.mki == hex("10000001") && initiator.media && !initiator.transmit_roc, "PCK profile");
    // TS 33.180 clause 7.4.1: the PCK-ID has the purpose tag '1'; another key identifier is refused.
    rejects([&] { mcx::derive_private_security(key, random, 0x20000001, true); });
    // TS 33.180 table E.1.3-1, independently calculated as above: MCVideo uses CS-ID 5
    // for the group call, 2 and 3 for the private call, and 8 for CSK SRTCP.
    auto video_group = mcx::derive_group_security(key, random, 0x00112233, 0x01234567, true);
    check(Bytes(video_group.master_key_salt.begin(), video_group.master_key_salt.end()) ==
              hex("203fa563df0d041fbe68280782286933a7a0e72a464284bec66e6e74"),
          "MCVideo GMK key/salt known answer");
    auto video_initiator = mcx::derive_private_security(key, random, 0x10000001, true, true);
    auto video_receiver = mcx::derive_private_security(key, random, 0x10000001, false, true);
    check(Bytes(video_initiator.master_key_salt.begin(), video_initiator.master_key_salt.end()) ==
              hex("6b488f6975ebe3bef880c161b58871f385f6d3b4cd08ed7d02ff1cc6"),
          "MCVideo PCK initiator known answer");
    check(Bytes(video_receiver.master_key_salt.begin(), video_receiver.master_key_salt.end()) ==
              hex("2238a6bb9f615aca5eaf957626a9332a2c300b21753a2cec34c5bff0"),
          "MCVideo PCK receiver known answer");
    auto video_floor = mcx::derive_floor_security(key, random, 0x20000001, true);
    check(Bytes(floor.master_key_salt.begin(), floor.master_key_salt.end()) ==
              hex("cc8b19f831d29ca809e4571918e91efa043ac01787e3e6661a0a63b4"),
          "CSK SRTCP known answer for MCPTT (CS-ID 6)");
    check(Bytes(video_floor.master_key_salt.begin(), video_floor.master_key_salt.end()) ==
              hex("51347d6b7ad6c6417991967bc7a571f0615770888a6f4e7af08a037a"),
          "CSK SRTCP known answer for MCVideo (CS-ID 8)");
    // MuSiK SRTCP (CS-ID 7 and 9, TS 33.180 clause 9.2.2) is not implemented (no MBMS), so it has no known answer.
    // TS 33.180 clause 7.5.2: PCK SRTP, MKI last, no ROC; the other direction's key and a replay are refused.
    {
      mcx::SecureStream ptx(initiator, 0x12345678), prx(initiator, 0x12345678), wrong_direction(receiver, 0x12345678);
      auto packet = hex("8060000100000140123456780102030405060708");
      auto secured = ptx.protect_rtp(packet);
      check(secured.size() == packet.size() + 20, "PCK SRTP carries GCM tag and MKI without ROC");
      check(std::equal(initiator.mki.begin(), initiator.mki.end(), secured.end() - 4), "PCK MKI wire position");
      rejects([&] { wrong_direction.unprotect_rtp(secured); });
      check(prx.unprotect_rtp(secured) == packet, "PCK SRTP recovery");
      rejects([&] { prx.unprotect_rtp(secured); });
    }
    // TS 33.180 clause 7.5.2: GMK SRTP with the 16-octet AEAD tag of annex E.2.2, the 64-bit MKI and the ROC
    // (RFC 4771); a changed payload, ROC or MKI, a replay and a wrong key are refused.
    mcx::SecureStream tx(group, 0x12345678), rx(group, 0x12345678);
    auto rtp = hex("8060000100000140123456780102030405060708");
    auto encrypted = tx.protect_rtp(rtp);
    check(encrypted.size() == rtp.size() + 28 && encrypted != rtp, "GCM tag MKI and ROC overhead");
    check(std::equal(group.mki.begin(), group.mki.end(), encrypted.end() - 12), "GCM MKI wire position");
    auto tampered = encrypted;
    tampered[15] ^= 1;
    rejects([&] { rx.unprotect_rtp(tampered); });
    tampered = encrypted;
    tampered.back() = 99;
    rejects([&] { rx.unprotect_rtp(tampered); });
    tampered = encrypted;
    tampered[tampered.size() - 5] ^= 1;
    rejects([&] { rx.unprotect_rtp(tampered); });
    check(rx.unprotect_rtp(encrypted) == rtp, "authenticated RTP recovery after failed attempts");
    rejects([&] { rx.unprotect_rtp(encrypted); });
    auto wrong = group;
    wrong.master_key_salt[0] ^= 1;
    mcx::SecureStream other(wrong, 0x12345678);
    rejects([&] { other.unprotect_rtp(encrypted); });
    // TS 33.180 clauses 9.4.7 and 9.4.8: CSK SRTCP (RFC 3711 section 3.4) with the SRTCP index and the MKI.
    mcx::SecureStream ftx(floor, 0x12345678), frx(floor, 0x12345678);
    auto rtcp = hex("80cc0004123456784d4350540102030405060708");
    auto secured = ftx.protect_rtcp(rtcp);
    check(secured.size() == rtcp.size() + 24 && secured != rtcp, "SRTCP GCM index and MKI overhead");
    tampered = secured;
    tampered[10] ^= 1;
    rejects([&] { frx.unprotect_rtcp(tampered); });
    check(frx.unprotect_rtcp(secured) == rtcp, "SRTCP recovery");
    rejects([&] { frx.unprotect_rtcp(secured); });
    rejects([&] { frx.unprotect_rtcp(rtcp); });
    rejects([&] { ftx.protect_rtp(rtp); }); // CSK cannot protect SRTP (TS 33.180 annex E.4.2).
    // Sequence wrap and late entry use the authenticated transmitted ROC (TS 33.180 clause 7.5.2, RFC 4771).
    mcx::SecureStream wrap_tx(group, 0x12345678), wrap_rx(group, 0x12345678), late_rx(group, 0x12345678);
    auto before = rtp;
    before[2] = 0xff;
    before[3] = 0xff;
    auto before_wire = wrap_tx.protect_rtp(before);
    check(wrap_rx.unprotect_rtp(before_wire) == before, "before rollover");
    auto after = rtp;
    after[2] = 0;
    after[3] = 0;
    auto after_wire = wrap_tx.protect_rtp(after);
    check(after_wire.back() == 1, "ROC increments");
    check(wrap_rx.unprotect_rtp(after_wire) == after, "rollover authentication");
    check(late_rx.unprotect_rtp(after_wire) == after, "late join authenticates carried ROC");
    rejects([&] { wrap_rx.unprotect_rtp(before_wire); });
    rejects([&] { late_rx.unprotect_rtp(after_wire); });
    auto old_outbound = rtp;
    old_outbound[2] = 0xff;
    old_outbound[3] = 0xfe;
    rejects([&] { wrap_tx.protect_rtp(old_outbound); }); // Prevent wrong carried ROC on reordered send.
    // An invalid compound RTCP length must never be encrypted as valid signalling.
    auto malformed = rtcp;
    malformed[3] = 99;
    rejects([&] { ftx.protect_rtcp(malformed); });
    std::cout << "security tests passed\n";
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
