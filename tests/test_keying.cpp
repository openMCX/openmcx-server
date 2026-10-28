//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MIKEY-SAKKE key distribution and MCData payload security: the ECCSI and SAKKE primitives, the MIKEY-SAKKE UID,
// I_MESSAGE creation and opening for GMK and PCK, MCData protected and authenticated payloads, and keys across KMSs.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19); RFC 6507
// (ECCSI), RFC 6508 (SAKKE), RFC 6509 (MIKEY-SAKKE).

#include "keying_vectors.hpp"
#include "mcx/keying.hpp"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/eccsi.h>
#include <wolfssl/wolfcrypt/sakke.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>

//------------------------------------------------------------------------------
// Throws the text when the condition does not hold.
void check(bool condition, const char *text) {
  if (!condition) throw std::runtime_error(text);
}

//------------------------------------------------------------------------------
// Throws the text unless the action throws.
template <class Action> void rejected(Action &&action, const char *text) {
  try {
    action();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(text);
}

//------------------------------------------------------------------------------
// Helper: octets from hexadecimal text.
std::vector<unsigned char> unhex(std::string_view text) {
  std::vector<unsigned char> out;
  for (std::size_t at = 0; at + 1 < text.size(); at += 2)
    out.push_back(static_cast<unsigned char>(std::stoi(std::string(text.substr(at, 2)), nullptr, 16)));
  return out;
}

//------------------------------------------------------------------------------
// Helper: AES-GCM encryption with OpenSSL (any IV length), the ciphertext followed by the 16-octet tag.
std::vector<unsigned char> gcm_seal(const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv,
                                    const std::vector<unsigned char> &aad, const std::vector<unsigned char> &plain) {
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  int length = 0;
  std::vector<unsigned char> out(plain.size() + 16);
  check(EVP_EncryptInit_ex(ctx.get(), key.size() == 32 ? EVP_aes_256_gcm() : EVP_aes_128_gcm(), nullptr, nullptr,
                           nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) == 1 &&
            (aad.empty() || EVP_EncryptUpdate(ctx.get(), nullptr, &length, aad.data(), aad.size()) == 1) &&
            (plain.empty() || EVP_EncryptUpdate(ctx.get(), out.data(), &length, plain.data(), plain.size()) == 1) &&
            EVP_EncryptFinal_ex(ctx.get(), out.data() + plain.size(), &length) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, out.data() + plain.size()) == 1,
        "AES-GCM test encryption");
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 8.5.4.2 (table 8.5.4.2-2) and annex F.1.5: DP_AES_256_GCM. The AEAD_AES_256_GCM primitive against
// McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)", test cases 13 to 18 (case 18: a 60-octet IV, the
// GHASH path of J0 that the 16-octet IV of table 8.5.4.1-1 takes); the 256-bit DPCK is the entire KDF output under a
// CSK (checked by decrypting with it independently); DP_AES_256_GCM under a PCK or GMK, without the profile's code,
// or outside CSK signalling is refused.
void aes_256_gcm_payloads() {
  using namespace mcx::keying;
  const auto zero = unhex(std::string(64, '0'));
  check(gcm_seal(zero, unhex(std::string(24, '0')), {}, {}) == unhex("530f8afbc74536b9a963b4f1c4cb738b"),
        "GCM test case 13");
  check(gcm_seal(zero, unhex(std::string(24, '0')), {}, unhex(std::string(32, '0'))) ==
            unhex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
        "GCM test case 14");
  const auto key = unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
  const auto plain = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e24"
                           "49a6b525b16aedf5aa0de657ba637b391aafd255");
  const auto aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
  const auto short_plain = std::vector<unsigned char>(plain.begin(), plain.begin() + 60);
  check(gcm_seal(key, unhex("cafebabefacedbaddecaf888"), {}, plain) ==
            unhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
                  "c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c"),
        "GCM test case 15");
  check(gcm_seal(key, unhex("cafebabefacedbaddecaf888"), aad, short_plain) ==
            unhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
                  "c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b"),
        "GCM test case 16");
  check(gcm_seal(key, unhex("cafebabefacedbad"), aad, short_plain) ==
            unhex("c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f78"
                  "62ac430e64abe499f47c9b1f3a337dbf46a792c45e454913fe2ea8f2"),
        "GCM test case 17");
  check(gcm_seal(key,
                 unhex("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e242"
                       "9a6b525416aedbf5a0de6a57a637b39b"),
                 aad, short_plain) ==
            unhex("5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cde"
                  "a2418997200ef82e44ae7e3fa44a8266ee1c8eb0c8b5d4cf5ae9f19a"),
        "GCM test case 18");

  // An MCData signalling message under the CSK (CSK-ID purpose tag 2), DP_AES_256_GCM with the profile's code 2.
  std::array<unsigned char, 16> csk{};
  csk.fill(0x2c);
  const std::uint32_t csk_id = 0x20001234;
  KeyParameterWireProfile profile{10, 1, 0x79, 0x78};
  KeyParameterWireProfile profile_256{10, 1, 0x79, 0x78, 2};
  ProtectedPayload message{0x45, 1790000000, 9, 0, csk_id, {0x05, 0x01, 0x02, 0x03}};
  message.algorithm = PayloadAlgorithm::aes_256_gcm;
  rejected([&] { seal_payload(message, csk, profile); }, "DP_AES_256_GCM sent without a code in the profile");
  const auto wire = seal_payload(message, csk, profile_256);
  check(wire[11] == 2 && wire.size() == 1 + 5 + 4 + 1 + 1 + 16 + 4 + 3 + message.plain.size() + 16,
        "DP_AES_256_GCM layout: the profile's code, the 16-octet IV");
  const auto opened = open_payload(wire, csk, profile_256, true);
  check(opened.plain == message.plain && opened.algorithm == PayloadAlgorithm::aes_256_gcm,
        "DP_AES_256_GCM round trip under the CSK");
  rejected([&] { open_payload(wire, csk, profile_256); }, "DP_AES_256_GCM accepted outside CSK signalling");
  rejected([&] { open_payload(wire, csk, profile, true); }, "DP_AES_256_GCM accepted without the profile's code");
  // Annex F.1.5: the DPCK is the entire KDF output (TS 33.220 annex B: HMAC-SHA-256 over FC || P0 || L0), checked by
  // sealing the same message independently with it.
  const std::vector<unsigned char> input{0x53, 0x20, 0x00, 0x12, 0x34, 0x00, 0x04};
  std::vector<unsigned char> dpck(32);
  unsigned size = 32;
  check(HMAC(EVP_sha256(), csk.data(), csk.size(), input.data(), input.size(), dpck.data(), &size) != nullptr,
        "KDF");
  const std::vector<unsigned char> associated(wire.begin(), wire.begin() + 32),
      iv(wire.begin() + 12, wire.begin() + 28);
  const std::vector<unsigned char> expected = gcm_seal(dpck, iv, associated, message.plain);
  check(std::equal(expected.begin(), expected.end(), wire.begin() + 35) && wire.size() == 35 + expected.size(),
        "DP_AES_256_GCM DPCK is the entire KDF output");
  // The 128-bit DPCK of DP_AES_128_GCM is its 128 least significant bits.
  message.algorithm = PayloadAlgorithm::aes_128_gcm;
  const auto wire_128 = seal_payload(message, csk, profile_256);
  check(wire_128[11] == 1 && open_payload(wire_128, csk, profile_256, true).algorithm == PayloadAlgorithm::aes_128_gcm,
        "DP_AES_128_GCM under the CSK still the default");
  const std::vector<unsigned char> associated_128(wire_128.begin(), wire_128.begin() + 32),
      iv_128(wire_128.begin() + 12, wire_128.begin() + 28), dpck_128(dpck.begin() + 16, dpck.end());
  const auto expected_128 = gcm_seal(dpck_128, iv_128, associated_128, message.plain);
  check(std::equal(expected_128.begin(), expected_128.end(), wire_128.begin() + 35),
        "DP_AES_128_GCM DPCK is the 128 least significant bits");
  // E.1.1: a PCK or GMK is 16 octets, so DP_AES_256_GCM has no DPCK under them: refused both ways.
  auto under_pck = message;
  under_pck.algorithm = PayloadAlgorithm::aes_256_gcm;
  under_pck.dppk_id = 0x10001234;
  rejected([&] { seal_payload(under_pck, csk, profile_256); }, "DP_AES_256_GCM sent under a PCK");
  under_pck.dppk_id = 0x00001234;
  rejected([&] { seal_payload(under_pck, csk, profile_256); }, "DP_AES_256_GCM sent under a GMK");
  auto relabelled = wire;
  relabelled[28] = 0x10; // DPPK-ID 0x10001234, a PCK-ID
  rejected([&] { open_payload(relabelled, csk, profile_256, true); }, "DP_AES_256_GCM accepted under a PCK");
  auto tampered = wire;
  tampered.back() ^= 1;
  rejected([&] { open_payload(tampered, csk, profile_256, true); }, "tampered DP_AES_256_GCM accepted");
  auto unknown = wire;
  unknown[11] = 3;
  rejected([&] { open_payload(unknown, csk, profile_256, true); }, "unknown payload algorithm accepted");
}

//------------------------------------------------------------------------------
// RFC 6507 appendix A: the ECCSI test vector verifies; RFC 6508 appendix A: the SAKKE encapsulation
// of the test SSV matches the vector.
void primitive_vectors() {
  using namespace keying_vectors;
  EccsiKey signer{};
  check(wc_InitEccsiKey(&signer, nullptr, INVALID_DEVID) == 0, "initialize ECCSI vector");
  auto *pvt = wc_ecc_new_point();
  check(pvt != nullptr, "allocate vector PVT");
  check(wc_ImportEccsiPublicKey(&signer, eccsi_pubData.data(), eccsi_pubData.size(), 0) == 0, "RFC6507 KPAK");
  check(wc_DecodeEccsiPvtFromSig(&signer, eccsi_sig.data(), eccsi_sig.size(), pvt) == 0, "RFC6507 signature PVT");
  std::array<unsigned char, 32> hash{};
  byte hash_size = hash.size();
  check(wc_HashEccsiId(&signer, WC_HASH_TYPE_SHA256, eccsi_id.data(), eccsi_id.size(), pvt, hash.data(), &hash_size) ==
            0,
        "RFC6507 HS");
  check(wc_SetEccsiHash(&signer, hash.data(), hash_size) == 0, "set RFC6507 HS");
  int valid = 0;
  check(wc_VerifyEccsiHash(&signer, WC_HASH_TYPE_SHA256, eccsi_msg.data(), eccsi_msg.size(), eccsi_sig.data(),
                           eccsi_sig.size(), &valid) == 0 &&
            valid == 1,
        "RFC6507 Appendix A signature");
  wc_ecc_del_point(pvt);
  wc_FreeEccsiKey(&signer);
  SakkeKey recipient{};
  check(wc_InitSakkeKey(&recipient, nullptr, INVALID_DEVID) == 0, "initialize SAKKE vector");
  check(wc_ImportSakkePublicKey(&recipient, sakke_pubData.data(), sakke_pubData.size(), 0) == 0, "RFC6508 public key");
  check(wc_SetSakkeIdentity(&recipient, sakke_id.data(), sakke_id.size()) == 0, "RFC6508 identity");
  auto ssv = sakke_ssv;
  std::array<unsigned char, 257> auth{};
  word16 size = auth.size();
  check(wc_MakeSakkeEncapsulatedSSV(&recipient, WC_HASH_TYPE_SHA256, ssv.data(), ssv.size(), auth.data(), &size) == 0,
        "RFC6508 encapsulation");
  check(auth == sakke_expAuth && ssv == sakke_encSsv, "RFC6508 Appendix A encapsulation vector");
  wc_FreeSakkeKey(&recipient);
}

//------------------------------------------------------------------------------
// RFC 3830 section 5.2: re-signs an I_MESSAGE whose signed part (everything before the signature) was changed.
mcx::keying::Bytes resign(const mcx::keying::PublicParameters &pub, const mcx::keying::IdentityKeys &sender,
                          std::uint64_t time, const mcx::keying::Bytes &message,
                          const std::function<void(mcx::keying::Bytes &)> &change) {
  mcx::keying::Bytes body(message.begin(), message.end() - 129);
  change(body);
  const auto signature = mcx::keying::sign(pub, sender, time, body);
  body.insert(body.end(), signature.begin(), signature.end());
  return body;
}

//------------------------------------------------------------------------------
// RFC 3830 section 6.15: a general extension payload with its next payload, type and data.
mcx::keying::Bytes extension(byte next, byte type, const mcx::keying::Bytes &data) {
  mcx::keying::Bytes out{next, type, static_cast<byte>(data.size() >> 8), static_cast<byte>(data.size())};
  out.insert(out.end(), data.begin(), data.end());
  return out;
}

//------------------------------------------------------------------------------
// Helper: adds chained general extension payloads (the last with next payload SIGN, 4) after the SAKKE payload of an
// I_MESSAGE body that has none (the SAKKE payload, 5 + 273 octets, ends before the 2-octet SIGN header).
void add_extensions(mcx::keying::Bytes &body, const mcx::keying::Bytes &extensions) {
  body[body.size() - 2 - 5 - 273] = 21;
  body.insert(body.end() - 2, extensions.begin(), extensions.end());
}

//------------------------------------------------------------------------------
// TS 33.180 table E.6.1-1: a Key Parameters payload (IEI 0x79): Key Type, Status 1, Activation and Expiry 0, Text
// "k", the MC Group IDs when given, then the extra (Reserved) octets.
mcx::keying::Bytes key_parameters(byte type, const std::vector<std::string> *groups, const mcx::keying::Bytes &extra) {
  mcx::keying::Bytes content{type, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 'k'};
  if (groups) {
    mcx::keying::Bytes list{static_cast<byte>(groups->size())};
    for (const auto &group : *groups) {
      list.insert(list.end(), {0x7b, 0, static_cast<byte>(group.size())});
      list.insert(list.end(), group.begin(), group.end());
    }
    content.insert(content.end(), {0, static_cast<byte>(list.size())});
    content.insert(content.end(), list.begin(), list.end());
  }
  content.insert(content.end(), extra.begin(), extra.end());
  mcx::keying::Bytes out{0x79, static_cast<byte>(content.size() >> 8), static_cast<byte>(content.size())};
  out.insert(out.end(), content.begin(), content.end());
  return out;
}

//------------------------------------------------------------------------------
// RFC 5905 section 6 (NTP eras), RFC 6509 section 4.1 (V ignored), RFC 3830 sections 6.11 (RAND length) and 6.15
// (general extensions), TS 33.180 annexes E.1.2, E.5 and E.6 (SAKKE-to-self, every key type, Reserved IEs, the
// Protected Payload Date and Time not compared): the I_MESSAGE readers accept what the specifications allow.
void relaxed_readers() {
  using namespace mcx::keying;
  // RFC 5905 section 6: the era nearest to the local clock.
  check(ntp_from_wire(0xfffffff6, (1ULL << 32) + 10) == 0xfffffff6, "era 0 timestamp read in era 1");
  check(ntp_from_wire(5, 0xfffffff0) == (1ULL << 32) + 5, "era 1 timestamp read in era 0");
  check(ntp_from_wire(0xd6b43232, 0xd6b43232 + 7) == 0xd6b43232, "TS 33.180 D.2.4 example in era 0");
  check(ntp_from_wire(10, (2ULL << 32) + 20) == (2ULL << 32) + 10, "era 2");

  const std::uint64_t after = (1ULL << 32) + 10; // 2036-02-07 06:28:26 UTC
  Period period{"kms.example.org", 2592000, 0};
  auto authority = create_authority(period);
  const auto &pub = authority.public_parameters;
  auto alice = issue(authority, "sip:alice@example.org", after);
  auto bob = issue(authority, "sip:bob@example.org", after);
  check(uid(alice.uri, period, after).size() == 44, "UID with TIME after 2036");
  KeyMessage pck;
  pck.key.fill(0x31);
  pck.csb_id = 0x10000042;
  // One I_MESSAGE across the era boundary: sent at 2^32 - 10, received at 2^32 + 10.
  pck.ntp_seconds = (1ULL << 32) - 10;
  auto crossing = create_mikey(pub, alice, bob.uri, pck);
  check(crossing[12] == 0xff && crossing[13] == 0xff && crossing[14] == 0xff && crossing[15] == 0xf6,
        "low 32 bits of the NTP seconds on the wire");
  check(open_mikey(pub, bob, alice.uri, crossing, after).ntp_seconds == pck.ntp_seconds, "crossing the era");
  pck.ntp_seconds = (1ULL << 32) + 5;
  auto in_era_1 = create_mikey(pub, alice, bob.uri, pck);
  const auto opened = open_mikey(pub, bob, alice.uri, in_era_1, after);
  check(opened.ntp_seconds == pck.ntp_seconds && opened.key == pck.key, "an I_MESSAGE of era 1");
  rejected([&] { open_mikey(pub, bob, alice.uri, in_era_1, after + 400); }, "stale era 1 I_MESSAGE accepted");

  const auto time = pck.ntp_seconds;
  // RFC 6509 section 4.1: V "MUST be set to '0' and ignored by the Responder".
  auto v_set = resign(pub, alice, time, in_era_1, [](Bytes &body) { body[3] |= 0x80; });
  check(open_mikey(pub, bob, alice.uri, v_set, after).key == pck.key, "V bit ignored");
  auto prf = resign(pub, alice, time, in_era_1, [](Bytes &body) { body[3] = 2; });
  rejected([&] { open_mikey(pub, bob, alice.uri, prf, after); }, "unimplemented PRF accepted");
  check(mikey_csb_id(v_set) == pck.csb_id && mikey_initiator(v_set) == alice.uri, "V bit ignored, unauthenticated");

  // RFC 3830 section 6.11: "RAND len ... SHOULD be at least 16": a longer and a shorter RAND are read; an empty one
  // is refused.
  auto longer = pck;
  longer.random.assign(32, 0x5a);
  auto long_rand = create_mikey(pub, alice, bob.uri, longer);
  check(open_mikey(pub, bob, alice.uri, long_rand, after).random == longer.random, "32-octet RAND");
  check(mikey_receiver(long_rand).first == bob.uri && mikey_initiator_kms(long_rand) == period.kms_uri,
        "32-octet RAND, unauthenticated");
  auto short_rand = resign(pub, alice, time, in_era_1, [](Bytes &body) {
    body[21] = 15;
    body.erase(body.begin() + 22);
  });
  check(open_mikey(pub, bob, alice.uri, short_rand, after).random.size() == 15, "15-octet RAND refused");
  check(mikey_receiver(short_rand).first == bob.uri, "15-octet RAND, unauthenticated");
  auto empty_rand = resign(pub, alice, time, in_era_1, [](Bytes &body) {
    body[21] = 0;
    body.erase(body.begin() + 22, body.begin() + 38);
  });
  rejected([&] { open_mikey(pub, bob, alice.uri, empty_rand, after); }, "empty RAND accepted");

  // TS 33.180 annex E.5 and RFC 3830 table 6.15: SAKKE-to-self (6) and a Vendor ID (0) are skipped; an unassigned
  // type is refused.
  const Bytes self(278, 0);
  auto with_self = resign(pub, alice, time, in_era_1, [&](Bytes &body) {
    auto chain = extension(21, 6, self);
    const auto vendor = extension(4, 0, {1, 2, 3});
    chain.insert(chain.end(), vendor.begin(), vendor.end());
    add_extensions(body, chain);
  });
  check(open_mikey(pub, bob, alice.uri, with_self, after).key == pck.key, "SAKKE-to-self and Vendor ID skipped");
  auto unknown = resign(pub, alice, time, in_era_1, [&](Bytes &body) { add_extensions(body, extension(4, 9, {1})); });
  rejected([&] { open_mikey(pub, bob, alice.uri, unknown, after); }, "unassigned general extension accepted");

  // TS 33.180 annex E.6: key parameters in a Protected Payload whose Date and Time, Payload ID and sequence differ
  // from the MIKEY timestamp; a MuSiK with its group and a trailing Reserved IE; a PCK with key parameters.
  const KeyParameterWireProfile profile{10, 1, 0x79, 0x78};
  const auto sealed = [&](const KeyMessage &key, const Bytes &parameters) {
    return seal_payload(ProtectedPayload{10, 12345, 7, 3, key.csb_id, parameters}, key.key, profile);
  };
  auto musik = pck;
  musik.csb_id = 0x60000007;
  const std::vector<std::string> groups{"sip:g@example.org"};
  auto musik_message = resign(pub, alice, time, create_mikey(pub, alice, bob.uri, musik), [&](Bytes &body) {
    auto chain = extension(21, 7, sealed(musik, key_parameters(6, &groups, {0x55, 0, 2, 0xaa, 0xbb})));
    const auto after_self = extension(4, 6, self);
    chain.insert(chain.end(), after_self.begin(), after_self.end());
    add_extensions(body, chain);
  });
  const auto musik_key = open_mikey(pub, bob, alice.uri, musik_message, after, 300, &profile);
  check(musik_key.properties && musik_key.properties->type == 6 && musik_key.properties->groups == groups &&
            musik_key.properties->text == "k",
        "MuSiK key parameters with a Reserved IE, then SAKKE-to-self");
  auto twice = resign(pub, alice, time, create_mikey(pub, alice, bob.uri, musik), [&](Bytes &body) {
    auto chain = extension(21, 7, sealed(musik, key_parameters(6, &groups, {})));
    const auto second = extension(4, 7, sealed(musik, key_parameters(6, &groups, {})));
    chain.insert(chain.end(), second.begin(), second.end());
    add_extensions(body, chain);
  });
  rejected([&] { open_mikey(pub, bob, alice.uri, twice, after, 300, &profile); }, "two key parameters accepted");
  auto pck_parameters = resign(pub, alice, time, in_era_1, [&](Bytes &body) {
    add_extensions(body, extension(4, 7, sealed(pck, key_parameters(1, nullptr, {}))));
  });
  const auto pck_key = open_mikey(pub, bob, alice.uri, pck_parameters, after, 300, &profile);
  check(pck_key.properties && pck_key.properties->type == 1 && pck_key.properties->groups.empty(),
        "PCK with key parameters");
  require_active(pck_key, {}, after - 2208988800ULL);
  auto reserved_type = resign(pub, alice, time, in_era_1, [&](Bytes &body) {
    add_extensions(body, extension(4, 7, sealed(pck, key_parameters(7, nullptr, {}))));
  });
  rejected([&] { open_mikey(pub, bob, alice.uri, reserved_type, after, 300, &profile); }, "reserved key type accepted");
}

//------------------------------------------------------------------------------
// TS 33.180 annex E.6.10 at each use (require_in_use): a CSK or PCK is usable 1 s before its Expiry time and not from
// that time on; Expiry time 0, or no Key Parameters at all, never expires; a revoked key (annex E.6.9) is refused.
void key_in_use() {
  using namespace mcx::keying;
  constexpr std::uint64_t expiry = 2000000000;
  KeyMessage key;
  key.csb_id = 0x20000001;
  key.properties = KeyProperties{2, 1, 0, expiry, "", {}};
  require_in_use(key, expiry - 1);
  rejected([&] { require_in_use(key, expiry); }, "CSK used at its Expiry time");
  key.csb_id = 0x10000001;
  key.properties->type = 1;
  require_in_use(key, expiry - 1);
  rejected([&] { require_in_use(key, expiry + 1); }, "PCK used past its Expiry time");
  key.properties->expiry_unix_seconds = 0;
  require_in_use(key, 4000000000);
  key.properties->status = 0;
  rejected([&] { require_in_use(key, expiry - 1); }, "revoked key used");
  key.properties.reset();
  require_in_use(key, 4000000000);
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.2.1.2: the example MIKEY-SAKKE UID; annex E: MIKEY-SAKKE I_MESSAGEs for a key and for a
// GMK with its annex E.6 parameters, opened only by the right receiver from the right sender while fresh; clause
// 5.2.8: the receiver and its KMS for a KRR; clause 8.5.4: MCData protected payloads and series; clause 8.5.5:
// authenticated payloads; clause 5.2.7: keys between users of different KMSs.
int main() {
  try {
    using namespace mcx::keying;
    primitive_vectors();
    relaxed_readers();
    aes_256_gcm_payloads();
    key_in_use();
    Period period{"kms.example.org", 2592000, 0};
    constexpr std::uint64_t time = 3599719634;
    check(uid("sip:user@example.org", period, time) == "OoH7FMOx0P5DycV3EE1VptgXiL/S8JdDxFV3RqWgNTs=",
          "TS33.180 F.2.1.2 UID vector");
    auto authority = create_authority(period);
    auto alice = issue(authority, "sip:alice@example.org", time);
    auto bob = issue(authority, "sip:bob@example.org", time);
    auto outsider = issue(authority, "sip:outsider@example.org", time);
    const auto &pub = authority.public_parameters;
    validate_identity(pub, alice, time);
    validate_identity(pub, bob, time);
    KeyMessage key;
    key.key.fill(0x42);
    key.random.assign(16, 0x27);
    key.csb_id = 0x02345678;
    key.ntp_seconds = time;
    auto data = create_mikey(pub, alice, bob.uri, key);
    check(data[0] == 1 && data[1] == 26, "MIKEY-SAKKE wire header");
    auto restored = open_mikey(pub, bob, alice.uri, data, time);
    check(restored.key == key.key && restored.random == key.random && restored.csb_id == key.csb_id,
          "ECCSI authenticated SAKKE recipient decrypts shared key");
    // An explicit test profile exercises TS 33.180 annex E.6 cryptography. These values do not
    // assert independent interoperability for the unassigned Key Parameters IEI.
    KeyParameterWireProfile profile{10, 1, 0x79, 0x78};
    key.properties =
        KeyProperties{0, 1, time - 2208988800ULL, time - 2208988800ULL + 60, "test group", {"sip:group@example.org"}};
    rejected([&] { create_mikey(pub, alice, bob.uri, key); }, "missing explicit E.6 wire profile accepted");
    auto group_data = create_mikey(pub, alice, bob.uri, key, &profile);
    auto group_key = open_mikey(pub, bob, alice.uri, group_data, time, 300, &profile);
    check(group_key.properties == key.properties, "encrypted E.6 properties round trip");
    require_active(group_key, "sip:group@example.org", time - 2208988800ULL);
    rejected([&] { require_active(group_key, "sip:other@example.org", time - 2208988800ULL); }, "wrong group accepted");
    rejected([&] { require_active(group_key, "sip:group@example.org", time - 2208988800ULL + 61); },
             "expired GMK accepted");
    group_key.properties->status = 0;
    rejected([&] { require_active(group_key, "sip:group@example.org", time - 2208988800ULL); }, "revoked GMK accepted");
    group_data[group_data.size() - 150] ^= 1;
    rejected([&] { open_mikey(pub, bob, alice.uri, group_data, time, 300, &profile); },
             "tampered key properties accepted");
    // TS 33.180 clause 9.2.2, annex H.3 and table E.6.11-1: an MSCCK (purpose tag and key type 5) and a MuSiK (6, with
    // the MC Group IDs of annex E.6.1 NOTE) distributed by key download; a key type that disagrees is refused.
    for (const std::uint8_t purpose : {std::uint8_t{5}, std::uint8_t{6}}) {
      KeyMessage signalling = key;
      signalling.csb_id = (std::uint32_t(purpose) << 28) | 0x0123456U;
      signalling.properties = KeyProperties{purpose, 1, time - 2208988800ULL, time - 2208988800ULL + 60, {},
                                            purpose == 6 ? std::vector<std::string>{"sip:group@example.org"}
                                                         : std::vector<std::string>{}};
      auto opened_signalling =
          open_mikey(pub, bob, alice.uri, create_mikey(pub, alice, bob.uri, signalling, &profile), time, 300, &profile);
      check(opened_signalling.properties == signalling.properties && opened_signalling.csb_id == signalling.csb_id,
            "MSCCK and MuSiK key parameters round trip");
      require_active(opened_signalling, {}, time - 2208988800ULL);
      signalling.properties->type = purpose == 5 ? 6 : 5;
      rejected([&] { create_mikey(pub, alice, bob.uri, signalling, &profile); }, "key type disagreeing with purpose");
    }
    KeyMessage mscck = key;
    mscck.csb_id = 0x50000001U;
    mscck.properties = KeyProperties{5, 1, time - 2208988800ULL, time - 2208988800ULL + 60, {}, {"sip:group@x"}};
    rejected([&] { create_mikey(pub, alice, bob.uri, mscck, &profile); }, "an MSCCK with group IDs accepted");
    rejected([&] { open_mikey(pub, outsider, alice.uri, data, time); }, "wrong recipient accepted");
    rejected([&] { open_mikey(pub, bob, outsider.uri, data, time); }, "wrong sender accepted");
    rejected([&] { open_mikey(pub, bob, alice.uri, data, time + 301); }, "stale MIKEY accepted");
    // TS 33.180 annex E.3.1: a PCK I_MESSAGE carries no key parameters, so it needs no
    // annex E.6 wire profile; the receiver learns the initiator from IDRi (TS 24.379
    // clause 11.1.1.2.1.2 step 4 a)).
    KeyMessage pck;
    pck.key.fill(0x51);
    pck.random.assign(16, 0x19);
    pck.csb_id = 0x10abcdef;
    pck.ntp_seconds = time;
    auto pck_data = create_mikey(pub, alice, bob.uri, pck);
    check(mikey_initiator(pck_data) == alice.uri, "I_MESSAGE initiator");
    // TS 33.180 clause 5.2.8: the receiver and its KMS, for a KMS Redirect Response.
    check(mikey_receiver(pck_data) == std::pair<std::string, std::string>{bob.uri, pub.period.kms_uri},
          "I_MESSAGE receiver and KMS");
    auto opened = open_mikey(pub, bob, mikey_initiator(pck_data), pck_data, time);
    check(opened.key == pck.key && opened.csb_id == 0x10abcdef && !opened.properties, "PCK round trip");
    rejected([&] { open_mikey(pub, bob, outsider.uri, pck_data, time); }, "PCK from another initiator accepted");
    rejected([&] { mikey_initiator(std::span(pck_data).first(40)); }, "truncated initiator accepted");
    check(mikey_csb_id(pck_data) == 0x10abcdef, "I_MESSAGE CSB-ID");
    // TS 33.180 clause 8.5.4.1 (table 8.5.4.1-1): an MCData DATA PAYLOAD (type 0x03)
    // protected with the PCK carries message type 0x43 (TS 24.282 clause 6.6.3.1) and
    // the PCK-ID as DPPK-ID.
    KeyParameterWireProfile payload_profile{10, 1, 0x79, 0x78};
    ProtectedPayload sealed{0x43, 1790000000, 0, 0, pck.csb_id, {0x03, 0x01, 0x78, 0x00, 0x03, 0x01, 'h', 'i'}};
    auto wire = seal_payload(sealed, pck.key, payload_profile);
    check(wire[0] == 0x43 && wire.size() == 1 + 5 + 4 + 1 + 1 + 16 + 4 + 3 + sealed.plain.size() + 16,
          "protected payload layout");
    check(payload_key_id(wire) == pck.csb_id, "DPPK-ID readable before decryption");
    auto unsealed = open_payload(wire, pck.key, payload_profile);
    check(unsealed.plain == sealed.plain && unsealed.message_type == 0x43 && unsealed.unix_seconds == 1790000000,
          "protected payload round trip");
    auto altered = wire;
    altered[2] ^= 1;
    rejected([&] { open_payload(altered, pck.key, payload_profile); }, "altered associated data accepted");
    altered = wire;
    altered.back() ^= 1;
    rejected([&] { open_payload(altered, pck.key, payload_profile); }, "altered ciphertext accepted");
    auto other = pck.key;
    other[0] ^= 1;
    rejected([&] { open_payload(wire, other, payload_profile); }, "wrong DPPK accepted");
    check(seal_payload(sealed, pck.key, payload_profile) != wire, "a fresh IV for every protected payload");
    // A file larger than one Protected Payload message becomes a numbered series
    // (TS 33.180 table 8.5.4.1-1 NOTE 2: Payload ID and Payload sequence number).
    Bytes file(150000);
    for (std::size_t index = 0; index < file.size(); ++index) file[index] = static_cast<byte>(index * 7);
    auto series = seal_series(file, 0x42, pck.key, pck.csb_id, payload_profile);
    check(series.size() == 8 + file.size() + 3 * (35 + 16) && series[0] == 0x42 && series[10] == 0 &&
              series[35 + 60000 + 16 + 10] == 1,
          "three messages numbered 0, 1 and 2, after the 8-octet length");
    check(open_series(series, 0x42, pck.key, payload_profile) == file, "series round trip");
    auto reordered = series;
    std::rotate(reordered.begin(), reordered.begin() + 35 + 60000 + 16, reordered.end());
    rejected([&] { open_series(reordered, 0x42, pck.key, payload_profile); }, "reordered series accepted");
    auto truncated = series;
    truncated.resize(series.size() - (35 + 30008 + 16));
    rejected([&] { open_series(truncated, 0x42, pck.key, payload_profile); },
             "series missing its last message accepted");
    truncated.pop_back();
    rejected([&] { open_series(truncated, 0x42, pck.key, payload_profile); }, "cut series accepted");
    check(open_series(seal_series({}, 0x42, pck.key, pck.csb_id, payload_profile), 0x42, pck.key, payload_profile)
              .empty(),
          "an empty file");
    rejected([&] { open_series(series, 0x43, pck.key, payload_profile); }, "series of another type accepted");
    // TS 33.180 clause 8.5.5 (table 8.5.5-1): an Authenticated Payload signed with the sender's ECCSI key.
    const Bytes original{0x43, 1, 2, 3, 4, 5};
    auto signed_payload = authenticate_payload(pub, alice, time, 0x43, original);
    check(signed_payload[0] == 0xc3 && signed_payload[1] == original_payload_iei, "bits 7 and 8 set, original first");
    auto verified = open_authenticated(pub, alice.uri, signed_payload, time);
    check(verified.original == original && verified.message_type == 0xc3 &&
              verified.signer_uid == uid(alice.uri, period, time) && verified.signer_kms == period.kms_uri,
          "authenticated payload round trip");
    check(open_authenticated(pub, alice.uri, signed_payload, time + 60).original == original,
          "verified later in the period");
    rejected([&] { open_authenticated(pub, bob.uri, signed_payload, time); }, "payload attributed to another sender");
    auto forged = signed_payload;
    forged[5] ^= 1;
    rejected([&] { open_authenticated(pub, alice.uri, forged, time); }, "altered original payload accepted");
    forged = signed_payload;
    forged.back() ^= 1;
    rejected([&] { open_authenticated(pub, alice.uri, forged, time); }, "altered signature accepted");
    auto by_bob = authenticate_payload(pub, bob, time, 0x03, original);
    rejected([&] { open_authenticated(pub, alice.uri, by_bob, time); }, "bob's signature accepted as alice's");
    rejected([&] { validate_identity(pub, bob, time + period.seconds); }, "expired identity accepted");
    data.back() ^= 1;
    rejected([&] { open_mikey(pub, bob, alice.uri, data, time); }, "tampered ECCSI signature accepted");
    data.pop_back();
    rejected([&] { open_mikey(pub, bob, alice.uri, data, time); }, "truncated MIKEY accepted");
    auto corrupted = bob;
    corrupted.receiver_secret.back() ^= 1;
    rejected([&] { validate_identity(pub, corrupted, time); }, "invalid receiver key accepted");
    {
      // TS 33.180 clauses 5.2.7 and 5.3.1.4, annex E.3.1 (IDRkmsi, IDRkmsr): sender
      // and recipient keyed by different KMSs.
      auto other_kms = create_authority(Period{"kms.other.example", 2592000, 0});
      const auto &other_pub = other_kms.public_parameters;
      auto erin = issue(other_kms, "sip:erin@other.example", time);
      KeyMessage cross;
      cross.key.fill(0x61);
      cross.random.assign(16, 0x62);
      cross.csb_id = 0x10a1b2c3;
      cross.ntp_seconds = time;
      auto message = create_mikey(pub, other_pub, alice, erin.uri, cross);
      check(mikey_initiator_kms(message) == "kms.example.org", "IDRkmsi names the initiator's KMS");
      const KmsLookup knows_home = [&](std::string_view uri) { return uri == pub.period.kms_uri ? &pub : nullptr; };
      auto opened = open_mikey(other_pub, knows_home, erin, alice.uri, message, time);
      check(opened.key == cross.key && opened.csb_id == cross.csb_id, "a key from another KMS's user opens");
      rejected([&] { open_mikey(other_pub, erin, alice.uri, message, time); }, "an unknown signing KMS was accepted");
      rejected([&] { open_mikey(pub, knows_home, bob, alice.uri, message, time); }, "a message for another KMS opened");
      const KmsLookup wrong = [&](std::string_view) { return &other_pub; };
      rejected([&] { open_mikey(other_pub, wrong, erin, alice.uri, message, time); },
               "a signature under the wrong KMS accepted");
      auto reply = create_mikey(other_pub, pub, erin, bob.uri, cross);
      const KmsLookup knows_other = [&](std::string_view uri) {
        return uri == other_pub.period.kms_uri ? &other_pub : nullptr;
      };
      check(open_mikey(pub, knows_other, bob, erin.uri, reply, time).key == cross.key, "the other direction opens");
      auto signed_payload = authenticate_payload(other_pub, erin, time, 0x03, std::vector<std::uint8_t>{1, 2, 3});
      check(open_authenticated(knows_other, erin.uri, signed_payload, time).original.size() == 3,
            "a payload signed under another KMS verifies with its parameters");
      rejected([&] { (void)open_authenticated(pub, erin.uri, signed_payload, time); },
               "a payload of an unknown KMS verified");
    }
    std::cout << "keying tests passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
