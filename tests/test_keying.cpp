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

#include <algorithm>
#include <iostream>
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
// TS 33.180 annex F.2.1.2: the example MIKEY-SAKKE UID; annex E: MIKEY-SAKKE I_MESSAGEs for a key and for a
// GMK with its annex E.6 parameters, opened only by the right receiver from the right sender while fresh; clause
// 5.2.8: the receiver and its KMS for a KRR; clause 8.5.4: MCData protected payloads and series; clause 8.5.5:
// authenticated payloads; clause 5.2.7: keys between users of different KMSs.
int main() {
  try {
    using namespace mcx::keying;
    primitive_vectors();
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
    key.random.fill(0x27);
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
    pck.random.fill(0x19);
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
      cross.random.fill(0x62);
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
