//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IMS AKA in the UE: MILENAGE against the test sets of TS 35.208 (sets 1 and 3 to 6) and TS 35.207 (set 2), the
// ISIM's AUTN check, AUTS and sequence numbers (TS 33.102 clause 6.3.3, annex C.2), the HTTP Digest responses
// (RFC 2617 and RFC 7616 examples), the AKA nonce, sec-agree parsing and selection (TS 33.203 clause 7.2, annex H) and
// the ESP keys (annex I).
//
// Specifications: TS 35.207 V19.0.0, TS 35.208 V19.0.0, TS 33.102 V19.1.0, TS 33.203 V19.1.0 (Rel-19), RFC 2617,
// RFC 3310, RFC 3329, RFC 7616.
#include "mcx/ims_aka.hpp"

extern "C" {
#include "hostap/common.h"
#include "milenage.h"
}

#include <unistd.h>

#include <filesystem>
#include <iostream>
#include <stdexcept>

using namespace mcx::aka;

//------------------------------------------------------------------------------
// Fails the test with the message why when the condition yes does not hold.
void check(bool yes, const std::string &why) {
  if (!yes) throw std::runtime_error(why);
}

//------------------------------------------------------------------------------
// Helper: bytes of hexadecimal text.
template <std::size_t N> std::array<std::uint8_t, N> bytes(const char *text) {
  std::array<std::uint8_t, N> out{};
  for (std::size_t index = 0; index < N; ++index) {
    unsigned value = 0;
    if (sscanf(text + 2 * index, "%2x", &value) != 1) throw std::runtime_error("hex");
    out[index] = static_cast<std::uint8_t>(value);
  }
  return out;
}

//------------------------------------------------------------------------------
// One MILENAGE test set: inputs K, RAND, SQN, AMF, OP, OPc and outputs f1, f1*, f2, f5, f3, f4, f5*.
struct TestSet {
  int number;
  const char *k, *rand, *sqn, *amf, *op, *opc, *f1, *f1_star, *f2, *f5, *f3, *f4, *f5_star;
};

// TS 35.208 clause 4.3 test sets 1 and 3 to 6 (hexadecimal format). Test set 2 of TS 35.208 V19.0.0 clause 4.3.2
// repeats test set 1; its values are TS 35.207 V19.0.0 clauses 4.4, 5.4 and 6.4 (test set 2 of the implementers'
// test data).
const TestSet test_sets[] = {
    {1, "465b5ce8b199b49faa5f0a2ee238a6bc", "23553cbe9637a89d218ae64dae47bf35", "ff9bb4d0b607", "b9b9",
     "cdc202d5123e20f62b6d676ac72cb318", "cd63cb71954a9f4e48a5994e37a02baf", "4a9ffac354dfafb3", "01cfaf9ec4e871e9",
     "a54211d5e3ba50bf", "aa689c648370", "b40ba9a3c58b2a05bbf0d987b21bf8cb", "f769bcd751044604127672711c6d3441",
     "451e8beca43b"},
    {2, "0396eb317b6d1c36f19c1c84cd6ffd16", "c00d603103dcee52c4478119494202e8", "fd8eef40df7d", "af17",
     "ff53bade17df5d4e793073ce9d7579fa", "53c15671c60a4b731c55b4a441c0bde2", "5df5b31807e258b0", "a8c016e51ef4a343",
     "d3a628ed988620f0", "c47783995f72", "58c433ff7a7082acd424220f2b67c556", "21a8c1f929702adb3e738488b9f5c5da",
     "30f1197061c1"},
    {3, "fec86ba6eb707ed08905757b1bb44b8f", "9f7c8d021accf4db213ccff0c7f71a6a", "9d0277595ffc", "725c",
     "dbc59adcb6f9a0ef735477b7fadf8374", "1006020f0a478bf6b699f15c062e42b3", "9cabc3e99baf7281", "95814ba2b3044324",
     "8011c48c0c214ed2", "33484dc2136b", "5dbdbb2954e8f3cde665b046179a5098", "59a92d3b476a0443487055cf88b2307b",
     "deacdd848cc6"},
    {4, "9e5944aea94b81165c82fbf9f32db751", "ce83dbc54ac0274a157c17f80d017bd6", "0b604a81eca8", "9e09",
     "223014c5806694c007ca1eeef57f004f", "a64a507ae1a2a98bb88eb4210135dc87", "74a58220cba84c49", "ac2cc74a96871837",
     "f365cd683cd92e96", "f0b9c08ad02e", "e203edb3971574f5a94b0d61b816345d", "0c4524adeac041c4dd830d20854fc46b",
     "6085a86c6f63"},
    {5, "4ab1deb05ca6ceb051fc98e77d026a84", "74b0cd6031a1c8339b2b6ce2b8c4a186", "e880a1b580b6", "9f07",
     "2d16c5cd1fdf6b22383584e3bef2a8d8", "dcf07cbd51855290b92a07a9891e523e", "49e785dd12626ef2", "9e85790336bb3fa2",
     "5860fc1bce351e7e", "31e11a609118", "7657766b373d1c2138f307e3de9242f9", "1c42e960d89b8fa99f2744e0708ccb53",
     "fe2555e54aa9"},
    {6, "6c38a116ac280c454f59332ee35c8c4f", "ee6466bc96202c5a557abbeff8babf63", "414b98222181", "4464",
     "1ba00a1a7c6700ac8c3ff3e96ad08725", "3803ef5363b947c6aaa225e58fae3934", "078adfb488241a57", "80246b8d0186bcf1",
     "16c8233f05a0ac28", "45b0f69ab06c", "3f8c7587fe8e4b233af676aede30ba3b", "a7466cc1e6b2a1337d49d3b66e95d7b4",
     "1f53cd2b1113"},
};

//------------------------------------------------------------------------------
// Helper: the AUTN the network sends for SQN (TS 33.102 clause 6.3.2): (SQN XOR AK) || AMF || MAC.
Autn make_autn(const Milenage &milenage, const Rand &rand, std::uint64_t sqn_value, const Amf &amf) {
  Sqn sqn{};
  for (int index = 5; index >= 0; --index, sqn_value >>= 8U) sqn[index] = static_cast<std::uint8_t>(sqn_value);
  const auto outputs = milenage.f2345(rand);
  const auto mac = milenage.f1(rand, sqn, amf);
  Autn autn{};
  for (int index = 0; index < 6; ++index) autn[index] = sqn[index] ^ outputs.ak[index];
  autn[6] = amf[0];
  autn[7] = amf[1];
  std::copy(mac.begin(), mac.end(), autn.begin() + 8);
  return autn;
}

//------------------------------------------------------------------------------
// TS 35.206/35.207/35.208 known answers, then the ISIM, digest, nonce, sec-agree and annex I checks.
int main() {
  try {
    for (const auto &set : test_sets) {
      const Milenage milenage(bytes<16>(set.k), bytes<16>(set.opc));
      const auto rand = bytes<16>(set.rand);
      const auto sqn = bytes<6>(set.sqn);
      const auto amf = bytes<2>(set.amf);
      const auto name = "test set " + std::to_string(set.number) + ": ";
      check(milenage.f1(rand, sqn, amf) == bytes<8>(set.f1), name + "f1");
      check(milenage.f1_star(rand, sqn, amf) == bytes<8>(set.f1_star), name + "f1*");
      const auto outputs = milenage.f2345(rand);
      check(outputs.res == bytes<8>(set.f2), name + "f2");
      check(outputs.ak == bytes<6>(set.f5), name + "f5");
      check(outputs.ck == bytes<16>(set.f3), name + "f3");
      check(outputs.ik == bytes<16>(set.f4), name + "f4");
      check(outputs.ak_star == bytes<6>(set.f5_star), name + "f5*");
    }

    // TS 33.102 annex C.2: the array of 32 SEQ values by IND, the wrap-around limit and replay.
    SequenceNumbers sqn;
    check(sqn.fresh(0x20) && !sqn.fresh(0x00), "SEQ 1 fresh, SEQ 0 not");
    sqn.accept(0x21); // SEQ 1, IND 1
    check(!sqn.fresh(0x21), "replayed SQN accepted");
    check(sqn.fresh(0x20), "SEQ 1 with another IND rejected");
    check(sqn.fresh(0x41) && sqn.highest() == 0x21, "SEQ 2 IND 1");
    check(!sqn.fresh((SequenceNumbers::delta + 2) << 5U), "jump above delta accepted");
    check(sqn.fresh(SequenceNumbers::delta << 5U), "jump of delta rejected");
    const auto restored = SequenceNumbers::parse(sqn.serialize());
    check(!restored.fresh(0x21) && restored.highest() == 0x21, "serialised state");

    // TS 33.102 clause 6.3.3: the ISIM with test set 1's keys; SQN state persisted across a restart.
    const auto file = std::filesystem::temp_directory_path() / ("openmcx-isim-" + std::to_string(getpid()) + ".json");
    std::filesystem::remove(file);
    const auto k = bytes<16>(test_sets[0].k), opc = bytes<16>(test_sets[0].opc);
    const Milenage network(k, opc);
    const auto rand = bytes<16>(test_sets[0].rand);
    const Amf amf{0x80, 0x00};
    {
      SoftIsim isim(k, opc, file);
      const auto good = isim.authenticate(rand, make_autn(network, rand, 0x40, amf));
      check(good.status == AuthStatus::success, "valid challenge refused");
      check(good.res == bytes<8>(test_sets[0].f2) && good.ck == bytes<16>(test_sets[0].f3) &&
                good.ik == bytes<16>(test_sets[0].f4),
            "RES, CK, IK");
      auto bad_mac = make_autn(network, rand, 0x60, amf);
      bad_mac[15] ^= 1U;
      check(isim.authenticate(rand, bad_mac).status == AuthStatus::mac_failure, "MAC failure not seen");
    }
    {
      SoftIsim isim(k, opc, file);
      const auto replay = isim.authenticate(rand, make_autn(network, rand, 0x40, amf));
      check(replay.status == AuthStatus::sync_failure, "replay after restart accepted");
      // The network side recovers SQN_MS from AUTS (hostap milenage_auts, TS 33.102 clause 6.3.5).
      Sqn recovered{};
      check(milenage_auts(opc.data(), k.data(), rand.data(), replay.auts.data(), recovered.data()) == 0,
            "AUTS MAC-S invalid");
      check(recovered == Sqn{0, 0, 0, 0, 0, 0x40}, "AUTS carries SQN_MS");
      check(isim.authenticate(rand, make_autn(network, rand, 0x60, amf)).status == AuthStatus::success,
            "next SQN refused");
    }
    std::filesystem::remove(file);

    // RFC 2617 section 3.5 and RFC 7616 section 3.9.1 examples (MD5 and SHA-256 request-digests).
    check(digest_response(AkaAlgorithm::akav1_md5, "Mufasa", "testrealm@host.com", "Circle Of Life", "GET",
                          "/dir/index.html", "dcd98b7102dd2f0e8b11d0f600bfb0c093", "00000001", "0a4f113b",
                          "auth") == "6629fae49393a05397450978507c4ef1",
          "RFC 2617 response");
    check(digest_response(AkaAlgorithm::akav2_sha256, "Mufasa", "http-auth@example.org", "Circle of Life", "GET",
                          "/dir/index.html", "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", "00000001",
                          "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
                          "auth") == "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
          "RFC 7616 response");
    AuthResult result;
    result.res = bytes<8>(test_sets[0].f2);
    check(digest_password(AkaAlgorithm::akav1_md5, result) == std::string(result.res.begin(), result.res.end()),
          "AKAv1 password is RES");
    check(digest_password(AkaAlgorithm::akav2_sha256, result).size() == 44, "AKAv2 password is base64 of 32 bytes");
    check(aka_algorithm("akav2-sha-256") == AkaAlgorithm::akav2_sha256 && !aka_algorithm("MD5"), "algorithm names");

    // RFC 3310 section 3.2: the nonce (here with 8 octets of server data).
    std::vector<std::uint8_t> nonce_bytes(rand.begin(), rand.end());
    const auto autn = make_autn(network, rand, 0x80, amf);
    nonce_bytes.insert(nonce_bytes.end(), autn.begin(), autn.end());
    const auto two = parse_nonce(base64(nonce_bytes));
    check(two && two->rand == rand && two->autn == autn, "nonce RAND || AUTN");
    nonce_bytes.resize(40, 7);
    check(parse_nonce(base64(nonce_bytes)).has_value(), "nonce with server data");
    check(!parse_nonce(base64(std::vector<std::uint8_t>(31, 1))) && !parse_nonce("not base64!"), "short nonce");

    // TS 37.579-1 table 5.5.2.19.7-1: a Security-Server with two mechanisms, hmac-md5-96 preferred; the UE takes
    // the hmac-sha-1-96 one ("Ipsec-3gpp" as the table writes it).
    const auto server = parse_sec_mechanisms(
        "ipsec-3gpp;q=0.9;alg=hmac-md5-96;ealg=aes-cbc;spi-c=1111;spi-s=2222;port-c=5100;port-s=6100, "
        "Ipsec-3gpp;q=0.7;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=3333;spi-s=4444;port-c=5101;port-s=6101");
    check(server.size() == 2 && server[0].q == 0.9 && server[1].port_s == 6101, "Security-Server parsed");
    const auto chosen = select_mechanism(server);
    check(chosen && chosen->spi_c == 3333U && chosen->ealg == "aes-cbc", "hmac-sha-1-96 chosen");
    // TS 33.203 clause 7.2: no ealg: NULL encryption.
    const auto null = select_mechanism(
        parse_sec_mechanisms("ipsec-3gpp;alg=hmac-sha-1-96;spi-c=1;spi-s=2;port-c=3;port-s=4;prot=esp;mod=trans"));
    check(null && null->ealg == "null", "NULL encryption");
    check(!select_mechanism(parse_sec_mechanisms("ipsec-3gpp;alg=hmac-sha-1-96;spi-c=1;spi-s=2;port-c=3")),
          "mechanism without port-s accepted");
    check(!select_mechanism(parse_sec_mechanisms("ipsec-3gpp;alg=hmac-sha-1-96;ealg=des-ede3-cbc;spi-c=1;spi-s=2;"
                                                 "port-c=3;port-s=4")),
          "des-ede3-cbc accepted");
    bool threw = false;
    try {
      (void)parse_sec_mechanisms("ipsec-3gpp;alg=hmac-sha-1-96;spi-c=4294967296");
    } catch (const std::invalid_argument &) {
      threw = true;
    }
    check(threw, "SPI above 2^32-1 accepted");
    SecMechanism offer;
    offer.name = "ipsec-3gpp";
    offer.alg = "hmac-sha-1-96";
    offer.ealg = "aes-cbc";
    offer.prot = "esp";
    offer.mod = "trans";
    offer.spi_c = 11;
    offer.spi_s = 12;
    offer.port_c = 13;
    offer.port_s = 14;
    check(format_sec_mechanism(offer) ==
              "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;prot=esp;mod=trans;spi-c=11;spi-s=12;port-c=13;port-s=14",
          "Security-Client text");

    // TS 33.203 annex I.
    const auto ik = bytes<16>(test_sets[0].f4), ck = bytes<16>(test_sets[0].f3);
    const auto ik_esp = integrity_key_esp("hmac-sha-1-96", ik);
    check(ik_esp.size() == 20 && std::equal(ik.begin(), ik.end(), ik_esp.begin()) && ik_esp[16] == 0 && ik_esp[19] == 0,
          "IK_ESP = IK || 32 zero bits");
    check(encryption_key_esp("aes-cbc", ck) == std::vector<std::uint8_t>(ck.begin(), ck.end()), "CK_ESP = CK");
    check(encryption_key_esp("null", ck).empty(), "NULL has no key");
    check(key_from_hex("465b5ce8b199b49faa5f0a2ee238a6bc") == k && amf_from_hex("8000") == amf, "hex keys");
  } catch (const std::exception &error) {
    std::cerr << "ims_aka: " << error.what() << '\n';
    return 1;
  }
  std::cout << "ims_aka: ok\n";
  return 0;
}
