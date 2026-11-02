//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The KM client's TrK and InK (include/mcx/transport_keys.hpp): loading the pre-provisioned keys, the key selection
// with the TrK integrity fallback, the annex F.1.4 derivation for 256-bit XPKs, HMAC-SHA256, the RFC 3394 key wrap
// and the ETSI test suite's padding before it.
//
// Specifications: TS 33.180 V19.5.0 (Rel-19), TS 33.220 annex B, RFC 3394 section 4.

#include "mcx/transport_keys.hpp"
#include "mcx/xml_security.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>

using namespace mcx;
using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// Throws the message when the condition does not hold.
void check(bool condition, const char *what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Fails unless the action throws.
template <class Action> void rejects(Action action, const char *what) {
  bool failed = false;
  try {
    action();
  } catch (const std::exception &) {
    failed = true;
  }
  check(failed, what);
}

//------------------------------------------------------------------------------
// Helpers: hexadecimal text and octets.
std::string hex(const Bytes &data) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  for (auto b : data) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 15]);
  }
  return out;
}

Bytes unhex(const std::string &text) {
  Bytes out;
  for (std::size_t i = 0; i < text.size(); i += 2)
    out.push_back(static_cast<std::uint8_t>(std::stoi(text.substr(i, 2), nullptr, 16)));
  return out;
}

//------------------------------------------------------------------------------
// Helper: a key file with the given content and mode.
std::string key_file(const std::filesystem::path &dir, const std::string &name, const std::string &content,
                     mode_t mode) {
  auto path = dir / name;
  std::ofstream(path) << content << "\n";
  ::chmod(path.c_str(), mode);
  return path.string();
}

//------------------------------------------------------------------------------
// Helper: true when loading the key configuration in a child process throws within the test's bound (a fixture bound
// against a hanging test, not a protocol value); a load that blocks is killed by the alarm and counts as false.
bool refused_in_child(const nlohmann::json &cfg, const std::string &user) {
  const pid_t child = ::fork();
  if (child == 0) {
    ::alarm(5);
    try {
      transport::load(cfg, user);
    } catch (const std::exception &) {
      ::_exit(0);
    }
    ::_exit(1);
  }
  int status = 0;
  return child > 0 && ::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

//------------------------------------------------------------------------------
// TS 33.220 annex B.2.0 with TS 33.180 annex F.1.4, built here field by field: HMAC-SHA-256(XPK, FC || P0 || L0 || P1
// || L1), P1 the XPK-ID in 4 octets, L1 = 0x00 0x04.
Bytes kdf(const Bytes &xpk, std::uint8_t fc, const std::string &user, std::uint32_t id) {
  Bytes s{fc};
  s.insert(s.end(), user.begin(), user.end());
  s.push_back(static_cast<std::uint8_t>(user.size() >> 8));
  s.push_back(static_cast<std::uint8_t>(user.size()));
  s.insert(s.end(), {static_cast<std::uint8_t>(id >> 24), static_cast<std::uint8_t>(id >> 16),
                     static_cast<std::uint8_t>(id >> 8), static_cast<std::uint8_t>(id), 0x00, 0x04});
  Bytes out(32);
  unsigned length = 0;
  HMAC(EVP_sha256(), xpk.data(), static_cast<int>(xpk.size()), s.data(), s.size(), out.data(), &length);
  return out;
}

int main() {
  try {
    const std::string user = "sip:alice@mcx.test";
    Bytes trk(32), ink(32), ink128(16);
    for (int i = 0; i < 32; ++i) trk[i] = static_cast<std::uint8_t>(i), ink[i] = static_cast<std::uint8_t>(0xa0 + i);
    for (int i = 0; i < 16; ++i) ink128[i] = static_cast<std::uint8_t>(0x50 + i);

    // RFC 3394 sections 4.3 and 4.6: 128 and 256 bits of key data under a 256-bit KEK.
    const auto data128 = unhex("00112233445566778899aabbccddeeff");
    const auto data256 = unhex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
    check(hex(transport::wrap(trk, data128)) == "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7", "RFC 3394 4.3");
    check(hex(transport::wrap(trk, data256)) ==
              "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
          "RFC 3394 4.6");
    check(transport::unwrap(trk, transport::wrap(trk, data256)) == data256, "unwrap round trip");
    auto tampered = transport::wrap(trk, data256);
    tampered[5] ^= 1;
    rejects([&] { transport::unwrap(trk, tampered); }, "a tampered wrap fails the integrity check");
    rejects([&] { transport::unwrap(ink, transport::wrap(trk, data256)); }, "another KEK fails the integrity check");
    // TS 33.180 D.3.3.2 key sizes under plain RFC 3394: the 32-octet SSK wraps; the 65-octet PVT and the 257-octet
    // RSK do not (RFC 3394 section 2: multiples of 64 bits; TS 33.180 specifies no other wrap, see wrap_key_material).
    check(transport::wrap(trk, Bytes(32, 7)).size() == 40, "the SSK wraps");
    rejects([&] { transport::wrap(trk, Bytes(65, 7)); }, "the PVT is not a multiple of 64 bits");
    rejects([&] { transport::wrap(trk, Bytes(257, 7)); }, "the RSK is not a multiple of 64 bits");
    rejects([&] { transport::wrap(ink128, data128); }, "kw-aes256 needs a 256-bit key");
    rejects([&] { transport::unwrap(trk, Bytes(20)); }, "a wrap is 64-bit blocks");

    // The ETSI test suite's padding before kw-aes256 (f_MCX_XML_EncryptKey; not a TS 33.180 rule): n - 1 zero octets
    // and one octet n, 1 <= n <= 8, then RFC 3394. Known answers from an independent implementation (Python
    // cryptography aes_key_wrap over the padded input), KEK 00..1f, key material 0x30, 0x31, ...
    auto material = [](std::size_t size) {
      Bytes out(size);
      for (std::size_t i = 0; i < size; ++i) out[i] = static_cast<std::uint8_t>(0x30 + i);
      return out;
    };
    check(hex(transport::wrap_key_material(trk, material(65))) ==
              "79e569d5137aa02f28fb1b0d44358c44c9e8055c2f4066892a87df2877b7da2783670ab6fb59fa2e203e8e12111f1508"
              "312ba7d1f2c88a790956f68807b4528c2f300b9473bd7fe5e9c022f3f82a6ff8",
          "padded wrap of a 65-octet PVT (72 octets padded)");
    check(hex(transport::wrap_key_material(trk, material(32))) ==
              "9e5239874f9bdfb102d6accf076496d4075175874a21b7acc17ac24a8ce7bae9c8d61e813b0ce52c727cd5dfffe1c000",
          "padded wrap of a 32-octet SSK: a whole padding block (40 octets padded)");
    for (std::size_t size : {8u, 32u, 65u, 257u, 63u, 64u}) {
      const auto wrapped = transport::wrap_key_material(trk, material(size));
      check(wrapped.size() == (size / 8 + 1) * 8 + 8, "padded wrap size");
      check(transport::unwrap_key_material(trk, wrapped) == material(size), "padded wrap round trip");
    }
    check(transport::wrap_key_material(trk, material(257)).size() == 272, "the RSK: 264 octets padded, 272 wrapped");
    rejects([&] { transport::wrap_key_material(trk, material(7)); }, "less than 64 bits of key material");
    // Padding length octets outside 1..8 after a valid RFC 3394 unwrap.
    auto bad_padding = [&](std::uint8_t last) {
      auto block = material(32);
      block.back() = last;
      return transport::wrap(trk, block);
    };
    rejects([&] { transport::unwrap_key_material(trk, bad_padding(0)); }, "padding length 0");
    rejects([&] { transport::unwrap_key_material(trk, bad_padding(9)); }, "padding length 9");
    rejects([&] { transport::unwrap_key_material(trk, bad_padding(0xff)); }, "padding length 255");
    check(transport::unwrap_key_material(trk, bad_padding(8)).size() == 24, "padding length 8");
    auto padded_tampered = transport::wrap_key_material(trk, material(65));
    padded_tampered[9] ^= 1;
    rejects([&] { transport::unwrap_key_material(trk, padded_tampered); }, "a tampered padded wrap");
    rejects([&] { transport::unwrap_key_material(ink, transport::wrap_key_material(trk, material(65))); },
            "a padded wrap under another KEK");

    // TS 33.180 annex F.1.4: 256-bit XPK, the entire KDF output; 128-bit XPK, the 128 least significant bits (and
    // the same keys as the CSK derivation of XML protection).
    transport::Xpk trk_key{trk, 0x0a0b0c0d}, ink_key{ink, 0x01020304}, ink128_key{ink128, 7};
    check(transport::confidentiality_key(trk_key, user) == kdf(trk, 0x51, user, 0x0a0b0c0d), "F.1.4 FC 0x51, 256 bits");
    check(transport::integrity_key(trk_key, user) == kdf(trk, 0x52, user, 0x0a0b0c0d), "F.1.4 FC 0x52, 256 bits");
    const auto short_key = kdf(ink128, 0x52, user, 7);
    check(transport::integrity_key(ink128_key, user) == Bytes(short_key.begin() + 16, short_key.end()),
          "F.1.4 128-bit XPK: the 128 least significant bits");
    xmlsec::Key csk;
    std::copy(ink128.begin(), ink128.end(), csk.xpk.begin());
    csk.id = 7;
    csk.user = user;
    const auto xml_key = xmlsec::integrity_key(csk);
    check(transport::integrity_key(ink128_key, user) == Bytes(xml_key.begin(), xml_key.end()),
          "the same derivation as XML protection");
    rejects([&] { xmlsec::protection_key(Bytes(24), 1, user, 0x51); }, "an XPK is 128 or 256 bits");
    rejects([&] { transport::integrity_key(trk_key, ""); }, "the MC service user ID is needed");

    // TS 33.180 annex D.1: HMAC-SHA256 with a 256-bit signature under the integrity key.
    {
      const auto key = transport::integrity_key(ink_key, user);
      Bytes expected(32);
      unsigned length = 0;
      HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char *>("kms"), 3,
           expected.data(), &length);
      check(transport::mac(ink_key, user, "kms") == expected && length == 32, "HMAC-SHA256 under the integrity key");
    }

    // TS 33.180 clauses 5.3.2 and 9.3.3, annexes D.2.2 and D.3.1: the key selection.
    auto dir = std::filesystem::temp_directory_path() / ("mcx-transport-keys-" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    const auto trk_file = key_file(dir, "trk.hex", hex(trk), 0600);
    const auto ink_file = key_file(dir, "ink.hex", hex(ink), 0600);
    nlohmann::json both = {{"trk", {{"file", trk_file}, {"id", 0x0a0b0c0d}}},
                           {"ink", {{"file", ink_file}, {"id", 0x01020304}}}};
    nlohmann::json trk_only = {{"trk", {{"file", trk_file}, {"id", 0x0a0b0c0d}}}};
    nlohmann::json ink_only = {{"ink", {{"file", ink_file}, {"id", 0x01020304}}}};
    auto keys = transport::load(both, user);
    check(transport::integrity_xpk(keys)->id == 0x01020304, "integrity with the InK when present");
    check(transport::confidentiality_xpk(keys)->id == 0x0a0b0c0d, "confidentiality with the TrK");
    keys = transport::load(trk_only, user);
    check(transport::integrity_xpk(keys)->id == 0x0a0b0c0d && transport::integrity_xpk(keys)->key == trk,
          "integrity with the TrK when no InK is present");
    keys = transport::load(ink_only, user);
    check(!transport::confidentiality_xpk(keys) && transport::integrity_xpk(keys)->id == 0x01020304,
          "no confidentiality without a TrK");
    keys = transport::load(nlohmann::json(), user);
    check(!transport::integrity_xpk(keys) && !transport::confidentiality_xpk(keys), "no keys, no protection");

    // TS 33.180 clauses 5.3.3, 5.11.1 and 9.3.3: refused key configurations.
    const auto open_file = key_file(dir, "open.hex", hex(trk), 0644);
    rejects([&] { transport::load({{"trk", {{"file", open_file}, {"id", 1}}}}, user); },
            "a key file others can read is refused");
    rejects([&] { transport::load({{"trk", {{"file", dir.string()}, {"id", 1}}}}, user); },
            "a key path that is not a regular file is refused");
    // A FIFO without a writer is refused without blocking; a symbolic link to an owner-only regular file (a secret
    // mount) is read.
    const auto fifo = (dir / "fifo.hex").string();
    check(::mkfifo(fifo.c_str(), 0600) == 0, "test FIFO");
    check(refused_in_child({{"trk", {{"file", fifo}, {"id", 1}}}}, user), "a FIFO is refused without blocking");
    const auto link = (dir / "link.hex").string();
    std::filesystem::create_symlink(trk_file, link);
    check(transport::load({{"trk", {{"file", link}, {"id", 0x0a0b0c0d}}}}, user).trk->key == trk,
          "a symbolic link to an owner-only key file is read");
    const auto short_trk = key_file(dir, "short.hex", hex(ink128), 0600);
    rejects([&] { transport::load({{"trk", {{"file", short_trk}, {"id", 1}}}}, user); }, "the TrK is 256 bits");
    const auto odd_ink = key_file(dir, "odd.hex", hex(Bytes(24, 1)), 0600);
    rejects([&] { transport::load({{"ink", {{"file", odd_ink}, {"id", 1}}}}, user); }, "the InK is 128 or 256 bits");
    const auto bad_hex = key_file(dir, "bad.hex", std::string(64, 'z'), 0600);
    rejects([&] { transport::load({{"trk", {{"file", bad_hex}, {"id", 1}}}}, user); }, "the key is hexadecimal");
    rejects([&] { transport::load({{"trk", {{"file", trk_file}, {"id", 0x100000000ULL}}}}, user); },
            "the identifier is 32 bits");
    rejects([&] { transport::load({{"trk", {{"file", trk_file}}}}, user); }, "the identifier is needed");
    rejects([&] { transport::load(trk_only, ""); }, "keys need the MC service user ID");
    std::filesystem::remove_all(dir);
  } catch (const std::exception &error) {
    std::cerr << "FAIL: " << error.what() << "\n";
    return 1;
  }
  std::cout << "transport keys: ok\n";
  return 0;
}
