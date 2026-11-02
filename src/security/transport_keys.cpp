//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The KM client's transport key (TrK) and integrity key (InK) for KMS traffic (include/mcx/transport_keys.hpp).
//
// Specifications: TS 33.180 V19.5.0 (Rel-19), RFC 3394; the key-wrap padding of the ETSI test suite for TS 37.579.
#include "mcx/transport_keys.hpp"

#include "mcx/xml_security.hpp"

#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <unistd.h>

#include <cctype>
#include <cstddef>
#include <initializer_list>
#include <limits>
#include <memory>
#include <stdexcept>
#include <sys/stat.h>

namespace mcx::transport {
namespace {
using Bytes = std::vector<std::uint8_t>;

//------------------------------------------------------------------------------
// Helper: throws the given error when a condition fails.
void require(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Helper: the octets of a key file's hexadecimal text (white space ignored).
Bytes unhex(const std::string &text, const std::string &name) {
  // Reserved up front so that no reallocation leaves a copy of the key text behind.
  std::string digits;
  digits.reserve(text.size());
  for (char c : text)
    if (!std::isspace(static_cast<unsigned char>(c))) digits.push_back(c);
  require(!digits.empty() && digits.size() % 2 == 0, name + ": the key file must hold the key in hexadecimal");
  Bytes out;
  out.reserve(digits.size() / 2);
  for (std::size_t i = 0; i < digits.size(); i += 2) {
    auto value = [&](char c) {
      require(std::isxdigit(static_cast<unsigned char>(c)), name + ": the key file must hold the key in hexadecimal");
      return std::isdigit(static_cast<unsigned char>(c)) ? c - '0' : std::tolower(c) - 'a' + 10;
    };
    out.push_back(static_cast<std::uint8_t>(value(digits[i]) << 4 | value(digits[i + 1])));
  }
  OPENSSL_cleanse(digits.data(), digits.size());
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.3.3 and 5.11.1: one pre-provisioned key, {"file": <path>, "id": <32-bit identifier>}, of one of
// the allowed sizes, from a file only its owner can read or write.
Xpk key(const nlohmann::json &cfg, const std::string &name, std::initializer_list<std::size_t> sizes) {
  require(cfg.is_object() && cfg.contains("file") && cfg["file"].is_string() && cfg.contains("id") &&
              cfg["id"].is_number_integer(),
          name + ": expected {\"file\": <path>, \"id\": <32-bit identifier>}");
  const auto &id = cfg["id"];
  require((id.is_number_unsigned() || id.get<std::int64_t>() >= 0) &&
              id.get<std::uint64_t>() <= std::numeric_limits<std::uint32_t>::max(),
          name + ": the identifier is 32 bits (TS 33.180 5.3.3)");
  const auto path = cfg["file"].get<std::string>();
  // One descriptor for the check and the read, so the file read is the file checked; O_NONBLOCK so that opening a FIFO
  // without a writer does not block before the check refuses it.
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  require(fd >= 0, name + ": cannot read " + path);
  std::string content;
  struct stat info{};
  const bool owner_only = ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && (info.st_mode & (S_IRWXG | S_IRWXO)) == 0;
  bool read_all = false;
  if (owner_only) {
    content.reserve(static_cast<std::size_t>(info.st_size) + 1); // no reallocation copies of the key text
    char buffer[4096];
    ssize_t n = 0;
    while ((n = ::read(fd, buffer, sizeof buffer)) > 0) content.append(buffer, static_cast<std::size_t>(n));
    read_all = n == 0;
    OPENSSL_cleanse(buffer, sizeof buffer);
  }
  ::close(fd);
  if (owner_only && !read_all) {
    OPENSSL_cleanse(content.data(), content.size());
    throw std::runtime_error(name + ": cannot read " + path);
  }
  require(owner_only, name + ": " + path +
                          " must be a regular file readable by its owner only (OpenMCX's storage of "
                          "TS 33.180 5.11.1 'stored in a protected state', whose method is out of scope)");
  Xpk out{{}, id.get<std::uint32_t>()};
  try {
    out.key = unhex(content, name);
  } catch (...) {
    OPENSSL_cleanse(content.data(), content.size());
    throw;
  }
  OPENSSL_cleanse(content.data(), content.size());
  bool sized = false;
  for (auto size : sizes) sized = sized || out.key.size() == size;
  if (!sized) {
    OPENSSL_cleanse(out.key.data(), out.key.size());
    throw std::runtime_error(name + ": wrong key length");
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: RFC 3394 key wrap or unwrap with AES-256 (OpenSSL's id-aes256-wrap, the default initial value A6A6A6A6A6A6A6A6).
Bytes aes_wrap(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> in, bool encrypt) {
  require(kek.size() == 32, "kw-aes256 needs a 256-bit key");
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  require(ctx != nullptr, "AES key wrap failed");
  EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  require(EVP_CipherInit_ex(ctx.get(), EVP_aes_256_wrap(), nullptr, kek.data(), nullptr, encrypt ? 1 : 0) == 1,
          "AES key wrap failed");
  Bytes out(in.size() + 8);
  int length = 0;
  const bool done =
      EVP_CipherUpdate(ctx.get(), out.data(), &length, in.data(), static_cast<int>(in.size())) == 1 && length > 0;
  if (!done) {
    OPENSSL_cleanse(out.data(), out.size());
    throw std::runtime_error(encrypt ? "AES key wrap failed" : "AES key unwrap failed its integrity check");
  }
  out.resize(static_cast<std::size_t>(length));
  return out;
}
} // namespace

//------------------------------------------------------------------------------
// TS 33.180 clauses 5.3.2, 5.3.3, 5.11.1 and 9.3.3: the pre-provisioned TrK (256 bits) and InK (128 or 256 bits).
TransportKeys load(const nlohmann::json &cfg, const std::string &user) {
  TransportKeys keys;
  keys.user = user;
  if (cfg.is_null()) return keys;
  require(cfg.is_object(), "transport keys: expected an object with \"trk\" and/or \"ink\"");
  if (cfg.contains("trk")) keys.trk = key(cfg["trk"], "trk", {32});
  if (cfg.contains("ink")) keys.ink = key(cfg["ink"], "ink", {16, 32});
  require(!(keys.trk || keys.ink) || !user.empty(), "transport keys need the MC service user ID (TS 33.180 F.1.4)");
  return keys;
}

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.2: the entry of the MC service user's URI in security.transport_keys.
TransportKeys load_for(const nlohmann::json &security, const std::string &user) {
  if (!security.is_object() || !security.contains("transport_keys")) return load(nullptr, user);
  const auto &all = security.at("transport_keys");
  require(all.is_object(), "security.transport_keys: expected an object keyed by MC service user URI");
  const auto entry = all.find(user);
  return load(entry == all.end() ? nlohmann::json() : *entry, user);
}

//------------------------------------------------------------------------------
// TS 33.180 clause 9.3.3: the TrK for confidentiality.
std::optional<Xpk> confidentiality_xpk(const TransportKeys &keys) { return keys.trk; }

//------------------------------------------------------------------------------
// TS 33.180 clause 5.3.2, annexes D.2.2 and D.3.1: the InK when present, else the TrK.
std::optional<Xpk> integrity_xpk(const TransportKeys &keys) { return keys.ink ? keys.ink : keys.trk; }

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.4: FC 0x51.
std::vector<std::uint8_t> confidentiality_key(const Xpk &xpk, const std::string &user) {
  return xmlsec::protection_key(xpk.key, xpk.id, user, 0x51);
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.1.4: FC 0x52.
std::vector<std::uint8_t> integrity_key(const Xpk &xpk, const std::string &user) {
  return xmlsec::protection_key(xpk.key, xpk.id, user, 0x52);
}

//------------------------------------------------------------------------------
// TS 33.180 annex D.1: HMAC-SHA256, 256 bits, under the integrity key.
std::vector<std::uint8_t> mac(const Xpk &xpk, const std::string &user, std::string_view data) {
  auto key = integrity_key(xpk, user);
  const auto out = xmlsec::hmac_sha256(key, data);
  OPENSSL_cleanse(key.data(), key.size());
  return {out.begin(), out.end()};
}

//------------------------------------------------------------------------------
// RFC 3394 section 2.2.1: n >= 2 64-bit blocks of key material.
std::vector<std::uint8_t> wrap(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> key_material) {
  require(key_material.size() >= 16 && key_material.size() % 8 == 0,
          "kw-aes256 (RFC 3394) wraps only key material of at least 128 bits in 64-bit blocks");
  return aes_wrap(kek, key_material, true);
}

//------------------------------------------------------------------------------
// RFC 3394 section 2.2.2: the integrity check of the unwrapped key material.
std::vector<std::uint8_t> unwrap(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> wrapped) {
  require(wrapped.size() >= 24 && wrapped.size() % 8 == 0, "wrapped key material must be 64-bit blocks (RFC 3394)");
  return aes_wrap(kek, wrapped, false);
}

//------------------------------------------------------------------------------
// The ETSI test suite's padding before kw-aes256 (f_MCX_XML_EncryptKey; TS 33.180 9.3.4.2 has no rule): n - 1 zero
// octets and one octet n, 1 <= n <= 8, then RFC 3394.
std::vector<std::uint8_t> wrap_key_material(std::span<const std::uint8_t> kek,
                                            std::span<const std::uint8_t> key_material) {
  require(key_material.size() >= 8, "key material to wrap must be at least 64 bits");
  const std::size_t n = 8 - key_material.size() % 8;
  Bytes padded(key_material.begin(), key_material.end());
  padded.resize(padded.size() + n, 0);
  padded.back() = static_cast<std::uint8_t>(n);
  try {
    auto out = wrap(kek, padded);
    OPENSSL_cleanse(padded.data(), padded.size());
    return out;
  } catch (...) {
    OPENSSL_cleanse(padded.data(), padded.size());
    throw;
  }
}

//------------------------------------------------------------------------------
// RFC 3394 unwrap and integrity check, then the padding length octet (1 to 8) and its removal.
std::vector<std::uint8_t> unwrap_key_material(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> wrapped) {
  auto padded = unwrap(kek, wrapped);
  const std::size_t n = padded.back();
  if (n < 1 || n > 8 || n >= padded.size()) {
    OPENSSL_cleanse(padded.data(), padded.size());
    throw std::runtime_error("unwrapped key material has an invalid padding length");
  }
  Bytes out(padded.begin(), padded.end() - static_cast<std::ptrdiff_t>(n));
  OPENSSL_cleanse(padded.data(), padded.size());
  return out;
}
} // namespace mcx::transport
