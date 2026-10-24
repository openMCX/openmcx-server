//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IMS AKA in the UE: a software ISIM on the MILENAGE algorithm set (hostap's implementation, dependencies/hostap) with
// the sequence number handling of TS 33.102 annex C.2, the HTTP Digest AKA passwords and responses, the sec-agree
// mechanisms of the Security-Client, Security-Server and Security-Verify header fields and the ESP keys of the IPsec
// security associations.
//
// Specifications: TS 35.206 V19.0.0 (Rel-19), TS 33.102 V19.1.0 (Rel-19), TS 33.203 V19.1.0 (Rel-19),
// TS 24.229 V19.7.0 (Rel-19), RFC 2617, RFC 3310, RFC 3329, RFC 4169, RFC 7616.
#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mcx::aka {
using Key = std::array<std::uint8_t, 16>;
using Rand = std::array<std::uint8_t, 16>;
using Autn = std::array<std::uint8_t, 16>;
using Sqn = std::array<std::uint8_t, 6>;
using Amf = std::array<std::uint8_t, 2>;
using Mac = std::array<std::uint8_t, 8>;

//------------------------------------------------------------------------------
// TS 35.206 clause 4.1: the outputs of f2, f3, f4, f5 and f5* for one RAND.
struct Milenage2345 {
  std::array<std::uint8_t, 8> res{}; // f2
  Key ck{};                          // f3
  Key ik{};                          // f4
  Sqn ak{};                          // f5
  Sqn ak_star{};                     // f5*
};

//------------------------------------------------------------------------------
// TS 35.206 clause 4.1: the MILENAGE functions of a subscriber key K and OPc, with the default constants and
// rotations of TS 35.206; computed by hostap's milenage_f1 and milenage_f2345 (dependencies/hostap/README.md).
class Milenage {
public:
  Milenage(const Key &k, const Key &opc) : k_(k), opc_(opc) {}

  // f1 (MAC-A) and f1* (MAC-S) of SQN || RAND || AMF.
  [[nodiscard]] Mac f1(const Rand &rand, const Sqn &sqn, const Amf &amf) const;
  [[nodiscard]] Mac f1_star(const Rand &rand, const Sqn &sqn, const Amf &amf) const;
  [[nodiscard]] Milenage2345 f2345(const Rand &rand) const;

private:
  Key k_{}, opc_{};
};

//------------------------------------------------------------------------------
// TS 33.102 annex C.2 with the parameters of profile 2 (annex C.3.2, sequence numbers that are not time-based):
// SQN = SEQ || IND with a 5-bit IND, an array of a = 32 accepted SEQ values SEQ_MS(i) that start at zero, the wrap
// around limit delta = 2^28 of annex C.2.1 and no age limit L (optional in annex C.2.2). SQN_MS is the highest accepted
// sequence number.
class SequenceNumbers {
public:
  static constexpr unsigned ind_bits = 5;
  static constexpr unsigned array_size = 1U << ind_bits;
  static constexpr std::uint64_t delta = std::uint64_t{1} << 28;

  // Annex C.2.1 and C.2.2: whether a received 48-bit SQN is in the correct range.
  [[nodiscard]] bool fresh(std::uint64_t sqn) const noexcept;
  // Annex C.2.2 (a): SEQ_MS(IND) = SEQ of an accepted SQN, which may become SQN_MS.
  void accept(std::uint64_t sqn) noexcept;

  [[nodiscard]] std::uint64_t highest() const noexcept { return sqn_ms_; }

  // The state as kept in the ISIM's file: {"format": "openmcx-isim-sqn-1", "sqn_ms": n, "seq_ms": [32 values]}.
  [[nodiscard]] std::string serialize() const;
  // Throws on text that is not such a state.
  [[nodiscard]] static SequenceNumbers parse(std::string_view text);

private:
  std::array<std::uint64_t, array_size> seq_ms_{};
  std::uint64_t sqn_ms_ = 0;
};

//------------------------------------------------------------------------------
// TS 33.102 clause 6.3.3: the outcome of the ISIM's authentication of a challenge (RAND, AUTN).
enum class AuthStatus {
  success,      // RES, CK and IK computed
  mac_failure,  // XMAC != MAC: the network is not authenticated
  sync_failure, // SQN out of range: AUTS computed
};

struct AuthResult {
  AuthStatus status = AuthStatus::mac_failure;
  std::array<std::uint8_t, 8> res{};
  Key ck{}, ik{};
  // AUTS = (SQN_MS XOR f5*K(RAND)) || f1*K(SQN_MS || RAND || AMF*), AMF* all zeros (TS 33.102 clause 6.3.3).
  std::array<std::uint8_t, 14> auts{};
};

//------------------------------------------------------------------------------
// TS 33.203 clause 6.1 and TS 33.102 clause 6.3.3: a software ISIM: its long-term key K and OPc, and its sequence
// numbers (annex C.2), kept in a file that is written before a RES leaves the ISIM, so that a challenge is never
// accepted twice across restarts. A missing file is the initial state (all zero, annex C.2.2).
class SoftIsim {
public:
  SoftIsim(const Key &k, const Key &opc, std::filesystem::path sqn_file);

  // TS 33.102 clause 6.3.3: AK = f5(RAND), SQN = (SQN XOR AK) XOR AK, XMAC = f1(SQN || RAND || AMF) compared with
  // MAC, then the SQN range; RES = f2(RAND), CK = f3(RAND), IK = f4(RAND) when both hold. The AMF is not checked: its
  // separation bit concerns EPS and 5G AKA (TS 33.102 annex H), not IMS AKA.
  [[nodiscard]] AuthResult authenticate(const Rand &rand, const Autn &autn);

  [[nodiscard]] const SequenceNumbers &sequence_numbers() const noexcept { return sqn_; }

private:
  void save() const;
  Milenage milenage_;
  std::filesystem::path sqn_file_;
  SequenceNumbers sqn_;
};

//------------------------------------------------------------------------------
// TS 24.229 clause 5.1.1.5.1: the AKA algorithms of a WWW-Authenticate header field the UE supports.
enum class AkaAlgorithm { akav1_md5, akav2_sha256 };

// The algorithm named in a challenge ("AKAv1-MD5" or "AKAv2-SHA-256", case-insensitive, RFC 3310 section 3.1 and
// RFC 4169 section 3), or none.
[[nodiscard]] std::optional<AkaAlgorithm> aka_algorithm(std::string_view name);
// The name sent in the Authorization header field.
[[nodiscard]] std::string_view algorithm_name(AkaAlgorithm algorithm);

//------------------------------------------------------------------------------
// RFC 3310 section 3.3 (AKAv1: the password is RES, as octets) and RFC 4169 section 3 with TS 33.203 clause 6.1.1
// (AKAv2-SHA-256: the password is base64(PRF(RES || IK || CK, "http-digest-akav2-password")), PRF = HMAC-SHA-256).
[[nodiscard]] std::string digest_password(AkaAlgorithm algorithm, const AuthResult &result);

//------------------------------------------------------------------------------
// RFC 2617 section 3.2.2.1 (MD5, for AKAv1-MD5) and RFC 7616 section 3.4.1 (SHA-256, for AKAv2-SHA-256): the
// request-digest; with qop "auth", nc and cnonce, or without qop (RFC 2069 compatibility) when qop is empty.
[[nodiscard]] std::string digest_response(AkaAlgorithm algorithm, std::string_view username, std::string_view realm,
                                          std::string_view password, std::string_view method, std::string_view uri,
                                          std::string_view nonce, std::string_view nc, std::string_view cnonce,
                                          std::string_view qop);

//------------------------------------------------------------------------------
// RFC 3310 section 3.2: the nonce of an AKA challenge, base64(RAND || AUTN || server data); none when it is not
// base64 or too short.
struct AkaNonce {
  Rand rand{};
  Autn autn{};
};

[[nodiscard]] std::optional<AkaNonce> parse_nonce(std::string_view nonce);

// Helper: base64 (RFC 4648 section 4) of bytes, as the auts parameter of RFC 3310 section 3.4 carries AUTS.
[[nodiscard]] std::string base64(std::span<const std::uint8_t> bytes);

//------------------------------------------------------------------------------
// RFC 3329 section 2.2 and TS 33.203 annex H: one sec-mechanism of a Security-Client, Security-Server or
// Security-Verify header field ("ipsec-3gpp" with its parameters). Parameters that are absent stay unset.
struct SecMechanism {
  std::string name;
  std::optional<double> q;
  std::string alg;
  std::optional<std::string> ealg, prot, mod;
  std::optional<std::uint32_t> spi_c, spi_s;
  std::optional<std::uint16_t> port_c, port_s;
};

// RFC 3329 section 2.2: the sec-mechanisms of header field values (comma-separated lists); a mechanism with an
// invalid parameter value throws std::invalid_argument.
[[nodiscard]] std::vector<SecMechanism> parse_sec_mechanisms(std::string_view value);

// TS 33.203 annex H: a sec-mechanism in the parameter order of TS 37.579-1 table 5.5.2.13-1 (name, q, alg, ealg, prot,
// mod, spi-c, spi-s, port-c, port-s; absent parameters left out).
[[nodiscard]] std::string format_sec_mechanism(const SecMechanism &mechanism);

//------------------------------------------------------------------------------
// TS 33.203 clause 7.2 and annex H: the UE's choice from a Security-Server: by preference (RFC 3329 section 2.3.1:
// highest q first, then in order) the first mechanism that is "ipsec-3gpp" (case-insensitive) with ESP ("prot"
// absent or "esp") in transport mode ("mod" absent or "trans"), the integrity algorithm the UE supports
// (hmac-sha-1-96) and an encryption algorithm it supports (aes-cbc, or the NULL algorithm when the P-CSCF names none or
// "null", clause 7.2), with all four SPIs and ports; none when nothing is acceptable (clause 7.3.2.2). The chosen
// mechanism's ealg is set ("null" when absent).
[[nodiscard]] std::optional<SecMechanism> select_mechanism(const std::vector<SecMechanism> &server);

//------------------------------------------------------------------------------
// TS 33.203 annex I: IK_ESP and CK_ESP from IK_IM and CK_IM: for hmac-sha-1-96 IK followed by 32 zero bits; for
// aes-cbc CK itself; the NULL encryption algorithm has no key. Other algorithms throw std::invalid_argument.
[[nodiscard]] std::vector<std::uint8_t> integrity_key_esp(std::string_view alg, const Key &ik);
[[nodiscard]] std::vector<std::uint8_t> encryption_key_esp(std::string_view ealg, const Key &ck);

//------------------------------------------------------------------------------
// Helper: 16 or 2 bytes from hexadecimal text (the ISIM configuration's k, opc and amf); throws std::invalid_argument
// on other text.
[[nodiscard]] Key key_from_hex(std::string_view text);
[[nodiscard]] Amf amf_from_hex(std::string_view text);
// Helper: lower-case hexadecimal text of bytes.
[[nodiscard]] std::string hex(std::span<const std::uint8_t> bytes);
} // namespace mcx::aka
