//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MIKEY-SAKKE UID form (TS 33.180 annex F.2.1.1 does not say whether its 32 octets or their base64 text enters
// ECCSI and SAKKE; spec defect, Known limitations "MIKEY-SAKKE UID form"): keys issued for either form, the key set
// detection (raw first, then text) and its refusal under the text-only policy, and ECCSI and SAKKE in each form.
//
// Specifications: TS 33.180 V19.5.0 (Rel-19); RFC 6507, RFC 6508.

#include "mcx/key_documents.hpp"

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace mcx::keying;

//------------------------------------------------------------------------------
// Throws the message when the condition does not hold.
void check(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Whether the action throws.
template <class Action> bool throws(Action action) {
  try {
    action();
  } catch (const std::exception &) {
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
// RFC 4648 section 4: base64 of octets (the expected text form of the UID).
std::string base64(const Bytes &data) {
  static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  std::size_t index = 0;
  for (; index + 2 < data.size(); index += 3) {
    const unsigned value = (data[index] << 16U) | (data[index + 1] << 8U) | data[index + 2];
    out += table[(value >> 18U) & 63U];
    out += table[(value >> 12U) & 63U];
    out += table[(value >> 6U) & 63U];
    out += table[value & 63U];
  }
  if (data.size() - index == 2) {
    const unsigned value = (data[index] << 16U) | (data[index + 1] << 8U);
    out += table[(value >> 18U) & 63U];
    out += table[(value >> 12U) & 63U];
    out += table[(value >> 6U) & 63U];
    out += '=';
  } else if (data.size() - index == 1) {
    const unsigned value = data[index] << 16U;
    out += table[(value >> 18U) & 63U];
    out += table[(value >> 12U) & 63U];
    out += "==";
  }
  return out;
}

//------------------------------------------------------------------------------
// TS 33.180 annex F.2.1.1: the text form is the base64 of the 32 octets; a key set for the 32 octets is found by
// raw_then_text and refused by text_only, a text key set is found as text by both; ECCSI signatures and SAKKE
// encapsulations interwork only within one form.
int main() {
  try {
    const std::uint64_t now = 4000000000ULL;
    const std::string user = "sip:a@example.org";
    const std::string request = "https://kms.example.org/keymanagement/identity/v1/keyprov";
    const Period period{"https://kms.example.org", 2592000, 0};

    const auto raw_uid = uid_raw(user, period, now);
    check(raw_uid.size() == 32, "the UID is the full 256-bit output");
    check(base64(raw_uid) == uid(user, period, now), "the text form is the base64 of the 32 octets");

    const auto text_authority = create_authority(period);
    auto raw_authority = text_authority;
    raw_authority.public_parameters.uid_form = UidForm::raw;
    const auto &text_kms = text_authority.public_parameters; // as parse_kms_init returns it (text)
    const auto &raw_kms = raw_authority.public_parameters;

    const auto text_keys = issue(text_authority, user, now);
    const auto raw_keys = issue(raw_authority, user, now);
    check(text_keys.signing_pair != raw_keys.signing_pair, "keys depend on the UID form");

    // The key set of a KMS whose keys are for the 32 octets: found by raw_then_text, refused by text_only.
    const auto raw_document = kms_keyprov_xml(text_kms, raw_keys, request, now);
    const auto found = parse_kms_keyprov(raw_document, text_kms, user, request, now, nullptr, UidDetection::raw_then_text);
    check(found.uid_form == UidForm::raw && found.signing_pair == raw_keys.signing_pair, "raw key set detected");
    check(throws([&] { parse_kms_keyprov(raw_document, text_kms, user, request, now); }),
          "the text-only policy refuses a raw key set");

    // OpenMCX's key set (text): text under both policies.
    const auto text_document = kms_keyprov_xml(text_kms, text_keys, request, now);
    check(parse_kms_keyprov(text_document, text_kms, user, request, now, nullptr, UidDetection::raw_then_text).uid_form ==
              UidForm::text,
          "text key set detected as text");
    check(parse_kms_keyprov(text_document, text_kms, user, request, now).uid_form == UidForm::text,
          "text key set under the text-only policy");

    // A key set valid in neither form is refused (keys of another user under the same UserUri).
    const auto other = issue(raw_authority, "sip:b@example.org", now);
    auto mismatch = other;
    mismatch.uri = user;
    check(throws([&] {
            parse_kms_keyprov(kms_keyprov_xml(text_kms, mismatch, request, now), text_kms, user, request, now, nullptr,
                              UidDetection::raw_then_text);
          }),
          "a key set valid in neither form is refused");

    // RFC 6507: an ECCSI signature in the raw form verifies only in the raw form.
    const std::array<std::uint8_t, 4> message{1, 2, 3, 4};
    const auto signature = sign(raw_kms, raw_keys, now, message);
    check(verify(raw_kms, user, now, message, signature), "raw ECCSI signature verifies");
    check(!verify(text_kms, user, now, message, signature), "raw ECCSI signature fails as text");
    const auto text_signature = sign(text_kms, text_keys, now, message);
    check(verify(text_kms, user, now, message, text_signature) && !verify(raw_kms, user, now, message, text_signature),
          "text ECCSI signature verifies only as text");

    // RFC 6508: a SAKKE encapsulation to the raw UID opens only with the raw form.
    const std::array<std::uint8_t, 16> key{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};
    const auto data = encapsulate(raw_kms, user, now, key);
    check(decapsulate(raw_kms, raw_keys, now, data) == key, "raw SAKKE round trip");
    bool text_opens = false;
    try {
      text_opens = decapsulate(text_kms, raw_keys, now, data) == key;
    } catch (const std::exception &) {
      text_opens = false;
    }
    check(!text_opens, "raw SAKKE data does not open as text");
    std::cout << "uid form ok\n";
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
  return 0;
}
