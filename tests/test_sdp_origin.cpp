//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The "o=" line of the SDP one side sends in a dialog (src/sip/helpers.cpp, SdpOrigin): RFC 3264 section 8 keeps the
// <sess-id> of the session and increments its <sess-version> by one for a changed description, and keeps it for an
// unchanged one; RFC 4566 section 5.2 for the fields. Found by the TS 37.579-6 conformance run of the MCVideo client
// (6.1.1.1, 6.1.1.2: every re-INVITE offer and every answer to one had a new <sess-id> and version 1).
//
// Specifications: RFC 3264, RFC 4566; TS 24.281 V19.6.0 clause 6.2.1 (via TS 24.229).

#include "../src/sip/sip_impl.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

// The <sess-id> and <sess-version> of an SDP's "o=" line.
static std::pair<std::string, std::string> origin_of(const std::string &sdp) {
  const auto at = sdp.find("o=- ");
  const auto end = sdp.find("\r\n", at);
  const auto line = sdp.substr(at + 4, end - at - 4);
  const auto first = line.find(' '), second = line.find(' ', first + 1);
  return {line.substr(0, first), line.substr(first + 1, second - first - 1)};
}

static mcx::MediaDescription media() {
  mcx::MediaDescription out;
  out.address = "192.0.2.1";
  out.audio_port = 40000;
  out.floor_port = 40002;
  out.floor_ssrc = 77;
  return out;
}

//------------------------------------------------------------------------------
// RFC 4566 section 5.2: make_sdp writes the given <sess-id> and <sess-version>.
static void Rfc4566_5_2_OriginFields() {
  const auto [id, version] = origin_of(mcx::make_sdp(media(), 4242, 7));
  expect(id == "4242" && version == "7", "o= fields: " + id + " " + version);
}

//------------------------------------------------------------------------------
// RFC 3264 section 8: one <sess-id> for the dialog, the version incremented only for a changed description.
static void Rfc3264_8_SameSessionNewVersion() {
  mcx::SdpOrigin origin;
  auto offer = media();
  const auto first = mcx::next_sdp_origin(origin, offer);
  expect(first.id != 0 && first.version == 1, "first SDP: a new origin with version 1");
  const auto id = first.id;
  mcx::next_sdp_origin(origin, offer);
  expect(origin.id == id && origin.version == 1, "an unchanged description keeps the version");
  offer.implicit_request = true;
  mcx::next_sdp_origin(origin, offer);
  expect(origin.id == id && origin.version == 2, "a changed description increments the version by one");
  offer.audio_port = 40010;
  offer.floor_port = 40012;
  mcx::next_sdp_origin(origin, offer);
  expect(origin.id == id && origin.version == 3, "every change increments it again");
  const auto [text_id, text_version] = origin_of(mcx::make_sdp(offer, origin.id, origin.version));
  expect(text_id == std::to_string(id) && text_version == "3", "the SDP written with the origin");
  mcx::SdpOrigin other;
  mcx::next_sdp_origin(other, offer);
  expect(other.id != id, "another dialog takes another <sess-id>");
}

//------------------------------------------------------------------------------
// RFC 3264 section 8: an SDP the caller wrote itself continues from its own "o=" line.
static void Rfc3264_8_RecordedText() {
  mcx::SdpOrigin origin;
  mcx::record_sdp_text(origin, mcx::make_sdp(media(), 900, 4));
  expect(origin.id == 900 && origin.version == 4, "the recorded origin");
  auto changed = media();
  changed.implicit_request = true;
  mcx::next_sdp_origin(origin, changed);
  expect(origin.id == 900 && origin.version == 5, "the next SDP after a recorded one");
}

int main() {
  const std::vector<std::pair<const char *, void (*)()>> tests = {
      {"Rfc4566_5_2_OriginFields", Rfc4566_5_2_OriginFields},
      {"Rfc3264_8_SameSessionNewVersion", Rfc3264_8_SameSessionNewVersion},
      {"Rfc3264_8_RecordedText", Rfc3264_8_RecordedText},
  };
  int failures = 0;
  for (const auto &[name, test] : tests) {
    try {
      test();
    } catch (const std::exception &error) {
      std::cerr << name << ": " << error.what() << '\n';
      ++failures;
    }
  }
  if (failures == 0) std::cout << tests.size() << " SDP origin tests passed\n";
  return failures == 0 ? 0 : 1;
}
