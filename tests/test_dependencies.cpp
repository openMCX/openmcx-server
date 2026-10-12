//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Dependency smoke test: PJSIP, libxml2, the AMR-WB encoder and decoder (one frame each way) and libsrtp2 initialise,
// work and shut down.
//
// Specifications: none (third-party libraries only).

#include <libxml/parser.h>
#include <pjlib.h>
#include <pjsip.h>
#include <srtp2/srtp.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <iostream>
#include <opencore-amrwb/dec_if.h>
#include <vo-amrwbenc/enc_if.h>

//------------------------------------------------------------------------------
// Initialises each third-party library, encodes and decodes one AMR-WB frame, parses a minimal XML document and shuts
// everything down again.
int main() {
  if (pj_init() != PJ_SUCCESS || srtp_init() != srtp_err_status_ok) return 1;
  void *encoder = E_IF_init();
  void *decoder = D_IF_init();
  if (!encoder || !decoder) return 2;
  // One 20 ms frame at 16 kHz (320 samples) of a tone, encoded in AMR-WB mode 8 (23.85 kbit/s: 60 octets plus the
  // one-octet header) and decoded again.
  constexpr int samples_per_frame = 320;
  constexpr int mode_23_85 = 8;
  constexpr int mode_23_85_frame_octets = 61;
  std::array<short, samples_per_frame> speech{};
  for (std::size_t index = 0; index < speech.size(); ++index)
    speech[index] = static_cast<short>(8000.0 * std::sin(2.0 * 3.14159265358979 * 440.0 * double(index) / 16000.0));
  std::array<unsigned char, 64> frame{};
  if (E_IF_encode(encoder, mode_23_85, speech.data(), frame.data(), 0) != mode_23_85_frame_octets) return 4;
  std::array<short, samples_per_frame> decoded{};
  D_IF_decode(decoder, frame.data(), decoded.data(), 0);
  if (std::all_of(decoded.begin(), decoded.end(), [](short sample) { return sample == 0; })) return 5;
  xmlDocPtr doc = xmlReadMemory("<mcptt/>", 8, "test.xml", nullptr, XML_PARSE_NONET);
  if (!doc) return 3;
  xmlFreeDoc(doc);
  E_IF_exit(encoder);
  D_IF_exit(decoder);
  srtp_shutdown();
  pj_shutdown();
  std::cout << "PJSIP, XML, AMR-WB encode/decode and SRTP dependency smoke passed\n";
}
