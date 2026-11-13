//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The ICE attributes of a pre-established session's SDP (include/mcx/protocol.hpp, src/protocol/ice_sdp.cpp): the
// "a=candidate" grammar of RFC 8839 section 5.1, the credentials, "ice-lite" and "ice-options", the layout of
// TS 37.579-1 table 5.5.3.1.1-1 (PRE_ESTABLISHED_SESSION: host candidates for RTP, RTCP and the media plane control
// channel), and what is refused.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 37.579-1 V18.1.0 (Rel-18), RFC 8839, RFC 8445.

#include "mcx/protocol.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

//------------------------------------------------------------------------------
// Checks that the operation throws; what names what would have been wrongly accepted.
static void rejects(const std::function<void()> &operation, const std::string &what) {
  try {
    operation();
  } catch (const std::exception &) {
    return;
  }
  throw std::runtime_error(what + " accepted");
}

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

//------------------------------------------------------------------------------
// Helper: the offer of a pre-established session with host candidates on its default addresses.
static mcx::MediaDescription offer() {
  mcx::MediaDescription media;
  media.address = "192.0.2.1";
  media.audio_port = 40000;
  media.floor_port = 40002;
  media.floor_ssrc = 77;
  mcx::IceDescription ice;
  ice.ufrag = "Ab12";
  ice.pwd = "abcdefghij0123456789+/";
  ice.options = {"ice2"};
  ice.audio = {{"1", 1, "UDP", 2130706431, "192.0.2.1", 40000, "host"},
               {"1", 2, "UDP", 2130706430, "192.0.2.1", 40001, "host"}};
  ice.control = {{"1", 1, "UDP", 2130706431, "192.0.2.1", 40002, "host"}};
  media.ice = ice;
  return media;
}

//------------------------------------------------------------------------------
// RFC 8839 section 5.1: the candidate grammar, the example of section 5.1 and a server reflexive candidate with
// raddr, rport and an extension attribute (ignored).
static void Rfc8839_5_1_Candidate() {
  const auto host = mcx::parse_ice_candidate("1 1 UDP 2130706431 10.0.1.1 8998 typ host");
  expect(host.foundation == "1" && host.component == 1 && host.priority == 2130706431 && host.port == 8998,
         "host candidate fields");
  expect(mcx::ice_candidate_value(host) == "1 1 UDP 2130706431 10.0.1.1 8998 typ host", "host candidate written");
  const auto reflexive =
      mcx::parse_ice_candidate("2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 10.0.1.1 rport 8998 generation 0");
  expect(reflexive.type == "srflx" && reflexive.related_address == "10.0.1.1" && reflexive.related_port == 8998,
         "related address");
  expect(mcx::parse_ice_candidate(mcx::ice_candidate_value(reflexive)) == reflexive, "srflx round trip");
  rejects([] { (void)mcx::parse_ice_candidate("1 1 UDP 1 10.0.1.1 8998 host"); }, "candidate without typ");
  rejects([] { (void)mcx::parse_ice_candidate("1 0 UDP 1 10.0.1.1 8998 typ host"); }, "component 0");
  rejects([] { (void)mcx::parse_ice_candidate("1 1 UDP 4294967296 10.0.1.1 8998 typ host"); }, "priority > 2^32-1");
  rejects([] { (void)mcx::parse_ice_candidate("f=x 1 UDP 1 10.0.1.1 8998 typ host"); }, "foundation with '='");
  rejects([] { (void)mcx::parse_ice_candidate("1 1 UDP 1 10.0.1.1 70000 typ host"); }, "port above 65535");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 8.2.1 step 9, TS 37.579-1 table 5.5.3.1.1-1: the offer carries the credentials at session level,
// RTP and RTCP host candidates in the audio section and one in the application section; it reads back the same.
static void Clause_8_2_1_PreEstablishedOffer() {
  const auto sdp = mcx::make_sdp(offer(), 1);
  const auto session = sdp.find("a=ice-ufrag:Ab12\r\na=ice-pwd:abcdefghij0123456789+/\r\n");
  expect(session != std::string::npos && session < sdp.find("m=audio"), "credentials at session level");
  expect(sdp.find("a=ice-options:ice2\r\n") < sdp.find("m=audio"), "ice-options at session level");
  const auto rtcp = sdp.find("a=candidate:1 2 UDP 2130706430 192.0.2.1 40001 typ host\r\n");
  expect(rtcp != std::string::npos && rtcp < sdp.find("m=application"), "RTCP candidate in the audio section");
  expect(sdp.find("a=candidate:1 1 UDP 2130706431 192.0.2.1 40002 typ host\r\n") > sdp.find("m=application"),
         "control candidate in the application section");
  expect(sdp.find("a=ice-lite") == std::string::npos, "a full agent is not lite");
  const auto parsed = mcx::parse_sdp(sdp);
  expect(parsed.ice && *parsed.ice == *offer().ice, "ICE attributes round trip");
  auto plain = offer();
  plain.ice.reset();
  expect(!mcx::parse_sdp(mcx::make_sdp(plain, 1)).ice, "no ICE attributes, no description");
}

//------------------------------------------------------------------------------
// RFC 8839 sections 5.3 and 5.4: "ice-lite" at session level only; media-level credentials, which must be the same
// in both sections here.
static void Rfc8839_5_4_CredentialsAndLite() {
  auto lite = offer();
  lite.ice->lite = true;
  const auto sdp = mcx::make_sdp(lite, 1);
  expect(sdp.find("a=ice-lite\r\n") < sdp.find("m=audio") && mcx::parse_sdp(sdp).ice->lite, "ice-lite");
  auto media_level = mcx::make_sdp(offer(), 1);
  media_level.erase(media_level.find("a=ice-ufrag:"), std::string("a=ice-ufrag:Ab12\r\n").size());
  media_level.insert(media_level.find("m=application"), "a=ice-ufrag:Ab12\r\n");
  media_level.insert(media_level.find("a=fmtp:MCPTT"), "a=ice-ufrag:Ab12\r\n");
  expect(mcx::parse_sdp(media_level).ice->ufrag == "Ab12", "media-level ufrag");
  auto different = media_level;
  different.replace(different.rfind("a=ice-ufrag:Ab12"), 16, "a=ice-ufrag:Zz99");
  rejects([&] { (void)mcx::parse_sdp(different); }, "different ufrag per section");
  auto media_lite = mcx::make_sdp(offer(), 1);
  media_lite.insert(media_lite.find("a=fmtp:MCPTT"), "a=ice-lite\r\n");
  rejects([&] { (void)mcx::parse_sdp(media_lite); }, "ice-lite at media level");
}

//------------------------------------------------------------------------------
// RFC 8839 sections 5.1 and 5.4: short credentials, a candidate for a component the section does not have, a
// session-level candidate, candidates without credentials, and control candidates without a control channel.
static void Rfc8839_5_4_Refusals() {
  auto short_pwd = offer();
  short_pwd.ice->pwd = "tooshort";
  rejects([&] { (void)mcx::make_sdp(short_pwd, 1); }, "ice-pwd of 8 characters");
  auto third = offer();
  third.ice->audio.push_back({"1", 3, "UDP", 1, "192.0.2.1", 40004, "host"});
  rejects([&] { (void)mcx::make_sdp(third, 1); }, "audio component 3");
  auto sdp = mcx::make_sdp(offer(), 1);
  auto session_candidate = sdp;
  session_candidate.insert(session_candidate.find("m=audio"), "a=candidate:9 1 UDP 1 192.0.2.1 9 typ host\r\n");
  rejects([&] { (void)mcx::parse_sdp(session_candidate); }, "session-level candidate");
  auto no_credentials = sdp;
  no_credentials.erase(no_credentials.find("a=ice-pwd:"), std::string("a=ice-pwd:abcdefghij0123456789+/\r\n").size());
  rejects([&] { (void)mcx::parse_sdp(no_credentials); }, "candidates without ice-pwd");
  auto no_floor = offer();
  no_floor.control = mcx::MediaControl::none;
  no_floor.floor_port = 0;
  no_floor.floor_ssrc = 0;
  rejects([&] { (void)mcx::make_sdp(no_floor, 1); }, "control candidates without a control channel");
  no_floor.ice->control.clear();
  expect(mcx::parse_sdp(mcx::make_sdp(no_floor, 1)).ice->audio.size() == 2, "private call without floor control");
}

//------------------------------------------------------------------------------
// RFC 3264 section 8.2 (MediaDescription::control_removed): a call over the session without floor control removes the
// session's media-floor control stream with port 0 (no attributes, no candidates); the other streams stay. The
// session's negotiated media keep the control channel it had (session_media_keeping_control). Only that stream may
// be removed.
static void Rfc3264_8_2_RemovedControlStream() {
  const auto session = offer();
  auto call = session;
  call.control = mcx::MediaControl::none;
  call.control_removed = true;
  call.floor_ssrc = 0;
  call.ice->control.clear();
  const auto sdp = mcx::make_sdp(call, 1);
  expect(sdp.find("m=application 0 udp MCPTT\r\n") != std::string::npos, "port-0 m=application line");
  expect(sdp.find("a=fmtp:MCPTT") == std::string::npos, "no attributes of the removed stream");
  const auto parsed = mcx::parse_sdp(sdp);
  expect(parsed.control == mcx::MediaControl::none && parsed.control_removed, "parsed: removed, no control");
  expect(parsed.ice && parsed.ice->control.empty() && parsed.ice->audio.size() == 2, "parsed: audio candidates");
  const auto kept = mcx::session_media_keeping_control(parsed, session);
  expect(kept.control == mcx::MediaControl::floor && kept.floor_port == 40002 && kept.floor_ssrc == 77 &&
             !kept.control_removed && kept.ice->control.size() == 1,
         "the session keeps its control channel");
  expect(mcx::session_media_keeping_control(mcx::parse_sdp(mcx::make_sdp(session, 1)), std::nullopt).floor_port ==
             40002,
         "an answer with the stream: unchanged");
  auto audio_removed = mcx::make_sdp(session, 1);
  audio_removed.replace(audio_removed.find("m=audio 40000"), 13, "m=audio 0");
  rejects([&] { (void)mcx::parse_sdp(audio_removed); }, "removed speech stream");
}

//------------------------------------------------------------------------------
// SdpReadOptions: the TS 37.579 test system's answer to the INVITE creating a pre-established session (the R&S trace
// R5s260356 of TC_6_1_1_5_MCPTT): an ICE lite peer's candidates without credentials, and floor control without
// "mc_floor_ssrc" (TS 24.380 clause 14.3.8: only with multiplexing). Refused by default (an OpenMCX server's reading
// of a client); with the options, read without ICE and with floor_ssrc 0. A credential alone, and an
// "mc_floor_ssrc" of 0, are refused either way.
static void SdpReadOptions_TestSystemAnswer() {
  const std::string answer = "v=0\r\no=- 1111111111 1111111111 IN IP4 172.22.1.201\r\ns= \r\nb=AS:38\r\nt=0 0\r\n"
                             "a=ice-lite\r\nm=audio 60350 RTP/SAVP 114\r\ni=speech\r\nc=IN IP4 172.22.1.201\r\n"
                             "b=AS:38\r\nb=RS:0\r\nb=RR:2000\r\na=rtpmap:114 AMR-WB/16000/1\r\n"
                             "a=fmtp:114 mode-change-capability=2;max-red=0\r\na=ptime:20\r\na=maxptime:240\r\n"
                             "a=candidate:1234 1 UDP 2130706431 172.22.1.201 60350 typ host\r\n"
                             "a=candidate:1234 2 UDP 2130706430 172.22.1.201 60351 typ host\r\n"
                             "m=application 60354 udp MCPTT\r\nc=IN IP4 172.22.1.201\r\n"
                             "a=fmtp:MCPTT mc_queueing;mc_priority=3\r\n"
                             "a=candidate:4321 1 UDP 2130706431 172.22.1.201 60354 typ host\r\n";
  rejects([&] { (void)mcx::parse_sdp(answer); }, "no mc_floor_ssrc, no credentials (default)");
  const mcx::SdpReadOptions lenient{.floor_ssrc_optional = true, .ice_without_credentials = true};
  const auto media = mcx::parse_sdp(answer, lenient);
  expect(media.control == mcx::MediaControl::floor && media.floor_ssrc == 0, "floor control without its SSRC");
  expect(!media.ice, "candidates without credentials: no ICE");
  expect(media.address == "172.22.1.201" && media.audio_port == 60350 && media.floor_port == 60354 &&
             media.queueing && media.floor_priority == 3,
         "the default addresses and the floor parameters");
  rejects([&] { (void)mcx::parse_sdp(answer, {.floor_ssrc_optional = true}); }, "candidates without credentials");
  auto with_ssrc = answer;
  with_ssrc.replace(with_ssrc.find("mc_queueing;"), 12, "mc_queueing;mc_floor_ssrc=9;");
  rejects([&] { (void)mcx::parse_sdp(with_ssrc); }, "candidates without credentials (default)");
  const auto multiplexing = mcx::parse_sdp(with_ssrc, {.ice_without_credentials = true});
  expect(multiplexing.floor_ssrc == 9 && !multiplexing.ice, "an mc_floor_ssrc is read as before");
  auto ufrag_only = answer;
  ufrag_only.insert(ufrag_only.find("m=audio"), "a=ice-ufrag:abcd\r\n");
  rejects([&] { (void)mcx::parse_sdp(ufrag_only, lenient); }, "a ufrag without a pwd");
  auto zero = answer;
  zero.replace(zero.find("mc_queueing;"), 12, "mc_queueing;mc_floor_ssrc=0;");
  rejects([&] { (void)mcx::parse_sdp(zero, lenient); }, "mc_floor_ssrc 0");
}

int main() {
  const std::vector<std::pair<const char *, void (*)()>> tests = {
      {"Rfc8839_5_1_Candidate", Rfc8839_5_1_Candidate},
      {"Clause_8_2_1_PreEstablishedOffer", Clause_8_2_1_PreEstablishedOffer},
      {"Rfc8839_5_4_CredentialsAndLite", Rfc8839_5_4_CredentialsAndLite},
      {"Rfc8839_5_4_Refusals", Rfc8839_5_4_Refusals},
      {"Rfc3264_8_2_RemovedControlStream", Rfc3264_8_2_RemovedControlStream},
      {"SdpReadOptions_TestSystemAnswer", SdpReadOptions_TestSystemAnswer},
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
  if (failures == 0) std::cout << tests.size() << " ICE SDP tests passed\n";
  return failures == 0 ? 0 : 1;
}
