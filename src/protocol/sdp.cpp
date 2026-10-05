// SDP offers and answers: the MCPTT and MCVideo media (AMR-WB speech, H.264 video) with their floor or transmission
// control channel, and the MCData MSRP media.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), TS 24.380 V19.2.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19),
// TS 24.581 V19.2.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.582 V19.0.0, TS 24.229, RFC 4566, RFC 3264,
// RFC 4567, RFC 4867, RFC 6184, RFC 5576, RFC 3605, RFC 4975, RFC 4145, RFC 5547.

#include <algorithm>

#include "protocol_internal.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// RFC 4567: checks the key management data of "a=key-mgmt:mikey", which is base64.
static void key_mgmt_data(std::string_view data) {
  if (data.empty() || data.size() > 87380 || data.size() % 4) invalid("invalid key management data");
  for (std::size_t index = 0; index < data.size(); ++index) {
    const char character = data[index];
    const bool padding = character == '=' && index + 2 >= data.size();
    if (!padding && !std::isalnum(static_cast<unsigned char>(character)) && character != '+' && character != '/')
      invalid("invalid key management data");
  }
}

//------------------------------------------------------------------------------
// RFC 4566 section 6 and RFC 3264 section 5.1: whether a value is a media direction attribute. The MC service
// procedures use sendrecv, sendonly and recvonly; inactive (RFC 3264 section 8.4, a held stream) is read and written
// as well, so that every SDP parse_sdp accepts can be written back.
static bool media_direction(std::string_view value) {
  return value == "sendrecv" || value == "sendonly" || value == "recvonly" || value == "inactive";
}

//------------------------------------------------------------------------------
// RFC 4566 section 5: the first line of an SDP session description is "v=".
static void version_first(std::string_view sdp) {
  if (!sdp.starts_with("v=")) invalid("SDP must start with v=");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.2.1 and clause 6.2.2 with TS 24.380 clause 14.2 and clause 14.3 (MCPTT), TS 24.281 clause
// 6.2.1 and clause 6.2.2 with TS 24.581 clause 12.1.2 (MCVideo): writes the SDP offer or answer: AMR-WB audio
// (RFC 4867), H.264 video for MCVideo (RFC 6184), and the "m=application" media plane control channel with its
// fmtp parameters.
std::string make_sdp(const MediaDescription &media, std::uint64_t session_id) {
  address(media.address);
  if (!media.floor_address.empty()) address(media.floor_address);
  if (!media_direction(media.direction)) invalid("unsupported SDP media direction");
  // Without media plane control (MediaControl::none) the service is told by the
  // video section: an MCVideo call has one (TS 24.281 clause 10.2.3), MCPTT none (TS 24.379 clause 11.1.2).
  const bool video =
      media.control == MediaControl::transmission || (media.control == MediaControl::none && media.video);
  const bool controlled = media.control != MediaControl::none;
  if (!media.audio_port || media.payload_type < 96 || media.payload_type > 127 ||
      (controlled && (!media.floor_port || media.audio_port == media.floor_port ||
                      media.floor_port == media.rtcp_port || !media.floor_ssrc)))
    invalid("invalid SDP media configuration");
  // TS 24.281 clause 6.2.1: an MCVideo offer has an audio and a video section; MCPTT has no video.
  if (video != media.video.has_value()) invalid("video media belongs to MCVideo transmission control");
  if (video) {
    const auto &video_media = *media.video;
    if (!video_media.port || video_media.port == media.audio_port || video_media.port == media.rtcp_port ||
        (controlled && video_media.port == media.floor_port) ||
        (video_media.rtcp_port &&
         ((controlled && video_media.rtcp_port == media.floor_port) || video_media.rtcp_port == media.audio_port)) ||
        video_media.payload_type < 96 || video_media.payload_type > 127 ||
        video_media.payload_type == media.payload_type || video_media.packetization_mode > 1 ||
        video_media.profile_level_id.size() != 6 ||
        video_media.profile_level_id.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
      invalid("invalid SDP video configuration");
    if (!media_direction(video_media.direction)) invalid("unsupported SDP media direction");
  } else if (media.granted || media.granted_audio_ssrc || media.granted_video_ssrc)
    invalid("transmission control parameters in an MCPTT SDP");
  std::ostringstream out;
  out << "v=0\r\no=- " << session_id << " 1 IN IP4 " << media.address << "\r\ns=" << (video ? "MCVideo" : "MCPTT")
      << "\r\nc=IN IP4 " << media.address << "\r\nt=0 0\r\n";
  if (!media.key_mgmt.empty()) {
    if (!media.protected_media) invalid("key management requires protected media");
    key_mgmt_data(media.key_mgmt);
    out << "a=key-mgmt:mikey " << media.key_mgmt << "\r\n";
  }
  out << "m=audio " << media.audio_port << ' ' << (media.protected_media ? "RTP/SAVP" : "RTP/AVP") << ' '
      << unsigned(media.payload_type) << "\r\ni=" << (video ? "audio component of MCVideo" : "speech")
      << "\r\na=rtpmap:" << unsigned(media.payload_type) << " AMR-WB/16000/1\r\na=fmtp:" << unsigned(media.payload_type)
      << " octet-align=" << (media.octet_aligned ? 1 : 0)
      // TS 26.179 clause 4.1.3: mode-change-capability "2", max-red "0", ptime "20" and maxptime "240" offered;
      // no mode-set (all modes); one channel.
      << ";mode-change-capability=2;max-red=0\r\na=ptime:20\r\na=maxptime:240\r\na=" << media.direction << "\r\n";
  if (media.rtcp_port) out << "a=rtcp:" << media.rtcp_port << "\r\n";
  if (media.audio_ssrc) out << "a=ssrc:" << media.audio_ssrc << " cname:" << (video ? "mcvideo" : "mcptt") << "\r\n";
  if (video) {
    // TS 24.281 clause 6.2.1 step 3 with RFC 6184 section 8.2.1.
    const auto &video_media = *media.video;
    out << "m=video " << video_media.port << ' ' << (media.protected_media ? "RTP/SAVP" : "RTP/AVP") << ' '
        << unsigned(video_media.payload_type)
        << "\r\ni=video component of MCVideo\r\na=rtpmap:" << unsigned(video_media.payload_type)
        << " H264/90000\r\na=fmtp:" << unsigned(video_media.payload_type)
        << " profile-level-id=" << video_media.profile_level_id
        << ";packetization-mode=" << video_media.packetization_mode << "\r\na=" << video_media.direction << "\r\n";
    if (video_media.rtcp_port) out << "a=rtcp:" << video_media.rtcp_port << "\r\n";
    if (video_media.ssrc) out << "a=ssrc:" << video_media.ssrc << " cname:mcvideo\r\n";
  }
  if (!controlled) {
    if (media.granted || media.granted_audio_ssrc || media.granted_video_ssrc || media.implicit_request ||
        media.queueing || media.floor_priority)
      invalid(video ? "transmission control parameters without transmission control"
                    : "floor control parameters without floor control");
    return out.str();
  }
  const char *control = video ? "MCVideo" : "MCPTT";
  out << "m=application " << media.floor_port << " udp " << control << "\r\n";
  if (!media.floor_address.empty() && media.floor_address != media.address)
    out << "c=IN IP4 " << media.floor_address << "\r\n";
  // TS 24.380 clause 14.2.7 (mc_floor_ssrc) or TS 24.581 clause 14.2.7 (mc_transmission_ssrc); the
  // parameters are ';'-separated as for MCPTT.
  out << "a=fmtp:" << control << (video ? " mc_transmission_ssrc=" : " mc_floor_ssrc=") << media.floor_ssrc;
  if (media.floor_priority) {
    if (*media.floor_priority > 99) invalid("floor priority exceeds SDP range");
    out << ";mc_priority=" << unsigned(*media.floor_priority);
  }
  if (media.queueing) out << ";mc_queueing";
  if (media.implicit_request) out << ";mc_implicit_request";
  if (media.granted) out << ";mc_granted";
  if (media.granted_audio_ssrc) out << ";mc_audio_ssrc=" << media.granted_audio_ssrc;
  if (media.granted_video_ssrc) out << ";mc_video_ssrc=" << media.granted_video_ssrc;
  out << "\r\n";
  return out.str();
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.3.2.1 and clause 10.2.5.2.1 with TS 24.582: writes the MCData SDP, an "m=message" section
// carrying MSRP (RFC 4975), with the local MSRP URI in "a=path", "a=setup" (RFC 4145), the accepted types and
// the file attributes of RFC 5547.
std::string msrp_sdp(const MsrpMedia &media, std::uint64_t session_id) {
  address(media.address);
  if (!media.port || media.path.empty()) invalid("invalid MSRP media configuration");
  if (media.setup != "actpass" && media.setup != "active" && media.setup != "passive")
    invalid("invalid MSRP setup attribute");
  if (media.direction != "sendonly" && media.direction != "recvonly" && media.direction != "sendrecv")
    invalid("unsupported SDP media direction");
  if (media.accept_types.empty()) invalid("MSRP media needs accepted types");
  std::ostringstream out;
  out << "v=0\r\no=- " << session_id << " 1 IN IP4 " << media.address << "\r\ns=MCData\r\nc=IN IP4 " << media.address
      << "\r\nt=0 0\r\n";
  if (!media.key_mgmt.empty()) {
    key_mgmt_data(media.key_mgmt);
    out << "a=key-mgmt:mikey " << media.key_mgmt << "\r\n";
  }
  out << "m=message " << media.port << ' ' << (media.secure ? "TCP/TLS/MSRP" : "TCP/MSRP")
      << " *\r\na=path:" << media.path << "\r\na=setup:" << media.setup << "\r\na=accept-types:";
  for (std::size_t index = 0; index < media.accept_types.size(); ++index)
    out << (index ? " " : "") << media.accept_types[index];
  out << "\r\na=" << media.direction << "\r\n";
  if (!media.file_selector.empty()) out << "a=file-selector:" << media.file_selector << "\r\n";
  if (!media.file_date.empty()) out << "a=file-date:" << media.file_date << "\r\n";
  if (!media.file_description.empty()) out << "a=file-description:" << media.file_description << "\r\n";
  return out.str();
}

//------------------------------------------------------------------------------
// TS 24.282 clause 9.2.3.2.1 and clause 10.2.5.2.1 with TS 24.582: reads the MCData SDP: the connection address,
// the "m=message" MSRP section (RFC 4975) with its path, setup (RFC 4145), accepted types, direction and file
// attributes (RFC 5547), and the MIKEY key management (RFC 4567).
MsrpMedia parse_msrp_sdp(std::string_view sdp) {
  bounded(sdp);
  version_first(sdp);
  MsrpMedia out;
  bool message = false, version = false;
  for (auto line : tokens(sdp, '\n')) {
    if (line.size() < 2 || line[1] != '=') invalid("malformed SDP line");
    const auto value = std::string_view(line).substr(2);
    switch (line[0]) {
    case 'v':
      if (value != "0") invalid("unsupported SDP version");
      version = true;
      break;
    case 'c': {
      const auto parts = tokens(value, ' ');
      if (parts.size() != 3 || parts[0] != "IN" || parts[1] != "IP4") invalid("unsupported SDP connection");
      address(parts[2]);
      out.address = parts[2];
      break;
    }
    case 'm': {
      const auto parts = tokens(value, ' ');
      if (parts.size() < 3 || parts[0] != "message") {
        message = false; // another media section: MCData reads only "m=message"
        break;
      }
      if (parts[2] != "TCP/MSRP" && parts[2] != "TCP/TLS/MSRP") invalid("unsupported MSRP transport");
      out.secure = parts[2] == "TCP/TLS/MSRP";
      out.port = static_cast<std::uint16_t>(number(parts[1], 65535));
      if (!out.port) invalid("invalid MSRP port");
      message = true;
      break;
    }
    case 'a': {
      if (value.starts_with("key-mgmt:")) {
        const auto fields = tokens(value.substr(9), ' ');
        if (fields.size() != 2 || fields[0] != "mikey" || !out.key_mgmt.empty())
          invalid("unsupported or duplicate key management");
        key_mgmt_data(fields[1]);
        out.key_mgmt = fields[1];
        break;
      }
      if (!message) break;
      const auto colon = value.find(':');
      const auto name = value.substr(0, colon);
      const auto rest = colon == std::string_view::npos ? std::string_view{} : value.substr(colon + 1);
      if (name == "path")
        out.path = std::string(rest);
      else if (name == "setup")
        out.setup = std::string(rest);
      else if (name == "accept-types")
        out.accept_types = tokens(rest, ' ');
      else if (name == "file-selector")
        out.file_selector = std::string(rest);
      else if (name == "file-date")
        out.file_date = std::string(rest);
      else if (name == "file-description")
        out.file_description = std::string(rest);
      else if (name == "sendonly" || name == "recvonly" || name == "sendrecv")
        out.direction = std::string(name);
      break;
    }
    default: break;
    }
  }
  if (!version || out.address.empty()) invalid("incomplete SDP");
  if (!out.port || out.path.empty()) invalid("SDP without an MSRP media stream");
  if (out.setup != "actpass" && out.setup != "active" && out.setup != "passive")
    invalid("invalid MSRP setup attribute");
  return out;
}

namespace {

// The state of an SDP being read: the current media section and what has been seen so far.
struct SdpState {
  std::string section, session_address;
  bool audio = false, floor = false, version = false;
  std::string audio_address, video_address, control_name;
  bool matched_video_codec = false;
  std::uint16_t rtcp = 0;
  bool matched_codec = false;
};

//------------------------------------------------------------------------------
// RFC 4566 section 5.14 with TS 24.379 clause 6.2.1, TS 24.380 clause 14.2 and TS 24.281 clause 6.2.1: an "m="
// line: the AMR-WB audio, the H.264 video of MCVideo, or the "m=application" floor or transmission control
// channel.
void parse_media_line(const std::string &value, MediaDescription &out, SdpState &state) {
  auto fields = tokens(value, ' ');
  if (fields.size() != 4) invalid("unsupported SDP media formats");
  state.section = fields[0];
  auto port = number(fields[1], 65535);
  if (!port) invalid("disabled media is unsupported");
  if (state.section == "audio") {
    if (state.audio) invalid("duplicate SDP audio");
    state.audio = true;
    out.audio_port = port;
    if (fields[2] != "RTP/AVP" && fields[2] != "RTP/SAVP") invalid("unsupported RTP profile");
    out.protected_media = fields[2] == "RTP/SAVP";
    out.payload_type = number(fields[3], 127);
    if (out.payload_type < 96) invalid("AMR-WB requires dynamic payload type");
  } else if (state.section == "video") {
    // TS 24.281 clause 6.2.1 step 3: one H.264 video stream (MCVideo only).
    if (out.video) invalid("duplicate SDP video");
    if (fields[2] != "RTP/AVP" && fields[2] != "RTP/SAVP") invalid("unsupported RTP profile");
    VideoMedia video_media;
    video_media.port = port;
    video_media.payload_type = number(fields[3], 127);
    if (video_media.payload_type < 96) invalid("H.264 requires dynamic payload type");
    if ((fields[2] == "RTP/SAVP") != out.protected_media && state.audio) invalid("mixed protected and clear media");
    out.video = video_media;
  } else if (state.section == "application") {
    if (state.floor || fields[2] != "udp" || (fields[3] != "MCPTT" && fields[3] != "MCVideo"))
      invalid("unsupported floor media");
    state.floor = true;
    state.control_name = fields[3];
    out.control = fields[3] == "MCVideo" ? MediaControl::transmission : MediaControl::floor;
    out.floor_port = port;
  } else
    invalid("unsupported SDP media");
}

//------------------------------------------------------------------------------
// RFC 4566 section 5.7: a "c=" line, of the session or of the current media section.
void parse_connection_line(const std::string &value, MediaDescription &out, SdpState &state) {
  auto fields = tokens(value, ' ');
  if (fields.size() != 3 || fields[0] != "IN" || fields[1] != "IP4") invalid("unsupported SDP connection");
  address(fields[2]);
  if (state.section.empty())
    state.session_address = fields[2];
  else if (state.section == "audio")
    state.audio_address = fields[2];
  else if (state.section == "video")
    state.video_address = fields[2];
  else
    out.floor_address = fields[2];
}

//------------------------------------------------------------------------------
// RFC 6184 section 8.1 with TS 24.281 clause 6.2.1 step 3: the "a=fmtp" line of the H.264 video.
void parse_video_format(const std::string &value, VideoMedia &video) {
  auto space = value.find(' ');
  if (space == value.npos || number(value.substr(5, space - 5), 127) != video.payload_type)
    invalid("conflicting SDP format");
  // RFC 6184 section 8.1; other parameters (sprop-parameter-sets and the like) are not needed here.
  for (auto parameter : tokens(value.substr(space + 1), ';')) {
    auto eq = parameter.find('=');
    auto key = trim(parameter.substr(0, eq));
    auto val = eq == parameter.npos ? "" : trim(parameter.substr(eq + 1));
    if (key == "packetization-mode")
      video.packetization_mode = number(val, 1);
    else if (key == "profile-level-id") {
      if (val.size() != 6 || val.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        invalid("invalid H.264 profile-level-id");
      video.profile_level_id = val;
    }
  }
}

//------------------------------------------------------------------------------
// TS 24.281 clause 6.2.1 step 3 with RFC 6184 section 8.2.1: an attribute of the "m=video" section: rtpmap,
// direction (RFC 4566), ssrc (RFC 5576), rtcp (RFC 3605) and fmtp.
void parse_video_attribute(const std::string &line, const std::string &value, VideoMedia &video, SdpState &state) {
  if (line.starts_with("a=rtpmap:")) {
    auto fields = tokens(value.substr(7), ' ');
    if (fields.size() != 2 || number(fields[0], 127) != video.payload_type) invalid("conflicting SDP payload mapping");
    if (fields[1] != "H264/90000") invalid("unsupported video codec");
    state.matched_video_codec = true;
  } else if (media_direction(value) && line.starts_with("a=")) {
    video.direction = std::string(value);
  } else if (line.starts_with("a=ssrc:")) {
    // RFC 5576: the SSRC the offerer sends its video with (TS 24.281 clause 6.2.1 step 3 e).
    const auto fields = tokens(value.substr(5), ' ');
    if (fields.empty()) invalid("invalid SDP ssrc");
    const auto ssrc = number(fields[0], UINT32_MAX);
    if (video.ssrc && video.ssrc != ssrc) invalid("conflicting video SSRCs");
    video.ssrc = ssrc;
  } else if (line.starts_with("a=rtcp:")) {
    auto parameters = tokens(value.substr(5), ' ');
    if (parameters.size() != 1) invalid("RTCP requires one port in this profile");
    video.rtcp_port = number(parameters.front(), 65535);
  } else if (line.starts_with("a=fmtp:")) {
    parse_video_format(value, video);
  }
}

//------------------------------------------------------------------------------
// RFC 4867 section 8.1 (AMR-WB), TS 24.380 clause 14.2 and TS 24.581 clause 14.2: one fmtp parameter of the audio
// or of the floor or transmission control channel.
void parse_format_parameter(const std::string &parameter, const std::string &section, bool transmission,
                            MediaDescription &out) {
  auto eq = parameter.find('=');
  auto key = trim(parameter.substr(0, eq));
  auto val = eq == parameter.npos ? "" : trim(parameter.substr(eq + 1));
  if (section == "audio" && key == "octet-align")
    out.octet_aligned = number(val, 1) == 1;
  else if (section == "audio" && (key == "interleaving" || key == "crc" || key == "robust-sorting") && val != "0")
    invalid("unsupported AMR-WB payload option");
  else if (section == "audio" && key == "mode-set") {
    // RFC 4867 section 8.1: a comma-separated list of the AMR-WB modes 0 to 8.
    out.mode_set.clear();
    std::size_t start = 0;
    while (start <= val.size()) {
      const auto end = std::min(val.find(',', start), val.size());
      const auto mode = static_cast<std::uint8_t>(number(trim(val.substr(start, end - start)), 8));
      if (std::find(out.mode_set.begin(), out.mode_set.end(), mode) == out.mode_set.end()) out.mode_set.push_back(mode);
      start = end + 1;
    }
  }
  else if (transmission && key == "mc_transmission_ssrc") {
    if (out.floor_ssrc) invalid("duplicate transmission control SSRC");
    out.floor_ssrc = number(val, UINT32_MAX);
  } else if (transmission && key == "mc_granted")
    out.granted = true;
  else if (transmission && key == "mc_audio_ssrc")
    out.granted_audio_ssrc = number(val, UINT32_MAX);
  else if (transmission && key == "mc_video_ssrc")
    out.granted_video_ssrc = number(val, UINT32_MAX);
  else if (section == "application" && !transmission && key == "mc_floor_ssrc") {
    if (out.floor_ssrc) invalid("duplicate floor SSRC");
    out.floor_ssrc = number(val, UINT32_MAX);
  } else if (section == "application" && key == "mc_priority") {
    if (out.floor_priority || val.size() > 2) invalid("duplicate or invalid floor priority");
    out.floor_priority = number(val, 99);
  } else if (section == "application" && key == "mc_queueing")
    out.queueing = true;
  else if (section == "application" && key == "mc_implicit_request")
    out.implicit_request = true;
  else if (section == "application" && !transmission && key == "mc_no_floor_ctrl")
    invalid("call requires floor control");
}

//------------------------------------------------------------------------------
// TS 24.380 clause 14.2 (MCPTT) and TS 24.581 clause 14.2 (MCVideo) with RFC 4867 section 8.1: an "a=fmtp" line
// outside the video section: the AMR-WB parameters or those of the media plane control channel.
void parse_format(const std::string &value, MediaDescription &out, const SdpState &state) {
  const auto &section = state.section;
  auto space = value.find(' ');
  if (space == value.npos) invalid("invalid SDP format parameters");
  auto format = value.substr(5, space - 5);
  if (section == "audio" && number(format, 127) != out.payload_type) invalid("conflicting SDP format");
  if (section == "application" && format != state.control_name) invalid("conflicting floor format");
  const bool transmission = section == "application" && out.control == MediaControl::transmission;
  // TS 24.581 clause 12.1.2.3 lists the MCVideo parameters with COLON between them;
  // ';' as in TS 24.380 clause 12.1.2.3 is accepted as well, and is what openMCX sends.
  auto parameters = tokens(value.substr(space + 1), ';');
  if (transmission) {
    std::vector<std::string> split;
    for (const auto &parameter : parameters)
      for (auto piece : tokens(parameter, ':')) split.push_back(piece);
    parameters = split;
  }
  for (const auto &parameter : parameters) parse_format_parameter(parameter, section, transmission, out);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.2.1 with RFC 4566, RFC 4567 and RFC 5576: an attribute of the session or of the "m=audio" or
// "m=application" section: rtpmap, direction, key-mgmt, ssrc, rtcp (RFC 3605) and fmtp.
void parse_attribute(const std::string &line, const std::string &value, MediaDescription &out, SdpState &state) {
  const auto &section = state.section;
  if (section == "audio" && line.starts_with("a=rtpmap:")) {
    auto fields = tokens(value.substr(7), ' ');
    if (fields.size() != 2 || number(fields[0], 127) != out.payload_type) invalid("conflicting SDP payload mapping");
    if (fields[1] != "AMR-WB/16000/1" && fields[1] != "AMR-WB/16000") invalid("unsupported codec");
    state.matched_codec = true;
  } else if (section == "audio" && media_direction(value) && line.starts_with("a=")) {
    // RFC 4566 direction; TS 24.379 clause 6.2.1 uses sendonly/recvonly in ambient listening offers.
    out.direction = std::string(value);
  } else if ((section.empty() || section == "audio") && line.starts_with("a=key-mgmt:")) {
    auto fields = tokens(value.substr(9), ' ');
    if (fields.size() != 2 || fields[0] != "mikey" || !out.key_mgmt.empty())
      invalid("unsupported or duplicate key management");
    key_mgmt_data(fields[1]);
    out.key_mgmt = std::string(fields[1]);
  } else if (section == "audio" && line.starts_with("a=ssrc:")) {
    // RFC 5576: the SSRC the offerer sends its speech with; what a private call
    // without floor control (TS 24.379 clause 11.1.2) is relayed with.
    const auto fields = tokens(value.substr(5), ' ');
    if (fields.empty()) invalid("invalid SDP ssrc");
    const auto ssrc = number(fields[0], UINT32_MAX);
    if (out.audio_ssrc && out.audio_ssrc != ssrc) invalid("conflicting audio SSRCs");
    out.audio_ssrc = ssrc;
  } else if (section == "audio" && line.starts_with("a=rtcp:")) {
    auto parameters = tokens(value.substr(5), ' ');
    if (parameters.size() != 1) invalid("RTCP requires one port in this profile");
    state.rtcp = number(parameters.front(), 65535);
  } else if (line.starts_with("a=fmtp:")) {
    // RFC 4566 section 6: "a=fmtp" is a media-level attribute only.
    if (section.empty()) invalid("SDP format parameters outside a media section");
    parse_format(value, out, state);
  }
}

//------------------------------------------------------------------------------
// TS 24.379 clause 6.2.1, TS 24.380 clause 14.2 and TS 24.281 clause 6.2.1 step 3: completes and checks the
// description once every line is read: the addresses, the media plane control, the video and the ports.
void finish_sdp(MediaDescription &out, const SdpState &state) {
  out.address = state.audio_address.empty() ? state.session_address : state.audio_address;
  if (out.floor_address.empty())
    out.floor_address = state.session_address.empty() ? out.address : state.session_address;
  address(out.address);
  address(out.floor_address);
  // An SDP without "m=application" has no media plane control: an MCVideo private
  // call without transmission control (TS 24.281 clause 10.2.3) or an MCPTT private call
  // without floor control (TS 24.379 clause 11.1.2). Whether the call allows it is the
  // server's decision.
  if (!state.floor) out.control = MediaControl::none;
  if (!state.version || !state.audio || !state.matched_codec || (state.floor && !out.floor_ssrc))
    invalid("incomplete MCPTT SDP");
  // MCPTT floor control has no video section, and MCVideo transmission control needs
  // one (TS 24.281 clause 6.2.1 step 3).
  if (out.video && out.control == MediaControl::floor) invalid("unsupported SDP media");
  if (!out.video && out.control == MediaControl::transmission) invalid("incomplete MCVideo SDP");
  if (out.video) {
    if (!state.matched_video_codec) invalid("incomplete MCVideo SDP");
    if (!state.video_address.empty() && state.video_address != out.address)
      invalid("a separate video address is not supported");
  }
  if (!out.key_mgmt.empty() && !out.protected_media) invalid("key management requires protected media");
  out.rtcp_port = state.rtcp ? state.rtcp : (out.audio_port < 65535 ? out.audio_port + 1 : 0);
  if (!out.rtcp_port || out.floor_port == out.rtcp_port || out.floor_port == out.audio_port)
    invalid("overlapping SDP ports");
  // The same overlaps make_sdp refuses: the video RTP port against the audio RTP and RTCP ports and the control port,
  // the video RTCP port (RFC 3605) against the audio RTP port and the control port.
  if (out.video) {
    const auto &video_media = *out.video;
    if (video_media.port == out.audio_port || video_media.port == out.rtcp_port ||
        (out.floor_port && video_media.port == out.floor_port) || video_media.payload_type == out.payload_type ||
        (video_media.rtcp_port &&
         (video_media.rtcp_port == out.audio_port || (out.floor_port && video_media.rtcp_port == out.floor_port))))
      invalid("overlapping SDP ports");
  }
}

} // namespace

//------------------------------------------------------------------------------
// TS 24.379 clause 6.2.1 and clause 6.2.2 with TS 24.380 clause 14.2 and clause 14.3 (MCPTT), TS 24.281 clause
// 6.2.1 with TS 24.581 clause 12.1.2 (MCVideo): reads an SDP offer or answer: the AMR-WB audio, the H.264 video
// of MCVideo, and the floor or transmission control channel with its fmtp parameters.
MediaDescription parse_sdp(std::string_view sdp) {
  bounded(sdp);
  version_first(sdp);
  MediaDescription out;
  SdpState state;
  for (auto line : tokens(sdp, '\n')) {
    if (line.size() < 2 || line[1] != '=') invalid("malformed SDP line");
    auto value = line.substr(2);
    if (line.starts_with("v=")) {
      if (state.version || value != "0") invalid("invalid SDP version");
      state.version = true;
    }
    if (line.starts_with("m="))
      parse_media_line(value, out, state);
    else if (line.starts_with("c="))
      parse_connection_line(value, out, state);
    else if (state.section == "video") {
      if (!out.video) invalid("SDP video attribute without video media"); // parse_media_line sets it
      parse_video_attribute(line, value, *out.video, state);
    } else
      parse_attribute(line, value, out, state);
  }
  finish_sdp(out, state);
  return out;
}

//------------------------------------------------------------------------------
// TS 26.179 clause 4.1.3 with RFC 4867 section 8.1: the AMR-WB mode allowed by a peer's mode-set.
int amr_wb_send_mode(int wanted, const std::vector<std::uint8_t> &mode_set) {
  if (mode_set.empty() || std::find(mode_set.begin(), mode_set.end(), wanted) != mode_set.end()) return wanted;
  int below = -1, lowest = 9;
  for (const auto mode : mode_set) {
    if (mode < wanted && mode > below) below = mode;
    lowest = std::min<int>(lowest, mode);
  }
  return below >= 0 ? below : lowest;
}

} // namespace mcx
