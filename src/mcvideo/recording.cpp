// Video recordings of the MCVideo server: the stream of a one-to-server video push saved to a file and played
// back by a one-from-server video pull (member functions of McvideoServer).
//
// Specifications: TS 24.281 V19.6.0 (Rel-19).

#include "mcvideo_server.hpp"

namespace mcx {

//------------------------------------------------------------------------------
// TS 24.281 clause 13.2.3.2.3 step 5: the controlling MCVideo function saves the media stream to a file.
// A recording holds one record per RTP packet, as received and in order: its offset
// from the first packet in ms (8 octets), SSRC and timestamp (4 each), sequence
// number (2), marker (1), payload length (4) and payload, in network byte order.
// Played back as recorded, the pictures keep the pushing client's SSRC and timestamps.
void McvideoServer::write_record(std::ostream &out, std::uint64_t offset, const RtpPacket &packet) {
  const auto put = [&](std::uint64_t value, int octets) {
    for (int index = octets - 1; index >= 0; --index) out.put(static_cast<char>((value >> (8 * index)) & 0xff));
  };
  put(offset, 8);
  put(packet.ssrc, 4);
  put(packet.timestamp, 4);
  put(packet.sequence, 2);
  put(packet.marker ? 1 : 0, 1);
  put(packet.payload.size(), 4);
  out.write(reinterpret_cast<const char *>(packet.payload.data()), static_cast<std::streamsize>(packet.payload.size()));
  out.flush();
}

//------------------------------------------------------------------------------
// TS 24.281 clause 12.2.3.2.5 step 2: read a recording (the format of write_record) to transmit it to the
// client of a one-from-server video pull: each packet with its offset in ms from the first.
std::vector<std::pair<std::uint64_t, RtpPacket>> McvideoServer::read_recording(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  std::vector<std::pair<std::uint64_t, RtpPacket>> out;
  const auto get = [&](int octets, std::uint64_t &value) {
    value = 0;
    for (int index = 0; index < octets; ++index) {
      const int octet = in.get();
      if (octet == EOF) return false;
      value = (value << 8) | static_cast<std::uint8_t>(octet);
    }
    return true;
  };
  std::uint64_t offset, ssrc, timestamp, sequence, marker, size;
  while (get(8, offset)) {
    if (!get(4, ssrc) || !get(4, timestamp) || !get(2, sequence) || !get(1, marker) || !get(4, size) || size > 65535)
      throw std::runtime_error("truncated recording");
    RtpPacket packet;
    packet.ssrc = static_cast<std::uint32_t>(ssrc);
    packet.timestamp = static_cast<std::uint32_t>(timestamp);
    packet.sequence = static_cast<std::uint16_t>(sequence);
    packet.marker = marker != 0;
    packet.payload.resize(size);
    if (!in.read(reinterpret_cast<char *>(packet.payload.data()), static_cast<std::streamsize>(size)))
      throw std::runtime_error("truncated recording");
    out.emplace_back(offset, std::move(packet));
  }
  return out;
}

//------------------------------------------------------------------------------
// Helper: the directory of this server's recordings (configuration "recordings_dir").
std::filesystem::path McvideoServer::recordings_dir() const {
  return cfg_.at(svc_.name).value("recordings_dir", std::string("/artifacts/mcvideo-server/recordings"));
}

//------------------------------------------------------------------------------
// TS 24.281 clause 13.2.3.2.3: the base of the URL of a recording, sent in the <video-push-url> element of the
// SIP INFO request (configuration "recording_url_base", by default https://<advertised address>/recordings/).
std::string McvideoServer::recording_url_base() const {
  return cfg_.at(svc_.name).value("recording_url_base",
                                  "https://" + cfg_.at("sip").at("advertise").get<std::string>() + "/recordings/");
}

//------------------------------------------------------------------------------
// TS 24.281 clause 12.2.3.2.5 step 2: the file of one of this server's recordings named by the URL in the
// <video-pull-url> element, or empty.
std::filesystem::path McvideoServer::recording_of(const std::string &url) const {
  const auto base = recording_url_base();
  if (!url.starts_with(base)) return {};
  const auto id = url.substr(base.size());
  if (id.empty() || id.size() > 64 ||
      !std::all_of(id.begin(), id.end(), [](unsigned char character) { return std::isxdigit(character) != 0; }))
    return {};
  const auto path = recordings_dir() / id;
  return std::filesystem::is_regular_file(path) ? path : std::filesystem::path{};
}

} // namespace mcx
