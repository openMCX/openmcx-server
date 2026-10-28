//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The MBMS bearers' host groups (include/mcx/multicast.hpp): host group addresses, the "mbms" configuration block,
// the listening status report (TS 24.379 annex F.2) and a send and receive through a joined socket.
//
// Specifications: RFC 1112, TS 24.379 V19.7.0 (Rel-19).

#include "mcx/multicast.hpp"

#include "mcx/mbms_usage.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
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

//------------------------------------------------------------------------------
// RFC 1112 section 4: class D addresses only.
static void Section_4_HostGroupAddresses() {
  for (const auto *address : {"224.0.0.1", "239.10.0.1", "239.255.255.255"})
    if (!mcx::is_ipv4_multicast(address)) throw std::runtime_error(std::string("host group refused: ") + address);
  for (const auto *address : {"223.255.255.255", "240.0.0.1", "10.0.0.1", "239.10.0", "mcptt-server", ""})
    if (mcx::is_ipv4_multicast(address)) throw std::runtime_error(std::string("not a host group: ") + address);
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.3.3.2 and annex F.2: the listening status report is written and read back; a report without a
// TMGI or a session, an unknown status, an <announcement> and the version are checked.
static void Clause_14_3_3_2_ListeningStatus() {
  const mcx::MbmsListeningStatus listening{true, "sip:mcptt@example.test;session=abc", std::nullopt, {"000001"}};
  const auto xml = mcx::mbms_listening_status_xml(listening);
  const auto read = mcx::parse_mbms_usage_info(xml);
  if (!read.listening_status || *read.listening_status != listening || !read.announcements.empty() ||
      read.suspension_status)
    throw std::runtime_error("listening status not read back: " + xml);
  auto stopped = listening;
  stopped.listening = false;
  stopped.tmgis = {"00000299F907"};
  const auto back = mcx::parse_mbms_usage_info(mcx::mbms_listening_status_xml(stopped));
  if (!back.listening_status || back.listening_status->listening ||
      back.listening_status->tmgis.front() != "00000299f907")
    throw std::runtime_error("not-listening status not read back");

  rejects([&] { (void)mcx::mbms_listening_status_xml({true, "sip:s@example.test", std::nullopt, {}}); }, "no TMGI");
  rejects([&] { (void)mcx::mbms_listening_status_xml({true, "", std::nullopt, {"000001"}}); }, "no session");
  const std::string ns = mcx::mbms_usage_ns;
  const auto document = [&](const std::string &inner) {
    return "<mcptt-mbms-usage-info xmlns=\"" + ns + "\">" + inner + "</mcptt-mbms-usage-info>";
  };
  const std::string status = "<mbms-listening-status><mbms-listening-status>%s</mbms-listening-status>"
                             "<session-id>sip:s@example.test</session-id><TMGI>000001</TMGI></mbms-listening-status>";
  const auto with = [&](const std::string &value) {
    auto copy = status;
    copy.replace(copy.find("%s"), 2, value);
    return copy;
  };
  rejects([&] { (void)mcx::parse_mbms_usage_info(document(with("listening"))); }, "a document without <version>");
  rejects([&] { (void)mcx::parse_mbms_usage_info(document(with("maybe") + "<version>1</version>")); },
          "an unknown listening status");
  const auto announced =
      mcx::parse_mbms_usage_info(document("<announcement><TMGI>000001</TMGI></announcement><version>1</version>"));
  if (announced.announcements.size() != 1 || announced.listening_status)
    throw std::runtime_error("announcement not seen");
  const std::string unqualified = "<mcptt-mbms-usage-info><version>1</version></mcptt-mbms-usage-info>";
  rejects([&] { (void)mcx::parse_mbms_usage_info(unqualified); }, "a document without the namespace");
}

//------------------------------------------------------------------------------
// RFC 1112 sections 7.1 and 7.2: a datagram sent to a host group with loopback reaches a socket of this host that
// joined it, and not one that did not. Skipped where the host has no route to the host groups (a build without a
// network).
static void Section_7_SendAndReceive() {
  const std::string group = "239.10.200.1";
  mcx::UdpSocket joined("0.0.0.0", 0), sender("0.0.0.0", 0);
  rejects([&] { joined.join("10.0.0.1", "0.0.0.0"); }, "joining a unicast address");
  rejects([&] { sender.multicast_sending("0.0.0.0", 0); }, "time-to-live 0");
  rejects([&] { sender.multicast_sending("eth0", 1); }, "an interface name");
  joined.join(group, "0.0.0.0");
  sender.multicast_sending("0.0.0.0", 1, true);
  const std::vector<std::uint8_t> packet = {0x80, 0x60, 0x00, 0x01};
  try {
    sender.send(packet, group, joined.port());
  } catch (const std::exception &error) {
    std::cout << "multicast send and receive skipped: " << error.what() << '\n';
    return;
  }
  for (int attempt = 0; attempt < 100; ++attempt) {
    if (const auto datagram = joined.receive()) {
      if (datagram->bytes != packet) throw std::runtime_error("multicast datagram changed");
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  throw std::runtime_error("multicast datagram not received by the joined socket");
}

//------------------------------------------------------------------------------
// The "mbms" block of pre-activated bearers: defaults, a bearer read back, and what is refused (a missing general
// purpose subchannel or service area, a TMGI or a host group and port used twice, a unicast address).
static void MbmsBlock() {
  const auto bearer = [](const std::string &tmgi, const std::string &general_purpose) {
    return mcx::Json{{"tmgi", tmgi},
                     {"general_purpose", general_purpose},
                     {"subchannels", {"239.10.0.2:40002"}},
                     {"service_areas", {"0001"}}};
  };
  auto block = mcx::Json{{"users", {"mcptt-a"}}, {"bearers", {bearer("00000199F907", "239.10.1.1:40100")}}};
  block["bearers"][0]["qci"] = 65;
  const auto config = mcx::mbms_config(block);
  if (config.ttl != 1 || config.payload_type != 96 || config.bearer_announcement_ms != 0 || !config.serves("mcptt-a"))
    throw std::runtime_error("mbms defaults not taken");
  const auto *read = config.bearer("00000199f907");
  if (!read || read->qci != 65 || read->general_purpose.port != 40100 || read->subchannels.size() != 1 ||
      read->subchannels[0].tmgi != "00000199f907" || read->service_areas != std::vector<std::string>{"0001"})
    throw std::runtime_error("mbms bearer not read back");
  auto twice = block;
  twice["bearers"].push_back(bearer("00000199f907", "239.10.1.2:40100"));
  rejects([&] { (void)mcx::mbms_config(twice); }, "a TMGI used twice");
  auto shared = block;
  shared["bearers"].push_back(bearer("000002", "239.10.0.2:40002"));
  rejects([&] { (void)mcx::mbms_config(shared); }, "a host group and port used twice");
  auto unicast = block;
  unicast["bearers"][0]["general_purpose"] = "10.0.0.1:40100";
  rejects([&] { (void)mcx::mbms_config(unicast); }, "a unicast general purpose subchannel");
  auto no_area = block;
  no_area["bearers"][0].erase("service_areas");
  rejects([&] { (void)mcx::mbms_config(no_area); }, "a bearer without service areas");
  rejects([&] { (void)mcx::mbms_config(mcx::Json{{"bearers", mcx::Json::array()}}); }, "no bearer");
}

//------------------------------------------------------------------------------
int main() {
  Section_4_HostGroupAddresses();
  MbmsBlock();
  Clause_14_3_3_2_ListeningStatus();
  Section_7_SendAndReceive();
  std::cout << "multicast tests passed\n";
}
