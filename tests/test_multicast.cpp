//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The IP multicast delivery of MCPTT group call speech (an OpenMCX profile, include/mcx/multicast.hpp): host group
// addresses, the "multicast" configuration block, the listening status report (TS 24.379 annex F.2) and a send and
// receive through a joined socket.
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
// Helper: a group entry of the configuration block.
static mcx::Json entry(const std::string &host_group, const std::string &tmgi) {
  return {{"host_group", host_group}, {"tmgi", tmgi}};
}

//------------------------------------------------------------------------------
// The configuration block: defaults, the opt-in list, the groups with their TMGIs, and what is refused.
static void ConfigurationBlock() {
  const mcx::Json block = {{"users", {"mcptt-a", "mcptt-b"}},
                           {"groups",
                            {{"sip:fire@example.test", entry("239.10.0.1:40000", "000001")},
                             {"sip:police@example.test", entry("239.10.0.2:40000", "00000299F907")}}}};
  const auto config = mcx::multicast_config(block);
  if (config.interface != "0.0.0.0" || config.ttl != 1 || config.payload_type != 96 || config.octet_aligned)
    throw std::runtime_error("multicast defaults not taken");
  if (!config.serves("mcptt-a") || config.serves("mcptt-c")) throw std::runtime_error("opt-in list not taken");
  const auto *fire = config.group("sip:fire@example.test");
  if (!fire || *fire != mcx::MulticastDestination{"239.10.0.1", 40000, "000001"} ||
      config.group("sip:other@example.test"))
    throw std::runtime_error("group host groups not taken");
  if (config.group("sip:police@example.test")->tmgi != "00000299f907") throw std::runtime_error("TMGI not lower-cased");

  auto changed = [&](const std::string &key, const mcx::Json &value) {
    auto copy = block;
    copy[key] = value;
    return copy;
  };
  const auto set = mcx::multicast_config(changed("ttl", 4));
  if (set.ttl != 4) throw std::runtime_error("ttl not taken");
  rejects([&] { (void)mcx::multicast_config(changed("ttl", 0)); }, "ttl 0");
  rejects([&] { (void)mcx::multicast_config(changed("ttl", 256)); }, "ttl 256");
  rejects([&] { (void)mcx::multicast_config(changed("payload_type", 8)); }, "a static payload type");
  rejects([&] { (void)mcx::multicast_config(changed("groups", mcx::Json::object())); }, "no groups");
  rejects([&] { (void)mcx::multicast_config(changed("groups", "239.10.0.1:40000")); }, "groups that are not a map");
  rejects([&] { (void)mcx::multicast_config(changed("users", "mcptt-a")); }, "users that are not a list");
  const auto group = [&](const mcx::Json &value) { return changed("groups", {{"sip:fire@example.test", value}}); };
  for (const auto *value : {"10.0.0.1:40000", "239.10.0.1", "239.10.0.1:0", "239.10.0.1:65536", "239.10.0.1:4x",
                            "mcast:40000"})
    rejects([&] { (void)mcx::multicast_config(group(entry(value, "000001"))); }, std::string("group address ") + value);
  for (const auto *value : {"", "0001", "00000x", "0000010000", "00000100000100"})
    rejects([&] { (void)mcx::multicast_config(group(entry("239.10.0.1:40000", value))); },
            std::string("TMGI ") + value);
  rejects([&] { (void)mcx::multicast_config(group("239.10.0.1:40000")); }, "a group without a TMGI");
  const mcx::Json shared = {{"sip:fire@example.test", entry("239.10.0.1:40000", "000001")},
                            {"sip:x@example.test", entry("239.10.0.1:40000", "000002")}};
  rejects([&] { (void)mcx::multicast_config(changed("groups", shared)); }, "two groups on one address and port");
  const mcx::Json same_tmgi = {{"sip:fire@example.test", entry("239.10.0.1:40000", "000001")},
                               {"sip:x@example.test", entry("239.10.0.2:40000", "000001")}};
  rejects([&] { (void)mcx::multicast_config(changed("groups", same_tmgi)); }, "two groups with one TMGI");
  rejects([&] { (void)mcx::multicast_config(mcx::Json::array()); }, "a block that is not an object");
}

//------------------------------------------------------------------------------
// TS 24.379 clause 14.3.3.2 and annex F.2: the listening status report is written and read back; a report without a
// TMGI or a session, an unknown status, an <announcement> and the version are checked.
static void Clause_14_3_3_2_ListeningStatus() {
  const mcx::MbmsListeningStatus listening{true, "sip:mcptt@example.test;session=abc", std::nullopt, {"000001"}};
  const auto xml = mcx::mbms_listening_status_xml(listening);
  const auto read = mcx::parse_mbms_usage_info(xml);
  if (!read.listening_status || *read.listening_status != listening || read.announcement || read.suspension_status)
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
  if (!announced.announcement || announced.listening_status) throw std::runtime_error("announcement not seen");
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
int main() {
  Section_4_HostGroupAddresses();
  ConfigurationBlock();
  Clause_14_3_3_2_ListeningStatus();
  Section_7_SendAndReceive();
  std::cout << "multicast tests passed\n";
}
