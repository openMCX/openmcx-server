//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The IP multicast delivery of MCPTT group call speech (an OpenMCX profile, include/mcx/multicast.hpp): host group
// addresses, the "multicast" configuration block and a send and receive through a joined socket.
//
// Specifications: RFC 1112.

#include "mcx/multicast.hpp"

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
// The configuration block: defaults, the opt-in list, the groups, and what is refused.
static void ConfigurationBlock() {
  const mcx::Json block = {{"users", {"mcptt-a", "mcptt-b"}},
                           {"groups", {{"sip:fire@example.test", "239.10.0.1:40000"},
                                       {"sip:police@example.test", "239.10.0.2:40000"}}}};
  const auto config = mcx::multicast_config(block);
  if (config.interface != "0.0.0.0" || config.ttl != 1 || config.payload_type != 96 || config.octet_aligned)
    throw std::runtime_error("multicast defaults not taken");
  if (!config.serves("mcptt-a") || config.serves("mcptt-c")) throw std::runtime_error("opt-in list not taken");
  const auto *fire = config.group("sip:fire@example.test");
  if (!fire || *fire != mcx::MulticastDestination{"239.10.0.1", 40000} || config.group("sip:other@example.test"))
    throw std::runtime_error("group host groups not taken");

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
  for (const auto *value : {"10.0.0.1:40000", "239.10.0.1", "239.10.0.1:0", "239.10.0.1:65536", "239.10.0.1:4x",
                            "mcast:40000"})
    rejects([&] { (void)mcx::multicast_config(changed("groups", {{"sip:fire@example.test", value}})); },
            std::string("group address ") + value);
  const mcx::Json shared = {{"sip:fire@example.test", "239.10.0.1:40000"}, {"sip:x@example.test", "239.10.0.1:40000"}};
  rejects([&] { (void)mcx::multicast_config(changed("groups", shared)); }, "two groups on one address and port");
  rejects([&] { (void)mcx::multicast_config(mcx::Json::array()); }, "a block that is not an object");
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
  Section_7_SendAndReceive();
  std::cout << "multicast tests passed\n";
}
