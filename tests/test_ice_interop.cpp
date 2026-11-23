//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// OpenMCX's ICE agent (src/media/ice.cpp) against the pjnath agent it replaces (tests/support/ice_pjnath.cpp), on
// real UDP sockets on the loopback address: either one as the controlling client, the other as the controlled
// participating function, on all three components; and a role conflict between them. Built only while pjproject is
// in the development image (PLAN.md phase 7 removes it).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19), RFC 8445, RFC 5389.

#include "support/ice_pjnath.hpp"
#include "support/ice_side.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static void expect(bool condition, const std::string &what) {
  if (!condition) throw std::runtime_error(what);
}

template <typename Client, typename Server> static void complete(bool client_controlling, bool server_controlling) {
  IceSide<Client> client(client_controlling);
  IceSide<Server> server(server_controlling);
  server.agent->start(client.agent->local_description());
  client.agent->start(server.agent->local_description());
  run_ice(client, server, std::chrono::seconds(10));
  expect(client.agent->state() == mcx::IceState::Completed, "client completed");
  expect(server.agent->state() == mcx::IceState::Completed, "server completed");
  for (unsigned component = 1; component <= 2; ++component) {
    const auto from_client = client.agent->selected(mcx::IceStream::Audio, component);
    const auto from_server = server.agent->selected(mcx::IceStream::Audio, component);
    expect(from_client && from_client->second == server.sockets[component - 1]->port(), "client's speech pair");
    expect(from_server && from_server->second == client.sockets[component - 1]->port(), "server's speech pair");
  }
  const auto control = client.agent->selected(mcx::IceStream::Control, 1);
  expect(control && control->second == server.sockets[2]->port(), "client's control pair");
  expect(!client.agent->needs_updated_offer() && !server.agent->needs_updated_offer(), "host candidates nominated");
}

// RFC 8445 sections 7 and 8: OpenMCX's agent controlling, pjnath's controlled.
static void Rfc8445_OwnControllingPjnathControlled() { complete<mcx::IceAgent, mcx::PjnathIceAgent>(true, false); }

// RFC 8445 sections 7 and 8: pjnath's agent controlling, OpenMCX's controlled.
static void Rfc8445_PjnathControllingOwnControlled() { complete<mcx::PjnathIceAgent, mcx::IceAgent>(true, false); }

// RFC 8445 section 7.3.1.1: both controlling, then both controlled, each way round.
static void Rfc8445_7_3_1_1_RoleConflicts() {
  complete<mcx::IceAgent, mcx::PjnathIceAgent>(true, true);
  complete<mcx::PjnathIceAgent, mcx::IceAgent>(true, true);
  complete<mcx::IceAgent, mcx::PjnathIceAgent>(false, false);
}

int main() {
  const std::vector<std::pair<const char *, void (*)()>> tests = {
      {"Rfc8445_OwnControllingPjnathControlled", Rfc8445_OwnControllingPjnathControlled},
      {"Rfc8445_PjnathControllingOwnControlled", Rfc8445_PjnathControllingOwnControlled},
      {"Rfc8445_7_3_1_1_RoleConflicts", Rfc8445_7_3_1_1_RoleConflicts},
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
  if (failures == 0) std::cout << tests.size() << " ICE interoperability tests passed\n";
  return failures == 0 ? 0 : 1;
}
