//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// openmcx-mcptt-server: the entry point of the MCPTT server (class McpttServer, mcptt_server.hpp).
//
// Specifications: TS 24.379 V19.7.0 (Rel-19).

#include "mcptt_server.hpp"

//------------------------------------------------------------------------------
// Helper: the process entry point; runs the MCPTT server through the shared entry point (serve).
int main(int argc, char **argv) {
  return mcx::serve(argc, argv, "openmcx-mcptt-server",
                    [](mcx::Json cfg, bool disable_tls) { mcx::McpttServer(std::move(cfg), disable_tls).run(); });
}
