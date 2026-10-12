//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// openmcx-mcdata-server: the entry point of the MCData server (class DataServer, data_server.hpp).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19).

#include "data_server.hpp"

//------------------------------------------------------------------------------
// Helper: the process entry point; runs the MCData server through the shared entry point (serve), keeping SIGPIPE's
// default action as it always has.
int main(int argc, char **argv) {
  return mcx::serve(
      argc, argv, "openmcx-mcdata-server",
      [](mcx::Json cfg, bool disable_tls) { mcx::DataServer(std::move(cfg), disable_tls).run(); }, false);
}
