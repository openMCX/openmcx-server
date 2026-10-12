//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// openmcx-mcvideo-server: the entry point of the MCVideo server (class McvideoServer, mcvideo_server.hpp).
//
// Specifications: TS 24.281 V19.6.0 (Rel-19).

#include "mcvideo_server.hpp"

//------------------------------------------------------------------------------
// Helper: the process entry point; runs the MCVideo server through the shared entry point (serve).
int main(int argc, char **argv) {
  return mcx::serve(argc, argv, "openmcx-mcvideo-server",
                    [](mcx::Json cfg, bool disable_tls) { mcx::McvideoServer(std::move(cfg), disable_tls).run(); });
}
