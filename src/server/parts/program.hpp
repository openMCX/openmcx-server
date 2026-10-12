//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The entry point shared by the MC server programs (openmcx-mcptt-server, openmcx-mcvideo-server and
// openmcx-mcdata-server): arguments, configuration, control commands, the banner and the stop signals.
//
// Specifications: none (the server programs).
#pragma once

#include "mcx/runtime.hpp"

#include <csignal>
#include <functional>
#include <string_view>

namespace mcx {
// Set by SIGINT and SIGTERM: the run loop ends.
extern volatile std::sig_atomic_t stopping;

//------------------------------------------------------------------------------
// Helper: SIGINT and SIGTERM handler; the run loop ends, and the server releases its calls.
void stop_signal(int signal_number);

//------------------------------------------------------------------------------
// The entry point of an MC server program: reads the arguments and the configuration, serves a control command or
// prints the banner and runs the server that run_server builds until SIGINT or SIGTERM. With `ignore_sigpipe`, a
// peer closing a Diameter or MSRP connection is a write error, not a reason to stop (the MCPTT and MCVideo servers;
// the MCData server has always kept the default action). Errors are reported with the program's name.
int serve(int argc, char **argv, std::string_view program,
          const std::function<void(Json cfg, bool disable_tls)> &run_server, bool ignore_sigpipe = true);
} // namespace mcx
