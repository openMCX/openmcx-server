// The entry point shared by the MC server programs (program.hpp).
//
// Specifications: none (the server programs).

#include "parts/program.hpp"

#include "mcx/banner.hpp"

#include <iostream>

namespace mcx {
volatile std::sig_atomic_t stopping = 0;

//------------------------------------------------------------------------------
// Helper: SIGINT and SIGTERM handler; the run loop ends.
void stop_signal(int /*signal_number*/) { stopping = 1; }

//------------------------------------------------------------------------------
// Helper: the process entry point of a server program.
int serve(int argc, char **argv, std::string_view program,
          const std::function<void(Json cfg, bool disable_tls)> &run_server, bool ignore_sigpipe) {
  try {
    auto args = arguments(argc, argv);
    auto cfg = load_config(args.config, args.disable_tls);
    if (dispatch_control(args, cfg)) return 0;
    print_banner(program);
    if (args.disable_tls) event("debug_clear_sip", {{"transport", "tcp"}, {"tls", false}});
    std::signal(SIGINT, stop_signal);
    std::signal(SIGTERM, stop_signal);
    if (ignore_sigpipe) std::signal(SIGPIPE, SIG_IGN);
    run_server(std::move(cfg), args.disable_tls);
    return 0;
  } catch (const std::exception &error) {
    std::cerr << program << ": " << error.what() << '\n';
    return 1;
  }
}
} // namespace mcx
