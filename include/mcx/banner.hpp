// The openMCX startup banner, printed by every long-running openMCX program (openMCX, no 3GPP specification).
#pragma once

#include <iostream>
#include <string_view>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the startup banner on stderr, naming the program; stdout stays a clean JSON event stream.
inline void print_banner(std::string_view program) {
  std::cerr << R"(
                            __  __   ____ __  __
  ___   _ __    ___  _ __  |  \/  | / ___|\ \/ /
 / _ \ | '_ \  / _ \| '_ \ | |\/| || |     \  /
| (_) || |_) ||  __/| | | || |  | || |___  /  \
 \___/ | .__/  \___||_| |_||_|  |_| \____|/_/\_\
       |_|
)" << "  3GPP Release 19 "
            << program << " - MCX Services\n\n"
            << std::flush;
}

} // namespace mcx
