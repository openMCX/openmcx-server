//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The OpenMCX startup banner, printed by every long-running OpenMCX program (OpenMCX, no 3GPP specification).
#pragma once

#include <iostream>
#include <string>
#include <string_view>

namespace mcx {

//------------------------------------------------------------------------------
// Helper: the program's short name in the debug log lines ("mcptt-server", "user-db", "client"), set by print_banner.
inline std::string &log_program() {
  static std::string name;
  return name;
}

//------------------------------------------------------------------------------
// Helper: the startup banner on stderr, naming the program; stdout stays a clean JSON event stream.
inline void print_banner(std::string_view program) {
  auto name = std::string(program);
  for (std::string_view prefix : {"openmcx-", "mcx-"})
    if (name.starts_with(prefix)) name.erase(0, prefix.size());
  log_program() = name;
  std::cerr << R"(
  ___                   __  __  ______  __
 / _ \ _ __   ___ _ __ |  \/  |/ ___\ \/ /
| | | | '_ \ / _ \ '_ \| |\/| | |    \  /
| |_| | |_) |  __/ | | | |  | | |___ /  \
 \___/| .__/ \___|_| |_|_|  |_|\____/_/\_\
      |_|
)" << "  3GPP Release 19 "
            << program << " - MCX Services\n\n"
            << std::flush;
}

} // namespace mcx
