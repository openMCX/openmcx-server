//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Prototype (not part of any program): the two logging helpers of include/mcx/runtime.hpp that src/security/xfrm.cpp
// uses, for aka_probe, which does not link src/common/runtime.cpp (it brings the protocol code with it). MCX_LOG=debug
// prints the SAs installed.
//
// Specifications: none (OpenMCX logging).

#include "mcx/runtime.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace mcx {

//------------------------------------------------------------------------------
// The log level: "debug" with MCX_LOG=debug, otherwise "info".
LogLevel log_level() {
  const char *level = std::getenv("MCX_LOG");
  return level != nullptr && std::string(level) == "debug" ? LogLevel::debug : LogLevel::info;
}

//------------------------------------------------------------------------------
// A debug line on stderr.
void debug_line(std::string_view text) { std::cerr << text << '\n'; }

} // namespace mcx
