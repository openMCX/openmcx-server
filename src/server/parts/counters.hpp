//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Counters of an MC server's procedures, as the status report shows them: one JSON object of named counts per area
// (location, document subscriptions, MCData communications, ...). Shared by the MCPTT and MCVideo servers
// (McServer) and the MCData server (DataServer).
//
// Specifications: none (a local status report).
#pragma once

#include "mcx/runtime.hpp"

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>

namespace mcx {
//------------------------------------------------------------------------------
// Named counts: those listed at construction are shown from zero, any other from its first count.
class Counters {
public:
  Counters() = default;

  Counters(std::initializer_list<std::string_view> names) {
    for (const auto name : names) values_[std::string(name)] = 0;
  }

  // One more (or `amount` more) of the named count.
  void add(const std::string &name, std::uint64_t amount = 1) {
    values_[name] = values_.value(name, std::uint64_t{0}) + amount;
  }

  // The counts for the status report.
  [[nodiscard]] const Json &json() const { return values_; }

private:
  Json values_ = Json::object();
};
} // namespace mcx
