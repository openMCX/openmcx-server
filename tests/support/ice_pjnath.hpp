//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The pjnath ICE agent OpenMCX used before its own (tests/support/ice_pjnath.cpp), with the interface of
// include/mcx/ice.hpp, as a test peer for test_ice_interop.

#pragma once

#include "mcx/ice.hpp"

namespace mcx {

class PjnathIceAgent {
public:
  PjnathIceAgent(bool controlling, IceLocalSockets sockets, IceSender sender);
  ~PjnathIceAgent();
  PjnathIceAgent(const PjnathIceAgent &) = delete;
  PjnathIceAgent &operator=(const PjnathIceAgent &) = delete;

  [[nodiscard]] const IceDescription &local_description() const noexcept;
  void start(const IceDescription &remote);
  bool receive(IceStream stream, unsigned component, std::span<const std::uint8_t> packet, const std::string &host,
               std::uint16_t port);
  void tick();

  [[nodiscard]] IceState state() const noexcept { return state_; }

  [[nodiscard]] std::optional<std::pair<std::string, std::uint16_t>> selected(IceStream stream,
                                                                              unsigned component) const;
  [[nodiscard]] bool needs_updated_offer() const;

  struct Impl;

private:
  std::unique_ptr<Impl> impl_;
  IceState state_ = IceState::Gathered;
  friend struct Impl;
};

} // namespace mcx
