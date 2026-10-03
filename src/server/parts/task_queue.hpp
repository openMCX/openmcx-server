// The tasks an MC server runs after the request it is handling has been answered (a NOTIFY after the 200 to a
// PUBLISH, a registration after a service authorisation, ...), on its run loop. Shared by the MCPTT and MCVideo
// servers (McServer) and the MCData server (DataServer).
//
// Specifications: none (the servers' run loop).
#pragma once

#include "mcx/runtime.hpp"

#include <deque>
#include <exception>
#include <functional>
#include <utility>

namespace mcx {
//------------------------------------------------------------------------------
// The queue of tasks for the run loop.
class TaskQueue {
public:
  void push_back(std::function<void()> task) { tasks_.push_back(std::move(task)); }

  // Runs the tasks queued so far (those they queue run on the next pass); a task that fails is reported as
  // operation_failed and the others still run.
  void run() {
    auto tasks = std::move(tasks_);
    tasks_.clear();
    for (auto &task : tasks) try {
        task();
      } catch (const std::exception &error) {
        event("operation_failed", {{"reason", error.what()}});
      }
  }

  [[nodiscard]] bool empty() const { return tasks_.empty(); }

private:
  std::deque<std::function<void()>> tasks_;
};
} // namespace mcx
