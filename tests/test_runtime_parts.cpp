// The runtime helpers of the MC servers (src/server/parts/counters.hpp, task_queue.hpp): the named counts of the
// status report and the queue of tasks run after a request is answered.
//
// Specifications: none (the servers' status report and run loop).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "parts/counters.hpp"
#include "parts/task_queue.hpp"

#include <cassert>
#include <iostream>
#include <sstream>
#include <stdexcept>
using namespace mcx;

namespace {
//------------------------------------------------------------------------------
// Helper: the listed counts show from zero, others from their first count; amounts add up; the JSON is what the
// status report always had (an object of numbers, in name order).
void CountersAsTheStatusShows() {
  Counters counters{"reports", "refused"};
  assert(counters.json().dump() == R"({"refused":0,"reports":0})");
  counters.add("reports");
  counters.add("bytes", 1500);
  counters.add("bytes", 500);
  assert(counters.json().dump() == R"({"bytes":2000,"refused":0,"reports":1})");
  assert(Counters{}.json().dump() == "{}");
}

//------------------------------------------------------------------------------
// Helper: the tasks queued so far run once; what they queue waits for the next pass; a failing task is reported as
// operation_failed and the others still run.
void TaskQueueRunsOnce() {
  TaskQueue queue;
  int ran = 0;
  queue.push_back([&] {
    ++ran;
    queue.push_back([&] { ran += 10; });
  });
  queue.push_back([] { throw std::runtime_error("broken"); });
  queue.push_back([&] { ++ran; });
  std::ostringstream lines;
  auto *previous = std::cout.rdbuf(lines.rdbuf());
  queue.run();
  std::cout.rdbuf(previous);
  assert(ran == 2 && !queue.empty());
  assert(lines.str().find(R"("event":"operation_failed")") != std::string::npos);
  assert(lines.str().find(R"("reason":"broken")") != std::string::npos);
  queue.run();
  assert(ran == 12 && queue.empty());
}
} // namespace

//------------------------------------------------------------------------------
int main() {
  CountersAsTheStatusShows();
  TaskQueueRunsOnce();
  std::cout << "runtime_parts: all checks passed\n";
}
