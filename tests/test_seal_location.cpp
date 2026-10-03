// SEAL location management documents: the client's configuration, location and history reports,
// subscriptions, requests and notifications (urn:3gpp:ns:sealLocationInfo:1.0).
//
// Specifications: TS 24.545 (not kept locally), TS 23.434 (not kept locally).

#include "mcx/seal_location.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

using namespace mcx::seal;

namespace {
//------------------------------------------------------------------------------
// Fails the test, naming the source line, when condition is false (not assert: the tests are built with NDEBUG).
void check_at(bool condition, int line) {
  if (!condition) {
    throw std::runtime_error("check failed at line " + std::to_string(line));
  }
}
} // namespace

#define check(condition) check_at((condition), __LINE__)

//------------------------------------------------------------------------------
// TS 24.545 location management client and server documents: parsing, building and refusing
// malformed input.
static void run_tests() {
  // TS 24.545 clause 6.2.2.3.1: the configuration a client reads.
  const auto config = parse_configuration(
      "<?xml version=\"1.0\"?><location-info xmlns=\"urn:3gpp:ns:sealLocationInfo:1.0\"><identity><VAL-user-id>"
      "<sealURI>sip:alice@mcx.test</sealURI></VAL-user-id></identity><configuration><location-information>"
      "<current-geographical-coordinate/></location-information><triggering-criteria><periodic-report "
      "trigger-id=\"periodic\">5"
      "</periodic-report></triggering-criteria><minimum-interval-length>1</minimum-interval-length></"
      "configuration><anyExt>"
      "<report-uri xmlns=\"urn:openmcx:ns:sealLocation:1.0\">https://lms:8443/r</report-uri>"
      "<history-uri "
      "xmlns=\"urn:openmcx:ns:sealLocation:1.0\">https://lms:8443/h</history-uri></anyExt></location-info>");
  check(config.periodic == 5 && config.minimum_interval == 1 && config.report_uri == "https://lms:8443/r" &&
        config.history_uri == "https://lms:8443/h");

  // A report and a history report carry the coordinate as <threebytes>, longitude first.
  const Fix fix{4473924, 93206, "2026-09-26T00:00:00Z", false};
  const auto report = report_xml("sip:alice@mcx.test", "periodic", fix);
  check(report.find("<trigger-id>periodic</trigger-id>") != std::string::npos);
  check(
      report.find("<longitude><threebytes>93206</threebytes></longitude><latitude><threebytes>4473924</threebytes>") !=
      std::string::npos);
  const auto history = history_xml("history", {fix, fix});
  check(history.find("<anyExt><history-loc-result-report><subscription-identifier>history") != std::string::npos);

  // A subscription names the users, the interval and the duration.
  const auto sub = subscription_xml("sip:mcptt@mcx.test", {"sip:bob@mcx.test", "sip:erin@other.test"}, 2, 300);
  check(sub.find("<time-interval-length>2</time-interval-length><expiry-time>-300</expiry-time>") != std::string::npos);
  check(unsubscription_xml("sip:mcptt@mcx.test", "7")
            .find("<subscription-identifier>7</subscription-identifier><expiry-time>0") != std::string::npos);
  check(request_xml("sip:mcptt@mcx.test", {"sip:bob@mcx.test"}, true).find("<history xmlns=") != std::string::npos);

  // A notification, with a history position marked.
  const auto answer = parse_answer(
      "<?xml version=\"1.0\"?><location-info "
      "xmlns=\"urn:3gpp:ns:sealLocationInfo:1.0\"><identity><VAL-user-id><sealURI>"
      "sip:mcptt@mcx.test</sealURI></VAL-user-id></identity><notification "
      "trigger-id=\"history\"><identities-list><VAL-user-id>"
      "<sealURI>sip:bob@mcx.test</sealURI></VAL-user-id></"
      "identities-list><reports><loc-info-report><VAL-user-id><sealURI>"
      "sip:bob@mcx.test</sealURI></VAL-user-id><latest-location><latest-coordinate><longitude><threebytes>93206</"
      "threebytes>"
      "</longitude><latitude><threebytes>4473924</threebytes></latitude></latest-coordinate></latest-location><anyExt>"
      "<timestamp>2026-09-26T00:00:00Z</timestamp><history xmlns=\"urn:openmcx:ns:sealLocation:1.0\"/></anyExt>"
      "</loc-info-report></reports><subscription-identifier>7</subscription-identifier></notification></"
      "location-info>");
  check(answer.notification && answer.trigger == "history" && answer.subscription == "7" && answer.users.size() == 1);
  check(answer.reports.size() == 1 && answer.reports[0].user == "sip:bob@mcx.test" &&
        answer.reports[0].fix.latitude == 4473924 && answer.reports[0].fix.history &&
        answer.reports[0].fix.timestamp == "2026-09-26T00:00:00Z");

  // A subscription's answer and its end.
  const auto accepted =
      parse_answer("<location-info xmlns=\"urn:3gpp:ns:sealLocationInfo:1.0\"><subscription-identifier>3"
                   "</subscription-identifier><expiry-time>300</expiry-time></location-info>");
  check(!accepted.notification && accepted.subscription == "3" && accepted.expiry == 300);

  // Refused: another namespace, a DTD, a coordinate out of range.
  for (const std::string bad :
       {"<location-info xmlns=\"urn:other\"/>", "<!DOCTYPE x><location-info/>",
        "<location-info xmlns=\"urn:3gpp:ns:sealLocationInfo:1.0\"><notification><reports><loc-info-report>"
        "<latest-location><latest-coordinate><longitude><threebytes>99999999</threebytes></longitude>"
        "<latitude><threebytes>1</threebytes></latitude></latest-coordinate></latest-location>"
        "</loc-info-report></reports></notification></location-info>"}) {
    bool refused = false;
    try {
      (void)parse_answer(bad);
    } catch (const std::runtime_error &) {
      refused = true;
    }
    check(refused);
  }
}

//------------------------------------------------------------------------------
// Runs the tests; a failed check (or an unexpected exception) fails the run with its message instead of
// terminating the process.
int main() {
  try {
    run_tests();
  } catch (const std::exception &error) {
    std::cerr << "seal location tests failed: " << error.what() << '\n';
    return 1;
  }
  std::cout << "seal location tests passed\n";
  return 0;
}
