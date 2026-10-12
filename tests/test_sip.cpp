//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// SIP engine (PJSIP): configuration checks, header lookup, and the transaction, dialog, subscription and INVITE
// session behaviour seen by the application, in one process and as separate server and client processes.
//
// Specifications: TS 24.379 V19.7.0 (Rel-19).
#include "mcx/sip.hpp"

#include <pthread.h>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace {

int failures = 0;
volatile std::sig_atomic_t poll_signal_received = 0;

//------------------------------------------------------------------------------
// Test helper: SIGUSR1 handler that records the signal interrupting SipEngine::poll().
void handle_poll_signal(int) { poll_signal_received = 1; }

//------------------------------------------------------------------------------
// Test helper: report a failure and count it when the condition is false.
void check(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

//------------------------------------------------------------------------------
// Test helper: the function must throw std::invalid_argument (configuration refused).
template <typename Function> void rejects(Function &&function, const std::string &message) {
  try {
    function();
    check(false, message);
  } catch (const std::invalid_argument &) {
    // The expected refusal.
  }
}

//------------------------------------------------------------------------------
// Test helper: an environment variable a multi-process role needs; its absence fails the role.
std::string required_environment(const char *name) {
  const char *value = std::getenv(name);
  if (value == nullptr || *value == '\0') throw std::runtime_error(std::string(name) + " is not set");
  return value;
}

//------------------------------------------------------------------------------
// RFC 3261 section 7.3.1: header field names are case-insensitive; a missing header field reads as empty.
void test_case_insensitive_header_lookup() {
  const std::vector<mcx::SipHeader> headers{{"P-Asserted-Identity", "<sip:mcptt-1@example.test>"},
                                            {"Event", "presence"}};
  check(mcx::get_header(headers, "p-asserted-identity") == "<sip:mcptt-1@example.test>",
        "SIP header lookup is ASCII case-insensitive");
  check(mcx::get_header(headers, "missing").empty(), "missing SIP header lookup is empty");
}

//------------------------------------------------------------------------------
// SipEngine configuration: TLS with peer certificate verification is required (a debug-only TCP configuration
// with plain sip: core URI is still accepted), a runtime identity is required, and digest credentials are either
// both set or both absent (trusted server).
void test_tls_and_identity_configuration_are_required() {
  mcx::SipConfig config;
  config.listen_address = "127.0.0.1";
  config.advertise_address = "client.example.test";
  config.listen_port = 5061;
  config.core_uri = "sips:core.example.test:5061;transport=tls";
  config.identity = "sip:mcptt-1@example.test";
  config.username = "mcptt-1";
  config.password = "secret";
  config.tls.ca_file = "/tmp/ca.pem";
  config.tls.cert_file = "/tmp/client.pem";
  config.tls.key_file = "/tmp/client.key";

  auto insecure = config;
  insecure.tls.enabled = false;
  rejects([&] { mcx::SipEngine engine(insecure, {}); }, "SIP engine rejects insecure transport fallback");

  auto debug = config;
  debug.tls.enabled = false;
  debug.core_uri = "sip:core.example.test:5060;transport=tcp";
  debug.listen_port = 5060;
  debug.tls.ca_file.clear();
  debug.tls.cert_file.clear();
  debug.tls.key_file.clear();
  mcx::SipEngine debug_engine(debug, {});
  check(debug_engine.contact_target() == "sip:mcptt-1@client.example.test:5060;transport=tcp",
        "debug TCP engine advertises a sip: TCP Contact");

  auto unverified = config;
  unverified.tls.verify_server = false;
  rejects([&] { mcx::SipEngine engine(unverified, {}); }, "SIP engine rejects disabled peer certificate verification");

  auto missing_identity = config;
  missing_identity.identity.clear();
  rejects([&] { mcx::SipEngine engine(missing_identity, {}); }, "SIP engine rejects missing runtime identity");

  auto trusted_server = config;
  trusted_server.username.clear();
  trusted_server.password.clear();
  mcx::SipEngine server_engine(trusted_server, {});
  check(server_engine.contact_target() == "sips:mcptt-1@client.example.test:5061;transport=tls" &&
            !server_engine.running(),
        "trusted server engine without digest credentials is accepted, with a sips: TLS Contact");

  auto missing_password = config;
  missing_password.password.clear();
  rejects([&] { mcx::SipEngine engine(missing_password, {}); },
          "SIP engine rejects half-configured digest credentials");

  auto missing_username = config;
  missing_username.username.clear();
  rejects([&] { mcx::SipEngine engine(missing_username, {}); },
          "SIP engine rejects half-configured digest credentials");

  auto explicit_tls_transport = config;
  explicit_tls_transport.core_uri = "sip:core.example.test:5061;transport=tls";
  mcx::SipEngine explicit_tls_engine(explicit_tls_transport, {});

  auto insecure_core_uri = config;
  insecure_core_uri.core_uri = "sip:core.example.test";
  rejects([&] { mcx::SipEngine engine(insecure_core_uri, {}); }, "SIP engine rejects a core URI without TLS transport");
}

//------------------------------------------------------------------------------
// One process over mutual TLS (runs only with OPENMCX_SIP_TEST_CERT_DIR): REGISTER refused without digest
// credentials; a multipart PUBLISH like the one of TS 24.379 clause 7.2.2 (application/vnd.3gpp.mcptt-info+xml
// and application/poc-settings+xml) reaches the application with its parts, also with leading MIME framing
// (RFC 2046 section 5.1.1); a self-routed SUBSCRIBE and INVITE get 482 (RFC 3261 section 8.2.2.2, merged
// requests); an INVITE with an unsupported Require option tag is refused before the application (RFC 3261 section
// 8.2.2.3); a signal interrupting poll() returns normally.
void test_native_mutual_tls_request_callbacks_when_configured() {
  const char *certificate_directory = std::getenv("OPENMCX_SIP_TEST_CERT_DIR");
  if (certificate_directory == nullptr) {
    std::cout << "mutual TLS self-loop skipped: OPENMCX_SIP_TEST_CERT_DIR not set (run_sip_tls.py runs it)\n";
    return;
  }

  const std::string directory(certificate_directory);
  mcx::SipConfig config;
  config.listen_address = "127.0.0.1";
  config.advertise_address = "127.0.0.1";
  config.listen_port = 15061;
  config.core_uri = "sip:127.0.0.1:15061;transport=tls";
  config.identity = "sip:trusted-as@openmcx.test";
  config.tls.ca_file = directory + "/cert.pem";
  config.tls.cert_file = directory + "/cert.pem";
  config.tls.key_file = directory + "/key.pem";

  bool request_received = false;
  bool response_received = false;
  int final_status = 0;
  std::string observed_error;
  std::string observed_content_type;
  std::size_t observed_part_count = 0;
  int invite_application_calls = 0;
  bool invite_disconnected = false;
  mcx::MediaDescription media;
  media.address = "127.0.0.1";
  media.floor_address = "127.0.0.1";
  media.audio_port = 41000;
  media.rtcp_port = 41001;
  media.floor_port = 41002;
  media.payload_type = 96;
  media.floor_ssrc = 1001;
  media.audio_ssrc = 1002;
  const std::vector<mcx::BodyPart> published_parts{{"application/vnd.3gpp.mcptt-info+xml", "<mcptt-info/>"},
                                                   {"application/poc-settings+xml", "<poc-settings/>"}};
  const std::string boundary = "publish-boundary";
  const std::string published_body = mcx::multipart_body(published_parts, boundary);
  mcx::SipCallbacks callbacks;
  callbacks.on_request = [&](const mcx::SipMessage &message) {
    mcx::SipResponse response;
    response.status_code = 200;
    response.reason = "OK";
    if (message.method == "INVITE") {
      ++invite_application_calls;
      response.local_media = media;
      // An answer whose header the engine refuses (CR/LF injection) once the INVITE session exists.
      if (!mcx::get_header(message.headers, "X-Unsafe-Answer").empty())
        response.headers.push_back({"X-Answer", "broken\r\nInjected: header"});
      return response;
    }
    observed_content_type = message.content_type;
    observed_part_count = message.parts.size();
    request_received =
        message.method == "PUBLISH" && message.content_type.find("boundary=publish-boundary") != std::string::npos &&
        message.parts.size() == published_parts.size() &&
        message.parts[0].content_type == published_parts[0].content_type &&
        message.parts[0].body == published_parts[0].body &&
        message.parts[1].content_type == published_parts[1].content_type &&
        message.parts[1].body == published_parts[1].body && !message.source_address.empty() && !message.call_id.empty();
    return response;
  };
  callbacks.on_error = [&](std::string_view error) { observed_error = error; };
  callbacks.on_call_state = [&](std::string_view, mcx::SipCallState state, int) {
    if (state == mcx::SipCallState::disconnected) {
      invite_disconnected = true;
    }
  };

  mcx::SipEngine engine(config, std::move(callbacks));
  engine.start();
  rejects([&] { engine.register_account(300); }, "trusted SIP server without digest credentials cannot REGISTER");
  engine.publish("sips:service@openmcx.test", "multipart/mixed; boundary=" + boundary, published_body, {},
                 [&](const mcx::SipResponse &response) {
                   final_status = response.status_code;
                   response_received = response.status_code == 200;
                 });
  for (int iteration = 0; iteration < 200 && !response_received; ++iteration) {
    engine.poll(std::chrono::milliseconds(10));
  }
  check(request_received, "native PJSIP TLS listener delivers incoming request metadata and body");
  check(response_received, "native PJSIP transaction delivers final response callback");
  if (!request_received || !response_received) {
    std::cerr << "multipart diagnostic: status=" << final_status << " content-type='" << observed_content_type
              << "' parts=" << observed_part_count << " error='" << observed_error << "'\n";
  }

  request_received = false;
  response_received = false;
  final_status = 0;
  engine.publish("sips:service@openmcx.test", "multipart/mixed; boundary=" + boundary, "\r\n" + published_body, {},
                 [&](const mcx::SipResponse &response) {
                   final_status = response.status_code;
                   response_received = response.status_code == 200;
                 });
  for (int iteration = 0; iteration < 200 && !response_received; ++iteration) {
    engine.poll(std::chrono::milliseconds(10));
  }
  check(request_received && response_received, "PJSIP-style leading MIME framing is normalized before strict parsing");

  int subscription_status = 0;
  const std::string subscription_dialog =
      engine.subscribe("sips:service@openmcx.test", "presence", 3600, {},
                       [&](const mcx::SipResponse &response) { subscription_status = response.status_code; });
  check(!subscription_dialog.empty(), "outgoing SUBSCRIBE retains its dialog while usage is attached");
  for (int iteration = 0; iteration < 200 && subscription_status == 0; ++iteration) {
    engine.poll(std::chrono::milliseconds(10));
  }
  check(subscription_status == 482, "self-routed SUBSCRIBE collision receives a final response");

  int unsupported_invite_status = 0;
  engine.request("INVITE", "sips:service@openmcx.test", "application/sdp", mcx::make_sdp(media, 9),
                 {{"Require", "x-unsupported"}},
                 [&](const mcx::SipResponse &response) { unsupported_invite_status = response.status_code; });
  for (int iteration = 0; iteration < 200 && unsupported_invite_status == 0; ++iteration) {
    engine.poll(std::chrono::milliseconds(10));
  }
  check(unsupported_invite_status == 420,
        "unsupported INVITE extension receives 420 Bad Extension (RFC 3261 section 8.2.2.3)");
  check(invite_application_calls == 0, "unsupported INVITE is rejected before the application commits call state");

  int colliding_invite_status = 0;
  const std::string colliding_dialog =
      engine.invite("sips:service@openmcx.test", media, {},
                    [&](const mcx::SipResponse &response) { colliding_invite_status = response.status_code; });
  check(!colliding_dialog.empty(), "outgoing INVITE returns a dialog identifier");
  for (int iteration = 0; iteration < 200 && (colliding_invite_status == 0 || !invite_disconnected); ++iteration) {
    engine.poll(std::chrono::milliseconds(10));
  }
  check(colliding_invite_status == 482, "an initial request colliding with a live Call-ID is rejected");
  check(invite_application_calls == 0, "Call-ID collision is rejected before the application callback");
  check(invite_disconnected, "rejected outgoing INVITE retires through the disconnected callback");
  if (colliding_invite_status != 482 || invite_application_calls != 0 || !invite_disconnected) {
    std::cerr << "collision diagnostic: status=" << colliding_invite_status << " app-calls=" << invite_application_calls
              << " disconnected=" << invite_disconnected << " error='" << observed_error << "'\n";
  }

  // RFC 3261 section 13.3.1: an answer that fails after the INVITE session was created is replaced by a 500 sent in
  // that session, which then ends without leaving its dialog behind.
  int failed_answer_status = 0;
  invite_disconnected = false;
  engine.request("INVITE", "sips:service@openmcx.test", "application/sdp", mcx::make_sdp(media, 10),
                 {{"X-Unsafe-Answer", "1"}},
                 [&](const mcx::SipResponse &response) { failed_answer_status = response.status_code; });
  for (int iteration = 0; iteration < 200 && (failed_answer_status == 0 || !invite_disconnected); ++iteration) {
    engine.poll(std::chrono::milliseconds(10));
  }
  check(failed_answer_status == 500, "an INVITE whose answer cannot be built is answered 500 in its session");
  check(invite_disconnected, "an INVITE whose answer failed is reported disconnected");
  check(engine.subscription_count() == 0, "no subscription dialog is left behind");

  struct sigaction signal_action{};
  struct sigaction previous_action{};
  signal_action.sa_handler = handle_poll_signal;
  sigemptyset(&signal_action.sa_mask);
  sigaction(SIGUSR1, &signal_action, &previous_action);
  const pthread_t polling_thread = pthread_self();
  std::thread interrupter([polling_thread] {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    pthread_kill(polling_thread, SIGUSR1);
  });
  bool interrupted_poll_returned = true;
  try {
    engine.poll(std::chrono::milliseconds(500));
  } catch (...) {
    interrupted_poll_returned = false;
  }
  interrupter.join();
  sigaction(SIGUSR1, &previous_action, nullptr);
  check(poll_signal_received != 0 && interrupted_poll_returned,
        "interrupted SIP polling returns normally for graceful shutdown");

  engine.stop();
  check(!engine.running(), "SIP TLS endpoint stops cleanly");
}

//------------------------------------------------------------------------------
// Test helper: the configuration of one of the separate test processes (TLS, or TCP with OPENMCX_SIP_TEST_TCP).
mcx::SipConfig process_config(const std::string &directory, std::uint16_t port, std::string identity,
                              std::string core_uri) {
  mcx::SipConfig config;
  config.listen_address = "127.0.0.1";
  config.advertise_address = "127.0.0.1";
  config.listen_port = port;
  config.core_uri = std::move(core_uri);
  if (std::getenv("OPENMCX_SIP_TEST_TCP")) {
    config.tls.enabled = false;
    config.core_uri = "sip:127.0.0.1:15061;transport=tcp";
  }
  config.identity = std::move(identity);
  config.tls.ca_file = directory + "/cert.pem";
  config.tls.cert_file = directory + "/cert.pem";
  config.tls.key_file = directory + "/key.pem";
  return config;
}

//------------------------------------------------------------------------------
// Role "server" (RFC 6665 section 4.2, notifier): three rounds of SUBSCRIBE, two active NOTIFY requests and a
// terminated one each, the dialog released after the terminating NOTIFY; then three invalid SUBSCRIBE requests
// refused with 400, keeping no dialog.
void run_subscribe_server(const std::string &directory) {
  bool received = false;
  std::vector<std::string> subscriptions;
  int rejected = 0;
  mcx::SipCallbacks callbacks;
  callbacks.on_request = [&](const mcx::SipMessage &message) {
    received = message.method == "SUBSCRIBE" && mcx::get_header(message.headers, "Event") == "presence" &&
               message.content_type == "application/vnd.3gpp.mcptt-info+xml" && message.body == "<mcptt-info/>" &&
               !message.dialog_id.empty();
    if (received) {
      subscriptions.push_back(message.dialog_id);
    } else if (message.method == "SUBSCRIBE") {
      ++rejected;
    }
    mcx::SipResponse response;
    response.status_code = received ? 200 : 400;
    response.reason = received ? "OK" : "Bad Request";
    return response;
  };
  mcx::SipEngine engine(
      process_config(directory, 15061, "sip:service@openmcx.test", "sip:127.0.0.1:15061;transport=tls"),
      std::move(callbacks));
  engine.start();
  std::ofstream(required_environment("OPENMCX_SIP_TEST_READY_FILE")) << "ready\n";
  for (int round = 0; round < 3; ++round) {
    for (int iteration = 0; iteration < 500 && subscriptions.size() <= static_cast<std::size_t>(round); ++iteration) {
      engine.poll(std::chrono::milliseconds(10));
    }
    check(subscriptions.size() > static_cast<std::size_t>(round), "server receives fresh SUBSCRIBE dialog request");
    if (subscriptions.size() <= static_cast<std::size_t>(round)) break;
    const auto dialog = subscriptions[round];

    int first_notify_status = 0;
    engine.notify(dialog, "presence", "active;expires=3600", "application/pidf+xml", "<presence version=\"1\"/>", {},
                  [&](const mcx::SipResponse &response) { first_notify_status = response.status_code; });
    for (int iteration = 0; iteration < 500 && first_notify_status == 0; ++iteration) {
      engine.poll(std::chrono::milliseconds(10));
    }
    check(first_notify_status == 200, "separate TLS server receives first NOTIFY 200 response");

    int second_notify_status = 0;
    engine.notify(dialog, "presence", "active;expires=3600", "application/pidf+xml", "<presence version=\"2\"/>", {},
                  [&](const mcx::SipResponse &response) { second_notify_status = response.status_code; });
    for (int iteration = 0; iteration < 500 && second_notify_status == 0; ++iteration) {
      engine.poll(std::chrono::milliseconds(10));
    }
    check(second_notify_status == 200, "separate TLS server receives second NOTIFY 200 response");
    check(engine.subscription_count() == 1, "active subscription remains retained");
    int terminated_status = 0;
    engine.notify(dialog, "presence", "terminated;reason=noresource", "application/pidf+xml",
                  "<presence version=\"3\"/>", {},
                  [&](const mcx::SipResponse &response) { terminated_status = response.status_code; });
    for (int iteration = 0; iteration < 500 && terminated_status == 0; ++iteration)
      engine.poll(std::chrono::milliseconds(10));
    check(terminated_status == 200, "terminated NOTIFY receives final response before cleanup");
    check(engine.subscription_count() == subscriptions.size() - static_cast<std::size_t>(round) - 1,
          "terminated notifier releases only its retained dialog");
  }
  for (int iteration = 0; iteration < 500 && rejected < 3; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(rejected == 3, "server rejects repeated invalid subscriptions");
  check(engine.subscription_count() == 0, "rejected subscriptions retain no server dialog");
  engine.stop();
}

//------------------------------------------------------------------------------
// Role "client" (RFC 6665 section 4.1, subscriber): SUBSCRIBE with an application/vnd.3gpp.mcptt-info+xml body,
// the NOTIFY requests answered in order and the dialog released after "terminated"; a refused initial SUBSCRIBE
// is reported to the caller and keeps no dialog.
void run_subscribe_client(const std::string &directory) {
  int final_status = 0;
  int notify_count = 0;
  std::string expected_dialog;
  mcx::SipCallbacks callbacks;
  callbacks.on_request = [&](const mcx::SipMessage &message) {
    const int expected_version = notify_count + 1;
    const bool valid = message.method == "NOTIFY" && message.dialog_id == expected_dialog &&
                       mcx::get_header(message.headers, "Event") == "presence" &&
                       mcx::get_header(message.headers, "Subscription-State") ==
                           (expected_version == 3 ? "terminated;reason=noresource" : "active;expires=3600") &&
                       message.content_type == "application/pidf+xml" &&
                       message.body == "<presence version=\"" + std::to_string(expected_version) + "\"/>";
    if (valid) {
      ++notify_count;
    }
    mcx::SipResponse response;
    response.status_code = valid ? 200 : 400;
    response.reason = valid ? "OK" : "Bad Request";
    return response;
  };
  mcx::SipEngine engine(
      process_config(directory, 15062, "sip:client@openmcx.test", "sip:127.0.0.1:15061;transport=tls"),
      std::move(callbacks));
  engine.start();
  for (int round = 0; round < 3; ++round) {
    notify_count = 0;
    final_status = 0;
    const std::string dialog = engine.subscribe(
        (std::getenv("OPENMCX_SIP_TEST_TCP") ? "sip:service@127.0.0.1:15061;transport=tcp"
                                             : "sips:service@127.0.0.1:15061"),
        "presence", 3600, {}, [&](const mcx::SipResponse &response) { final_status = response.status_code; },
        "application/vnd.3gpp.mcptt-info+xml", "<mcptt-info/>");
    expected_dialog = dialog;
    check(!dialog.empty(), "separate TLS client creates SUBSCRIBE dialog");
    for (int iteration = 0; iteration < 500 && final_status == 0; ++iteration) {
      engine.poll(std::chrono::milliseconds(10));
    }
    check(final_status == 200, "separate TLS client receives SUBSCRIBE 200 response");
    for (int iteration = 0; iteration < 1000 && notify_count < 3; ++iteration) {
      engine.poll(std::chrono::milliseconds(10));
    }
    check(notify_count == 3, "client answers active and terminated in-dialog NOTIFY requests");
    check(engine.subscription_count() == 0, "terminated subscriber releases dialog after response flush");
  }
  for (int round = 0; round < 3; ++round) {
    final_status = 0;
    (void)engine.subscribe((std::getenv("OPENMCX_SIP_TEST_TCP") ? "sip:service@127.0.0.1:15061;transport=tcp"
                                                                : "sips:service@127.0.0.1:15061"),
                           "unsupported", 60, {},
                           [&](const mcx::SipResponse &response) { final_status = response.status_code; });
    for (int iteration = 0; iteration < 500 && final_status == 0; ++iteration)
      engine.poll(std::chrono::milliseconds(10));
    check(final_status == 400, "initial SUBSCRIBE rejection delivered to caller");
    check(engine.subscription_count() == 0, "failed initial SUBSCRIBE releases client dialog");
  }
  engine.stop();
}

//------------------------------------------------------------------------------
// Test helper: media description with audio, RTCP and floor control ports from the given base port.
mcx::MediaDescription call_media(std::uint16_t port) {
  mcx::MediaDescription media;
  media.address = media.floor_address = "127.0.0.1";
  media.audio_port = port;
  media.rtcp_port = port + 1;
  media.floor_port = port + 2;
  media.floor_ssrc = port;
  return media;
}

//------------------------------------------------------------------------------
// Role "call-server": answers the INVITE of the call client like a controlling MCPTT function (TS 24.379 clause
// 6.3.3.2.3.2: a deferred 200 (OK) with a session Contact and the isfocus media feature tag), accepts, refuses
// or defers INFO, MESSAGE and re-INVITE, sends reverse INFO, MESSAGE and re-INVITE after the update ACK, and
// ends the "reject" call before answering it.
void run_call_server(const std::string &directory) {
  int confirmed = 0, disconnected = 0;
  int update_ack = 0, reverse_result = 0;
  int info_received = 0, message_received = 0, reverse_info = 0, reverse_message = 0;
  int deferred_requests = 0;
  std::vector<std::pair<std::string, bool>> deferred; // transaction, re-INVITE
  std::chrono::steady_clock::time_point deferred_at;
  std::string reverse_dialog;
  bool reverse_sent = false;
  std::string pending;
  bool reject_pending = false;
  std::chrono::steady_clock::time_point answer_at;
  mcx::SipCallbacks callbacks;
  callbacks.on_ack = [&](std::string_view id) {
    ++update_ack;
    // The first ACK completes initial admission; reverse only the update.
    if (update_ack == 2) reverse_dialog = id;
  };
  callbacks.on_request = [&](const mcx::SipMessage &message) {
    mcx::SipResponse response;
    response.status_code = 200;
    if (message.method == "INFO" || message.method == "MESSAGE") {
      if (mcx::get_header(message.headers, "X-Test-Fail") == "yes") {
        response.status_code = 500;
        return response;
      }
      check(message.body == "<client/>" && message.content_type == "application/test+xml",
            "established request preserves client MIME body");
      if (!mcx::get_header(message.headers, "X-Test-Defer").empty()) {
        check(!message.transaction_id.empty(), "request carries a deferral handle");
        ++deferred_requests;
        deferred.emplace_back(message.transaction_id, false);
        deferred_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
        response.deferred = true;
        return response;
      }
      if (message.method == "INFO")
        ++info_received;
      else
        ++message_received;
    }
    if (message.method == "INVITE" && mcx::get_header(message.headers, "X-Test-Change") == "deferred") {
      ++deferred_requests;
      deferred.emplace_back(message.transaction_id, true);
      deferred_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
      response.deferred = true;
      return response;
    }
    if (message.method == "INVITE") {
      if (mcx::get_header(message.headers, "X-Test-Change") == "reject") {
        response.status_code = 488;
        return response;
      }
      if (mcx::get_header(message.headers, "X-Test-Change") == "emergency") {
        check(message.parts.size() == 2, "re-INVITE retains SDP and application MIME parts");
        response.local_media = call_media(42000);
        response.headers.push_back({"X-Test-Change", "accepted"});
        return response;
      }
      response.status_code = 180;
      response.local_media = call_media(42000);
      if (message.request_uri.find("service") != std::string::npos) {
        // The main call gives its SDP answer only with the final answer,
        // and its requests toward the caller take a pinned route.
        response.local_media.reset();
        response.deferred = true;
        response.peer_route = std::getenv("OPENMCX_SIP_TEST_TCP") ? "<sip:127.0.0.1:15062;transport=tcp;lr>"
                                                                  : "<sip:127.0.0.1:15062;transport=tls;lr>";
      }
      if (message.request_uri.find("cancel") == std::string::npos) {
        pending = message.dialog_id;
        reject_pending = message.request_uri.find("reject") != std::string::npos;
        answer_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(80);
      }
    }
    return response;
  };
  callbacks.on_call_state = [&](std::string_view, mcx::SipCallState state, int) {
    if (state == mcx::SipCallState::confirmed) ++confirmed;
    if (state == mcx::SipCallState::disconnected) ++disconnected;
  };
  mcx::SipEngine engine(
      process_config(directory, 15061, "sip:service@openmcx.test", "sip:127.0.0.1:15061;transport=tls"), callbacks);
  engine.start();
  std::ofstream(required_environment("OPENMCX_SIP_TEST_READY_FILE")) << "ready\n";
  for (int iteration = 0; iteration < 1500 && disconnected < 4; ++iteration) {
    engine.poll(std::chrono::milliseconds(10));
    if (!reverse_dialog.empty() && !reverse_sent) {
      reverse_sent = true;
      engine.request_in_dialog(reverse_dialog, "INFO", "application/test+xml", "<server/>", {},
                               [&](const mcx::SipResponse &response) { reverse_info = response.status_code; });
      engine.request_in_dialog(reverse_dialog, "MESSAGE", "application/test+xml", "<server/>", {},
                               [&](const mcx::SipResponse &response) { reverse_message = response.status_code; });
      engine.reinvite(reverse_dialog, call_media(42000), {},
                      [&](const mcx::SipResponse &response) { reverse_result = response.status_code; },
                      {{"X-Test-Change", "reverse"}});
    }
    if (!deferred.empty() && std::chrono::steady_clock::now() >= deferred_at) {
      for (const auto &[id, reinvite] : deferred) {
        mcx::SipResponse later;
        if (reinvite) {
          later.status_code = 200;
          later.local_media = call_media(42000);
          later.parts = {{"application/test+xml", "<deferred/>"}};
          later.headers = {{"X-Test-Change", "deferred-accepted"}};
        } else {
          later.status_code = 202;
          later.content_type = "application/test+xml";
          later.body = "<deferred/>";
          later.headers = {{"X-Test-Deferred", "yes"}};
        }
        engine.respond(id, later);
        engine.respond(id, later); // a repeated response is ignored
      }
      deferred.clear();
    }
    if (!pending.empty() && std::chrono::steady_clock::now() >= answer_at) {
      if (reject_pending) {
        engine.bye(pending);
        engine.bye(pending);
        pending.clear();
        continue;
      }
      mcx::SipResponse answer;
      answer.status_code = 200;
      answer.local_media = call_media(42000);
      answer.contact_uri = std::getenv("OPENMCX_SIP_TEST_TCP") ? "sip:session@127.0.0.1:15061;transport=tcp"
                                                               : "sips:session@127.0.0.1:15061";
      answer.focus = true;
      answer.parts = {{"application/test+xml", "<normal/>"}};
      engine.answer(pending, answer);
      pending.clear();
    }
  }
  check(confirmed == 1 && disconnected == 4,
        "normal release, two early CANCEL paths and local early rejection each disconnect once");
  check(update_ack == 4, "application observes deferred initial, two accepted and one deferred update ACK only");
  check(deferred_requests == 3, "out-of-dialog MESSAGE, in-dialog INFO and re-INVITE were deferred");
  check(reverse_result == 200, "reverse re-INVITE succeeds after receiving ACK");
  // Two INFO requests are accepted; a third carries X-Test-Fail and is refused.
  check(info_received == 2 && message_received == 1, "INVITE UAS delivers established INFO and MESSAGE to application");
  check(reverse_info == 200 && reverse_message == 200,
        "INVITE UAC answers reverse INFO and MESSAGE through application");
  engine.stop();
}

//------------------------------------------------------------------------------
// Role "call-client": an INVITE session against "call-server". TS 24.379 clause 6.3.3.2.3.2 steps 2, 3, 5 and 6:
// the final answer requires "timer", sets refresher "uac" and has one Contact with the session URI and isfocus;
// in-dialog INFO and MESSAGE, a refused INFO leaving the dialog usable, re-INVITE accepted and refused (the
// session stays, RFC 3261 section 14.1), deferred responses, idempotent BYE, CANCEL of early calls (RFC 3261
// section 9.1) and 487 (Request Terminated) for an unanswered INVITE that its server ends.
void run_call_client(const std::string &directory) {
  int confirmed = 0, disconnected = 0, early = 0;
  std::string contact;
  int reverse_received = 0, reverse_acked = 0, info_received = 0, message_received = 0;
  mcx::SipCallbacks callbacks;
  callbacks.on_ack = [&](std::string_view) { ++reverse_acked; };
  callbacks.on_request = [&](const mcx::SipMessage &request) {
    mcx::SipResponse response;
    response.status_code = 200;
    if (request.method == "INFO" || request.method == "MESSAGE") {
      check(request.body == "<server/>" && request.content_type == "application/test+xml",
            "established request preserves server MIME body");
      if (request.method == "INFO")
        ++info_received;
      else
        ++message_received;
    }
    if (request.method == "INVITE") {
      check(mcx::get_header(request.headers, "X-Test-Change") == "reverse",
            "server can reverse re-INVITE direction on existing dialog");
      check(request.content_type == "application/sdp" && request.remote_media,
            "a re-INVITE with SDP only has a plain application/sdp body");
      ++reverse_received;
      response.local_media = call_media(43000);
    }
    return response;
  };
  callbacks.on_call_state = [&](std::string_view, mcx::SipCallState state, int) {
    if (state == mcx::SipCallState::confirmed) ++confirmed;
    if (state == mcx::SipCallState::disconnected) ++disconnected;
    if (state == mcx::SipCallState::early) ++early;
  };
  // Nothing listens on the core port: every request below takes an explicit Route.
  mcx::SipEngine engine(
      process_config(directory, 15062, "sip:client@openmcx.test", "sip:127.0.0.1:15099;transport=tls"), callbacks);
  engine.start();
  const std::vector<mcx::SipHeader> route{{"Route", std::getenv("OPENMCX_SIP_TEST_TCP")
                                                        ? "<sip:127.0.0.1:15061;transport=tcp;lr>"
                                                        : "<sip:127.0.0.1:15061;transport=tls;lr>"}};
  const auto target = std::getenv("OPENMCX_SIP_TEST_TCP") ? "sip:service@127.0.0.1:15061;transport=tcp"
                                                          : "sips:service@127.0.0.1:15061";
  const auto dialog = engine.invite(
      target, call_media(43000), {},
      [&](const mcx::SipResponse &response) {
        if (response.status_code == 200) {
          check(response.parts.size() == 2 && response.parts.back().body == "<normal/>",
                "multipart response preserves original MIME boundary and application body");
          contact = mcx::get_header(response.headers, "Contact");
          check(mcx::get_header(response.headers, "Require").find("timer") != std::string_view::npos,
                "MCPTT final answer requires session timer");
          check(mcx::get_header(response.headers, "Session-Expires").find("refresher=uac") != std::string_view::npos,
                "MCPTT session timer negotiates UAC refresher");
          int count = 0;
          for (const auto &header : response.headers)
            if (header.name == "Contact") ++count;
          check(count == 1, "final answer contains one Contact header");
        }
      },
      route);
  for (int iteration = 0; iteration < 500 && !confirmed; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(confirmed == 1, "outgoing call is confirmed before release");
  check(contact.find("session@") != std::string::npos && contact.find("isfocus") != std::string::npos,
        "deferred final answer advertises the public session Contact and focus role");
  int info_result = 0, message_result = 0;
  engine.request_in_dialog(dialog, "INFO", "application/test+xml", "<client/>", {},
                           [&](const mcx::SipResponse &response) { info_result = response.status_code; });
  engine.request_in_dialog(dialog, "MESSAGE", "application/test+xml", "<client/>", {},
                           [&](const mcx::SipResponse &response) { message_result = response.status_code; });
  for (int iteration = 0; iteration < 500 && (!info_result || !message_result); ++iteration)
    engine.poll(std::chrono::milliseconds(10));
  check(info_result == 200 && message_result == 200, "established INFO and MESSAGE receive application responses");
  // A failed in-dialog request must not disturb the dialog or the engine: the
  // MCData server sends SIP INFO requests inside media plane dialogs.
  int refused = 0, after_refusal = 0;
  engine.request_in_dialog(dialog, "INFO", "application/test+xml", "<client/>", {{"X-Test-Fail", "yes"}},
                           [&](const mcx::SipResponse &response) { refused = response.status_code; });
  for (int iteration = 0; iteration < 500 && !refused; ++iteration) engine.poll(std::chrono::milliseconds(10));
  engine.request_in_dialog(dialog, "INFO", "application/test+xml", "<client/>", {},
                           [&](const mcx::SipResponse &response) { after_refusal = response.status_code; });
  for (int iteration = 0; iteration < 500 && !after_refusal; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(refused == 500 && after_refusal == 200, "a refused in-dialog request is reported and the dialog stays usable");
  int changed = 0;
  engine.reinvite(
      dialog, call_media(43000), {{"application/test+xml", "<change/>"}},
      [&](const mcx::SipResponse &response) {
        changed = response.status_code;
        check(mcx::get_header(response.headers, "X-Test-Change") == "accepted", "re-INVITE reaches application");
        check(response.content_type == "application/sdp" && response.body.find("m=audio") != std::string::npos,
              "an answer with SDP only has a plain application/sdp body");
      },
      {{"X-Test-Change", "emergency"}});
  for (int iteration = 0; iteration < 500 && changed == 0; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(changed == 200 && disconnected == 0 && confirmed == 1,
        "re-INVITE changes existing session without duplicate confirmation or teardown");
  for (int iteration = 0; iteration < 500 && !reverse_acked; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(reverse_received == 1 && reverse_acked == 1, "reverse re-INVITE completes through ACK");
  check(info_received == 1 && message_received == 1, "INVITE UAC delivers reverse INFO and MESSAGE to application");
  int rejected_update = 0;
  engine.reinvite(dialog, call_media(43000), {},
                  [&](const mcx::SipResponse &response) { rejected_update = response.status_code; },
                  {{"X-Test-Change", "reject"}});
  for (int iteration = 0; iteration < 500 && !rejected_update; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(rejected_update == 488 && disconnected == 0, "rejected re-INVITE preserves existing dialog");
  int retried = 0;
  engine.reinvite(dialog, call_media(43000), {{"application/test+xml", "<change/>"}},
                  [&](const mcx::SipResponse &response) { retried = response.status_code; },
                  {{"X-Test-Change", "emergency"}});
  for (int iteration = 0; iteration < 500 && !retried; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(retried == 200,
        "accepted re-INVITE after rejection clears pending transaction state, status=" + std::to_string(retried));
  int deferred_message = 0, deferred_info = 0, deferred_change = 0;
  auto deferred_reply = [](int &status) {
    return [&status](const mcx::SipResponse &response) {
      status = response.status_code;
      check(response.body == "<deferred/>" && mcx::get_header(response.headers, "X-Test-Deferred") == "yes",
            "deferred response carries the application body and headers");
    };
  };
  auto message_headers = route;
  message_headers.push_back({"X-Test-Defer", "1"});
  engine.request("MESSAGE", target, "application/test+xml", "<client/>", message_headers,
                 deferred_reply(deferred_message));
  engine.request_in_dialog(dialog, "INFO", "application/test+xml", "<client/>", {{"X-Test-Defer", "1"}},
                           deferred_reply(deferred_info));
  engine.reinvite(dialog, call_media(43000), {{"application/test+xml", "<change/>"}},
                  [&](const mcx::SipResponse &response) {
                    deferred_change = response.status_code;
                    check(mcx::get_header(response.headers, "X-Test-Change") == "deferred-accepted" &&
                              response.parts.size() == 2 && response.parts.back().body == "<deferred/>",
                          "deferred re-INVITE answer carries SDP, application body and headers");
                  },
                  {{"X-Test-Change", "deferred"}});
  for (int iteration = 0; iteration < 500 && (!deferred_message || !deferred_info || !deferred_change); ++iteration)
    engine.poll(std::chrono::milliseconds(10));
  check(deferred_message == 202 && deferred_info == 202 && deferred_change == 200,
        "explicitly routed MESSAGE, INFO and re-INVITE receive deferred responses");
  engine.bye(dialog);
  try {
    engine.bye(dialog);
  } catch (const std::exception &error) {
    check(false, std::string("repeated release must be idempotent: ") + error.what());
  }
  for (int iteration = 0; iteration < 500 && !disconnected; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(disconnected == 1, "outgoing release notifies disconnected exactly once");
  try {
    engine.bye(dialog);
  } catch (const std::exception &error) {
    check(false, std::string("release of retired call must be harmless: ") + error.what());
  }
  early = 0;
  const auto cancel_target =
      std::getenv("OPENMCX_SIP_TEST_TCP") ? "sip:cancel@127.0.0.1:15061;transport=tcp" : "sips:cancel@127.0.0.1:15061";
  const auto canceled = engine.invite(cancel_target, call_media(43000), {}, {}, route);
  for (int iteration = 0; iteration < 500 && !early; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(early > 0, "pending call receives provisional response before cancellation");
  engine.bye(canceled);
  engine.bye(canceled);
  for (int iteration = 0; iteration < 500 && disconnected < 2; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(disconnected == 2 && confirmed == 1, "early call is canceled without a confirmed dialog or duplicate teardown");
  engine.bye(canceled);
  const auto immediate = engine.invite(cancel_target, call_media(43000), {}, {}, route);
  engine.bye(immediate);
  engine.bye(immediate);
  for (int iteration = 0; iteration < 500 && disconnected < 3; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(disconnected == 3 && confirmed == 1,
        "cancellation before provisional response is sent when provisional response arrives");
  int reject_status = 0;
  const auto reject_target =
      std::getenv("OPENMCX_SIP_TEST_TCP") ? "sip:reject@127.0.0.1:15061;transport=tcp" : "sips:reject@127.0.0.1:15061";
  const auto rejected = engine.invite(
      reject_target, call_media(43000), {},
      [&](const mcx::SipResponse &response) { reject_status = response.status_code; }, route);
  for (int iteration = 0; iteration < 500 && disconnected < 4; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(disconnected == 4 && confirmed == 1 && reject_status == 487,
        "ending an unanswered incoming INVITE rejects with 487 instead of confirming it");
  engine.bye(rejected);
  engine.stop();
}

//------------------------------------------------------------------------------
// Role "bye-auth-server": the UAS of a confirmed dialog sends BYE and retries it after 407 with proxy digest
// credentials (RFC 3261 section 22.3); the wire peer proves the retry by writing the ".verified" file.
void run_bye_auth_server(const std::string &directory) {
  int confirmed = 0, disconnected = 0, initial_ack = 0;
  std::string dialog;
  std::string error;
  mcx::SipCallbacks callbacks;
  callbacks.on_ack = [&](std::string_view) { ++initial_ack; };
  callbacks.on_request = [&](const mcx::SipMessage &message) {
    mcx::SipResponse response;
    response.status_code = message.method == "INVITE" ? 200 : 405;
    if (message.method == "INVITE") {
      dialog = message.dialog_id;
      response.local_media = call_media(42000);
    }
    return response;
  };
  callbacks.on_call_state = [&](std::string_view, mcx::SipCallState state, int) {
    if (state == mcx::SipCallState::confirmed) ++confirmed;
    if (state == mcx::SipCallState::disconnected) ++disconnected;
  };
  callbacks.on_error = [&](std::string_view text) { error = text; };
  auto config = process_config(directory, 15061, "sip:uas@openmcx.test", "sip:127.0.0.1:15062;transport=tls");
  if (std::getenv("OPENMCX_SIP_TEST_TCP")) config.core_uri = "sip:127.0.0.1:15062;transport=tcp";
  config.username = "incoming-dialog-user";
  config.password = "incoming-dialog-test-password";
  mcx::SipEngine engine(config, callbacks);
  engine.start();
  const auto ready_file = required_environment("OPENMCX_SIP_TEST_READY_FILE");
  std::ofstream(ready_file) << "ready\n";
  const std::string verified_file = ready_file + ".verified";
  bool sent_bye = false, verified = false;
  for (int iteration = 0; iteration < 1200 && !verified; ++iteration) {
    engine.poll(std::chrono::milliseconds(10));
    if (confirmed && !sent_bye) {
      sent_bye = true;
      engine.bye(dialog);
    }
    verified = std::ifstream(verified_file).good();
  }
  // Sending BYE itself can emit disconnected, so only the independent wire
  // peer's authenticated-retry verification proves this regression passed.
  for (int iteration = 0; iteration < 20; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(confirmed == 1 && sent_bye, "incoming INVITE creates a confirmed UAS dialog that originates BYE");
  check(verified, "UAS BYE retries 407 with a correct proxy digest from configured credentials");
  check(disconnected == 1, "authenticated UAS release retires once");
  check(initial_ack == 1, "immediate initial successful answer notifies ACK exactly once");
  if (!verified) std::cerr << "UAS BYE authentication diagnostic: " << error << '\n';
  engine.stop();
}

//------------------------------------------------------------------------------
// Role "transaction-failure": a SUBSCRIBE towards a port where nothing listens fails at the transport and invokes
// its response callback exactly once with an error status.
void run_transaction_failure(const std::string &directory) {
  auto config = process_config(directory, 15062, "sip:client@openmcx.test", "sip:127.0.0.1:15063;transport=tls");
  if (std::getenv("OPENMCX_SIP_TEST_TCP")) config.core_uri = "sip:127.0.0.1:15063;transport=tcp";
  mcx::SipEngine engine(config, {});
  engine.start();
  int responses = 0, status = 0;
  const auto dialog = engine.subscribe(config.core_uri, "presence", 60, {}, [&](const mcx::SipResponse &response) {
    ++responses;
    status = response.status_code;
  });
  check(!dialog.empty(), "transport-failing request still has a tracked subscription identifier");
  for (int iteration = 0; iteration < 500 && !responses; ++iteration) engine.poll(std::chrono::milliseconds(10));
  check(responses == 1 && status >= 400, "terminated in-dialog transaction invokes failure callback exactly once");
  engine.stop();
}

} // namespace

//------------------------------------------------------------------------------
// Runs one role of a multi-process test (OPENMCX_SIP_TEST_ROLE) or the single-process tests.
int main() {
  if (const char *role = std::getenv("OPENMCX_SIP_TEST_ROLE")) {
    const char *certificate_directory = std::getenv("OPENMCX_SIP_TEST_CERT_DIR");
    if (certificate_directory == nullptr) {
      return 2;
    }
    try {
      if (std::string_view(role) == "bye-auth-server") {
        run_bye_auth_server(certificate_directory);
      } else if (std::string_view(role) == "transaction-failure") {
        run_transaction_failure(certificate_directory);
      } else if (std::string_view(role) == "call-server") {
        run_call_server(certificate_directory);
      } else if (std::string_view(role) == "call-client") {
        run_call_client(certificate_directory);
      } else if (std::string_view(role) == "server") {
        run_subscribe_server(certificate_directory);
      } else if (std::string_view(role) == "client") {
        run_subscribe_client(certificate_directory);
      } else {
        return 2;
      }
    } catch (const std::exception &error) {
      check(false, std::string(role) + ": " + error.what());
    }
    return failures == 0 ? 0 : 1;
  }
  test_case_insensitive_header_lookup();
  test_tls_and_identity_configuration_are_required();
  test_native_mutual_tls_request_callbacks_when_configured();
  if (failures != 0) {
    return 1;
  }
  std::cout << "SIP API validation tests passed\n";
  return 0;
}
