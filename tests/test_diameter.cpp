//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Diameter user profile pull between the MCPTT server and the user database over a real SCTP peer (freeDiameter):
// the profile answer, an unknown user, an unconfigured peer, and recovery after the user database is restarted.
//
// Specifications: TS 29.283 (Diameter data management applications; text not kept locally).
#include "mcx/diameter.hpp"

#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <thread>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

//------------------------------------------------------------------------------
// Fails the test with the message when the value does not hold.
static void check(bool value, const char *message) {
  if (!value) throw std::runtime_error(message);
}

//------------------------------------------------------------------------------
// Writes the contents to the file at path or fails the test.
static void write_file(const fs::path &path, const std::string &contents) {
  std::ofstream out(path);
  if (!out || !(out << contents)) throw std::runtime_error("cannot write " + path.string());
}

//------------------------------------------------------------------------------
// The freeDiameter configuration of one peer: SCTP on the loopback address without TLS, connected to one peer.
static std::string native_config(std::string identity, unsigned port, std::string peer, unsigned peer_port,
                                 std::string peer_host = "127.0.0.1") {
  return "Identity = \"" + identity +
         "\";\n"
         "Realm = \"mcx.test\";\n"
         "Port = " +
         std::to_string(port) +
         ";\n"
         "SecPort = 0;\n"
         "No_TCP;\n"
         "No_IPv6;\n"
         "NoRelay;\n"
         "AppServThreads = 2;\n"
         "ListenOn = \"127.0.0.1\";\n"
         "ConnectPeer = \"" +
         peer + "\" { ConnectTo = \"" + peer_host +
         "\"; "
         "Port = " +
         std::to_string(peer_port) + "; No_TLS; No_TCP; Realm = \"mcx.test\"; TcTimer = 1; };\n";
}

//------------------------------------------------------------------------------
// Child process: a client whose identity the user database has not configured pulls a profile; exits 0 when the
// user database refuses the connection (it never reaches OPEN), 2 when it is served and 3 on any other failure (a
// broken configuration must not pass for a refusal).
static int rogue_attempt(const char *config_path) {
  try {
    mcx::DiameterProfileClient client(config_path, 2s);
    (void)client.pull("sip:alice@mcx.test");
    return 2;
  } catch (const std::exception &error) {
    if (std::string_view(error.what()).find("did not reach OPEN") != std::string_view::npos) return 0;
    std::cerr << "rogue client failed otherwise: " << error.what() << '\n';
    return 3;
  }
}

//------------------------------------------------------------------------------
// TS 29.283: the profile pull from the user database (the mcx-user-db binary given as argument) returns the MCPTT
// user profile with the MCPTT ID and its SIP identity; an unknown user and an unconfigured peer are refused; while
// the user database is down a pull fails, and the client reconnects once it is back.
int main(int argc, char **argv) {
  if (argc == 3 && std::string(argv[1]) == "--rogue") return rogue_attempt(argv[2]);
  if (argc != 2) throw std::runtime_error("usage: test_diameter /path/to/mcx-user-db");

  const auto base = fs::temp_directory_path() / ("openmcx-diameter-" + std::to_string(::getpid()));
  fs::create_directories(base);
  const unsigned server_port = 24000 + (::getpid() % 10000) * 2;
  const unsigned client_port = server_port + 1;
  check(client_port < 65535, "test port overflow");
  const auto site = base / "site.json";
  const auto server_conf = base / "server.conf";
  const auto client_conf = base / "client.conf";
  const auto rogue_conf = base / "rogue.conf";
  write_file(
      site,
      R"({"users":[{"username":"alice","mc_id":"alice-mc","mcptt_id":"sip:alice@mcx.test","sip_uri":"sip:alice@ims.mcx.test","client_id":"urn:uuid:alice-device","groups":["sip:team@mcx.test"]}]})");
  write_file(server_conf, native_config("user-db.mcx.test", server_port, "mcptt-server.mcx.test", client_port));
  // A ConnectTo host name is resolved by DiameterProfileClient itself.
  write_file(client_conf,
             native_config("mcptt-server.mcx.test", client_port, "user-db.mcx.test", server_port, "localhost"));
  write_file(rogue_conf, native_config("rogue.mcx.test", client_port + 1, "user-db.mcx.test", server_port));

  auto start_server = [&] {
    const pid_t child = ::fork();
    if (child == 0) {
      ::execl(argv[1], argv[1], "--config", site.c_str(), "--diameter-config", server_conf.c_str(),
              static_cast<char *>(nullptr));
      _exit(127);
    }
    if (child < 0) throw std::runtime_error("fork server failed");
    return child;
  };
  pid_t server = start_server();

  auto cleanup = [&] {
    ::kill(server, SIGTERM);
    int status = 0;
    (void)::waitpid(server, &status, 0);
    fs::remove_all(base);
  };

  try {
    // The configured client first: its pull, retried while the user database starts, shows the database is up, so
    // that the refusal of the unconfigured peer below is the database's.
    mcx::DiameterProfileClient client(client_conf.string(), 5s);
    std::string profile;
    for (int attempt = 0; attempt != 10; ++attempt) {
      try {
        profile = client.pull("sip:alice@mcx.test");
        break;
      } catch (const std::exception &) {
        if (attempt == 9) throw;
        std::this_thread::sleep_for(300ms);
      }
    }

    const pid_t rogue = ::fork();
    if (rogue == 0) {
      ::execl(argv[0], argv[0], "--rogue", rogue_conf.c_str(), static_cast<char *>(nullptr));
      _exit(127);
    }
    int rogue_status = 0;
    check(::waitpid(rogue, &rogue_status, 0) == rogue, "waiting for rogue client failed");
    check(WIFEXITED(rogue_status) && WEXITSTATUS(rogue_status) == 0, "unconfigured Diameter peer was not refused");

    check(profile.size() < 1024 * 1024, "profile response is unbounded");
    check(profile.find("urn:3gpp:mcptt:user-profile:1.0") != std::string::npos, "MCPTT user profile namespace missing");
    check(profile.find("sip:alice@mcx.test") != std::string::npos, "MCPTT identity missing from returned profile");
    check(profile.find("sip:alice@ims.mcx.test") != std::string::npos,
          "SIP identity binding missing from returned profile");

    bool unknown_failed = false;
    try {
      (void)client.pull("sip:unknown@mcx.test");
    } catch (const std::exception &) {
      unknown_failed = true;
    }
    check(unknown_failed, "unknown MCPTT user returned a profile");

    // The user database dies abruptly: requests fail without taking the
    // client down, and the client reconnects once the database is back.
    ::kill(server, SIGKILL);
    int killed = 0;
    check(::waitpid(server, &killed, 0) == server, "waiting for killed user database failed");
    bool outage_failed = false;
    try {
      (void)client.pull("sip:alice@mcx.test");
    } catch (const std::exception &) {
      outage_failed = true;
    }
    check(outage_failed, "profile pulled while the user database was down");
    server = start_server();
    std::string recovered;
    for (int attempt = 0; attempt != 20 && recovered.empty(); ++attempt) {
      try {
        recovered = client.pull("sip:alice@mcx.test");
      } catch (const std::exception &) {
        std::this_thread::sleep_for(500ms);
      }
    }
    check(recovered == profile, "profile not pulled after the user database restarted");
    cleanup();
  } catch (...) {
    cleanup();
    throw;
  }
  std::cout << "TS 29.283 Data-Pull-Request/Answer completed over a real SCTP peer, "
               "also after the peer was killed and restarted\n";
}
